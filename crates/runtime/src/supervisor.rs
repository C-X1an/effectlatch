//! Credential-free runner process supervision.
//!
//! The child receives only bounded Wasm/input/configuration frames on standard
//! input. All effect authorization stays in the parent-side broker. The Linux
//! runner is placed in its own process group and the group is killed on every
//! abnormal return. Native Windows and macOS execution is rejected by the
//! domain host check; those hosts must use the documented Linux VM/container.
use std::{
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, ExitStatus, Stdio},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use effectlatch_domain::{Limits, require_execution_host, types::EffectRequest};
use thiserror::Error;

use crate::{
    abi::{AbiCaps, DispatchFailure, EffectReply, LOG_BYTES, MAX_HOST_CALLS},
    ipc::{
        ChildFrame, EffectResponse, EffectResponseFrame, MESSAGE_FRAME_BYTES, ParentSequence,
        ProtocolError, START_FRAME_BYTES, StartFrame, read_child, write_frame,
    },
};

const PROTOCOL_VERSION: u8 = 1;
const SUPERVISION_ALLOWANCE: Duration = Duration::from_millis(500);
const LEASE_POLL: Duration = Duration::from_millis(20);
const EXIT_POLL: Duration = Duration::from_millis(5);
const CLEANUP_WAIT: Duration = Duration::from_millis(250);
const REAPER_CAPACITY: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseState {
    Current,
    Cancelled,
    Lost,
}

#[derive(Clone, Copy, Debug, Error)]
pub enum BrokerError {
    #[error("run cancellation was requested")]
    Cancelled,
    #[error("run lease is no longer current")]
    LeaseLost,
    #[error(transparent)]
    Effect(#[from] DispatchFailure),
}

/// Parent-side authority for one supervised invocation.
///
/// `dispatch_if_current` must perform its durable lease/cancellation check and
/// effect intent commit atomically at the broker boundary. The supervisor's
/// `lease_state` polling stops idle or compute-only guests quickly, but is not
/// itself the authorization linearization point. Dispatch implementations must
/// use their own bounded external deadline; a previously authorized in-flight
/// action may finish after this supervisor returns.
pub trait DispatchBroker: Send + Sync + 'static {
    fn lease_state(&self) -> LeaseState;

    fn dispatch_if_current(&self, request: EffectRequest) -> Result<EffectReply, BrokerError>;
}

#[derive(Clone, Debug)]
pub struct Supervisor {
    runner: PathBuf,
    operator_caps: Limits,
    abi_caps: AbiCaps,
}

#[derive(Debug, Eq, PartialEq)]
pub struct SupervisedOutcome {
    pub output: Option<Vec<u8>>,
    pub logs: Vec<String>,
}

#[derive(Debug, Error)]
pub enum SupervisorError {
    #[error("unsupported execution host: {0}")]
    UnsupportedHost(#[from] effectlatch_domain::ConfigError),
    #[error("runner path is not a file")]
    RunnerPath,
    #[error("invalid operator ABI caps")]
    InvalidAbiCaps,
    #[error("runner process IO failed: {0}")]
    Io(#[from] io::Error),
    #[error("runner protocol failed: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("runner exceeded its monotonic wall deadline")]
    Deadline,
    #[error("run cancellation was observed")]
    Cancelled,
    #[error("run lease was lost")]
    LeaseLost,
    #[error("runner reported bounded failure: {0}")]
    RunnerFailure(String),
    #[error("runner exited without a valid finish frame: {0:?}")]
    ChildExit(Option<i32>),
    #[error("broker returned a response inconsistent with the request")]
    BrokerResponse,
    #[error("supervision clock overflow")]
    Clock,
}

impl Supervisor {
    pub fn new(runner: impl Into<PathBuf>, operator_caps: Limits) -> Result<Self, SupervisorError> {
        Self::new_with_abi_caps(
            runner,
            operator_caps,
            AbiCaps {
                host_calls: MAX_HOST_CALLS,
                log_bytes: LOG_BYTES,
            },
        )
    }

    pub fn new_with_abi_caps(
        runner: impl Into<PathBuf>,
        operator_caps: Limits,
        abi_caps: AbiCaps,
    ) -> Result<Self, SupervisorError> {
        require_execution_host(std::env::consts::OS, std::env::consts::ARCH)?;
        operator_caps.validate(operator_caps)?;
        abi_caps
            .validate()
            .map_err(|_| SupervisorError::InvalidAbiCaps)?;
        let runner = runner.into();
        if !runner.is_file() {
            return Err(SupervisorError::RunnerPath);
        }
        Ok(Self {
            runner,
            operator_caps,
            abi_caps,
        })
    }

    pub fn run(
        &self,
        module: Vec<u8>,
        input: Vec<u8>,
        limits: Limits,
        broker: Arc<dyn DispatchBroker>,
    ) -> Result<SupervisedOutcome, SupervisorError> {
        let limits = limits.validate(self.operator_caps)?;
        let started = Instant::now();
        let deadline = started
            .checked_add(Duration::from_millis(limits.wall_ms))
            .and_then(|at| at.checked_add(SUPERVISION_ALLOWANCE))
            .ok_or(SupervisorError::Clock)?;
        let mut child = RunnerChild::spawn(&self.runner, self.operator_caps, self.abi_caps)?;
        let start = StartFrame {
            version: PROTOCOL_VERSION,
            kind: "start".into(),
            module_b64: STANDARD.encode(module),
            input_b64: STANDARD.encode(input),
            limits,
        };
        start.check()?;
        let mut start_bytes = Vec::new();
        write_frame(&mut start_bytes, &start, START_FRAME_BYTES)?;
        child.write_bounded(start_bytes, deadline, broker.as_ref())?;

        let stdout = child.take_stdout()?;
        let (frames_tx, frames_rx) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name("effectlatch-runner-output".into())
            .spawn(move || {
                let mut stdout = stdout;
                loop {
                    let frame = read_child(&mut stdout);
                    let finished = matches!(frame, Ok(ChildFrame::Finish { .. }));
                    if frames_tx.send(frame).is_err() || finished {
                        return;
                    }
                }
            })?;

        let (dispatch_tx, dispatch_rx) = mpsc::channel();
        let mut sequence = ParentSequence::with_log_cap(self.abi_caps.log_bytes)?;
        let mut logs = Vec::new();
        let mut dispatch_pending = false;

        loop {
            match broker.lease_state() {
                LeaseState::Current => {}
                LeaseState::Cancelled => return Err(SupervisorError::Cancelled),
                LeaseState::Lost => return Err(SupervisorError::LeaseLost),
            }
            if Instant::now() >= deadline {
                return Err(SupervisorError::Deadline);
            }

            if dispatch_pending {
                match dispatch_rx.try_recv() {
                    Ok((message_id, request, result)) => {
                        dispatch_pending = false;
                        let response = match result {
                            Ok(reply) => {
                                if !valid_reply(&request, &reply) {
                                    return Err(SupervisorError::BrokerResponse);
                                }
                                EffectResponse::Committed { reply }
                            }
                            Err(BrokerError::Cancelled) => return Err(SupervisorError::Cancelled),
                            Err(BrokerError::LeaseLost) => return Err(SupervisorError::LeaseLost),
                            Err(BrokerError::Effect(failure)) => EffectResponse::Failed {
                                code: dispatch_code(failure),
                            },
                        };
                        let frame = EffectResponseFrame {
                            version: PROTOCOL_VERSION,
                            kind: "effect_response".into(),
                            message_id,
                            response,
                        };
                        sequence.respond(&frame)?;
                        let mut response_bytes = Vec::new();
                        write_frame(&mut response_bytes, &frame, MESSAGE_FRAME_BYTES)?;
                        child.write_bounded(response_bytes, deadline, broker.as_ref())?;
                    }
                    Err(mpsc::TryRecvError::Empty) => {}
                    Err(mpsc::TryRecvError::Disconnected) => {
                        return Err(SupervisorError::BrokerResponse);
                    }
                }
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            let wait = remaining.min(LEASE_POLL);
            match frames_rx.recv_timeout(wait) {
                Ok(Ok(frame)) => {
                    sequence.observe(&frame)?;
                    match frame {
                        ChildFrame::EffectRequest {
                            message_id,
                            request,
                            ..
                        } => {
                            if dispatch_pending {
                                return Err(SupervisorError::Protocol(ProtocolError::Sequence));
                            }
                            dispatch_pending = true;
                            let broker = broker.clone();
                            let result_tx = dispatch_tx.clone();
                            thread::Builder::new()
                                .name("effectlatch-broker-dispatch".into())
                                .spawn(move || {
                                    let result = broker.dispatch_if_current(request.clone());
                                    let _ = result_tx.send((message_id, request, result));
                                })?;
                        }
                        ChildFrame::Log { message, .. } => logs.push(message),
                        ChildFrame::Finish {
                            output_b64,
                            error_code,
                            ..
                        } => {
                            if dispatch_pending {
                                return Err(SupervisorError::Protocol(ProtocolError::Sequence));
                            }
                            let status = child.wait_bounded(deadline)?;
                            if !status.success() {
                                return Err(SupervisorError::ChildExit(status.code()));
                            }
                            if let Some(code) = error_code {
                                return Err(SupervisorError::RunnerFailure(code));
                            }
                            let output = output_b64
                                .map(|value| STANDARD.decode(value))
                                .transpose()
                                .map_err(|_| ProtocolError::Message)?;
                            child.disarm()?;
                            return Ok(SupervisedOutcome { output, logs });
                        }
                    }
                }
                Ok(Err(error)) => return Err(error.into()),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    let status = child.wait_bounded(deadline)?;
                    return Err(SupervisorError::ChildExit(status.code()));
                }
            }
        }
    }
}

fn valid_reply(request: &EffectRequest, reply: &EffectReply) -> bool {
    reply.ordinal == request.ordinal
        && reply.response.project == request.arguments.project
        && !reply.response.ticket_id.is_empty()
}

fn dispatch_code(failure: DispatchFailure) -> i32 {
    match failure {
        DispatchFailure::Policy => -3,
        DispatchFailure::Unresolved => -4,
        DispatchFailure::ReplayDivergence => -5,
        DispatchFailure::Unavailable => -7,
    }
}

struct RunnerChild {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    armed: bool,
    permit: Option<ReapPermit>,
}

static LIVE_RUNNERS: AtomicUsize = AtomicUsize::new(0);

struct ReapPermit;

impl ReapPermit {
    fn reserve() -> Result<Self, io::Error> {
        LIVE_RUNNERS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < REAPER_CAPACITY).then_some(count + 1)
            })
            .map_err(|_| {
                io::Error::new(io::ErrorKind::WouldBlock, "runner cleanup capacity full")
            })?;
        Ok(Self)
    }
}

impl Drop for ReapPermit {
    fn drop(&mut self) {
        LIVE_RUNNERS.fetch_sub(1, Ordering::AcqRel);
    }
}

struct ReapJob {
    child: Child,
    _permit: ReapPermit,
}

impl RunnerChild {
    fn spawn(path: &Path, caps: Limits, abi_caps: AbiCaps) -> Result<Self, io::Error> {
        reaper_sender()?;
        let permit = ReapPermit::reserve()?;
        let caps = serde_json::to_string(&caps).map_err(io::Error::other)?;
        let mut command = Command::new(path);
        command
            .arg("--operator-caps-json")
            .arg(caps)
            .arg("--host-calls")
            .arg(abi_caps.host_calls.to_string())
            .arg("--log-bytes")
            .arg(abi_caps.log_bytes.to_string())
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command.spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("missing child stdin"))?;
        Ok(Self {
            child: Some(child),
            stdin: Some(stdin),
            armed: true,
            permit: Some(permit),
        })
    }

    fn write_bounded(
        &mut self,
        bytes: Vec<u8>,
        deadline: Instant,
        broker: &dyn DispatchBroker,
    ) -> Result<(), SupervisorError> {
        let mut stdin = self
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("child stdin is closed"))?;
        let (written_tx, written_rx) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name("effectlatch-runner-input".into())
            .spawn(move || {
                let result = stdin.write_all(&bytes).and_then(|_| stdin.flush());
                let _ = written_tx.send((stdin, result));
            })?;
        loop {
            match broker.lease_state() {
                LeaseState::Current => {}
                LeaseState::Cancelled => return Err(SupervisorError::Cancelled),
                LeaseState::Lost => return Err(SupervisorError::LeaseLost),
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(SupervisorError::Deadline);
            }
            match written_rx.recv_timeout(remaining.min(LEASE_POLL)) {
                Ok((stdin, result)) => {
                    self.stdin = Some(stdin);
                    return Ok(result?);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::other("runner input writer exited").into());
                }
            }
        }
    }

    fn take_stdout(&mut self) -> Result<std::process::ChildStdout, io::Error> {
        self.child
            .as_mut()
            .ok_or_else(|| io::Error::other("runner child already reaped"))?
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("missing child stdout"))
    }

    fn wait_bounded(&mut self, invocation_deadline: Instant) -> Result<ExitStatus, io::Error> {
        let cleanup_deadline = Instant::now()
            .checked_add(CLEANUP_WAIT)
            .ok_or_else(|| io::Error::other("clock overflow"))?;
        let deadline = invocation_deadline.min(cleanup_deadline);
        loop {
            if Instant::now() >= deadline {
                self.kill_tree();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "runner did not exit before its invocation deadline",
                ));
            }
            if let Some(status) = self
                .child
                .as_mut()
                .ok_or_else(|| io::Error::other("runner child already reaped"))?
                .try_wait()?
            {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                self.kill_tree();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "runner did not exit after its finish frame",
                ));
            }
            thread::sleep(EXIT_POLL.min(deadline.saturating_duration_since(Instant::now())));
        }
    }

    fn disarm(&mut self) -> Result<(), io::Error> {
        // A successful finish only proves the runner exited. A compromised
        // runner could have left another process in its group, so clean up the
        // group before dropping the supervision guard.
        #[cfg(target_os = "linux")]
        self.kill_process_group()?;
        self.armed = false;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn kill_process_group(&self) -> Result<(), io::Error> {
        use rustix::{
            io::Errno,
            process::{Pid, Signal, kill_process_group},
        };

        let raw = i32::try_from(
            self.child
                .as_ref()
                .ok_or_else(|| io::Error::other("runner child already reaped"))?
                .id(),
        )
        .map_err(|_| io::Error::other("runner process id exceeds OS range"))?;
        let group =
            Pid::from_raw(raw).ok_or_else(|| io::Error::other("runner process id is zero"))?;
        match kill_process_group(group, Signal::KILL) {
            Ok(()) | Err(Errno::SRCH) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn kill_tree(&mut self) {
        self.stdin.take();
        #[cfg(target_os = "linux")]
        let _ = self.kill_process_group();
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            if !matches!(child.try_wait(), Ok(Some(_))) {
                let permit = self.permit.take().expect("live runner owns cleanup permit");
                queue_reap(ReapJob {
                    child,
                    _permit: permit,
                });
            }
        }
    }
}

fn reaper_sender() -> Result<&'static mpsc::SyncSender<ReapJob>, io::Error> {
    static REAPER: OnceLock<Result<mpsc::SyncSender<ReapJob>, String>> = OnceLock::new();
    let sender = REAPER.get_or_init(|| {
        let (tx, rx) = mpsc::sync_channel(REAPER_CAPACITY);
        thread::Builder::new()
            .name("effectlatch-runner-reaper".into())
            .spawn(move || {
                let mut active: Vec<ReapJob> = Vec::with_capacity(REAPER_CAPACITY);
                loop {
                    if active.len() < REAPER_CAPACITY {
                        match rx.recv_timeout(EXIT_POLL) {
                            Ok(job) => active.push(job),
                            Err(mpsc::RecvTimeoutError::Timeout) => {}
                            Err(mpsc::RecvTimeoutError::Disconnected) if active.is_empty() => break,
                            Err(mpsc::RecvTimeoutError::Disconnected) => {}
                        }
                    } else {
                        thread::sleep(EXIT_POLL);
                    }
                    active.retain_mut(|job| !matches!(job.child.try_wait(), Ok(Some(_))));
                }
            })
            .map(|_| tx)
            .map_err(|error| error.to_string())
    });
    sender
        .as_ref()
        .map_err(|error| io::Error::other(error.clone()))
}

fn queue_reap(job: ReapJob) {
    // Every child reserves one of REAPER_CAPACITY permits before spawn, so a
    // live child cannot find a full queue. The worker has no panic path. If
    // either invariant breaks, fail closed instead of dropping the only
    // Child handle or blocking the invocation deadline indefinitely.
    let sender = reaper_sender().expect("reaper initialized before child spawn");
    if sender.try_send(job).is_err() {
        eprintln!("effectlatch: runner reaper invariant failed");
        std::process::abort();
    }
}

impl Drop for RunnerChild {
    fn drop(&mut self) {
        if self.armed {
            self.kill_tree();
        }
    }
}
