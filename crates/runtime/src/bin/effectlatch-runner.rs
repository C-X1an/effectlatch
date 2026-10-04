use std::{
    env,
    io::{self, Write},
    process,
    sync::mpsc,
    thread,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use effectlatch_domain::Limits;
use effectlatch_runtime::{
    abi::{AbiCaps, AbiCode, AbiError, DispatchFailure, EffectDispatcher, execute_abi},
    engine::BoundedEngine,
    ipc::{
        ChildFrame, EffectResponse, EffectResponseFrame, MESSAGE_FRAME_BYTES, ProtocolError,
        read_frame, read_start, write_frame,
    },
};
use thiserror::Error;

const PARENT_GONE_EXIT: i32 = 70;

#[derive(Debug, Error)]
enum RunnerError {
    #[error("invalid runner arguments")]
    Arguments,
    #[error("runner inherited an environment entry")]
    Environment,
    #[error("runner inherited a non-protocol descriptor")]
    Descriptor,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}

fn main() {
    if run().is_err() {
        process::exit(1);
    }
}

fn run() -> Result<(), RunnerError> {
    let (operator_caps, abi_caps) = parse_operator_caps()?;
    if env::vars_os().next().is_some() {
        return Err(RunnerError::Environment);
    }
    verify_descriptor_allowlist()?;

    let start = {
        let stdin = io::stdin();
        read_start(&mut stdin.lock())?
    };
    let module = STANDARD
        .decode(&start.module_b64)
        .map_err(|_| ProtocolError::Message)?;
    let input = STANDARD
        .decode(&start.input_b64)
        .map_err(|_| ProtocolError::Message)?;

    let (responses_tx, responses_rx) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("effectlatch-parent-input".into())
        .spawn(move || {
            let stdin = io::stdin();
            let mut stdin = stdin.lock();
            loop {
                let response =
                    read_frame::<_, EffectResponseFrame>(&mut stdin, MESSAGE_FRAME_BYTES).and_then(
                        |frame| {
                            frame.check()?;
                            Ok(frame)
                        },
                    );
                match response {
                    Ok(response) => {
                        if responses_tx.send(response).is_err() {
                            process::exit(PARENT_GONE_EXIT);
                        }
                    }
                    Err(_) => process::exit(PARENT_GONE_EXIT),
                }
            }
        })?;

    let (events_tx, events_rx) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("effectlatch-wasm".into())
        .spawn(move || {
            let result = execute(
                start,
                module,
                input,
                operator_caps,
                abi_caps,
                events_tx.clone(),
                responses_rx,
            );
            let _ = events_tx.send(WorkerEvent::Finished(result));
        })?;

    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    while let Ok(event) = events_rx.recv() {
        match event {
            WorkerEvent::Frame(frame) => write_frame(&mut stdout, &frame, MESSAGE_FRAME_BYTES)?,
            WorkerEvent::Finished(Ok(outcome)) => {
                for message in outcome.logs {
                    write_frame(
                        &mut stdout,
                        &ChildFrame::Log {
                            version: 1,
                            message,
                        },
                        MESSAGE_FRAME_BYTES,
                    )?;
                }
                write_frame(
                    &mut stdout,
                    &ChildFrame::Finish {
                        version: 1,
                        output_b64: outcome.output.map(|bytes| STANDARD.encode(bytes)),
                        error_code: None,
                    },
                    MESSAGE_FRAME_BYTES,
                )?;
                stdout.flush()?;
                return Ok(());
            }
            WorkerEvent::Finished(Err(error)) => {
                write_frame(
                    &mut stdout,
                    &ChildFrame::Finish {
                        version: 1,
                        output_b64: None,
                        error_code: Some(abi_error_code(&error).into()),
                    },
                    MESSAGE_FRAME_BYTES,
                )?;
                stdout.flush()?;
                return Ok(());
            }
        }
    }
    Err(RunnerError::Io(io::Error::other("worker channel closed")))
}

fn parse_operator_caps() -> Result<(Limits, AbiCaps), RunnerError> {
    let mut args = env::args_os();
    let _executable = args.next().ok_or(RunnerError::Arguments)?;
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--operator-caps-json")) {
        return Err(RunnerError::Arguments);
    }
    let raw = args.next().ok_or(RunnerError::Arguments)?;
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--host-calls")) {
        return Err(RunnerError::Arguments);
    }
    let host_calls = args
        .next()
        .and_then(|value| value.to_str().and_then(|text| text.parse::<u32>().ok()))
        .ok_or(RunnerError::Arguments)?;
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--log-bytes")) {
        return Err(RunnerError::Arguments);
    }
    let log_bytes = args
        .next()
        .and_then(|value| value.to_str().and_then(|text| text.parse::<usize>().ok()))
        .ok_or(RunnerError::Arguments)?;
    if args.next().is_some() {
        return Err(RunnerError::Arguments);
    }
    let caps: Limits = serde_json::from_str(raw.to_str().ok_or(RunnerError::Arguments)?)
        .map_err(|_| RunnerError::Arguments)?;
    let caps = caps.validate(caps).map_err(|_| RunnerError::Arguments)?;
    let abi_caps = AbiCaps {
        host_calls,
        log_bytes,
    }
    .validate()
    .map_err(|_| RunnerError::Arguments)?;
    Ok((caps, abi_caps))
}

#[cfg(target_os = "linux")]
fn verify_descriptor_allowlist() -> Result<(), RunnerError> {
    let entries = std::fs::read_dir("/proc/self/fd")?;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(fd) = name.to_str().and_then(|value| value.parse::<u32>().ok()) else {
            return Err(RunnerError::Descriptor);
        };
        if fd <= 2 {
            continue;
        }
        // read_dir itself owns one descriptor whose target is /proc/<pid>/fd.
        let target = std::fs::read_link(entry.path())?;
        let own_fd_directory =
            target.starts_with("/proc") && target.file_name() == Some(std::ffi::OsStr::new("fd"));
        if !own_fd_directory {
            return Err(RunnerError::Descriptor);
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn verify_descriptor_allowlist() -> Result<(), RunnerError> {
    Err(RunnerError::Descriptor)
}

enum WorkerEvent {
    Frame(ChildFrame),
    Finished(Result<effectlatch_runtime::abi::AbiOutcome, AbiError>),
}

fn execute(
    start: effectlatch_runtime::ipc::StartFrame,
    module: Vec<u8>,
    input: Vec<u8>,
    operator_caps: Limits,
    abi_caps: AbiCaps,
    events: mpsc::SyncSender<WorkerEvent>,
    responses: mpsc::Receiver<EffectResponseFrame>,
) -> Result<effectlatch_runtime::abi::AbiOutcome, AbiError> {
    let engine = BoundedEngine::new()?;
    let module = engine.compile(&module)?;
    execute_abi(
        &engine,
        &module,
        input,
        start.limits,
        operator_caps,
        abi_caps,
        Box::new(IpcDispatcher {
            next_id: 1,
            events,
            responses,
        }),
    )
}

struct IpcDispatcher {
    next_id: u64,
    events: mpsc::SyncSender<WorkerEvent>,
    responses: mpsc::Receiver<EffectResponseFrame>,
}

impl EffectDispatcher for IpcDispatcher {
    fn dispatch(
        &mut self,
        request: effectlatch_domain::types::EffectRequest,
    ) -> Result<Vec<u8>, DispatchFailure> {
        let message_id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(DispatchFailure::Unavailable)?;
        self.events
            .send(WorkerEvent::Frame(ChildFrame::EffectRequest {
                version: 1,
                message_id,
                request,
            }))
            .map_err(|_| DispatchFailure::Unavailable)?;
        let response = self
            .responses
            .recv()
            .map_err(|_| DispatchFailure::Unavailable)?;
        if response.message_id != message_id {
            return Err(DispatchFailure::Unavailable);
        }
        match response.response {
            EffectResponse::Committed { reply } => {
                serde_json::to_vec(&reply).map_err(|_| DispatchFailure::Unavailable)
            }
            EffectResponse::Failed { code } => match code {
                -3 => Err(DispatchFailure::Policy),
                -4 => Err(DispatchFailure::Unresolved),
                -5 => Err(DispatchFailure::ReplayDivergence),
                _ => Err(DispatchFailure::Unavailable),
            },
        }
    }
}

fn abi_error_code(error: &AbiError) -> &'static str {
    match error {
        AbiError::InputSize => "INPUT_SIZE",
        AbiError::InvalidCaps => "INVALID_CAPS",
        AbiError::Violation(code) => match code {
            AbiCode::InvalidMemory => "INVALID_MEMORY",
            AbiCode::Size => "SIZE",
            AbiCode::Policy => "POLICY",
            AbiCode::Unresolved => "UNRESOLVED",
            AbiCode::ReplayDivergence => "REPLAY_DIVERGED",
            AbiCode::InvalidState => "INVALID_STATE",
            AbiCode::Unavailable => "UNAVAILABLE",
        },
        AbiError::Runtime(_) => "RUNTIME_FAILURE",
        AbiError::StatePoisoned => "STATE_POISONED",
    }
}
