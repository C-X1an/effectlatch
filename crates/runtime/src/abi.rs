//! Checked guest imports. All guest bytes are copied before a broker call.
use std::sync::{Arc, Mutex};

use effectlatch_domain::{Limits, PAYLOAD_BYTES, types::EffectRequest};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use wasmtime::{Caller, Extern, Linker, Memory};

use crate::engine::{BoundedEngine, RuntimeError, RuntimeStore, ValidatedModule};

pub const MAX_HOST_CALLS: u32 = 64;
pub const LOG_BYTES: usize = 16 * 1024;
pub const EFFECT_REQUEST_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct AbiCaps {
    pub host_calls: u32,
    pub log_bytes: usize,
}
impl AbiCaps {
    pub fn validate(self) -> Result<Self, AbiError> {
        if self.host_calls == 0
            || self.host_calls > MAX_HOST_CALLS
            || self.log_bytes == 0
            || self.log_bytes > LOG_BYTES
        {
            return Err(AbiError::InvalidCaps);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectReply {
    pub ordinal: u64,
    pub state: Committed,
    pub response: TicketResponse,
    pub replayed: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Committed {
    #[serde(rename = "COMMITTED")]
    Committed,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TicketResponse {
    pub ticket_id: String,
    pub project: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum AbiCode {
    InvalidMemory = -1,
    Size = -2,
    Policy = -3,
    Unresolved = -4,
    ReplayDivergence = -5,
    InvalidState = -6,
    Unavailable = -7,
}

#[derive(Clone, Copy, Debug, Error)]
pub enum DispatchFailure {
    #[error("effect denied by policy")]
    Policy,
    #[error("effect outcome unresolved")]
    Unresolved,
    #[error("effect replay diverged")]
    ReplayDivergence,
    #[error("effect service unavailable")]
    Unavailable,
}
impl DispatchFailure {
    fn code(self) -> AbiCode {
        match self {
            Self::Policy => AbiCode::Policy,
            Self::Unresolved => AbiCode::Unresolved,
            Self::ReplayDivergence => AbiCode::ReplayDivergence,
            Self::Unavailable => AbiCode::Unavailable,
        }
    }
}

/// The broker remains authoritative for grant/lease/effect identity. This
/// interface receives an owned, strictly parsed request, never guest memory.
pub trait EffectDispatcher: Send {
    fn dispatch(&mut self, request: EffectRequest) -> Result<Vec<u8>, DispatchFailure>;
}
impl<F> EffectDispatcher for F
where
    F: FnMut(EffectRequest) -> Result<Vec<u8>, DispatchFailure> + Send,
{
    fn dispatch(&mut self, request: EffectRequest) -> Result<Vec<u8>, DispatchFailure> {
        self(request)
    }
}

#[derive(Debug, Error)]
pub enum AbiError {
    #[error("invalid guest input size")]
    InputSize,
    #[error("invalid ABI operator caps")]
    InvalidCaps,
    #[error("guest violated ABI: {0:?}")]
    Violation(AbiCode),
    #[error("runtime failed: {0}")]
    Runtime(#[from] RuntimeError),
    #[error("ABI state poisoned")]
    StatePoisoned,
}

#[derive(Debug)]
pub struct AbiOutcome {
    pub return_code: i32,
    pub output: Option<Vec<u8>>,
    pub logs: Vec<String>,
    pub host_calls: u32,
}

struct State {
    input: Vec<u8>,
    output: Option<Vec<u8>>,
    logs: Vec<String>,
    log_bytes: usize,
    calls: u32,
    caps: AbiCaps,
    next_ordinal: u64,
    max_effects: u64,
    sticky: Option<AbiCode>,
    dispatcher: Box<dyn EffectDispatcher>,
}
type Shared = Arc<Mutex<State>>;
type HostCaller<'a> = Caller<'a, RuntimeStore<Shared>>;

fn fail(state: &mut State, code: AbiCode) -> i32 {
    state.sticky.get_or_insert(code);
    code as i32
}

fn unresolved(state: &mut State) -> Result<i32, wasmtime::Error> {
    fail(state, AbiCode::Unresolved);
    Err(wasmtime::Error::msg("effect outcome unresolved"))
}

fn budget(state: &mut State) -> Result<(), i32> {
    state.calls = state.calls.saturating_add(1);
    if let Some(code) = state.sticky {
        return Err(code as i32);
    }
    if state.output.is_some() {
        return Err(fail(state, AbiCode::InvalidState));
    }
    if state.calls > state.caps.host_calls {
        return Err(fail(state, AbiCode::InvalidState));
    }
    Ok(())
}

fn range(
    caller: &mut HostCaller<'_>,
    ptr: i32,
    len: i32,
) -> Result<(Memory, usize, usize), AbiCode> {
    let length = usize::try_from(len).map_err(|_| AbiCode::Size)?;
    let start = u64::from(ptr as u32);
    let end = start
        .checked_add(length as u64)
        .ok_or(AbiCode::InvalidMemory)?;
    let memory = caller
        .get_export("memory")
        .and_then(Extern::into_memory)
        .ok_or(AbiCode::InvalidMemory)?;
    if end > memory.data_size(&*caller) as u64 {
        return Err(AbiCode::InvalidMemory);
    }
    let start = usize::try_from(start).map_err(|_| AbiCode::InvalidMemory)?;
    Ok((memory, start, length))
}

fn read(caller: &mut HostCaller<'_>, ptr: i32, len: i32) -> Result<Vec<u8>, AbiCode> {
    let (memory, start, length) = range(caller, ptr, len)?;
    let mut bytes = vec![0; length];
    memory
        .read(&*caller, start, &mut bytes)
        .map_err(|_| AbiCode::InvalidMemory)?;
    Ok(bytes)
}

fn install(linker: &mut Linker<RuntimeStore<Shared>>) -> Result<(), RuntimeError> {
    linker.func_wrap(
        "effectlatch_v1",
        "input_len",
        |caller: HostCaller<'_>| -> i32 {
            let shared = caller.data().host().clone();
            let Ok(mut state) = shared.lock() else {
                return AbiCode::Unavailable as i32;
            };
            if let Err(code) = budget(&mut state) {
                return code;
            }
            state.input.len() as i32
        },
    )?;
    linker.func_wrap(
        "effectlatch_v1",
        "input_read",
        |mut caller: HostCaller<'_>, ptr: i32, capacity: i32| -> i32 {
            let shared = caller.data().host().clone();
            let Ok(mut state) = shared.lock() else {
                return AbiCode::Unavailable as i32;
            };
            if let Err(code) = budget(&mut state) {
                return code;
            }
            if capacity < 0 || (capacity as usize) < state.input.len() {
                return fail(&mut state, AbiCode::Size);
            }
            let (memory, start, _) = match range(&mut caller, ptr, capacity) {
                Ok(value) => value,
                Err(code) => return fail(&mut state, code),
            };
            if memory.write(&mut caller, start, &state.input).is_err() {
                return fail(&mut state, AbiCode::InvalidMemory);
            }
            state.input.len() as i32
        },
    )?;
    linker.func_wrap(
        "effectlatch_v1",
        "output_write",
        |mut caller: HostCaller<'_>, ptr: i32, len: i32| -> i32 {
            let shared = caller.data().host().clone();
            let Ok(mut state) = shared.lock() else {
                return AbiCode::Unavailable as i32;
            };
            if let Err(code) = budget(&mut state) {
                return code;
            }
            if state.output.is_some() {
                return fail(&mut state, AbiCode::InvalidState);
            }
            if len < 0 || len as usize > PAYLOAD_BYTES {
                return fail(&mut state, AbiCode::Size);
            }
            let bytes = match read(&mut caller, ptr, len) {
                Ok(bytes) => bytes,
                Err(code) => return fail(&mut state, code),
            };
            state.output = Some(bytes);
            len
        },
    )?;
    linker.func_wrap(
        "effectlatch_v1",
        "log",
        |mut caller: HostCaller<'_>, ptr: i32, len: i32| -> i32 {
            let shared = caller.data().host().clone();
            let Ok(mut state) = shared.lock() else {
                return AbiCode::Unavailable as i32;
            };
            if let Err(code) = budget(&mut state) {
                return code;
            }
            if len < 0 || (len as usize) > state.caps.log_bytes.saturating_sub(state.log_bytes) {
                return fail(&mut state, AbiCode::Size);
            }
            let bytes = match read(&mut caller, ptr, len) {
                Ok(bytes) => bytes,
                Err(code) => return fail(&mut state, code),
            };
            let message = match String::from_utf8(bytes) {
                Ok(message) => message,
                Err(_) => return fail(&mut state, AbiCode::Policy),
            };
            state.log_bytes += len as usize;
            state.logs.push(message);
            len
        },
    )?;
    linker.func_wrap(
        "effectlatch_v1",
        "effect_call",
        |mut caller: HostCaller<'_>,
         req_ptr: i32,
         req_len: i32,
         resp_ptr: i32,
         resp_cap: i32|
         -> Result<i32, wasmtime::Error> {
            let shared = caller.data().host().clone();
            let mut state = shared
                .lock()
                .map_err(|_| wasmtime::Error::msg("ABI state poisoned"))?;
            if let Err(code) = budget(&mut state) {
                return Ok(code);
            }
            if req_len <= 0
                || req_len as usize > EFFECT_REQUEST_BYTES
                || resp_cap < PAYLOAD_BYTES as i32
            {
                return Ok(fail(&mut state, AbiCode::Size));
            }
            // Validate the *full* destination before creating a durable intent.
            if let Err(code) = range(&mut caller, resp_ptr, resp_cap) {
                return Ok(fail(&mut state, code));
            }
            let request_bytes = match read(&mut caller, req_ptr, req_len) {
                Ok(bytes) => bytes,
                Err(code) => return Ok(fail(&mut state, code)),
            };
            let request = match EffectRequest::parse(&request_bytes) {
                Ok(request) => request,
                Err(_) => return Ok(fail(&mut state, AbiCode::Policy)),
            };
            if request.ordinal > state.next_ordinal || request.ordinal >= state.max_effects {
                return Ok(fail(&mut state, AbiCode::Policy));
            }
            let ordinal = request.ordinal;
            let project = request.arguments.project.clone();
            let response = match state.dispatcher.dispatch(request) {
                Ok(response) => response,
                Err(error) => {
                    let code = error.code();
                    fail(&mut state, code);
                    if code == AbiCode::Unresolved {
                        return unresolved(&mut state);
                    }
                    return Ok(code as i32);
                }
            };
            if response.len() > PAYLOAD_BYTES || response.len() > resp_cap as usize {
                return unresolved(&mut state);
            }
            let valid_reply = serde_json::from_slice::<EffectReply>(&response).is_ok_and(|reply| {
                reply.ordinal == ordinal
                    && reply.response.project == project
                    && !reply.response.ticket_id.is_empty()
            });
            if !valid_reply {
                return unresolved(&mut state);
            }
            let (memory, start, _) = match range(&mut caller, resp_ptr, resp_cap) {
                Ok(value) => value,
                Err(_) => return unresolved(&mut state),
            };
            if memory.write(&mut caller, start, &response).is_err() {
                return unresolved(&mut state);
            }
            if ordinal == state.next_ordinal {
                state.next_ordinal += 1;
            }
            Ok(response.len() as i32)
        },
    )?;
    Ok(())
}

pub fn execute_abi(
    engine: &BoundedEngine,
    module: &ValidatedModule,
    input: Vec<u8>,
    requested: Limits,
    operator_caps: Limits,
    abi_caps: AbiCaps,
    dispatcher: Box<dyn EffectDispatcher>,
) -> Result<AbiOutcome, AbiError> {
    if input.len() > PAYLOAD_BYTES {
        return Err(AbiError::InputSize);
    }
    let abi_caps = abi_caps.validate()?;
    let shared = Arc::new(Mutex::new(State {
        input,
        output: None,
        logs: Vec::new(),
        log_bytes: 0,
        calls: 0,
        caps: abi_caps,
        next_ordinal: 0,
        max_effects: requested.max_effects,
        sticky: None,
        dispatcher,
    }));
    let result = engine.execute(module, shared.clone(), requested, operator_caps, install);
    let state = shared.lock().map_err(|_| AbiError::StatePoisoned)?;
    if let Some(code) = state.sticky {
        return Err(AbiError::Violation(code));
    }
    let return_code = result?;
    Ok(AbiOutcome {
        return_code,
        output: state.output.clone(),
        logs: state.logs.clone(),
        host_calls: state.calls,
    })
}
