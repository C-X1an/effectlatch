//! Length-prefixed parent/runner protocol. The process supervisor supplies the
//! outer deadline and kills a child on any error returned here.
use std::io::{Read, Write};

use base64::{Engine, engine::general_purpose::STANDARD};
use effectlatch_domain::{Limits, MODULE_BYTES, PAYLOAD_BYTES, types::EffectRequest};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use thiserror::Error;

use crate::abi::EffectReply;

pub const START_FRAME_BYTES: usize = 4 * 1024 * 1024;
pub const MESSAGE_FRAME_BYTES: usize = 128 * 1024;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("pipe IO failed or frame was truncated: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame length exceeds protocol cap")]
    FrameSize,
    #[error("invalid JSON frame: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unknown protocol version or message type")]
    Message,
    #[error("out-of-sequence or mismatched message ID")]
    Sequence,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartFrame {
    pub version: u8,
    #[serde(rename = "type")]
    pub kind: String,
    pub module_b64: String,
    pub input_b64: String,
    pub limits: Limits,
}
impl StartFrame {
    pub fn check(&self) -> Result<(), ProtocolError> {
        if self.version != 1 || self.kind != "start" {
            return Err(ProtocolError::Message);
        }
        canonical_base64(&self.module_b64, MODULE_BYTES)?;
        canonical_base64(&self.input_b64, PAYLOAD_BYTES)?;
        Ok(())
    }
}

fn canonical_base64(value: &str, max_bytes: usize) -> Result<Vec<u8>, ProtocolError> {
    if value.len() > max_bytes.div_ceil(3) * 4 {
        return Err(ProtocolError::FrameSize);
    }
    let decoded = STANDARD.decode(value).map_err(|_| ProtocolError::Message)?;
    if decoded.len() > max_bytes || STANDARD.encode(&decoded) != value {
        return Err(ProtocolError::Message);
    }
    Ok(decoded)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ChildFrame {
    EffectRequest {
        version: u8,
        message_id: u64,
        request: EffectRequest,
    },
    Log {
        version: u8,
        message: String,
    },
    Finish {
        version: u8,
        output_b64: Option<String>,
        error_code: Option<String>,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEffectRequestFrame {
    version: u8,
    #[serde(rename = "type")]
    kind: String,
    message_id: u64,
    request: Box<RawValue>,
}
impl ChildFrame {
    fn version(&self) -> u8 {
        match self {
            Self::EffectRequest { version, .. }
            | Self::Log { version, .. }
            | Self::Finish { version, .. } => *version,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectResponseFrame {
    pub version: u8,
    #[serde(rename = "type")]
    pub kind: String,
    pub message_id: u64,
    pub response: EffectResponse,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum EffectResponse {
    Committed { reply: EffectReply },
    Failed { code: i32 },
}
impl EffectResponseFrame {
    pub fn check(&self) -> Result<(), ProtocolError> {
        if self.version != 1 || self.kind != "effect_response" {
            return Err(ProtocolError::Message);
        }
        if let EffectResponse::Failed { code } = &self.response
            && !(-7..=-3).contains(code)
        {
            return Err(ProtocolError::Message);
        }
        Ok(())
    }
}

/// Reads exactly one frame. The length is rejected before body allocation.
pub fn read_frame<R: Read, T: for<'de> Deserialize<'de>>(
    reader: &mut R,
    maximum: usize,
) -> Result<T, ProtocolError> {
    let body = read_frame_bytes(reader, maximum)?;
    Ok(serde_json::from_slice(&body)?)
}

fn read_frame_bytes<R: Read>(reader: &mut R, maximum: usize) -> Result<Vec<u8>, ProtocolError> {
    let mut header = [0_u8; 4];
    reader.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > maximum {
        return Err(ProtocolError::FrameSize);
    }
    let mut body = vec![0_u8; length];
    reader.read_exact(&mut body)?;
    Ok(body)
}

pub fn write_frame<W: Write, T: Serialize>(
    writer: &mut W,
    frame: &T,
    maximum: usize,
) -> Result<(), ProtocolError> {
    let body = serde_json::to_vec(frame)?;
    if body.is_empty() || body.len() > maximum {
        return Err(ProtocolError::FrameSize);
    }
    let length = u32::try_from(body.len()).map_err(|_| ProtocolError::FrameSize)?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(&body)?;
    writer.flush()?;
    Ok(())
}

pub fn read_start<R: Read>(reader: &mut R) -> Result<StartFrame, ProtocolError> {
    let start: StartFrame = read_frame(reader, START_FRAME_BYTES)?;
    start.check()?;
    Ok(start)
}

pub fn read_child<R: Read>(reader: &mut R) -> Result<ChildFrame, ProtocolError> {
    let body = read_frame_bytes(reader, MESSAGE_FRAME_BYTES)?;
    let kind = serde_json::from_slice::<serde_json::Value>(&body)?
        .get("type")
        .and_then(|value| value.as_str())
        .ok_or(ProtocolError::Message)?
        .to_owned();
    let frame = if kind == "effect_request" {
        let raw: RawEffectRequestFrame = serde_json::from_slice(&body)?;
        if raw.kind != "effect_request" {
            return Err(ProtocolError::Message);
        }
        let version = raw.version;
        let message_id = raw.message_id;
        let request = raw.request;
        let request =
            EffectRequest::parse(request.get().as_bytes()).map_err(|_| ProtocolError::Message)?;
        ChildFrame::EffectRequest {
            version,
            message_id,
            request,
        }
    } else {
        serde_json::from_slice::<ChildFrame>(&body)?
    };
    if frame.version() != 1 {
        return Err(ProtocolError::Message);
    }
    match &frame {
        ChildFrame::EffectRequest { request, .. } => {
            request.validate().map_err(|_| ProtocolError::Message)?
        }
        ChildFrame::Log { message, .. } if message.len() <= 16 * 1024 => {}
        ChildFrame::Finish {
            output_b64,
            error_code,
            ..
        } => {
            if output_b64.is_some() && error_code.is_some() {
                return Err(ProtocolError::Message);
            }
            if let Some(output) = output_b64 {
                canonical_base64(output, PAYLOAD_BYTES)?;
            }
            if error_code.as_ref().is_some_and(|code| {
                code.is_empty()
                    || code.len() > 64
                    || !code.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
            }) {
                return Err(ProtocolError::Message);
            }
        }
        _ => return Err(ProtocolError::Message),
    }
    Ok(frame)
}

/// Parent-side state for one child. A new effect ID is accepted only after the
/// previous response was sent; finish/log cannot interleave an outstanding call.
#[derive(Debug)]
pub struct ParentSequence {
    next_id: u64,
    pending: Option<u64>,
    finished: bool,
    log_bytes: usize,
    log_cap: usize,
    messages: u32,
}
impl ParentSequence {
    pub fn new() -> Self {
        Self {
            next_id: 1,
            pending: None,
            finished: false,
            log_bytes: 0,
            log_cap: 16 * 1024,
            messages: 0,
        }
    }

    pub fn with_log_cap(log_cap: usize) -> Result<Self, ProtocolError> {
        if log_cap == 0 || log_cap > 16 * 1024 {
            return Err(ProtocolError::FrameSize);
        }
        Ok(Self {
            next_id: 1,
            pending: None,
            finished: false,
            log_bytes: 0,
            log_cap,
            messages: 0,
        })
    }

    pub fn observe(&mut self, frame: &ChildFrame) -> Result<(), ProtocolError> {
        self.messages = self.messages.saturating_add(1);
        if self.finished || self.messages > 128 {
            return Err(ProtocolError::Sequence);
        }
        match frame {
            ChildFrame::EffectRequest { message_id, .. }
                if self.pending.is_none() && *message_id == self.next_id =>
            {
                self.pending = Some(*message_id);
                self.next_id = self.next_id.checked_add(1).ok_or(ProtocolError::Sequence)?;
            }
            ChildFrame::Log { message, .. }
                if self.pending.is_none()
                    && message.len() <= self.log_cap.saturating_sub(self.log_bytes) =>
            {
                self.log_bytes += message.len();
            }
            ChildFrame::Finish { .. } if self.pending.is_none() => self.finished = true,
            _ => return Err(ProtocolError::Sequence),
        }
        Ok(())
    }

    pub fn respond(&mut self, response: &EffectResponseFrame) -> Result<(), ProtocolError> {
        response.check()?;
        if self.pending != Some(response.message_id) {
            return Err(ProtocolError::Sequence);
        }
        self.pending = None;
        Ok(())
    }
}
impl Default for ParentSequence {
    fn default() -> Self {
        Self::new()
    }
}
