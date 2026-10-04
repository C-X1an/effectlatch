use crate::{Limits, MAX_EFFECTS, PAYLOAD_BYTES};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("invalid {0}")]
    Invalid(&'static str),
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn alias(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TicketArguments {
    pub project: String,
    pub title: String,
    pub body: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EffectRequest {
    pub ordinal: u64,
    pub action: String,
    pub destination: String,
    pub arguments: TicketArguments,
}
impl EffectRequest {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.ordinal >= MAX_EFFECTS {
            return Err(ValidationError::Invalid("ordinal"));
        }
        if self.action != "ticket.create" {
            return Err(ValidationError::Invalid("action"));
        }
        if !alias(&self.destination) || !alias(&self.arguments.project) {
            return Err(ValidationError::Invalid("destination/project"));
        }
        let title = &self.arguments.title;
        if title.is_empty() || title.chars().count() > 200 || title.len() > 800 {
            return Err(ValidationError::Invalid("title"));
        }
        if self.arguments.body.len() > 8192 {
            return Err(ValidationError::Invalid("body"));
        }
        Ok(())
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, ValidationError> {
        if bytes.len() > crate::EFFECT_REQUEST_BYTES {
            return Err(ValidationError::Invalid("request size"));
        }
        let request: Self = serde_json::from_slice(bytes)?;
        request.validate()?;
        Ok(request)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunCreate {
    pub module_digest: String,
    pub grant_id: String,
    pub input_b64: String,
    #[serde(default)]
    pub limits: Limits,
}
#[derive(Clone, Debug)]
pub struct NormalizedRun {
    pub module_digest: [u8; 32],
    pub grant_id: Uuid,
    pub input: Vec<u8>,
    pub limits: Limits,
}

pub fn digest_bytes(value: &str) -> Result<[u8; 32], ValidationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ValidationError::Invalid("digest"));
    }
    let mut out = [0; 32];
    for (i, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let nibble = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        out[i] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    Ok(out)
}
impl RunCreate {
    pub fn normalize(self, caps: Limits) -> Result<NormalizedRun, ValidationError> {
        let module_digest = digest_bytes(&self.module_digest)?;
        let grant_id =
            Uuid::parse_str(&self.grant_id).map_err(|_| ValidationError::Invalid("grant_id"))?;
        if grant_id.to_string() != self.grant_id {
            return Err(ValidationError::Invalid("canonical grant_id"));
        }
        if self.input_b64.len() > PAYLOAD_BYTES.div_ceil(3) * 4 {
            return Err(ValidationError::Invalid("input size"));
        }
        let input = STANDARD
            .decode(&self.input_b64)
            .map_err(|_| ValidationError::Invalid("base64"))?;
        if input.len() > PAYLOAD_BYTES || STANDARD.encode(&input) != self.input_b64 {
            return Err(ValidationError::Invalid("canonical base64"));
        }
        let limits = self
            .limits
            .validate(caps)
            .map_err(|_| ValidationError::Invalid("limits"))?;
        Ok(NormalizedRun {
            module_digest,
            grant_id,
            input,
            limits,
        })
    }
}
