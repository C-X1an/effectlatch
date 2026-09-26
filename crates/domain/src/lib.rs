//! Pure, credential-free runtime configuration shared by the execution boundary.
//! No operating-system or database capability is exposed by this crate.

use std::fmt;
pub mod hash;
pub mod types;

pub const MODULE_BYTES: usize = 2 * 1024 * 1024;
pub const PAYLOAD_BYTES: usize = 64 * 1024;
pub const LOG_BYTES: usize = 16 * 1024;
pub const EFFECT_REQUEST_BYTES: usize = 16 * 1024;
pub const MAX_EFFECTS: u64 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    pub fuel: u64,
    pub memory_bytes: u64,
    pub wall_ms: u64,
    pub max_effects: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            fuel: 10_000_000,
            memory_bytes: 64 * 1024 * 1024,
            wall_ms: 2_000,
            max_effects: MAX_EFFECTS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    InvalidLimit(&'static str),
    UnsupportedHost,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit(name) => write!(f, "limit {name} must be positive and within operator caps"),
            Self::UnsupportedHost => f.write_str("EffectLatch execution requires Linux x86_64 or a verified Linux ARM64 host; use a Linux VM or Docker on Windows/macOS"),
        }
    }
}
impl std::error::Error for ConfigError {}

impl Limits {
    /// Validate caller limits against a trusted operator configuration.
    /// Fault experiments may increase operator wall time, never the fixed effect cap.
    pub fn validate(self, caps: Self) -> Result<Self, ConfigError> {
        for (name, value, cap) in [
            ("fuel", self.fuel, caps.fuel),
            (
                "memory_bytes",
                self.memory_bytes,
                caps.memory_bytes.min(64 * 1024 * 1024),
            ),
            ("wall_ms", self.wall_ms, caps.wall_ms),
            (
                "max_effects",
                self.max_effects,
                caps.max_effects.min(MAX_EFFECTS),
            ),
        ] {
            if value == 0 || value > cap {
                return Err(ConfigError::InvalidLimit(name));
            }
        }
        Ok(self)
    }
}

/// Capability diagnostic only; a supported architecture is not evidence of testing it.
pub fn require_execution_host(os: &str, arch: &str) -> Result<(), ConfigError> {
    if os == "linux" && matches!(arch, "x86_64" | "aarch64") {
        Ok(())
    } else {
        Err(ConfigError::UnsupportedHost)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_cannot_disable_or_raise_limits() {
        let caps = Limits::default();
        for bad in [
            Limits { fuel: 0, ..caps },
            Limits {
                memory_bytes: 67_108_865,
                ..caps
            },
            Limits {
                wall_ms: 2_001,
                ..caps
            },
            Limits {
                max_effects: 9,
                ..caps
            },
        ] {
            assert!(bad.validate(caps).is_err());
        }
        assert!(
            Limits {
                fuel: 1,
                memory_bytes: 65_536,
                wall_ms: 1,
                max_effects: 1
            }
            .validate(caps)
            .is_ok()
        );
    }

    #[test]
    fn windows_is_diagnosed_instead_of_claiming_isolation() {
        let error = require_execution_host("windows", "x86_64").unwrap_err();
        assert!(error.to_string().contains("Linux"));
        assert!(require_execution_host("linux", "riscv64").is_err());
    }
}
pub mod grants;
pub mod state;
