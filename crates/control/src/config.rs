//! Strict operator configuration. Secrets are loaded through separate files.
use serde::Deserialize;
use std::{collections::BTreeMap, net::SocketAddr};

fn local_fixture_url(value: &str) -> bool {
    let Ok(uri) = value.parse::<axum::http::Uri>() else {
        return false;
    };
    let Some(authority) = uri.authority() else {
        return false;
    };
    let Some(port) = authority.port_u16() else {
        return false;
    };
    uri.scheme_str() == Some("http")
        && ((authority.as_str() == format!("127.0.0.1:{port}") && port != 0)
            || authority.as_str() == "fixture:8790")
        && uri.path() == "/"
        && uri.query().is_none()
}

#[derive(Debug, thiserror::Error)]
#[error("invalid control configuration")]
pub struct ConfigError;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: Server,
    pub limits: Limits,
    pub retention: Retention,
    pub adapters: BTreeMap<String, Adapter>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Server {
    pub bind: SocketAddr,
    pub max_json_bytes: u64,
    pub max_module_bytes: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_pending_global: u64,
    pub max_pending_per_tenant: u64,
    pub max_active_global: u64,
    pub max_active_per_tenant: u64,
    pub max_attempts: u64,
    pub lease_ms: u64,
    pub heartbeat_ms: u64,
    pub sweep_ms: u64,
    pub wall_ms: u64,
    pub memory_bytes: u64,
    pub fuel: u64,
    pub max_effects: u64,
    pub max_host_calls: u64,
    pub max_log_bytes: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Retention {
    pub payload_hours: u64,
    pub metadata_days: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Adapter {
    pub base_url: String,
    pub idempotency: bool,
    pub retention_seconds: u64,
    pub retry_horizon_seconds: u64,
    pub mode: String,
    pub projects: Vec<String>,
    pub namespace: Option<String>,
}

impl Config {
    pub fn parse(bytes: &[u8]) -> Result<Self, ConfigError> {
        if bytes.len() > 65_536 {
            return Err(ConfigError);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| ConfigError)?;
        let value: Self = toml::from_str(text).map_err(|_| ConfigError)?;
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(), ConfigError> {
        let l = &self.limits;
        let bounded = [
            (self.server.max_json_bytes, 131_072),
            (self.server.max_module_bytes, 2_097_152),
            (l.max_pending_global, 1000),
            (l.max_pending_per_tenant, 100),
            (l.max_active_global, 4),
            (l.max_active_per_tenant, 1),
            (l.max_attempts, 3),
            (l.lease_ms, 6000),
            (l.heartbeat_ms, 2000),
            (l.sweep_ms, 1000),
            (l.memory_bytes, 67_108_864),
            (l.max_effects, 8),
            (l.max_host_calls, 64),
            (l.max_log_bytes, 16_384),
            (l.wall_ms, 60_000),
        ];
        if bounded
            .iter()
            .any(|(value, max)| *value == 0 || value > max)
            || l.heartbeat_ms >= l.lease_ms
            || l.max_pending_per_tenant > l.max_pending_global
            || l.max_active_per_tenant > l.max_active_global
            || l.wall_ms == 0
            || l.fuel == 0
            || self.retention.payload_hours != 24
            || self.retention.metadata_days != 30
            || self.adapters.is_empty()
            || self.adapters.len() > 16
        {
            return Err(ConfigError);
        }
        for (alias, adapter) in &self.adapters {
            if !identifier(alias)
                || adapter.base_url.len() > 2048
                || !local_fixture_url(&adapter.base_url)
                || adapter.projects.is_empty()
                || adapter.projects.len() > 16
                || adapter.projects.iter().any(|p| !identifier(p))
                || adapter
                    .projects
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != adapter.projects.len()
                || adapter
                    .namespace
                    .as_ref()
                    .is_some_and(|v| v.len() > 64 || v.is_empty())
            {
                return Err(ConfigError);
            }
            if adapter.idempotency {
                if adapter.mode != "idem"
                    || adapter.retry_horizon_seconds != 82_800
                    || adapter.retention_seconds < 86_400
                {
                    return Err(ConfigError);
                }
            } else if adapter.mode != "nonidem"
                || adapter.retry_horizon_seconds != 0
                || adapter.retention_seconds != 0
            {
                return Err(ConfigError);
            }
        }
        // This scoped product only sends to the local or private-network fixture.
        // The adapter also disables redirects and binds the fixed ticket path.
        Ok(())
    }
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
