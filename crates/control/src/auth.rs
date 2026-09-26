//! Operator-owned principal mapping; request text never supplies authority.
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, io::Read, path::Path};
use subtle::ConstantTimeEq;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid principal configuration")]
    Configuration,
    #[error("principal configuration could not be read")]
    Read(#[source] std::io::Error),
    #[error("invalid credential")]
    Unauthorized,
    #[error("role denied")]
    Forbidden,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authority {
    Owner {
        tenant: Uuid,
    },
    Invoker {
        tenant: Uuid,
        grants: BTreeSet<Uuid>,
    },
    Worker {
        worker_id: String,
        tenants: BTreeSet<Uuid>,
    },
}

#[derive(Debug, Clone)]
pub struct Principal {
    pub id: String,
    pub authority: Authority,
}

impl Principal {
    pub fn owner_tenant(&self) -> Result<Uuid, AuthError> {
        match self.authority {
            Authority::Owner { tenant } => Ok(tenant),
            _ => Err(AuthError::Forbidden),
        }
    }
    pub fn tenant(&self) -> Result<Uuid, AuthError> {
        match &self.authority {
            Authority::Owner { tenant } | Authority::Invoker { tenant, .. } => Ok(*tenant),
            Authority::Worker { .. } => Err(AuthError::Forbidden),
        }
    }
    pub fn permits_grant(&self, tenant: Uuid, grant: Uuid) -> bool {
        match &self.authority {
            Authority::Owner { tenant: own } => *own == tenant,
            Authority::Invoker {
                tenant: own,
                grants,
            } => *own == tenant && grants.contains(&grant),
            Authority::Worker { .. } => false,
        }
    }
    pub fn permits_worker(&self, worker: &str, tenant: Uuid) -> bool {
        matches!(&self.authority, Authority::Worker { worker_id, tenants }
            if worker_id == worker && tenants.contains(&tenant))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    version: u32,
    principals: Vec<Record>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    id: String,
    role: String,
    token_sha256: String,
    tenant_id: Option<String>,
    worker_id: Option<String>,
    #[serde(default)]
    allowed_grants: Vec<String>,
    #[serde(default)]
    allowed_tenants: Vec<String>,
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn canonical_uuid(value: &str) -> Result<Uuid, AuthError> {
    let id = Uuid::parse_str(value).map_err(|_| AuthError::Configuration)?;
    if id.to_string() != value {
        return Err(AuthError::Configuration);
    }
    Ok(id)
}
fn ids(values: &[String]) -> Result<BTreeSet<Uuid>, AuthError> {
    if values.len() > 1024 {
        return Err(AuthError::Configuration);
    }
    let result: BTreeSet<_> = values
        .iter()
        .map(|v| canonical_uuid(v))
        .collect::<Result<_, _>>()?;
    if result.len() != values.len() {
        return Err(AuthError::Configuration);
    }
    Ok(result)
}

/// No Debug implementation: configured credential digests are not log fields.
pub struct Principals(Vec<([u8; 32], Principal)>);
impl Principals {
    /// Startup-only synchronous load from an operator-owned regular file.
    /// Read one byte past the limit to detect growth without unbounded allocation.
    pub fn load(path: &Path) -> Result<Self, AuthError> {
        let metadata = std::fs::metadata(path).map_err(AuthError::Read)?;
        if !metadata.is_file() || metadata.len() > 1_048_576 {
            return Err(AuthError::Configuration);
        }
        let file = std::fs::File::open(path).map_err(AuthError::Read)?;
        if !file.metadata().map_err(AuthError::Read)?.is_file() {
            return Err(AuthError::Configuration);
        }
        let mut bytes = Vec::new();
        file.take(1_048_577)
            .read_to_end(&mut bytes)
            .map_err(AuthError::Read)?;
        Self::parse(&bytes)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, AuthError> {
        if bytes.len() > 1_048_576 {
            return Err(AuthError::Configuration);
        }
        let file: File = serde_json::from_slice(bytes).map_err(|_| AuthError::Configuration)?;
        if file.version != 1 || file.principals.is_empty() || file.principals.len() > 1024 {
            return Err(AuthError::Configuration);
        }
        let mut names = BTreeSet::new();
        let mut hashes = BTreeSet::new();
        let mut entries = Vec::with_capacity(file.principals.len());
        for record in file.principals {
            if !identifier(&record.id)
                || !names.insert(record.id.clone())
                || record.token_sha256.len() != 64
                || !record
                    .token_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(AuthError::Configuration);
            }
            let mut digest = [0; 32];
            for (index, byte) in digest.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&record.token_sha256[index * 2..index * 2 + 2], 16)
                    .map_err(|_| AuthError::Configuration)?;
            }
            if !hashes.insert(digest) {
                return Err(AuthError::Configuration);
            }
            let authority = match record.role.as_str() {
                "owner" | "invoker"
                    if record.worker_id.is_none() && record.allowed_tenants.is_empty() =>
                {
                    let tenant = canonical_uuid(
                        record
                            .tenant_id
                            .as_deref()
                            .ok_or(AuthError::Configuration)?,
                    )?;
                    let grants = ids(&record.allowed_grants)?;
                    if record.role == "owner" {
                        if !grants.is_empty() {
                            return Err(AuthError::Configuration);
                        }
                        Authority::Owner { tenant }
                    } else {
                        Authority::Invoker { tenant, grants }
                    }
                }
                "worker" if record.tenant_id.is_none() && record.allowed_grants.is_empty() => {
                    let worker_id = record.worker_id.ok_or(AuthError::Configuration)?;
                    let tenants = ids(&record.allowed_tenants)?;
                    if !identifier(&worker_id) || tenants.is_empty() {
                        return Err(AuthError::Configuration);
                    }
                    Authority::Worker { worker_id, tenants }
                }
                _ => return Err(AuthError::Configuration),
            };
            entries.push((
                digest,
                Principal {
                    id: record.id,
                    authority,
                },
            ));
        }
        Ok(Self(entries))
    }
    pub fn authenticate(&self, authorization: &str) -> Result<&Principal, AuthError> {
        let token = authorization
            .strip_prefix("Bearer ")
            .ok_or(AuthError::Unauthorized)?;
        if !(32..=256).contains(&token.len()) || !token.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(AuthError::Unauthorized);
        }
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let mut matched = None;
        for (expected, principal) in &self.0 {
            if bool::from(expected.ct_eq(&digest)) {
                matched = Some(principal);
            }
        }
        matched.ok_or(AuthError::Unauthorized)
    }
}
