//! Contract framing uses exact bytes and a single NUL domain terminator.
use crate::{
    grants::Authority,
    types::{EffectRequest, NormalizedRun},
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn frame(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}
pub fn run(request: &NormalizedRun) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"effectlatch/run/v1\0");
    hash.update(request.module_digest);
    hash.update(request.grant_id.as_bytes());
    frame(&mut hash, &request.input);
    for value in [
        request.limits.fuel,
        request.limits.memory_bytes,
        request.limits.wall_ms,
        request.limits.max_effects,
    ] {
        hash.update(value.to_be_bytes());
    }
    hash.finalize().into()
}
pub fn effect(request: &EffectRequest) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"effectlatch/effect/v1\0");
    for value in [
        &request.action,
        &request.destination,
        &request.arguments.project,
        &request.arguments.title,
        &request.arguments.body,
    ] {
        frame(&mut hash, value.as_bytes());
    }
    hash.finalize().into()
}
pub fn provider(tenant: Uuid, run: Uuid, ordinal: u64) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"effectlatch/provider/v1\0");
    hash.update(tenant.as_bytes());
    hash.update(run.as_bytes());
    hash.update(ordinal.to_be_bytes());
    hash.finalize().into()
}
pub fn event(
    tenant: Uuid,
    run: Uuid,
    seq: u64,
    previous: &[u8; 32],
    kind: &str,
    payload: &[u8],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"effectlatch/event/v1\0");
    hash.update(tenant.as_bytes());
    hash.update(run.as_bytes());
    hash.update(seq.to_be_bytes());
    hash.update(previous);
    frame(&mut hash, kind.as_bytes());
    frame(&mut hash, payload);
    hash.finalize().into()
}
pub fn checkpoint(tenant: Uuid, run: Uuid, seq: u64, terminal: &[u8; 32]) -> Vec<u8> {
    let mut bytes = b"effectlatch/checkpoint/v1\0".to_vec();
    bytes.extend_from_slice(tenant.as_bytes());
    bytes.extend_from_slice(run.as_bytes());
    bytes.extend_from_slice(&seq.to_be_bytes());
    bytes.extend_from_slice(terminal);
    bytes
}

pub fn grant(parent: Option<Uuid>, authority: &Authority) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"effectlatch/grant/v1\0");
    match parent {
        Some(parent) => {
            hash.update([1]);
            hash.update(parent.as_bytes());
        }
        None => hash.update([0]),
    }
    for values in [
        &authority.actions,
        &authority.destinations,
        &authority.projects,
    ] {
        hash.update((values.len() as u64).to_be_bytes());
        for value in values {
            frame(&mut hash, value.as_bytes());
        }
    }
    hash.update(authority.expires_at_ms.to_be_bytes());
    hash.update(authority.max_effects.to_be_bytes());
    hash.finalize().into()
}

pub fn grant_revocation(grant: Uuid, reason: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"effectlatch/grant-revocation/v1\0");
    hash.update(grant.as_bytes());
    frame(&mut hash, reason.as_bytes());
    hash.finalize().into()
}
