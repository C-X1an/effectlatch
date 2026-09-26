//! Worker-only lease RPC. Authentication supplies the worker identity and
//! tenant allowlist; request fields can only confirm, never expand them.
use crate::{
    api::{self, ApiState},
    auth::{Authority, Principal},
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Extension, Path, State, rejection::JsonRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use effectlatch_domain::hash;
use effectlatch_store::{
    Error as StoreError,
    scheduler::{ClaimPolicy, ReapPolicy},
};
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeSet;
use std::{sync::Arc, time::Duration};
use tokio::sync::watch;
use uuid::Uuid;

pub fn routes(max_json_bytes: usize) -> Router<ApiState> {
    Router::new()
        .route("/internal/v1/claim", post(claim))
        .route("/internal/v1/runs/{id}/heartbeat", post(heartbeat))
        .route("/internal/v1/runs/{id}/started", post(started))
        .route("/internal/v1/runs/{id}/finish", post(finish))
        .layer(DefaultBodyLimit::max(max_json_bytes))
}

/// Sweep a bounded batch each tick; database failures are retried only after
/// the configured interval. Shutdown stops future sweeps and is bounded by
/// the caller, which can abort a stuck database request after its drain time.
pub async fn sweep(
    store: Arc<effectlatch_store::Store>,
    policy: ReapPolicy,
    sweep_ms: u64,
    mut stop: watch::Receiver<bool>,
) {
    let mut ticks = tokio::time::interval(Duration::from_millis(sweep_ms));
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() { break; }
            }
            _ = ticks.tick() => {
                for _ in 0..64 {
                    match store.reap_one(policy).await {
                        Ok(Some(_)) => {},
                        Ok(None) => break,
                        Err(error) => {
                            eprintln!("lease sweep failed: {error}");
                            break;
                        }
                    }
                }
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimRequest {
    worker_id: String,
    available_slots: u8,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseRequest {
    worker_id: String,
    lease_epoch: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FinishRequest {
    worker_id: String,
    lease_epoch: i64,
    output_b64: Option<String>,
    error_code: Option<String>,
}

fn worker_tenants<'a>(principal: &'a Principal, worker_id: &str) -> Result<&'a BTreeSet<Uuid>, ()> {
    match &principal.authority {
        Authority::Worker {
            worker_id: configured,
            tenants,
        } if configured == worker_id => Ok(tenants),
        _ => Err(()),
    }
}

fn bad_json(_: JsonRejection) -> Response {
    api::error(
        StatusCode::BAD_REQUEST,
        "INVALID_JSON",
        "Worker request is invalid",
        false,
    )
}

fn forbidden() -> Response {
    api::error(
        StatusCode::FORBIDDEN,
        "FORBIDDEN",
        "Worker is not permitted",
        false,
    )
}

fn store_error(error: StoreError) -> Response {
    match error {
        StoreError::RunNotFound => api::error(
            StatusCode::NOT_FOUND,
            "RUN_NOT_FOUND",
            "Run does not exist",
            false,
        ),
        StoreError::LeaseConflict => api::error(
            StatusCode::CONFLICT,
            "LEASE_CONFLICT",
            "Lease is stale, expired or incompatible",
            false,
        ),
        StoreError::Configuration(_) => api::error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "INVALID_LEASE_REQUEST",
            "Lease request is invalid",
            false,
        ),
        _ => api::error(
            StatusCode::SERVICE_UNAVAILABLE,
            "STORE_UNAVAILABLE",
            "Lease operation unavailable",
            true,
        ),
    }
}

async fn claim(
    State(state): State<ApiState>,
    Extension(principal): Extension<Principal>,
    request: Result<Json<ClaimRequest>, JsonRejection>,
) -> Response {
    let Json(request) = match request {
        Ok(request) => request,
        Err(error) => return bad_json(error),
    };
    let tenants = match worker_tenants(&principal, &request.worker_id) {
        Ok(tenants) => tenants,
        Err(()) => return forbidden(),
    };
    let tenants: Vec<_> = tenants.iter().copied().collect();
    match state
        .store
        .claim_run(
            &request.worker_id,
            &tenants,
            request.available_slots,
            ClaimPolicy {
                max_active_global: state.max_active_global,
                max_active_per_tenant: state.max_active_per_tenant,
                max_attempts: state.max_attempts,
                lease_ms: state.lease_ms,
            },
        )
        .await
    {
        Ok(Some(lease)) => {
            let limits = match serde_json::from_str::<serde_json::Value>(&lease.limits_json) {
                Ok(limits) => limits,
                Err(_) => {
                    return api::error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "STORE_UNAVAILABLE",
                        "Stored limits are invalid",
                        false,
                    );
                }
            };
            (
                StatusCode::OK,
                Json(json!({"lease":{
                    "run_id":lease.run,
                    "epoch":lease.epoch,
                    "expires_at":lease.expires_at,
                    "module_digest":hash::hex(&lease.module_digest),
                    "module_b64":STANDARD.encode(lease.module),
                    "input_b64":STANDARD.encode(lease.input),
                    "limits":limits
                }})),
            )
                .into_response()
        }
        Ok(None) => (StatusCode::OK, Json(json!({"lease":null}))).into_response(),
        Err(error) => store_error(error),
    }
}

async fn heartbeat(
    State(state): State<ApiState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
    request: Result<Json<LeaseRequest>, JsonRejection>,
) -> Response {
    let Json(request) = match request {
        Ok(value) => value,
        Err(error) => return bad_json(error),
    };
    let tenants = match worker_tenants(&principal, &request.worker_id) {
        Ok(value) => value,
        Err(()) => return forbidden(),
    };
    let tenants: Vec<_> = tenants.iter().copied().collect();
    match state
        .store
        .heartbeat_run(
            id,
            &request.worker_id,
            &tenants,
            request.lease_epoch,
            state.lease_ms,
        )
        .await
    {
        Ok(result) => (
            StatusCode::OK,
            Json(
                json!({"expires_at":result.expires_at,"cancel_requested":result.cancel_requested}),
            ),
        )
            .into_response(),
        Err(error) => store_error(error),
    }
}

async fn started(
    State(state): State<ApiState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
    request: Result<Json<LeaseRequest>, JsonRejection>,
) -> Response {
    let Json(request) = match request {
        Ok(value) => value,
        Err(error) => return bad_json(error),
    };
    let tenants = match worker_tenants(&principal, &request.worker_id) {
        Ok(value) => value,
        Err(()) => return forbidden(),
    };
    let tenants: Vec<_> = tenants.iter().copied().collect();
    match state
        .store
        .mark_run_started(id, &request.worker_id, &tenants, request.lease_epoch)
        .await
    {
        Ok(()) => (StatusCode::OK, Json(json!({"state":"running"}))).into_response(),
        Err(error) => store_error(error),
    }
}

async fn finish(
    State(state): State<ApiState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<Uuid>,
    request: Result<Json<FinishRequest>, JsonRejection>,
) -> Response {
    let Json(request) = match request {
        Ok(value) => value,
        Err(error) => return bad_json(error),
    };
    let tenants = match worker_tenants(&principal, &request.worker_id) {
        Ok(value) => value,
        Err(()) => return forbidden(),
    };
    let tenants: Vec<_> = tenants.iter().copied().collect();
    let output = match request.output_b64 {
        Some(encoded) => match STANDARD.decode(&encoded) {
            Ok(decoded) if decoded.len() <= 65_536 && STANDARD.encode(&decoded) == encoded => {
                Some(decoded)
            }
            _ => {
                return api::error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "INVALID_OUTPUT",
                    "Output must be canonical bounded base64",
                    false,
                );
            }
        },
        None => None,
    };
    match state
        .store
        .finish_run(
            id,
            &request.worker_id,
            &tenants,
            request.lease_epoch,
            output.as_deref(),
            request.error_code.as_deref(),
        )
        .await
    {
        Ok(run) => (StatusCode::OK, Json(api::RunView::from(run))).into_response(),
        Err(error) => store_error(error),
    }
}
