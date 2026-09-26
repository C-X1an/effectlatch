//! Authenticated HTTP admission boundary. Tenant identity comes exclusively
//! from the operator-owned principal mapping.
mod wasm;

use crate::{
    auth::{Principal, Principals},
    config, grants, scheduler,
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Extension, Request, State, rejection::BytesRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use effectlatch_domain::{Limits, hash, types::RunCreate};
use effectlatch_store::{AdmissionKind, Error as StoreError, PutModule, RunRecord, Store};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct ApiState {
    pub(crate) store: Arc<Store>,
    caps: Limits,
    max_pending_global: u64,
    max_pending_tenant: u64,
    pub(crate) grant_bounds: grants::Bounds,
    pub(crate) lease_ms: u64,
    pub(crate) max_active_global: u8,
    pub(crate) max_active_per_tenant: u8,
    pub(crate) max_attempts: u8,
}

impl ApiState {
    pub fn new(store: Arc<Store>, configuration: &config::Config) -> Self {
        let limits = &configuration.limits;
        Self {
            store,
            caps: Limits {
                fuel: limits.fuel,
                memory_bytes: limits.memory_bytes,
                wall_ms: limits.wall_ms,
                max_effects: limits.max_effects,
            },
            max_pending_global: limits.max_pending_global,
            max_pending_tenant: limits.max_pending_per_tenant,
            grant_bounds: grants::Bounds::from_config(&configuration.adapters),
            lease_ms: limits.lease_ms,
            max_active_global: limits.max_active_global as u8,
            max_active_per_tenant: limits.max_active_per_tenant as u8,
            max_attempts: limits.max_attempts as u8,
        }
    }
}

pub fn routes(
    state: ApiState,
    principals: Arc<Principals>,
    max_json_bytes: usize,
    max_module_bytes: usize,
) -> Router {
    let modules = Router::new()
        .route("/v1/modules", post(upload_module))
        .layer(DefaultBodyLimit::max(max_module_bytes));
    let runs = Router::new()
        .route("/v1/runs", post(create_run))
        .layer(DefaultBodyLimit::max(max_json_bytes));
    let grants = Router::new()
        .route("/v1/grants", post(grants::create_root))
        .route("/v1/grants/{id}/children", post(grants::create_child))
        .route("/v1/grants/{id}", axum::routing::get(grants::get))
        .route("/v1/grants/{id}/revoke", post(grants::revoke))
        .layer(DefaultBodyLimit::max(max_json_bytes));
    modules
        .merge(runs)
        .merge(grants)
        .merge(scheduler::routes(max_json_bytes))
        .layer(middleware::from_fn_with_state(principals, authenticate))
        .with_state(state)
}

#[derive(Serialize)]
struct ModuleResponse {
    digest: String,
    size_bytes: usize,
    abi_version: u8,
}

async fn upload_module(
    State(state): State<ApiState>,
    Extension(principal): Extension<Principal>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let Some(content_type) = headers.get(header::CONTENT_TYPE) else {
        return error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "INVALID_MEDIA_TYPE",
            "Expected application/wasm",
            false,
        );
    };
    if content_type.as_bytes() != b"application/wasm" {
        return error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "INVALID_MEDIA_TYPE",
            "Expected application/wasm",
            false,
        );
    }
    let tenant = match principal.tenant() {
        Ok(tenant) => tenant,
        Err(_) => {
            return error(
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                "Role is not permitted",
                false,
            );
        }
    };
    let body = match body {
        Ok(body) => body,
        Err(rejection) => {
            let status = rejection.status();
            return error(
                status,
                if status == StatusCode::PAYLOAD_TOO_LARGE {
                    "BODY_TOO_LARGE"
                } else {
                    "INVALID_BODY"
                },
                "Module body is invalid",
                false,
            );
        }
    };
    if wasm::validate(&body).is_err() {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "INVALID_MODULE",
            "Module does not implement EffectLatch ABI v1",
            false,
        );
    }
    let digest: [u8; 32] = Sha256::digest(&body).into();
    match state.store.put_module(tenant, &digest, &body).await {
        Ok(kind) => {
            let status = if kind == PutModule::Created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            };
            (
                status,
                Json(ModuleResponse {
                    digest: hash::hex(&digest),
                    size_bytes: body.len(),
                    abi_version: 1,
                }),
            )
                .into_response()
        }
        Err(_) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "STORE_UNAVAILABLE",
            "Module could not be stored",
            true,
        ),
    }
}

#[derive(Serialize)]
struct EffectView {
    ordinal: i32,
    state: String,
    request_hash: String,
    provider_key: String,
    send_attempts: i32,
}

#[derive(Serialize)]
pub(crate) struct RunView {
    id: Uuid,
    state: String,
    module_digest: String,
    grant_id: Uuid,
    created_at: String,
    updated_at: String,
    lease_epoch: i64,
    attempt: i32,
    cancel_requested: bool,
    output_b64: Option<String>,
    error_code: Option<String>,
    effects: Vec<EffectView>,
}

impl From<RunRecord> for RunView {
    fn from(run: RunRecord) -> Self {
        Self {
            id: run.id,
            state: run.state,
            module_digest: hash::hex(&run.module_digest),
            grant_id: run.grant_id,
            created_at: run.created_at,
            updated_at: run.updated_at,
            lease_epoch: run.lease_epoch,
            attempt: run.attempt,
            cancel_requested: run.cancel_requested,
            output_b64: run.output.map(|bytes| STANDARD.encode(bytes)),
            error_code: run.error_code,
            effects: run
                .effects
                .into_iter()
                .map(|effect| EffectView {
                    ordinal: effect.ordinal,
                    state: effect.state,
                    request_hash: hash::hex(&effect.request_hash),
                    provider_key: effect.provider_key,
                    send_attempts: effect.send_attempts,
                })
                .collect(),
        }
    }
}

async fn create_run(
    State(state): State<ApiState>,
    Extension(principal): Extension<Principal>,
    headers: HeaderMap,
    payload: Result<Json<RunCreate>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let tenant = match principal.tenant() {
        Ok(tenant) => tenant,
        Err(_) => {
            return error(
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                "Role is not permitted",
                false,
            );
        }
    };
    let values: Vec<_> = headers.get_all("idempotency-key").iter().collect();
    let key = match values.as_slice() {
        [value] => match value.to_str() {
            Ok(value)
                if !value.is_empty()
                    && value.len() <= 128
                    && value.bytes().all(|byte| byte.is_ascii_graphic()) =>
            {
                value
            }
            _ => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "INVALID_IDEMPOTENCY_KEY",
                    "Idempotency-Key must be 1..128 visible ASCII bytes",
                    false,
                );
            }
        },
        _ => {
            return error(
                StatusCode::BAD_REQUEST,
                "INVALID_IDEMPOTENCY_KEY",
                "Exactly one Idempotency-Key is required",
                false,
            );
        }
    };
    let create = match payload {
        Ok(Json(create)) => create,
        Err(rejection) => {
            let status = rejection.status();
            return error(
                status,
                if status == StatusCode::PAYLOAD_TOO_LARGE {
                    "BODY_TOO_LARGE"
                } else if status == StatusCode::UNSUPPORTED_MEDIA_TYPE {
                    "INVALID_MEDIA_TYPE"
                } else {
                    "INVALID_JSON"
                },
                "Run body is invalid",
                false,
            );
        }
    };
    let request = match create.normalize(state.caps) {
        Ok(request) => request,
        Err(_) => {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "INVALID_RUN",
                "Run request is invalid",
                false,
            );
        }
    };
    if !principal.permits_grant(tenant, request.grant_id) {
        return error(
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "Grant is not permitted",
            false,
        );
    }
    match state
        .store
        .admit_run(
            tenant,
            key,
            &request,
            state.max_pending_global,
            state.max_pending_tenant,
        )
        .await
    {
        Ok(admission) => {
            let status = if admission.kind == AdmissionKind::Created {
                StatusCode::ACCEPTED
            } else {
                StatusCode::OK
            };
            (status, Json(RunView::from(admission.run))).into_response()
        }
        Err(StoreError::IdempotencyConflict) => error(
            StatusCode::CONFLICT,
            "IDEMPOTENCY_CONFLICT",
            "Idempotency-Key is bound to another request",
            false,
        ),
        Err(StoreError::CapacityExhausted) => {
            let mut response = error(
                StatusCode::TOO_MANY_REQUESTS,
                "QUEUE_FULL",
                "Pending run capacity is exhausted",
                true,
            );
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
            response
        }
        Err(StoreError::ModuleNotFound) => error(
            StatusCode::NOT_FOUND,
            "MODULE_NOT_FOUND",
            "Module does not exist",
            false,
        ),
        Err(StoreError::GrantDenied) => error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "GRANT_DENIED",
            "Grant is unavailable",
            false,
        ),
        Err(_) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "STORE_UNAVAILABLE",
            "Run could not be admitted",
            true,
        ),
    }
}

pub(crate) fn error(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    retryable: bool,
) -> Response {
    (
        status,
        Json(json!({"error":{
            "code":code,
            "message":message,
            "request_id":Uuid::new_v4().to_string(),
            "retryable":retryable,
            "details":{}
        }})),
    )
        .into_response()
}

/// Reject ambiguous repeated credentials; only the operator mapping creates the
/// principal extension consumed by handlers. Client identity text is ignored.
pub async fn authenticate(
    State(principals): State<Arc<Principals>>,
    mut request: Request,
    next: Next,
) -> Response {
    let mut credentials = request.headers().get_all(header::AUTHORIZATION).iter();
    let credential = credentials.next().and_then(|value| value.to_str().ok());
    let principal = if credentials.next().is_none() {
        credential
            .and_then(|value| principals.authenticate(value).ok())
            .cloned()
    } else {
        None
    };
    match principal {
        Some(principal) => {
            request.extensions_mut().insert(principal);
            next.run(request).await
        }
        None => error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "Invalid credential",
            false,
        ),
    }
}
