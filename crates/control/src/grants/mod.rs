//! Owner-managed grant derivation and revocation. The store supplies database
//! time and root-first locks; this boundary supplies operator-configured roots.
use crate::{
    api::{ApiState, error},
    auth::Principal,
    config,
};
use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use effectlatch_domain::grants::{Authority, GrantError};
use effectlatch_store::{Error as StoreError, GrantRecord};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

#[derive(Clone)]
pub struct Bounds {
    actions: BTreeSet<String>,
    projects_by_destination: BTreeMap<String, BTreeSet<String>>,
}

impl Bounds {
    pub fn from_config(adapters: &BTreeMap<String, config::Adapter>) -> Self {
        Self {
            actions: BTreeSet::from(["ticket.create".to_owned()]),
            projects_by_destination: adapters
                .iter()
                .map(|(destination, adapter)| {
                    (
                        destination.clone(),
                        adapter.projects.iter().cloned().collect(),
                    )
                })
                .collect(),
        }
    }

    fn permits(&self, authority: &Authority) -> bool {
        authority.actions.is_subset(&self.actions)
            && authority.destinations.iter().all(|destination| {
                self.projects_by_destination
                    .get(destination)
                    .is_some_and(|projects| authority.projects.is_subset(projects))
            })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantCreate {
    actions: Vec<String>,
    destinations: Vec<String>,
    projects: Vec<String>,
    expires_at: String,
    max_effects: u64,
}

impl GrantCreate {
    fn normalize(self, bounds: &Bounds) -> Result<Authority, GrantError> {
        if self.actions.is_empty()
            || self.actions.len() > 16
            || self.destinations.is_empty()
            || self.destinations.len() > 16
            || self.projects.is_empty()
            || self.projects.len() > 16
        {
            return Err(GrantError::Invalid);
        }
        let action_count = self.actions.len();
        let destination_count = self.destinations.len();
        let project_count = self.projects.len();
        let actions: BTreeSet<_> = self.actions.into_iter().collect();
        let destinations: BTreeSet<_> = self.destinations.into_iter().collect();
        let projects: BTreeSet<_> = self.projects.into_iter().collect();
        if actions.len() != action_count
            || destinations.len() != destination_count
            || projects.len() != project_count
        {
            return Err(GrantError::Invalid);
        }
        let expires =
            OffsetDateTime::parse(&self.expires_at, &Rfc3339).map_err(|_| GrantError::Invalid)?;
        let expires_at_ms = i64::try_from(expires.unix_timestamp_nanos() / 1_000_000)
            .map_err(|_| GrantError::Invalid)?;
        let authority = Authority {
            actions,
            destinations,
            projects,
            expires_at_ms,
            max_effects: self.max_effects,
        };
        authority.validate_shape()?;
        if !bounds.permits(&authority) {
            return Err(GrantError::Escalation);
        }
        Ok(authority)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revoke {
    reason: String,
}

#[derive(Serialize)]
pub struct GrantView {
    id: Uuid,
    parent_id: Option<Uuid>,
    depth: i32,
    actions: Vec<String>,
    destinations: Vec<String>,
    projects: Vec<String>,
    expires_at: String,
    max_effects: i64,
    used_effects: i64,
    remaining_effects: i64,
    revoked_at: Option<String>,
    ancestry: Vec<Uuid>,
}

impl From<GrantRecord> for GrantView {
    fn from(record: GrantRecord) -> Self {
        Self {
            id: record.id,
            parent_id: record.parent_id,
            depth: record.depth,
            actions: record.actions,
            destinations: record.destinations,
            projects: record.projects,
            expires_at: record.expires_at,
            max_effects: record.max_effects,
            used_effects: record.used_effects,
            remaining_effects: record.max_effects.saturating_sub(record.used_effects),
            revoked_at: record.revoked_at,
            ancestry: record.ancestry,
        }
    }
}

#[derive(Serialize)]
struct RevocationView {
    id: Uuid,
    revoked_at: String,
}

fn canonical_id(value: &str) -> Option<Uuid> {
    let id = Uuid::parse_str(value).ok()?;
    if id.to_string() != value {
        return None;
    }
    Some(id)
}

fn not_found() -> Response {
    error(
        StatusCode::NOT_FOUND,
        "GRANT_NOT_FOUND",
        "Grant does not exist",
        false,
    )
}

fn store_error(error_value: StoreError) -> Response {
    match error_value {
        StoreError::GrantNotFound => not_found(),
        StoreError::GrantValidation(_) => error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "INVALID_GRANT",
            "Grant authority is invalid",
            false,
        ),
        _ => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "STORE_UNAVAILABLE",
            "Grant operation could not be completed",
            true,
        ),
    }
}

pub async fn create_root(
    State(state): State<ApiState>,
    Extension(principal): Extension<Principal>,
    payload: Result<Json<GrantCreate>, axum::extract::rejection::JsonRejection>,
) -> Response {
    create(state, principal, None, payload).await
}

pub async fn create_child(
    State(state): State<ApiState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    payload: Result<Json<GrantCreate>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let parent = match canonical_id(&id) {
        Some(id) => id,
        None => return not_found(),
    };
    create(state, principal, Some(parent), payload).await
}

async fn create(
    state: ApiState,
    principal: Principal,
    parent: Option<Uuid>,
    payload: Result<Json<GrantCreate>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let tenant = match principal.owner_tenant() {
        Ok(tenant) => tenant,
        Err(_) => {
            return error(
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                "Owner role is required",
                false,
            );
        }
    };
    let Json(create) = match payload {
        Ok(payload) => payload,
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
                "Grant body is invalid",
                false,
            );
        }
    };
    let authority = match create.normalize(&state.grant_bounds) {
        Ok(authority) => authority,
        Err(_) => {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "INVALID_GRANT",
                "Grant authority is invalid",
                false,
            );
        }
    };
    match state
        .store
        .create_grant(tenant, parent, &principal.id, authority)
        .await
    {
        Ok(record) => (StatusCode::CREATED, Json(GrantView::from(record))).into_response(),
        Err(error_value) => store_error(error_value),
    }
}

pub async fn get(
    State(state): State<ApiState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Response {
    let id = match canonical_id(&id) {
        Some(id) => id,
        None => return not_found(),
    };
    let tenant = match principal.tenant() {
        Ok(tenant) if principal.permits_grant(tenant, id) => tenant,
        _ => return not_found(),
    };
    match state.store.get_grant(tenant, id).await {
        Ok(record) => Json(GrantView::from(record)).into_response(),
        Err(error_value) => store_error(error_value),
    }
}

pub async fn revoke(
    State(state): State<ApiState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    payload: Result<Json<Revoke>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let id = match canonical_id(&id) {
        Some(id) => id,
        None => return not_found(),
    };
    let tenant = match principal.owner_tenant() {
        Ok(tenant) => tenant,
        Err(_) => {
            return error(
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                "Owner role is required",
                false,
            );
        }
    };
    let reason = match payload {
        Ok(Json(revoke))
            if !revoke.reason.is_empty()
                && revoke.reason.len() <= 1024
                && revoke.reason.chars().count() <= 256 =>
        {
            revoke.reason
        }
        Ok(_) => {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "INVALID_REASON",
                "Revocation reason is invalid",
                false,
            );
        }
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
                "Revocation body is invalid",
                false,
            );
        }
    };
    match state
        .store
        .revoke_grant(tenant, id, &principal.id, &reason)
        .await
    {
        Ok(record) => Json(RevocationView {
            id: record.id,
            revoked_at: record.revoked_at,
        })
        .into_response(),
        Err(error_value) => store_error(error_value),
    }
}
