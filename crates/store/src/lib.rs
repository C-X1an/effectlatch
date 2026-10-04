//! PostgreSQL authority. No network effect may run inside a store transaction.
pub mod scheduler;
use effectlatch_domain::{
    grants::{Authority, Grant, GrantError, reservation_plan, validate_child},
    types::NormalizedRun,
};
use sqlx::{PgPool, Postgres, Row, Transaction, postgres::PgPoolOptions};
use std::{path::Path, time::Duration};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid store configuration: {0}")]
    Configuration(&'static str),
    #[error("database operation failed")]
    Database(#[from] sqlx::Error),
    #[error("migration failed")]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error("run does not exist in this tenant")]
    RunNotFound,
    #[error("effect does not exist in this run")]
    EffectNotFound,
    #[error("stored event counter or hash is invalid")]
    CorruptEventHead,
    #[error("database schema is incompatible with this application")]
    IncompatibleSchema,
    #[error("scheduler singleton is missing")]
    MissingScheduler,
    #[error("module does not exist in this tenant")]
    ModuleNotFound,
    #[error("grant does not exist, is expired, or is revoked")]
    GrantDenied,
    #[error("idempotency key is already bound to a different request")]
    IdempotencyConflict,
    #[error("pending run capacity is exhausted")]
    CapacityExhausted,
    #[error("grant does not exist in this tenant")]
    GrantNotFound,
    #[error("grant validation failed")]
    GrantValidation(#[source] GrantError),
    #[error("stored grant ancestry or reservation is invalid")]
    CorruptGrant,
    #[error("run lease does not exist, has expired, or has been fenced")]
    LeaseConflict,
    #[error("scheduler counter or active slot is inconsistent")]
    CorruptScheduler,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PutModule {
    Created,
    Existing,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AdmissionKind {
    Created,
    Existing,
}

#[derive(Debug, Clone)]
pub struct RunRecord {
    pub id: Uuid,
    pub state: String,
    pub module_digest: [u8; 32],
    pub grant_id: Uuid,
    pub created_at: String,
    pub updated_at: String,
    pub lease_epoch: i64,
    pub attempt: i32,
    pub cancel_requested: bool,
    pub output: Option<Vec<u8>>,
    pub error_code: Option<String>,
    pub effects: Vec<EffectRecord>,
}

#[derive(Debug, Clone)]
pub struct EffectRecord {
    pub ordinal: i32,
    pub state: String,
    pub request_hash: [u8; 32],
    pub provider_key: String,
    pub send_attempts: i32,
}

#[derive(Debug, Clone)]
pub struct Admission {
    pub kind: AdmissionKind,
    pub run: RunRecord,
}

#[derive(Debug, Clone)]
pub struct GrantRecord {
    pub id: Uuid,
    pub parent_id: Option<Uuid>,
    pub depth: i32,
    pub actions: Vec<String>,
    pub destinations: Vec<String>,
    pub projects: Vec<String>,
    pub expires_at: String,
    pub max_effects: i64,
    pub used_effects: i64,
    pub revoked_at: Option<String>,
    pub ancestry: Vec<Uuid>,
}

#[derive(Debug, Clone)]
pub struct RevocationRecord {
    pub id: Uuid,
    pub revoked_at: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ReservationKind {
    Created,
    Existing,
}

#[derive(Debug, Clone, Copy)]
pub struct GrantReservation {
    pub tenant: Uuid,
    pub run: Uuid,
    pub ordinal: i32,
}

pub struct Store {
    pool: PgPool,
}

impl Store {
    /// Acquisitions and server-side statements are bounded. Connection strings are
    /// never included in this type's Debug output or error display.
    pub async fn connect(url: &str, max_connections: u32) -> Result<Self, Error> {
        if !(1..=32).contains(&max_connections) {
            return Err(Error::Configuration("pool size must be 1..=32"));
        }
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(Duration::from_secs(5))
            .idle_timeout(Duration::from_secs(60))
            .after_connect(|conn, _| Box::pin(async move {
                sqlx::raw_sql("SET statement_timeout = '10s'; SET lock_timeout = '3s'; SET idle_in_transaction_session_timeout = '15s'; SET default_transaction_isolation = 'read committed'")
                    .execute(conn).await?;
                Ok(())
            }))
            .connect(url).await?;
        Ok(Self { pool })
    }

    /// SQLx retains applied checksums and rejects altered applied migrations.
    /// The directory must be an operator-owned application resource.
    pub async fn migrate(&self, directory: &Path) -> Result<(), Error> {
        let migrator = sqlx::migrate::Migrator::new(directory).await?;
        let mut connection = self.pool.acquire().await?;
        // SQLx holds a session advisory lock while migrating. An early migration
        // error must never return that session (and its lock) to the shared pool.
        // Also close on cancellation, before this future reaches explicit close.
        connection.close_on_drop();
        let result = migrator.run(&mut *connection).await;
        let closed = connection.close().await;
        result?;
        closed?;
        Ok(())
    }

    pub async fn begin(&self) -> Result<Transaction<'_, Postgres>, Error> {
        Ok(self.pool.begin().await?)
    }

    /// Read-only startup gate. Reject missing, dirty, changed, older and newer
    /// migration histories. Only the explicit migration command changes schema.
    pub async fn check_schema(&self, directory: &Path) -> Result<(), Error> {
        let expected = sqlx::migrate::Migrator::new(directory).await?;
        let migrations: Vec<_> = expected
            .iter()
            .filter(|migration| migration.migration_type.is_up_migration())
            .collect();
        if migrations.is_empty() || migrations.len() > 1024 {
            return Err(Error::IncompatibleSchema);
        }
        let rows = sqlx::query(
            "SELECT version, checksum, success FROM _sqlx_migrations ORDER BY version LIMIT 1025",
        )
        .fetch_all(&self.pool)
        .await?;
        if rows.len() != migrations.len() {
            return Err(Error::IncompatibleSchema);
        }
        for (row, migration) in rows.iter().zip(migrations) {
            let version: i64 = row.try_get("version")?;
            let checksum: Vec<u8> = row.try_get("checksum")?;
            let success: bool = row.try_get("success")?;
            if !success || version != migration.version || checksum != migration.checksum.as_ref() {
                return Err(Error::IncompatibleSchema);
            }
        }
        Ok(())
    }

    /// Fixed advisory namespace 0x454c415443480001 (ELATCH, version 1).
    /// Lock order: this advisory lock, scheduler singleton, tenant, then run.
    /// Dispatch transactions must use `begin` and never acquire this lock.
    pub async fn begin_scheduler(&self) -> Result<Transaction<'_, Postgres>, Error> {
        let mut tx = self.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(0x454c_4154_4348_0001_i64)
            .execute(&mut *tx)
            .await?;
        let row =
            sqlx::query("SELECT dispatch_seq FROM scheduler_state WHERE singleton=true FOR UPDATE")
                .fetch_optional(&mut *tx)
                .await?;
        if row.is_none() {
            return Err(Error::MissingScheduler);
        }
        Ok(tx)
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }

    /// Store content under the credential-derived tenant. The caller must
    /// validate the Wasm contract before invoking this method.
    pub async fn put_module(
        &self,
        tenant: Uuid,
        digest: &[u8; 32],
        wasm: &[u8],
    ) -> Result<PutModule, Error> {
        if wasm.is_empty() || wasm.len() > effectlatch_domain::MODULE_BYTES {
            return Err(Error::Configuration("invalid module size"));
        }
        let result = sqlx::query("INSERT INTO modules(tenant_id,digest,wasm,abi_version) VALUES($1,$2,$3,1) ON CONFLICT (tenant_id,digest) DO NOTHING")
            .bind(tenant).bind(digest.as_slice()).bind(wasm)
            .execute(&self.pool).await?;
        if result.rows_affected() == 1 {
            return Ok(PutModule::Created);
        }
        let existing: Vec<u8> =
            sqlx::query_scalar("SELECT wasm FROM modules WHERE tenant_id=$1 AND digest=$2")
                .bind(tenant)
                .bind(digest.as_slice())
                .fetch_optional(&self.pool)
                .await?
                .ok_or(Error::ModuleNotFound)?;
        if existing != wasm {
            return Err(Error::Database(sqlx::Error::Protocol(
                "module digest collision".into(),
            )));
        }
        Ok(PutModule::Existing)
    }

    /// Admit a normalized request under the global scheduler lock. Existing
    /// identity is checked before queue capacity, so safe retries still work
    /// when the queue has since filled.
    pub async fn admit_run(
        &self,
        tenant: Uuid,
        key: &str,
        request: &NormalizedRun,
        max_pending_global: u64,
        max_pending_tenant: u64,
    ) -> Result<Admission, Error> {
        if key.is_empty()
            || key.len() > 128
            || !key.bytes().all(|byte| byte.is_ascii_graphic())
            || max_pending_global == 0
            || max_pending_global > 1000
            || max_pending_tenant == 0
            || max_pending_tenant > 100
            || max_pending_tenant > max_pending_global
        {
            return Err(Error::Configuration("invalid admission parameters"));
        }
        let request_hash = effectlatch_domain::hash::run(request);
        let mut tx = self.begin_scheduler().await?;
        let tenant_limit: i32 =
            sqlx::query_scalar("SELECT queue_limit FROM tenants WHERE id=$1 FOR UPDATE")
                .bind(tenant)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(Error::GrantDenied)?;

        if let Some(row) = sqlx::query(
            "SELECT request_hash FROM runs WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE",
        )
        .bind(tenant)
        .bind(key)
        .fetch_optional(&mut *tx)
        .await?
        {
            let existing: Vec<u8> = row.try_get("request_hash")?;
            if existing.as_slice() != request_hash {
                return Err(Error::IdempotencyConflict);
            }
            let run = fetch_run_by_key(&mut tx, tenant, key).await?;
            tx.commit().await?;
            return Ok(Admission {
                kind: AdmissionKind::Existing,
                run,
            });
        }

        let module_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM modules WHERE tenant_id=$1 AND digest=$2)",
        )
        .bind(tenant)
        .bind(request.module_digest.as_slice())
        .fetch_one(&mut *tx)
        .await?;
        if !module_exists {
            return Err(Error::ModuleNotFound);
        }
        let grant_live: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM grants WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL AND expires_at>clock_timestamp())",
        )
        .bind(tenant)
        .bind(request.grant_id)
        .fetch_one(&mut *tx)
        .await?;
        if !grant_live {
            return Err(Error::GrantDenied);
        }

        // A deferred retry owns the next available queue position. Count it
        // during new-key admission so fresh submissions cannot starve recovery.
        let global_pending: i64 =
            sqlx::query_scalar("SELECT count(*) FROM runs WHERE state IN ('queued','retry_wait')")
                .fetch_one(&mut *tx)
                .await?;
        let tenant_pending: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM runs WHERE tenant_id=$1 AND state IN ('queued','retry_wait')",
        )
        .bind(tenant)
        .fetch_one(&mut *tx)
        .await?;
        let effective_tenant_limit = u64::from(tenant_limit as u32).min(max_pending_tenant);
        if u64::try_from(global_pending).unwrap_or(u64::MAX) >= max_pending_global
            || u64::try_from(tenant_pending).unwrap_or(u64::MAX) >= effective_tenant_limit
        {
            return Err(Error::CapacityExhausted);
        }

        let run_id = Uuid::new_v4();
        let limits = serde_json::to_string(&request.limits)
            .map_err(|_| Error::Configuration("limits cannot be serialized"))?;
        let inserted = sqlx::query("INSERT INTO runs(tenant_id,id,idempotency_key,request_hash,module_digest,grant_id,input_bytes,limits,state) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,'queued') ON CONFLICT (tenant_id,idempotency_key) DO NOTHING")
            .bind(tenant).bind(run_id).bind(key).bind(request_hash.as_slice())
            .bind(request.module_digest.as_slice()).bind(request.grant_id)
            .bind(&request.input).bind(limits).execute(&mut *tx).await?;
        if inserted.rows_affected() == 0 {
            let row = sqlx::query("SELECT request_hash FROM runs WHERE tenant_id=$1 AND idempotency_key=$2 FOR UPDATE")
                .bind(tenant).bind(key).fetch_one(&mut *tx).await?;
            let existing: Vec<u8> = row.try_get("request_hash")?;
            if existing.as_slice() != request_hash {
                return Err(Error::IdempotencyConflict);
            }
            let run = fetch_run_by_key(&mut tx, tenant, key).await?;
            tx.commit().await?;
            return Ok(Admission {
                kind: AdmissionKind::Existing,
                run,
            });
        }
        append_event(
            &mut tx,
            tenant,
            run_id,
            "run.admitted",
            br#"{"state":"queued"}"#,
        )
        .await?;
        let run = fetch_run_by_key(&mut tx, tenant, key).await?;
        tx.commit().await?;
        Ok(Admission {
            kind: AdmissionKind::Created,
            run,
        })
    }

    /// Create a root or attenuated child. Parent links have no update API;
    /// ancestry is locked root-first before liveness and attenuation checks.
    pub async fn create_grant(
        &self,
        tenant: Uuid,
        parent: Option<Uuid>,
        actor_id: &str,
        authority: Authority,
    ) -> Result<GrantRecord, Error> {
        if actor_id.is_empty() || actor_id.len() > 64 {
            return Err(Error::Configuration("invalid grant actor"));
        }
        let mut tx = self.begin().await?;
        let mut ancestry = if let Some(parent) = parent {
            load_grant_chain_locked(&mut tx, tenant, parent).await?
        } else {
            sqlx::query("SELECT id FROM tenants WHERE id=$1 FOR UPDATE")
                .bind(tenant)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(Error::GrantNotFound)?;
            Vec::new()
        };
        let now_ms: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint")
                .fetch_one(&mut *tx)
                .await?;
        if ancestry.is_empty() {
            authority.validate(now_ms).map_err(Error::GrantValidation)?;
        } else {
            validate_child(&authority, &ancestry, tenant, now_ms)
                .map_err(Error::GrantValidation)?;
        }
        let id = Uuid::new_v4();
        let depth = i32::try_from(ancestry.len()).map_err(|_| Error::CorruptGrant)?;
        let actions: Vec<_> = authority.actions.iter().cloned().collect();
        let destinations: Vec<_> = authority.destinations.iter().cloned().collect();
        let projects: Vec<_> = authority.projects.iter().cloned().collect();
        let max_effects = i64::try_from(authority.max_effects)
            .map_err(|_| Error::Configuration("grant budget is too large"))?;
        sqlx::query("INSERT INTO grants(tenant_id,id,parent_id,depth,actions,destinations,projects,max_effects,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,to_timestamp($9::double precision/1000.0))")
            .bind(tenant).bind(id).bind(parent).bind(depth).bind(&actions)
            .bind(&destinations).bind(&projects).bind(max_effects)
            .bind(authority.expires_at_ms).execute(&mut *tx).await?;
        let detail = effectlatch_domain::hash::grant(parent, &authority);
        sqlx::query("INSERT INTO operator_events(tenant_id,actor_id,action,object_id,detail_hash) VALUES($1,$2,'grant.created',$3,$4)")
            .bind(tenant).bind(actor_id).bind(id).bind(detail.as_slice())
            .execute(&mut *tx).await?;
        ancestry.push(Grant {
            id,
            tenant_id: tenant,
            parent_id: parent,
            depth: u8::try_from(depth).map_err(|_| Error::CorruptGrant)?,
            authority,
            used_effects: 0,
            revoked: false,
        });
        let ancestry_ids = ancestry.iter().map(|grant| grant.id).collect();
        let record = fetch_grant_record(&mut tx, tenant, id, ancestry_ids).await?;
        tx.commit().await?;
        Ok(record)
    }

    pub async fn get_grant(&self, tenant: Uuid, id: Uuid) -> Result<GrantRecord, Error> {
        let mut tx = self.begin().await?;
        let ancestry = load_grant_chain_locked(&mut tx, tenant, id).await?;
        let ancestry_ids = ancestry.iter().map(|grant| grant.id).collect();
        let record = fetch_grant_record(&mut tx, tenant, id, ancestry_ids).await?;
        tx.commit().await?;
        Ok(record)
    }

    /// Revocation and dispatch authorization take the same root-first locks.
    /// Repeated revocation returns the original database timestamp.
    pub async fn revoke_grant(
        &self,
        tenant: Uuid,
        id: Uuid,
        actor_id: &str,
        reason: &str,
    ) -> Result<RevocationRecord, Error> {
        if actor_id.is_empty()
            || actor_id.len() > 64
            || reason.is_empty()
            || reason.len() > 1024
            || reason.chars().count() > 256
        {
            return Err(Error::Configuration("invalid revocation metadata"));
        }
        let mut tx = self.begin().await?;
        load_grant_chain_locked(&mut tx, tenant, id).await?;
        let existing: Option<String> = sqlx::query_scalar("SELECT to_char(revoked_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') FROM grants WHERE tenant_id=$1 AND id=$2")
            .bind(tenant).bind(id).fetch_one(&mut *tx).await?;
        let revoked_at = if let Some(existing) = existing {
            existing
        } else {
            let timestamp: String = sqlx::query_scalar("UPDATE grants SET revoked_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL RETURNING to_char(revoked_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')")
                .bind(tenant).bind(id).fetch_one(&mut *tx).await?;
            let detail = effectlatch_domain::hash::grant_revocation(id, reason);
            sqlx::query("INSERT INTO operator_events(tenant_id,actor_id,action,object_id,detail_hash) VALUES($1,$2,'grant.revoked',$3,$4)")
                .bind(tenant).bind(actor_id).bind(id).bind(detail.as_slice())
                .execute(&mut *tx).await?;
            timestamp
        };
        tx.commit().await?;
        Ok(RevocationRecord { id, revoked_at })
    }

    /// Reserve every ancestor once for a prepared logical effect. Callers own
    /// the surrounding effect transaction; no network operation is permitted.
    pub async fn reserve_grant_chain(
        tx: &mut Transaction<'_, Postgres>,
        request: GrantReservation,
    ) -> Result<ReservationKind, Error> {
        let grant_id: Uuid =
            sqlx::query_scalar("SELECT grant_id FROM runs WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
                .bind(request.tenant)
                .bind(request.run)
                .fetch_optional(&mut **tx)
                .await?
                .ok_or(Error::RunNotFound)?;
        let ancestry = load_grant_chain_locked(tx, request.tenant, grant_id).await?;
        let effect = sqlx::query("SELECT action,destination,project,state,reservation_charged FROM effects WHERE tenant_id=$1 AND run_id=$2 AND ordinal=$3 FOR UPDATE")
            .bind(request.tenant).bind(request.run).bind(request.ordinal)
            .fetch_optional(&mut **tx).await?.ok_or(Error::EffectNotFound)?;
        let action: String = effect.try_get("action")?;
        let destination: String = effect.try_get("destination")?;
        let project: String = effect.try_get("project")?;
        let state: String = effect.try_get("state")?;
        let reservation_charged: bool = effect.try_get("reservation_charged")?;
        let existing: Vec<Uuid> = sqlx::query_scalar("SELECT grant_id FROM effect_reservations WHERE tenant_id=$1 AND run_id=$2 AND ordinal=$3 ORDER BY grant_id")
            .bind(request.tenant).bind(request.run).bind(request.ordinal).fetch_all(&mut **tx).await?;
        if !existing.is_empty() {
            let mut expected: Vec<_> = ancestry.iter().map(|grant| grant.id).collect();
            expected.sort_unstable();
            if existing == expected && reservation_charged {
                return Ok(ReservationKind::Existing);
            }
            return Err(Error::CorruptGrant);
        }
        if reservation_charged || state != "PREPARED" {
            return Err(Error::CorruptGrant);
        }
        let now_ms: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint")
                .fetch_one(&mut **tx)
                .await?;
        let plan = reservation_plan(
            &ancestry,
            request.tenant,
            now_ms,
            &action,
            &destination,
            &project,
        )
        .map_err(Error::GrantValidation)?;
        for (grant, next) in plan {
            let next = i64::try_from(next).map_err(|_| Error::CorruptGrant)?;
            let updated = sqlx::query("UPDATE grants SET used_effects=$3 WHERE tenant_id=$1 AND id=$2 AND used_effects=$3-1")
                .bind(request.tenant).bind(grant).bind(next).execute(&mut **tx).await?;
            if updated.rows_affected() != 1 {
                return Err(Error::CorruptGrant);
            }
            sqlx::query("INSERT INTO effect_reservations(tenant_id,run_id,ordinal,grant_id) VALUES($1,$2,$3,$4)")
                .bind(request.tenant).bind(request.run).bind(request.ordinal).bind(grant)
                .execute(&mut **tx).await?;
        }
        let charged = sqlx::query("UPDATE effects SET reservation_charged=true,updated_at=clock_timestamp() WHERE tenant_id=$1 AND run_id=$2 AND ordinal=$3 AND reservation_charged=false")
            .bind(request.tenant).bind(request.run).bind(request.ordinal)
            .execute(&mut **tx).await?;
        if charged.rows_affected() != 1 {
            return Err(Error::CorruptGrant);
        }
        Ok(ReservationKind::Created)
    }
}

async fn load_grant_chain_locked(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    leaf: Uuid,
) -> Result<Vec<Grant>, Error> {
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "WITH RECURSIVE chain(id,parent_id,depth) AS (SELECT id,parent_id,depth FROM grants WHERE tenant_id=$1 AND id=$2 UNION SELECT g.id,g.parent_id,g.depth FROM grants g JOIN chain c ON g.tenant_id=$1 AND g.id=c.parent_id) SELECT id FROM chain ORDER BY depth",
    )
    .bind(tenant)
    .bind(leaf)
    .fetch_all(&mut **tx)
    .await?;
    if ids.is_empty() || ids.len() > 5 {
        return Err(Error::GrantNotFound);
    }
    let mut grants = Vec::with_capacity(ids.len());
    for id in ids {
        let row = sqlx::query("SELECT id,parent_id,depth,actions,destinations,projects,max_effects,used_effects,floor(extract(epoch FROM expires_at)*1000)::bigint expires_at_ms,(revoked_at IS NOT NULL) revoked FROM grants WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
            .bind(tenant).bind(id).fetch_optional(&mut **tx).await?
            .ok_or(Error::GrantNotFound)?;
        let depth: i32 = row.try_get("depth")?;
        let max_effects: i64 = row.try_get("max_effects")?;
        let used_effects: i64 = row.try_get("used_effects")?;
        grants.push(Grant {
            id: row.try_get("id")?,
            tenant_id: tenant,
            parent_id: row.try_get("parent_id")?,
            depth: u8::try_from(depth).map_err(|_| Error::CorruptGrant)?,
            authority: Authority {
                actions: row
                    .try_get::<Vec<String>, _>("actions")?
                    .into_iter()
                    .collect(),
                destinations: row
                    .try_get::<Vec<String>, _>("destinations")?
                    .into_iter()
                    .collect(),
                projects: row
                    .try_get::<Vec<String>, _>("projects")?
                    .into_iter()
                    .collect(),
                expires_at_ms: row.try_get("expires_at_ms")?,
                max_effects: u64::try_from(max_effects).map_err(|_| Error::CorruptGrant)?,
            },
            used_effects: u64::try_from(used_effects).map_err(|_| Error::CorruptGrant)?,
            revoked: row.try_get("revoked")?,
        });
    }
    let mut structural = grants.clone();
    for grant in &mut structural {
        grant.revoked = false;
    }
    effectlatch_domain::grants::validate_chain(&structural, tenant, i64::MIN).map_err(|error| {
        match error {
            GrantError::Inactive => Error::CorruptGrant,
            other => Error::GrantValidation(other),
        }
    })?;
    Ok(grants)
}

async fn fetch_grant_record(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    id: Uuid,
    ancestry: Vec<Uuid>,
) -> Result<GrantRecord, Error> {
    let row = sqlx::query("SELECT id,parent_id,depth,actions,destinations,projects,max_effects,used_effects,to_char(expires_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') expires_at,to_char(revoked_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') revoked_at FROM grants WHERE tenant_id=$1 AND id=$2")
        .bind(tenant).bind(id).fetch_optional(&mut **tx).await?
        .ok_or(Error::GrantNotFound)?;
    Ok(GrantRecord {
        id: row.try_get("id")?,
        parent_id: row.try_get("parent_id")?,
        depth: row.try_get("depth")?,
        actions: row.try_get("actions")?,
        destinations: row.try_get("destinations")?,
        projects: row.try_get("projects")?,
        expires_at: row.try_get("expires_at")?,
        max_effects: row.try_get("max_effects")?,
        used_effects: row.try_get("used_effects")?,
        revoked_at: row.try_get("revoked_at")?,
        ancestry,
    })
}

async fn fetch_run_by_key(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    key: &str,
) -> Result<RunRecord, Error> {
    let row = sqlx::query(
        "SELECT id,state,module_digest,grant_id,to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') created_at,to_char(updated_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') updated_at,lease_epoch,attempt,cancel_requested,output_bytes,error_code FROM runs WHERE tenant_id=$1 AND idempotency_key=$2",
    )
    .bind(tenant)
    .bind(key)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(Error::RunNotFound)?;
    let digest: Vec<u8> = row.try_get("module_digest")?;
    let id: Uuid = row.try_get("id")?;
    let effect_rows = sqlx::query("SELECT ordinal,state,request_hash,provider_key,send_attempts FROM effects WHERE tenant_id=$1 AND run_id=$2 ORDER BY ordinal")
        .bind(tenant).bind(id).fetch_all(&mut **tx).await?;
    let mut effects = Vec::with_capacity(effect_rows.len());
    for effect in effect_rows {
        let request_hash: Vec<u8> = effect.try_get("request_hash")?;
        effects.push(EffectRecord {
            ordinal: effect.try_get("ordinal")?,
            state: effect.try_get("state")?,
            request_hash: request_hash
                .try_into()
                .map_err(|_| Error::IncompatibleSchema)?,
            provider_key: effect.try_get("provider_key")?,
            send_attempts: effect.try_get("send_attempts")?,
        });
    }
    Ok(RunRecord {
        id,
        state: row.try_get("state")?,
        module_digest: digest.try_into().map_err(|_| Error::IncompatibleSchema)?,
        grant_id: row.try_get("grant_id")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        lease_epoch: row.try_get("lease_epoch")?,
        attempt: row.try_get("attempt")?,
        cancel_requested: row.try_get("cancel_requested")?,
        output: row.try_get("output_bytes")?,
        error_code: row.try_get("error_code")?,
        effects,
    })
}

/// Append exact payload bytes under the run-row lock. Callers pass the same
/// transaction used for the associated state mutation and commit both together.
/// Acquire any scheduler/tenant locks before calling this function.
pub async fn append_event(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    run: Uuid,
    kind: &str,
    payload: &[u8],
) -> Result<[u8; 32], Error> {
    if kind.is_empty() || kind.len() > 128 || payload.len() > 16_384 {
        return Err(Error::Configuration("invalid event kind or payload size"));
    }
    let head = sqlx::query(
        "SELECT next_event_seq, last_event_hash FROM runs WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(tenant)
    .bind(run)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(Error::RunNotFound)?;
    let seq: i64 = head.try_get("next_event_seq")?;
    let next = seq
        .checked_add(1)
        .filter(|_| seq > 0)
        .ok_or(Error::CorruptEventHead)?;
    let previous: Vec<u8> = head.try_get("last_event_hash")?;
    let previous: [u8; 32] = previous.try_into().map_err(|_| Error::CorruptEventHead)?;
    let hash = effectlatch_domain::hash::event(tenant, run, seq as u64, &previous, kind, payload);
    sqlx::query("INSERT INTO run_events(tenant_id,run_id,seq,kind,payload_bytes,prev_hash,event_hash) VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(tenant).bind(run).bind(seq).bind(kind).bind(payload).bind(previous.as_slice()).bind(hash.as_slice())
        .execute(&mut **tx).await?;
    sqlx::query(
        "UPDATE runs SET next_event_seq=$3,last_event_hash=$4 WHERE tenant_id=$1 AND id=$2",
    )
    .bind(tenant)
    .bind(run)
    .bind(next)
    .bind(hash.as_slice())
    .execute(&mut **tx)
    .await?;
    Ok(hash)
}
