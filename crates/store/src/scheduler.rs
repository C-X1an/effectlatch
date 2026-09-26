//! Durable scheduler and lease fencing. Every slot mutation starts with the
//! fixed scheduler advisory lock, then locks tenant and run rows in that order.
use crate::{Error, RunRecord, Store, append_event, fetch_run_by_key, load_grant_chain_locked};
use sqlx::Row;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Lease {
    pub tenant: Uuid,
    pub run: Uuid,
    pub epoch: i64,
    pub expires_at: String,
    pub module_digest: [u8; 32],
    pub module: Vec<u8>,
    pub input: Vec<u8>,
    pub limits_json: String,
}

#[derive(Debug, Clone)]
pub struct Heartbeat {
    pub expires_at: String,
    pub cancel_requested: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct ClaimPolicy {
    pub max_active_global: u8,
    pub max_active_per_tenant: u8,
    pub max_attempts: u8,
    pub lease_ms: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct ReapPolicy {
    pub max_attempts: u8,
    pub max_pending_global: u64,
    pub max_pending_tenant: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Reaped {
    Requeued,
    WaitingForQueue,
    NeedsReconciliation,
    Cancelled,
    Failed,
}

fn worker_identifier(worker: &str) -> bool {
    !worker.is_empty()
        && worker.len() <= 64
        && worker
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

impl Store {
    /// Claim at most one run. The allowlist is taken from the authenticated
    /// worker principal, never from request text. All ordering is durable.
    pub async fn claim_run(
        &self,
        worker: &str,
        allowed_tenants: &[Uuid],
        available_slots: u8,
        policy: ClaimPolicy,
    ) -> Result<Option<Lease>, Error> {
        if !worker_identifier(worker)
            || allowed_tenants.is_empty()
            || allowed_tenants.len() > 1024
            || !(1..=2).contains(&available_slots)
            || !(1..=4).contains(&policy.max_active_global)
            || policy.max_active_per_tenant != 1
            || !(1..=3).contains(&policy.max_attempts)
            || !(1..=6000).contains(&policy.lease_ms)
        {
            return Err(Error::Configuration("invalid claim parameters"));
        }
        let mut tx = self.begin_scheduler().await?;
        let active: i64 =
            sqlx::query_scalar("SELECT COALESCE(sum(active_count),0)::bigint FROM tenants")
                .fetch_one(&mut *tx)
                .await?;
        if !(0..=4).contains(&active) {
            return Err(Error::CorruptScheduler);
        }
        if active >= i64::from(policy.max_active_global) {
            tx.commit().await?;
            return Ok(None);
        }
        let worker_active: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM runs WHERE active_slot_held AND lease_owner=$1",
        )
        .bind(worker)
        .fetch_one(&mut *tx)
        .await?;
        if worker_active >= 2 {
            tx.commit().await?;
            return Ok(None);
        }
        let candidate = sqlx::query(
            "SELECT t.id AS tenant_id, q.id AS run_id FROM tenants t \
             JOIN LATERAL (SELECT id FROM runs WHERE tenant_id=t.id AND state='queued' \
             AND cancel_requested=false AND attempt<$2 ORDER BY created_at,id LIMIT 1) q ON true \
             WHERE t.id=ANY($1::uuid[]) AND t.active_count<LEAST(t.active_limit,$3) \
             ORDER BY t.last_served_seq,t.id LIMIT 1",
        )
        .bind(allowed_tenants)
        .bind(i32::from(policy.max_attempts))
        .bind(i32::from(policy.max_active_per_tenant))
        .fetch_optional(&mut *tx)
        .await?;
        let Some(candidate) = candidate else {
            tx.commit().await?;
            return Ok(None);
        };
        let tenant: Uuid = candidate.try_get("tenant_id")?;
        let run: Uuid = candidate.try_get("run_id")?;
        let tenant_row =
            sqlx::query("SELECT active_count,active_limit FROM tenants WHERE id=$1 FOR UPDATE")
                .bind(tenant)
                .fetch_one(&mut *tx)
                .await?;
        let active_count: i32 = tenant_row.try_get("active_count")?;
        let active_limit: i32 = tenant_row.try_get("active_limit")?;
        if active_count < 0
            || active_count >= active_limit
            || active_count >= i32::from(policy.max_active_per_tenant)
        {
            return Err(Error::CorruptScheduler);
        }
        let run_row = sqlx::query("SELECT state,active_slot_held,lease_epoch,attempt,grant_id FROM runs WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
            .bind(tenant).bind(run).fetch_one(&mut *tx).await?;
        let state: String = run_row.try_get("state")?;
        let held: bool = run_row.try_get("active_slot_held")?;
        let epoch: i64 = run_row.try_get("lease_epoch")?;
        let attempt: i32 = run_row.try_get("attempt")?;
        if state != "queued"
            || held
            || epoch == i64::MAX
            || attempt >= i32::from(policy.max_attempts)
        {
            return Err(Error::CorruptScheduler);
        }
        let grant_id: Uuid = run_row.try_get("grant_id")?;
        let chain = load_grant_chain_locked(&mut tx, tenant, grant_id).await?;
        let grant_ids: Vec<_> = chain.iter().map(|grant| grant.id).collect();
        let grant_live: bool = sqlx::query_scalar("SELECT bool_and(revoked_at IS NULL AND expires_at>clock_timestamp()) FROM grants WHERE tenant_id=$1 AND id=ANY($2::uuid[])")
            .bind(tenant).bind(&grant_ids).fetch_one(&mut *tx).await?;
        if !grant_live {
            sqlx::query("UPDATE runs SET state='failed',error_code='GRANT_DENIED',updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
                .bind(tenant).bind(run).execute(&mut *tx).await?;
            append_event(
                &mut tx,
                tenant,
                run,
                "grant.denied",
                br#"{"reason":"inactive"}"#,
            )
            .await?;
            append_event(
                &mut tx,
                tenant,
                run,
                "run.failed",
                br#"{"state":"failed","error_code":"GRANT_DENIED"}"#,
            )
            .await?;
            tx.commit().await?;
            return Ok(None);
        }
        let dispatch_seq: i64 = sqlx::query_scalar("UPDATE scheduler_state SET dispatch_seq=dispatch_seq+1 WHERE singleton=true AND dispatch_seq<9223372036854775807 RETURNING dispatch_seq")
            .fetch_optional(&mut *tx).await?.ok_or(Error::CorruptScheduler)?;
        sqlx::query(
            "UPDATE tenants SET active_count=active_count+1,last_served_seq=$2 WHERE id=$1",
        )
        .bind(tenant)
        .bind(dispatch_seq)
        .execute(&mut *tx)
        .await?;
        let row = sqlx::query("UPDATE runs SET state='leased',lease_epoch=lease_epoch+1,lease_owner=$3,lease_expires_at=LEAST(clock_timestamp()+($4::bigint*interval '1 millisecond'),(SELECT min(expires_at) FROM grants WHERE tenant_id=$1 AND id=ANY($5::uuid[]))),attempt=attempt+1,active_slot_held=true,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 RETURNING lease_epoch,to_char(lease_expires_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS expires_at,module_digest,input_bytes,limits::text AS limits_json")
            .bind(tenant).bind(run).bind(worker).bind(i64::try_from(policy.lease_ms).map_err(|_| Error::Configuration("invalid lease"))?).bind(&grant_ids)
            .fetch_one(&mut *tx).await?;
        let epoch: i64 = row.try_get("lease_epoch")?;
        let digest: Vec<u8> = row.try_get("module_digest")?;
        let digest: [u8; 32] = digest.try_into().map_err(|_| Error::IncompatibleSchema)?;
        let module: Vec<u8> =
            sqlx::query_scalar("SELECT wasm FROM modules WHERE tenant_id=$1 AND digest=$2")
                .bind(tenant)
                .bind(digest.as_slice())
                .fetch_one(&mut *tx)
                .await?;
        let payload = serde_json::to_vec(&serde_json::json!({"epoch":epoch,"worker_id":worker}))
            .map_err(|_| Error::Configuration("claim event cannot be serialized"))?;
        append_event(&mut tx, tenant, run, "lease.claimed", &payload).await?;
        let lease = Lease {
            tenant,
            run,
            epoch,
            expires_at: row.try_get("expires_at")?,
            module_digest: digest,
            module,
            input: row
                .try_get::<Option<Vec<u8>>, _>("input_bytes")?
                .unwrap_or_default(),
            limits_json: row.try_get("limits_json")?,
        };
        tx.commit().await?;
        Ok(Some(lease))
    }

    /// Database time and the stored owner/epoch determine renewal. A worker
    /// that misses expiry cannot revive its lease before the reaper runs.
    pub async fn heartbeat_run(
        &self,
        run: Uuid,
        worker: &str,
        allowed_tenants: &[Uuid],
        epoch: i64,
        lease_ms: u64,
    ) -> Result<Heartbeat, Error> {
        if !worker_identifier(worker) || epoch <= 0 || !(1..=6000).contains(&lease_ms) {
            return Err(Error::Configuration("invalid heartbeat parameters"));
        }
        let mut tx = self.begin().await?;
        let tenant: Uuid = sqlx::query_scalar("SELECT tenant_id FROM runs WHERE id=$1")
            .bind(run)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(Error::RunNotFound)?;
        if !allowed_tenants.contains(&tenant) {
            return Err(Error::RunNotFound);
        }
        let row = sqlx::query("UPDATE runs AS r SET lease_expires_at=LEAST(clock_timestamp()+($5::bigint*interval '1 millisecond'),(SELECT g.expires_at FROM grants g WHERE g.tenant_id=r.tenant_id AND g.id=r.grant_id)),updated_at=clock_timestamp() WHERE r.tenant_id=$1 AND r.id=$2 AND r.lease_owner=$3 AND r.lease_epoch=$4 AND r.lease_expires_at>clock_timestamp() AND r.active_slot_held AND r.state IN ('leased','running') AND EXISTS(SELECT 1 FROM grants g WHERE g.tenant_id=r.tenant_id AND g.id=r.grant_id AND g.expires_at>clock_timestamp() AND g.revoked_at IS NULL) RETURNING to_char(lease_expires_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS expires_at,cancel_requested")
            .bind(tenant).bind(run).bind(worker).bind(epoch).bind(i64::try_from(lease_ms).map_err(|_| Error::Configuration("invalid lease"))?)
            .fetch_optional(&mut *tx).await?.ok_or(Error::LeaseConflict)?;
        let result = Heartbeat {
            expires_at: row.try_get("expires_at")?,
            cancel_requested: row.try_get("cancel_requested")?,
        };
        tx.commit().await?;
        Ok(result)
    }

    /// Record child readiness only under the currently live lease. Repeating
    /// the call on the same running lease is safe and appends no extra event.
    pub async fn mark_run_started(
        &self,
        run: Uuid,
        worker: &str,
        allowed_tenants: &[Uuid],
        epoch: i64,
    ) -> Result<(), Error> {
        if !worker_identifier(worker) || epoch <= 0 {
            return Err(Error::Configuration("invalid started parameters"));
        }
        let mut tx = self.begin().await?;
        let tenant: Uuid = sqlx::query_scalar("SELECT tenant_id FROM runs WHERE id=$1")
            .bind(run)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(Error::RunNotFound)?;
        if !allowed_tenants.contains(&tenant) {
            return Err(Error::RunNotFound);
        }
        let row = sqlx::query("SELECT state,lease_owner,lease_epoch,lease_expires_at>clock_timestamp() AS live,active_slot_held FROM runs WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
            .bind(tenant).bind(run).fetch_one(&mut *tx).await?;
        let state: String = row.try_get("state")?;
        if row.try_get::<Option<String>, _>("lease_owner")?.as_deref() != Some(worker)
            || row.try_get::<i64, _>("lease_epoch")? != epoch
            || !row.try_get::<Option<bool>, _>("live")?.unwrap_or(false)
            || !row.try_get::<bool, _>("active_slot_held")?
            || !matches!(state.as_str(), "leased" | "running")
        {
            return Err(Error::LeaseConflict);
        }
        if state == "leased" {
            sqlx::query("UPDATE runs SET state='running',updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
                .bind(tenant).bind(run).execute(&mut *tx).await?;
            append_event(
                &mut tx,
                tenant,
                run,
                "runner.started",
                br#"{"state":"running"}"#,
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Reassess one expired slot. An in-flight or unknown remote effect bars
    /// automatic replay; the later recovery broker resolves its effect state.
    pub async fn reap_one(&self, policy: ReapPolicy) -> Result<Option<(Uuid, Reaped)>, Error> {
        if !(1..=3).contains(&policy.max_attempts)
            || !(1..=1000).contains(&policy.max_pending_global)
            || !(1..=100).contains(&policy.max_pending_tenant)
            || policy.max_pending_tenant > policy.max_pending_global
        {
            return Err(Error::Configuration("invalid reaper limits"));
        }
        let mut tx = self.begin_scheduler().await?;
        let global_pending: i64 =
            sqlx::query_scalar("SELECT count(*) FROM runs WHERE state='queued'")
                .fetch_one(&mut *tx)
                .await?;
        if global_pending
            < i64::try_from(policy.max_pending_global).map_err(|_| Error::CorruptScheduler)?
        {
            let waiting = sqlx::query("SELECT r.tenant_id,r.id FROM runs r JOIN tenants t ON t.id=r.tenant_id WHERE r.state='retry_wait' AND (SELECT count(*) FROM runs q WHERE q.tenant_id=r.tenant_id AND q.state='queued')<LEAST(t.queue_limit,$1::integer) ORDER BY r.created_at,r.id LIMIT 1")
                .bind(i32::try_from(policy.max_pending_tenant).map_err(|_| Error::CorruptScheduler)?)
                .fetch_optional(&mut *tx).await?;
            if let Some(waiting) = waiting {
                let tenant: Uuid = waiting.try_get("tenant_id")?;
                let run: Uuid = waiting.try_get("id")?;
                sqlx::query("SELECT id FROM tenants WHERE id=$1 FOR UPDATE")
                    .bind(tenant)
                    .fetch_one(&mut *tx)
                    .await?;
                let row = sqlx::query(
                    "SELECT state,cancel_requested,attempt,active_slot_held FROM runs WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
                )
                .bind(tenant)
                .bind(run)
                .fetch_one(&mut *tx)
                .await?;
                if row.try_get::<String, _>("state")? != "retry_wait"
                    || row.try_get::<bool, _>("active_slot_held")?
                {
                    return Err(Error::CorruptScheduler);
                }
                let uncertain: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM effects WHERE tenant_id=$1 AND run_id=$2 AND state IN ('DISPATCHING','OUTCOME_UNKNOWN'))")
                    .bind(tenant).bind(run).fetch_one(&mut *tx).await?;
                let (next, outcome, event) = if uncertain {
                    (
                        "needs_reconciliation",
                        Reaped::NeedsReconciliation,
                        "run.needs_reconciliation",
                    )
                } else if row.try_get::<bool, _>("cancel_requested")? {
                    ("cancelled", Reaped::Cancelled, "run.cancelled")
                } else if row.try_get::<i32, _>("attempt")? >= i32::from(policy.max_attempts) {
                    ("failed", Reaped::Failed, "run.failed")
                } else {
                    ("queued", Reaped::Requeued, "run.requeued")
                };
                sqlx::query("UPDATE runs SET state=$3,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
                    .bind(tenant).bind(run).bind(next).execute(&mut *tx).await?;
                let payload = format!(r#"{{"state":"{next}"}}"#);
                append_event(&mut tx, tenant, run, event, payload.as_bytes()).await?;
                tx.commit().await?;
                return Ok(Some((run, outcome)));
            }
        }
        let candidate = sqlx::query("SELECT tenant_id,id FROM runs WHERE active_slot_held AND state IN ('leased','running') AND lease_expires_at<=clock_timestamp() ORDER BY lease_expires_at,id LIMIT 1")
            .fetch_optional(&mut *tx).await?;
        let Some(candidate) = candidate else {
            tx.commit().await?;
            return Ok(None);
        };
        let tenant: Uuid = candidate.try_get("tenant_id")?;
        let run: Uuid = candidate.try_get("id")?;
        let tenant_row =
            sqlx::query("SELECT active_count,queue_limit FROM tenants WHERE id=$1 FOR UPDATE")
                .bind(tenant)
                .fetch_one(&mut *tx)
                .await?;
        let count: i32 = tenant_row.try_get("active_count")?;
        let queue_limit: i32 = tenant_row.try_get("queue_limit")?;
        if count <= 0 {
            return Err(Error::CorruptScheduler);
        }
        let row = sqlx::query("SELECT active_slot_held,attempt,cancel_requested,lease_expires_at<=clock_timestamp() AS expired FROM runs WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
            .bind(tenant).bind(run).fetch_one(&mut *tx).await?;
        if !row.try_get::<bool, _>("active_slot_held")? {
            return Err(Error::CorruptScheduler);
        }
        // Heartbeat does not take the scheduler lock. It can renew between
        // candidate selection and this row lock; in that case no slot expired.
        if !row.try_get::<Option<bool>, _>("expired")?.unwrap_or(false) {
            tx.commit().await?;
            return Ok(None);
        }
        let uncertain: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM effects WHERE tenant_id=$1 AND run_id=$2 AND state IN ('DISPATCHING','OUTCOME_UNKNOWN'))")
            .bind(tenant).bind(run).fetch_one(&mut *tx).await?;
        let cancel: bool = row.try_get("cancel_requested")?;
        let attempt: i32 = row.try_get("attempt")?;
        let tenant_pending: i64 =
            sqlx::query_scalar("SELECT count(*) FROM runs WHERE tenant_id=$1 AND state='queued'")
                .bind(tenant)
                .fetch_one(&mut *tx)
                .await?;
        let tenant_cap = i64::from(queue_limit)
            .min(i64::try_from(policy.max_pending_tenant).map_err(|_| Error::CorruptScheduler)?);
        let (next, outcome, event) = if uncertain {
            (
                "needs_reconciliation",
                Reaped::NeedsReconciliation,
                "run.needs_reconciliation",
            )
        } else if cancel {
            ("cancelled", Reaped::Cancelled, "run.cancelled")
        } else if attempt >= i32::from(policy.max_attempts) {
            ("failed", Reaped::Failed, "run.failed")
        } else if global_pending
            >= i64::try_from(policy.max_pending_global).map_err(|_| Error::CorruptScheduler)?
            || tenant_pending >= tenant_cap
        {
            ("retry_wait", Reaped::WaitingForQueue, "run.retry_wait")
        } else {
            ("queued", Reaped::Requeued, "run.requeued")
        };
        let released = sqlx::query(
            "UPDATE tenants SET active_count=active_count-1 WHERE id=$1 AND active_count>0",
        )
        .bind(tenant)
        .execute(&mut *tx)
        .await?;
        if released.rows_affected() != 1 {
            return Err(Error::CorruptScheduler);
        }
        sqlx::query("UPDATE runs SET state=$3,active_slot_held=false,lease_owner=NULL,lease_expires_at=NULL,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
            .bind(tenant).bind(run).bind(next).execute(&mut *tx).await?;
        append_event(
            &mut tx,
            tenant,
            run,
            "lease.expired",
            br#"{"expired":true}"#,
        )
        .await?;
        let payload = serde_json::to_vec(&serde_json::json!({"state":next}))
            .map_err(|_| Error::Configuration("reap event cannot be serialized"))?;
        append_event(&mut tx, tenant, run, event, &payload).await?;
        tx.commit().await?;
        Ok(Some((run, outcome)))
    }

    /// Final output is fenced against the live lease. Release the durable slot
    /// in the same transaction as the terminal state and run event.
    pub async fn finish_run(
        &self,
        run: Uuid,
        worker: &str,
        allowed_tenants: &[Uuid],
        epoch: i64,
        output: Option<&[u8]>,
        error_code: Option<&str>,
    ) -> Result<RunRecord, Error> {
        if !worker_identifier(worker)
            || epoch <= 0
            || output.is_some_and(|value| value.len() > 65_536)
            || error_code.is_some_and(|value| {
                value.is_empty()
                    || value.len() > 64
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_uppercase() || byte == b'_')
            })
            || (output.is_some() && error_code.is_some())
        {
            return Err(Error::Configuration("invalid finish parameters"));
        }
        let mut tx = self.begin_scheduler().await?;
        let tenant: Uuid = sqlx::query_scalar("SELECT tenant_id FROM runs WHERE id=$1")
            .bind(run)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(Error::RunNotFound)?;
        if !allowed_tenants.contains(&tenant) {
            return Err(Error::RunNotFound);
        }
        let active_count: i32 =
            sqlx::query_scalar("SELECT active_count FROM tenants WHERE id=$1 FOR UPDATE")
                .bind(tenant)
                .fetch_one(&mut *tx)
                .await?;
        if active_count <= 0 {
            return Err(Error::CorruptScheduler);
        }
        let row = sqlx::query("SELECT state,idempotency_key,lease_owner,lease_epoch,lease_expires_at>clock_timestamp() AS live,active_slot_held,cancel_requested FROM runs WHERE tenant_id=$1 AND id=$2 FOR UPDATE")
            .bind(tenant).bind(run).fetch_one(&mut *tx).await?;
        if row.try_get::<String, _>("state")? != "running"
            || row.try_get::<Option<String>, _>("lease_owner")?.as_deref() != Some(worker)
            || row.try_get::<i64, _>("lease_epoch")? != epoch
            || !row.try_get::<Option<bool>, _>("live")?.unwrap_or(false)
            || !row.try_get::<bool, _>("active_slot_held")?
        {
            return Err(Error::LeaseConflict);
        }
        let unresolved: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM effects WHERE tenant_id=$1 AND run_id=$2 AND state IN ('PREPARED','DISPATCHING','OUTCOME_UNKNOWN'))")
            .bind(tenant).bind(run).fetch_one(&mut *tx).await?;
        if unresolved {
            return Err(Error::LeaseConflict);
        }
        let cancel: bool = row.try_get("cancel_requested")?;
        let key: String = row.try_get("idempotency_key")?;
        let state = if cancel {
            "cancelled"
        } else if error_code.is_some() {
            "failed"
        } else {
            "succeeded"
        };
        let event = match state {
            "cancelled" => "run.cancelled",
            "failed" => "run.failed",
            _ => "run.succeeded",
        };
        let updated = sqlx::query(
            "UPDATE tenants SET active_count=active_count-1 WHERE id=$1 AND active_count>0",
        )
        .bind(tenant)
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(Error::CorruptScheduler);
        }
        sqlx::query("UPDATE runs SET state=$3,output_bytes=$4,error_code=$5,active_slot_held=false,lease_owner=NULL,lease_expires_at=NULL,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2")
            .bind(tenant).bind(run).bind(state).bind(output).bind(error_code)
            .execute(&mut *tx).await?;
        let payload = serde_json::to_vec(&serde_json::json!({"state":state}))
            .map_err(|_| Error::Configuration("finish event cannot be serialized"))?;
        append_event(&mut tx, tenant, run, event, &payload).await?;
        let result = fetch_run_by_key(&mut tx, tenant, &key).await?;
        tx.commit().await?;
        Ok(result)
    }
}
