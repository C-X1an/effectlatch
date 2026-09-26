-- EffectLatch initial schema.
CREATE TABLE tenants (
 id uuid PRIMARY KEY, name text NOT NULL,
 queue_limit integer NOT NULL DEFAULT 100 CHECK(queue_limit BETWEEN 1 AND 1000),
 active_limit integer NOT NULL DEFAULT 1 CHECK(active_limit BETWEEN 1 AND 4),
 active_count integer NOT NULL DEFAULT 0 CHECK(active_count >= 0 AND active_count <= active_limit),
 last_served_seq bigint NOT NULL DEFAULT 0
);
CREATE TABLE scheduler_state (singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton), dispatch_seq bigint NOT NULL DEFAULT 0);
INSERT INTO scheduler_state(singleton) VALUES(true);
CREATE TABLE modules (
 tenant_id uuid NOT NULL REFERENCES tenants(id), digest bytea NOT NULL CHECK(octet_length(digest)=32),
 wasm bytea NOT NULL CHECK(octet_length(wasm)<=2097152), abi_version integer NOT NULL CHECK(abi_version=1),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(tenant_id,digest)
);
CREATE TABLE grants (
 tenant_id uuid NOT NULL REFERENCES tenants(id), id uuid NOT NULL,
 parent_id uuid, depth integer NOT NULL CHECK(depth BETWEEN 0 AND 4),
 actions text[] NOT NULL CHECK(cardinality(actions) BETWEEN 1 AND 16),
 destinations text[] NOT NULL CHECK(cardinality(destinations) BETWEEN 1 AND 16),
 projects text[] NOT NULL CHECK(cardinality(projects) BETWEEN 1 AND 16),
 max_effects bigint NOT NULL CHECK(max_effects BETWEEN 1 AND 100),
 used_effects bigint NOT NULL DEFAULT 0 CHECK(used_effects>=0 AND used_effects<=max_effects),
 expires_at timestamptz NOT NULL, revoked_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,parent_id) REFERENCES grants(tenant_id,id),
 CHECK ((parent_id IS NULL AND depth=0) OR (parent_id IS NOT NULL AND depth>0))
);
CREATE INDEX grants_parent ON grants(tenant_id,parent_id);
CREATE TABLE runs (
 tenant_id uuid NOT NULL REFERENCES tenants(id), id uuid NOT NULL,
 idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 128),
 request_hash bytea NOT NULL CHECK(octet_length(request_hash)=32),
 module_digest bytea NOT NULL, grant_id uuid NOT NULL,
 input_bytes bytea CHECK(octet_length(input_bytes)<=65536), output_bytes bytea CHECK(octet_length(output_bytes)<=65536),
 limits jsonb NOT NULL, state text NOT NULL CHECK(state IN ('queued','leased','running','succeeded','failed','cancelled','needs_reconciliation')),
 lease_epoch bigint NOT NULL DEFAULT 0 CHECK(lease_epoch>=0), lease_owner text, lease_expires_at timestamptz,
 attempt integer NOT NULL DEFAULT 0 CHECK(attempt BETWEEN 0 AND 3),
 active_slot_held boolean NOT NULL DEFAULT false, cancel_requested boolean NOT NULL DEFAULT false,
 error_code text, next_event_seq bigint NOT NULL DEFAULT 1,
 last_event_hash bytea NOT NULL DEFAULT decode(repeat('00',32),'hex') CHECK(octet_length(last_event_hash)=32),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 payload_expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '24 hours',
 PRIMARY KEY(tenant_id,id), UNIQUE(id), UNIQUE(tenant_id,idempotency_key),
 FOREIGN KEY(tenant_id,module_digest) REFERENCES modules(tenant_id,digest),
 FOREIGN KEY(tenant_id,grant_id) REFERENCES grants(tenant_id,id)
);
CREATE INDEX runs_queue ON runs(state,created_at,id) WHERE state='queued';
CREATE INDEX runs_tenant_list ON runs(tenant_id,created_at,id);
CREATE INDEX runs_expired_lease ON runs(lease_expires_at) WHERE active_slot_held;
CREATE TABLE effects (
 tenant_id uuid NOT NULL, run_id uuid NOT NULL, ordinal integer NOT NULL CHECK(ordinal BETWEEN 0 AND 7),
 request_hash bytea NOT NULL CHECK(octet_length(request_hash)=32), request_bytes bytea CHECK(octet_length(request_bytes)<=16384),
 action text NOT NULL, destination text NOT NULL, project text NOT NULL,
 adapter_config_hash bytea NOT NULL CHECK(octet_length(adapter_config_hash)=32),
 idempotency_supported boolean NOT NULL, provider_key text NOT NULL,
 state text NOT NULL CHECK(state IN ('PREPARED','DISPATCHING','COMMITTED','DEFINITELY_FAILED','OUTCOME_UNKNOWN')),
 dispatch_nonce uuid, dispatch_epoch bigint, first_intent_at timestamptz, dispatch_deadline timestamptz,
 retry_not_after timestamptz, send_attempts integer NOT NULL DEFAULT 0 CHECK(send_attempts BETWEEN 0 AND 3),
 reservation_charged boolean NOT NULL DEFAULT false,
 response_bytes bytea CHECK(octet_length(response_bytes)<=65536), response_hash bytea,
 external_reference text, resolved_by text, resolution_reason text, resolution_evidence_hash bytea,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,run_id,ordinal), UNIQUE(tenant_id,provider_key),
 FOREIGN KEY(tenant_id,run_id) REFERENCES runs(tenant_id,id),
 CHECK(response_hash IS NULL OR octet_length(response_hash)=32)
);
CREATE INDEX effects_dispatch_deadline ON effects(dispatch_deadline) WHERE state='DISPATCHING';
CREATE TABLE effect_reservations (
 tenant_id uuid NOT NULL, run_id uuid NOT NULL, ordinal integer NOT NULL, grant_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,run_id,ordinal,grant_id),
 FOREIGN KEY(tenant_id,run_id,ordinal) REFERENCES effects(tenant_id,run_id,ordinal),
 FOREIGN KEY(tenant_id,grant_id) REFERENCES grants(tenant_id,id)
);
CREATE TABLE run_events (
 tenant_id uuid NOT NULL, run_id uuid NOT NULL, seq bigint NOT NULL CHECK(seq>0),
 kind text NOT NULL, payload_bytes bytea NOT NULL CHECK(octet_length(payload_bytes)<=16384),
 prev_hash bytea NOT NULL CHECK(octet_length(prev_hash)=32), event_hash bytea NOT NULL CHECK(octet_length(event_hash)=32),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(tenant_id,run_id,seq),
 FOREIGN KEY(tenant_id,run_id) REFERENCES runs(tenant_id,id)
);
CREATE TABLE checkpoints (
 tenant_id uuid NOT NULL, run_id uuid NOT NULL, terminal_seq bigint NOT NULL,
 terminal_hash bytea NOT NULL CHECK(octet_length(terminal_hash)=32), public_key bytea NOT NULL CHECK(octet_length(public_key)=32),
 signature bytea NOT NULL CHECK(octet_length(signature)=64), created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,run_id,terminal_seq), FOREIGN KEY(tenant_id,run_id) REFERENCES runs(tenant_id,id)
);
CREATE TABLE operator_events (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants(id),
 actor_id text NOT NULL, action text NOT NULL, object_id uuid NOT NULL,
 detail_hash bytea NOT NULL CHECK(octet_length(detail_hash)=32), created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
