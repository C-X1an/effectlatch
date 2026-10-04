-- An expired, safe-to-replay run cannot re-enter a full pending queue.
-- Keep it durable without consuming an active slot until scheduler capacity
-- permits promotion back to queued.
ALTER TABLE runs DROP CONSTRAINT runs_state_check;
ALTER TABLE runs ADD CONSTRAINT runs_state_check CHECK (
 state IN ('queued','retry_wait','leased','running','succeeded','failed','cancelled','needs_reconciliation')
);
CREATE INDEX runs_retry_wait ON runs(created_at,id) WHERE state='retry_wait';
