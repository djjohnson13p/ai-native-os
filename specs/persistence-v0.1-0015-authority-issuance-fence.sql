-- Authority issuance fence. Historical grant rows are retained, but none is
-- backfilled: pre-0015 rows cannot prove coordinator issuance. The trusted
-- Authority Coordinator will insert a receipt only in the same transaction as
-- a fully checked grant. No provider/planner-facing API writes this table.
CREATE TABLE IF NOT EXISTS authority_issuance_receipts (
    grant_id TEXT PRIMARY KEY REFERENCES authority_grants(grant_id),
    token_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    execution_binding_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    policy_decision_id TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    issuance_profile TEXT NOT NULL CHECK (issuance_profile='coordinator-issued-v0.1'),
    CHECK (length(token_id)>0 AND length(task_id)>0 AND
           length(execution_binding_id)>0 AND length(attempt_id)>0 AND
           length(policy_decision_id)>0 AND length(issued_at)>0)
);
CREATE TRIGGER IF NOT EXISTS authority_issuance_receipt_exact_insert
BEFORE INSERT ON authority_issuance_receipts
WHEN NOT EXISTS (
    SELECT 1 FROM authority_grants g
    JOIN policy_decisions d ON d.decision_id=g.policy_decision_id
      AND d.task_id=g.task_id AND d.semantic_program_hash=g.semantic_program_hash
      AND d.node_id=g.node_id AND d.policy_snapshot_id=g.policy_snapshot_id
      AND d.principal_kind=g.principal_kind AND d.principal_id=g.principal_id
      AND d.decision='ALLOW'
    JOIN authority_requests r ON r.request_id=d.authority_request_id
      AND r.task_id=g.task_id AND r.semantic_program_hash=g.semantic_program_hash
      AND r.node_id=g.node_id AND r.capability=g.capability
      AND r.principal_kind=g.principal_kind AND r.principal_id=g.principal_id
      AND r.execution_binding_id=g.execution_binding_id
      AND r.attempt_id=g.attempt_id
    WHERE g.grant_id=NEW.grant_id AND g.token_id=NEW.token_id
      AND g.task_id=NEW.task_id
      AND g.execution_binding_id=NEW.execution_binding_id
      AND g.attempt_id=NEW.attempt_id
      AND g.policy_decision_id=NEW.policy_decision_id
      AND g.issued_at=NEW.issued_at
      AND g.state='ACTIVE' AND g.delegable=0 AND g.max_delegation_depth=0
)
BEGIN SELECT RAISE(ABORT, 'authority receipt must match exact grant'); END;
CREATE TRIGGER IF NOT EXISTS authority_issuance_receipt_no_update
BEFORE UPDATE ON authority_issuance_receipts
BEGIN SELECT RAISE(ABORT, 'authority receipt is immutable'); END;
CREATE TRIGGER IF NOT EXISTS authority_issuance_receipt_no_delete
BEFORE DELETE ON authority_issuance_receipts
BEGIN SELECT RAISE(ABORT, 'authority receipt is immutable'); END;
