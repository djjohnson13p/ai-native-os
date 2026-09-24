-- Private, non-executable policy evaluation for pending local candidates.
-- Policy content is immutable; every activation has a distinct revision.
CREATE TABLE IF NOT EXISTS authority_policy_payloads (
    content_hash TEXT PRIMARY KEY,
    policy_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS authority_policy_activations (
    revision INTEGER PRIMARY KEY CHECK (revision > 0),
    content_hash TEXT NOT NULL REFERENCES authority_policy_payloads(content_hash),
    activated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS authority_evaluation_fingerprints (
    decision_id TEXT PRIMARY KEY REFERENCES policy_decisions(decision_id),
    candidate_id TEXT NOT NULL REFERENCES authority_candidate_reservations(candidate_id),
    fingerprint TEXT NOT NULL,
    activation_revision INTEGER NOT NULL REFERENCES authority_policy_activations(revision),
    evaluated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS authority_approval_bindings (
    approval_id TEXT PRIMARY KEY REFERENCES approval_requests(approval_id),
    candidate_id TEXT NOT NULL REFERENCES authority_candidate_reservations(candidate_id),
    fingerprint TEXT NOT NULL,
    activation_revision INTEGER NOT NULL REFERENCES authority_policy_activations(revision),
    requiring_decision_id TEXT NOT NULL REFERENCES policy_decisions(decision_id),
    revoked_at TEXT
);
CREATE TRIGGER IF NOT EXISTS authority_policy_payload_no_duplicate
BEFORE INSERT ON authority_policy_payloads
WHEN EXISTS (SELECT 1 FROM authority_policy_payloads WHERE content_hash=NEW.content_hash)
BEGIN SELECT RAISE(ABORT,'policy payload already exists'); END;
CREATE TRIGGER IF NOT EXISTS authority_policy_activation_no_duplicate
BEFORE INSERT ON authority_policy_activations
WHEN EXISTS (SELECT 1 FROM authority_policy_activations WHERE revision=NEW.revision)
BEGIN SELECT RAISE(ABORT,'policy activation already exists'); END;
CREATE TRIGGER IF NOT EXISTS authority_evaluation_no_duplicate
BEFORE INSERT ON authority_evaluation_fingerprints
WHEN EXISTS (SELECT 1 FROM authority_evaluation_fingerprints WHERE decision_id=NEW.decision_id)
BEGIN SELECT RAISE(ABORT,'evaluation already exists'); END;
CREATE TRIGGER IF NOT EXISTS authority_approval_binding_no_duplicate
BEFORE INSERT ON authority_approval_bindings
WHEN EXISTS (SELECT 1 FROM authority_approval_bindings WHERE approval_id=NEW.approval_id)
BEGIN SELECT RAISE(ABORT,'approval binding already exists'); END;
CREATE TRIGGER IF NOT EXISTS authority_approval_binding_exact_insert
BEFORE INSERT ON authority_approval_bindings
WHEN NOT EXISTS (
    SELECT 1 FROM approval_requests a
    JOIN policy_decisions d ON d.decision_id=NEW.requiring_decision_id
    JOIN authority_evaluation_fingerprints e ON e.decision_id=d.decision_id
    WHERE a.approval_id=NEW.approval_id AND a.status='PENDING'
      AND d.authority_request_id=a.authority_request_id
      AND d.approval_request_id=a.approval_id AND d.decision='REQUIRE_APPROVAL'
      AND d.task_id=a.task_id AND d.semantic_program_hash=a.semantic_program_hash
      AND d.node_id=a.node_id AND d.action=a.action
      AND e.candidate_id=NEW.candidate_id AND e.fingerprint=NEW.fingerprint
      AND e.activation_revision=NEW.activation_revision)
BEGIN SELECT RAISE(ABORT,'approval has no exact requiring evaluation'); END;
CREATE TRIGGER IF NOT EXISTS authority_approval_request_no_duplicate
BEFORE INSERT ON approval_requests
WHEN EXISTS (SELECT 1 FROM authority_approval_bindings WHERE approval_id=NEW.approval_id)
BEGIN SELECT RAISE(ABORT,'bound approval request already exists'); END;
CREATE TRIGGER IF NOT EXISTS authority_approval_request_immutable
BEFORE UPDATE ON approval_requests
WHEN EXISTS (SELECT 1 FROM authority_approval_bindings WHERE approval_id=OLD.approval_id)
 AND (NEW.approval_id<>OLD.approval_id OR NEW.authority_request_id<>OLD.authority_request_id
   OR NEW.task_id<>OLD.task_id OR NEW.semantic_program_hash<>OLD.semantic_program_hash
   OR NEW.node_id<>OLD.node_id OR NEW.action<>OLD.action OR NEW.request_json<>OLD.request_json
   OR NEW.created_at<>OLD.created_at OR NEW.expires_at IS NOT OLD.expires_at)
BEGIN SELECT RAISE(ABORT,'bound approval request is immutable'); END;
CREATE TRIGGER IF NOT EXISTS authority_approval_request_no_delete
BEFORE DELETE ON approval_requests
WHEN EXISTS (SELECT 1 FROM authority_approval_bindings WHERE approval_id=OLD.approval_id)
BEGIN SELECT RAISE(ABORT,'bound approval request is durable'); END;
CREATE TRIGGER IF NOT EXISTS authority_approval_decision_no_duplicate
BEFORE INSERT ON approval_decisions
WHEN EXISTS (
    SELECT 1 FROM approval_decisions existing
    WHERE (existing.decision_id=NEW.decision_id AND (
        EXISTS (SELECT 1 FROM authority_approval_bindings WHERE approval_id=existing.approval_id)
        OR EXISTS (SELECT 1 FROM authority_approval_bindings WHERE approval_id=NEW.approval_id)))
       OR (existing.approval_id=NEW.approval_id AND
           EXISTS (SELECT 1 FROM authority_approval_bindings WHERE approval_id=NEW.approval_id)))
BEGIN SELECT RAISE(ABORT,'bound approval decision already exists'); END;
CREATE TRIGGER IF NOT EXISTS authority_approval_decision_immutable
BEFORE UPDATE ON approval_decisions
WHEN EXISTS (SELECT 1 FROM authority_approval_bindings WHERE approval_id=OLD.approval_id)
BEGIN SELECT RAISE(ABORT,'bound approval decision is immutable'); END;
CREATE TRIGGER IF NOT EXISTS authority_approval_decision_no_delete
BEFORE DELETE ON approval_decisions
WHEN EXISTS (SELECT 1 FROM authority_approval_bindings WHERE approval_id=OLD.approval_id)
BEGIN SELECT RAISE(ABORT,'bound approval decision is durable'); END;
CREATE TRIGGER IF NOT EXISTS authority_policy_payload_no_update
BEFORE UPDATE ON authority_policy_payloads BEGIN SELECT RAISE(ABORT,'policy payload is immutable'); END;
CREATE TRIGGER IF NOT EXISTS authority_policy_payload_no_delete
BEFORE DELETE ON authority_policy_payloads BEGIN SELECT RAISE(ABORT,'policy payload is immutable'); END;
CREATE TRIGGER IF NOT EXISTS authority_policy_activation_no_update
BEFORE UPDATE ON authority_policy_activations BEGIN SELECT RAISE(ABORT,'policy activation is immutable'); END;
CREATE TRIGGER IF NOT EXISTS authority_policy_activation_no_delete
BEFORE DELETE ON authority_policy_activations BEGIN SELECT RAISE(ABORT,'policy activation is immutable'); END;
CREATE TRIGGER IF NOT EXISTS authority_evaluation_no_update
BEFORE UPDATE ON authority_evaluation_fingerprints BEGIN SELECT RAISE(ABORT,'evaluation is immutable'); END;
CREATE TRIGGER IF NOT EXISTS authority_evaluation_no_delete
BEFORE DELETE ON authority_evaluation_fingerprints BEGIN SELECT RAISE(ABORT,'evaluation is immutable'); END;
CREATE TRIGGER IF NOT EXISTS authority_approval_binding_immutable
BEFORE UPDATE ON authority_approval_bindings
WHEN NEW.approval_id<>OLD.approval_id OR NEW.candidate_id<>OLD.candidate_id
  OR NEW.fingerprint<>OLD.fingerprint OR NEW.activation_revision<>OLD.activation_revision
  OR NEW.requiring_decision_id<>OLD.requiring_decision_id OR OLD.revoked_at IS NOT NULL
  OR NEW.revoked_at IS NULL
BEGIN SELECT RAISE(ABORT,'approval binding is immutable'); END;
CREATE TRIGGER IF NOT EXISTS authority_approval_binding_no_delete
BEFORE DELETE ON authority_approval_bindings BEGIN SELECT RAISE(ABORT,'approval binding is durable'); END;
CREATE TRIGGER IF NOT EXISTS authority_approval_status_guard
BEFORE UPDATE OF status ON approval_requests
WHEN EXISTS (SELECT 1 FROM authority_approval_bindings WHERE approval_id=OLD.approval_id)
 AND (OLD.status<>'PENDING' OR NEW.status NOT IN ('APPROVED','DENIED','EXPIRED','CANCELLED','STALE'))
BEGIN SELECT RAISE(ABORT,'approval status transition is invalid'); END;
