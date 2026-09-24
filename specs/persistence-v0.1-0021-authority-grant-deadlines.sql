-- Session-local grant deadlines. No existing grant receives a deadline by migration.
-- A row is only admissible with its exact 0015 receipt, current lease and one
-- paired trusted-time observation. The coordinator must insert it with the grant.
CREATE TABLE IF NOT EXISTS authority_clock_sessions (
    session_id TEXT NOT NULL PRIMARY KEY CHECK (length(session_id)=32 AND session_id NOT GLOB '*[^0-9a-f]*'),
    owner_id TEXT NOT NULL CHECK (length(owner_id)>0),
    owner_epoch INTEGER NOT NULL CHECK (typeof(owner_epoch)='integer' AND owner_epoch>=1),
    high_water_monotonic_nanos INTEGER NOT NULL CHECK (typeof(high_water_monotonic_nanos)='integer' AND high_water_monotonic_nanos>=0),
    high_water_observed_unix_nanos INTEGER NOT NULL CHECK (typeof(high_water_observed_unix_nanos)='integer'),
    high_water_state_revision INTEGER NOT NULL CHECK (typeof(high_water_state_revision)='integer') REFERENCES trusted_time_observations(state_revision),
    revision INTEGER NOT NULL CHECK (typeof(revision)='integer' AND revision>=1),
    UNIQUE(owner_id,owner_epoch)
);
CREATE TABLE IF NOT EXISTS authority_grant_deadlines (
    grant_id TEXT NOT NULL PRIMARY KEY REFERENCES authority_issuance_receipts(grant_id),
    token_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    execution_binding_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    policy_decision_id TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    grant_expires_at TEXT NOT NULL,
    grant_expiry_unix_nanos INTEGER NOT NULL CHECK (typeof(grant_expiry_unix_nanos)='integer'),
    approval_id TEXT,
    approval_request_expires_at TEXT,
    approval_request_expiry_unix_nanos INTEGER,
    approval_decision_id TEXT,
    approved_until TEXT,
    approved_until_unix_nanos INTEGER,
    session_id TEXT NOT NULL REFERENCES authority_clock_sessions(session_id),
    owner_id TEXT NOT NULL,
    owner_epoch INTEGER NOT NULL CHECK (typeof(owner_epoch)='integer' AND owner_epoch>=1),
    issued_state_revision INTEGER NOT NULL CHECK (typeof(issued_state_revision)='integer') REFERENCES trusted_time_observations(state_revision),
    issued_monotonic_nanos INTEGER NOT NULL CHECK (typeof(issued_monotonic_nanos)='integer' AND issued_monotonic_nanos>=0),
    deadline_monotonic_nanos INTEGER NOT NULL CHECK (typeof(deadline_monotonic_nanos)='integer' AND deadline_monotonic_nanos>issued_monotonic_nanos),
    issued_observed_unix_nanos INTEGER NOT NULL CHECK (typeof(issued_observed_unix_nanos)='integer'),
    issued_effective_unix_nanos INTEGER NOT NULL CHECK (typeof(issued_effective_unix_nanos)='integer' AND issued_effective_unix_nanos>=0 AND issued_effective_unix_nanos>=issued_observed_unix_nanos),
    effective_expiry_unix_nanos INTEGER NOT NULL CHECK (typeof(effective_expiry_unix_nanos)='integer' AND effective_expiry_unix_nanos>issued_effective_unix_nanos),
    CHECK (effective_expiry_unix_nanos<=grant_expiry_unix_nanos),
    CHECK ((approval_id IS NULL AND approval_request_expires_at IS NULL
            AND approval_request_expiry_unix_nanos IS NULL AND approval_decision_id IS NULL
            AND approved_until IS NULL AND approved_until_unix_nanos IS NULL)
        OR (approval_id IS NOT NULL AND approval_request_expires_at IS NOT NULL
            AND typeof(approval_request_expiry_unix_nanos)='integer'
            AND approval_decision_id IS NOT NULL AND approved_until IS NOT NULL
            AND typeof(approved_until_unix_nanos)='integer'
            AND effective_expiry_unix_nanos<=approval_request_expiry_unix_nanos
            AND effective_expiry_unix_nanos<=approved_until_unix_nanos)),
    CHECK (deadline_monotonic_nanos-issued_monotonic_nanos=
           effective_expiry_unix_nanos-issued_effective_unix_nanos)
);
CREATE TABLE IF NOT EXISTS authority_grant_expiry_latches (
    grant_id TEXT NOT NULL PRIMARY KEY REFERENCES authority_grant_deadlines(grant_id),
    session_id TEXT NOT NULL REFERENCES authority_clock_sessions(session_id),
    owner_id TEXT NOT NULL,
    owner_epoch INTEGER NOT NULL CHECK (typeof(owner_epoch)='integer' AND owner_epoch>=1),
    observed_state_revision INTEGER NOT NULL CHECK (typeof(observed_state_revision)='integer') REFERENCES trusted_time_observations(state_revision),
    observed_monotonic_nanos INTEGER NOT NULL CHECK (typeof(observed_monotonic_nanos)='integer' AND observed_monotonic_nanos>=0),
    observed_unix_nanos INTEGER NOT NULL CHECK (typeof(observed_unix_nanos)='integer'),
    observed_effective_unix_nanos INTEGER NOT NULL CHECK (typeof(observed_effective_unix_nanos)='integer' AND observed_effective_unix_nanos>=observed_unix_nanos),
    reason TEXT NOT NULL CHECK (reason IN ('MONOTONIC_DEADLINE','WALL_EXPIRY'))
);
CREATE TRIGGER IF NOT EXISTS authority_clock_session_exact_insert
BEFORE INSERT ON authority_clock_sessions
WHEN EXISTS (SELECT 1 FROM authority_clock_sessions WHERE session_id=NEW.session_id
             OR (owner_id=NEW.owner_id AND owner_epoch=NEW.owner_epoch))
 OR NEW.revision<>1
 OR NOT EXISTS (
    SELECT 1 FROM task_manager_lease l
    JOIN trusted_time_state s ON s.singleton_id=1 AND s.confidence='TRUSTED_LOCAL'
    JOIN trusted_time_observations o ON o.state_revision=s.revision
    WHERE l.singleton_id=1 AND l.owner_id=NEW.owner_id AND l.fence_epoch=NEW.owner_epoch
      AND s.revision=NEW.high_water_state_revision AND o.confidence='TRUSTED_LOCAL'
      AND o.monotonic_nanos=NEW.high_water_monotonic_nanos
      AND o.observed_unix_nanos=NEW.high_water_observed_unix_nanos)
BEGIN SELECT RAISE(ABORT,'clock session lacks exact lease and paired time'); END;
CREATE TRIGGER IF NOT EXISTS authority_clock_session_monotone_update
BEFORE UPDATE ON authority_clock_sessions
WHEN NEW.session_id IS NOT OLD.session_id OR NEW.owner_id IS NOT OLD.owner_id
 OR NEW.owner_epoch IS NOT OLD.owner_epoch OR NEW.revision<>OLD.revision+1
 OR NEW.high_water_monotonic_nanos<OLD.high_water_monotonic_nanos
 OR NEW.high_water_state_revision<=OLD.high_water_state_revision
 OR NOT EXISTS (
    SELECT 1 FROM task_manager_lease l
    JOIN trusted_time_state s ON s.singleton_id=1 AND s.confidence='TRUSTED_LOCAL'
    JOIN trusted_time_observations o ON o.state_revision=s.revision
    WHERE l.singleton_id=1 AND l.owner_id=OLD.owner_id AND l.fence_epoch=OLD.owner_epoch
      AND s.revision=NEW.high_water_state_revision AND o.confidence='TRUSTED_LOCAL'
      AND o.monotonic_nanos=NEW.high_water_monotonic_nanos
      AND o.observed_unix_nanos=NEW.high_water_observed_unix_nanos)
BEGIN SELECT RAISE(ABORT,'clock session high-water cannot regress or detach'); END;
CREATE TRIGGER IF NOT EXISTS authority_clock_session_no_delete
BEFORE DELETE ON authority_clock_sessions
BEGIN SELECT RAISE(ABORT,'clock session is durable'); END;
CREATE TRIGGER IF NOT EXISTS authority_grant_deadline_exact_insert
BEFORE INSERT ON authority_grant_deadlines
WHEN EXISTS (SELECT 1 FROM authority_grant_deadlines WHERE grant_id=NEW.grant_id)
 OR NOT EXISTS (
    SELECT 1 FROM authority_issuance_receipts r
    JOIN authority_grants g ON g.grant_id=r.grant_id
    LEFT JOIN approval_requests a ON a.approval_id=NEW.approval_id
    LEFT JOIN approval_decisions ad ON ad.decision_id=NEW.approval_decision_id
    JOIN authority_clock_sessions c ON c.session_id=NEW.session_id
    JOIN task_manager_lease l ON l.singleton_id=1
    JOIN trusted_time_state s ON s.singleton_id=1 AND s.confidence='TRUSTED_LOCAL'
    JOIN trusted_time_observations o ON o.state_revision=s.revision
    WHERE r.grant_id=NEW.grant_id AND r.token_id=NEW.token_id
      AND r.task_id=NEW.task_id AND r.execution_binding_id=NEW.execution_binding_id
      AND r.attempt_id=NEW.attempt_id AND r.policy_decision_id=NEW.policy_decision_id
      AND r.issued_at=NEW.issued_at AND g.grant_id=r.grant_id
      AND g.token_id=r.token_id AND g.task_id=r.task_id
      AND g.execution_binding_id=r.execution_binding_id AND g.attempt_id=r.attempt_id
      AND g.policy_decision_id=r.policy_decision_id AND g.issued_at=r.issued_at
      AND g.expires_at=NEW.grant_expires_at AND g.approval_id IS NEW.approval_id
      AND (NEW.approval_id IS NULL OR
           (a.status='APPROVED' AND a.expires_at=NEW.approval_request_expires_at
            AND ad.approval_id=a.approval_id AND ad.decision='APPROVE'
            AND ad.approved_until=NEW.approved_until))
      AND c.owner_id=NEW.owner_id AND c.owner_epoch=NEW.owner_epoch
      AND l.owner_id=NEW.owner_id AND l.fence_epoch=NEW.owner_epoch
      AND s.revision=NEW.issued_state_revision AND o.confidence='TRUSTED_LOCAL'
      AND o.monotonic_nanos=NEW.issued_monotonic_nanos
      AND o.observed_unix_nanos=NEW.issued_observed_unix_nanos
      AND o.expiry_floor_unix_nanos=NEW.issued_effective_unix_nanos
      AND c.high_water_monotonic_nanos=NEW.issued_monotonic_nanos
      AND c.high_water_state_revision=NEW.issued_state_revision)
BEGIN SELECT RAISE(ABORT,'grant deadline lacks exact grant, receipt, session and paired time'); END;
CREATE TRIGGER IF NOT EXISTS authority_grant_deadline_no_update
BEFORE UPDATE ON authority_grant_deadlines
BEGIN SELECT RAISE(ABORT,'grant deadline is immutable'); END;
CREATE TRIGGER IF NOT EXISTS authority_grant_deadline_no_delete
BEFORE DELETE ON authority_grant_deadlines
BEGIN SELECT RAISE(ABORT,'grant deadline is durable'); END;
CREATE TRIGGER IF NOT EXISTS authority_grant_expiry_exact_insert
BEFORE INSERT ON authority_grant_expiry_latches
WHEN EXISTS (SELECT 1 FROM authority_grant_expiry_latches WHERE grant_id=NEW.grant_id)
 OR NOT EXISTS (
    SELECT 1 FROM authority_grant_deadlines d
    JOIN authority_clock_sessions c ON c.session_id=d.session_id
    JOIN task_manager_lease l ON l.singleton_id=1
    JOIN trusted_time_state s ON s.singleton_id=1 AND s.confidence='TRUSTED_LOCAL'
    JOIN trusted_time_observations o ON o.state_revision=s.revision
    WHERE d.grant_id=NEW.grant_id AND d.session_id=NEW.session_id
      AND d.owner_id=NEW.owner_id AND d.owner_epoch=NEW.owner_epoch
      AND c.owner_id=d.owner_id AND c.owner_epoch=d.owner_epoch
      AND l.owner_id=d.owner_id AND l.fence_epoch=d.owner_epoch
      AND s.revision=NEW.observed_state_revision AND o.confidence='TRUSTED_LOCAL'
      AND o.monotonic_nanos=NEW.observed_monotonic_nanos
      AND o.observed_unix_nanos=NEW.observed_unix_nanos
      AND o.expiry_floor_unix_nanos=NEW.observed_effective_unix_nanos
      AND c.high_water_monotonic_nanos>=NEW.observed_monotonic_nanos
      AND ((NEW.reason='MONOTONIC_DEADLINE' AND NEW.observed_monotonic_nanos>=d.deadline_monotonic_nanos)
        OR (NEW.reason='WALL_EXPIRY' AND NEW.observed_effective_unix_nanos>=d.effective_expiry_unix_nanos)))
BEGIN SELECT RAISE(ABORT,'grant expiry lacks exact session time or deadline'); END;
CREATE TRIGGER IF NOT EXISTS authority_grant_expiry_no_update
BEFORE UPDATE ON authority_grant_expiry_latches
BEGIN SELECT RAISE(ABORT,'grant expiry is immutable'); END;
CREATE TRIGGER IF NOT EXISTS authority_grant_expiry_no_delete
BEFORE DELETE ON authority_grant_expiry_latches
BEGIN SELECT RAISE(ABORT,'grant expiry is durable'); END;
-- SQLite OR REPLACE may bypass DELETE triggers when recursive_triggers is off.
CREATE TRIGGER IF NOT EXISTS authority_grant_deadline_grant_no_replace
BEFORE INSERT ON authority_grants
WHEN EXISTS (SELECT 1 FROM authority_grant_deadlines WHERE grant_id=NEW.grant_id OR token_id=NEW.token_id)
BEGIN SELECT RAISE(ABORT,'deadline-bound grant cannot be replaced'); END;
CREATE TRIGGER IF NOT EXISTS authority_grant_deadline_grant_identity_guard
BEFORE UPDATE ON authority_grants
WHEN EXISTS (SELECT 1 FROM authority_grant_deadlines WHERE grant_id=OLD.grant_id)
 AND (NEW.grant_id IS NOT OLD.grant_id OR NEW.token_id IS NOT OLD.token_id
   OR NEW.task_id IS NOT OLD.task_id
   OR NEW.semantic_program_hash IS NOT OLD.semantic_program_hash
   OR NEW.node_id IS NOT OLD.node_id OR NEW.capability IS NOT OLD.capability
   OR NEW.principal_kind IS NOT OLD.principal_kind OR NEW.principal_id IS NOT OLD.principal_id
   OR NEW.execution_binding_id IS NOT OLD.execution_binding_id
   OR NEW.attempt_id IS NOT OLD.attempt_id OR NEW.policy_decision_id IS NOT OLD.policy_decision_id
   OR NEW.policy_snapshot_id IS NOT OLD.policy_snapshot_id
   OR NEW.approval_id IS NOT OLD.approval_id OR NEW.grants_json IS NOT OLD.grants_json
   OR NEW.scope IS NOT OLD.scope OR NEW.max_uses IS NOT OLD.max_uses
   OR NEW.delegable IS NOT OLD.delegable
   OR NEW.max_delegation_depth IS NOT OLD.max_delegation_depth
   OR NEW.issued_at IS NOT OLD.issued_at OR NEW.expires_at IS NOT OLD.expires_at
   OR NEW.uses_consumed<OLD.uses_consumed
   OR (OLD.state<>'ACTIVE' AND NEW.uses_consumed IS NOT OLD.uses_consumed)
   OR (OLD.state<>'ACTIVE' AND NEW.state IS NOT OLD.state)
   OR (OLD.state='ACTIVE' AND NEW.state NOT IN ('ACTIVE','CONSUMED','EXPIRED','REVOKED'))
   OR (NEW.state='CONSUMED' AND (NEW.max_uses IS NULL OR NEW.uses_consumed<NEW.max_uses))
   OR (NEW.state='REVOKED' AND NEW.revoked_at IS NULL)
   OR (NEW.state<>'REVOKED' AND NEW.revoked_at IS NOT NULL)
   OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NOT OLD.revoked_at)
   OR (OLD.revocation_reason_code IS NOT NULL AND NEW.revocation_reason_code IS NOT OLD.revocation_reason_code))
BEGIN SELECT RAISE(ABORT,'deadline-bound grant identity is immutable'); END;
CREATE TRIGGER IF NOT EXISTS authority_grant_deadline_grant_no_delete
BEFORE DELETE ON authority_grants
WHEN EXISTS (SELECT 1 FROM authority_grant_deadlines WHERE grant_id=OLD.grant_id)
BEGIN SELECT RAISE(ABORT,'deadline-bound grant is durable'); END;
CREATE TRIGGER IF NOT EXISTS authority_grant_deadline_receipt_no_replace
BEFORE INSERT ON authority_issuance_receipts
WHEN EXISTS (SELECT 1 FROM authority_grant_deadlines WHERE grant_id=NEW.grant_id)
BEGIN SELECT RAISE(ABORT,'deadline-bound receipt cannot be replaced'); END;
