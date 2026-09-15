-- AI-Native OS v0.1 control-plane persistence draft
--
-- Architecture reference: docs/35-v0.1-persistence-model.md
-- Pre-v1: breaking changes are expected.
-- Large artifact bytes, model weights, and raw secrets do NOT belong in this DB.

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA busy_timeout = 5000;

BEGIN;

CREATE TABLE IF NOT EXISTS schema_migrations (
    migration_id        TEXT PRIMARY KEY,
    checksum            TEXT NOT NULL,
    applied_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
    task_id                 TEXT PRIMARY KEY,
    revision                INTEGER NOT NULL CHECK (revision >= 1),
    state                   TEXT NOT NULL CHECK (state IN (
        'CREATED', 'PLANNING', 'WAITING_FOR_INPUT', 'WAITING_FOR_AUTH',
        'RUNNABLE', 'RUNNING', 'VERIFYING', 'PAUSED', 'RECOVERING',
        'ROLLING_BACK', 'COMPLETED', 'FAILED', 'CANCELLED', 'ROLLED_BACK'
    )),
    state_reason_json       TEXT,
    principal_kind          TEXT NOT NULL CHECK (principal_kind IN ('user', 'system-service')),
    principal_id            TEXT NOT NULL,
    workspace_id            TEXT,
    original_intent         TEXT NOT NULL,
    normalized_intent_json  TEXT,
    active_program_revision INTEGER,
    constraints_json        TEXT,
    failure_json            TEXT,
    recovery_json           TEXT,
    created_at              TEXT NOT NULL,
    updated_at              TEXT NOT NULL,
    completed_at            TEXT,
    CHECK (length(task_id) > 0),
    CHECK (length(original_intent) > 0)
);

CREATE TABLE IF NOT EXISTS plan_revisions (
    task_id             TEXT NOT NULL,
    plan_revision       INTEGER NOT NULL CHECK (plan_revision >= 1),
    plan_id             TEXT NOT NULL,
    planner_kind        TEXT,
    planner_provider    TEXT,
    plan_json           TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    superseded_at       TEXT,
    PRIMARY KEY (task_id, plan_revision),
    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS registry_snapshots (
    snapshot_id         TEXT PRIMARY KEY,
    generation          TEXT,
    manifest_json       TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    publisher_id        TEXT,
    signature_ref       TEXT,
    CHECK (length(snapshot_id) > 0)
);

CREATE TABLE IF NOT EXISTS validation_results (
    validation_result_id TEXT PRIMARY KEY,
    task_id               TEXT,
    program_id            TEXT,
    ir_version            TEXT,
    valid                 INTEGER NOT NULL CHECK (valid IN (0, 1)),
    semantic_hash         TEXT,
    registry_snapshot_id  TEXT,
    validator_id          TEXT NOT NULL,
    validator_version     TEXT NOT NULL,
    validator_build_hash  TEXT,
    result_json           TEXT NOT NULL,
    validated_at          TEXT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE,
    FOREIGN KEY (registry_snapshot_id) REFERENCES registry_snapshots(snapshot_id),
    CHECK ((valid = 1 AND semantic_hash IS NOT NULL AND registry_snapshot_id IS NOT NULL)
        OR (valid = 0 AND semantic_hash IS NULL))
);

CREATE TABLE IF NOT EXISTS semantic_program_revisions (
    task_id                    TEXT NOT NULL,
    program_revision           INTEGER NOT NULL CHECK (program_revision >= 1),
    program_id                 TEXT NOT NULL,
    ir_version                 TEXT NOT NULL,
    semantic_hash              TEXT,
    registry_snapshot_id       TEXT,
    validation_result_id       TEXT,
    status                     TEXT NOT NULL CHECK (status IN (
        'candidate', 'validated', 'active', 'superseded', 'rejected'
    )),
    program_json               TEXT NOT NULL,
    created_from_plan_revision INTEGER,
    created_at                 TEXT NOT NULL,
    superseded_at              TEXT,
    superseded_reason          TEXT,
    PRIMARY KEY (task_id, program_revision),
    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE,
    FOREIGN KEY (task_id, created_from_plan_revision)
        REFERENCES plan_revisions(task_id, plan_revision),
    FOREIGN KEY (registry_snapshot_id) REFERENCES registry_snapshots(snapshot_id),
    FOREIGN KEY (validation_result_id) REFERENCES validation_results(validation_result_id),
    CHECK ((status IN ('validated', 'active', 'superseded') AND semantic_hash IS NOT NULL)
        OR status IN ('candidate', 'rejected'))
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_one_active_program_per_task
ON semantic_program_revisions(task_id)
WHERE status = 'active';

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id             TEXT PRIMARY KEY,
    uri                     TEXT NOT NULL UNIQUE,
    semantic_type           TEXT,
    media_type              TEXT NOT NULL,
    format                  TEXT,
    size_bytes              INTEGER CHECK (size_bytes IS NULL OR size_bytes >= 0),
    hash_algorithm          TEXT,
    hash_value              TEXT,
    sensitivity             TEXT NOT NULL CHECK (sensitivity IN (
        'public', 'local', 'private', 'confidential', 'secret'
    )),
    retention_class         TEXT CHECK (retention_class IS NULL OR retention_class IN (
        'ephemeral', 'task', 'persistent', 'user-managed'
    )),
    expires_at              TEXT,
    origin_kind             TEXT NOT NULL CHECK (origin_kind IN (
        'user', 'task', 'provider', 'system', 'remote', 'legacy'
    )),
    origin_task_id          TEXT,
    origin_program_hash     TEXT,
    origin_node_id          TEXT,
    origin_binding_id       TEXT,
    origin_provider_id      TEXT,
    storage_ref             TEXT,
    integrity_state         TEXT NOT NULL DEFAULT 'unknown' CHECK (integrity_state IN (
        'unknown', 'pending', 'verified', 'failed'
    )),
    integrity_verified_at   TEXT,
    integrity_verifier      TEXT,
    labels_json             TEXT,
    created_at              TEXT NOT NULL,
    FOREIGN KEY (origin_task_id) REFERENCES tasks(task_id),
    CHECK ((hash_algorithm IS NULL AND hash_value IS NULL)
        OR (hash_algorithm IS NOT NULL AND hash_value IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS task_artifacts (
    task_id             TEXT NOT NULL,
    artifact_id         TEXT NOT NULL,
    role                TEXT NOT NULL CHECK (role IN (
        'input', 'output', 'intermediate', 'checkpoint'
    )),
    node_id             TEXT,
    added_at            TEXT NOT NULL,
    PRIMARY KEY (task_id, artifact_id, role),
    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE,
    FOREIGN KEY (artifact_id) REFERENCES artifacts(artifact_id)
);

CREATE TABLE IF NOT EXISTS artifact_lineage (
    parent_artifact_id  TEXT NOT NULL,
    child_artifact_id   TEXT NOT NULL,
    task_id             TEXT NOT NULL,
    node_id             TEXT,
    relationship        TEXT NOT NULL CHECK (relationship IN (
        'consumed-by', 'transformed-to', 'verified-as', 'exported-as'
    )),
    created_at          TEXT NOT NULL,
    PRIMARY KEY (parent_artifact_id, child_artifact_id, relationship),
    FOREIGN KEY (parent_artifact_id) REFERENCES artifacts(artifact_id),
    FOREIGN KEY (child_artifact_id) REFERENCES artifacts(artifact_id),
    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE,
    CHECK (parent_artifact_id <> child_artifact_id)
);

CREATE TABLE IF NOT EXISTS policy_decisions (
    policy_decision_id      TEXT PRIMARY KEY,
    task_id                 TEXT NOT NULL,
    semantic_hash           TEXT,
    node_id                 TEXT,
    principal_kind          TEXT NOT NULL,
    principal_id            TEXT NOT NULL,
    provider_id             TEXT,
    decision                TEXT NOT NULL CHECK (decision IN (
        'allow', 'deny', 'require-approval', 'narrowed', 'defer'
    )),
    decision_json           TEXT NOT NULL,
    policy_snapshot_ref     TEXT,
    decided_at              TEXT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id             TEXT PRIMARY KEY,
    task_id                 TEXT NOT NULL,
    semantic_hash           TEXT,
    node_id                 TEXT,
    request_json            TEXT NOT NULL,
    impact_level            INTEGER CHECK (impact_level IS NULL OR (impact_level >= 0 AND impact_level <= 4)),
    state                   TEXT NOT NULL CHECK (state IN (
        'pending', 'approved', 'denied', 'expired', 'cancelled'
    )),
    actor                   TEXT,
    requested_at            TEXT NOT NULL,
    resolved_at             TEXT,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS grant_records (
    token_id                TEXT PRIMARY KEY,
    task_id                 TEXT NOT NULL,
    principal_kind          TEXT NOT NULL,
    principal_id            TEXT NOT NULL,
    metadata_json           TEXT NOT NULL,
    protected_material_ref  TEXT,
    issued_at               TEXT NOT NULL,
    expires_at              TEXT NOT NULL,
    revoked_at              TEXT,
    approval_id             TEXT,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE,
    FOREIGN KEY (approval_id) REFERENCES approvals(approval_id)
);

CREATE TABLE IF NOT EXISTS execution_bindings (
    binding_id              TEXT PRIMARY KEY,
    task_id                 TEXT NOT NULL,
    semantic_hash           TEXT NOT NULL,
    ir_version              TEXT NOT NULL,
    node_id                 TEXT NOT NULL,
    capability              TEXT NOT NULL,
    capability_contract_hash TEXT,
    provider_id             TEXT NOT NULL,
    provider_version        TEXT NOT NULL,
    attempt                 INTEGER NOT NULL CHECK (attempt >= 1),
    policy_decision_id      TEXT NOT NULL,
    execution_profile_ref   TEXT NOT NULL,
    placement_json          TEXT NOT NULL,
    binding_json            TEXT NOT NULL,
    state                   TEXT NOT NULL CHECK (state IN (
        'prepared', 'starting', 'running', 'succeeded', 'failed',
        'cancelled', 'unknown'
    )),
    created_at              TEXT NOT NULL,
    started_at              TEXT,
    finished_at             TEXT,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE,
    FOREIGN KEY (policy_decision_id) REFERENCES policy_decisions(policy_decision_id),
    UNIQUE (task_id, semantic_hash, node_id, attempt)
);

CREATE TABLE IF NOT EXISTS binding_grants (
    binding_id              TEXT NOT NULL,
    token_id                TEXT NOT NULL,
    PRIMARY KEY (binding_id, token_id),
    FOREIGN KEY (binding_id) REFERENCES execution_bindings(binding_id) ON DELETE CASCADE,
    FOREIGN KEY (token_id) REFERENCES grant_records(token_id)
);

CREATE TABLE IF NOT EXISTS operations (
    operation_id            TEXT PRIMARY KEY,
    task_id                 TEXT NOT NULL,
    semantic_hash           TEXT NOT NULL,
    node_id                 TEXT NOT NULL,
    binding_id              TEXT,
    effect_class            TEXT NOT NULL,
    idempotency_key         TEXT,
    state                   TEXT NOT NULL CHECK (state IN (
        'prepared', 'started', 'succeeded', 'failed', 'unknown', 'cancelled'
    )),
    external_receipt        TEXT,
    details_json            TEXT,
    prepared_at             TEXT NOT NULL,
    started_at              TEXT,
    finished_at             TEXT,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE,
    FOREIGN KEY (binding_id) REFERENCES execution_bindings(binding_id)
);

CREATE TABLE IF NOT EXISTS provenance_events (
    event_id                TEXT PRIMARY KEY,
    task_id                 TEXT NOT NULL,
    sequence                INTEGER NOT NULL CHECK (sequence >= 1),
    timestamp               TEXT NOT NULL,
    event_type              TEXT NOT NULL,
    semantic_hash           TEXT,
    ir_version              TEXT,
    registry_snapshot_id    TEXT,
    node_id                 TEXT,
    execution_binding_id    TEXT,
    provider_id             TEXT,
    status                  TEXT,
    previous_event_hash     TEXT,
    event_hash              TEXT,
    event_json              TEXT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE,
    FOREIGN KEY (registry_snapshot_id) REFERENCES registry_snapshots(snapshot_id),
    FOREIGN KEY (execution_binding_id) REFERENCES execution_bindings(binding_id),
    UNIQUE (task_id, sequence)
);

CREATE TABLE IF NOT EXISTS skills (
    skill_id                TEXT NOT NULL,
    version                 TEXT NOT NULL,
    status                  TEXT NOT NULL CHECK (status IN (
        'candidate', 'validated', 'compiled', 'deprecated', 'disabled'
    )),
    manifest_hash           TEXT,
    source_ir_hash          TEXT NOT NULL,
    source_ir_version       TEXT NOT NULL,
    manifest_json           TEXT NOT NULL,
    privacy_scope           TEXT NOT NULL CHECK (privacy_scope IN (
        'local_private', 'account_private', 'organization_private', 'shareable'
    )),
    last_validated_at       TEXT,
    created_at              TEXT NOT NULL,
    updated_at              TEXT NOT NULL,
    PRIMARY KEY (skill_id, version)
);

CREATE INDEX IF NOT EXISTS ix_tasks_state
ON tasks(state);

CREATE INDEX IF NOT EXISTS ix_plan_revisions_task
ON plan_revisions(task_id, plan_revision DESC);

CREATE INDEX IF NOT EXISTS ix_semantic_programs_task
ON semantic_program_revisions(task_id, program_revision DESC);

CREATE INDEX IF NOT EXISTS ix_semantic_programs_hash
ON semantic_program_revisions(semantic_hash);

CREATE INDEX IF NOT EXISTS ix_artifacts_origin_task
ON artifacts(origin_task_id);

CREATE INDEX IF NOT EXISTS ix_task_artifacts_task_role
ON task_artifacts(task_id, role);

CREATE INDEX IF NOT EXISTS ix_policy_decisions_task_node
ON policy_decisions(task_id, semantic_hash, node_id);

CREATE INDEX IF NOT EXISTS ix_execution_bindings_task_state
ON execution_bindings(task_id, state);

CREATE INDEX IF NOT EXISTS ix_operations_task_state
ON operations(task_id, state);

CREATE INDEX IF NOT EXISTS ix_provenance_task_sequence
ON provenance_events(task_id, sequence);

CREATE INDEX IF NOT EXISTS ix_grants_task_expiry
ON grant_records(task_id, expires_at);

-- Application invariant: provenance events are append-only in normal operation.
CREATE TRIGGER IF NOT EXISTS provenance_events_no_update
BEFORE UPDATE ON provenance_events
BEGIN
    SELECT RAISE(ABORT, 'provenance_events are append-only');
END;

CREATE TRIGGER IF NOT EXISTS provenance_events_no_delete
BEFORE DELETE ON provenance_events
BEGIN
    SELECT RAISE(ABORT, 'provenance_events are append-only');
END;

INSERT OR IGNORE INTO schema_migrations(migration_id, checksum, applied_at)
VALUES ('0001_v0_1_control_plane', 'UNGENERATED-DRAFT-CHECKSUM', '2026-09-15T00:00:00Z');

COMMIT;

-- NOTE: tasks.active_program_revision is deliberately not declared as a circular
-- composite foreign key in this first draft. The Task Manager transaction must
-- prove it references an `active` semantic_program_revisions row for the same task.
-- A later migration may enforce this with a separate active-program relation if
-- implementation testing shows the invariant is cleaner at the SQL layer.
