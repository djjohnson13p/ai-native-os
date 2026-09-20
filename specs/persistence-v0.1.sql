-- AI-Native OS v0.1 trusted control-plane persistence draft
--
-- Architecture references:
--   docs/35-v0.1-persistence-model.md
--   docs/73-v0.1-provenance-journal-and-hash-chain.md
--   docs/74-v0.1-task-manager-transition-and-cas-contract.md
--   docs/75-v0.1-artifact-store-content-identity-and-publication.md
--   docs/76-v0.1-semantic-registry-and-provider-registration-lifecycle.md
--   docs/77-v0.1-authority-coordinator-policy-approval-and-grant-lifecycle.md
--   docs/78-v0.1-execution-binding-and-provider-supervisor.md
--   docs/79-v0.1-credential-broker-and-secret-mediation.md
--   docs/80-v0.1-crash-consistency-recovery-and-commit-protocol.md
--
-- Pre-v1: breaking changes are expected.
-- Large artifact bytes, model weights, raw credentials/secrets, and opaque bearer
-- token material DO NOT belong in this database.

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

-- ---------------------------------------------------------------------------
-- Task / plan / semantic-program state
-- ---------------------------------------------------------------------------

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
    intent_commitment_nonce BLOB NOT NULL DEFAULT (randomblob(32)),
    active_plan_revision    INTEGER,
    active_program_revision INTEGER,
    active_step_ids_json     TEXT NOT NULL DEFAULT '[]',
    waiting_on_json          TEXT NOT NULL DEFAULT '[]',
    constraints_json        TEXT,
    failure_json            TEXT,
    recovery_json           TEXT,
    created_at              TEXT NOT NULL,
    updated_at              TEXT NOT NULL,
    completed_at            TEXT,
    CHECK (length(task_id) > 0),
    CHECK (length(original_intent) > 0)
);

CREATE TABLE IF NOT EXISTS task_transitions (
    transition_id           TEXT PRIMARY KEY,
    task_id                 TEXT NOT NULL,
    expected_revision       INTEGER NOT NULL CHECK (expected_revision >= 1),
    expected_state          TEXT NOT NULL,
    to_state                TEXT NOT NULL,
    result_revision         INTEGER,
    result_state            TEXT,
    outcome                 TEXT NOT NULL CHECK (outcome IN ('PENDING', 'COMMITTED', 'REJECTED')),
    reason_code             TEXT NOT NULL,
    request_json            TEXT NOT NULL,
    result_json             TEXT,
    provenance_event_id     TEXT,
    requested_at            TEXT NOT NULL,
    committed_at            TEXT
);

CREATE TABLE IF NOT EXISTS task_manager_lease (
    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    owner_id     TEXT NOT NULL,
    fence_epoch  INTEGER NOT NULL CHECK (fence_epoch >= 1),
    acquired_at  TEXT NOT NULL
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

-- ---------------------------------------------------------------------------
-- Semantic/provider implementation registry
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS provider_registrations (
    registration_id        TEXT PRIMARY KEY,
    provider_id            TEXT NOT NULL,
    provider_version       TEXT NOT NULL,
    manifest_hash          TEXT,
    package_content_hash   TEXT NOT NULL,
    registry_snapshot_id   TEXT,
    state                  TEXT NOT NULL CHECK (state IN (
        'registered', 'disabled', 'revoked', 'superseded', 'invalid'
    )),
    trust_status           TEXT NOT NULL,
    registration_json      TEXT NOT NULL,
    registered_at          TEXT NOT NULL,
    updated_at             TEXT,
    FOREIGN KEY (registry_snapshot_id) REFERENCES registry_snapshots(snapshot_id),
    UNIQUE (provider_id, provider_version, package_content_hash)
);

CREATE TABLE IF NOT EXISTS provider_conformance_evidence (
    evidence_id            TEXT PRIMARY KEY,
    registration_id        TEXT NOT NULL,
    capability             TEXT NOT NULL,
    contract_hash          TEXT,
    suite_id               TEXT,
    suite_hash             TEXT,
    status                 TEXT NOT NULL,
    evidence_json          TEXT NOT NULL,
    tested_at              TEXT,
    FOREIGN KEY (registration_id) REFERENCES provider_registrations(registration_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- Artifact content identity / output publication
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS artifact_store_binding (
    singleton_id           INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    database_identity      TEXT NOT NULL,
    canonical_root         TEXT NOT NULL,
    root_identity          TEXT NOT NULL,
    bound_at               TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifact_blobs (
    content_hash           TEXT PRIMARY KEY,
    size_bytes             INTEGER NOT NULL CHECK (size_bytes >= 0),
    storage_ref            TEXT NOT NULL,
    durability_state       TEXT NOT NULL CHECK (durability_state IN (
        'STAGED', 'DURABLE', 'MISSING', 'CORRUPT', 'ORPHANED'
    )),
    created_at             TEXT NOT NULL,
    verified_at            TEXT
);

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id             TEXT PRIMARY KEY,
    uri                     TEXT NOT NULL UNIQUE,
    semantic_type           TEXT,
    media_type              TEXT NOT NULL,
    format                  TEXT,
    size_bytes              INTEGER CHECK (size_bytes IS NULL OR size_bytes >= 0),
    content_hash            TEXT,
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
    integrity_state         TEXT NOT NULL DEFAULT 'unknown' CHECK (integrity_state IN (
        'unknown', 'pending', 'verified', 'failed'
    )),
    integrity_verified_at   TEXT,
    integrity_verifier      TEXT,
    labels_json             TEXT,
    created_at              TEXT NOT NULL,
    FOREIGN KEY (origin_task_id) REFERENCES tasks(task_id),
    FOREIGN KEY (content_hash) REFERENCES artifact_blobs(content_hash)
);

CREATE TABLE IF NOT EXISTS artifact_output_allocations (
    allocation_id           TEXT PRIMARY KEY,
    task_id                 TEXT NOT NULL,
    semantic_program_hash   TEXT NOT NULL,
    node_id                 TEXT NOT NULL,
    binding_id              TEXT,
    attempt_id              TEXT,
    output_port             TEXT,
    expected_semantic_type  TEXT,
    allowed_media_types_json TEXT,
    max_size_bytes          INTEGER CHECK (max_size_bytes IS NULL OR max_size_bytes >= 0),
    sensitivity             TEXT NOT NULL,
    retention               TEXT NOT NULL,
    state                   TEXT NOT NULL CHECK (state IN (
        'ALLOCATED', 'WRITING', 'FINALIZING', 'PUBLISHED', 'ABORTED', 'EXPIRED', 'FAILED'
    )),
    writer_grant_id         TEXT,
    writer_grant_one_shot_consumed INTEGER CHECK (
        writer_grant_one_shot_consumed IS NULL OR writer_grant_one_shot_consumed IN (0, 1)
    ),
    publication_id          TEXT,
    published_artifact_id   TEXT,
    staging_ref             TEXT,
    created_at              TEXT NOT NULL,
    expires_at              TEXT NOT NULL,
    updated_at              TEXT,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE,
    FOREIGN KEY (published_artifact_id) REFERENCES artifacts(artifact_id)
);

CREATE TABLE IF NOT EXISTS artifact_publications (
    publication_id          TEXT PRIMARY KEY,
    allocation_id           TEXT NOT NULL,
    task_id                 TEXT NOT NULL,
    artifact_id             TEXT,
    content_hash            TEXT,
    request_json            TEXT NOT NULL,
    result_json             TEXT,
    state                   TEXT NOT NULL CHECK (state IN (
        'PENDING', 'COMMITTED', 'FAILED', 'ABORTED'
    )),
    requested_at            TEXT NOT NULL,
    committed_at            TEXT,
    FOREIGN KEY (allocation_id) REFERENCES artifact_output_allocations(allocation_id),
    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE,
    FOREIGN KEY (artifact_id) REFERENCES artifacts(artifact_id),
    FOREIGN KEY (content_hash) REFERENCES artifact_blobs(content_hash)
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

-- ---------------------------------------------------------------------------
-- Policy / approval / grants
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS policy_snapshots (
    snapshot_id              TEXT PRIMARY KEY,
    scope_kind               TEXT NOT NULL,
    scope_id                 TEXT NOT NULL,
    policy_language          TEXT NOT NULL,
    policy_language_version  TEXT,
    policy_set_hash          TEXT NOT NULL,
    entity_schema_hash       TEXT,
    configuration_hash       TEXT,
    engine_id                TEXT NOT NULL,
    engine_version           TEXT NOT NULL,
    snapshot_json            TEXT NOT NULL,
    created_at               TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS authority_requests (
    request_id               TEXT PRIMARY KEY,
    task_id                  TEXT NOT NULL,
    semantic_program_hash    TEXT NOT NULL,
    registry_snapshot_id     TEXT NOT NULL,
    node_id                  TEXT NOT NULL,
    capability               TEXT NOT NULL,
    principal_kind           TEXT NOT NULL,
    principal_id             TEXT NOT NULL,
    execution_binding_id     TEXT,
    attempt_id               TEXT,
    action                   TEXT NOT NULL,
    resolved_resource_kind   TEXT NOT NULL,
    resolved_resource_id     TEXT NOT NULL,
    semantic_selector        TEXT,
    request_json             TEXT NOT NULL,
    requested_at             TEXT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE,
    FOREIGN KEY (registry_snapshot_id) REFERENCES registry_snapshots(snapshot_id)
);

CREATE TABLE IF NOT EXISTS policy_decisions (
    decision_id              TEXT PRIMARY KEY,
    authority_request_id     TEXT NOT NULL,
    task_id                  TEXT NOT NULL,
    semantic_program_hash    TEXT NOT NULL,
    node_id                  TEXT NOT NULL,
    principal_kind           TEXT NOT NULL,
    principal_id             TEXT NOT NULL,
    action                   TEXT NOT NULL,
    resolved_resource_kind   TEXT NOT NULL,
    resolved_resource_id     TEXT NOT NULL,
    decision                 TEXT NOT NULL CHECK (decision IN (
        'ALLOW', 'DENY', 'REQUIRE_APPROVAL'
    )),
    policy_snapshot_id       TEXT NOT NULL,
    approval_request_id      TEXT,
    reason_codes_json        TEXT NOT NULL,
    decision_json            TEXT NOT NULL,
    decided_at               TEXT NOT NULL,
    FOREIGN KEY (authority_request_id) REFERENCES authority_requests(request_id),
    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE,
    FOREIGN KEY (policy_snapshot_id) REFERENCES policy_snapshots(snapshot_id)
);

CREATE TABLE IF NOT EXISTS approval_requests (
    approval_id              TEXT PRIMARY KEY,
    authority_request_id     TEXT NOT NULL,
    task_id                  TEXT NOT NULL,
    semantic_program_hash    TEXT NOT NULL,
    node_id                  TEXT NOT NULL,
    action                   TEXT NOT NULL,
    status                   TEXT NOT NULL CHECK (status IN (
        'PENDING', 'APPROVED', 'DENIED', 'EXPIRED', 'CANCELLED', 'STALE'
    )),
    request_json             TEXT NOT NULL,
    created_at               TEXT NOT NULL,
    expires_at               TEXT,
    FOREIGN KEY (authority_request_id) REFERENCES authority_requests(request_id),
    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS approval_decisions (
    decision_id              TEXT PRIMARY KEY,
    approval_id              TEXT NOT NULL,
    task_id                  TEXT NOT NULL,
    decision                 TEXT NOT NULL CHECK (decision IN ('APPROVE', 'DENY')),
    decided_by_kind          TEXT NOT NULL,
    decided_by_id            TEXT NOT NULL,
    scope                    TEXT NOT NULL,
    approved_until           TEXT,
    decision_json            TEXT NOT NULL,
    decided_at               TEXT NOT NULL,
    FOREIGN KEY (approval_id) REFERENCES approval_requests(approval_id),
    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS authority_grants (
    grant_id                 TEXT PRIMARY KEY,
    token_id                 TEXT UNIQUE,
    task_id                  TEXT NOT NULL,
    semantic_program_hash    TEXT NOT NULL,
    node_id                  TEXT NOT NULL,
    capability               TEXT NOT NULL,
    principal_kind           TEXT NOT NULL,
    principal_id             TEXT NOT NULL,
    execution_binding_id     TEXT,
    attempt_id               TEXT,
    policy_decision_id       TEXT NOT NULL,
    policy_snapshot_id       TEXT NOT NULL,
    approval_id              TEXT,
    grants_json              TEXT NOT NULL,
    scope                    TEXT NOT NULL,
    max_uses                 INTEGER CHECK (max_uses IS NULL OR max_uses >= 1),
    uses_consumed            INTEGER NOT NULL DEFAULT 0 CHECK (uses_consumed >= 0),
    state                    TEXT NOT NULL CHECK (state IN (
        'ACTIVE', 'CONSUMED', 'EXPIRED', 'REVOKED'
    )),
    delegable                INTEGER NOT NULL DEFAULT 0 CHECK (delegable IN (0, 1)),
    max_delegation_depth     INTEGER NOT NULL DEFAULT 0 CHECK (max_delegation_depth >= 0),
    issued_at                TEXT NOT NULL,
    expires_at               TEXT NOT NULL,
    revoked_at               TEXT,
    revocation_reason_code   TEXT,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE,
    FOREIGN KEY (policy_decision_id) REFERENCES policy_decisions(decision_id),
    FOREIGN KEY (policy_snapshot_id) REFERENCES policy_snapshots(snapshot_id),
    FOREIGN KEY (approval_id) REFERENCES approval_requests(approval_id),
    CHECK (max_uses IS NULL OR uses_consumed <= max_uses)
);

-- No table stores opaque bearer-token bytes. token_id is a persisted handle/identity only.

-- ---------------------------------------------------------------------------
-- Credential broker metadata / use records (no raw secret material)
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS credential_handles (
    credential_id            TEXT PRIMARY KEY,
    owner_principal_kind     TEXT NOT NULL,
    owner_principal_id       TEXT NOT NULL,
    credential_class         TEXT NOT NULL,
    issuer_or_service_id     TEXT,
    exportability            TEXT NOT NULL,
    status                   TEXT NOT NULL CHECK (status IN (
        'ACTIVE', 'EXPIRED', 'REVOKED', 'ROTATING', 'UNAVAILABLE'
    )),
    metadata_json            TEXT NOT NULL,
    secure_store_ref         TEXT NOT NULL,
    created_at               TEXT NOT NULL,
    expires_at               TEXT,
    rotated_at               TEXT,
    revoked_at               TEXT
);

CREATE TABLE IF NOT EXISTS credential_use_records (
    request_id               TEXT PRIMARY KEY,
    result_id                TEXT UNIQUE,
    task_id                  TEXT NOT NULL,
    credential_id            TEXT NOT NULL,
    execution_binding_id     TEXT NOT NULL,
    authority_grant_id       TEXT NOT NULL,
    principal_kind           TEXT NOT NULL,
    principal_id             TEXT NOT NULL,
    use_mode                 TEXT NOT NULL,
    status                   TEXT,
    request_json             TEXT NOT NULL,
    result_json              TEXT,
    requested_at             TEXT NOT NULL,
    completed_at             TEXT,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE,
    FOREIGN KEY (credential_id) REFERENCES credential_handles(credential_id),
    FOREIGN KEY (authority_grant_id) REFERENCES authority_grants(grant_id)
);

-- ---------------------------------------------------------------------------
-- Execution bindings / provider attempts / operations
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS execution_bindings (
    binding_id               TEXT PRIMARY KEY,
    attempt_id               TEXT NOT NULL UNIQUE,
    task_id                  TEXT NOT NULL,
    semantic_program_hash    TEXT NOT NULL,
    registry_snapshot_id     TEXT NOT NULL,
    ir_version               TEXT NOT NULL,
    node_id                  TEXT NOT NULL,
    capability               TEXT NOT NULL,
    capability_contract_hash TEXT,
    provider_registration_id TEXT,
    provider_id              TEXT NOT NULL,
    provider_version         TEXT NOT NULL,
    provider_manifest_hash   TEXT,
    provider_build_hash      TEXT,
    attempt                  INTEGER NOT NULL CHECK (attempt >= 1),
    policy_decision_refs_json TEXT NOT NULL,
    grant_refs_json          TEXT NOT NULL,
    execution_profile_ref    TEXT NOT NULL,
    placement_json           TEXT NOT NULL,
    binding_json             TEXT NOT NULL,
    created_at               TEXT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE,
    FOREIGN KEY (registry_snapshot_id) REFERENCES registry_snapshots(snapshot_id),
    FOREIGN KEY (provider_registration_id) REFERENCES provider_registrations(registration_id),
    UNIQUE (task_id, semantic_program_hash, node_id, attempt)
);

CREATE TABLE IF NOT EXISTS step_executions (
    attempt_id               TEXT PRIMARY KEY,
    task_id                  TEXT NOT NULL,
    semantic_program_hash    TEXT NOT NULL,
    registry_snapshot_id     TEXT,
    node_id                  TEXT NOT NULL,
    binding_id               TEXT,
    provider_id              TEXT,
    provider_version         TEXT,
    invocation_id            TEXT,
    attempt_number           INTEGER NOT NULL CHECK (attempt_number BETWEEN 1 AND 100),
    revision                 INTEGER NOT NULL CHECK (revision >= 1),
    state                    TEXT NOT NULL CHECK (state IN (
        'PENDING', 'BLOCKED', 'READY', 'STARTING', 'RUNNING',
        'SUCCEEDED', 'FAILED', 'CANCELLED', 'SKIPPED', 'UNKNOWN'
    )),
    operation_id             TEXT,
    idempotency_key          TEXT,
    outcome_certainty        TEXT CHECK (outcome_certainty IS NULL OR outcome_certainty IN (
        'NOT_STARTED', 'STARTED_NO_EFFECT', 'COMPLETED',
        'FAILED_NO_EFFECT', 'FAILED_PARTIAL_EFFECT', 'OUTCOME_UNKNOWN'
    )),
    failure_json             TEXT,
    input_artifacts_json     TEXT,
    output_artifacts_json    TEXT,
    started_at               TEXT,
    finished_at              TEXT,
    created_at               TEXT NOT NULL,
    updated_at               TEXT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE,
    FOREIGN KEY (binding_id) REFERENCES execution_bindings(binding_id),
    FOREIGN KEY (registry_snapshot_id) REFERENCES registry_snapshots(snapshot_id)
);

CREATE TABLE IF NOT EXISTS provider_invocations (
    invocation_id            TEXT PRIMARY KEY,
    attempt_id               TEXT NOT NULL,
    binding_id               TEXT NOT NULL,
    task_id                  TEXT NOT NULL,
    provider_id              TEXT NOT NULL,
    provider_version         TEXT NOT NULL,
    status                   TEXT NOT NULL CHECK (status IN (
        'PENDING', 'STARTING', 'RUNNING', 'SUCCEEDED', 'SEMANTIC_FAILURE',
        'PROVIDER_FAILURE', 'START_FAILED', 'TIMED_OUT', 'CANCELLED',
        'OUTPUT_FINALIZATION_FAILED', 'AUTHORITY_REVOKED', 'OUTCOME_UNKNOWN'
    )),
    request_json             TEXT NOT NULL,
    result_json              TEXT,
    started_at               TEXT,
    completed_at             TEXT,
    FOREIGN KEY (attempt_id) REFERENCES step_executions(attempt_id),
    FOREIGN KEY (binding_id) REFERENCES execution_bindings(binding_id),
    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS operations (
    operation_id             TEXT PRIMARY KEY,
    task_id                  TEXT NOT NULL,
    semantic_program_hash    TEXT NOT NULL,
    node_id                  TEXT NOT NULL,
    binding_id               TEXT,
    attempt_id               TEXT,
    transaction_class        TEXT,
    effect_class             TEXT NOT NULL,
    idempotency_key          TEXT,
    state                    TEXT NOT NULL CHECK (state IN (
        'PREPARED', 'STARTED', 'SUCCEEDED', 'FAILED', 'UNKNOWN', 'CANCELLED'
    )),
    outcome_certainty        TEXT CHECK (outcome_certainty IS NULL OR outcome_certainty IN (
        'NOT_STARTED', 'STARTED_NO_EFFECT', 'COMPLETED',
        'FAILED_NO_EFFECT', 'FAILED_PARTIAL_EFFECT', 'OUTCOME_UNKNOWN'
    )),
    external_receipt         TEXT,
    details_json             TEXT,
    prepared_at              TEXT NOT NULL,
    started_at               TEXT,
    finished_at              TEXT,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE,
    FOREIGN KEY (binding_id) REFERENCES execution_bindings(binding_id),
    FOREIGN KEY (attempt_id) REFERENCES step_executions(attempt_id)
);

-- ---------------------------------------------------------------------------
-- Provenance journal
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS provenance_events (
    event_id                 TEXT PRIMARY KEY,
    task_id                  TEXT NOT NULL,
    stream_id                TEXT NOT NULL,
    sequence                 INTEGER NOT NULL CHECK (sequence >= 1),
    timestamp                TEXT NOT NULL,
    event_type               TEXT NOT NULL,
    semantic_program_hash    TEXT,
    ir_version               TEXT,
    registry_snapshot_id     TEXT,
    node_id                  TEXT,
    execution_binding_id     TEXT,
    provider_id              TEXT,
    status                   TEXT,
    previous_event_hash      TEXT,
    event_hash               TEXT NOT NULL,
    event_json               TEXT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE,
    FOREIGN KEY (registry_snapshot_id) REFERENCES registry_snapshots(snapshot_id),
    FOREIGN KEY (execution_binding_id) REFERENCES execution_bindings(binding_id),
    UNIQUE (task_id, sequence),
    UNIQUE (stream_id, sequence)
);

CREATE TABLE IF NOT EXISTS provenance_checkpoints (
    checkpoint_id            TEXT PRIMARY KEY,
    task_id                  TEXT NOT NULL,
    stream_id                TEXT NOT NULL,
    through_sequence         INTEGER NOT NULL CHECK (through_sequence >= 1),
    event_hash               TEXT NOT NULL,
    checkpoint_json          TEXT NOT NULL,
    created_at               TEXT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- Recovery assessments
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS recovery_epochs (
    recovery_epoch_id        TEXT PRIMARY KEY,
    daemon_instance_id       TEXT,
    started_at               TEXT NOT NULL,
    completed_at             TEXT
);

CREATE TABLE IF NOT EXISTS recovery_assessments (
    assessment_id            TEXT PRIMARY KEY,
    recovery_epoch_id        TEXT NOT NULL,
    task_id                  TEXT NOT NULL,
    basis_revision           INTEGER NOT NULL CHECK (basis_revision >= 1),
    subject_kind             TEXT NOT NULL,
    subject_id               TEXT NOT NULL,
    certainty                TEXT NOT NULL CHECK (certainty IN (
        'NOT_STARTED', 'STARTED_NO_EFFECT', 'COMPLETED',
        'FAILED_NO_EFFECT', 'FAILED_PARTIAL_EFFECT', 'OUTCOME_UNKNOWN'
    )),
    safe_action              TEXT NOT NULL,
    reason_codes_json        TEXT NOT NULL,
    assessment_json          TEXT NOT NULL,
    created_at               TEXT NOT NULL,
    FOREIGN KEY (recovery_epoch_id) REFERENCES recovery_epochs(recovery_epoch_id),
    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS recovery_unknown_operations (
    assessment_id            TEXT NOT NULL,
    ordinal                  INTEGER NOT NULL CHECK (ordinal >= 0),
    operation_id             TEXT NOT NULL,
    PRIMARY KEY (assessment_id, ordinal),
    UNIQUE (assessment_id, operation_id),
    FOREIGN KEY (assessment_id) REFERENCES recovery_assessments(assessment_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- Skills / adaptive reuse metadata
-- ---------------------------------------------------------------------------

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

-- ---------------------------------------------------------------------------
-- Indexes
-- ---------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS ix_tasks_state
ON tasks(state);

CREATE INDEX IF NOT EXISTS ix_task_transitions_task
ON task_transitions(task_id, requested_at);

CREATE INDEX IF NOT EXISTS ix_plan_revisions_task
ON plan_revisions(task_id, plan_revision DESC);

CREATE INDEX IF NOT EXISTS ix_semantic_programs_task
ON semantic_program_revisions(task_id, program_revision DESC);

CREATE INDEX IF NOT EXISTS ix_semantic_programs_hash
ON semantic_program_revisions(semantic_hash);

CREATE INDEX IF NOT EXISTS ix_provider_registrations_provider
ON provider_registrations(provider_id, provider_version, state);

CREATE INDEX IF NOT EXISTS ix_artifacts_origin_task
ON artifacts(origin_task_id);

CREATE INDEX IF NOT EXISTS ix_artifacts_content_hash
ON artifacts(content_hash);

CREATE INDEX IF NOT EXISTS ix_allocations_task_state
ON artifact_output_allocations(task_id, state);

CREATE INDEX IF NOT EXISTS ix_publications_task_state
ON artifact_publications(task_id, state);

CREATE INDEX IF NOT EXISTS ix_task_artifacts_task_role
ON task_artifacts(task_id, role);

CREATE INDEX IF NOT EXISTS ix_authority_requests_task_node
ON authority_requests(task_id, semantic_program_hash, node_id);

CREATE INDEX IF NOT EXISTS ix_policy_decisions_request
ON policy_decisions(authority_request_id, decided_at);

CREATE INDEX IF NOT EXISTS ix_approvals_task_status
ON approval_requests(task_id, status);

CREATE INDEX IF NOT EXISTS ix_grants_task_state_expiry
ON authority_grants(task_id, state, expires_at);

CREATE INDEX IF NOT EXISTS ix_credentials_owner_state
ON credential_handles(owner_principal_kind, owner_principal_id, status);

CREATE INDEX IF NOT EXISTS ix_credential_uses_task
ON credential_use_records(task_id, requested_at);

CREATE INDEX IF NOT EXISTS ix_execution_bindings_task_node
ON execution_bindings(task_id, semantic_program_hash, node_id, attempt);

CREATE INDEX IF NOT EXISTS ix_step_executions_task_state
ON step_executions(task_id, state);

CREATE UNIQUE INDEX IF NOT EXISTS ux_step_executions_attempt_tuple
ON step_executions(
    task_id,
    semantic_program_hash,
    node_id,
    attempt_number
);

CREATE INDEX IF NOT EXISTS ix_provider_invocations_task_status
ON provider_invocations(task_id, status);

CREATE INDEX IF NOT EXISTS ix_operations_task_state
ON operations(task_id, state);

CREATE INDEX IF NOT EXISTS ix_provenance_task_sequence
ON provenance_events(task_id, sequence);

CREATE INDEX IF NOT EXISTS ix_recovery_task
ON recovery_assessments(task_id, created_at);

-- ---------------------------------------------------------------------------
-- Immutability / append-only guards
-- ---------------------------------------------------------------------------

CREATE TRIGGER IF NOT EXISTS execution_bindings_no_update
BEFORE UPDATE ON execution_bindings
BEGIN
    SELECT RAISE(ABORT, 'execution_bindings are immutable; create a new attempt/binding');
END;

CREATE TRIGGER IF NOT EXISTS execution_bindings_no_delete
BEFORE DELETE ON execution_bindings
BEGIN
    SELECT RAISE(ABORT, 'execution_bindings are retained for audit/recovery');
END;

CREATE TRIGGER IF NOT EXISTS step_executions_attempt_number_insert_guard
BEFORE INSERT ON step_executions
WHEN NEW.attempt_number NOT BETWEEN 1 AND 100
BEGIN
    SELECT RAISE(ABORT, 'step attempt_number must be between 1 and 100');
END;

CREATE TRIGGER IF NOT EXISTS step_executions_attempt_number_update_guard
BEFORE UPDATE OF attempt_number ON step_executions
WHEN NEW.attempt_number NOT BETWEEN 1 AND 100
BEGIN
    SELECT RAISE(ABORT, 'step attempt_number must be between 1 and 100');
END;

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

CREATE TRIGGER IF NOT EXISTS published_artifacts_no_content_update
BEFORE UPDATE OF content_hash, size_bytes ON artifacts
WHEN OLD.content_hash IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'published artifact content identity is immutable; create a new Artifact');
END;

INSERT OR IGNORE INTO schema_migrations(migration_id, checksum, applied_at)
VALUES ('0001_v0_1_trusted_control_plane', 'UNGENERATED-DRAFT-CHECKSUM', '2026-09-15T00:00:00Z');

COMMIT;

-- NOTES:
-- 1. tasks.active_program_revision is deliberately not a circular composite FK in
--    this draft. Task Manager must prove it references an active program row for
--    the same Task in the transition transaction.
-- 2. Execution Bindings are immutable receipts. Mutable provider-attempt state is
--    stored in step_executions/provider_invocations.
-- 3. No raw credential/bearer token material is persisted. secure_store_ref and
--    token_id are opaque trusted-subsystem references/identities.
-- 4. JSON columns are convenience envelopes during v0.1; trusted code validates
--    them against the corresponding schema before persistence/use.
-- 5. Filesystem/blob durability is coordinated with DB metadata through the
--    publication/recovery protocol; SQLite ACID does not make blob writes atomic.
-- 6. task_transitions intentionally has no tasks foreign key: rejected requests
--    for absent task IDs are retained for global transition-ID idempotency.
--    COMMITTED transition/task identity is enforced by the Task Manager transaction.
