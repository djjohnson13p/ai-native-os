-- Additive Issue #2 semantic snapshot store over the existing Task Manager DB.
-- Existing registry_snapshots rows remain untouched; admission is explicit.
CREATE TABLE IF NOT EXISTS semantic_type_contracts (
    content_hash TEXT PRIMARY KEY,
    semantic_id TEXT NOT NULL,
    full_version TEXT NOT NULL,
    contract_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS semantic_capability_contracts (
    content_hash TEXT PRIMARY KEY,
    semantic_id TEXT NOT NULL,
    full_version TEXT NOT NULL,
    contract_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS registry_snapshot_admissions (
    snapshot_id TEXT PRIMARY KEY REFERENCES registry_snapshots(snapshot_id),
    state TEXT NOT NULL CHECK (state IN ('ADMITTED','DEPRECATED','QUARANTINED','REVOKED'))
);

CREATE TABLE IF NOT EXISTS registry_snapshot_entries (
    snapshot_id TEXT NOT NULL REFERENCES registry_snapshot_admissions(snapshot_id),
    contract_class TEXT NOT NULL CHECK (contract_class IN ('type','capability')),
    semantic_id TEXT NOT NULL,
    major INTEGER NOT NULL CHECK (major >= 0),
    full_version TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    PRIMARY KEY (snapshot_id,contract_class,semantic_id,major)
);

CREATE TABLE IF NOT EXISTS registry_activations (
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('device','user','organization')),
    scope_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL REFERENCES registry_snapshot_admissions(snapshot_id),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    PRIMARY KEY (scope_kind,scope_id)
);

CREATE TRIGGER IF NOT EXISTS immutable_admitted_registry_snapshots_update
BEFORE UPDATE ON registry_snapshots
WHEN EXISTS (SELECT 1 FROM registry_snapshot_admissions WHERE snapshot_id=OLD.snapshot_id)
BEGIN SELECT RAISE(ABORT, 'admitted registry snapshot is immutable'); END;

CREATE TRIGGER IF NOT EXISTS immutable_admitted_registry_snapshots_delete
BEFORE DELETE ON registry_snapshots
WHEN EXISTS (SELECT 1 FROM registry_snapshot_admissions WHERE snapshot_id=OLD.snapshot_id)
BEGIN SELECT RAISE(ABORT, 'admitted registry snapshot is immutable'); END;

CREATE TRIGGER IF NOT EXISTS immutable_semantic_type_contracts_update
BEFORE UPDATE ON semantic_type_contracts
BEGIN SELECT RAISE(ABORT, 'semantic type contract is immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_semantic_type_contracts_delete
BEFORE DELETE ON semantic_type_contracts
BEGIN SELECT RAISE(ABORT, 'semantic type contract is immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_semantic_capability_contracts_update
BEFORE UPDATE ON semantic_capability_contracts
BEGIN SELECT RAISE(ABORT, 'semantic capability contract is immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_semantic_capability_contracts_delete
BEFORE DELETE ON semantic_capability_contracts
BEGIN SELECT RAISE(ABORT, 'semantic capability contract is immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_registry_snapshot_entries_update
BEFORE UPDATE ON registry_snapshot_entries
BEGIN SELECT RAISE(ABORT, 'registry snapshot entry is immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_registry_snapshot_entries_delete
BEFORE DELETE ON registry_snapshot_entries
BEGIN SELECT RAISE(ABORT, 'registry snapshot entry is immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_registry_snapshot_admissions_delete
BEFORE DELETE ON registry_snapshot_admissions
BEGIN SELECT RAISE(ABORT, 'registry admission cannot be deleted'); END;

-- Admission can become more restrictive, but containment cannot be undone by
-- direct SQL. Same-state writes are harmless; snapshot identity is immutable.
CREATE TRIGGER IF NOT EXISTS one_way_registry_snapshot_admissions_update
BEFORE UPDATE ON registry_snapshot_admissions
WHEN NEW.snapshot_id IS NOT OLD.snapshot_id OR NOT (
    NEW.state = OLD.state
    OR OLD.state = 'ADMITTED'
    OR (OLD.state = 'DEPRECATED' AND NEW.state IN ('QUARANTINED','REVOKED'))
    OR (OLD.state = 'QUARANTINED' AND NEW.state = 'REVOKED')
)
BEGIN SELECT RAISE(ABORT, 'registry admission restriction cannot be reversed'); END;

-- REPLACE is a DELETE+INSERT in SQLite, and DELETE triggers need not fire for
-- that conflict action. Do not permit a second INSERT for an admitted identity.
CREATE TRIGGER IF NOT EXISTS immutable_registry_snapshot_admissions_reinsert
BEFORE INSERT ON registry_snapshot_admissions
WHEN EXISTS (
    SELECT 1 FROM registry_snapshot_admissions WHERE snapshot_id IS NEW.snapshot_id
)
BEGIN SELECT RAISE(ABORT, 'registry admission cannot be replaced'); END;

-- SQLite REPLACE need not fire DELETE triggers. Protect every immutable row
-- against a duplicate identity INSERT before conflict handling can replace it.
CREATE TRIGGER IF NOT EXISTS immutable_admitted_registry_snapshots_reinsert
BEFORE INSERT ON registry_snapshots
WHEN EXISTS (
    SELECT 1 FROM registry_snapshots s
    JOIN registry_snapshot_admissions a USING(snapshot_id)
    WHERE s.snapshot_id IS NEW.snapshot_id
)
BEGIN SELECT RAISE(ABORT, 'admitted registry snapshot cannot be replaced'); END;

-- An unadmitted row also cannot use UPDATE OR REPLACE to take an admitted ID.
CREATE TRIGGER IF NOT EXISTS immutable_admitted_registry_snapshots_target_update
BEFORE UPDATE ON registry_snapshots
WHEN NEW.snapshot_id IS NOT OLD.snapshot_id AND EXISTS (
    SELECT 1 FROM registry_snapshot_admissions WHERE snapshot_id IS NEW.snapshot_id
)
BEGIN SELECT RAISE(ABORT, 'admitted registry snapshot cannot be replaced'); END;

CREATE TRIGGER IF NOT EXISTS immutable_semantic_type_contracts_reinsert
BEFORE INSERT ON semantic_type_contracts
WHEN EXISTS (
    SELECT 1 FROM semantic_type_contracts WHERE content_hash IS NEW.content_hash
)
BEGIN SELECT RAISE(ABORT, 'semantic type contract cannot be replaced'); END;

CREATE TRIGGER IF NOT EXISTS immutable_semantic_capability_contracts_reinsert
BEFORE INSERT ON semantic_capability_contracts
WHEN EXISTS (
    SELECT 1 FROM semantic_capability_contracts WHERE content_hash IS NEW.content_hash
)
BEGIN SELECT RAISE(ABORT, 'semantic capability contract cannot be replaced'); END;

CREATE TRIGGER IF NOT EXISTS immutable_registry_snapshot_entries_reinsert
BEFORE INSERT ON registry_snapshot_entries
WHEN EXISTS (
    SELECT 1 FROM registry_snapshot_entries WHERE
        snapshot_id IS NEW.snapshot_id
        AND contract_class IS NEW.contract_class
        AND semantic_id IS NEW.semantic_id
        AND major IS NEW.major
)
BEGIN SELECT RAISE(ABORT, 'registry snapshot entry cannot be replaced'); END;

-- The entry set is complete when admission is published. New entries for an
-- admitted snapshot would change its meaning and can never be appended later.
CREATE TRIGGER IF NOT EXISTS immutable_admitted_registry_snapshot_entries_insert
BEFORE INSERT ON registry_snapshot_entries
WHEN EXISTS (
    SELECT 1 FROM registry_snapshot_admissions WHERE snapshot_id IS NEW.snapshot_id
)
BEGIN SELECT RAISE(ABORT, 'admitted registry snapshot entry set is immutable'); END;

-- A default's revision is an optimistic concurrency token. A direct writer
-- cannot reset it through UPDATE or REPLACE and revive a stale CAS token.
CREATE TRIGGER IF NOT EXISTS registry_activation_no_duplicate_insert
BEFORE INSERT ON registry_activations
WHEN EXISTS (
    SELECT 1 FROM registry_activations
    WHERE scope_kind IS NEW.scope_kind AND scope_id IS NEW.scope_id
)
BEGIN SELECT RAISE(ABORT, 'registry activation cannot be replaced'); END;

CREATE TRIGGER IF NOT EXISTS registry_activation_revision_monotonic
BEFORE UPDATE ON registry_activations
WHEN NEW.scope_kind IS NOT OLD.scope_kind
    OR NEW.scope_id IS NOT OLD.scope_id
    OR NEW.revision <= OLD.revision
BEGIN SELECT RAISE(ABORT, 'registry activation revision must advance'); END;

CREATE TRIGGER IF NOT EXISTS registry_activation_no_delete
BEFORE DELETE ON registry_activations
BEGIN SELECT RAISE(ABORT, 'registry activation cannot be deleted'); END;
