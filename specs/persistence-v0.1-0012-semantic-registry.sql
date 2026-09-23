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
