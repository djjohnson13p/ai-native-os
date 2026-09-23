-- Additive Stage-1 semantic repair fence. A guard repair appends a generation;
-- it never changes the historical admission projection. Generation zero is
-- the canonical pre-repair baseline. A current-generation receipt is required
-- after a repair before an admitted snapshot can be used for new work.
CREATE TABLE IF NOT EXISTS semantic_repair_fences (
    generation INTEGER PRIMARY KEY CHECK (generation >= 0),
    reason TEXT NOT NULL CHECK (reason IN ('BOOTSTRAP','GUARD_REPAIR')),
    created_at TEXT NOT NULL CHECK (length(created_at) > 0)
);
CREATE TRIGGER IF NOT EXISTS semantic_repair_fence_no_update
BEFORE UPDATE ON semantic_repair_fences
BEGIN SELECT RAISE(ABORT, 'semantic repair fence is immutable'); END;
CREATE TRIGGER IF NOT EXISTS semantic_repair_fence_no_delete
BEFORE DELETE ON semantic_repair_fences
BEGIN SELECT RAISE(ABORT, 'semantic repair fence is immutable'); END;
CREATE TRIGGER IF NOT EXISTS semantic_repair_fence_no_duplicate_insert
BEFORE INSERT ON semantic_repair_fences
WHEN EXISTS (SELECT 1 FROM semantic_repair_fences WHERE generation=NEW.generation)
BEGIN SELECT RAISE(ABORT, 'semantic repair fence cannot be replaced'); END;
CREATE TRIGGER IF NOT EXISTS semantic_repair_fence_sequence
BEFORE INSERT ON semantic_repair_fences
WHEN (NEW.generation=0 AND (NEW.reason<>'BOOTSTRAP' OR EXISTS (SELECT 1 FROM semantic_repair_fences)))
  OR (NEW.generation>0 AND (NEW.reason<>'GUARD_REPAIR'
       OR NEW.generation IS NOT (SELECT MAX(generation)+1 FROM semantic_repair_fences)))
  OR NEW.generation=9223372036854775807
BEGIN SELECT RAISE(ABORT, 'semantic repair fence generation is not monotonic'); END;
INSERT INTO semantic_repair_fences(generation,reason,created_at)
SELECT 0,'BOOTSTRAP',strftime('%Y-%m-%dT%H:%M:%fZ','now')
WHERE NOT EXISTS (SELECT 1 FROM semantic_repair_fences);

-- Terminal history is independent of the mutable admission projection.
-- The initial copy is safe only when the earlier one-way guard was intact;
-- fenced upgrade marks every old admission unprovable otherwise.
CREATE TABLE IF NOT EXISTS semantic_terminal_admissions (
    snapshot_id TEXT PRIMARY KEY REFERENCES registry_snapshot_admissions(snapshot_id),
    terminal_state TEXT NOT NULL CHECK (terminal_state IN ('QUARANTINED','REVOKED'))
);
CREATE TRIGGER IF NOT EXISTS semantic_terminal_admission_no_update
BEFORE UPDATE ON semantic_terminal_admissions
BEGIN SELECT RAISE(ABORT, 'semantic terminal admission is immutable'); END;
CREATE TRIGGER IF NOT EXISTS semantic_terminal_admission_no_delete
BEFORE DELETE ON semantic_terminal_admissions
BEGIN SELECT RAISE(ABORT, 'semantic terminal admission is immutable'); END;
CREATE TRIGGER IF NOT EXISTS semantic_terminal_admission_no_duplicate_insert
BEFORE INSERT ON semantic_terminal_admissions
WHEN EXISTS (SELECT 1 FROM semantic_terminal_admissions WHERE snapshot_id=NEW.snapshot_id)
BEGIN SELECT RAISE(ABORT, 'semantic terminal admission cannot be replaced'); END;
INSERT INTO semantic_terminal_admissions(snapshot_id,terminal_state)
SELECT a.snapshot_id,a.state FROM registry_snapshot_admissions a
WHERE a.state IN ('QUARANTINED','REVOKED')
  AND NOT EXISTS (SELECT 1 FROM semantic_terminal_admissions t
                  WHERE t.snapshot_id=a.snapshot_id);
CREATE TRIGGER IF NOT EXISTS semantic_terminal_admission_insert
AFTER INSERT ON registry_snapshot_admissions
WHEN NEW.state IN ('QUARANTINED','REVOKED')
BEGIN INSERT INTO semantic_terminal_admissions(snapshot_id,terminal_state)
     VALUES (NEW.snapshot_id,NEW.state); END;
CREATE TRIGGER IF NOT EXISTS semantic_terminal_admission_transition
AFTER UPDATE OF state ON registry_snapshot_admissions
WHEN NEW.state IN ('QUARANTINED','REVOKED')
 AND NOT EXISTS (SELECT 1 FROM semantic_terminal_admissions WHERE snapshot_id=NEW.snapshot_id)
BEGIN INSERT INTO semantic_terminal_admissions(snapshot_id,terminal_state)
     VALUES (NEW.snapshot_id,NEW.state); END;

CREATE TABLE IF NOT EXISTS semantic_legacy_unprovable_admissions (
    snapshot_id TEXT PRIMARY KEY REFERENCES registry_snapshot_admissions(snapshot_id)
);
CREATE TRIGGER IF NOT EXISTS semantic_legacy_unprovable_no_update
BEFORE UPDATE ON semantic_legacy_unprovable_admissions
BEGIN SELECT RAISE(ABORT, 'unprovable semantic history is immutable'); END;
CREATE TRIGGER IF NOT EXISTS semantic_legacy_unprovable_no_delete
BEFORE DELETE ON semantic_legacy_unprovable_admissions
BEGIN SELECT RAISE(ABORT, 'unprovable semantic history is immutable'); END;
CREATE TRIGGER IF NOT EXISTS semantic_legacy_unprovable_no_duplicate_insert
BEFORE INSERT ON semantic_legacy_unprovable_admissions
WHEN EXISTS (SELECT 1 FROM semantic_legacy_unprovable_admissions WHERE snapshot_id=NEW.snapshot_id)
BEGIN SELECT RAISE(ABORT, 'unprovable semantic history cannot be replaced'); END;

-- An activation revision may have been rolled back while an 0012 monotonicity
-- guard was absent. Snapshot re-attestation must not revive a stale CAS scope.
CREATE TABLE IF NOT EXISTS semantic_invalidated_activation_scopes (
    scope_kind TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    PRIMARY KEY (scope_kind,scope_id)
);
CREATE TRIGGER IF NOT EXISTS semantic_invalidated_activation_no_update
BEFORE UPDATE ON semantic_invalidated_activation_scopes
BEGIN SELECT RAISE(ABORT, 'invalidated activation scope is immutable'); END;
CREATE TRIGGER IF NOT EXISTS semantic_invalidated_activation_no_delete
BEFORE DELETE ON semantic_invalidated_activation_scopes
BEGIN SELECT RAISE(ABORT, 'invalidated activation scope is immutable'); END;
CREATE TRIGGER IF NOT EXISTS semantic_invalidated_activation_no_duplicate_insert
BEFORE INSERT ON semantic_invalidated_activation_scopes
WHEN EXISTS (SELECT 1 FROM semantic_invalidated_activation_scopes
             WHERE scope_kind=NEW.scope_kind AND scope_id=NEW.scope_id)
BEGIN SELECT RAISE(ABORT, 'invalidated activation scope cannot be replaced'); END;

-- Preserve every activation identity even if a damaged 0012 guard later
-- permits a key rename, DELETE, or REPLACE. Repair invalidates this ledger,
-- not merely the activation rows that happen to remain at startup.
CREATE TABLE IF NOT EXISTS semantic_activation_scope_history (
    scope_kind TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    PRIMARY KEY (scope_kind,scope_id)
);
CREATE TRIGGER IF NOT EXISTS semantic_activation_scope_history_no_update
BEFORE UPDATE ON semantic_activation_scope_history
BEGIN SELECT RAISE(ABORT, 'activation scope history is immutable'); END;
CREATE TRIGGER IF NOT EXISTS semantic_activation_scope_history_no_delete
BEFORE DELETE ON semantic_activation_scope_history
BEGIN SELECT RAISE(ABORT, 'activation scope history is immutable'); END;
CREATE TRIGGER IF NOT EXISTS semantic_activation_scope_history_no_duplicate_insert
BEFORE INSERT ON semantic_activation_scope_history
WHEN EXISTS (SELECT 1 FROM semantic_activation_scope_history
             WHERE scope_kind=NEW.scope_kind AND scope_id=NEW.scope_id)
BEGIN SELECT RAISE(ABORT, 'activation scope history cannot be replaced'); END;
INSERT INTO semantic_activation_scope_history(scope_kind,scope_id)
SELECT a.scope_kind,a.scope_id FROM registry_activations a
WHERE NOT EXISTS (SELECT 1 FROM semantic_activation_scope_history h
                  WHERE h.scope_kind=a.scope_kind AND h.scope_id=a.scope_id);
CREATE TRIGGER IF NOT EXISTS semantic_activation_scope_history_insert
AFTER INSERT ON registry_activations
WHEN NOT EXISTS (SELECT 1 FROM semantic_activation_scope_history h
                 WHERE h.scope_kind=NEW.scope_kind AND h.scope_id=NEW.scope_id)
BEGIN INSERT INTO semantic_activation_scope_history(scope_kind,scope_id)
     VALUES (NEW.scope_kind,NEW.scope_id); END;
CREATE TRIGGER IF NOT EXISTS semantic_activation_scope_history_key_update
AFTER UPDATE OF scope_kind,scope_id ON registry_activations
WHEN NOT EXISTS (SELECT 1 FROM semantic_activation_scope_history h
                 WHERE h.scope_kind=NEW.scope_kind AND h.scope_id=NEW.scope_id)
BEGIN INSERT INTO semantic_activation_scope_history(scope_kind,scope_id)
     VALUES (NEW.scope_kind,NEW.scope_id); END;

-- A first 0014 bootstrap cannot reconstruct scope identities already lost
-- while pre-0014 activation guards were absent. This singleton bars all
-- activation use until a future explicit migration establishes new authority.
CREATE TABLE IF NOT EXISTS semantic_legacy_activation_quarantine (
    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id=1),
    reason TEXT NOT NULL CHECK (reason='UNPROVABLE_PRE_0014_HISTORY')
);
CREATE TRIGGER IF NOT EXISTS semantic_legacy_activation_quarantine_no_update
BEFORE UPDATE ON semantic_legacy_activation_quarantine
BEGIN SELECT RAISE(ABORT, 'legacy activation quarantine is immutable'); END;
CREATE TRIGGER IF NOT EXISTS semantic_legacy_activation_quarantine_no_delete
BEFORE DELETE ON semantic_legacy_activation_quarantine
BEGIN SELECT RAISE(ABORT, 'legacy activation quarantine is immutable'); END;
CREATE TRIGGER IF NOT EXISTS semantic_legacy_activation_quarantine_no_duplicate_insert
BEFORE INSERT ON semantic_legacy_activation_quarantine
WHEN EXISTS (SELECT 1 FROM semantic_legacy_activation_quarantine WHERE singleton_id=NEW.singleton_id)
BEGIN SELECT RAISE(ABORT, 'legacy activation quarantine cannot be replaced'); END;

CREATE TABLE IF NOT EXISTS semantic_snapshot_reattestations (
    snapshot_id TEXT NOT NULL REFERENCES registry_snapshot_admissions(snapshot_id),
    generation INTEGER NOT NULL REFERENCES semantic_repair_fences(generation),
    decision_id TEXT NOT NULL CHECK (length(decision_id) BETWEEN 1 AND 512),
    decision_source TEXT NOT NULL CHECK (length(decision_source) BETWEEN 1 AND 256),
    verification_profile TEXT NOT NULL CHECK (verification_profile='strict-semantic-v0.1'),
    verified_at TEXT NOT NULL CHECK (length(verified_at) > 0),
    PRIMARY KEY (snapshot_id,generation)
);
CREATE TRIGGER IF NOT EXISTS semantic_snapshot_reattestation_no_update
BEFORE UPDATE ON semantic_snapshot_reattestations
BEGIN SELECT RAISE(ABORT, 'semantic re-attestation is immutable'); END;
CREATE TRIGGER IF NOT EXISTS semantic_snapshot_reattestation_no_delete
BEFORE DELETE ON semantic_snapshot_reattestations
BEGIN SELECT RAISE(ABORT, 'semantic re-attestation is immutable'); END;
CREATE TRIGGER IF NOT EXISTS semantic_snapshot_reattestation_no_duplicate_insert
BEFORE INSERT ON semantic_snapshot_reattestations
WHEN EXISTS (SELECT 1 FROM semantic_snapshot_reattestations
             WHERE snapshot_id=NEW.snapshot_id AND generation=NEW.generation)
BEGIN SELECT RAISE(ABORT, 'semantic re-attestation cannot be replaced'); END;
CREATE TRIGGER IF NOT EXISTS semantic_snapshot_reattestation_current_only
BEFORE INSERT ON semantic_snapshot_reattestations
WHEN NEW.generation IS NOT (SELECT MAX(generation) FROM semantic_repair_fences)
  OR NOT EXISTS (SELECT 1 FROM registry_snapshot_admissions
                 WHERE snapshot_id=NEW.snapshot_id AND state IN ('ADMITTED','DEPRECATED'))
  OR EXISTS (SELECT 1 FROM semantic_terminal_admissions WHERE snapshot_id=NEW.snapshot_id)
  OR EXISTS (SELECT 1 FROM semantic_legacy_unprovable_admissions WHERE snapshot_id=NEW.snapshot_id)
BEGIN SELECT RAISE(ABORT, 'semantic re-attestation requires current usable admission'); END;

CREATE VIEW IF NOT EXISTS semantic_current_usable_snapshots AS
SELECT a.snapshot_id,a.state
FROM registry_snapshot_admissions a
JOIN semantic_repair_fences f
  ON f.generation=(SELECT MAX(generation) FROM semantic_repair_fences)
WHERE a.state IN ('ADMITTED','DEPRECATED')
  AND NOT EXISTS (SELECT 1 FROM semantic_terminal_admissions t
                  WHERE t.snapshot_id=a.snapshot_id)
  AND NOT EXISTS (SELECT 1 FROM semantic_legacy_unprovable_admissions u
                  WHERE u.snapshot_id=a.snapshot_id)
  AND (f.generation=0 OR EXISTS (
      SELECT 1 FROM semantic_snapshot_reattestations r
      WHERE r.snapshot_id=a.snapshot_id AND r.generation=f.generation
        AND r.verification_profile='strict-semantic-v0.1'
  ));

CREATE TRIGGER IF NOT EXISTS semantic_repair_activation_insert
BEFORE INSERT ON registry_activations
WHEN EXISTS (SELECT 1 FROM semantic_legacy_activation_quarantine)
 OR EXISTS (SELECT 1 FROM semantic_invalidated_activation_scopes q
             WHERE q.scope_kind=NEW.scope_kind AND q.scope_id=NEW.scope_id)
 OR ((SELECT MAX(generation) FROM semantic_repair_fences)>0
     AND NOT EXISTS (SELECT 1 FROM semantic_current_usable_snapshots
                     WHERE snapshot_id=NEW.snapshot_id AND state='ADMITTED'))
BEGIN SELECT RAISE(ABORT, 'activation requires current semantic re-attestation'); END;
CREATE TRIGGER IF NOT EXISTS semantic_repair_activation_update
BEFORE UPDATE ON registry_activations
WHEN EXISTS (SELECT 1 FROM semantic_legacy_activation_quarantine)
 OR EXISTS (SELECT 1 FROM semantic_invalidated_activation_scopes q
             WHERE q.scope_kind=NEW.scope_kind AND q.scope_id=NEW.scope_id)
 OR ((SELECT MAX(generation) FROM semantic_repair_fences)>0
     AND NOT EXISTS (SELECT 1 FROM semantic_current_usable_snapshots
                     WHERE snapshot_id=NEW.snapshot_id AND state='ADMITTED'))
BEGIN SELECT RAISE(ABORT, 'activation requires current semantic re-attestation'); END;
CREATE TRIGGER IF NOT EXISTS semantic_repair_registration_insert
BEFORE INSERT ON provider_registrations
WHEN (SELECT MAX(generation) FROM semantic_repair_fences)>0
 AND (NEW.registry_snapshot_id IS NULL OR NOT EXISTS (
    SELECT 1 FROM semantic_current_usable_snapshots
    WHERE snapshot_id=NEW.registry_snapshot_id))
BEGIN SELECT RAISE(ABORT, 'registration requires current semantic re-attestation'); END;
CREATE TRIGGER IF NOT EXISTS semantic_repair_registration_enable
BEFORE UPDATE OF state ON provider_registrations
WHEN (SELECT MAX(generation) FROM semantic_repair_fences)>0
 AND NEW.state='registered' AND NOT EXISTS (
    SELECT 1 FROM semantic_current_usable_snapshots
    WHERE snapshot_id=NEW.registry_snapshot_id)
BEGIN SELECT RAISE(ABORT, 'enablement requires current semantic re-attestation'); END;
CREATE TRIGGER IF NOT EXISTS semantic_repair_binding_insert
BEFORE INSERT ON execution_bindings
WHEN (SELECT MAX(generation) FROM semantic_repair_fences)>0
 AND (NOT EXISTS (SELECT 1 FROM semantic_current_usable_snapshots
                  WHERE snapshot_id=NEW.registry_snapshot_id)
   OR NOT EXISTS (
      SELECT 1 FROM provider_registrations p
      JOIN semantic_current_usable_snapshots s ON s.snapshot_id=p.registry_snapshot_id
      WHERE p.registration_id=NEW.provider_registration_id))
BEGIN SELECT RAISE(ABORT, 'binding requires current semantic re-attestation'); END;
