-- Durable fence for time observations around effects outside the SQLite commit.
-- Preparation and resolution are separate immutable receipts. The pending table
-- is an indexed projection maintained only by their insert triggers.
CREATE TABLE IF NOT EXISTS trusted_time_effect_preparations (
    marker_id TEXT PRIMARY KEY CHECK (length(marker_id)=32 AND marker_id NOT GLOB '*[^0-9a-f]*'),
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    subject_kind TEXT NOT NULL CHECK (subject_kind IN
        ('ARTIFACT_READ','ARTIFACT_STAGING_WRITE','ARTIFACT_STAGING_SEAL',
         'ARTIFACT_PUBLICATION','ARTIFACT_EXPORT_CONSTRUCTION',
         'ARTIFACT_EXPORT_COPY','ARTIFACT_EXPORT_FINALIZE')),
    subject_id TEXT NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 256 AND instr(subject_id,char(0))=0),
    owner_id TEXT NOT NULL,
    owner_epoch INTEGER NOT NULL CHECK (owner_epoch>=1),
    prepared_state_revision INTEGER NOT NULL REFERENCES trusted_time_observations(state_revision),
    prepared_observed_unix_nanos INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS trusted_time_effect_resolutions (
    marker_id TEXT PRIMARY KEY REFERENCES trusted_time_effect_preparations(marker_id),
    resolved_state_revision INTEGER NOT NULL UNIQUE REFERENCES trusted_time_observations(state_revision),
    entry_observed_unix_nanos INTEGER,
    resolution_kind TEXT NOT NULL CHECK (resolution_kind IN ('EFFECT_INVOKED','NO_EFFECT'))
);
CREATE TABLE IF NOT EXISTS trusted_time_effect_pending (
    marker_id TEXT PRIMARY KEY REFERENCES trusted_time_effect_preparations(marker_id)
);
CREATE TRIGGER IF NOT EXISTS trusted_time_effect_prepare_no_duplicate
BEFORE INSERT ON trusted_time_effect_preparations
WHEN EXISTS (SELECT 1 FROM trusted_time_effect_preparations WHERE marker_id=NEW.marker_id)
BEGIN SELECT RAISE(ABORT,'in-flight time marker already exists'); END;
CREATE TRIGGER IF NOT EXISTS trusted_time_effect_prepare_exact_insert
BEFORE INSERT ON trusted_time_effect_preparations
WHEN NOT EXISTS (
    SELECT 1 FROM trusted_time_state s
    JOIN trusted_time_observations o ON o.state_revision=s.revision
    JOIN task_manager_lease l ON l.singleton_id=1
    WHERE s.singleton_id=1 AND s.confidence='TRUSTED_LOCAL'
      AND o.confidence='TRUSTED_LOCAL'
      AND o.observed_unix_nanos=NEW.prepared_observed_unix_nanos
      AND s.revision=NEW.prepared_state_revision
      AND l.owner_id=NEW.owner_id AND l.fence_epoch=NEW.owner_epoch)
BEGIN SELECT RAISE(ABORT,'in-flight time preparation lacks exact clock and owner'); END;
CREATE TRIGGER IF NOT EXISTS trusted_time_effect_prepare_project
AFTER INSERT ON trusted_time_effect_preparations
BEGIN INSERT INTO trusted_time_effect_pending(marker_id) VALUES (NEW.marker_id); END;
CREATE TRIGGER IF NOT EXISTS trusted_time_effect_prepare_no_update
BEFORE UPDATE ON trusted_time_effect_preparations
BEGIN SELECT RAISE(ABORT,'in-flight time preparation is immutable'); END;
CREATE TRIGGER IF NOT EXISTS trusted_time_effect_prepare_no_delete
BEFORE DELETE ON trusted_time_effect_preparations
BEGIN SELECT RAISE(ABORT,'in-flight time preparation is durable'); END;
CREATE TRIGGER IF NOT EXISTS trusted_time_effect_resolution_no_duplicate
BEFORE INSERT ON trusted_time_effect_resolutions
WHEN EXISTS (SELECT 1 FROM trusted_time_effect_resolutions WHERE marker_id=NEW.marker_id
              OR resolved_state_revision=NEW.resolved_state_revision)
BEGIN SELECT RAISE(ABORT,'in-flight time resolution already exists'); END;
CREATE TRIGGER IF NOT EXISTS trusted_time_effect_resolution_exact_insert
BEFORE INSERT ON trusted_time_effect_resolutions
WHEN NOT EXISTS (
    SELECT 1 FROM trusted_time_effect_preparations p
    JOIN trusted_time_effect_pending x ON x.marker_id=p.marker_id
    JOIN trusted_time_state s ON s.singleton_id=1
    JOIN trusted_time_observations o ON o.state_revision=s.revision
    JOIN task_manager_lease l ON l.singleton_id=1
    WHERE p.marker_id=NEW.marker_id AND s.revision=NEW.resolved_state_revision
      AND s.revision>p.prepared_state_revision
      AND o.confidence=s.confidence
      AND o.observed_unix_nanos IS NEW.entry_observed_unix_nanos
      AND ((NEW.resolution_kind='EFFECT_INVOKED'
            AND s.confidence='TRUSTED_LOCAL' AND NEW.entry_observed_unix_nanos IS NOT NULL)
        OR (NEW.resolution_kind='NO_EFFECT'
            AND s.confidence IN ('TRUSTED_LOCAL','TIME_UNCERTAIN')))
      AND l.owner_id=p.owner_id AND l.fence_epoch=p.owner_epoch
      AND (SELECT COUNT(*) FROM trusted_time_effect_pending)=1)
BEGIN SELECT RAISE(ABORT,'in-flight time resolution lacks exact entry clock and owner'); END;
CREATE TRIGGER IF NOT EXISTS trusted_time_effect_resolution_project
AFTER INSERT ON trusted_time_effect_resolutions
BEGIN DELETE FROM trusted_time_effect_pending WHERE marker_id=NEW.marker_id; END;
CREATE TRIGGER IF NOT EXISTS trusted_time_effect_resolution_no_update
BEFORE UPDATE ON trusted_time_effect_resolutions
BEGIN SELECT RAISE(ABORT,'in-flight time resolution is immutable'); END;
CREATE TRIGGER IF NOT EXISTS trusted_time_effect_resolution_no_delete
BEFORE DELETE ON trusted_time_effect_resolutions
BEGIN SELECT RAISE(ABORT,'in-flight time resolution is durable'); END;
CREATE TRIGGER IF NOT EXISTS trusted_time_effect_pending_no_duplicate
BEFORE INSERT ON trusted_time_effect_pending
WHEN EXISTS (SELECT 1 FROM trusted_time_effect_pending WHERE marker_id=NEW.marker_id)
BEGIN SELECT RAISE(ABORT,'in-flight time marker is already pending'); END;
CREATE TRIGGER IF NOT EXISTS trusted_time_effect_pending_exact_insert
BEFORE INSERT ON trusted_time_effect_pending
WHEN NOT EXISTS (SELECT 1 FROM trusted_time_effect_preparations WHERE marker_id=NEW.marker_id)
  OR EXISTS (SELECT 1 FROM trusted_time_effect_resolutions WHERE marker_id=NEW.marker_id)
BEGIN SELECT RAISE(ABORT,'in-flight time pending projection is invalid'); END;
CREATE TRIGGER IF NOT EXISTS trusted_time_effect_pending_no_update
BEFORE UPDATE ON trusted_time_effect_pending
BEGIN SELECT RAISE(ABORT,'in-flight time pending projection is immutable'); END;
CREATE TRIGGER IF NOT EXISTS trusted_time_effect_pending_no_unresolved_delete
BEFORE DELETE ON trusted_time_effect_pending
WHEN NOT EXISTS (SELECT 1 FROM trusted_time_effect_resolutions WHERE marker_id=OLD.marker_id)
BEGIN SELECT RAISE(ABORT,'unresolved in-flight time marker cannot be deleted'); END;
