-- A placement receipt is the durable causal authority to recover one exact
-- pending blob after a filesystem/SQLite commit gap. Existing blob rows do not
-- imply a receipt; migration intentionally grants nothing to legacy placements.
CREATE TABLE IF NOT EXISTS artifact_placement_receipts (
    placement_id TEXT PRIMARY KEY CHECK (
        length(placement_id)=32 AND placement_id NOT GLOB '*[^0-9a-f]*'),
    pending_ref TEXT NOT NULL UNIQUE CHECK (
        length(pending_ref) BETWEEN 1 AND 256 AND instr(pending_ref,char(0))=0),
    payload_hash TEXT NOT NULL CHECK (
        length(payload_hash)=71 AND substr(payload_hash,1,7)='sha256:'
        AND substr(payload_hash,8) NOT GLOB '*[^0-9a-f]*'),
    payload_size INTEGER NOT NULL CHECK (payload_size>=0),
    origin TEXT NOT NULL CHECK (origin IN ('IMPORT','PUBLICATION')),
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    operation_id TEXT NOT NULL CHECK (
        length(operation_id) BETWEEN 1 AND 256 AND instr(operation_id,char(0))=0),
    operation_request_id TEXT NOT NULL CHECK (
        length(operation_request_id)>0 AND json_valid(operation_request_id)),
    owner_epoch INTEGER NOT NULL CHECK (owner_epoch>=1),
    placement_marker_id TEXT REFERENCES trusted_time_effect_preparations(marker_id),
    CHECK ((origin='IMPORT' AND placement_marker_id IS NULL)
        OR (origin='PUBLICATION' AND placement_marker_id IS NOT NULL))
);
CREATE TRIGGER IF NOT EXISTS artifact_placement_receipt_exact_insert
BEFORE INSERT ON artifact_placement_receipts
WHEN NOT EXISTS (
    SELECT 1 FROM task_manager_lease l
    WHERE l.singleton_id=1 AND l.fence_epoch=NEW.owner_epoch)
  OR (NEW.origin='PUBLICATION' AND NOT EXISTS (
    SELECT 1 FROM trusted_time_effect_preparations p
    JOIN trusted_time_effect_resolutions r ON r.marker_id=p.marker_id
    WHERE p.marker_id=NEW.placement_marker_id
      AND p.subject_kind='ARTIFACT_PUBLICATION'
      AND p.subject_id=NEW.operation_id
      AND p.task_id=NEW.task_id AND p.owner_epoch=NEW.owner_epoch
      AND r.resolution_kind='EFFECT_INVOKED'))
BEGIN SELECT RAISE(ABORT,'artifact placement receipt lacks exact owner or publication marker'); END;
CREATE TRIGGER IF NOT EXISTS artifact_placement_receipt_no_update
BEFORE UPDATE ON artifact_placement_receipts
BEGIN SELECT RAISE(ABORT,'artifact placement receipt is immutable'); END;
CREATE TRIGGER IF NOT EXISTS artifact_placement_receipt_no_delete
BEFORE DELETE ON artifact_placement_receipts
BEGIN SELECT RAISE(ABORT,'artifact placement receipt is durable'); END;
