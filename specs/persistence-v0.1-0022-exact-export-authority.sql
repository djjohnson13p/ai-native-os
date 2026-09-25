-- Coordinator-owned service catalog and immutable, non-executable export pins.
-- A catalog row is never repurposed; disabling it immediately fences pending
-- candidates and retained export handles. Re-registration uses a new service ID.
CREATE TABLE IF NOT EXISTS authority_export_services (
    service_id TEXT PRIMARY KEY,
    destination_class TEXT NOT NULL,
    adapter_id TEXT NOT NULL,
    descriptor_hash TEXT NOT NULL,
    registered_at TEXT NOT NULL,
    CHECK (length(service_id)>10 AND substr(service_id,1,10)='service://'),
    CHECK (length(destination_class)>0 AND length(adapter_id)>0),
    CHECK (length(descriptor_hash)=71 AND substr(descriptor_hash,1,7)='sha256:')
);
CREATE TABLE IF NOT EXISTS authority_export_service_states (
    service_id TEXT PRIMARY KEY REFERENCES authority_export_services(service_id),
    state TEXT NOT NULL CHECK (state IN ('READY','DISABLED')),
    revision INTEGER NOT NULL CHECK (revision>=1),
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS authority_candidate_export_pins (
    candidate_id TEXT PRIMARY KEY REFERENCES authority_candidate_reservations(candidate_id),
    semantic_selector TEXT NOT NULL,
    service_id TEXT NOT NULL REFERENCES authority_export_services(service_id),
    destination_class TEXT NOT NULL,
    descriptor_hash TEXT NOT NULL,
    adapter_id TEXT NOT NULL,
    operation_id TEXT NOT NULL UNIQUE,
    source_artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id),
    source_content_hash TEXT NOT NULL,
    purpose TEXT NOT NULL,
    sensitivity TEXT NOT NULL CHECK (sensitivity IN ('public','local','private','confidential','secret')),
    max_size_bytes INTEGER NOT NULL CHECK (max_size_bytes>0 AND max_size_bytes<=8388608),
    reserved_at TEXT NOT NULL,
    CHECK (length(semantic_selector)>0 AND length(source_content_hash)>0 AND length(purpose)>0)
);
CREATE TRIGGER IF NOT EXISTS authority_export_service_no_update
BEFORE UPDATE ON authority_export_services
BEGIN SELECT RAISE(ABORT,'export service identity is immutable'); END;
CREATE TRIGGER IF NOT EXISTS authority_export_service_no_delete
BEFORE DELETE ON authority_export_services
BEGIN SELECT RAISE(ABORT,'export service identity is durable'); END;
CREATE TRIGGER IF NOT EXISTS authority_export_service_state_guard
BEFORE UPDATE ON authority_export_service_states
WHEN NEW.service_id<>OLD.service_id OR OLD.state<>'READY'
  OR NEW.state<>'DISABLED' OR NEW.revision<>OLD.revision+1
BEGIN SELECT RAISE(ABORT,'export service state transition is invalid'); END;
CREATE TRIGGER IF NOT EXISTS authority_export_service_state_no_delete
BEFORE DELETE ON authority_export_service_states
BEGIN SELECT RAISE(ABORT,'export service state is durable'); END;
CREATE TRIGGER IF NOT EXISTS authority_candidate_export_pin_no_update
BEFORE UPDATE ON authority_candidate_export_pins
BEGIN SELECT RAISE(ABORT,'candidate export pin is immutable'); END;
CREATE TRIGGER IF NOT EXISTS authority_candidate_export_pin_no_delete
BEFORE DELETE ON authority_candidate_export_pins
BEGIN SELECT RAISE(ABORT,'candidate export pin is durable'); END;
