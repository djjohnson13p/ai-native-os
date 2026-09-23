-- Additive provider lifecycle constraints over the trusted control-plane baseline.
-- Registration identity, registration_json admission receipt, and conformance
-- evidence are immutable. The state/trust columns are current lifecycle data;
-- revocation is terminal. Health is deliberately separate.
CREATE TABLE IF NOT EXISTS provider_health_observations (
    registration_id TEXT PRIMARY KEY REFERENCES provider_registrations(registration_id),
    status TEXT NOT NULL CHECK (status IN ('unknown','ready','degraded','unavailable','blocked')),
    checked_at TEXT NOT NULL,
    reason TEXT
);

CREATE TABLE IF NOT EXISTS provider_manifest_payloads (
    registration_id TEXT PRIMARY KEY REFERENCES provider_registrations(registration_id),
    manifest_json TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS provider_manifest_payload_immutable_update
BEFORE UPDATE ON provider_manifest_payloads
BEGIN SELECT RAISE(ABORT, 'provider manifest payload is immutable'); END;
CREATE TRIGGER IF NOT EXISTS provider_manifest_payload_immutable_delete
BEFORE DELETE ON provider_manifest_payloads
BEGIN SELECT RAISE(ABORT, 'provider manifest payload cannot be deleted'); END;
CREATE TRIGGER IF NOT EXISTS provider_manifest_payload_no_duplicate_insert
BEFORE INSERT ON provider_manifest_payloads
WHEN EXISTS (SELECT 1 FROM provider_manifest_payloads WHERE registration_id=NEW.registration_id)
BEGIN SELECT RAISE(ABORT, 'provider manifest payload cannot be replaced'); END;

CREATE TRIGGER IF NOT EXISTS provider_registration_identity_immutable
BEFORE UPDATE OF registration_id,provider_id,provider_version,manifest_hash,package_content_hash,
    registry_snapshot_id,registration_json,registered_at ON provider_registrations
BEGIN SELECT RAISE(ABORT, 'provider registration identity is immutable'); END;

CREATE TRIGGER IF NOT EXISTS provider_registration_no_delete
BEFORE DELETE ON provider_registrations
BEGIN SELECT RAISE(ABORT, 'provider registration cannot be deleted'); END;
CREATE TRIGGER IF NOT EXISTS provider_registration_no_duplicate_insert
BEFORE INSERT ON provider_registrations
WHEN EXISTS (
    SELECT 1 FROM provider_registrations
    WHERE registration_id=NEW.registration_id
       OR (provider_id=NEW.provider_id AND provider_version=NEW.provider_version
           AND package_content_hash=NEW.package_content_hash)
)
BEGIN SELECT RAISE(ABORT, 'provider registration cannot be replaced'); END;

-- The admitted trust level is part of the immutable registration receipt.
-- Runtime disable/revocation uses state; later trust elevation requires a new
-- admission identity and receipt rather than editing this projection.
CREATE TRIGGER IF NOT EXISTS provider_registration_trust_receipt_insert
BEFORE INSERT ON provider_registrations
WHEN CASE WHEN json_valid(NEW.registration_json) THEN
    json_type(NEW.registration_json, '$.trust.status') IS NOT 'text'
    OR NEW.trust_status NOT IN (
        'unverified','locally-trusted','project-reviewed',
        'organization-approved','denied','revoked'
    )
    OR NEW.trust_status IS NOT json_extract(NEW.registration_json, '$.trust.status')
    ELSE 1 END
BEGIN SELECT RAISE(ABORT, 'provider trust must match immutable admission receipt'); END;
CREATE TRIGGER IF NOT EXISTS provider_registration_trust_immutable_update
BEFORE UPDATE OF trust_status ON provider_registrations
WHEN NEW.trust_status IS NOT OLD.trust_status
BEGIN SELECT RAISE(ABORT, 'provider trust cannot change without new admission'); END;

CREATE TRIGGER IF NOT EXISTS provider_registration_revocation_terminal
BEFORE UPDATE OF state ON provider_registrations
WHEN OLD.state = 'revoked' AND NEW.state <> 'revoked'
BEGIN SELECT RAISE(ABORT, 'provider revocation is terminal'); END;

CREATE TRIGGER IF NOT EXISTS provider_evidence_immutable_update
BEFORE UPDATE ON provider_conformance_evidence
BEGIN SELECT RAISE(ABORT, 'provider conformance evidence is immutable'); END;

CREATE TRIGGER IF NOT EXISTS provider_evidence_immutable_delete
BEFORE DELETE ON provider_conformance_evidence
BEGIN SELECT RAISE(ABORT, 'provider conformance evidence cannot be deleted'); END;
CREATE TRIGGER IF NOT EXISTS provider_evidence_no_duplicate_insert
BEFORE INSERT ON provider_conformance_evidence
WHEN EXISTS (SELECT 1 FROM provider_conformance_evidence WHERE evidence_id=NEW.evidence_id)
BEGIN SELECT RAISE(ABORT, 'provider conformance evidence cannot be replaced'); END;

CREATE INDEX IF NOT EXISTS ix_provider_conformance_latest
ON provider_conformance_evidence(registration_id,capability,contract_hash,suite_id,suite_hash,tested_at);

-- Only bindings inserted after this trigger is installed receive an admission
-- marker. Historical bindings cannot acquire one later, even if a result with
-- a backdated executed_at is recorded. The key remains stable across VACUUM.
CREATE TABLE IF NOT EXISTS execution_binding_admission_markers (
    binding_id TEXT PRIMARY KEY NOT NULL
        REFERENCES execution_bindings(binding_id) DEFERRABLE INITIALLY DEFERRED,
    conformance_evidence_id TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS execution_binding_marker_no_update
BEFORE UPDATE ON execution_binding_admission_markers
BEGIN SELECT RAISE(ABORT, 'execution binding admission marker is immutable'); END;
CREATE TRIGGER IF NOT EXISTS execution_binding_marker_no_delete
BEFORE DELETE ON execution_binding_admission_markers
BEGIN SELECT RAISE(ABORT, 'execution binding admission marker cannot be deleted'); END;
CREATE TRIGGER IF NOT EXISTS execution_binding_marker_no_duplicate_insert
BEFORE INSERT ON execution_binding_admission_markers
WHEN EXISTS (SELECT 1 FROM execution_binding_admission_markers
             WHERE binding_id=NEW.binding_id)
  OR EXISTS (SELECT 1 FROM execution_bindings WHERE binding_id=NEW.binding_id)
BEGIN SELECT RAISE(ABORT, 'execution binding admission marker cannot be backfilled or replaced'); END;

-- A REPLACE can delete an immutable binding without firing its DELETE trigger
-- when recursive_triggers is disabled. Reject every key it could replace first.
CREATE TRIGGER IF NOT EXISTS execution_binding_no_duplicate_insert
BEFORE INSERT ON execution_bindings
WHEN EXISTS (
    SELECT 1 FROM execution_bindings
    WHERE binding_id=NEW.binding_id OR attempt_id=NEW.attempt_id
       OR (task_id=NEW.task_id AND semantic_program_hash=NEW.semantic_program_hash
           AND node_id=NEW.node_id AND attempt=NEW.attempt)
)
BEGIN SELECT RAISE(ABORT, 'execution binding cannot be replaced'); END;

-- The selected evidence must already be present when a binding is admitted.
-- An old binding cannot become valid merely because a matching result is
-- recorded later with a backdated executed_at claim.
CREATE TRIGGER IF NOT EXISTS execution_binding_evidence_pin_required
BEFORE INSERT ON execution_bindings
WHEN CASE WHEN json_valid(NEW.binding_json) THEN
    json_type(NEW.binding_json, '$.conformance_evidence_id') IS NOT 'text'
    OR length(json_extract(NEW.binding_json, '$.conformance_evidence_id')) NOT BETWEEN 1 AND 256
    ELSE 1 END
BEGIN SELECT RAISE(ABORT, 'binding requires a valid conformance evidence pin'); END;
CREATE TRIGGER IF NOT EXISTS execution_binding_evidence_present_at_insert
BEFORE INSERT ON execution_bindings
WHEN json_valid(NEW.binding_json)
 AND json_type(NEW.binding_json, '$.conformance_evidence_id') = 'text'
 AND NOT EXISTS (
    SELECT 1 FROM provider_conformance_evidence
    WHERE evidence_id=json_extract(NEW.binding_json, '$.conformance_evidence_id')
      AND registration_id=NEW.provider_registration_id
      AND capability=NEW.capability
      AND contract_hash=NEW.capability_contract_hash
      AND status='pass'
)
BEGIN SELECT RAISE(ABORT, 'binding conformance evidence was not admitted'); END;

CREATE TRIGGER IF NOT EXISTS execution_binding_admission_marker_insert
BEFORE INSERT ON execution_bindings
WHEN json_valid(NEW.binding_json)
 AND json_type(NEW.binding_json, '$.conformance_evidence_id') = 'text'
 AND EXISTS (
    SELECT 1 FROM provider_conformance_evidence
    WHERE evidence_id=json_extract(NEW.binding_json, '$.conformance_evidence_id')
      AND registration_id=NEW.provider_registration_id
      AND capability=NEW.capability
      AND contract_hash=NEW.capability_contract_hash
      AND status='pass'
)
BEGIN
    INSERT INTO execution_binding_admission_markers(binding_id,conformance_evidence_id)
    VALUES (NEW.binding_id,json_extract(NEW.binding_json, '$.conformance_evidence_id'));
END;
