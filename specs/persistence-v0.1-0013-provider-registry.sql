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

CREATE TRIGGER IF NOT EXISTS provider_registration_identity_immutable
BEFORE UPDATE OF registration_id,provider_id,provider_version,manifest_hash,package_content_hash,
    registry_snapshot_id,registration_json,registered_at ON provider_registrations
BEGIN SELECT RAISE(ABORT, 'provider registration identity is immutable'); END;

CREATE TRIGGER IF NOT EXISTS provider_registration_no_delete
BEFORE DELETE ON provider_registrations
BEGIN SELECT RAISE(ABORT, 'provider registration cannot be deleted'); END;

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

CREATE INDEX IF NOT EXISTS ix_provider_conformance_latest
ON provider_conformance_evidence(registration_id,capability,contract_hash,suite_id,suite_hash,tested_at);
