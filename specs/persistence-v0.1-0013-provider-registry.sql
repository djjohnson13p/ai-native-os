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

-- A later review of the same exact build is an appended decision, not a rewrite
-- of its original registration receipt or a second build identity.
CREATE TABLE IF NOT EXISTS provider_trust_admissions (
    admission_id TEXT PRIMARY KEY,
    registration_id TEXT NOT NULL REFERENCES provider_registrations(registration_id),
    decision_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    trust_status TEXT NOT NULL CHECK (trust_status IN
        ('locally-trusted','project-reviewed','organization-approved')),
    authority_ref TEXT NOT NULL,
    admitted_at TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    UNIQUE (registration_id, decision_id),
    UNIQUE (registration_id, revision)
);
CREATE TRIGGER IF NOT EXISTS provider_trust_admission_no_update
BEFORE UPDATE ON provider_trust_admissions
BEGIN SELECT RAISE(ABORT, 'provider trust admission is immutable'); END;
CREATE TRIGGER IF NOT EXISTS provider_trust_admission_no_delete
BEFORE DELETE ON provider_trust_admissions
BEGIN SELECT RAISE(ABORT, 'provider trust admission cannot be deleted'); END;
CREATE TRIGGER IF NOT EXISTS provider_trust_admission_no_duplicate_insert
BEFORE INSERT ON provider_trust_admissions
WHEN EXISTS (SELECT 1 FROM provider_trust_admissions
    WHERE admission_id=NEW.admission_id
       OR (registration_id=NEW.registration_id AND decision_id=NEW.decision_id)
       OR (registration_id=NEW.registration_id AND revision=NEW.revision))
BEGIN SELECT RAISE(ABORT, 'provider trust admission cannot be replaced'); END;
CREATE TRIGGER IF NOT EXISTS provider_trust_admission_receipt_insert
BEFORE INSERT ON provider_trust_admissions
WHEN CASE WHEN json_valid(NEW.receipt_json) THEN
    json_extract(NEW.receipt_json,'$.registration_id') IS NOT NEW.registration_id
    OR json_extract(NEW.receipt_json,'$.decision_id') IS NOT NEW.decision_id
    OR json_extract(NEW.receipt_json,'$.revision') IS NOT NEW.revision
    OR json_extract(NEW.receipt_json,'$.trust_status') IS NOT NEW.trust_status
    OR json_extract(NEW.receipt_json,'$.authority_ref') IS NOT NEW.authority_ref
    OR json_extract(NEW.receipt_json,'$.admitted_at') IS NOT NEW.admitted_at
    OR NEW.revision IS NOT COALESCE((SELECT MAX(revision)+1
        FROM provider_trust_admissions WHERE registration_id=NEW.registration_id),1)
    ELSE 1 END
BEGIN SELECT RAISE(ABORT, 'provider trust admission receipt mismatch'); END;

CREATE TRIGGER IF NOT EXISTS provider_registration_revocation_terminal
BEFORE UPDATE OF state ON provider_registrations
WHEN OLD.state = 'revoked' AND NEW.state <> 'revoked'
BEGIN SELECT RAISE(ABORT, 'provider revocation is terminal'); END;
-- A retained terminal epoch also survives a registration row replaced while
-- an older uniqueness or initial-epoch guard was missing.
CREATE TRIGGER IF NOT EXISTS provider_registration_revoked_epoch_insert
BEFORE INSERT ON provider_registrations
WHEN EXISTS (SELECT 1 FROM provider_state_epochs
             WHERE registration_id=NEW.registration_id AND state='revoked')
BEGIN SELECT RAISE(ABORT, 'provider revocation epoch is terminal'); END;
CREATE TRIGGER IF NOT EXISTS provider_registration_revoked_epoch_update
BEFORE UPDATE OF state ON provider_registrations
WHEN NEW.state<>'revoked' AND EXISTS (
    SELECT 1 FROM provider_state_epochs
    WHERE registration_id=NEW.registration_id AND state='revoked')
BEGIN SELECT RAISE(ABORT, 'provider revocation epoch is terminal'); END;

-- Registration creates a disabled candidate. An enabled interval must have
-- its own transition time. Equal-time transitions preserve insertion order;
-- the effective clock cannot move backward.
CREATE TRIGGER IF NOT EXISTS provider_registration_no_initial_enablement
BEFORE INSERT ON provider_registrations
WHEN NEW.state='registered'
BEGIN SELECT RAISE(ABORT, 'provider cannot be enabled at registration'); END;
CREATE TRIGGER IF NOT EXISTS provider_registration_state_transition_clock
BEFORE UPDATE OF state,updated_at ON provider_registrations
WHEN NEW.state IS NOT OLD.state AND NOT EXISTS (
    WITH times AS (
        SELECT COALESCE(CAST(strftime('%s', COALESCE(OLD.updated_at,OLD.registered_at)) AS INTEGER),CASE WHEN substr(COALESCE(OLD.updated_at,OLD.registered_at),-6,1) IN ('+','-') AND substr(COALESCE(OLD.updated_at,OLD.registered_at),-5,5) GLOB '[0-2][0-9]:[0-5][0-9]' AND CAST(substr(COALESCE(OLD.updated_at,OLD.registered_at),-5,2) AS INTEGER)<=23 THEN CAST(strftime('%s',substr(COALESCE(OLD.updated_at,OLD.registered_at),1,length(COALESCE(OLD.updated_at,OLD.registered_at))-6)||'Z') AS INTEGER) - (CASE substr(COALESCE(OLD.updated_at,OLD.registered_at),-6,1) WHEN '+' THEN 1 ELSE -1 END) * (CAST(substr(COALESCE(OLD.updated_at,OLD.registered_at),-5,2) AS INTEGER)*3600 + CAST(substr(COALESCE(OLD.updated_at,OLD.registered_at),-2,2) AS INTEGER)*60) END) AS old_second,
               COALESCE(CAST(strftime('%s', NEW.updated_at) AS INTEGER),CASE WHEN substr(NEW.updated_at,-6,1) IN ('+','-') AND substr(NEW.updated_at,-5,5) GLOB '[0-2][0-9]:[0-5][0-9]' AND CAST(substr(NEW.updated_at,-5,2) AS INTEGER)<=23 THEN CAST(strftime('%s',substr(NEW.updated_at,1,length(NEW.updated_at)-6)||'Z') AS INTEGER) - (CASE substr(NEW.updated_at,-6,1) WHEN '+' THEN 1 ELSE -1 END) * (CAST(substr(NEW.updated_at,-5,2) AS INTEGER)*3600 + CAST(substr(NEW.updated_at,-2,2) AS INTEGER)*60) END) AS new_second,
               substr(CASE WHEN substr(COALESCE(OLD.updated_at,OLD.registered_at),20,1)='.' THEN
                   substr(COALESCE(OLD.updated_at,OLD.registered_at),21,
                       instr(replace(replace(replace(substr(COALESCE(OLD.updated_at,OLD.registered_at),21),'+','Z'),'-','Z'),'z','Z'),'Z')-1)
                   ELSE '' END || '000000000',1,9) AS old_fraction,
               substr(CASE WHEN substr(NEW.updated_at,20,1)='.' THEN
                   substr(NEW.updated_at,21,
                       instr(replace(replace(replace(substr(NEW.updated_at,21),'+','Z'),'-','Z'),'z','Z'),'Z')-1)
                   ELSE '' END || '000000000',1,9) AS new_fraction
    )
    SELECT 1 FROM times WHERE old_second IS NOT NULL AND new_second IS NOT NULL
      AND (new_second>old_second OR
           (new_second=old_second AND new_fraction>=old_fraction))
)
BEGIN SELECT RAISE(ABORT, 'provider state transition requires a later time'); END;
CREATE TRIGGER IF NOT EXISTS provider_registration_updated_at_requires_transition
BEFORE UPDATE OF state,updated_at ON provider_registrations
WHEN NEW.state IS OLD.state AND NEW.updated_at IS NOT OLD.updated_at
BEGIN SELECT RAISE(ABORT, 'provider state time requires a transition'); END;

-- Each state change mints a monotonic identity. Clock equality is permitted,
-- so timestamps alone cannot distinguish an old enabled interval from a
-- later disable/re-enable at the same instant.
CREATE TABLE IF NOT EXISTS provider_state_epochs (
    registration_id TEXT NOT NULL REFERENCES provider_registrations(registration_id),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    state TEXT NOT NULL CHECK (state IN ('registered','disabled','revoked','superseded','invalid')),
    transitioned_at TEXT NOT NULL,
    PRIMARY KEY (registration_id,revision)
);
-- Existing rows are disabled by fenced upgrade before this script runs.
INSERT INTO provider_state_epochs(registration_id,revision,state,transitioned_at)
SELECT r.registration_id,0,r.state,COALESCE(r.updated_at,r.registered_at)
FROM provider_registrations r
WHERE NOT EXISTS (SELECT 1 FROM provider_state_epochs e WHERE e.registration_id=r.registration_id);
CREATE TRIGGER IF NOT EXISTS provider_state_epoch_no_update
BEFORE UPDATE ON provider_state_epochs
BEGIN SELECT RAISE(ABORT, 'provider state epoch is immutable'); END;
CREATE TRIGGER IF NOT EXISTS provider_state_epoch_no_delete
BEFORE DELETE ON provider_state_epochs
BEGIN SELECT RAISE(ABORT, 'provider state epoch cannot be deleted'); END;
CREATE TRIGGER IF NOT EXISTS provider_state_epoch_no_duplicate_insert
BEFORE INSERT ON provider_state_epochs
WHEN EXISTS (SELECT 1 FROM provider_state_epochs
             WHERE registration_id=NEW.registration_id AND revision=NEW.revision)
BEGIN SELECT RAISE(ABORT, 'provider state epoch cannot be replaced'); END;
CREATE TRIGGER IF NOT EXISTS provider_state_epoch_event_insert_guard
BEFORE INSERT ON provider_state_epochs
WHEN NEW.revision >= 9223372036854775807 OR NOT EXISTS (
    SELECT 1 FROM provider_registrations r
    WHERE r.registration_id=NEW.registration_id
      AND r.state=NEW.state
      AND COALESCE(r.updated_at,r.registered_at)=NEW.transitioned_at
      AND NEW.revision=CASE
          WHEN (SELECT MAX(revision) FROM provider_state_epochs
                WHERE registration_id=NEW.registration_id) >= 9223372036854775806 THEN NULL
          ELSE COALESCE((SELECT MAX(revision)+1 FROM provider_state_epochs
                         WHERE registration_id=NEW.registration_id),0)
          END
      AND NOT EXISTS (
          SELECT 1 FROM provider_state_epochs e
          WHERE e.registration_id=NEW.registration_id
            AND e.revision=NEW.revision-1 AND e.state=NEW.state
      )
)
BEGIN SELECT RAISE(ABORT, 'provider state epoch does not match transition'); END;
CREATE TRIGGER IF NOT EXISTS provider_state_epoch_initial
AFTER INSERT ON provider_registrations
BEGIN
    INSERT INTO provider_state_epochs(registration_id,revision,state,transitioned_at)
    VALUES (NEW.registration_id,0,NEW.state,COALESCE(NEW.updated_at,NEW.registered_at));
END;
CREATE TRIGGER IF NOT EXISTS provider_state_epoch_transition
AFTER UPDATE OF state ON provider_registrations
WHEN NEW.state IS NOT OLD.state
BEGIN
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM provider_state_epochs
        WHERE registration_id=NEW.registration_id
          AND (typeof(revision)<>'integer' OR revision>=9223372036854775806
               OR (NEW.state='registered' AND revision>=9223372036854775805))
    ) THEN RAISE(ABORT, 'provider state epoch revision exhausted') END;
    INSERT INTO provider_state_epochs(registration_id,revision,state,transitioned_at)
    VALUES (NEW.registration_id,
            COALESCE((SELECT MAX(revision)+1 FROM provider_state_epochs
                      WHERE registration_id=NEW.registration_id),0),
            NEW.state,NEW.updated_at);
END;

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
CREATE TABLE IF NOT EXISTS execution_binding_trust_markers (
    binding_id TEXT PRIMARY KEY NOT NULL
        REFERENCES execution_bindings(binding_id) DEFERRABLE INITIALLY DEFERRED,
    trust_source_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS execution_binding_enablement_markers (
    binding_id TEXT PRIMARY KEY NOT NULL
        REFERENCES execution_bindings(binding_id) DEFERRABLE INITIALLY DEFERRED,
    registration_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 0),
    FOREIGN KEY (registration_id,revision)
        REFERENCES provider_state_epochs(registration_id,revision)
);
CREATE TRIGGER IF NOT EXISTS execution_binding_enablement_marker_no_update
BEFORE UPDATE ON execution_binding_enablement_markers
BEGIN SELECT RAISE(ABORT, 'execution binding enablement marker is immutable'); END;
CREATE TRIGGER IF NOT EXISTS execution_binding_enablement_marker_no_delete
BEFORE DELETE ON execution_binding_enablement_markers
BEGIN SELECT RAISE(ABORT, 'execution binding enablement marker cannot be deleted'); END;
CREATE TRIGGER IF NOT EXISTS execution_binding_enablement_marker_no_duplicate_insert
BEFORE INSERT ON execution_binding_enablement_markers
WHEN EXISTS (SELECT 1 FROM execution_binding_enablement_markers
             WHERE binding_id=NEW.binding_id)
  OR EXISTS (SELECT 1 FROM execution_bindings WHERE binding_id=NEW.binding_id)
BEGIN SELECT RAISE(ABORT, 'execution binding enablement marker cannot be replaced'); END;
CREATE TRIGGER IF NOT EXISTS execution_binding_enablement_marker_insert
BEFORE INSERT ON execution_bindings
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM provider_registrations r
        JOIN provider_state_epochs e ON e.registration_id=r.registration_id
        WHERE r.registration_id=NEW.provider_registration_id
          AND r.state='registered' AND e.state='registered'
          AND e.transitioned_at=r.updated_at
          AND e.revision=(SELECT MAX(revision) FROM provider_state_epochs
                          WHERE registration_id=r.registration_id)
    ) THEN RAISE(ABORT, 'binding requires current provider enablement interval') END;
    INSERT INTO execution_binding_enablement_markers(binding_id,registration_id,revision)
    SELECT NEW.binding_id,e.registration_id,e.revision
    FROM provider_state_epochs e
    WHERE e.registration_id=NEW.provider_registration_id
      AND e.revision=(SELECT MAX(revision) FROM provider_state_epochs
                      WHERE registration_id=NEW.provider_registration_id);
END;
-- Bindings admitted by the older 5eb3b71 trust guards retain their immutable
-- sidecars for audit, but cannot become executable under the newer rules.
CREATE TABLE IF NOT EXISTS execution_binding_legacy_trust_quarantine (
    binding_id TEXT PRIMARY KEY NOT NULL REFERENCES execution_bindings(binding_id)
);
CREATE TRIGGER IF NOT EXISTS execution_binding_legacy_trust_quarantine_no_update
BEFORE UPDATE ON execution_binding_legacy_trust_quarantine
BEGIN SELECT RAISE(ABORT, 'legacy binding trust quarantine is immutable'); END;
CREATE TRIGGER IF NOT EXISTS execution_binding_legacy_trust_quarantine_no_delete
BEFORE DELETE ON execution_binding_legacy_trust_quarantine
BEGIN SELECT RAISE(ABORT, 'legacy binding trust quarantine cannot be deleted'); END;
CREATE TRIGGER IF NOT EXISTS execution_binding_legacy_trust_quarantine_no_duplicate_insert
BEFORE INSERT ON execution_binding_legacy_trust_quarantine
WHEN EXISTS (SELECT 1 FROM execution_binding_legacy_trust_quarantine
             WHERE binding_id=NEW.binding_id)
BEGIN SELECT RAISE(ABORT, 'legacy binding trust quarantine cannot be replaced'); END;
CREATE TRIGGER IF NOT EXISTS execution_binding_trust_marker_no_update
BEFORE UPDATE ON execution_binding_trust_markers
BEGIN SELECT RAISE(ABORT, 'execution binding trust marker is immutable'); END;
CREATE TRIGGER IF NOT EXISTS execution_binding_trust_marker_no_delete
BEFORE DELETE ON execution_binding_trust_markers
BEGIN SELECT RAISE(ABORT, 'execution binding trust marker cannot be deleted'); END;
CREATE TRIGGER IF NOT EXISTS execution_binding_trust_marker_no_duplicate_insert
BEFORE INSERT ON execution_binding_trust_markers
WHEN EXISTS (SELECT 1 FROM execution_binding_trust_markers
             WHERE binding_id=NEW.binding_id)
  OR EXISTS (SELECT 1 FROM execution_bindings WHERE binding_id=NEW.binding_id)
BEGIN SELECT RAISE(ABORT, 'execution binding trust marker cannot be backfilled or replaced'); END;
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

-- A binding consumes an attempt only for the exact admitted registration
-- identity. The public receipt's provider projection is required at INSERT,
-- before later launch-time consistency checks can run.
CREATE TRIGGER IF NOT EXISTS execution_binding_provider_identity_at_insert
BEFORE INSERT ON execution_bindings
WHEN NOT EXISTS (
    SELECT 1 FROM provider_registrations r
    WHERE r.registration_id=NEW.provider_registration_id
      AND NEW.provider_manifest_hash IS NOT NULL
      AND NEW.provider_build_hash IS NOT NULL
      AND r.manifest_hash IS NEW.provider_manifest_hash
      AND r.package_content_hash IS NEW.provider_build_hash
      AND r.provider_id IS NEW.provider_id
      AND r.provider_version IS NEW.provider_version
      AND aios_binding_receipt_matches_v1(
          NEW.binding_json,NEW.binding_id,NEW.attempt_id,NEW.task_id,
          NEW.semantic_program_hash,NEW.registry_snapshot_id,NEW.ir_version,
          NEW.node_id,NEW.capability,NEW.capability_contract_hash,
          NEW.provider_id,NEW.provider_version,NEW.provider_manifest_hash,
          NEW.provider_build_hash,NEW.attempt,NEW.policy_decision_refs_json,
          NEW.grant_refs_json,NEW.execution_profile_ref,NEW.placement_json,
          NEW.created_at)=1
)
BEGIN SELECT RAISE(ABORT, 'binding provider identity does not match registration'); END;

-- The selected evidence must already be present when a binding is admitted.
-- An old binding cannot become valid merely because a matching result is
-- recorded later with a backdated executed_at claim.
CREATE TRIGGER IF NOT EXISTS execution_binding_evidence_pin_required
BEFORE INSERT ON execution_bindings
WHEN aios_binding_evidence_pin_v1(NEW.binding_json) IS NULL
BEGIN SELECT RAISE(ABORT, 'binding requires a valid conformance evidence pin'); END;
CREATE TRIGGER IF NOT EXISTS execution_binding_evidence_present_at_insert
BEFORE INSERT ON execution_bindings
WHEN aios_binding_evidence_pin_v1(NEW.binding_json) IS NOT NULL
 AND NOT EXISTS (
    SELECT 1 FROM provider_conformance_evidence e
    WHERE e.evidence_id=aios_binding_evidence_pin_v1(NEW.binding_json)
      AND e.registration_id=NEW.provider_registration_id
      AND e.capability=NEW.capability
      AND e.contract_hash=NEW.capability_contract_hash
      AND e.status='pass'
      AND e.suite_id IS NOT NULL AND e.suite_hash IS NOT NULL
      AND EXISTS (
          SELECT 1 FROM provider_manifest_payloads m,
               json_each(m.manifest_json,'$.provides') AS offered
          WHERE m.registration_id=NEW.provider_registration_id
            AND json_valid(m.manifest_json)
            AND json_extract(offered.value,'$.contract.capability') IS
                substr(NEW.capability,1,instr(NEW.capability,'@')-1)
            AND json_extract(offered.value,'$.contract.contract_hash') IS NEW.capability_contract_hash
            AND json_extract(offered.value,'$.conformance.suite') IS e.suite_id
            AND json_extract(offered.value,'$.conformance.suite_hash') IS e.suite_hash
      )
)
BEGIN SELECT RAISE(ABORT, 'binding conformance evidence was not admitted'); END;

-- A pinned result must have existed by the binding's declared creation time.
-- Compare UTC seconds and then all nine fractional digits; julianday alone
-- rounds at millisecond precision and raw RFC 3339 text compares offsets wrong.
CREATE TRIGGER IF NOT EXISTS execution_binding_evidence_not_future
BEFORE INSERT ON execution_bindings
WHEN NOT EXISTS (
    WITH pin AS (
        SELECT tested_at FROM provider_conformance_evidence
        WHERE evidence_id=aios_binding_evidence_pin_v1(NEW.binding_json)
    ), times AS (
        SELECT
            COALESCE(CAST(strftime('%s', tested_at) AS INTEGER),CASE WHEN substr(tested_at,-6,1) IN ('+','-') AND substr(tested_at,-5,5) GLOB '[0-2][0-9]:[0-5][0-9]' AND CAST(substr(tested_at,-5,2) AS INTEGER)<=23 THEN CAST(strftime('%s',substr(tested_at,1,length(tested_at)-6)||'Z') AS INTEGER) - (CASE substr(tested_at,-6,1) WHEN '+' THEN 1 ELSE -1 END) * (CAST(substr(tested_at,-5,2) AS INTEGER)*3600 + CAST(substr(tested_at,-2,2) AS INTEGER)*60) END) AS tested_second,
            COALESCE(CAST(strftime('%s', NEW.created_at) AS INTEGER),CASE WHEN substr(NEW.created_at,-6,1) IN ('+','-') AND substr(NEW.created_at,-5,5) GLOB '[0-2][0-9]:[0-5][0-9]' AND CAST(substr(NEW.created_at,-5,2) AS INTEGER)<=23 THEN CAST(strftime('%s',substr(NEW.created_at,1,length(NEW.created_at)-6)||'Z') AS INTEGER) - (CASE substr(NEW.created_at,-6,1) WHEN '+' THEN 1 ELSE -1 END) * (CAST(substr(NEW.created_at,-5,2) AS INTEGER)*3600 + CAST(substr(NEW.created_at,-2,2) AS INTEGER)*60) END) AS created_second,
            substr(CASE WHEN substr(tested_at,20,1)='.' THEN
                substr(tested_at,21,
                    instr(replace(replace(replace(substr(tested_at,21),'+','Z'),'-','Z'),'z','Z'),'Z')-1)
                ELSE '' END || '000000000',1,9) AS tested_fraction,
            substr(CASE WHEN substr(NEW.created_at,20,1)='.' THEN
                substr(NEW.created_at,21,
                    instr(replace(replace(replace(substr(NEW.created_at,21),'+','Z'),'-','Z'),'z','Z'),'Z')-1)
                ELSE '' END || '000000000',1,9) AS created_fraction
        FROM pin
    )
    SELECT 1 FROM times
    WHERE tested_second IS NOT NULL AND created_second IS NOT NULL
      AND (tested_second < created_second OR
           (tested_second = created_second AND tested_fraction <= created_fraction))
)
BEGIN SELECT RAISE(ABORT, 'binding predates pinned conformance evidence'); END;

-- A result expiring at or before binding creation cannot authorize an
-- immutable attempt. The optional absence of expires_at means unbounded;
-- present values compare as UTC seconds plus full nanosecond fractions.
CREATE TRIGGER IF NOT EXISTS execution_binding_evidence_unexpired_at_insert
BEFORE INSERT ON execution_bindings
WHEN NOT EXISTS (
    WITH pin AS (
        SELECT evidence_json FROM provider_conformance_evidence
        WHERE evidence_id=aios_binding_evidence_pin_v1(NEW.binding_json)
    ), expiry AS (
        SELECT json_extract(evidence_json, '$.expires_at') AS expires_at,
               json_type(evidence_json, '$.expires_at') AS expiry_type
        FROM pin WHERE json_valid(evidence_json)
    ), times AS (
        SELECT expiry_type,
               COALESCE(CAST(strftime('%s', expires_at) AS INTEGER),CASE WHEN substr(expires_at,-6,1) IN ('+','-') AND substr(expires_at,-5,5) GLOB '[0-2][0-9]:[0-5][0-9]' AND CAST(substr(expires_at,-5,2) AS INTEGER)<=23 THEN CAST(strftime('%s',substr(expires_at,1,length(expires_at)-6)||'Z') AS INTEGER) - (CASE substr(expires_at,-6,1) WHEN '+' THEN 1 ELSE -1 END) * (CAST(substr(expires_at,-5,2) AS INTEGER)*3600 + CAST(substr(expires_at,-2,2) AS INTEGER)*60) END) AS expiry_second,
               COALESCE(CAST(strftime('%s', NEW.created_at) AS INTEGER),CASE WHEN substr(NEW.created_at,-6,1) IN ('+','-') AND substr(NEW.created_at,-5,5) GLOB '[0-2][0-9]:[0-5][0-9]' AND CAST(substr(NEW.created_at,-5,2) AS INTEGER)<=23 THEN CAST(strftime('%s',substr(NEW.created_at,1,length(NEW.created_at)-6)||'Z') AS INTEGER) - (CASE substr(NEW.created_at,-6,1) WHEN '+' THEN 1 ELSE -1 END) * (CAST(substr(NEW.created_at,-5,2) AS INTEGER)*3600 + CAST(substr(NEW.created_at,-2,2) AS INTEGER)*60) END) AS created_second,
               substr(CASE WHEN substr(expires_at,20,1)='.' THEN
                   substr(expires_at,21,
                       instr(replace(replace(replace(substr(expires_at,21),'+','Z'),'-','Z'),'z','Z'),'Z')-1)
                   ELSE '' END || '000000000',1,9) AS expiry_fraction,
               substr(CASE WHEN substr(NEW.created_at,20,1)='.' THEN
                   substr(NEW.created_at,21,
                       instr(replace(replace(replace(substr(NEW.created_at,21),'+','Z'),'-','Z'),'z','Z'),'Z')-1)
                   ELSE '' END || '000000000',1,9) AS created_fraction
        FROM expiry
    )
    SELECT 1 FROM times
    WHERE expiry_type IS NULL OR expiry_type='null'
       OR (expiry_type='text' AND expiry_second IS NOT NULL AND created_second IS NOT NULL
           AND (expiry_second>created_second OR
                (expiry_second=created_second AND expiry_fraction>created_fraction)))
)
BEGIN SELECT RAISE(ABORT, 'binding conformance evidence expired at creation'); END;

-- A pass that was current when tested is not enough: a later exact-suite
-- result effective by binding creation supersedes it, including a failure.
-- Equal timestamps are ambiguous, so neither result may consume an attempt.
CREATE TRIGGER IF NOT EXISTS execution_binding_evidence_latest_at_insert
BEFORE INSERT ON execution_bindings
WHEN NOT EXISTS (
    WITH clock AS (
        SELECT COALESCE(CAST(strftime('%s', NEW.created_at) AS INTEGER),CASE WHEN substr(NEW.created_at,-6,1) IN ('+','-') AND substr(NEW.created_at,-5,5) GLOB '[0-2][0-9]:[0-5][0-9]' AND CAST(substr(NEW.created_at,-5,2) AS INTEGER)<=23 THEN CAST(strftime('%s',substr(NEW.created_at,1,length(NEW.created_at)-6)||'Z') AS INTEGER) - (CASE substr(NEW.created_at,-6,1) WHEN '+' THEN 1 ELSE -1 END) * (CAST(substr(NEW.created_at,-5,2) AS INTEGER)*3600 + CAST(substr(NEW.created_at,-2,2) AS INTEGER)*60) END) AS second,
               substr(CASE WHEN substr(NEW.created_at,20,1)='.' THEN
                   substr(NEW.created_at,21,
                       instr(replace(replace(replace(substr(NEW.created_at,21),'+','Z'),'-','Z'),'z','Z'),'Z')-1)
                   ELSE '' END || '000000000',1,9) AS fraction
    ), pin AS (
        SELECT registration_id,capability,contract_hash,suite_id,suite_hash
        FROM provider_conformance_evidence
        WHERE evidence_id=aios_binding_evidence_pin_v1(NEW.binding_json)
          AND suite_id IS NOT NULL AND suite_hash IS NOT NULL
    ), candidates AS (
        SELECT e.evidence_id,e.status,
               COALESCE(CAST(strftime('%s', e.tested_at) AS INTEGER),CASE WHEN substr(e.tested_at,-6,1) IN ('+','-') AND substr(e.tested_at,-5,5) GLOB '[0-2][0-9]:[0-5][0-9]' AND CAST(substr(e.tested_at,-5,2) AS INTEGER)<=23 THEN CAST(strftime('%s',substr(e.tested_at,1,length(e.tested_at)-6)||'Z') AS INTEGER) - (CASE substr(e.tested_at,-6,1) WHEN '+' THEN 1 ELSE -1 END) * (CAST(substr(e.tested_at,-5,2) AS INTEGER)*3600 + CAST(substr(e.tested_at,-2,2) AS INTEGER)*60) END) AS second,
               substr(CASE WHEN substr(e.tested_at,20,1)='.' THEN
                   substr(e.tested_at,21,
                       instr(replace(replace(replace(substr(e.tested_at,21),'+','Z'),'-','Z'),'z','Z'),'Z')-1)
                   ELSE '' END || '000000000',1,9) AS fraction
        FROM provider_conformance_evidence e JOIN pin p
          ON e.registration_id=p.registration_id AND e.capability=p.capability
         AND e.contract_hash=p.contract_hash AND e.suite_id=p.suite_id
         AND e.suite_hash=p.suite_hash
    ), eligible AS (
        SELECT c.* FROM candidates c, clock t
        WHERE c.second IS NOT NULL AND t.second IS NOT NULL
          AND (c.second<t.second OR
               (c.second=t.second AND c.fraction<=t.fraction))
    )
    SELECT 1 FROM eligible selected
    WHERE selected.evidence_id=aios_binding_evidence_pin_v1(NEW.binding_json)
      AND selected.status='pass'
      AND NOT EXISTS (SELECT 1 FROM candidates WHERE second IS NULL)
      AND NOT EXISTS (
          SELECT 1 FROM eligible other
          WHERE other.evidence_id<>selected.evidence_id
            AND (other.second>selected.second OR
                 (other.second=selected.second AND other.fraction>=selected.fraction))
      )
)
BEGIN SELECT RAISE(ABORT, 'binding conformance evidence is not latest'); END;

-- A binding can use only a trust decision already present at INSERT time.
-- The marker's source is the immutable original registration receipt for an
-- initially trusted build, or the latest appended trust decision receipt.
-- Historical untrusted bindings cannot acquire a marker after later review.
CREATE TRIGGER IF NOT EXISTS execution_binding_trust_marker_insert
BEFORE INSERT ON execution_bindings
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM provider_registrations r
        WHERE r.registration_id=NEW.provider_registration_id
          AND r.state='registered'
          AND r.trust_status NOT IN ('denied','revoked')
          AND (r.trust_status IN ('locally-trusted','project-reviewed','organization-approved')
               OR EXISTS (SELECT 1 FROM provider_trust_admissions a
                          WHERE a.registration_id=r.registration_id))
    ) THEN RAISE(ABORT, 'binding requires current trusted provider admission') END;
    SELECT CASE WHEN aios_binding_trust_pin_v1(NEW.binding_json) IS NULL
        OR aios_binding_trust_pin_v1(NEW.binding_json) IS NOT COALESCE(
            (SELECT a.admission_id FROM provider_trust_admissions a
             WHERE a.registration_id=NEW.provider_registration_id
               AND COALESCE(CAST(strftime('%s', a.admitted_at) AS INTEGER),CASE WHEN substr(a.admitted_at,-6,1) IN ('+','-') AND substr(a.admitted_at,-5,5) GLOB '[0-2][0-9]:[0-5][0-9]' AND CAST(substr(a.admitted_at,-5,2) AS INTEGER)<=23 THEN CAST(strftime('%s',substr(a.admitted_at,1,length(a.admitted_at)-6)||'Z') AS INTEGER) - (CASE substr(a.admitted_at,-6,1) WHEN '+' THEN 1 ELSE -1 END) * (CAST(substr(a.admitted_at,-5,2) AS INTEGER)*3600 + CAST(substr(a.admitted_at,-2,2) AS INTEGER)*60) END) IS NOT NULL
               AND COALESCE(CAST(strftime('%s', NEW.created_at) AS INTEGER),CASE WHEN substr(NEW.created_at,-6,1) IN ('+','-') AND substr(NEW.created_at,-5,5) GLOB '[0-2][0-9]:[0-5][0-9]' AND CAST(substr(NEW.created_at,-5,2) AS INTEGER)<=23 THEN CAST(strftime('%s',substr(NEW.created_at,1,length(NEW.created_at)-6)||'Z') AS INTEGER) - (CASE substr(NEW.created_at,-6,1) WHEN '+' THEN 1 ELSE -1 END) * (CAST(substr(NEW.created_at,-5,2) AS INTEGER)*3600 + CAST(substr(NEW.created_at,-2,2) AS INTEGER)*60) END) IS NOT NULL
               AND (
                   COALESCE(CAST(strftime('%s', a.admitted_at) AS INTEGER),CASE WHEN substr(a.admitted_at,-6,1) IN ('+','-') AND substr(a.admitted_at,-5,5) GLOB '[0-2][0-9]:[0-5][0-9]' AND CAST(substr(a.admitted_at,-5,2) AS INTEGER)<=23 THEN CAST(strftime('%s',substr(a.admitted_at,1,length(a.admitted_at)-6)||'Z') AS INTEGER) - (CASE substr(a.admitted_at,-6,1) WHEN '+' THEN 1 ELSE -1 END) * (CAST(substr(a.admitted_at,-5,2) AS INTEGER)*3600 + CAST(substr(a.admitted_at,-2,2) AS INTEGER)*60) END)
                       < COALESCE(CAST(strftime('%s', NEW.created_at) AS INTEGER),CASE WHEN substr(NEW.created_at,-6,1) IN ('+','-') AND substr(NEW.created_at,-5,5) GLOB '[0-2][0-9]:[0-5][0-9]' AND CAST(substr(NEW.created_at,-5,2) AS INTEGER)<=23 THEN CAST(strftime('%s',substr(NEW.created_at,1,length(NEW.created_at)-6)||'Z') AS INTEGER) - (CASE substr(NEW.created_at,-6,1) WHEN '+' THEN 1 ELSE -1 END) * (CAST(substr(NEW.created_at,-5,2) AS INTEGER)*3600 + CAST(substr(NEW.created_at,-2,2) AS INTEGER)*60) END)
                   OR (COALESCE(CAST(strftime('%s', a.admitted_at) AS INTEGER),CASE WHEN substr(a.admitted_at,-6,1) IN ('+','-') AND substr(a.admitted_at,-5,5) GLOB '[0-2][0-9]:[0-5][0-9]' AND CAST(substr(a.admitted_at,-5,2) AS INTEGER)<=23 THEN CAST(strftime('%s',substr(a.admitted_at,1,length(a.admitted_at)-6)||'Z') AS INTEGER) - (CASE substr(a.admitted_at,-6,1) WHEN '+' THEN 1 ELSE -1 END) * (CAST(substr(a.admitted_at,-5,2) AS INTEGER)*3600 + CAST(substr(a.admitted_at,-2,2) AS INTEGER)*60) END)
                           = COALESCE(CAST(strftime('%s', NEW.created_at) AS INTEGER),CASE WHEN substr(NEW.created_at,-6,1) IN ('+','-') AND substr(NEW.created_at,-5,5) GLOB '[0-2][0-9]:[0-5][0-9]' AND CAST(substr(NEW.created_at,-5,2) AS INTEGER)<=23 THEN CAST(strftime('%s',substr(NEW.created_at,1,length(NEW.created_at)-6)||'Z') AS INTEGER) - (CASE substr(NEW.created_at,-6,1) WHEN '+' THEN 1 ELSE -1 END) * (CAST(substr(NEW.created_at,-5,2) AS INTEGER)*3600 + CAST(substr(NEW.created_at,-2,2) AS INTEGER)*60) END)
                       AND substr(CASE WHEN substr(a.admitted_at,20,1)='.' THEN
                           substr(a.admitted_at,21,
                               instr(replace(replace(replace(substr(a.admitted_at,21),'+','Z'),'-','Z'),'z','Z'),'Z')-1)
                           ELSE '' END || '000000000',1,9)
                           <= substr(CASE WHEN substr(NEW.created_at,20,1)='.' THEN
                           substr(NEW.created_at,21,
                               instr(replace(replace(replace(substr(NEW.created_at,21),'+','Z'),'-','Z'),'z','Z'),'Z')-1)
                           ELSE '' END || '000000000',1,9))
               )
             ORDER BY a.revision DESC LIMIT 1),
            CASE WHEN (SELECT r.trust_status FROM provider_registrations r
                       WHERE r.registration_id=NEW.provider_registration_id)
                IN ('locally-trusted','project-reviewed','organization-approved')
                THEN NEW.provider_registration_id END)
    THEN RAISE(ABORT, 'binding trust source does not match current admission') END;
    INSERT INTO execution_binding_trust_markers(binding_id,trust_source_id)
    VALUES (NEW.binding_id,aios_binding_trust_pin_v1(NEW.binding_json));
END;

CREATE TRIGGER IF NOT EXISTS execution_binding_trust_not_future
BEFORE INSERT ON execution_bindings
WHEN NOT EXISTS (
    WITH latest AS (
        SELECT COALESCE(
            (SELECT admitted_at FROM provider_trust_admissions
             WHERE registration_id=NEW.provider_registration_id
               AND admission_id=aios_binding_trust_pin_v1(NEW.binding_json)),
            (SELECT registered_at FROM provider_registrations
             WHERE registration_id=NEW.provider_registration_id
               AND registration_id=aios_binding_trust_pin_v1(NEW.binding_json))
        ) AS admitted_at
    ), times AS (
        SELECT COALESCE(CAST(strftime('%s', admitted_at) AS INTEGER),CASE WHEN substr(admitted_at,-6,1) IN ('+','-') AND substr(admitted_at,-5,5) GLOB '[0-2][0-9]:[0-5][0-9]' AND CAST(substr(admitted_at,-5,2) AS INTEGER)<=23 THEN CAST(strftime('%s',substr(admitted_at,1,length(admitted_at)-6)||'Z') AS INTEGER) - (CASE substr(admitted_at,-6,1) WHEN '+' THEN 1 ELSE -1 END) * (CAST(substr(admitted_at,-5,2) AS INTEGER)*3600 + CAST(substr(admitted_at,-2,2) AS INTEGER)*60) END) AS admitted_second,
               COALESCE(CAST(strftime('%s', NEW.created_at) AS INTEGER),CASE WHEN substr(NEW.created_at,-6,1) IN ('+','-') AND substr(NEW.created_at,-5,5) GLOB '[0-2][0-9]:[0-5][0-9]' AND CAST(substr(NEW.created_at,-5,2) AS INTEGER)<=23 THEN CAST(strftime('%s',substr(NEW.created_at,1,length(NEW.created_at)-6)||'Z') AS INTEGER) - (CASE substr(NEW.created_at,-6,1) WHEN '+' THEN 1 ELSE -1 END) * (CAST(substr(NEW.created_at,-5,2) AS INTEGER)*3600 + CAST(substr(NEW.created_at,-2,2) AS INTEGER)*60) END) AS created_second,
               substr(CASE WHEN substr(admitted_at,20,1)='.' THEN
                   substr(admitted_at,21,
                       instr(replace(replace(replace(substr(admitted_at,21),'+','Z'),'-','Z'),'z','Z'),'Z')-1)
                   ELSE '' END || '000000000',1,9) AS admitted_fraction,
               substr(CASE WHEN substr(NEW.created_at,20,1)='.' THEN
                   substr(NEW.created_at,21,
                       instr(replace(replace(replace(substr(NEW.created_at,21),'+','Z'),'-','Z'),'z','Z'),'Z')-1)
                   ELSE '' END || '000000000',1,9) AS created_fraction
        FROM latest
    )
    SELECT 1 FROM times
    WHERE admitted_second IS NOT NULL AND created_second IS NOT NULL
      AND (admitted_second < created_second OR
           (admitted_second=created_second AND admitted_fraction<=created_fraction))
)
BEGIN SELECT RAISE(ABORT, 'binding predates provider trust admission'); END;

-- The registration starts disabled. The current registered interval began at
-- the last state transition, which must already have taken effect by the
-- binding's declared creation time.
CREATE TRIGGER IF NOT EXISTS execution_binding_provider_enablement_not_future
BEFORE INSERT ON execution_bindings
WHEN NOT EXISTS (
    WITH times AS (
        SELECT COALESCE(CAST(strftime('%s', r.updated_at) AS INTEGER),CASE WHEN substr(r.updated_at,-6,1) IN ('+','-') AND substr(r.updated_at,-5,5) GLOB '[0-2][0-9]:[0-5][0-9]' AND CAST(substr(r.updated_at,-5,2) AS INTEGER)<=23 THEN CAST(strftime('%s',substr(r.updated_at,1,length(r.updated_at)-6)||'Z') AS INTEGER) - (CASE substr(r.updated_at,-6,1) WHEN '+' THEN 1 ELSE -1 END) * (CAST(substr(r.updated_at,-5,2) AS INTEGER)*3600 + CAST(substr(r.updated_at,-2,2) AS INTEGER)*60) END) AS enabled_second,
               COALESCE(CAST(strftime('%s', NEW.created_at) AS INTEGER),CASE WHEN substr(NEW.created_at,-6,1) IN ('+','-') AND substr(NEW.created_at,-5,5) GLOB '[0-2][0-9]:[0-5][0-9]' AND CAST(substr(NEW.created_at,-5,2) AS INTEGER)<=23 THEN CAST(strftime('%s',substr(NEW.created_at,1,length(NEW.created_at)-6)||'Z') AS INTEGER) - (CASE substr(NEW.created_at,-6,1) WHEN '+' THEN 1 ELSE -1 END) * (CAST(substr(NEW.created_at,-5,2) AS INTEGER)*3600 + CAST(substr(NEW.created_at,-2,2) AS INTEGER)*60) END) AS created_second,
               substr(CASE WHEN substr(r.updated_at,20,1)='.' THEN
                   substr(r.updated_at,21,
                       instr(replace(replace(replace(substr(r.updated_at,21),'+','Z'),'-','Z'),'z','Z'),'Z')-1)
                   ELSE '' END || '000000000',1,9) AS enabled_fraction,
               substr(CASE WHEN substr(NEW.created_at,20,1)='.' THEN
                   substr(NEW.created_at,21,
                       instr(replace(replace(replace(substr(NEW.created_at,21),'+','Z'),'-','Z'),'z','Z'),'Z')-1)
                   ELSE '' END || '000000000',1,9) AS created_fraction
        FROM provider_registrations r
        WHERE r.registration_id=NEW.provider_registration_id AND r.state='registered'
    )
    SELECT 1 FROM times
    WHERE enabled_second IS NOT NULL AND created_second IS NOT NULL
      AND (enabled_second<created_second OR
           (enabled_second=created_second AND enabled_fraction<=created_fraction))
)
BEGIN SELECT RAISE(ABORT, 'binding predates provider enablement'); END;

CREATE TRIGGER IF NOT EXISTS execution_binding_admission_marker_insert
BEFORE INSERT ON execution_bindings
WHEN aios_binding_evidence_pin_v1(NEW.binding_json) IS NOT NULL
 AND EXISTS (
    SELECT 1 FROM provider_conformance_evidence
    WHERE evidence_id=aios_binding_evidence_pin_v1(NEW.binding_json)
      AND registration_id=NEW.provider_registration_id
      AND capability=NEW.capability
      AND contract_hash=NEW.capability_contract_hash
      AND status='pass'
)
BEGIN
    INSERT INTO execution_binding_admission_markers(binding_id,conformance_evidence_id)
    VALUES (NEW.binding_id,aios_binding_evidence_pin_v1(NEW.binding_json));
END;
