-- Reserved identities and resolved resources are non-executable. Finalization
-- must atomically revalidate these pins, issue grants, create the immutable
-- Execution Binding, and CAS the separate status row.
CREATE TABLE IF NOT EXISTS authority_candidate_reservations (
    candidate_id TEXT PRIMARY KEY,
    binding_id TEXT NOT NULL UNIQUE,
    attempt_id TEXT NOT NULL UNIQUE,
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    semantic_program_hash TEXT NOT NULL,
    registry_snapshot_id TEXT NOT NULL REFERENCES registry_snapshots(snapshot_id),
    ir_version TEXT NOT NULL,
    node_id TEXT NOT NULL,
    capability TEXT NOT NULL,
    capability_contract_hash TEXT NOT NULL,
    provider_registration_id TEXT NOT NULL REFERENCES provider_registrations(registration_id),
    provider_id TEXT NOT NULL,
    provider_version TEXT NOT NULL,
    provider_manifest_hash TEXT NOT NULL,
    provider_build_hash TEXT NOT NULL,
    conformance_evidence_id TEXT NOT NULL REFERENCES provider_conformance_evidence(evidence_id),
    provider_trust_source_id TEXT NOT NULL,
    execution_profile_ref TEXT NOT NULL,
    isolation_class TEXT NOT NULL CHECK (isolation_class IN ('P0','P1','P2','P3','P4','P5')),
    placement_locality TEXT NOT NULL CHECK (placement_locality='local'),
    attempt_number INTEGER NOT NULL CHECK (attempt_number BETWEEN 1 AND 100),
    resource_count INTEGER NOT NULL CHECK (resource_count BETWEEN 1 AND 32),
    created_at TEXT NOT NULL,
    UNIQUE (task_id,semantic_program_hash,node_id,attempt_number),
    CHECK (length(candidate_id)>0 AND length(binding_id)>0 AND length(attempt_id)>0
       AND length(provider_trust_source_id)>0 AND length(execution_profile_ref)>0)
);
CREATE TABLE IF NOT EXISTS authority_candidate_resources (
    candidate_id TEXT NOT NULL REFERENCES authority_candidate_reservations(candidate_id),
    action TEXT NOT NULL,
    semantic_selector TEXT NOT NULL,
    resource_kind TEXT NOT NULL CHECK (resource_kind IN ('artifact','output-allocation')),
    resource_id TEXT NOT NULL,
    output_port TEXT,
    expected_semantic_type TEXT NOT NULL,
    PRIMARY KEY(candidate_id,action,semantic_selector),
    CHECK (length(resource_id)>0 AND length(action)>0 AND length(semantic_selector)>0),
    CHECK ((resource_kind='artifact' AND output_port IS NULL)
        OR (resource_kind='output-allocation' AND output_port IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_authority_candidate_output_identity
ON authority_candidate_resources(resource_id)
WHERE resource_kind='output-allocation';
CREATE TABLE IF NOT EXISTS authority_candidate_status (
    candidate_id TEXT PRIMARY KEY REFERENCES authority_candidate_reservations(candidate_id),
    revision INTEGER NOT NULL CHECK (revision>=1),
    state TEXT NOT NULL CHECK (state IN ('PENDING','FINALIZED','STALE','CANCELLED')),
    updated_at TEXT NOT NULL,
    CHECK (revision>1 OR state='PENDING')
);
-- OR REPLACE does not reliably fire DELETE triggers with recursive_triggers=OFF.
CREATE TRIGGER IF NOT EXISTS authority_candidate_reservation_no_duplicate_insert
BEFORE INSERT ON authority_candidate_reservations
WHEN EXISTS (SELECT 1 FROM authority_candidate_reservations c
    WHERE c.candidate_id=NEW.candidate_id OR c.binding_id=NEW.binding_id
       OR c.attempt_id=NEW.attempt_id
       OR (c.task_id=NEW.task_id AND c.semantic_program_hash=NEW.semantic_program_hash
           AND c.node_id=NEW.node_id AND c.attempt_number=NEW.attempt_number))
BEGIN SELECT RAISE(ABORT, 'authority candidate reservation already exists'); END;
CREATE TRIGGER IF NOT EXISTS authority_candidate_resource_no_duplicate_insert
BEFORE INSERT ON authority_candidate_resources
WHEN EXISTS (SELECT 1 FROM authority_candidate_resources r
    WHERE (r.candidate_id=NEW.candidate_id AND r.action=NEW.action
           AND r.semantic_selector=NEW.semantic_selector)
       OR (NEW.resource_kind='output-allocation' AND r.resource_kind='output-allocation'
           AND r.resource_id=NEW.resource_id))
BEGIN SELECT RAISE(ABORT, 'authority candidate resource already exists'); END;
CREATE TRIGGER IF NOT EXISTS authority_candidate_status_no_duplicate_insert
BEFORE INSERT ON authority_candidate_status
WHEN EXISTS (SELECT 1 FROM authority_candidate_status s WHERE s.candidate_id=NEW.candidate_id)
BEGIN SELECT RAISE(ABORT, 'authority candidate status already exists'); END;
CREATE TRIGGER IF NOT EXISTS authority_candidate_reservation_exact_insert
BEFORE INSERT ON authority_candidate_reservations
WHEN EXISTS (SELECT 1 FROM execution_bindings
             WHERE binding_id=NEW.binding_id OR attempt_id=NEW.attempt_id)
  OR EXISTS (SELECT 1 FROM step_executions WHERE attempt_id=NEW.attempt_id
             OR binding_id=NEW.binding_id
             OR (task_id=NEW.task_id AND semantic_program_hash=NEW.semantic_program_hash
                 AND node_id=NEW.node_id AND attempt_number=NEW.attempt_number))
BEGIN SELECT RAISE(ABORT, 'authority candidate identity already consumed'); END;
-- A reserved identity can be consumed only by the exact final immutable binding.
-- Existing binding admission guards still require policy/grant and provider receipts.
-- JSON1 checks here only compare candidate pins. The existing strict binding
-- receipt parser remains the authoritative validation on executable admission.
CREATE TRIGGER IF NOT EXISTS authority_candidate_binding_insert_guard
BEFORE INSERT ON execution_bindings
WHEN EXISTS (
    SELECT 1 FROM authority_candidate_reservations c
    LEFT JOIN authority_candidate_status s USING(candidate_id)
    WHERE (c.binding_id=NEW.binding_id OR c.attempt_id=NEW.attempt_id
       OR (c.task_id=NEW.task_id AND c.semantic_program_hash=NEW.semantic_program_hash
           AND c.node_id=NEW.node_id AND c.attempt_number=NEW.attempt))
    AND NOT COALESCE((s.state='PENDING' AND c.binding_id=NEW.binding_id AND c.attempt_id=NEW.attempt_id
       AND c.task_id=NEW.task_id AND c.semantic_program_hash=NEW.semantic_program_hash
       AND c.registry_snapshot_id=NEW.registry_snapshot_id AND c.ir_version=NEW.ir_version
       AND c.node_id=NEW.node_id AND c.capability=NEW.capability
       AND c.capability_contract_hash=NEW.capability_contract_hash
       AND c.provider_registration_id=NEW.provider_registration_id
       AND c.provider_id=NEW.provider_id AND c.provider_version=NEW.provider_version
       AND c.provider_manifest_hash=NEW.provider_manifest_hash
       AND c.provider_build_hash=NEW.provider_build_hash AND c.attempt_number=NEW.attempt
       AND c.execution_profile_ref=NEW.execution_profile_ref
       AND json_type(NEW.binding_json,'$.conformance_evidence_id')='text'
       AND json_extract(NEW.binding_json,'$.conformance_evidence_id')=c.conformance_evidence_id
       AND (SELECT COUNT(*) FROM json_each(NEW.binding_json)
            WHERE key='conformance_evidence_id')=1
       AND json_type(NEW.binding_json,'$.provider_trust_source_id')='text'
       AND json_extract(NEW.binding_json,'$.provider_trust_source_id')=c.provider_trust_source_id
       AND (SELECT COUNT(*) FROM json_each(NEW.binding_json)
            WHERE key='provider_trust_source_id')=1
       AND json_type(NEW.placement_json)='object'
       AND json_extract(NEW.placement_json,'$.locality')=c.placement_locality
       AND (SELECT COUNT(*) FROM json_each(NEW.placement_json))=1),0)
)
BEGIN SELECT RAISE(ABORT, 'execution binding collides with reserved authority candidate'); END;
-- An unbound or mismatched step may not steal an attempt ID or attempt tuple.
-- Finalization inserts the exact binding first, then its bound step, then CASes status.
CREATE TRIGGER IF NOT EXISTS authority_candidate_step_insert_guard
BEFORE INSERT ON step_executions
WHEN EXISTS (
    SELECT 1 FROM authority_candidate_reservations c
    LEFT JOIN authority_candidate_status s USING(candidate_id)
    WHERE (c.attempt_id=NEW.attempt_id OR c.binding_id=NEW.binding_id
       OR (c.task_id=NEW.task_id AND c.semantic_program_hash=NEW.semantic_program_hash
           AND c.node_id=NEW.node_id AND c.attempt_number=NEW.attempt_number))
    AND NOT COALESCE((s.state='PENDING' AND c.attempt_id=NEW.attempt_id
       AND c.binding_id=NEW.binding_id AND c.task_id=NEW.task_id
       AND c.semantic_program_hash=NEW.semantic_program_hash
       AND c.registry_snapshot_id=NEW.registry_snapshot_id AND c.node_id=NEW.node_id
       AND c.provider_id=NEW.provider_id AND c.provider_version=NEW.provider_version
       AND c.attempt_number=NEW.attempt_number
       AND NOT EXISTS (SELECT 1 FROM step_executions e
           WHERE e.attempt_id=NEW.attempt_id
              OR (e.task_id=NEW.task_id AND e.semantic_program_hash=NEW.semantic_program_hash
                  AND e.node_id=NEW.node_id AND e.attempt_number=NEW.attempt_number))
       AND EXISTS (SELECT 1 FROM execution_bindings b
           WHERE b.binding_id=c.binding_id AND b.attempt_id=c.attempt_id
             AND b.task_id=c.task_id AND b.semantic_program_hash=c.semantic_program_hash
             AND b.node_id=c.node_id AND b.attempt=c.attempt_number)),0)
)
BEGIN SELECT RAISE(ABORT, 'step execution collides with reserved authority candidate'); END;
CREATE TRIGGER IF NOT EXISTS authority_candidate_step_identity_update_guard
BEFORE UPDATE OF attempt_id,task_id,semantic_program_hash,registry_snapshot_id,node_id,
                 binding_id,provider_id,provider_version,attempt_number ON step_executions
WHEN (OLD.attempt_id IS NOT NEW.attempt_id OR OLD.task_id IS NOT NEW.task_id
   OR OLD.semantic_program_hash IS NOT NEW.semantic_program_hash
   OR OLD.registry_snapshot_id IS NOT NEW.registry_snapshot_id
   OR OLD.node_id IS NOT NEW.node_id OR OLD.binding_id IS NOT NEW.binding_id
   OR OLD.provider_id IS NOT NEW.provider_id OR OLD.provider_version IS NOT NEW.provider_version
   OR OLD.attempt_number IS NOT NEW.attempt_number)
 AND EXISTS (SELECT 1 FROM authority_candidate_reservations c
     WHERE c.attempt_id IN (OLD.attempt_id,NEW.attempt_id)
       OR c.binding_id IN (OLD.binding_id,NEW.binding_id)
       OR (c.task_id=NEW.task_id AND c.semantic_program_hash=NEW.semantic_program_hash
           AND c.node_id=NEW.node_id AND c.attempt_number=NEW.attempt_number)
       OR (c.task_id=OLD.task_id AND c.semantic_program_hash=OLD.semantic_program_hash
           AND c.node_id=OLD.node_id AND c.attempt_number=OLD.attempt_number))
BEGIN SELECT RAISE(ABORT, 'step update collides with reserved authority candidate'); END;
CREATE TRIGGER IF NOT EXISTS authority_candidate_step_no_delete
BEFORE DELETE ON step_executions
WHEN EXISTS (SELECT 1 FROM authority_candidate_reservations c
    WHERE c.attempt_id=OLD.attempt_id OR c.binding_id=OLD.binding_id
       OR (c.task_id=OLD.task_id AND c.semantic_program_hash=OLD.semantic_program_hash
           AND c.node_id=OLD.node_id AND c.attempt_number=OLD.attempt_number))
BEGIN SELECT RAISE(ABORT, 'reserved authority candidate step is durable'); END;
-- Only the eventual exact bound broker allocation may consume a reserved ID.
CREATE TRIGGER IF NOT EXISTS authority_candidate_allocation_insert_guard
BEFORE INSERT ON artifact_output_allocations
WHEN EXISTS (
    SELECT 1 FROM authority_candidate_resources r
    JOIN authority_candidate_reservations c USING(candidate_id)
    LEFT JOIN authority_candidate_status s USING(candidate_id)
    WHERE r.resource_kind='output-allocation' AND r.resource_id=NEW.allocation_id
      AND NOT COALESCE((s.state='PENDING' AND NEW.state='ALLOCATED'
        AND c.task_id=NEW.task_id AND c.semantic_program_hash=NEW.semantic_program_hash
        AND c.node_id=NEW.node_id AND c.binding_id=NEW.binding_id
        AND c.attempt_id=NEW.attempt_id AND r.output_port=NEW.output_port
        AND r.expected_semantic_type=NEW.expected_semantic_type
        AND NOT EXISTS (SELECT 1 FROM artifact_output_allocations a
            WHERE a.allocation_id=NEW.allocation_id)
        AND EXISTS (SELECT 1 FROM execution_bindings b
            WHERE b.binding_id=c.binding_id AND b.attempt_id=c.attempt_id)),0)
)
BEGIN SELECT RAISE(ABORT, 'output allocation collides with reserved authority candidate'); END;
CREATE TRIGGER IF NOT EXISTS authority_candidate_allocation_identity_update_guard
BEFORE UPDATE OF allocation_id,task_id,semantic_program_hash,node_id,binding_id,
                 attempt_id,output_port,expected_semantic_type ON artifact_output_allocations
WHEN (OLD.allocation_id IS NOT NEW.allocation_id OR OLD.task_id IS NOT NEW.task_id
   OR OLD.semantic_program_hash IS NOT NEW.semantic_program_hash
   OR OLD.node_id IS NOT NEW.node_id OR OLD.binding_id IS NOT NEW.binding_id
   OR OLD.attempt_id IS NOT NEW.attempt_id OR OLD.output_port IS NOT NEW.output_port
   OR OLD.expected_semantic_type IS NOT NEW.expected_semantic_type)
 AND EXISTS (SELECT 1 FROM authority_candidate_resources r
     WHERE r.resource_kind='output-allocation'
       AND r.resource_id IN (OLD.allocation_id,NEW.allocation_id))
BEGIN SELECT RAISE(ABORT, 'allocation update collides with reserved authority candidate'); END;
CREATE TRIGGER IF NOT EXISTS authority_candidate_allocation_no_delete
BEFORE DELETE ON artifact_output_allocations
WHEN EXISTS (SELECT 1 FROM authority_candidate_resources r
    WHERE r.resource_kind='output-allocation' AND r.resource_id=OLD.allocation_id)
BEGIN SELECT RAISE(ABORT, 'reserved authority candidate allocation is durable'); END;
CREATE TRIGGER IF NOT EXISTS authority_candidate_resource_exact_insert
BEFORE INSERT ON authority_candidate_resources
WHEN EXISTS (SELECT 1 FROM authority_candidate_status WHERE candidate_id=NEW.candidate_id)
  OR (NEW.resource_kind='output-allocation' AND EXISTS
      (SELECT 1 FROM artifact_output_allocations WHERE allocation_id=NEW.resource_id))
BEGIN SELECT RAISE(ABORT, 'authority candidate resource is not reservable'); END;
CREATE TRIGGER IF NOT EXISTS authority_candidate_status_exact_insert
BEFORE INSERT ON authority_candidate_status
WHEN NEW.revision<>1 OR NEW.state<>'PENDING' OR
     (SELECT COUNT(*) FROM authority_candidate_resources WHERE candidate_id=NEW.candidate_id)<>
     (SELECT resource_count FROM authority_candidate_reservations WHERE candidate_id=NEW.candidate_id)
BEGIN SELECT RAISE(ABORT, 'authority candidate resource set is incomplete'); END;
CREATE TRIGGER IF NOT EXISTS authority_candidate_status_cas_update
BEFORE UPDATE ON authority_candidate_status
WHEN NEW.candidate_id<>OLD.candidate_id OR OLD.state<>'PENDING'
  OR NEW.state NOT IN ('FINALIZED','STALE','CANCELLED')
  OR NEW.revision<>OLD.revision+1
  OR (NEW.state='FINALIZED' AND NOT EXISTS
      (SELECT 1 FROM execution_bindings b
       JOIN authority_candidate_reservations c ON c.candidate_id=OLD.candidate_id
       WHERE b.binding_id=c.binding_id AND b.attempt_id=c.attempt_id))
  OR (NEW.state='FINALIZED' AND NOT EXISTS
      (SELECT 1 FROM step_executions e
       JOIN authority_candidate_reservations c ON c.candidate_id=OLD.candidate_id
       WHERE e.attempt_id=c.attempt_id AND e.binding_id=c.binding_id
         AND e.task_id=c.task_id AND e.semantic_program_hash=c.semantic_program_hash
         AND e.registry_snapshot_id=c.registry_snapshot_id AND e.node_id=c.node_id
         AND e.provider_id=c.provider_id AND e.provider_version=c.provider_version
         AND e.attempt_number=c.attempt_number))
  OR (NEW.state='FINALIZED' AND EXISTS
      (SELECT 1 FROM authority_candidate_resources r
       JOIN authority_candidate_reservations c USING(candidate_id)
       WHERE c.candidate_id=OLD.candidate_id AND r.resource_kind='output-allocation'
         AND NOT EXISTS (SELECT 1 FROM artifact_output_allocations a
             WHERE a.allocation_id=r.resource_id AND a.state='ALLOCATED'
               AND a.task_id=c.task_id
               AND a.semantic_program_hash=c.semantic_program_hash AND a.node_id=c.node_id
               AND a.binding_id=c.binding_id AND a.attempt_id=c.attempt_id
               AND a.output_port=r.output_port
               AND a.expected_semantic_type=r.expected_semantic_type)))
BEGIN SELECT RAISE(ABORT, 'authority candidate status transition is invalid'); END;
CREATE TRIGGER IF NOT EXISTS authority_candidate_reservation_no_update
BEFORE UPDATE ON authority_candidate_reservations
BEGIN SELECT RAISE(ABORT, 'authority candidate reservation is immutable'); END;
CREATE TRIGGER IF NOT EXISTS authority_candidate_reservation_no_delete
BEFORE DELETE ON authority_candidate_reservations
BEGIN SELECT RAISE(ABORT, 'authority candidate reservation is immutable'); END;
CREATE TRIGGER IF NOT EXISTS authority_candidate_resource_no_update
BEFORE UPDATE ON authority_candidate_resources
BEGIN SELECT RAISE(ABORT, 'authority candidate resource is immutable'); END;
CREATE TRIGGER IF NOT EXISTS authority_candidate_resource_no_delete
BEFORE DELETE ON authority_candidate_resources
BEGIN SELECT RAISE(ABORT, 'authority candidate resource is immutable'); END;
CREATE TRIGGER IF NOT EXISTS authority_candidate_status_no_delete
BEFORE DELETE ON authority_candidate_status
BEGIN SELECT RAISE(ABORT, 'authority candidate status is durable'); END;
