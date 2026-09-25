//! Trusted host entry for the bounded local external-export profile.
//!
//! The host owns this object and the Task Manager writer lease. Provider code
//! receives only opaque execution handles; it cannot configure service
//! identities, adapters, or destination factories.

use super::{
    Actor, ArtifactExportWriter, ArtifactReader, CreateTask, ImportArtifactRequest,
    ProviderArtifactSession, Result, TaskManager, TaskManagerError, TaskMutation, TaskState,
    TransitionReason, TransitionRequest, WaitingKind, WaitingOn,
    artifact_store::ExactExportReplayIdentity,
    authority_candidate::{
        CandidateResourceChoice, CandidateResourceHandle, ReserveAuthorityCandidate,
        load_current_export_pin,
    },
    authority_policy::{AuthenticatedApprover, PolicyEffect},
    initial_program_admission::InitialProgramAdmissionRequest,
};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};

/// Process-local diagnostics for a service sink. Size and digest describe its
/// latest completed transfer; durable operation receipts remain authoritative.
/// No payload bytes or writer handle leave the coordinator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryExportObservation {
    pub opens: u64,
    pub finalizes: u64,
    pub completed_size_bytes: u64,
    pub completed_sha256: Option<String>,
}

#[derive(Default)]
struct MemorySinkState {
    opens: u64,
    finalizes: u64,
    completed_size_bytes: u64,
    completed_sha256: Option<String>,
}

struct MemoryExportWriter {
    state: Arc<Mutex<MemorySinkState>>,
    hasher: Sha256,
    size_bytes: u64,
    finalized: bool,
}

impl Write for MemoryExportWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.finalized {
            return Err(io::Error::other("memory export already finalized"));
        }
        self.size_bytes = self
            .size_bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| io::Error::other("memory export length overflow"))?;
        self.hasher.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl ArtifactExportWriter for MemoryExportWriter {
    fn finalize(&mut self) -> io::Result<()> {
        if self.finalized {
            return Err(io::Error::other("memory export already finalized"));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("memory sink poisoned"))?;
        let mut digest = String::from("sha256:");
        for byte in self.hasher.clone().finalize() {
            use std::fmt::Write as _;
            write!(&mut digest, "{byte:02x}").expect("string write");
        }
        state.completed_size_bytes = self.size_bytes;
        state.completed_sha256 = Some(digest);
        state.finalizes += 1;
        self.finalized = true;
        Ok(())
    }
}

struct RegisteredService {
    destination_class: String,
    adapter_id: String,
    sink: Arc<Mutex<MemorySinkState>>,
}

/// Trusted-host proposal for one local provider and one mediated export.
/// A provider never receives this type or a coordinator handle.
pub struct LocalExportProposal {
    pub task: CreateTask,
    pub constraints: serde_json::Value,
    pub admission_id: String,
    pub plan_id: String,
    pub plan_json: Vec<u8>,
    pub registry_snapshot_id: String,
    pub program_json: Vec<u8>,
    pub import: ImportArtifactRequest,
    pub candidate_id: String,
    pub binding_id: String,
    pub attempt_id: String,
    pub provider_registration_id: String,
    pub capability_contract_hash: String,
    pub node_id: String,
    pub source_selector: String,
    pub output_allocation_id: String,
    pub output_port: String,
    pub service_id: String,
    pub operation_id: String,
    pub purpose: String,
    pub max_size_bytes: u64,
}

/// Fresh identities for an unused attempt retired by trusted startup recovery.
pub struct RestartedLocalExportAttempt {
    pub candidate_id: String,
    pub binding_id: String,
    pub attempt_id: String,
    pub output_allocation_id: String,
    pub operation_id: String,
}

/// Opaque export prepared by the trusted coordinator.
#[derive(Clone)]
#[allow(
    clippy::struct_field_names,
    reason = "each opaque field names the exact identity it binds"
)]
pub struct PreparedLocalExport {
    issuer_id: String,
    task_id: String,
    candidate_id: String,
    binding_id: String,
    source_artifact_id: String,
    source_selector: String,
    destination_selector: String,
    service_id: String,
    operation_id: String,
    purpose: String,
    max_size_bytes: u64,
    approval_ids: Vec<String>,
}

/// Opaque session issued only after the trusted binding claim is admitted.
#[derive(Debug)]
pub struct AdmittedLocalArtifactRead {
    session: ProviderArtifactSession,
    source_artifact_id: String,
}

impl PreparedLocalExport {
    /// Returns the one-shot approval request ID for a trusted host UI.
    pub fn approval_id(&self) -> Option<&str> {
        self.approval_ids.first().map(String::as_str)
    }

    /// Returns every approval that must be decided before finalization.
    pub fn approval_ids(&self) -> &[String] {
        &self.approval_ids
    }

    /// Durable identity to persist before an export so its completed result
    /// can be reauthenticated after a process restart.
    pub fn replay_reference(&self) -> CompletedLocalExportReference {
        CompletedLocalExportReference {
            task_id: self.task_id.clone(),
            candidate_id: self.candidate_id.clone(),
            binding_id: self.binding_id.clone(),
            operation_id: self.operation_id.clone(),
            service_id: self.service_id.clone(),
            source_artifact_id: self.source_artifact_id.clone(),
            source_selector: self.source_selector.clone(),
            destination_selector: self.destination_selector.clone(),
            purpose: self.purpose.clone(),
            max_size_bytes: self.max_size_bytes,
        }
    }
}

/// Serializable historical lookup identity. It carries no execution authority:
/// every field is compared with the immutable candidate and export operation.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CompletedLocalExportReference {
    task_id: String,
    candidate_id: String,
    binding_id: String,
    operation_id: String,
    service_id: String,
    source_artifact_id: String,
    source_selector: String,
    destination_selector: String,
    purpose: String,
    max_size_bytes: u64,
}

/// Opaque active execution context. Every use still checks current grants.
pub struct LocalExportExecution {
    prepared: PreparedLocalExport,
}

/// Privileged host capability for local Task and mediated Artifact operations.
///
/// A provider must never receive this object or its underlying store. Store
/// ownership and the writer lease remain the trusted process boundary.
pub struct TrustedLocalCoordinator {
    manager: TaskManager,
    services: BTreeMap<String, RegisteredService>,
}

impl TrustedLocalCoordinator {
    /// Takes exclusive ownership of a Task Manager opened by the trusted host.
    /// Registry and provider evidence can be admitted through the manager's
    /// existing public store writers before this handoff.
    pub fn from_manager(manager: TaskManager) -> Self {
        Self {
            manager,
            services: BTreeMap::new(),
        }
    }

    /// Binds one exact service to a sealed in-memory sink before any export.
    ///
    /// # Errors
    /// Returns an error when service registration fails its identity or store checks.
    pub fn register_export_service(
        &mut self,
        service_id: &str,
        destination_class: &str,
        adapter_id: &str,
    ) -> Result<()> {
        // Never replace a live sink under an already-admitted service identity.
        if self.services.contains_key(service_id) {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        self.manager
            .register_trusted_export_service(service_id, destination_class, adapter_id)?;
        self.services.insert(
            service_id.to_owned(),
            RegisteredService {
                destination_class: destination_class.to_owned(),
                adapter_id: adapter_id.to_owned(),
                sink: Arc::new(Mutex::new(MemorySinkState::default())),
            },
        );
        Ok(())
    }

    /// Returns metadata about the sealed process-local sink, without exposing
    /// a byte stream that could be delivered over an unmediated network path.
    ///
    /// # Errors
    /// Returns an error for an unknown service or poisoned sink state.
    pub fn memory_export_observation(&self, service_id: &str) -> Result<MemoryExportObservation> {
        let service = self
            .services
            .get(service_id)
            .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?;
        let state = service
            .sink
            .lock()
            .map_err(|_| TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?;
        Ok(MemoryExportObservation {
            opens: state.opens,
            finalizes: state.finalizes,
            completed_size_bytes: state.completed_size_bytes,
            completed_sha256: state.completed_sha256.clone(),
        })
    }

    /// Withdraws a trusted service from future export use, including handles
    /// that were prepared before the withdrawal.
    ///
    /// # Errors
    /// Returns an error if the service is unknown or cannot be disabled.
    pub fn disable_export_service(&mut self, service_id: &str) -> Result<()> {
        if !self.services.contains_key(service_id) {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        self.manager.disable_trusted_export_service(service_id)
    }

    /// Activates one trusted host policy. Each activation has a distinct
    /// revision and invalidates approvals captured under an older revision.
    ///
    /// # Errors
    /// Returns an error when policy validation or activation fails.
    pub fn activate_policy(&mut self, raw: &[u8]) -> Result<i64> {
        self.manager.activate_local_authority_policy(raw)
    }

    /// Creates one Task, validates its raw program, imports its source, and
    /// evaluates a sealed candidate through the production coordinator paths.
    ///
    /// # Errors
    /// Returns an error if any admission or policy condition fails. A denied
    /// candidate never receives a grant or destination writer.
    #[allow(
        clippy::too_many_lines,
        reason = "keeps the bounded Task, program, source, and candidate path reviewable"
    )]
    pub fn prepare_local_export<R: Read>(
        &mut self,
        proposal: &LocalExportProposal,
        source: &mut R,
    ) -> Result<PreparedLocalExport> {
        let service = self
            .services
            .get(&proposal.service_id)
            .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?;
        if proposal.task.task_id != proposal.import.task_id
            || proposal.import.import_id.is_none()
            || proposal.task.active_step_ids != [proposal.node_id.as_str()]
            || !matches!(
                proposal
                    .constraints
                    .get("privacy")
                    .and_then(serde_json::Value::as_str),
                Some("local-first" | "remote-allowed")
            )
        {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        let destination_selector = format!("destination:{}", service.destination_class);
        if let Some(existing) = self.manager.get_task(&proposal.task.task_id)? {
            if existing.principal != proposal.task.principal
                || existing.workspace_id != proposal.task.workspace_id
                || existing.original_intent != proposal.task.original_intent
                || existing.normalized_intent != proposal.task.normalized_intent
                || existing.constraints.as_ref() != Some(&proposal.constraints)
                || !self.manager.verify_provenance(&proposal.task.task_id)?
            {
                return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
            }
        } else {
            self.manager
                .create_task_with_constraints(&proposal.task, Some(&proposal.constraints))?;
        }
        let admitted =
            self.manager
                .admit_initial_semantic_program(&InitialProgramAdmissionRequest {
                    transition_id: &proposal.admission_id,
                    task_id: &proposal.task.task_id,
                    expected_revision: 1,
                    plan_id: &proposal.plan_id,
                    plan_json: &proposal.plan_json,
                    registry_snapshot_id: &proposal.registry_snapshot_id,
                    program_json: &proposal.program_json,
                })?;
        if !admitted.applied {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        let imported = self.manager.import_artifact(&proposal.import, source)?;
        let task = self
            .manager
            .get_task(&proposal.task.task_id)?
            .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?;
        let hash = task
            .active_program
            .as_ref()
            .and_then(|program| program.get("semantic_hash"))
            .and_then(serde_json::Value::as_str)
            .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?;
        let resources = [
            CandidateResourceChoice {
                action: "artifact.read".into(),
                semantic_selector: proposal.source_selector.clone(),
                handle: CandidateResourceHandle::InputArtifact {
                    artifact_id: imported.artifact_id.clone(),
                },
            },
            CandidateResourceChoice {
                action: "artifact.write".into(),
                semantic_selector: "task.output".into(),
                handle: CandidateResourceHandle::OutputAllocation {
                    allocation_id: proposal.output_allocation_id.clone(),
                    output_port: proposal.output_port.clone(),
                },
            },
            CandidateResourceChoice {
                action: "data.egress".into(),
                semantic_selector: destination_selector,
                handle: CandidateResourceHandle::ExternalExport {
                    service_id: proposal.service_id.clone(),
                    source_artifact_id: imported.artifact_id.clone(),
                    operation_id: proposal.operation_id.clone(),
                    purpose: proposal.purpose.clone(),
                    max_size_bytes: proposal.max_size_bytes,
                },
            },
        ];
        self.manager
            .reserve_authority_candidate(&ReserveAuthorityCandidate {
                candidate_id: &proposal.candidate_id,
                binding_id: &proposal.binding_id,
                attempt_id: &proposal.attempt_id,
                task_id: &proposal.task.task_id,
                semantic_program_hash: hash,
                registry_snapshot_id: &proposal.registry_snapshot_id,
                node_id: &proposal.node_id,
                capability_contract_hash: &proposal.capability_contract_hash,
                provider_registration_id: &proposal.provider_registration_id,
                attempt_number: 1,
                resources: &resources,
            })?;
        let evaluation = self
            .manager
            .evaluate_pending_authority_candidate(&proposal.candidate_id)?;
        if evaluation
            .decisions
            .iter()
            .any(|decision| decision.effect == PolicyEffect::Deny)
        {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        let approval_ids: Vec<String> = evaluation
            .decisions
            .iter()
            .filter_map(|decision| decision.approval_id.clone())
            .collect();
        if !approval_ids.is_empty() {
            let waiting = self.manager.transition(&TransitionRequest {
                schema_version: "0.1".into(),
                transition_id: format!("transition:export-waiting:{}", proposal.candidate_id),
                task_id: proposal.task.task_id.clone(),
                expected_revision: 2,
                expected_state: TaskState::Planning,
                to_state: TaskState::WaitingForAuth,
                requested_by: Actor {
                    kind: "system-service".into(),
                    id: "aiosd.coordinator".into(),
                },
                reason: TransitionReason {
                    code: "APPROVAL_REQUIRED".into(),
                    message: None,
                    related_ids: approval_ids.clone(),
                },
                mutation: TaskMutation {
                    waiting_on: Some(
                        approval_ids
                            .iter()
                            .map(|id| WaitingOn {
                                kind: WaitingKind::Approval,
                                id: id.clone(),
                                message: None,
                            })
                            .collect(),
                    ),
                    ..TaskMutation::default()
                },
            })?;
            if !waiting.applied {
                return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
            }
        }
        Ok(PreparedLocalExport {
            issuer_id: self.manager.artifact_scope_issuer.clone(),
            task_id: proposal.task.task_id.clone(),
            candidate_id: proposal.candidate_id.clone(),
            binding_id: proposal.binding_id.clone(),
            source_artifact_id: imported.artifact_id,
            source_selector: proposal.source_selector.clone(),
            destination_selector: format!("destination:{}", service.destination_class),
            service_id: proposal.service_id.clone(),
            operation_id: proposal.operation_id.clone(),
            purpose: proposal.purpose.clone(),
            max_size_bytes: proposal.max_size_bytes,
            approval_ids,
        })
    }

    /// Returns the authoritative persisted structured prompt for this exact
    /// candidate after checking handle, approval membership, and Task owner.
    ///
    /// # Errors
    /// Returns an error if membership, owner, canonical prompt, or freshness fails.
    pub fn approval_prompt(
        &self,
        prepared: &PreparedLocalExport,
        approval_id: &str,
        authenticated_owner_id: &str,
    ) -> Result<serde_json::Value> {
        self.verify_approval_member(prepared, approval_id)?;
        self.manager.candidate_approval_prompt(
            approval_id,
            &prepared.candidate_id,
            &AuthenticatedApprover {
                principal_id: authenticated_owner_id,
            },
        )
    }

    /// Withdraws one prior approval. Its durable withdrawal marker fences
    /// finalization and every subsequent protected grant use.
    ///
    /// # Errors
    /// Returns an error if membership, owner, or withdrawal admission fails.
    pub fn withdraw_approval(
        &mut self,
        prepared: &PreparedLocalExport,
        approval_id: &str,
        authenticated_owner_id: &str,
    ) -> Result<()> {
        self.verify_approval_member(prepared, approval_id)?;
        self.manager.revoke_candidate_approval(
            approval_id,
            &AuthenticatedApprover {
                principal_id: authenticated_owner_id,
            },
        )
    }

    /// Records a decision by an owner already authenticated by the host.
    ///
    /// # Errors
    /// Returns an error for a foreign handle, stale approval, wrong owner, or
    /// a failed durable decision.
    pub fn decide_approval(
        &mut self,
        prepared: &PreparedLocalExport,
        authenticated_owner_id: &str,
        approve: bool,
    ) -> Result<()> {
        let [approval_id] = prepared.approval_ids.as_slice() else {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        };
        self.decide_approval_for(prepared, approval_id, authenticated_owner_id, approve)
    }

    /// Decides one specified approval from the prepared candidate.
    ///
    /// # Errors
    /// Returns an error if membership, owner, or decision admission fails.
    pub fn decide_approval_for(
        &mut self,
        prepared: &PreparedLocalExport,
        approval_id: &str,
        authenticated_owner_id: &str,
        approve: bool,
    ) -> Result<()> {
        self.verify_approval_member(prepared, approval_id)?;
        self.manager.decide_candidate_approval(
            approval_id,
            &AuthenticatedApprover {
                principal_id: authenticated_owner_id,
            },
            approve,
        )
    }

    /// Authenticated cancellation through the ordinary guarded Task CAS path.
    /// Unknown or possibly active effects keep cancellation from applying.
    ///
    /// # Errors
    /// Returns an error if the owner is wrong or guarded cancellation is refused.
    pub fn cancel_local_export(
        &mut self,
        prepared: &PreparedLocalExport,
        authenticated_owner_id: &str,
        transition_id: &str,
    ) -> Result<()> {
        self.verify_handle(prepared)?;
        self.cancel_task(&prepared.task_id, authenticated_owner_id, transition_id)
    }

    /// Cancels a durable Task by authenticated owner identity. This path does
    /// not depend on a process-local prepared handle surviving a restart.
    ///
    /// # Errors
    /// Returns an error if the Task or owner is invalid, or cancellation is unsafe.
    pub fn cancel_task(
        &mut self,
        task_id: &str,
        authenticated_owner_id: &str,
        transition_id: &str,
    ) -> Result<()> {
        if transition_id.is_empty() {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        let task = self
            .manager
            .get_task(task_id)?
            .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?;
        if task.principal.kind != "user"
            || task.principal.id != authenticated_owner_id
            || authenticated_owner_id.is_empty()
        {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        if task.state == TaskState::Cancelled {
            let same_request: bool = self.manager.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM task_transitions WHERE transition_id=?1
                 AND task_id=?2 AND to_state='CANCELLED' AND outcome='COMMITTED'
                 AND json_extract(request_json,'$.requested_by.kind')='user'
                 AND json_extract(request_json,'$.requested_by.id')=?3)",
                params![transition_id, task_id, authenticated_owner_id],
                |r| r.get(0),
            )?;
            if same_request && self.manager.verify_provenance(task_id)? {
                return Ok(());
            }
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        let result = self.manager.transition(&TransitionRequest {
            schema_version: "0.1".into(),
            transition_id: transition_id.into(),
            task_id: task_id.into(),
            expected_revision: task.revision,
            expected_state: task.state,
            to_state: TaskState::Cancelled,
            requested_by: task.principal,
            reason: TransitionReason {
                code: "USER_CANCELLED".into(),
                message: None,
                related_ids: vec![],
            },
            mutation: TaskMutation::default(),
        })?;
        if !result.applied {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        Ok(())
    }

    /// Finalizes exact grants and moves the prepared Task to runnable.
    ///
    /// # Errors
    /// Returns an error if approval, grant issuance, or either guarded Task
    /// transition is rejected. No execution handle is returned on failure.
    pub fn start_local_export(
        &mut self,
        prepared: &PreparedLocalExport,
    ) -> Result<LocalExportExecution> {
        self.verify_handle(prepared)?;
        let finalized = self
            .manager
            .finalize_pending_authority_candidate(&prepared.candidate_id)?;
        if finalized.binding_id != prepared.binding_id {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        let task = self
            .manager
            .get_task(&prepared.task_id)?
            .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?;
        if !matches!(
            task.state,
            TaskState::Planning
                | TaskState::WaitingForAuth
                | TaskState::Runnable
                | TaskState::Running
        ) {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        if matches!(task.state, TaskState::Planning | TaskState::WaitingForAuth) {
            let runnable = self.manager.transition(&TransitionRequest {
                schema_version: "0.1".into(),
                transition_id: format!("transition:export-runnable:{}", prepared.candidate_id),
                task_id: prepared.task_id.clone(),
                expected_revision: task.revision,
                expected_state: task.state,
                to_state: TaskState::Runnable,
                requested_by: Actor {
                    kind: "system-service".into(),
                    id: "aiosd.coordinator".into(),
                },
                reason: TransitionReason {
                    code: "AUTHORITY_READY".into(),
                    message: None,
                    related_ids: vec![],
                },
                mutation: TaskMutation {
                    waiting_on: Some(vec![]),
                    ..TaskMutation::default()
                },
            })?;
            if !runnable.applied {
                return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
            }
        }
        Ok(LocalExportExecution {
            prepared: prepared.clone(),
        })
    }

    /// Prepares a fresh attempt after startup retired an unused prior binding.
    /// The historical reference is authenticated against the finalized receipt;
    /// it carries no authority into the new clock session.
    ///
    /// # Errors
    /// Returns an error if the old receipt was not safely retired or current
    /// provider, resource, policy, and candidate admission fails.
    #[allow(
        clippy::too_many_lines,
        reason = "keeps historical replay authentication and fresh candidate admission together"
    )]
    pub fn prepare_restarted_local_export(
        &mut self,
        previous: &CompletedLocalExportReference,
        next: &RestartedLocalExportAttempt,
    ) -> Result<PreparedLocalExport> {
        // A restart reference is untrusted serialized data. Only an already
        // finalized receipt may be read here; finalizing a pending candidate
        // would create authority before the reference tuple is authenticated.
        let old = super::authority_policy::replay_finalized_candidate(
            &self.manager.connection,
            &previous.candidate_id,
        )?
        .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?;
        if old.binding_id != previous.binding_id {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        let pin = load_current_export_pin(&self.manager.connection, &previous.candidate_id)?
            .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?;
        if pin.service_id != previous.service_id
            || pin.operation_id != previous.operation_id
            || pin.source_artifact_id != previous.source_artifact_id
            || pin.selector != previous.destination_selector
            || pin.purpose != previous.purpose
            || pin.max_size_bytes != previous.max_size_bytes
        {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        let (task_id, snapshot, node, contract, registration, attempt_number, output_port): (
            String,
            String,
            String,
            String,
            String,
            i64,
            String,
        ) = self
            .manager
            .connection
            .query_row(
                "SELECT c.task_id,c.registry_snapshot_id,c.node_id,c.capability_contract_hash,
                    c.provider_registration_id,c.attempt_number,r.output_port
             FROM authority_candidate_reservations c
             JOIN authority_candidate_status s ON s.candidate_id=c.candidate_id
               AND s.state='FINALIZED'
             JOIN authority_candidate_resources r ON r.candidate_id=c.candidate_id
               AND r.action='artifact.write' AND r.semantic_selector='task.output'
             JOIN authority_candidate_resources source ON source.candidate_id=c.candidate_id
               AND source.action='artifact.read' AND source.semantic_selector=?4
               AND source.resource_id=?5
             WHERE c.candidate_id=?1 AND c.binding_id=?2 AND c.task_id=?3",
                params![
                    previous.candidate_id,
                    previous.binding_id,
                    previous.task_id,
                    previous.source_selector,
                    previous.source_artifact_id
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()?
            .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?;
        let task = self
            .manager
            .get_task(&task_id)?
            .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?;
        let old_step = self
            .manager
            .get_step_execution(&old.attempt_id)?
            .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?;
        let (grant_count, retired_count): (i64, i64) = self.manager.connection.query_row(
            "SELECT COUNT(*), COALESCE(SUM(CASE WHEN state='REVOKED'
                AND revocation_reason_code='AUTHORITY_SESSION_RETIRED'
                AND uses_consumed=0 THEN 1 ELSE 0 END),0)
             FROM authority_grants WHERE execution_binding_id=?1",
            [&previous.binding_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if task.state != TaskState::Planning
            || old_step.state != super::StepState::Ready
            || old_step.operation_id.is_some()
            || old_step.started_at.is_some()
            || old_step.outcome_certainty.is_some()
            || grant_count != i64::try_from(old.grant_ids.len()).unwrap_or(-1)
            || retired_count != grant_count
            || attempt_number >= 100
            || next.candidate_id == previous.candidate_id
            || next.binding_id == previous.binding_id
            || next.attempt_id == old.attempt_id
            || next.operation_id == previous.operation_id
        {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        let hash = task
            .active_program
            .as_ref()
            .and_then(|program| program.get("semantic_hash"))
            .and_then(serde_json::Value::as_str)
            .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?;
        let resources = [
            CandidateResourceChoice {
                action: "artifact.read".into(),
                semantic_selector: previous.source_selector.clone(),
                handle: CandidateResourceHandle::InputArtifact {
                    artifact_id: previous.source_artifact_id.clone(),
                },
            },
            CandidateResourceChoice {
                action: "artifact.write".into(),
                semantic_selector: "task.output".into(),
                handle: CandidateResourceHandle::OutputAllocation {
                    allocation_id: next.output_allocation_id.clone(),
                    output_port,
                },
            },
            CandidateResourceChoice {
                action: "data.egress".into(),
                semantic_selector: previous.destination_selector.clone(),
                handle: CandidateResourceHandle::ExternalExport {
                    service_id: previous.service_id.clone(),
                    source_artifact_id: previous.source_artifact_id.clone(),
                    operation_id: next.operation_id.clone(),
                    purpose: previous.purpose.clone(),
                    max_size_bytes: previous.max_size_bytes,
                },
            },
        ];
        self.manager
            .reserve_authority_candidate(&ReserveAuthorityCandidate {
                candidate_id: &next.candidate_id,
                binding_id: &next.binding_id,
                attempt_id: &next.attempt_id,
                task_id: &task_id,
                semantic_program_hash: hash,
                registry_snapshot_id: &snapshot,
                node_id: &node,
                capability_contract_hash: &contract,
                provider_registration_id: &registration,
                attempt_number: u32::try_from(attempt_number + 1)
                    .map_err(|_| TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?,
                resources: &resources,
            })?;
        let evaluation = self
            .manager
            .evaluate_pending_authority_candidate(&next.candidate_id)?;
        if evaluation
            .decisions
            .iter()
            .any(|decision| decision.effect != PolicyEffect::Allow)
        {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        Ok(PreparedLocalExport {
            issuer_id: self.manager.artifact_scope_issuer.clone(),
            task_id,
            candidate_id: next.candidate_id.clone(),
            binding_id: next.binding_id.clone(),
            source_artifact_id: previous.source_artifact_id.clone(),
            source_selector: previous.source_selector.clone(),
            destination_selector: previous.destination_selector.clone(),
            service_id: previous.service_id.clone(),
            operation_id: next.operation_id.clone(),
            purpose: previous.purpose.clone(),
            max_size_bytes: previous.max_size_bytes,
            approval_ids: vec![],
        })
    }

    /// Admits one genuine request under the current binding and returns the
    /// opaque session required for a protected Artifact read.
    ///
    /// # Errors
    /// Returns an error if the request or binding cannot be authenticated.
    pub fn admit_local_export_binding_claim(
        &self,
        prepared: &PreparedLocalExport,
        request_id: &str,
    ) -> Result<AdmittedLocalArtifactRead> {
        self.verify_handle(prepared)?;
        let session = self.manager.admit_provider_binding_request_claim(
            &prepared.task_id,
            &prepared.binding_id,
            request_id,
            &prepared.source_artifact_id,
        )?;
        Ok(AdmittedLocalArtifactRead {
            session,
            source_artifact_id: prepared.source_artifact_id.clone(),
        })
    }

    /// Uses the admitted binding session at the Artifact service's independent
    /// grant and resource check, returning a reader only after both admissions.
    ///
    /// # Errors
    /// Returns an error if the grant, binding, Artifact, or current Task state
    /// does not authorize a read.
    pub fn open_admitted_local_artifact(
        &mut self,
        admitted: &AdmittedLocalArtifactRead,
        grant_id: &str,
    ) -> Result<ArtifactReader> {
        let scope = self.manager.scope_execution_artifact_reads_with_claim(
            &admitted.session,
            std::slice::from_ref(&admitted.source_artifact_id),
            grant_id,
        )?;
        self.manager
            .open_artifact_reader(&scope, &admitted.source_artifact_id)
    }

    /// Transfers a pinned source into the sealed process-local memory sink.
    /// The caller cannot select a writer, destination class, or adapter identity.
    ///
    /// # Errors
    /// Returns an error if any current read/export grant, exact pin, deadline,
    /// callback, or durable completion check fails.
    #[allow(
        clippy::too_many_lines,
        reason = "preflight, guarded start, and exact no-effect retirement share this entry"
    )]
    pub fn export_local_artifact(&mut self, execution: &LocalExportExecution) -> Result<u64> {
        let prepared = &execution.prepared;
        self.verify_handle(prepared)?;
        let service = self
            .services
            .get(&prepared.service_id)
            .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?;
        let pin = load_current_export_pin(&self.manager.connection, &prepared.candidate_id)?
            .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?;
        if pin.service_id != prepared.service_id
            || pin.adapter_id != service.adapter_id
            || pin.source_artifact_id != prepared.source_artifact_id
            || pin.operation_id != prepared.operation_id
            || pin.purpose != prepared.purpose
            || pin.max_size_bytes != prepared.max_size_bytes
        {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        let sink_observer = Arc::clone(&service.sink);
        let sink = Arc::clone(&service.sink);
        let session = self
            .manager
            .issue_provider_artifact_session(&prepared.task_id, &prepared.binding_id)?;
        let scope = self
            .manager
            .scope_artifact_reads(&session, std::slice::from_ref(&prepared.source_artifact_id))?;
        let mut destination = self.manager.issue_exact_bound_artifact_export_destination(
            &session,
            &scope,
            &prepared.operation_id,
            &prepared.source_artifact_id,
            &prepared.service_id,
            &service.adapter_id,
            move || {
                let mut state = sink
                    .lock()
                    .map_err(|_| io::Error::other("memory sink poisoned"))?;
                state.opens += 1;
                drop(state);
                Ok(MemoryExportWriter {
                    state: sink,
                    hasher: Sha256::new(),
                    size_bytes: 0,
                    finalized: false,
                })
            },
        )?;
        let task = self
            .manager
            .get_task(&prepared.task_id)?
            .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?;
        if task.state == TaskState::Runnable {
            let running = self.manager.transition(&TransitionRequest {
                schema_version: "0.1".into(),
                transition_id: format!("transition:export-running:{}", prepared.candidate_id),
                task_id: prepared.task_id.clone(),
                expected_revision: task.revision,
                expected_state: TaskState::Runnable,
                to_state: TaskState::Running,
                requested_by: Actor {
                    kind: "system-service".into(),
                    id: "aiosd.coordinator".into(),
                },
                reason: TransitionReason {
                    code: "AUTHORITY_READY".into(),
                    message: None,
                    related_ids: vec![],
                },
                mutation: TaskMutation::default(),
            })?;
            if !running.applied {
                return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
            }
        } else if task.state != TaskState::Running {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        let opens_before = sink_observer
            .lock()
            .map_err(|_| TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?
            .opens;
        match self
            .manager
            .export_artifact(&scope, &prepared.source_artifact_id, &mut destination)
        {
            Ok(size) => Ok(size),
            Err(error) => {
                let operation: Option<(String, Option<String>)> = self.manager.connection.query_row(
                    "SELECT state,outcome_certainty FROM operations WHERE operation_id=?1 AND task_id=?2",
                    params![prepared.operation_id, prepared.task_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                ).optional()?;
                let authenticated_no_effect = match operation.as_ref() {
                    None => true,
                    Some((state, Some(certainty)))
                        if state == "FAILED" && certainty == "FAILED_NO_EFFECT" =>
                    {
                        matches!(
                            self.manager
                                .replay_bound_artifact_export(&session, &prepared.operation_id),
                            Err(TaskManagerError::InvalidRecord(
                                "ARTIFACT_EXPORT_FAILED_NO_EFFECT"
                            ))
                        )
                    }
                    _ => false,
                };
                if authenticated_no_effect {
                    self.retire_no_effect_export_attempt(
                        prepared,
                        &sink_observer,
                        opens_before,
                        operation.is_some(),
                    )?;
                }
                Err(error)
            }
        }
    }

    /// Retires only an exact attempt with authenticated no-effect evidence.
    /// An armed/unknown operation or any observed sink open is never cleaned up.
    fn retire_no_effect_export_attempt(
        &mut self,
        prepared: &PreparedLocalExport,
        sink: &Arc<Mutex<MemorySinkState>>,
        opens_before: u64,
        failed_operation_authenticated: bool,
    ) -> Result<()> {
        if sink
            .lock()
            .map_err(|_| TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?
            .opens
            != opens_before
        {
            return Ok(());
        }
        super::trusted_time::with_protected_immediate(
            &self.manager.connection,
            &self.manager.clock,
            |tx, now| {
                super::assert_manager_lease(
                    tx,
                    &self.manager.lease_owner,
                    self.manager.lease_epoch,
                )?;
                let attempt: Option<(String, String, Option<String>)> = tx
                    .query_row(
                        "SELECT c.attempt_id,e.state,e.outcome_certainty
                     FROM authority_candidate_reservations c
                     JOIN authority_candidate_status cs USING(candidate_id)
                     JOIN step_executions e ON e.attempt_id=c.attempt_id AND e.task_id=c.task_id
                        AND e.binding_id=c.binding_id
                     JOIN tasks t ON t.task_id=c.task_id
                     WHERE c.candidate_id=?1 AND c.task_id=?2 AND c.binding_id=?3
                       AND cs.state='FINALIZED' AND t.state='RUNNING'",
                        params![prepared.candidate_id, prepared.task_id, prepared.binding_id],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                    )
                    .optional()?;
                let Some((attempt_id, state, certainty)) = attempt else {
                    return Ok(());
                };
                if state != "RUNNING" || certainty.is_some() {
                    return Ok(());
                }
                let operation: Option<(String, Option<String>)> = tx
                    .query_row(
                        "SELECT state,outcome_certainty FROM operations
                     WHERE operation_id=?1 AND task_id=?2 AND attempt_id=?3",
                        params![prepared.operation_id, prepared.task_id, attempt_id],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
                let exact_no_effect = match operation.as_ref() {
                    None => !failed_operation_authenticated,
                    Some((state, Some(certainty))) => {
                        failed_operation_authenticated
                            && state == "FAILED"
                            && certainty == "FAILED_NO_EFFECT"
                    }
                    _ => false,
                };
                if !exact_no_effect {
                    return Ok(());
                }
                let other_effects: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM operations WHERE task_id=?1 AND attempt_id=?2 AND operation_id<>?3)
                        OR EXISTS(SELECT 1 FROM provider_invocations WHERE task_id=?1 AND attempt_id=?2)
                        OR EXISTS(SELECT 1 FROM credential_use_records WHERE task_id=?1)",
                    params![prepared.task_id, attempt_id, prepared.operation_id], |r| r.get(0))?;
                if other_effects {
                    return Ok(());
                }
                if tx.execute(
                    "UPDATE step_executions SET state='FAILED',outcome_certainty='FAILED_NO_EFFECT',
                     revision=revision+1,finished_at=?2,updated_at=?2
                     WHERE attempt_id=?1 AND state='RUNNING' AND outcome_certainty IS NULL",
                    params![attempt_id, now],
                )? != 1 { return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED")); }
                let mut event_id = String::from("event:export-no-effect:");
                for byte in Sha256::digest(attempt_id.as_bytes()) {
                    use std::fmt::Write as _;
                    write!(&mut event_id, "{byte:02x}").expect("string write");
                }
                super::append_event(
                    tx,
                    &prepared.task_id,
                    &serde_json::json!({
                        "schema_version":"0.1", "event_id":event_id,
                        "task_id":prepared.task_id,"event_type":"execution.failed",
                        "timestamp":now,"actor":{"kind":"system-service","id":"aiosd.coordinator"},
                        "status":"failure", "details":{"operation_id":prepared.operation_id,
                        "outcome_certainty":"FAILED_NO_EFFECT", "effect_boundary":"destination-not-invoked",
                            "reason_code":"ARTIFACT_EXPORT_FAILED_NO_EFFECT"}
                    }),
                )?;
                Ok(())
            },
        )
    }

    /// Returns the authenticated durable result of an already completed export.
    /// No current grant, artifact read, or destination writer is needed, so a
    /// lost response remains recoverable after the one-shot grant expires.
    ///
    /// # Errors
    /// Returns an error if the execution handle is foreign, the trusted
    /// service is no longer installed, or no matching completed operation exists.
    pub fn replay_local_artifact_export(&self, execution: &LocalExportExecution) -> Result<u64> {
        let prepared = &execution.prepared;
        self.verify_handle(prepared)?;
        if !self.services.contains_key(&prepared.service_id) {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        let session = self
            .manager
            .issue_provider_artifact_session(&prepared.task_id, &prepared.binding_id)?;
        self.manager
            .replay_bound_artifact_export(&session, &prepared.operation_id)
    }

    /// Replays a completed export after a trusted host restart from a saved
    /// reference. The immutable service descriptor and candidate pin are
    /// checked from the store; no adapter needs to be installed. This does
    /// not resurrect authority or accept an old in-memory execution handle.
    ///
    /// # Errors
    /// Returns an error for a changed candidate, service, operation, source
    /// or destination selector, purpose, ceiling, or unauthenticated result.
    pub fn replay_completed_local_export(
        &self,
        reference: &CompletedLocalExportReference,
    ) -> Result<u64> {
        let session = self
            .manager
            .issue_provider_artifact_session(&reference.task_id, &reference.binding_id)?;
        self.manager.replay_completed_exact_export(
            &session,
            &ExactExportReplayIdentity {
                candidate_id: &reference.candidate_id,
                operation_id: &reference.operation_id,
                service_id: &reference.service_id,
                source_artifact_id: &reference.source_artifact_id,
                source_selector: &reference.source_selector,
                destination_selector: &reference.destination_selector,
                purpose: &reference.purpose,
                max_size_bytes: reference.max_size_bytes,
            },
        )
    }

    fn verify_handle(&self, prepared: &PreparedLocalExport) -> Result<()> {
        if prepared.issuer_id != self.manager.artifact_scope_issuer {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        Ok(())
    }

    fn verify_approval_member(
        &self,
        prepared: &PreparedLocalExport,
        approval_id: &str,
    ) -> Result<()> {
        self.verify_handle(prepared)?;
        if !prepared.approval_ids.iter().any(|id| id == approval_id) {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Actor, CreateTask};
    use serde_json::json;

    #[test]
    fn trusted_task_constraints_are_part_of_genesis_and_reject_invalid_input() {
        let mut manager = TaskManager::open_in_memory().unwrap();
        let request = CreateTask {
            task_id: "T-coordinator-constraints".into(),
            principal: Actor {
                kind: "user".into(),
                id: "user:test".into(),
            },
            workspace_id: None,
            original_intent: "export source".into(),
            normalized_intent: None,
            active_step_ids: vec!["copy".into()],
        };
        let constraints = json!({"privacy":"remote-allowed","preserve_inputs":true});
        let created = manager
            .create_task_with_constraints(&request, Some(&constraints))
            .unwrap();
        assert_eq!(created.constraints, Some(constraints.clone()));
        assert!(manager.verify_provenance(&request.task_id).unwrap());
        let creation = manager.list_provenance(&request.task_id, None, 1).unwrap();
        assert_eq!(
            creation.records[0].event["details"]["creation"]["constraints"],
            constraints
        );

        for invalid in [
            json!({"privacy":"local-only","ambient_network":true}),
            json!({"privacy":"unknown"}),
            json!({"max_cost_microunits":-1}),
            json!({"deadline":"not-a-date"}),
        ] {
            let rejected = CreateTask {
                task_id: format!("T-invalid-constraints-{}", invalid.to_string().len()),
                ..request.clone()
            };
            assert!(
                manager
                    .create_task_with_constraints(&rejected, Some(&invalid))
                    .is_err()
            );
        }
    }
}

#[cfg(test)]
#[path = "coordinator_wrong_task_tests.rs"]
mod wrong_task_tests;
