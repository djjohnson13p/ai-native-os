//! Trusted host entry for the bounded local external-export profile.
//!
//! The host owns this object and the Task Manager writer lease. Provider code
//! receives only opaque execution handles; it cannot configure service
//! identities, adapters, or destination factories.

use super::{
    Actor, ArtifactExportWriter, CreateTask, ImportArtifactRequest, Result, TaskManager,
    TaskManagerError, TaskMutation, TaskState, TransitionReason, TransitionRequest, WaitingKind,
    WaitingOn,
    artifact_store::ExactExportReplayIdentity,
    authority_candidate::{
        CandidateResourceChoice, CandidateResourceHandle, ReserveAuthorityCandidate,
    },
    authority_policy::{AuthenticatedApprover, PolicyEffect},
    initial_program_admission::InitialProgramAdmissionRequest,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{self, Read};
use std::sync::Arc;

/// Host-supplied adapter for one registered exact export service.
///
/// The adapter is installed by the trusted host, not selected by a provider
/// request or supplied to an individual export operation.
pub trait TrustedExportAdapter: Send + Sync {
    /// Opens one destination writer after exact authority admission.
    ///
    /// # Errors
    /// Returns an I/O error when the destination cannot be opened.
    fn open(&self) -> io::Result<Box<dyn ArtifactExportWriter>>;
}

impl ArtifactExportWriter for Box<dyn ArtifactExportWriter> {
    fn finalize(&mut self) -> io::Result<()> {
        self.as_mut().finalize()
    }
}

struct RegisteredService {
    destination_class: String,
    adapter_id: String,
    adapter: Arc<dyn TrustedExportAdapter>,
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
    approval_id: Option<String>,
}

impl PreparedLocalExport {
    /// Returns the one-shot approval request ID for a trusted host UI.
    pub fn approval_id(&self) -> Option<&str> {
        self.approval_id.as_deref()
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

    /// Binds one exact service to its host-owned adapter before any export.
    ///
    /// # Errors
    /// Returns an error when service registration fails its identity or store checks.
    pub fn register_export_service(
        &mut self,
        service_id: &str,
        destination_class: &str,
        adapter_id: &str,
        adapter: Arc<dyn TrustedExportAdapter>,
    ) -> Result<()> {
        // An adapter ID is a trusted host assertion, not proof that two
        // factories are the same object. Never replace a live factory under
        // an already-admitted service identity.
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
                adapter,
            },
        );
        Ok(())
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
        let mut approvals = evaluation.decisions.iter().filter_map(|decision| {
            (decision.effect == PolicyEffect::RequireApproval)
                .then(|| decision.approval_id.clone())
                .flatten()
        });
        let approval_id = approvals.next();
        if approvals.next().is_some() {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        if let Some(approval_id) = &approval_id {
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
                    related_ids: vec![approval_id.clone()],
                },
                mutation: TaskMutation {
                    waiting_on: Some(vec![WaitingOn {
                        kind: WaitingKind::Approval,
                        id: approval_id.clone(),
                        message: None,
                    }]),
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
            approval_id,
        })
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
        self.verify_handle(prepared)?;
        let approval_id = prepared
            .approval_id
            .as_deref()
            .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?;
        self.manager.decide_candidate_approval(
            approval_id,
            &AuthenticatedApprover {
                principal_id: authenticated_owner_id,
            },
            approve,
        )
    }

    /// Finalizes exact grants and moves the prepared Task to running.
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
        if task.state != TaskState::Running {
            let runnable = self
                .manager
                .get_task(&prepared.task_id)?
                .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?;
            let running = self.manager.transition(&TransitionRequest {
                schema_version: "0.1".into(),
                transition_id: format!("transition:export-running:{}", prepared.candidate_id),
                task_id: prepared.task_id.clone(),
                expected_revision: runnable.revision,
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
        }
        Ok(LocalExportExecution {
            prepared: prepared.clone(),
        })
    }

    /// Transfers a pinned source to the host-configured adapter. The caller
    /// cannot select a writer factory, destination class, or adapter identity.
    ///
    /// # Errors
    /// Returns an error if any current read/export grant, exact pin, deadline,
    /// callback, or durable completion check fails.
    pub fn export_local_artifact(&mut self, execution: &LocalExportExecution) -> Result<u64> {
        let prepared = &execution.prepared;
        self.verify_handle(prepared)?;
        let service = self
            .services
            .get(&prepared.service_id)
            .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?;
        let adapter = Arc::clone(&service.adapter);
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
            move || adapter.open(),
        )?;
        self.manager
            .export_artifact(&scope, &prepared.source_artifact_id, &mut destination)
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
