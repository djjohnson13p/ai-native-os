//! Trusted replacement of an approval-blocked semantic program.

use super::{
    ActivePlan, Actor, ProgramAdmission, Result, TaskManager, TaskManagerError, TaskMutation,
    TaskState, TransitionReason, TransitionRequest, TransitionResult,
    active_program_validation_valid, canonical_json, load_admitted_semantic_registry,
    plan_program_coherent,
};
use crate::initial_program_admission::{
    raw_digest, single_node_id, strict_document, validate_plan,
};
use rusqlite::{OptionalExtension, Transaction, params};
use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub(crate) struct RevisedProgramAdmissionRequest<'a> {
    pub transition_id: &'a str,
    pub task_id: &'a str,
    pub expected_revision: u64,
    pub plan_id: &'a str,
    pub plan_json: &'a [u8],
    pub registry_snapshot_id: &'a str,
    pub program_json: &'a [u8],
}

pub(super) struct RevisedProgramAdmission {
    plan_json: String,
    registry_snapshot_id: String,
    program_json: String,
    program_digest: String,
    plan_digest: String,
}

fn reject() -> TaskManagerError {
    TaskManagerError::InvalidRecord("revised semantic program admission is not admissible")
}

impl TaskManager {
    /// Trusted-host entry for a new program after an approval-blocked plan.
    /// Raw IR and the currently admitted registry determine validity in the
    /// transition transaction; callers cannot supply validation or hashes.
    pub(crate) fn admit_revised_semantic_program(
        &mut self,
        input: &RevisedProgramAdmissionRequest<'_>,
    ) -> Result<TransitionResult> {
        self.admit_revised_semantic_program_impl(input, false)
    }

    fn admit_revised_semantic_program_impl(
        &mut self,
        input: &RevisedProgramAdmissionRequest<'_>,
        fail_provenance: bool,
    ) -> Result<TransitionResult> {
        let plan = strict_document(input.plan_json)?;
        let program = strict_document(input.program_json)?;
        let node = single_node_id(&program)?;
        let plan_revision = plan
            .get("revision")
            .and_then(Value::as_u64)
            .ok_or_else(reject)?;
        if plan_revision < 2 {
            return Err(reject());
        }
        validate_plan(
            &plan,
            input.task_id,
            input.plan_id,
            &program,
            &node,
            plan_revision,
        )?;
        let admission = RevisedProgramAdmission {
            plan_json: std::str::from_utf8(input.plan_json)
                .map_err(|_| reject())?
                .to_owned(),
            registry_snapshot_id: input.registry_snapshot_id.to_owned(),
            program_json: std::str::from_utf8(input.program_json)
                .map_err(|_| reject())?
                .to_owned(),
            program_digest: raw_digest(b"AIOS-REVISED-PROGRAM-RAW\0v1\0", input.program_json),
            plan_digest: raw_digest(b"AIOS-REVISED-PLAN-RAW\0v1\0", input.plan_json),
        };
        let request = TransitionRequest {
            schema_version: "0.1".into(),
            transition_id: input.transition_id.to_owned(),
            task_id: input.task_id.to_owned(),
            expected_revision: input.expected_revision,
            expected_state: TaskState::WaitingForAuth,
            to_state: TaskState::Planning,
            requested_by: Actor {
                kind: "system-service".into(),
                id: "aiosd.coordinator".into(),
            },
            reason: TransitionReason {
                code: "PROGRAM_REVISED".into(),
                message: None,
                related_ids: vec![
                    format!("program-raw:{}", admission.program_digest),
                    format!("plan-raw:{}", admission.plan_digest),
                    format!("registry:{}", admission.registry_snapshot_id),
                ],
            },
            mutation: TaskMutation {
                active_plan: Some(ActivePlan {
                    plan_id: input.plan_id.to_owned(),
                    revision: plan_revision,
                }),
                active_step_ids: Some(vec![node]),
                waiting_on: Some(Vec::new()),
                ..TaskMutation::default()
            },
        };
        self.transition_impl(
            &request,
            fail_provenance,
            false,
            Some(ProgramAdmission::Revised(&admission)),
        )
    }

    #[cfg(test)]
    pub(super) fn admit_revised_semantic_program_with_provenance_failure(
        &mut self,
        input: &RevisedProgramAdmissionRequest<'_>,
    ) -> Result<TransitionResult> {
        self.admit_revised_semantic_program_impl(input, true)
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "keeps validation, supersession, candidate retirement, and pointer CAS in one transaction"
)]
pub(super) fn persist_revised_program_admission_in(
    tx: &Transaction<'_>,
    request: &TransitionRequest,
    admission: &RevisedProgramAdmission,
    committed_at: &str,
) -> Result<i64> {
    let plan = strict_document(admission.plan_json.as_bytes())?;
    let program = strict_document(admission.program_json.as_bytes())?;
    let node = single_node_id(&program)?;
    let active_plan = request.mutation.active_plan.as_ref().ok_or_else(reject)?;
    if request.expected_state != TaskState::WaitingForAuth
        || request.to_state != TaskState::Planning
        || request.reason.code != "PROGRAM_REVISED"
        || request.reason.related_ids
            != [
                format!("program-raw:{}", admission.program_digest),
                format!("plan-raw:{}", admission.plan_digest),
                format!("registry:{}", admission.registry_snapshot_id),
            ]
        || request.mutation.waiting_on.as_deref() != Some(&[])
        || request.mutation.active_step_ids.as_deref() != Some(&[node.clone()])
    {
        return Err(reject());
    }
    validate_plan(
        &plan,
        &request.task_id,
        &active_plan.plan_id,
        &program,
        &node,
        active_plan.revision,
    )?;
    let (old_program, old_plan, old_hash): (i64, i64, String) = tx
        .query_row(
            "SELECT t.active_program_revision,t.active_plan_revision,p.semantic_hash
         FROM tasks t JOIN semantic_program_revisions p ON p.task_id=t.task_id
           AND p.program_revision=t.active_program_revision AND p.status='active'
           AND p.superseded_at IS NULL
         JOIN plan_revisions r ON r.task_id=t.task_id AND r.plan_revision=t.active_plan_revision
           AND r.superseded_at IS NULL AND p.created_from_plan_revision=r.plan_revision
         WHERE t.task_id=?1 AND t.state='WAITING_FOR_AUTH' AND t.revision=?2",
            params![
                request.task_id,
                i64::try_from(request.expected_revision).map_err(|_| reject())?
            ],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?
        .ok_or_else(reject)?;
    if !active_program_validation_valid(tx, &request.task_id, &old_hash)?
        || !plan_program_coherent(tx, &request.task_id, Some(old_program), None)?
    {
        return Err(reject());
    }
    // This profile admits only a non-executable pending preparation. A
    // completed unbound source import is allowed and is not in these tables.
    for table in [
        "execution_bindings",
        "authority_grants",
        "step_executions",
        "provider_invocations",
        "credential_use_records",
        "artifact_output_allocations",
    ] {
        let count: i64 = tx.query_row(
            &format!("SELECT COUNT(*) FROM {table} WHERE task_id=?1"),
            [&request.task_id],
            |r| r.get(0),
        )?;
        if count != 0 {
            return Err(reject());
        }
    }
    if !super::artifact_store::authenticated_unbound_import_operations(tx, &request.task_id)? {
        return Err(reject());
    }
    let current: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM semantic_current_usable_snapshots WHERE snapshot_id=?1 AND state='ADMITTED')",
        [&admission.registry_snapshot_id], |r| r.get(0),
    )?;
    if !current {
        return Err(reject());
    }
    let registry =
        load_admitted_semantic_registry(tx, &admission.registry_snapshot_id)?.ok_or_else(reject)?;
    let validated_at = OffsetDateTime::parse(committed_at, &Rfc3339).map_err(|_| reject())?;
    let report = aios_ir::Validator::new(registry, aios_ir::ValidationLimits::default())
        .validate_bytes_at(admission.program_json.as_bytes(), validated_at);
    let validation = report.output.validation;
    let hash = validation
        .semantic_hash
        .as_deref()
        .filter(|_| validation.valid)
        .ok_or_else(reject)?;
    if hash == old_hash
        || validation.registry_snapshot_id.as_deref() != Some(&admission.registry_snapshot_id)
        || validation.program_id.is_none()
        || validation.ir_version.as_deref() != Some("0.1")
    {
        return Err(reject());
    }
    let next_plan: i64 = tx.query_row(
        "SELECT COALESCE(MAX(plan_revision),0)+1 FROM plan_revisions WHERE task_id=?1",
        [&request.task_id],
        |r| r.get(0),
    )?;
    let next_program: i64 = tx.query_row(
        "SELECT COALESCE(MAX(program_revision),0)+1 FROM semantic_program_revisions WHERE task_id=?1",
        [&request.task_id], |r| r.get(0),
    )?;
    if next_plan != old_plan + 1
        || next_program != old_program + 1
        || i64::try_from(active_plan.revision).map_err(|_| reject())? != next_plan
    {
        return Err(reject());
    }
    // The status trigger enforces each PENDING -> STALE, revision+1 CAS.
    tx.execute(
        "UPDATE authority_candidate_status SET state='STALE',revision=revision+1,updated_at=?2
         WHERE candidate_id IN (SELECT candidate_id FROM authority_candidate_reservations
           WHERE task_id=?1) AND state='PENDING'",
        params![request.task_id, committed_at],
    )?;
    // Pending prompts belonging to retired candidates must not become live
    // blockers if a later program returns to the same semantic hash. Preserve
    // approved requests and their decisions for denial-only history checks.
    tx.execute(
        "UPDATE approval_requests SET status='STALE' WHERE task_id=?1 AND status='PENDING'
         AND approval_id IN (SELECT b.approval_id FROM authority_approval_bindings b
           JOIN authority_candidate_reservations c ON c.candidate_id=b.candidate_id
           JOIN authority_candidate_status s ON s.candidate_id=c.candidate_id
           WHERE c.task_id=?1 AND s.state='STALE')",
        [&request.task_id],
    )?;
    if tx.execute(
        "UPDATE semantic_program_revisions SET status='superseded',superseded_at=?3,
            superseded_reason='PROGRAM_REVISED' WHERE task_id=?1 AND program_revision=?2
            AND status='active' AND superseded_at IS NULL",
        params![request.task_id, old_program, committed_at],
    )? != 1
    {
        return Err(reject());
    }
    if tx.execute(
        "UPDATE plan_revisions SET superseded_at=?3 WHERE task_id=?1 AND plan_revision=?2
            AND superseded_at IS NULL",
        params![request.task_id, old_plan, committed_at],
    )? != 1
    {
        return Err(reject());
    }
    let validation_id = format!(
        "validation:{}",
        raw_digest(
            b"AIOS-REVISED-VALIDATION-ID\0v1\0",
            request.transition_id.as_bytes()
        )
    );
    let result_json = canonical_json(&validation)?;
    tx.execute(
        "INSERT INTO plan_revisions(task_id,plan_revision,plan_id,plan_json,created_at)
         VALUES (?1,?2,?3,?4,?5)",
        params![
            request.task_id,
            next_plan,
            active_plan.plan_id,
            admission.plan_json,
            committed_at
        ],
    )?;
    tx.execute(
        "INSERT INTO validation_results(validation_result_id,task_id,program_id,ir_version,
         valid,semantic_hash,registry_snapshot_id,validator_id,validator_version,
         validator_build_hash,result_json,validated_at)
         VALUES (?1,?2,?3,'0.1',1,?4,?5,?6,?7,?8,?9,?10)",
        params![
            validation_id,
            request.task_id,
            validation.program_id,
            hash,
            admission.registry_snapshot_id,
            validation.validator.id,
            validation.validator.version,
            validation.validator.build_hash,
            result_json,
            validation.validated_at
        ],
    )?;
    tx.execute(
        "INSERT INTO semantic_program_revisions(task_id,program_revision,program_id,ir_version,
         semantic_hash,registry_snapshot_id,validation_result_id,status,program_json,
         created_from_plan_revision,created_at)
         VALUES (?1,?2,?3,'0.1',?4,?5,?6,'active',?7,?8,?9)",
        params![
            request.task_id,
            next_program,
            validation.program_id,
            hash,
            admission.registry_snapshot_id,
            validation_id,
            admission.program_json,
            next_plan,
            committed_at
        ],
    )?;
    if tx.execute(
        "UPDATE tasks SET active_program_revision=?2 WHERE task_id=?1
         AND revision=?3 AND state='WAITING_FOR_AUTH' AND active_program_revision=?4
         AND active_plan_revision=?5",
        params![
            request.task_id,
            next_program,
            i64::try_from(request.expected_revision).map_err(|_| reject())?,
            old_program,
            old_plan
        ],
    )? != 1
    {
        return Err(reject());
    }
    Ok(next_program)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ArtifactOriginKind, CreateTask, ImportArtifactRequest, RetentionClass, Sensitivity,
        WaitingKind, WaitingOn,
        authority_candidate::{
            CandidateResourceChoice, CandidateResourceHandle, ReserveAuthorityCandidate,
        },
        authority_policy::{AuthenticatedApprover, PolicyEffect},
        trusted_time::{SecurityClockSample, synthetic_sample},
    };
    use aios_contracts::{CapabilityContract, ContractRef, RegistrySnapshot, TypeContract};
    use aios_registry::{
        ProviderTrustStatus, RegistryBuildOptions, SemanticRegistry, SnapshotHashEntry,
    };
    use serde_json::json;
    use std::path::Path;
    use tempfile::tempdir;

    const NOW: &str = "2026-09-19T00:00:00Z";
    const SUITE: &str = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
    const BUILD: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    struct FixedClock;
    impl crate::Clock for FixedClock {
        fn now(&self) -> String {
            NOW.into()
        }
        fn security_sample(&self) -> Option<SecurityClockSample> {
            Some(synthetic_sample(self.now()))
        }
    }

    fn program(label: &str) -> Vec<u8> {
        json!({"ir_version":"0.1","program_id":format!("program:{label}"),"kind":"task_graph",
            "inputs":{"source":{"type":"artifact.file@1"}},
            "nodes":[{"id":"copy","operation":{"kind":"invoke","capability":"artifact.copy@1"},
                "execution_class":"deterministic","inputs":{"source":{"source":"input","name":"source"}},
                "outputs":{"copy":"artifact.file@1"},"authority_requests":[
                    {"action":"artifact.read","resource":"input:source"},
                    {"action":"artifact.write","resource":"task.output"}],
                "egress":{"mode":"deny"},"failure":{"on_error":"stop"},
                "cache":if label == "B" {"deterministic_only"} else {"never"}}],
            "outputs":{"copy":{"source":"node","node":"copy","port":"copy"}}}).to_string().into_bytes()
    }

    fn plan(label: &str, revision: u64) -> Vec<u8> {
        json!({"schema_version":"0.1","plan_id":format!("plan:{label}"),"task_id":"T-revised",
            "revision":revision,"intent":"copy the source",
            "nodes":[{"id":"copy","capability":"artifact.copy","capability_version":"1",
                "depends_on":[],"inputs":[{"name":"source","ref":"input:source","type":"artifact.file@1"}],
                "outputs":[{"name":"copy","type":"artifact.file@1"}]}]}).to_string().into_bytes()
    }

    struct Fixture {
        manager: TaskManager,
        snapshot: String,
        registration: String,
        contract: String,
        source: String,
        initial_hash: String,
        approval: String,
    }

    #[allow(
        clippy::too_many_lines,
        reason = "constructs a real validated Task, provider, source, candidate, and approval wait"
    )]
    fn fixture(path: &Path) -> Fixture {
        let mut manager = TaskManager::open_with_clock(path, Box::new(FixedClock)).unwrap();
        manager
            .create_task(&CreateTask {
                task_id: "T-revised".into(),
                principal: Actor {
                    kind: "user".into(),
                    id: "user:test".into(),
                },
                workspace_id: None,
                original_intent: "copy the source".into(),
                normalized_intent: None,
                active_step_ids: vec![],
            })
            .unwrap();
        let mut snapshot: RegistrySnapshot = serde_json::from_str(include_str!(
            "../../../examples/aios-ir/registry-snapshot.json"
        ))
        .unwrap();
        let types: Vec<TypeContract> = serde_json::from_str(include_str!(
            "../../../examples/aios-ir/type-contracts.json"
        ))
        .unwrap();
        let mut contracts: Vec<CapabilityContract> = serde_json::from_str(include_str!(
            "../../../examples/aios-ir/capability-contracts.json"
        ))
        .unwrap();
        let copy = contracts
            .iter_mut()
            .find(|c| c.capability == "artifact.copy")
            .unwrap();
        copy.conformance.suite_hash = Some(SUITE.into());
        let contract = aios_registry::capability_contract_hash(copy)
            .unwrap()
            .to_string();
        snapshot
            .capability_contracts
            .iter_mut()
            .find(|e| e.id == "artifact.copy")
            .unwrap()
            .content_hash
            .clone_from(&contract);
        let entry = |e: &ContractRef| SnapshotHashEntry {
            id: e.id.clone(),
            version: e.version.clone(),
            content_hash: e.content_hash.clone(),
        };
        snapshot.snapshot_id = aios_registry::registry_snapshot_id(
            &snapshot.schema_version,
            &snapshot
                .type_contracts
                .iter()
                .map(entry)
                .collect::<Vec<_>>(),
            &snapshot
                .capability_contracts
                .iter()
                .map(entry)
                .collect::<Vec<_>>(),
        )
        .unwrap()
        .to_string();
        let registry = SemanticRegistry::from_records(
            snapshot,
            types,
            contracts,
            RegistryBuildOptions::default(),
        )
        .unwrap();
        let snapshot = manager
            .registry_store_writer()
            .unwrap()
            .admit_registry(&registry)
            .unwrap();
        let cases: Value = serde_json::from_str(include_str!(
            "../../../examples/aios-ir/provider-conformance-cases.json"
        ))
        .unwrap();
        let mut manifest = cases[0]["provider"].clone();
        manifest["provides"][0]["contract"]["capability"] = json!("artifact.copy");
        manifest["provides"][0]["contract"]["contract_hash"] = json!(contract);
        manifest["provides"][0]["conformance"]["suite"] = json!("conformance://artifact.copy/1");
        manifest["provides"][0]["conformance"]["suite_hash"] = json!(SUITE);
        manifest["provides"][0]["effect_classes"] = json!(["ARTIFACT_READ", "ARTIFACT_WRITE"]);
        manifest["provides"][0]["authority"]["actions"] =
            json!(["artifact.read", "artifact.write"]);
        let registration = manager
            .provider_store_writer()
            .unwrap()
            .register(
                &registry,
                &serde_json::to_vec(&manifest).unwrap(),
                BUILD,
                ProviderTrustStatus::LocallyTrusted,
                NOW,
            )
            .unwrap();
        let evidence = json!({"schema_version":"0.1","result_id":"evidence:revised",
            "provider_id":registration.provider_id,"provider_version":registration.provider_version,
            "provider_build_identity":{"kind":"build_hash","value":BUILD},
            "semantic_capability_ref":"artifact.copy@1","semantic_contract_version":"1.0",
            "semantic_contract_hash":contract,"conformance_suite":{"id":"conformance://artifact.copy/1","version":"0.1","hash":SUITE},
            "harness":{"id":"fixture-harness","version":"1"},"result":"pass",
            "tests_total":1,"tests_passed":1,"tests_failed":0,"executed_at":NOW,"expires_at":"2026-09-20T00:00:00Z"});
        manager
            .provider_store_writer()
            .unwrap()
            .record_evidence(
                &registration.registration_id,
                &serde_json::to_vec(&evidence).unwrap(),
            )
            .unwrap();
        manager
            .provider_store_writer()
            .unwrap()
            .enable(&registration.registration_id, NOW)
            .unwrap();
        let initial_program = program("A");
        let initial_plan = plan("A", 1);
        let admitted = manager
            .admit_initial_semantic_program(
                &crate::initial_program_admission::InitialProgramAdmissionRequest {
                    transition_id: "transition:initial-revised-test",
                    task_id: "T-revised",
                    expected_revision: 1,
                    plan_id: "plan:A",
                    plan_json: &initial_plan,
                    registry_snapshot_id: &snapshot,
                    program_json: &initial_program,
                },
            )
            .unwrap();
        assert!(admitted.applied);
        let initial_hash = manager
            .get_task("T-revised")
            .unwrap()
            .unwrap()
            .active_program
            .unwrap()["semantic_hash"]
            .as_str()
            .unwrap()
            .to_owned();
        let source = manager
            .import_artifact(
                &ImportArtifactRequest {
                    schema_version: "0.1".into(),
                    import_id: Some("import:revised".into()),
                    task_id: "T-revised".into(),
                    origin_kind: ArtifactOriginKind::User,
                    semantic_type: Some("artifact.file@1".into()),
                    media_type: "text/plain".into(),
                    format: None,
                    sensitivity: Sensitivity::Local,
                    retention: RetentionClass::Task,
                    expires_at: None,
                    labels: vec![],
                    max_size_bytes: Some(1024),
                },
                &mut std::io::Cursor::new(b"source bytes"),
            )
            .unwrap()
            .artifact_id;
        let resources = [
            CandidateResourceChoice {
                action: "artifact.read".into(),
                semantic_selector: "input:source".into(),
                handle: CandidateResourceHandle::InputArtifact {
                    artifact_id: source.clone(),
                },
            },
            CandidateResourceChoice {
                action: "artifact.write".into(),
                semantic_selector: "task.output".into(),
                handle: CandidateResourceHandle::OutputAllocation {
                    allocation_id: "allocation:A".into(),
                    output_port: "copy".into(),
                },
            },
        ];
        manager
            .reserve_authority_candidate(&ReserveAuthorityCandidate {
                candidate_id: "candidate:A",
                binding_id: "binding:A",
                attempt_id: "attempt:A",
                task_id: "T-revised",
                semantic_program_hash: &initial_hash,
                registry_snapshot_id: &snapshot,
                node_id: "copy",
                capability_contract_hash: &contract,
                provider_registration_id: &registration.registration_id,
                attempt_number: 1,
                resources: &resources,
            })
            .unwrap();
        manager.activate_local_authority_policy(json!({"schema_version":"0.1","rules":[
            {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"local"},
            {"effect":"REQUIRE_APPROVAL","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"}
        ]}).to_string().as_bytes()).unwrap();
        let evaluated = manager
            .evaluate_pending_authority_candidate("candidate:A")
            .unwrap();
        assert_eq!(
            evaluated.decisions[1].effect,
            PolicyEffect::RequireApproval,
            "{evaluated:?}"
        );
        let approval = evaluated.decisions[1].approval_id.clone().unwrap();
        let waiting = manager
            .transition(&TransitionRequest {
                schema_version: "0.1".into(),
                transition_id: "transition:wait-A".into(),
                task_id: "T-revised".into(),
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
                    related_ids: vec![approval.clone()],
                },
                mutation: TaskMutation {
                    waiting_on: Some(vec![WaitingOn {
                        kind: WaitingKind::Approval,
                        id: approval.clone(),
                        message: None,
                    }]),
                    ..TaskMutation::default()
                },
            })
            .unwrap();
        assert!(waiting.applied, "{waiting:?}");
        Fixture {
            manager,
            snapshot,
            registration: registration.registration_id,
            contract,
            source,
            initial_hash,
            approval,
        }
    }

    fn request<'a>(
        plan_json: &'a [u8],
        program_json: &'a [u8],
        snapshot: &'a str,
        transition_id: &'a str,
        plan_id: &'a str,
        expected_revision: u64,
    ) -> RevisedProgramAdmissionRequest<'a> {
        RevisedProgramAdmissionRequest {
            transition_id,
            task_id: "T-revised",
            expected_revision,
            plan_id,
            plan_json,
            registry_snapshot_id: snapshot,
            program_json,
        }
    }

    fn status(manager: &TaskManager, candidate: &str) -> (String, i64) {
        manager
            .connection
            .query_row(
                "SELECT state,revision FROM authority_candidate_status WHERE candidate_id=?1",
                [candidate],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap()
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "captures complete finalized authority before and after a denied revision"
    )]
    fn revised_admission_rejects_existing_finalized_authority_without_mutation() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("finalized-authority.sqlite3");
        let mut f = fixture(&path);
        f.manager
            .decide_candidate_approval(
                &f.approval,
                &AuthenticatedApprover {
                    principal_id: "user:test",
                },
                true,
            )
            .unwrap();
        f.manager
            .finalize_pending_authority_candidate("candidate:A")
            .unwrap();
        let before_task = f.manager.get_task("T-revised").unwrap().unwrap();
        assert_eq!(before_task.state, TaskState::WaitingForAuth);
        let before_candidate = status(&f.manager, "candidate:A");
        let before_approval: String = f
            .manager
            .connection
            .query_row(
                "SELECT status FROM approval_requests WHERE approval_id=?1",
                [&f.approval],
                |row| row.get(0),
            )
            .unwrap();
        let counts = |manager: &TaskManager| -> (i64, i64, i64, i64, i64, i64) {
            manager
                .connection
                .query_row(
                    "SELECT
                        (SELECT COUNT(*) FROM execution_bindings WHERE task_id='T-revised'),
                        (SELECT COUNT(*) FROM authority_grants WHERE task_id='T-revised'),
                        (SELECT COUNT(*) FROM step_executions WHERE task_id='T-revised'),
                        (SELECT COUNT(*) FROM artifact_output_allocations WHERE task_id='T-revised'),
                        (SELECT COUNT(*) FROM plan_revisions WHERE task_id='T-revised'),
                        (SELECT COUNT(*) FROM semantic_program_revisions WHERE task_id='T-revised')",
                    [],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                        ))
                    },
                )
                .unwrap()
        };
        let authority_rows = |manager: &TaskManager| {
            [
                "execution_bindings",
                "authority_grants",
                "step_executions",
                "artifact_output_allocations",
                "approval_requests",
            ]
            .iter()
            .map(|table| {
                let mut statement = manager
                    .connection
                    .prepare(&format!(
                        "SELECT * FROM {table} WHERE task_id=?1 ORDER BY rowid"
                    ))
                    .unwrap();
                let columns = statement.column_count();
                let mut rows = statement.query(["T-revised"]).unwrap();
                let mut snapshot = Vec::new();
                while let Some(row) = rows.next().unwrap() {
                    snapshot.push(
                        (0..columns)
                            .map(|column| row.get::<_, rusqlite::types::Value>(column).unwrap())
                            .collect::<Vec<_>>(),
                    );
                }
                snapshot
            })
            .collect::<Vec<_>>()
        };
        let before_counts = counts(&f.manager);
        let before_authority = authority_rows(&f.manager);
        assert!(before_counts.0 > 0);
        assert!(before_counts.1 > 0);
        assert!(before_counts.2 > 0);
        assert!(before_counts.3 > 0);
        assert_eq!((before_counts.4, before_counts.5), (1, 1));
        let provenance_before = f.manager.provenance_count("T-revised").unwrap();

        let replacement = program("B");
        let replacement_plan = plan("B", 2);
        let denial = f
            .manager
            .admit_revised_semantic_program(&request(
                &replacement_plan,
                &replacement,
                &f.snapshot,
                "transition:finalized-revision-denied",
                "plan:B",
                before_task.revision,
            ))
            .unwrap();
        assert!(!denial.applied, "{denial:?}");
        assert_eq!(denial.reason_code, "TASK_TRANSITION_GUARD_FAILED");
        assert_eq!(
            f.manager.get_task("T-revised").unwrap().unwrap(),
            before_task
        );
        assert_eq!(status(&f.manager, "candidate:A"), before_candidate);
        assert_eq!(counts(&f.manager), before_counts);
        assert_eq!(authority_rows(&f.manager), before_authority);
        let after_approval: String = f
            .manager
            .connection
            .query_row(
                "SELECT status FROM approval_requests WHERE approval_id=?1",
                [&f.approval],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(after_approval, before_approval);
        assert_eq!(
            f.manager.provenance_count("T-revised").unwrap(),
            provenance_before
        );
        assert!(f.manager.verify_provenance("T-revised").unwrap());
    }

    #[test]
    fn revised_admission_is_atomic_replayable_and_permanently_retires_old_candidate() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("revised.sqlite3");
        let mut f = fixture(&path);
        let replacement = program("B");
        assert_ne!(
            aios_ir::recompute_semantic_hash(&replacement).unwrap(),
            f.initial_hash
        );
        let replacement_plan = plan("B", 2);
        let input = request(
            &replacement_plan,
            &replacement,
            &f.snapshot,
            "transition:revise-B",
            "plan:B",
            3,
        );
        let before = f.manager.provenance_count("T-revised").unwrap();
        let first = f.manager.admit_revised_semantic_program(&input).unwrap();
        assert!(first.applied, "{first:?}");
        assert_eq!(status(&f.manager, "candidate:A"), ("STALE".into(), 2));
        let approval_still_present: bool = f
            .manager
            .connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM approval_requests WHERE approval_id=?1)",
                [&f.approval],
                |r| r.get(0),
            )
            .unwrap();
        assert!(approval_still_present);
        let task = f.manager.get_task("T-revised").unwrap().unwrap();
        assert_eq!(task.state, TaskState::Planning);
        assert!(task.waiting_on.is_empty());
        assert_ne!(
            task.active_program.unwrap()["semantic_hash"],
            f.initial_hash
        );
        assert_eq!(f.manager.provenance_count("T-revised").unwrap(), before + 1);
        assert!(
            f.manager
                .evaluate_pending_authority_candidate("candidate:A")
                .is_err()
        );
        assert!(
            f.manager
                .finalize_pending_authority_candidate("candidate:A")
                .is_err()
        );
        assert_eq!(
            f.manager.admit_revised_semantic_program(&input).unwrap(),
            first
        );
        let mut changed: Value = serde_json::from_slice(&replacement).unwrap();
        changed["program_id"] = json!("program:B-changed");
        let changed = changed.to_string().into_bytes();
        let conflict = f
            .manager
            .admit_revised_semantic_program(&request(
                &replacement_plan,
                &changed,
                &f.snapshot,
                "transition:revise-B",
                "plan:B",
                3,
            ))
            .unwrap();
        assert!(!conflict.applied);
        assert_eq!(conflict.reason_code, "TASK_TRANSITION_ID_REUSE_CONFLICT");
        assert!(f.manager.verify_provenance("T-revised").unwrap());
        drop(f.manager);
        let mut reopened = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        assert_eq!(status(&reopened, "candidate:A"), ("STALE".into(), 2));
        assert_eq!(
            reopened.admit_revised_semantic_program(&input).unwrap(),
            first
        );
    }

    #[test]
    fn invalid_stale_and_failed_provenance_revisions_leave_no_partial_authority() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("revision-rollback.sqlite3");
        let mut f = fixture(&path);
        let replacement = program("B");
        let replacement_plan = plan("B", 2);
        let input = request(
            &replacement_plan,
            &replacement,
            &f.snapshot,
            "transition:revise-B",
            "plan:B",
            3,
        );
        let before = f.manager.provenance_count("T-revised").unwrap();
        let failed = f
            .manager
            .admit_revised_semantic_program_with_provenance_failure(&input)
            .unwrap();
        assert!(!failed.applied);
        assert_eq!(failed.reason_code, "TASK_PROVENANCE_APPEND_FAILED");
        assert_eq!(status(&f.manager, "candidate:A"), ("PENDING".into(), 1));
        let baseline: (i64, i64, i64, i64, i64, i64) = f
            .manager
            .connection
            .query_row(
                "SELECT (SELECT COUNT(*) FROM plan_revisions WHERE task_id='T-revised'),
                    (SELECT COUNT(*) FROM semantic_program_revisions WHERE task_id='T-revised'),
                    (SELECT COUNT(*) FROM validation_results WHERE task_id='T-revised'),
                    (SELECT COUNT(*) FROM plan_revisions WHERE task_id='T-revised' AND superseded_at IS NOT NULL),
                    (SELECT COUNT(*) FROM authority_grants WHERE task_id='T-revised'),
                    (SELECT COUNT(*) FROM execution_bindings WHERE task_id='T-revised')",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .unwrap();
        assert_eq!(baseline, (1, 1, 1, 0, 0, 0));
        assert_eq!(f.manager.provenance_count("T-revised").unwrap(), before);
        let task = f.manager.get_task("T-revised").unwrap().unwrap();
        assert_eq!(task.state, TaskState::WaitingForAuth);
        assert_eq!(
            task.active_program.unwrap()["semantic_hash"],
            f.initial_hash
        );
        let bad=br#"{"ir_version":"0.1","program_id":"program:invalid","kind":"task_graph","nodes":[]}"#;
        assert!(
            f.manager
                .admit_revised_semantic_program(&request(
                    &replacement_plan,
                    bad,
                    &f.snapshot,
                    "transition:invalid-B",
                    "plan:B",
                    3
                ))
                .is_err()
        );
        assert_eq!(status(&f.manager, "candidate:A"), ("PENDING".into(), 1));
        let stale = f
            .manager
            .admit_revised_semantic_program(&request(
                &replacement_plan,
                &replacement,
                &f.snapshot,
                "transition:stale-B",
                "plan:B",
                2,
            ))
            .unwrap();
        assert!(!stale.applied);
        assert_eq!(stale.reason_code, "TASK_REVISION_CONFLICT");
        assert_eq!(status(&f.manager, "candidate:A"), ("PENDING".into(), 1));
        let after: (i64, i64, i64, i64, i64, i64) = f
            .manager
            .connection
            .query_row(
                "SELECT (SELECT COUNT(*) FROM plan_revisions WHERE task_id='T-revised'),
                    (SELECT COUNT(*) FROM semantic_program_revisions WHERE task_id='T-revised'),
                    (SELECT COUNT(*) FROM validation_results WHERE task_id='T-revised'),
                    (SELECT COUNT(*) FROM plan_revisions WHERE task_id='T-revised' AND superseded_at IS NOT NULL),
                    (SELECT COUNT(*) FROM authority_grants WHERE task_id='T-revised'),
                    (SELECT COUNT(*) FROM execution_bindings WHERE task_id='T-revised')",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .unwrap();
        assert_eq!(after, baseline);

        // A damaged current validation cannot be treated as sound history.
        f.manager
            .connection
            .execute(
                "UPDATE validation_results SET result_json='{}' WHERE task_id='T-revised'",
                [],
            )
            .unwrap();
        assert!(f.manager.admit_revised_semantic_program(&input).is_err());
        assert_eq!(status(&f.manager, "candidate:A"), ("PENDING".into(), 1));
        assert_eq!(f.manager.provenance_count("T-revised").unwrap(), before);
    }

    #[test]
    fn nullable_and_forged_import_operations_do_not_cross_revision_fence() {
        let directory = tempdir().unwrap();
        let mut f = fixture(&directory.path().join("unsafe-import.sqlite3"));
        let b = program("B");
        let b_plan = plan("B", 2);
        let input = request(
            &b_plan,
            &b,
            &f.snapshot,
            "transition:unsafe-import",
            "plan:B",
            3,
        );
        let provenance_before = f.manager.provenance_count("T-revised").unwrap();
        f.manager.connection.execute(
            "INSERT INTO operations(operation_id,task_id,effect_class,state,outcome_certainty,prepared_at)
             VALUES ('operation:forged-import','T-revised','ARTIFACT_IMPORT','SUCCEEDED',NULL,?1)",
            [NOW],
        ).unwrap();
        assert!(f.manager.admit_revised_semantic_program(&input).is_err());
        f.manager.connection.execute(
            "UPDATE operations SET transaction_class='reversible_local',outcome_certainty='COMPLETED',
             idempotency_key=operation_id,external_receipt='{}',details_json='{}',
             started_at=prepared_at,finished_at=prepared_at
             WHERE operation_id='operation:forged-import'",
            [],
        ).unwrap();
        assert!(f.manager.admit_revised_semantic_program(&input).is_err());
        f.manager
            .connection
            .execute(
                "DELETE FROM operations WHERE operation_id='operation:forged-import'",
                [],
            )
            .unwrap();
        assert_eq!(
            f.manager
                .connection
                .execute(
                    "UPDATE operations SET external_receipt='{}'
             WHERE task_id='T-revised' AND effect_class='ARTIFACT_IMPORT'",
                    [],
                )
                .unwrap(),
            1
        );
        assert!(f.manager.admit_revised_semantic_program(&input).is_err());
        assert_eq!(status(&f.manager, "candidate:A"), ("PENDING".into(), 1));
        assert_eq!(
            f.manager.provenance_count("T-revised").unwrap(),
            provenance_before
        );
        let revisions: (i64, i64) = f
            .manager
            .connection
            .query_row(
                "SELECT (SELECT COUNT(*) FROM plan_revisions WHERE task_id='T-revised'),
                    (SELECT COUNT(*) FROM semantic_program_revisions WHERE task_id='T-revised')",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(revisions, (1, 1));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "exercises two genuine approval waits and revisions without fixture SQL"
    )]
    fn returning_to_original_program_never_revives_retired_candidate() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("return.sqlite3");
        let mut f = fixture(&path);
        f.manager
            .decide_candidate_approval(
                &f.approval,
                &AuthenticatedApprover {
                    principal_id: "user:test",
                },
                true,
            )
            .unwrap();
        let b = program("B");
        let b_plan = plan("B", 2);
        let first_input = request(&b_plan, &b, &f.snapshot, "transition:to-B", "plan:B", 3);
        let first_receipt = f
            .manager
            .admit_revised_semantic_program(&first_input)
            .unwrap();
        assert!(first_receipt.applied);
        let b_hash = f
            .manager
            .get_task("T-revised")
            .unwrap()
            .unwrap()
            .active_program
            .unwrap()["semantic_hash"]
            .as_str()
            .unwrap()
            .to_owned();
        let resources = [
            CandidateResourceChoice {
                action: "artifact.read".into(),
                semantic_selector: "input:source".into(),
                handle: CandidateResourceHandle::InputArtifact {
                    artifact_id: f.source.clone(),
                },
            },
            CandidateResourceChoice {
                action: "artifact.write".into(),
                semantic_selector: "task.output".into(),
                handle: CandidateResourceHandle::OutputAllocation {
                    allocation_id: "allocation:B".into(),
                    output_port: "copy".into(),
                },
            },
        ];
        f.manager
            .reserve_authority_candidate(&ReserveAuthorityCandidate {
                candidate_id: "candidate:B",
                binding_id: "binding:B",
                attempt_id: "attempt:B",
                task_id: "T-revised",
                semantic_program_hash: &b_hash,
                registry_snapshot_id: &f.snapshot,
                node_id: "copy",
                capability_contract_hash: &f.contract,
                provider_registration_id: &f.registration,
                attempt_number: 1,
                resources: &resources,
            })
            .unwrap();
        let evaluation = f
            .manager
            .evaluate_pending_authority_candidate("candidate:B")
            .unwrap();
        assert_eq!(
            evaluation.decisions[1].effect,
            PolicyEffect::RequireApproval
        );
        let approval = evaluation.decisions[1].approval_id.clone().unwrap();
        assert!(
            f.manager
                .transition(&TransitionRequest {
                    schema_version: "0.1".into(),
                    transition_id: "transition:wait-B".into(),
                    task_id: "T-revised".into(),
                    expected_revision: 4,
                    expected_state: TaskState::Planning,
                    to_state: TaskState::WaitingForAuth,
                    requested_by: Actor {
                        kind: "system-service".into(),
                        id: "aiosd.coordinator".into()
                    },
                    reason: TransitionReason {
                        code: "APPROVAL_REQUIRED".into(),
                        message: None,
                        related_ids: vec![approval.clone()]
                    },
                    mutation: TaskMutation {
                        waiting_on: Some(vec![WaitingOn {
                            kind: WaitingKind::Approval,
                            id: approval.clone(),
                            message: None,
                        }]),
                        ..TaskMutation::default()
                    },
                })
                .unwrap()
                .applied
        );
        let a = program("A");
        let a_plan = plan("A-return", 3);
        assert!(
            f.manager
                .admit_revised_semantic_program(&request(
                    &a_plan,
                    &a,
                    &f.snapshot,
                    "transition:return-A",
                    "plan:A-return",
                    5,
                ))
                .unwrap()
                .applied
        );
        let active_hash = f
            .manager
            .get_task("T-revised")
            .unwrap()
            .unwrap()
            .active_program
            .unwrap()["semantic_hash"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(active_hash, f.initial_hash);
        assert_eq!(status(&f.manager, "candidate:A"), ("STALE".into(), 2));
        assert_eq!(status(&f.manager, "candidate:B"), ("STALE".into(), 2));
        let old_statuses: (String, String) = f
            .manager
            .connection
            .query_row(
                "SELECT (SELECT status FROM approval_requests WHERE approval_id=?1),
                    (SELECT status FROM approval_requests WHERE approval_id=?2)",
                params![f.approval, approval],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(old_statuses, ("APPROVED".into(), "STALE".into()));
        assert_eq!(
            f.manager
                .admit_revised_semantic_program(&first_input)
                .unwrap(),
            first_receipt
        );
        assert!(
            f.manager
                .evaluate_pending_authority_candidate("candidate:A")
                .is_err()
        );
        assert!(
            f.manager
                .finalize_pending_authority_candidate("candidate:A")
                .is_err()
        );
        assert!(f.manager.verify_provenance("T-revised").unwrap());
        let return_input = request(
            &a_plan,
            &a,
            &f.snapshot,
            "transition:return-A",
            "plan:A-return",
            5,
        );
        drop(f.manager);
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        assert!(
            manager
                .admit_revised_semantic_program(&return_input)
                .unwrap()
                .applied
        );
        assert_eq!(status(&manager, "candidate:A"), ("STALE".into(), 2));
        assert_eq!(status(&manager, "candidate:B"), ("STALE".into(), 2));
        let fresh_resources = [
            CandidateResourceChoice {
                action: "artifact.read".into(),
                semantic_selector: "input:source".into(),
                handle: CandidateResourceHandle::InputArtifact {
                    artifact_id: f.source.clone(),
                },
            },
            CandidateResourceChoice {
                action: "artifact.write".into(),
                semantic_selector: "task.output".into(),
                handle: CandidateResourceHandle::OutputAllocation {
                    allocation_id: "allocation:A-fresh".into(),
                    output_port: "copy".into(),
                },
            },
        ];
        manager
            .reserve_authority_candidate(&ReserveAuthorityCandidate {
                candidate_id: "candidate:A-fresh",
                binding_id: "binding:A-fresh",
                attempt_id: "attempt:A-fresh",
                task_id: "T-revised",
                semantic_program_hash: &f.initial_hash,
                registry_snapshot_id: &f.snapshot,
                node_id: "copy",
                capability_contract_hash: &f.contract,
                provider_registration_id: &f.registration,
                attempt_number: 2,
                resources: &fresh_resources,
            })
            .unwrap();
        let evaluated = manager
            .evaluate_pending_authority_candidate("candidate:A-fresh")
            .unwrap();
        let fresh_approval = evaluated.decisions[1].approval_id.clone().unwrap();
        assert_ne!(fresh_approval, f.approval);
        let wait = manager
            .transition(&TransitionRequest {
                schema_version: "0.1".into(),
                transition_id: "transition:wait-A-fresh".into(),
                task_id: "T-revised".into(),
                expected_revision: 6,
                expected_state: TaskState::Planning,
                to_state: TaskState::WaitingForAuth,
                requested_by: Actor {
                    kind: "system-service".into(),
                    id: "aiosd.coordinator".into(),
                },
                reason: TransitionReason {
                    code: "APPROVAL_REQUIRED".into(),
                    message: None,
                    related_ids: vec![fresh_approval.clone()],
                },
                mutation: TaskMutation {
                    waiting_on: Some(vec![WaitingOn {
                        kind: WaitingKind::Approval,
                        id: fresh_approval.clone(),
                        message: None,
                    }]),
                    ..TaskMutation::default()
                },
            })
            .unwrap();
        assert!(wait.applied, "{wait:?}");
        assert!(
            manager
                .finalize_pending_authority_candidate("candidate:A-fresh")
                .is_err()
        );
        let before_approval: (i64, i64) = manager
            .connection
            .query_row(
                "SELECT (SELECT COUNT(*) FROM authority_grants WHERE task_id='T-revised'),
                    (SELECT COUNT(*) FROM execution_bindings WHERE task_id='T-revised')",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(before_approval, (0, 0));
        manager
            .decide_candidate_approval(
                &fresh_approval,
                &AuthenticatedApprover {
                    principal_id: "user:test",
                },
                true,
            )
            .unwrap();
        manager
            .finalize_pending_authority_candidate("candidate:A-fresh")
            .unwrap();
        let runnable = manager
            .transition(&TransitionRequest {
                schema_version: "0.1".into(),
                transition_id: "transition:A-fresh-runnable".into(),
                task_id: "T-revised".into(),
                expected_revision: 7,
                expected_state: TaskState::WaitingForAuth,
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
                mutation: TaskMutation::default(),
            })
            .unwrap();
        assert!(runnable.applied, "{runnable:?}");
        let running = manager
            .transition(&TransitionRequest {
                schema_version: "0.1".into(),
                transition_id: "transition:A-fresh-running".into(),
                task_id: "T-revised".into(),
                expected_revision: 8,
                expected_state: TaskState::Runnable,
                to_state: TaskState::Running,
                requested_by: Actor {
                    kind: "system-service".into(),
                    id: "aiosd.coordinator".into(),
                },
                reason: TransitionReason {
                    code: "EXECUTION_STARTED".into(),
                    message: None,
                    related_ids: vec![],
                },
                mutation: TaskMutation::default(),
            })
            .unwrap();
        assert!(running.applied, "{running:?}");
    }
}
