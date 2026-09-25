//! Trusted initial semantic-program admission inside a Task transition.

use super::{
    ActivePlan, Actor, ProgramAdmission, Result, TaskManager, TaskManagerError, TaskMutation,
    TaskState, TransitionReason, TransitionRequest, TransitionResult, canonical_json,
    load_admitted_semantic_registry,
};
use rusqlite::{Transaction, params};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const MAX_RAW_DOCUMENT_BYTES: usize = 1_048_576;

pub(crate) struct InitialProgramAdmissionRequest<'a> {
    pub transition_id: &'a str,
    pub task_id: &'a str,
    pub expected_revision: u64,
    pub plan_id: &'a str,
    pub plan_json: &'a [u8],
    pub registry_snapshot_id: &'a str,
    pub program_json: &'a [u8],
}

pub(super) struct InitialProgramAdmission {
    pub plan_json: String,
    pub registry_snapshot_id: String,
    pub program_json: String,
    pub program_digest: String,
    pub plan_digest: String,
}

fn reject() -> TaskManagerError {
    TaskManagerError::InvalidRecord("initial semantic program admission is not admissible")
}

pub(super) fn raw_digest(domain: &[u8], raw: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(raw);
    let mut tagged = String::from("sha256:");
    for byte in hasher.finalize() {
        write!(&mut tagged, "{byte:02x}").expect("string write");
    }
    tagged
}

pub(super) fn strict_document(raw: &[u8]) -> Result<Value> {
    if raw.is_empty() || raw.len() > MAX_RAW_DOCUMENT_BYTES {
        return Err(reject());
    }
    aios_registry::parse_strict_json::<Value>(raw, aios_registry::StrictJsonLimits::default())
        .map_err(|_| reject())
}

pub(super) fn single_node_id(program: &Value) -> Result<String> {
    let nodes = program
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or_else(reject)?;
    let [node] = nodes.as_slice() else {
        return Err(reject());
    };
    node.get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty() && id.chars().count() <= 128)
        .map(str::to_owned)
        .ok_or_else(reject)
}

pub(super) fn validate_plan(
    plan: &Value,
    task_id: &str,
    plan_id: &str,
    program: &Value,
    node_id: &str,
    expected_revision: u64,
) -> Result<()> {
    let schema: Value = serde_json::from_str(include_str!("../../../specs/task-plan.schema.json"))
        .map_err(|_| reject())?;
    if !jsonschema::validator_for(&schema)
        .map_err(|_| reject())?
        .is_valid(plan)
        || plan.get("plan_id").and_then(Value::as_str) != Some(plan_id)
        || plan.get("task_id").and_then(Value::as_str) != Some(task_id)
        || plan.get("revision").and_then(Value::as_u64) != Some(expected_revision)
    {
        return Err(reject());
    }
    let [node] = plan["nodes"].as_array().ok_or_else(reject)?.as_slice() else {
        return Err(reject());
    };
    let capability = program["nodes"][0]["operation"]["capability"]
        .as_str()
        .and_then(|capability| capability.split_once('@'))
        .ok_or_else(reject)?;
    if node.get("id").and_then(Value::as_str) != Some(node_id)
        || node.get("capability").and_then(Value::as_str) != Some(capability.0)
        || node
            .get("capability_version")
            .and_then(Value::as_str)
            .is_some_and(|version| version != capability.1)
    {
        return Err(reject());
    }
    Ok(())
}

impl TaskManager {
    /// Trusted-host entry: raw IR, rather than a caller's validity or hash
    /// claim, determines the executable initial program.
    pub(crate) fn admit_initial_semantic_program(
        &mut self,
        input: &InitialProgramAdmissionRequest<'_>,
    ) -> Result<TransitionResult> {
        self.admit_initial_semantic_program_impl(input, false)
    }

    fn admit_initial_semantic_program_impl(
        &mut self,
        input: &InitialProgramAdmissionRequest<'_>,
        fail_provenance: bool,
    ) -> Result<TransitionResult> {
        let plan = strict_document(input.plan_json)?;
        let program = strict_document(input.program_json)?;
        let node_id = single_node_id(&program)?;
        validate_plan(&plan, input.task_id, input.plan_id, &program, &node_id, 1)?;
        let plan_json = std::str::from_utf8(input.plan_json)
            .map_err(|_| reject())?
            .to_owned();
        let program_json = std::str::from_utf8(input.program_json)
            .map_err(|_| reject())?
            .to_owned();
        let admission = InitialProgramAdmission {
            plan_json,
            registry_snapshot_id: input.registry_snapshot_id.to_owned(),
            program_json,
            program_digest: raw_digest(b"AIOS-INITIAL-PROGRAM-RAW\0v1\0", input.program_json),
            plan_digest: raw_digest(b"AIOS-INITIAL-PLAN-RAW\0v1\0", input.plan_json),
        };
        let request = TransitionRequest {
            schema_version: "0.1".into(),
            transition_id: input.transition_id.to_owned(),
            task_id: input.task_id.to_owned(),
            expected_revision: input.expected_revision,
            expected_state: TaskState::Created,
            to_state: TaskState::Planning,
            requested_by: Actor {
                kind: "system-service".into(),
                id: "aiosd.coordinator".into(),
            },
            reason: TransitionReason {
                code: "PROGRAM_ADMITTED".into(),
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
                    revision: 1,
                }),
                active_step_ids: Some(vec![node_id]),
                ..TaskMutation::default()
            },
        };
        self.transition_impl(
            &request,
            fail_provenance,
            false,
            Some(ProgramAdmission::Initial(&admission)),
        )
    }

    #[cfg(test)]
    fn admit_initial_semantic_program_with_provenance_failure(
        &mut self,
        input: &InitialProgramAdmissionRequest<'_>,
    ) -> Result<TransitionResult> {
        self.admit_initial_semantic_program_impl(input, true)
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the validation, plan, program, and active pointer form one transition transaction"
)]
pub(super) fn persist_initial_program_admission_in(
    tx: &Transaction<'_>,
    request: &TransitionRequest,
    admission: &InitialProgramAdmission,
    committed_at: &str,
) -> Result<()> {
    if request.expected_state != TaskState::Created
        || request.to_state != TaskState::Planning
        || request.expected_revision != 1
        || request.reason.code != "PROGRAM_ADMITTED"
        || request.reason.related_ids
            != [
                format!("program-raw:{}", admission.program_digest),
                format!("plan-raw:{}", admission.plan_digest),
                format!("registry:{}", admission.registry_snapshot_id),
            ]
    {
        return Err(reject());
    }
    let current: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM semantic_current_usable_snapshots
         WHERE snapshot_id=?1 AND state='ADMITTED')",
        [&admission.registry_snapshot_id],
        |row| row.get(0),
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
    let validated_node = single_node_id(&strict_document(admission.program_json.as_bytes())?)?;
    if validation.registry_snapshot_id.as_deref() != Some(&admission.registry_snapshot_id)
        || validation.program_id.is_none()
        || validation.ir_version.as_deref() != Some("0.1")
        || Some(validated_node.as_str())
            != request
                .mutation
                .active_step_ids
                .as_ref()
                .and_then(|steps| steps.first())
                .map(String::as_str)
        || request
            .mutation
            .active_step_ids
            .as_ref()
            .is_none_or(|steps| steps.len() != 1)
    {
        return Err(reject());
    }
    let active_plan = request.mutation.active_plan.as_ref().ok_or_else(reject)?;
    if active_plan.revision != 1 {
        return Err(reject());
    }
    let program_id = validation.program_id.as_deref().ok_or_else(reject)?;
    let validation_id = format!(
        "validation:{}",
        raw_digest(
            b"AIOS-INITIAL-VALIDATION-ID\0v1\0",
            request.transition_id.as_bytes()
        )
    );
    let validator_id = validation.validator.id.as_str();
    let validator_version = validation.validator.version.as_str();
    let validator_build_hash = validation.validator.build_hash.as_deref();
    let result_json = canonical_json(&validation)?;
    tx.execute(
        "INSERT INTO plan_revisions(task_id,plan_revision,plan_id,plan_json,created_at)
         VALUES (?1,1,?2,?3,?4)",
        params![
            request.task_id,
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
            program_id,
            hash,
            admission.registry_snapshot_id,
            validator_id,
            validator_version,
            validator_build_hash,
            result_json,
            validation.validated_at
        ],
    )?;
    tx.execute(
        "INSERT INTO semantic_program_revisions(task_id,program_revision,program_id,ir_version,
            semantic_hash,registry_snapshot_id,validation_result_id,status,program_json,
            created_from_plan_revision,created_at)
         VALUES (?1,1,?2,'0.1',?3,?4,?5,'active',?6,1,?7)",
        params![
            request.task_id,
            program_id,
            hash,
            admission.registry_snapshot_id,
            validation_id,
            admission.program_json,
            committed_at
        ],
    )?;
    if tx.execute(
        "UPDATE tasks SET active_program_revision=1
         WHERE task_id=?1 AND revision=1 AND state='CREATED'
           AND active_program_revision IS NULL AND active_plan_revision IS NULL",
        [&request.task_id],
    )? != 1
    {
        return Err(reject());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CreateTask, TaskState};
    use aios_contracts::{CapabilityContract, RegistrySnapshot, TypeContract};
    use aios_registry::{RegistryBuildOptions, SemanticRegistry, SnapshotState};
    use serde_json::json;
    use tempfile::tempdir;

    struct FixedClock;
    impl crate::Clock for FixedClock {
        fn now(&self) -> String {
            "2026-09-19T00:00:00Z".into()
        }
        fn security_sample(&self) -> Option<crate::SecurityClockSample> {
            Some(crate::trusted_time::synthetic_sample(self.now()))
        }
    }

    fn program() -> Vec<u8> {
        json!({
            "ir_version":"0.1","program_id":"program:initial","kind":"task_graph",
            "inputs":{"source":{"type":"artifact.file@1"}},
            "nodes":[{"id":"copy","operation":{"kind":"invoke","capability":"artifact.copy@1"},
                "execution_class":"deterministic",
                "inputs":{"source":{"source":"input","name":"source"}},
                "outputs":{"copy":"artifact.file@1"},
                "authority_requests":[{"action":"artifact.read","resource":"input:source"},
                    {"action":"artifact.write","resource":"task.output"}],
                "egress":{"mode":"deny"},"failure":{"on_error":"stop"},"cache":"never"}],
            "outputs":{"copy":{"source":"node","node":"copy","port":"copy"}}
        })
        .to_string()
        .into_bytes()
    }

    fn plan(task_id: &str, plan_id: &str) -> Vec<u8> {
        json!({
            "schema_version":"0.1","plan_id":plan_id,"task_id":task_id,
            "revision":1,"intent":"copy the source",
            "nodes":[{"id":"copy","capability":"artifact.copy",
                "capability_version":"1","depends_on":[],
                "inputs":[{"name":"source","ref":"input:source","type":"artifact.file@1"}],
                "outputs":[{"name":"copy","type":"artifact.file@1"}]}]
        })
        .to_string()
        .into_bytes()
    }

    fn admitted_manager(path: Option<&std::path::Path>) -> (TaskManager, String) {
        let mut manager = if let Some(path) = path {
            TaskManager::open_with_clock(path, Box::new(FixedClock)).unwrap()
        } else {
            TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap()
        };
        let snapshot: RegistrySnapshot = serde_json::from_str(include_str!(
            "../../../examples/aios-ir/registry-snapshot.json"
        ))
        .unwrap();
        let types: Vec<TypeContract> = serde_json::from_str(include_str!(
            "../../../examples/aios-ir/type-contracts.json"
        ))
        .unwrap();
        let capabilities: Vec<CapabilityContract> = serde_json::from_str(include_str!(
            "../../../examples/aios-ir/capability-contracts.json"
        ))
        .unwrap();
        let registry = SemanticRegistry::from_records(
            snapshot,
            types,
            capabilities,
            RegistryBuildOptions::default(),
        )
        .unwrap();
        let id = manager
            .registry_store_writer()
            .unwrap()
            .admit_registry(&registry)
            .unwrap();
        (manager, id)
    }

    fn create(manager: &mut TaskManager, task_id: &str) {
        manager
            .create_task(&CreateTask {
                task_id: task_id.into(),
                principal: Actor {
                    kind: "user".into(),
                    id: "user:test".into(),
                },
                workspace_id: None,
                original_intent: "copy the source".into(),
                normalized_intent: None,
                active_step_ids: Vec::new(),
            })
            .unwrap();
    }

    fn rows(manager: &TaskManager, task_id: &str) -> (i64, i64, i64, i64) {
        manager
            .connection
            .query_row(
                "SELECT
                (SELECT COUNT(*) FROM plan_revisions WHERE task_id=?1),
                (SELECT COUNT(*) FROM validation_results WHERE task_id=?1),
                (SELECT COUNT(*) FROM semantic_program_revisions WHERE task_id=?1),
                (SELECT COUNT(*) FROM task_transitions WHERE task_id=?1)",
                [task_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap()
    }

    #[test]
    fn initial_program_admission_is_atomic_provenanced_and_exactly_replayable() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("initial-program.sqlite3");
        let (mut manager, snapshot) = admitted_manager(Some(&path));
        create(&mut manager, "T-initial");
        let raw = program();
        let plan = plan("T-initial", "plan:initial");
        let request = InitialProgramAdmissionRequest {
            transition_id: "transition:initial-program",
            task_id: "T-initial",
            expected_revision: 1,
            plan_id: "plan:initial",
            plan_json: &plan,
            registry_snapshot_id: &snapshot,
            program_json: &raw,
        };
        let first = manager.admit_initial_semantic_program(&request).unwrap();
        assert!(first.applied, "{first:?}");
        assert_eq!(rows(&manager, "T-initial"), (1, 1, 1, 1));
        let task = manager.get_task("T-initial").unwrap().unwrap();
        assert_eq!(task.state, TaskState::Planning);
        assert_eq!(task.active_step_ids, vec!["copy"]);
        assert_eq!(task.active_plan.unwrap().plan_id, "plan:initial");
        let program_hash = task.active_program.unwrap()["semantic_hash"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            program_hash,
            aios_ir::recompute_semantic_hash(&raw).unwrap()
        );
        assert!(manager.verify_provenance("T-initial").unwrap());
        assert_eq!(
            manager.admit_initial_semantic_program(&request).unwrap(),
            first
        );
        let mut changed_plan: Value = serde_json::from_slice(&plan).unwrap();
        changed_plan["intent"] = json!("changed intent");
        let changed_plan = changed_plan.to_string().into_bytes();
        let conflict = manager
            .admit_initial_semantic_program(&InitialProgramAdmissionRequest {
                plan_json: &changed_plan,
                ..request
            })
            .unwrap();
        assert!(!conflict.applied);
        assert_eq!(conflict.reason_code, "TASK_TRANSITION_ID_REUSE_CONFLICT");
        let mut changed_program: Value = serde_json::from_slice(&raw).unwrap();
        changed_program["program_id"] = json!("program:changed");
        let changed_program = changed_program.to_string().into_bytes();
        let conflict = manager
            .admit_initial_semantic_program(&InitialProgramAdmissionRequest {
                program_json: &changed_program,
                ..request
            })
            .unwrap();
        assert!(!conflict.applied);
        assert_eq!(conflict.reason_code, "TASK_TRANSITION_ID_REUSE_CONFLICT");
        assert_eq!(rows(&manager, "T-initial"), (1, 1, 1, 1));
        let later = manager
            .transition(&TransitionRequest {
                schema_version: "0.1".into(),
                transition_id: "transition:later-cancel".into(),
                task_id: "T-initial".into(),
                expected_revision: 2,
                expected_state: TaskState::Planning,
                to_state: TaskState::Cancelled,
                requested_by: Actor {
                    kind: "user".into(),
                    id: "user:test".into(),
                },
                reason: TransitionReason {
                    code: "USER_CANCELLED".into(),
                    message: None,
                    related_ids: vec![],
                },
                mutation: TaskMutation::default(),
            })
            .unwrap();
        assert!(later.applied, "{later:?}");
        assert_eq!(
            manager.admit_initial_semantic_program(&request).unwrap(),
            first
        );
        drop(manager);
        let mut reopened = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        assert!(reopened.verify_provenance("T-initial").unwrap());
        assert_eq!(
            reopened.admit_initial_semantic_program(&request).unwrap(),
            first
        );
    }

    #[test]
    fn invalid_ir_and_retired_registry_leave_no_program_or_transition() {
        let (mut manager, snapshot) = admitted_manager(None);
        create(&mut manager, "T-invalid");
        let mut bad: Value = serde_json::from_slice(&program()).unwrap();
        bad["nodes"][0]["operation"]["capability"] = json!("artifact.unknown@1");
        let raw = bad.to_string().into_bytes();
        let invalid_program_plan = plan("T-invalid", "plan:invalid");
        let request = InitialProgramAdmissionRequest {
            transition_id: "transition:invalid-program",
            task_id: "T-invalid",
            expected_revision: 1,
            plan_id: "plan:invalid",
            plan_json: &invalid_program_plan,
            registry_snapshot_id: &snapshot,
            program_json: &raw,
        };
        assert!(manager.admit_initial_semantic_program(&request).is_err());
        assert_eq!(rows(&manager, "T-invalid"), (0, 0, 0, 0));
        assert_eq!(
            manager.get_task("T-invalid").unwrap().unwrap().state,
            TaskState::Created
        );
        create(&mut manager, "T-wrong-plan");
        let valid_program = program();
        for (transition_id, invalid_plan) in [
            ("transition:wrong-task-plan", plan("T-other", "plan:wrong")),
            (
                "transition:malformed-plan",
                br#"{"plan_id":"plan:wrong"}"#.to_vec(),
            ),
        ] {
            assert!(
                manager
                    .admit_initial_semantic_program(&InitialProgramAdmissionRequest {
                        transition_id,
                        task_id: "T-wrong-plan",
                        expected_revision: 1,
                        plan_id: "plan:wrong",
                        plan_json: &invalid_plan,
                        registry_snapshot_id: &snapshot,
                        program_json: &valid_program,
                    })
                    .is_err()
            );
            assert_eq!(rows(&manager, "T-wrong-plan"), (0, 0, 0, 0));
        }
        create(&mut manager, "T-retired");
        manager
            .registry_store_writer()
            .unwrap()
            .set_snapshot_state(&snapshot, SnapshotState::Revoked)
            .unwrap();
        let valid = program();
        let retired_plan = plan("T-retired", "plan:invalid");
        assert!(
            manager
                .admit_initial_semantic_program(&InitialProgramAdmissionRequest {
                    transition_id: "transition:retired-program",
                    task_id: "T-retired",
                    expected_revision: 1,
                    plan_id: "plan:invalid",
                    plan_json: &retired_plan,
                    registry_snapshot_id: &snapshot,
                    program_json: &valid,
                })
                .is_err()
        );
        assert_eq!(rows(&manager, "T-retired"), (0, 0, 0, 0));
        assert_eq!(
            manager.get_task("T-retired").unwrap().unwrap().state,
            TaskState::Created
        );
    }

    #[test]
    fn provenance_failure_rolls_back_program_and_active_pointers() {
        let (mut manager, snapshot) = admitted_manager(None);
        create(&mut manager, "T-rollback");
        let raw = program();
        let rollback_plan = plan("T-rollback", "plan:rollback");
        let result = manager
            .admit_initial_semantic_program_with_provenance_failure(
                &InitialProgramAdmissionRequest {
                    transition_id: "transition:rollback-program",
                    task_id: "T-rollback",
                    expected_revision: 1,
                    plan_id: "plan:rollback",
                    plan_json: &rollback_plan,
                    registry_snapshot_id: &snapshot,
                    program_json: &raw,
                },
            )
            .unwrap();
        assert!(!result.applied);
        assert_eq!(result.reason_code, "TASK_PROVENANCE_APPEND_FAILED");
        assert_eq!(rows(&manager, "T-rollback"), (0, 0, 0, 0));
        let task = manager.get_task("T-rollback").unwrap().unwrap();
        assert_eq!(task.state, TaskState::Created);
        assert!(task.active_plan.is_none());
        assert!(task.active_program.is_none());
        assert!(manager.verify_provenance("T-rollback").unwrap());
    }
}
