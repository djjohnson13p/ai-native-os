use super::*;

use std::fs::OpenOptions;
use std::process::Command;

use rusqlite::Connection;
use tempfile::tempdir;

#[test]
fn authority_issuance_fence_rejects_missing_or_replaced_guard() {
    for replacement in [
        "DROP TRIGGER authority_issuance_receipt_exact_insert;",
        "DROP TRIGGER authority_issuance_receipt_exact_insert;
         CREATE TRIGGER authority_issuance_receipt_exact_insert
         BEFORE INSERT ON authority_issuance_receipts BEGIN SELECT 1; END;",
    ] {
        let manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
        manager.connection.execute_batch(replacement).unwrap();
        assert!(preflight_migration_state(&manager.connection).is_err());
    }
}

#[test]
fn authority_issuance_migration_preserves_but_does_not_admit_legacy_grant() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
    manager.connection.execute_batch(
        "INSERT INTO policy_snapshots(snapshot_id,scope_kind,scope_id,policy_language,policy_set_hash,engine_id,engine_version,snapshot_json,created_at)
         VALUES ('legacy-policy','task','T-completion','builtin','sha256:fixture','fixture','1','{}','2026-09-19T00:00:00Z');
         INSERT INTO authority_requests(request_id,task_id,semantic_program_hash,registry_snapshot_id,node_id,capability,principal_kind,principal_id,execution_binding_id,attempt_id,action,resolved_resource_kind,resolved_resource_id,semantic_selector,request_json,requested_at)
         VALUES ('legacy-request','T-completion','sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50','snapshot-completion','node-completion','test.complete@1','provider','provider:test','binding-completion','attempt-completion','artifact.read','artifact','artifact:fixture','input:fixture','{}','2026-09-19T00:00:00Z');
         INSERT INTO policy_decisions(decision_id,authority_request_id,task_id,semantic_program_hash,node_id,principal_kind,principal_id,action,resolved_resource_kind,resolved_resource_id,decision,policy_snapshot_id,reason_codes_json,decision_json,decided_at)
         VALUES ('legacy-decision','legacy-request','T-completion','sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50','node-completion','provider','provider:test','artifact.read','artifact','artifact:fixture','ALLOW','legacy-policy','[]','{}','2026-09-19T00:00:00Z');
         INSERT INTO authority_grants(grant_id,task_id,semantic_program_hash,node_id,capability,principal_kind,principal_id,execution_binding_id,attempt_id,policy_decision_id,policy_snapshot_id,grants_json,scope,state,issued_at,expires_at)
         VALUES ('legacy-grant','T-completion','sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50','node-completion','test.complete@1','provider','provider:test','binding-completion','attempt-completion','legacy-decision','legacy-policy','[{\"action\":\"artifact.read\",\"resource_kind\":\"artifact\",\"resource_id\":\"artifact:fixture\",\"semantic_selector\":\"input:fixture\"}]','TASK','ACTIVE','2026-09-19T00:00:00Z','2026-09-20T00:00:00Z');
         DROP TABLE authority_issuance_receipts;
         DELETE FROM schema_migrations WHERE migration_id='0015_authority_issuance_fence';",
    ).unwrap();
    migrate_task_manager_schema(
        &manager.connection,
        &manager.lease_owner,
        manager.lease_epoch,
    )
    .unwrap();
    let (token_id, receipt_count): (Option<String>, i64) = manager.connection.query_row(
        "SELECT g.token_id,(SELECT COUNT(*) FROM authority_issuance_receipts WHERE grant_id=g.grant_id)
         FROM authority_grants g WHERE g.grant_id='legacy-grant'",
        [], |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap();
    assert_eq!(token_id, None);
    assert_eq!(receipt_count, 0);
    assert!(preflight_migration_state(&manager.connection).is_ok());
}

const HASH: &str = "sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50";
const CONTRACT_HASH: &str =
    "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const SUITE_HASH: &str = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
const TEST_TIME: &str = "2026-09-19T00:00:00Z";
const COMPLETION_ARTIFACT_ID: &str =
    "artifact:v1:sha256:52c0b01bbc16da99f646722fd55c1ca9dc2a03f6186637485da30679c38fdabe";

fn verified_provider_admission_from_binding(
    transaction: &Transaction<'_>,
    binding_id: &str,
    binding: &BindingEvidence,
    checked_at: &str,
) -> Result<bool> {
    let Ok(receipt) =
        aios_registry::BindingReceiptProjection::parse(binding.binding_json.as_bytes())
    else {
        return Ok(false);
    };
    verified_provider_admission(transaction, binding_id, binding, checked_at, &receipt)
}

fn conformance_pin_matches(value: &Value, latest_id: &str, required: bool) -> bool {
    aios_registry::BindingReceiptProjection::parse(value.to_string().as_bytes())
        .is_ok_and(|receipt| receipt.evidence_pin_matches(latest_id, required))
}

struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> String {
        "2026-09-19T00:00:00Z".to_owned()
    }
    fn security_sample(&self) -> Option<crate::SecurityClockSample> {
        Some(crate::trusted_time::synthetic_sample(self.now()))
    }
}

struct LaterClock;

impl Clock for LaterClock {
    fn now(&self) -> String {
        "2026-09-19T00:00:02Z".to_owned()
    }
    fn security_sample(&self) -> Option<crate::SecurityClockSample> {
        Some(crate::trusted_time::synthetic_sample(self.now()))
    }
}

struct MicroClock;

impl Clock for MicroClock {
    fn now(&self) -> String {
        "2026-09-19T00:00:00.000500Z".to_owned()
    }
    fn security_sample(&self) -> Option<crate::SecurityClockSample> {
        Some(crate::trusted_time::synthetic_sample(self.now()))
    }
}

fn create(task_id: &str) -> CreateTask {
    CreateTask {
        task_id: task_id.to_owned(),
        principal: Actor {
            kind: "user".to_owned(),
            id: "user:adversarial".to_owned(),
        },
        workspace_id: None,
        original_intent: "Exercise durable task controls.".to_owned(),
        normalized_intent: None,
        active_step_ids: Vec::new(),
    }
}

fn compatibility_create(task_id: &str) -> CreateTask {
    CreateTask {
        task_id: task_id.to_owned(),
        principal: Actor {
            kind: "user".to_owned(),
            id: "user:Alice Smith=👩\u{200d}💻e\u{301}".to_owned(),
        },
        workspace_id: Some("My Workspace=🧪e\u{301}".to_owned()),
        original_intent: "Exercise opaque Task identifier compatibility.".to_owned(),
        normalized_intent: None,
        active_step_ids: vec![
            "step one".to_owned(),
            "step=two".to_owned(),
            "step 👣".to_owned(),
            "step-e\u{301}".to_owned(),
        ],
    }
}

fn request(
    id: &str,
    task_id: &str,
    revision: u64,
    from: TaskState,
    to: TaskState,
) -> TransitionRequest {
    TransitionRequest {
        schema_version: SCHEMA_VERSION.to_owned(),
        transition_id: id.to_owned(),
        task_id: task_id.to_owned(),
        expected_revision: revision,
        expected_state: from,
        to_state: to,
        requested_by: Actor {
            kind: "system-service".to_owned(),
            id: "service:task-manager".to_owned(),
        },
        reason: TransitionReason {
            code: "STATE_CHANGE_REQUESTED".to_owned(),
            message: None,
            related_ids: Vec::new(),
        },
        mutation: if to == TaskState::Failed {
            TaskMutation {
                failure: Some(failure_record(false)),
                ..TaskMutation::default()
            }
        } else {
            TaskMutation::default()
        },
    }
}

fn seed_nonterminal_history(manager: &mut TaskManager, task_id: &str, final_state: TaskState) {
    manager.create_task(&create(task_id)).unwrap();
    let path: &[TaskState] = match final_state {
        TaskState::Runnable => &[TaskState::Planning, TaskState::Runnable],
        TaskState::Running => &[TaskState::Planning, TaskState::Runnable, TaskState::Running],
        TaskState::Verifying => &[
            TaskState::Planning,
            TaskState::Runnable,
            TaskState::Running,
            TaskState::Verifying,
        ],
        TaskState::Paused => &[
            TaskState::Planning,
            TaskState::Runnable,
            TaskState::Running,
            TaskState::Paused,
        ],
        TaskState::WaitingForInput => &[TaskState::Planning, TaskState::WaitingForInput],
        TaskState::WaitingForAuth => &[TaskState::Planning, TaskState::WaitingForAuth],
        _ => panic!("fixture only supports nonterminal recovery candidate states"),
    };
    let transaction = manager.connection.transaction().unwrap();
    let mut from = TaskState::Created;
    let mut revision = 1_u64;
    for to in path {
        let next_revision = revision + 1;
        let event = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "event_id": format!("event:seed:{task_id}:{next_revision}"),
            "task_id": task_id,
            "event_type": "task.transitioned",
            "timestamp": "2026-09-19T00:00:00Z",
            "actor": {"kind":"system-service","id":"service:test"},
            "status": "success",
            "task_transition": {
                "transition_id": format!("seed:{task_id}:{next_revision}"),
                "previous_state": from,
                "new_state": to,
                "previous_revision": revision,
                "new_revision": next_revision,
                "reason_code": "STATE_CHANGE_REQUESTED"
            },
            "committed_mutation": {
                "active_plan": null,
                "active_step_ids": null,
                "waiting_on": null,
                "failure": null,
                "recovery": null
            },
            "details": {"reason_message_ref": null, "active_program": null}
        });
        let appended = append_event(&transaction, task_id, &event).unwrap();
        transaction
            .execute(
                "UPDATE tasks SET state = ?2, revision = ?3, state_reason_json = ?4 WHERE task_id = ?1",
                rusqlite::params![task_id, to.as_str(), i64::try_from(next_revision).unwrap(), serde_json::json!({"code":"STATE_CHANGE_REQUESTED","message":null,"provenance_event_id":appended.event_id}).to_string()],
            )
            .unwrap();
        from = *to;
        revision = next_revision;
    }
    transaction.commit().unwrap();
}

fn seed_recovering_history(manager: &mut TaskManager, task_id: &str) -> u64 {
    seed_nonterminal_history(manager, task_id, TaskState::Running);
    let previous_revision = 4_u64;
    let new_revision = previous_revision + 1;
    let transaction = manager.connection.transaction().unwrap();
    let event = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "event_id": format!("event:seed:{task_id}:recovering"),
        "task_id": task_id,
        "event_type": "task.transitioned",
        "timestamp": TEST_TIME,
        "actor": {"kind":"system-service","id":"service:test"},
        "status": "success",
        "task_transition": {
            "transition_id": format!("seed:{task_id}:recovering"),
            "previous_state": TaskState::Running,
            "new_state": TaskState::Recovering,
            "previous_revision": previous_revision,
            "new_revision": new_revision,
            "reason_code": "STARTUP_RECOVERY_REQUIRED"
        },
        "committed_mutation": {
            "active_plan": null,
            "active_step_ids": null,
            "waiting_on": null,
            "failure": null,
            "recovery": null
        },
        "details": {"reason_message_ref": null, "active_program": null}
    });
    let appended = append_event(&transaction, task_id, &event).unwrap();
    transaction
        .execute(
            "UPDATE tasks
             SET state='RECOVERING', revision=?2, state_reason_json=?3
             WHERE task_id=?1",
            rusqlite::params![
                task_id,
                i64::try_from(new_revision).unwrap(),
                serde_json::json!({
                    "code": "STARTUP_RECOVERY_REQUIRED",
                    "message": null,
                    "provenance_event_id": appended.event_id
                })
                .to_string()
            ],
        )
        .unwrap();
    transaction.commit().unwrap();
    new_revision
}

#[test]
fn response_loss_reopen_replays_committed_rejected_and_absent_requests_exactly() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("response-loss.sqlite3");
    let applied_request = request(
        "tr-committed",
        "T-committed",
        1,
        TaskState::Created,
        TaskState::Planning,
    );
    let absent_request = request(
        "tr-absent",
        "T-absent",
        1,
        TaskState::Created,
        TaskState::Planning,
    );
    let illegal_request = request(
        "tr-illegal",
        "T-illegal",
        1,
        TaskState::Created,
        TaskState::Completed,
    );
    let (applied, absent, illegal) = {
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        manager.create_task(&create("T-committed")).unwrap();
        manager.create_task(&create("T-illegal")).unwrap();
        (
            manager.transition(&applied_request).unwrap(),
            manager.transition(&absent_request).unwrap(),
            manager.transition(&illegal_request).unwrap(),
        )
    };
    let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
    assert_eq!(manager.transition(&applied_request).unwrap(), applied);
    assert_eq!(manager.transition(&absent_request).unwrap(), absent);
    assert_eq!(manager.transition(&illegal_request).unwrap(), illegal);
    assert_eq!(manager.provenance_count("T-committed").unwrap(), 2);
    assert_eq!(manager.provenance_count("T-illegal").unwrap(), 1);
    let mut reused = applied_request;
    reused.to_state = TaskState::Failed;
    assert_eq!(
        manager.transition(&reused).unwrap().reason_code,
        "TASK_TRANSITION_ID_REUSE_CONFLICT"
    );
}

#[test]
fn step_attempt_survives_reopen_without_overwriting_prior_attempt_identity() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("step-history.sqlite3");
    {
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        manager.create_task(&create("T-step")).unwrap();
        let step = CreateStepExecution {
            attempt_id: "attempt-1".to_owned(),
            task_id: "T-step".to_owned(),
            semantic_program_hash: HASH.to_owned(),
            registry_snapshot_id: None,
            node_id: "node-1".to_owned(),
            binding_id: None,
            provider_id: Some("provider:test".to_owned()),
            provider_version: Some("0.1.0".to_owned()),
            attempt_number: 1,
            state: StepState::Unknown,
            operation_id: Some("operation-1".to_owned()),
            idempotency_key: Some("operation-1".to_owned()),
            outcome_certainty: Some(OutcomeCertainty::OutcomeUnknown),
            input_artifacts: vec!["artifact:input".to_owned()],
            output_artifacts: Vec::new(),
            failure: Some(StepFailure {
                code: "RESPONSE_LOST".to_owned(),
                summary: "lost response".to_owned(),
                retryable: false,
                safe_to_rebind: false,
                unknown_side_effects: true,
            }),
            started_at: Some("2026-09-19T00:00:00Z".to_owned()),
            finished_at: None,
        };
        assert_eq!(manager.create_step_execution(&step).unwrap().revision, 1);
    }
    let manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
    let step = manager.get_step_execution("attempt-1").unwrap().unwrap();
    assert_eq!(step.state, StepState::Unknown);
    assert_eq!(
        step.outcome_certainty,
        Some(OutcomeCertainty::OutcomeUnknown)
    );
    assert_eq!(step.attempt_number, 1);
    assert_eq!(step.input_artifacts, vec!["artifact:input"]);
}

#[test]
fn attempt_tuple_is_snapshot_independent_and_store_ownership_is_exclusive() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("attempt-race.sqlite3");
    let mut setup = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
    setup.create_task(&create("T-attempt-race")).unwrap();
    setup.connection.execute_batch(
        "INSERT INTO registry_snapshots (snapshot_id, manifest_json, created_at) VALUES ('snapshot-a', '{}', '2026-09-19T00:00:00Z');
         INSERT INTO registry_snapshots (snapshot_id, manifest_json, created_at) VALUES ('snapshot-b', '{}', '2026-09-19T00:00:00Z');
         INSERT INTO registry_snapshots (snapshot_id, manifest_json, created_at) VALUES ('snapshot-c', '{}', '2026-09-19T00:00:00Z');",
    ).unwrap();
    drop(setup);

    let mut owner = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
    assert!(TaskManager::open_with_clock(&path, Box::new(FixedClock)).is_err());
    let request = CreateStepExecution {
        attempt_id: "attempt-snapshot-a".to_owned(),
        task_id: "T-attempt-race".to_owned(),
        semantic_program_hash: HASH.to_owned(),
        registry_snapshot_id: Some("snapshot-a".to_owned()),
        node_id: "node-race".to_owned(),
        binding_id: None,
        provider_id: Some("provider:test".to_owned()),
        provider_version: Some("0.1.0".to_owned()),
        attempt_number: 1,
        state: StepState::Ready,
        operation_id: None,
        idempotency_key: None,
        outcome_certainty: Some(OutcomeCertainty::NotStarted),
        input_artifacts: Vec::new(),
        output_artifacts: Vec::new(),
        failure: None,
        started_at: None,
        finished_at: None,
    };
    owner.create_step_execution(&request).unwrap();
    let connection = Connection::open(&path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM step_executions WHERE task_id = 'T-attempt-race' AND semantic_program_hash = ?1 AND node_id = 'node-race' AND attempt_number = 1",
                [HASH],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    assert!(connection
        .execute(
            "INSERT INTO step_executions (attempt_id, task_id, semantic_program_hash, registry_snapshot_id, node_id, attempt_number, revision, state, outcome_certainty, input_artifacts_json, output_artifacts_json, created_at, updated_at) VALUES ('attempt-raw-duplicate', 'T-attempt-race', ?1, 'snapshot-c', 'node-race', 1, 1, 'READY', 'NOT_STARTED', '[]', '[]', '2026-09-19T00:00:00Z', '2026-09-19T00:00:00Z')",
            [HASH],
        )
        .is_err());
}

#[test]
fn startup_recovery_moves_running_and_verifying_tasks_through_cas_provenance() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_nonterminal_history(&mut manager, "T-running", TaskState::Running);
    seed_nonterminal_history(&mut manager, "T-verifying", TaskState::Verifying);
    for task_id in ["T-running", "T-verifying"] {
        manager.connection.execute(
            "INSERT INTO operations(operation_id,task_id,semantic_program_hash,node_id,effect_class,state,outcome_certainty,prepared_at)
             VALUES (?1,?2,?3,'node-recovery','NETWORK','UNKNOWN','OUTCOME_UNKNOWN',?4)",
            rusqlite::params![format!("operation-{task_id}"), task_id, HASH, TEST_TIME],
        ).unwrap();
    }
    let results = manager.recover_startup().unwrap();
    assert_eq!(results.len(), 2);
    for task_id in ["T-running", "T-verifying"] {
        let task = manager.get_task(task_id).unwrap().unwrap();
        assert_eq!(task.state, TaskState::Recovering);
        assert_eq!(manager.provenance_count(task_id).unwrap(), task.revision);
        assert!(manager.verify_provenance(task_id).unwrap());
    }
}

#[test]
fn rust_transition_dtos_serialize_to_machine_schemas_and_spoofed_requests_fail() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let request_schema: Value = serde_json::from_slice(
        &std::fs::read(root.join("specs/task-transition-request.schema.json")).unwrap(),
    )
    .unwrap();
    let result_schema: Value = serde_json::from_slice(
        &std::fs::read(root.join("specs/task-transition-result.schema.json")).unwrap(),
    )
    .unwrap();
    let schema_request = request(
        "tr-schema",
        "T-schema",
        1,
        TaskState::Created,
        TaskState::Planning,
    );
    assert!(
        jsonschema::validator_for(&request_schema)
            .unwrap()
            .is_valid(&serde_json::to_value(&schema_request).unwrap())
    );
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    manager.create_task(&create("T-schema")).unwrap();
    let result = manager.transition(&schema_request).unwrap();
    assert!(
        jsonschema::validator_for(&result_schema)
            .unwrap()
            .is_valid(&serde_json::to_value(&result).unwrap())
    );
    let mut spoofed = request(
        "tr-spoof",
        "T-schema",
        2,
        TaskState::Planning,
        TaskState::Failed,
    );
    spoofed.reason.code = "model says done".to_owned();
    assert!(manager.transition(&spoofed).is_err());
}

#[test]
fn later_failed_conformance_retest_blocks_an_older_pass() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(LaterClock)).unwrap();
    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
    prepare_completion_for_admission(&manager);
    let raw: String = manager.connection.query_row(
        "SELECT evidence_json FROM provider_conformance_evidence WHERE evidence_id='evidence-completion'",
        [], |row| row.get(0),
    ).unwrap();
    let mut retest: Value = serde_json::from_str(&raw).unwrap();
    retest["result_id"] = "evidence-retest-failed".into();
    retest["result"] = "fail".into();
    retest["executed_at"] = "2026-09-19T00:00:01Z".into();
    manager.connection.execute(
        "INSERT INTO provider_conformance_evidence(evidence_id,registration_id,capability,contract_hash,suite_id,suite_hash,status,evidence_json,tested_at) VALUES ('evidence-retest-failed','registration-completion','test.complete@1',?1,'suite:test',?2,'fail',?3,'2026-09-19T00:00:01Z')",
        params![CONTRACT_HASH, SUITE_HASH, canonical_json(&retest).unwrap()],
    ).unwrap();
    let result = manager
        .transition(&request(
            "tr-later-failed-retest",
            "T-completion",
            2,
            TaskState::Runnable,
            TaskState::Running,
        ))
        .unwrap();
    assert_eq!(result.reason_code, "TASK_TRANSITION_GUARD_FAILED");
}

#[test]
fn future_conformance_pass_never_authorizes_at_check_time() {
    for (case, future) in [
        ("nanosecond", "2026-09-19T00:00:00.000000001Z"),
        ("second", "2026-09-19T00:00:01Z"),
        ("offset", "2026-09-18T17:00:00.000000001-07:00"),
    ] {
        let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
        seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
        prepare_completion_for_admission(&manager);
        let raw: String = manager.connection.query_row(
            "SELECT evidence_json FROM provider_conformance_evidence WHERE evidence_id='evidence-completion'",
            [], |row| row.get(0),
        ).unwrap();
        let mut evidence: Value = serde_json::from_str(&raw).unwrap();
        evidence["executed_at"] = future.into();
        manager.connection.execute(
            "UPDATE provider_conformance_evidence SET tested_at=?1,evidence_json=?2 WHERE evidence_id='evidence-completion'",
            params![future,canonical_json(&evidence).unwrap()],
        ).unwrap();
        let result = manager
            .transition(&request(
                &format!("tr-future-conformance-{case}"),
                "T-completion",
                2,
                TaskState::Runnable,
                TaskState::Running,
            ))
            .unwrap();
        assert_eq!(result.reason_code, "TASK_TRANSITION_GUARD_FAILED", "{case}");
    }
}

#[test]
fn equal_instant_latest_conformance_receipts_fail_closed() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
    prepare_completion_for_admission(&manager);
    let raw: String = manager.connection.query_row(
        "SELECT evidence_json FROM provider_conformance_evidence WHERE evidence_id='evidence-completion'",
        [], |row| row.get(0),
    ).unwrap();
    let mut second: Value = serde_json::from_str(&raw).unwrap();
    second["result_id"] = "evidence-completion-tie".into();
    second["executed_at"] = "2026-09-18T17:00:00-07:00".into();
    manager.connection.execute(
        "INSERT INTO provider_conformance_evidence(evidence_id,registration_id,capability,contract_hash,suite_id,suite_hash,status,evidence_json,tested_at)
         VALUES ('evidence-completion-tie','registration-completion','test.complete@1',?1,'suite:test',?2,'pass',?3,'2026-09-18T17:00:00-07:00')",
        params![CONTRACT_HASH, SUITE_HASH, canonical_json(&second).unwrap()],
    ).unwrap();
    let result = manager
        .transition(&request(
            "tr-equal-time-conformance",
            "T-completion",
            2,
            TaskState::Runnable,
            TaskState::Running,
        ))
        .unwrap();
    assert_eq!(result.reason_code, "TASK_TRANSITION_GUARD_FAILED");
}

#[test]
fn submillisecond_future_retest_does_not_hide_latest_eligible_pass() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(MicroClock)).unwrap();
    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
    prepare_completion_for_admission(&manager);
    mutate_json_column(
        &manager,
        "SELECT evidence_json FROM provider_conformance_evidence WHERE evidence_id='evidence-completion'",
        "UPDATE provider_conformance_evidence SET evidence_json=?1, tested_at='2026-09-19T00:00:00.000400Z' WHERE evidence_id='evidence-completion'",
        "/executed_at",
        json!("2026-09-19T00:00:00.000400Z"),
    );
    let raw: String = manager.connection.query_row(
        "SELECT evidence_json FROM provider_conformance_evidence WHERE evidence_id='evidence-completion'",
        [], |row| row.get(0),
    ).unwrap();
    let mut future: Value = serde_json::from_str(&raw).unwrap();
    future["result_id"] = "evidence-future-failure".into();
    future["result"] = "fail".into();
    future["executed_at"] = "2026-09-19T00:00:00.000600Z".into();
    manager.connection.execute(
        "INSERT INTO provider_conformance_evidence(evidence_id,registration_id,capability,contract_hash,suite_id,suite_hash,status,evidence_json,tested_at)
         VALUES ('evidence-future-failure','registration-completion','test.complete@1',?1,'suite:test',?2,'fail',?3,'2026-09-19T00:00:00.000600Z')",
        params![CONTRACT_HASH, SUITE_HASH, canonical_json(&future).unwrap()],
    ).unwrap();
    let transaction = manager.connection.transaction().unwrap();
    assert!(
        binding_grants_valid(
            &transaction,
            &BindingGrantCheck {
                task_id: "T-completion",
                semantic_hash: HASH,
                node_id: "node-completion",
                binding_id: "binding-completion",
                attempt_id: "attempt-completion",
                grant_refs_json: "[]",
                checked_at: "2026-09-19T00:00:00.000500Z",
            }
        )
        .unwrap()
    );
}

#[test]
fn stamped_provider_migration_rejects_legacy_registration_without_admission_receipt() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
    prepare_completion_for_admission(&manager);
    manager
        .connection
        .execute_batch(include_str!(
            "../../../specs/persistence-v0.1-0013-provider-registry.sql"
        ))
        .unwrap();
    manager.connection.execute(
        "INSERT INTO schema_migrations(migration_id,checksum,applied_at) VALUES ('0013_provider_registry','provider-registry-v0.1',?1)",
        [TEST_TIME],
    ).unwrap();
    let result = manager
        .transition(&request(
            "tr-legacy-provider-without-receipt",
            "T-completion",
            2,
            TaskState::Runnable,
            TaskState::Running,
        ))
        .unwrap();
    assert_eq!(result.reason_code, "TASK_TRANSITION_GUARD_FAILED");
    manager.connection.execute(
        "INSERT INTO provider_manifest_payloads(registration_id,manifest_json) VALUES ('registration-completion','{}')", [],
    ).unwrap();
    let second = manager
        .transition(&request(
            "tr-legacy-provider-forged-payload",
            "T-completion",
            2,
            TaskState::Runnable,
            TaskState::Running,
        ))
        .unwrap();
    assert_eq!(second.reason_code, "TASK_TRANSITION_GUARD_FAILED");
}

#[test]
#[allow(clippy::too_many_lines)]
fn verified_provider_receipt_allows_unchanged_claim_on_new_snapshot() {
    use aios_contracts::{CapabilityContract, RegistrySnapshot, TypeContract};
    use aios_registry::{
        ProviderTrustStatus, RegistryBuildOptions, SemanticRegistry, SnapshotHashEntry,
    };

    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    manager.initialize_provider_store().unwrap();
    let mut snapshot: RegistrySnapshot = serde_json::from_str(include_str!(
        "../../../examples/aios-ir/registry-snapshot.json"
    ))
    .unwrap();
    let types: Vec<TypeContract> = serde_json::from_str(include_str!(
        "../../../examples/aios-ir/type-contracts.json"
    ))
    .unwrap();
    let mut capabilities: Vec<CapabilityContract> = serde_json::from_str(include_str!(
        "../../../examples/aios-ir/capability-contracts.json"
    ))
    .unwrap();
    let claimed = capabilities
        .iter_mut()
        .find(|contract| contract.capability == "artifact.hash")
        .unwrap();
    claimed.conformance.suite_hash = Some(SUITE_HASH.into());
    snapshot
        .capability_contracts
        .iter_mut()
        .find(|entry| entry.id == "artifact.hash")
        .unwrap()
        .content_hash = aios_registry::capability_contract_hash(claimed)
        .unwrap()
        .to_string();
    let refresh_id = |snapshot: &mut RegistrySnapshot| {
        let view = |entry: &aios_contracts::ContractRef| SnapshotHashEntry {
            id: entry.id.clone(),
            version: entry.version.clone(),
            content_hash: entry.content_hash.clone(),
        };
        snapshot.snapshot_id = aios_registry::registry_snapshot_id(
            &snapshot.schema_version,
            &snapshot.type_contracts.iter().map(view).collect::<Vec<_>>(),
            &snapshot
                .capability_contracts
                .iter()
                .map(view)
                .collect::<Vec<_>>(),
        )
        .unwrap()
        .to_string();
    };
    refresh_id(&mut snapshot);
    let first = SemanticRegistry::from_records(
        snapshot.clone(),
        types.clone(),
        capabilities.clone(),
        RegistryBuildOptions::default(),
    )
    .unwrap();
    let unrelated = capabilities
        .iter_mut()
        .find(|contract| contract.capability == "table.normalize")
        .unwrap();
    unrelated.version = "1.1".into();
    snapshot
        .capability_contracts
        .iter_mut()
        .find(|entry| entry.id == "table.normalize")
        .unwrap()
        .version = "1.1".into();
    snapshot
        .capability_contracts
        .iter_mut()
        .find(|entry| entry.id == "table.normalize")
        .unwrap()
        .content_hash = aios_registry::capability_contract_hash(unrelated)
        .unwrap()
        .to_string();
    refresh_id(&mut snapshot);
    let second = SemanticRegistry::from_records(
        snapshot,
        types,
        capabilities,
        RegistryBuildOptions::default(),
    )
    .unwrap();
    assert_ne!(first.snapshot_id(), second.snapshot_id());
    {
        let mut store = manager.registry_store_writer().unwrap();
        store.admit_registry(&first).unwrap();
        store.admit_registry(&second).unwrap();
    }
    let cases: Value = serde_json::from_str(include_str!(
        "../../../examples/aios-ir/provider-conformance-cases.json"
    ))
    .unwrap();
    let mut manifest = cases[0]["provider"].clone();
    manifest["provides"][0]["conformance"]["suite_hash"] = SUITE_HASH.into();
    let contract_hash = first
        .capability_contract_hash("artifact.hash", 1)
        .unwrap()
        .to_string();
    manifest["provides"][0]["contract"]["contract_hash"] = contract_hash.clone().into();
    let build = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let registration = manager
        .provider_store_writer()
        .unwrap()
        .register(
            &first,
            &serde_json::to_vec(&manifest).unwrap(),
            build,
            ProviderTrustStatus::Unverified,
            TEST_TIME,
        )
        .unwrap();
    let mut binding = BindingEvidence {
        capability: "artifact.hash@1".into(),
        principal_id: registration.provider_id,
        program_json: String::new(),
        registry_snapshot_id: second.snapshot_id().into(),
        contract_hash: Some(contract_hash),
        snapshot_manifest_json: String::new(),
        ir_version: String::new(),
        provider_version: registration.provider_version,
        provider_manifest_hash: Some(registration.manifest_hash),
        provider_build_hash: Some(registration.build_hash),
        provider_registration_id: Some(registration.registration_id),
        attempt: 1,
        policy_decision_refs_json: String::new(),
        grant_refs_json: String::new(),
        execution_profile_ref: String::new(),
        placement_json: String::new(),
        binding_json: String::new(),
        created_at: TEST_TIME.into(),
        conformance_evidence_id: String::new(),
        conformance_suite_id: Some("suite:artifact-hash".into()),
        conformance_suite_hash: Some(SUITE_HASH.into()),
        conformance_status: String::new(),
        conformance_json: String::new(),
        conformance_tested_at: None,
    };
    binding.conformance_suite_id = manifest["provides"][0]["conformance"]["suite"]
        .as_str()
        .map(str::to_owned);
    {
        let transaction = manager.connection.transaction().unwrap();
        assert!(
            !verified_provider_receipt_and_compatibility(&transaction, &binding, TEST_TIME)
                .unwrap()
        );
        transaction.rollback().unwrap();
    }
    manager
        .provider_store_writer()
        .unwrap()
        .admit_trust(
            binding.provider_registration_id.as_deref().unwrap(),
            "decision:fixture-promotion",
            ProviderTrustStatus::LocallyTrusted,
            "review:fixture-owner",
            TEST_TIME,
        )
        .unwrap();
    let transaction = manager.connection.transaction().unwrap();
    assert!(
        verified_provider_receipt_and_compatibility(&transaction, &binding, TEST_TIME).unwrap()
    );
    binding.registry_snapshot_id = first.snapshot_id().into();
    assert!(
        verified_provider_receipt_and_compatibility(&transaction, &binding, TEST_TIME).unwrap()
    );
    let original_receipt: String = transaction
        .query_row(
            "SELECT registration_json FROM provider_registrations WHERE registration_id=?1",
            [binding.provider_registration_id.as_deref().unwrap()],
            |row| row.get(0),
        )
        .unwrap();
    let original_value: Value = serde_json::from_str(&original_receipt).unwrap();
    for (pointer, replacement) in [
        ("/runtime/kind", json!("wasm")),
        ("/runtime/minimum_isolation", json!("P3")),
        ("/package/source_kind", json!("registry")),
        ("/state", json!("registered")),
        (
            "/capabilities/0/representations",
            json!({"artifact":["forged"]}),
        ),
    ] {
        transaction.execute_batch("SAVEPOINT forged_provider_receipt; DROP TRIGGER provider_registration_identity_immutable;").unwrap();
        let mut forged = original_value.clone();
        *forged.pointer_mut(pointer).unwrap() = replacement;
        transaction
            .execute(
                "UPDATE provider_registrations SET registration_json=?2 WHERE registration_id=?1",
                params![
                    binding.provider_registration_id.as_deref().unwrap(),
                    canonical_json(&forged).unwrap()
                ],
            )
            .unwrap();
        assert!(
            !verified_provider_receipt_and_compatibility(&transaction, &binding, TEST_TIME)
                .unwrap(),
            "forged receipt field {pointer} must not authorize launch"
        );
        transaction
            .execute_batch("ROLLBACK TO forged_provider_receipt; RELEASE forged_provider_receipt;")
            .unwrap();
    }
    let suite_version = first
        .capability_contract("artifact.hash", 1)
        .unwrap()
        .conformance
        .suite_version
        .as_deref()
        .unwrap();
    let contract = SnapshotContract {
        version: first
            .capability_contract("artifact.hash", 1)
            .unwrap()
            .version
            .clone(),
        content_hash: binding.contract_hash.clone().unwrap(),
    };
    binding.conformance_evidence_id = "cross-snapshot-pass".into();
    binding.conformance_status = "pass".into();
    binding.conformance_tested_at = Some(TEST_TIME.into());
    let mut evidence = json!({
        "schema_version": "0.1", "result_id": "cross-snapshot-pass",
        "provider_id": binding.principal_id, "provider_version": binding.provider_version,
        "provider_build_identity": {"kind": "build_hash", "value": build},
        "semantic_capability_ref": binding.capability,
        "semantic_contract_version": contract.version, "semantic_contract_hash": contract.content_hash,
        "conformance_suite": {"id": binding.conformance_suite_id, "version": suite_version,
            "hash": SUITE_HASH},
        "harness": {"id": "fixture-harness", "version": "1"},
        "result": "pass", "tests_total": 2, "tests_passed": 2, "tests_failed": 0,
        "executed_at": TEST_TIME, "expires_at": "2026-09-19T00:00:02Z"
    });
    binding.conformance_json = canonical_json(&evidence).unwrap();
    assert!(
        conformance_evidence_valid(
            &binding,
            &contract,
            "2026-09-19T00:00:01Z",
            Some(suite_version)
        )
        .unwrap()
    );
    evidence["tests_total"] = 0.into();
    evidence["tests_passed"] = 0.into();
    binding.conformance_json = canonical_json(&evidence).unwrap();
    assert!(
        !conformance_evidence_valid(
            &binding,
            &contract,
            "2026-09-19T00:00:01Z",
            Some(suite_version)
        )
        .unwrap()
    );
    evidence["tests_total"] = 2.into();
    evidence["tests_passed"] = 2.into();
    evidence["conformance_suite"]["version"] = "wrong".into();
    binding.conformance_json = canonical_json(&evidence).unwrap();
    assert!(
        !conformance_evidence_valid(
            &binding,
            &contract,
            "2026-09-19T00:00:01Z",
            Some(suite_version)
        )
        .unwrap()
    );
    evidence["conformance_suite"]["version"] = suite_version.into();
    evidence["expires_at"] = "2026-09-18T23:59:59Z".into();
    binding.conformance_json = canonical_json(&evidence).unwrap();
    assert!(
        !conformance_evidence_valid(
            &binding,
            &contract,
            "2026-09-19T00:00:01Z",
            Some(suite_version)
        )
        .unwrap()
    );
    transaction.rollback().unwrap();
    evidence["expires_at"] = "2026-09-19T00:00:02Z".into();
    manager
        .provider_store_writer()
        .unwrap()
        .record_evidence(
            binding.provider_registration_id.as_deref().unwrap(),
            &serde_json::to_vec(&evidence).unwrap(),
        )
        .unwrap();
    manager
        .provider_store_writer()
        .unwrap()
        .enable(
            binding.provider_registration_id.as_deref().unwrap(),
            TEST_TIME,
        )
        .unwrap();
    manager.create_task(&create("T-real-receipt")).unwrap();
    let trust_source_id: String = manager
        .connection
        .query_row(
            "SELECT admission_id FROM provider_trust_admissions
             WHERE registration_id=?1 ORDER BY revision DESC LIMIT 1",
            [binding.provider_registration_id.as_deref().unwrap()],
            |row| row.get(0),
        )
        .unwrap();
    let binding_receipt = canonical_json(&json!({
        "schema_version": "0.1",
        "binding_id": "binding-real-receipt",
        "attempt_id": "attempt-real-receipt",
        "task_id": "T-real-receipt",
        "semantic_program_hash": HASH,
        "registry_snapshot_id": second.snapshot_id(),
        "ir_version": "0.1",
        "node_id": "node-real",
        "capability": "artifact.hash@1",
        "capability_contract_hash": binding.contract_hash,
        "conformance_evidence_id": "cross-snapshot-pass",
        "provider_trust_source_id": trust_source_id,
        "provider": {
            "id": binding.principal_id,
            "version": binding.provider_version,
            "manifest_hash": binding.provider_manifest_hash,
            "package_or_build_hash": binding.provider_build_hash,
        },
        "attempt": 1,
        "policy_decision_refs": [],
        "authority": {"grant_refs": []},
        "execution_profile": {"profile_ref": "profile:test"},
        "placement": {"locality": "local"},
        "inputs": {},
        "outputs": {},
        "created_at": TEST_TIME,
    }))
    .unwrap();
    binding.binding_json = binding_receipt.clone();
    manager
        .connection
        .execute(
            "INSERT INTO execution_bindings(binding_id,attempt_id,task_id,semantic_program_hash,
         registry_snapshot_id,ir_version,node_id,capability,capability_contract_hash,
         provider_registration_id,provider_id,provider_version,provider_manifest_hash,
         provider_build_hash,attempt,policy_decision_refs_json,grant_refs_json,
         execution_profile_ref,placement_json,binding_json,created_at)
         VALUES ('binding-real-receipt','attempt-real-receipt','T-real-receipt',?1,?2,'0.1',
         'node-real','artifact.hash@1',?3,?4,?5,?6,?7,?8,1,'[]','[]','profile:test',
         '{\"locality\":\"local\"}',?9,?10)",
            params![
                HASH,
                second.snapshot_id(),
                binding.contract_hash,
                binding.provider_registration_id,
                binding.principal_id,
                binding.provider_version,
                binding.provider_manifest_hash,
                binding.provider_build_hash,
                binding_receipt,
                TEST_TIME
            ],
        )
        .unwrap();
    let first_trust_source: String = manager
        .connection
        .query_row(
            "SELECT trust_source_id FROM execution_binding_trust_markers WHERE binding_id='binding-real-receipt'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(first_trust_source.starts_with("sha256:"));
    {
        let transaction = manager.connection.transaction().unwrap();
        assert!(
            verified_provider_admission_from_binding(
                &transaction,
                "binding-real-receipt",
                &binding,
                TEST_TIME
            )
            .unwrap()
        );
        let original_receipt = binding.binding_json.clone();
        binding.binding_json = canonical_json(&json!({
            "conformance_evidence_id": "cross-snapshot-pass",
            "provider_trust_source_id": "decision:unrelated",
        }))
        .unwrap();
        assert!(
            !verified_provider_admission_from_binding(
                &transaction,
                "binding-real-receipt",
                &binding,
                TEST_TIME
            )
            .unwrap(),
            "a binding receipt must identify its durable trust source"
        );
        binding.binding_json = original_receipt;
        transaction.rollback().unwrap();
    }
    manager
        .provider_store_writer()
        .unwrap()
        .admit_trust(
            binding.provider_registration_id.as_deref().unwrap(),
            "decision:fixture-later-review",
            ProviderTrustStatus::ProjectReviewed,
            "review:fixture-owner",
            "2026-09-19T00:00:01Z",
        )
        .unwrap();
    {
        let transaction = manager.connection.transaction().unwrap();
        assert!(
            verified_provider_admission_from_binding(
                &transaction,
                "binding-real-receipt",
                &binding,
                TEST_TIME
            )
            .unwrap(),
            "a future trust decision must not invalidate the current binding early"
        );
        assert!(
            !verified_provider_admission_from_binding(
                &transaction,
                "binding-real-receipt",
                &binding,
                "2026-09-19T00:00:01Z"
            )
            .unwrap(),
            "the old binding expires when the new trust decision becomes effective"
        );
        transaction.rollback().unwrap();
    }
    let transaction = manager.connection.transaction().unwrap();
    assert_eq!(
        latest_conformance_evidence_id(
            &transaction,
            &BindingGrantCheck {
                task_id: "T-real-receipt",
                semantic_hash: HASH,
                node_id: "node-real",
                binding_id: "binding-real-receipt",
                attempt_id: "attempt-real-receipt",
                grant_refs_json: "[]",
                checked_at: "2026-09-19T00:00:01Z",
            },
            true
        )
        .unwrap()
        .as_deref(),
        Some("cross-snapshot-pass")
    );
    transaction.rollback().unwrap();
    let pinned = json!({"conformance_evidence_id":"cross-snapshot-pass"});
    manager
        .connection
        .execute(
            "INSERT INTO provider_conformance_evidence
             (evidence_id,registration_id,capability,contract_hash,suite_id,suite_hash,
              status,evidence_json,tested_at)
             VALUES ('unrelated-legacy-null-time',?1,?2,?3,'suite:unrelated',?4,
                     'pass','{}',NULL)",
            params![
                binding.provider_registration_id.as_deref().unwrap(),
                binding.capability,
                binding.contract_hash.as_deref().unwrap(),
                SUITE_HASH,
            ],
        )
        .unwrap();
    assert!(conformance_pin_matches(
        &pinned,
        "cross-snapshot-pass",
        true
    ));
    assert!(!conformance_pin_matches(
        &json!({}),
        "cross-snapshot-pass",
        true
    ));
    let latest = |manager: &mut TaskManager| {
        let transaction = manager.connection.transaction().unwrap();
        latest_conformance_evidence_id(
            &transaction,
            &BindingGrantCheck {
                task_id: "T-real-receipt",
                semantic_hash: HASH,
                node_id: "node-real",
                binding_id: "binding-real-receipt",
                attempt_id: "attempt-real-receipt",
                grant_refs_json: "[]",
                checked_at: "2026-09-19T00:00:01Z",
            },
            true,
        )
        .unwrap()
        .unwrap()
    };
    assert_eq!(latest(&mut manager), "cross-snapshot-pass");
    evidence["result_id"] = "renewed-pass".into();
    evidence["executed_at"] = "2026-09-19T00:00:00.500000Z".into();
    manager
        .provider_store_writer()
        .unwrap()
        .record_evidence(
            binding.provider_registration_id.as_deref().unwrap(),
            &serde_json::to_vec(&evidence).unwrap(),
        )
        .unwrap();
    assert_eq!(latest(&mut manager), "renewed-pass");
    assert!(!conformance_pin_matches(
        &pinned,
        &latest(&mut manager),
        true
    ));
    evidence["result_id"] = "later-failure".into();
    evidence["result"] = "fail".into();
    evidence["tests_passed"] = 1.into();
    evidence["tests_failed"] = 1.into();
    evidence["executed_at"] = "2026-09-19T00:00:00.750000Z".into();
    manager
        .provider_store_writer()
        .unwrap()
        .record_evidence(
            binding.provider_registration_id.as_deref().unwrap(),
            &serde_json::to_vec(&evidence).unwrap(),
        )
        .unwrap();
    assert_eq!(latest(&mut manager), "later-failure");
    assert!(!conformance_pin_matches(
        &pinned,
        &latest(&mut manager),
        true
    ));
    binding.registry_snapshot_id = second.snapshot_id().into();
    for (state, permitted) in [
        (aios_registry::SnapshotState::Deprecated, true),
        (aios_registry::SnapshotState::Quarantined, false),
        (aios_registry::SnapshotState::Revoked, false),
    ] {
        manager
            .registry_store_writer()
            .unwrap()
            .set_snapshot_state(first.snapshot_id(), state)
            .unwrap();
        let transaction = manager.connection.transaction().unwrap();
        assert_eq!(
            verified_provider_receipt_and_compatibility(&transaction, &binding, TEST_TIME).unwrap(),
            permitted
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn immutable_binding_pins_real_provider_evidence_across_retests() {
    use aios_contracts::{CapabilityContract, RegistrySnapshot, TypeContract};
    use aios_registry::{
        ProviderTrustStatus, RegistryBuildOptions, SemanticRegistry, SnapshotHashEntry,
    };

    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
    manager.initialize_provider_store().unwrap();
    prepare_completion_for_admission(&manager);
    let mut snapshot: RegistrySnapshot = serde_json::from_str(include_str!(
        "../../../examples/aios-ir/registry-snapshot.json"
    ))
    .unwrap();
    let types: Vec<TypeContract> = serde_json::from_str(include_str!(
        "../../../examples/aios-ir/type-contracts.json"
    ))
    .unwrap();
    let mut capabilities: Vec<CapabilityContract> = serde_json::from_str(include_str!(
        "../../../examples/aios-ir/capability-contracts.json"
    ))
    .unwrap();
    let mut completion = capabilities
        .iter()
        .find(|contract| contract.capability == "document.compose")
        .unwrap()
        .clone();
    completion.capability = "test.complete".into();
    completion.inputs.clear();
    completion.required_effect_classes.clear();
    completion.allowed_effect_classes = vec![aios_contracts::EffectClass::Pure];
    completion.required_authority_classes.clear();
    completion.allowed_authority_classes.clear();
    completion.conformance.suite_id = "suite:test".into();
    completion.conformance.suite_hash = Some(SUITE_HASH.into());
    let contract_hash = aios_registry::capability_contract_hash(&completion)
        .unwrap()
        .to_string();
    snapshot
        .capability_contracts
        .push(aios_contracts::ContractRef {
            id: completion.capability.clone(),
            version: completion.version.clone(),
            content_hash: contract_hash.clone(),
            source: None,
        });
    capabilities.push(completion);
    let view = |entry: &aios_contracts::ContractRef| SnapshotHashEntry {
        id: entry.id.clone(),
        version: entry.version.clone(),
        content_hash: entry.content_hash.clone(),
    };
    snapshot.snapshot_id = aios_registry::registry_snapshot_id(
        &snapshot.schema_version,
        &snapshot.type_contracts.iter().map(view).collect::<Vec<_>>(),
        &snapshot
            .capability_contracts
            .iter()
            .map(view)
            .collect::<Vec<_>>(),
    )
    .unwrap()
    .to_string();
    let registry = SemanticRegistry::from_records(
        snapshot,
        types,
        capabilities,
        RegistryBuildOptions::default(),
    )
    .unwrap();
    manager
        .registry_store_writer()
        .unwrap()
        .admit_registry(&registry)
        .unwrap();
    let cases: Value = serde_json::from_str(include_str!(
        "../../../examples/aios-ir/provider-conformance-cases.json"
    ))
    .unwrap();
    let mut manifest = cases[0]["provider"].clone();
    manifest["provides"][0]["contract"]["capability"] = "test.complete".into();
    manifest["provides"][0]["contract"]["version"] = "1.0".into();
    manifest["provides"][0]["contract"]["contract_hash"] = contract_hash.clone().into();
    manifest["provides"][0]["conformance"]["suite"] = "suite:test".into();
    manifest["provides"][0]["conformance"]["suite_hash"] = SUITE_HASH.into();
    manifest["provides"][0]["effect_classes"] = json!(["PURE"]);
    manifest["provides"][0]["authority"]["actions"] = json!([]);
    manifest["provides"][0]["authority"]["resource_classes"] = json!([]);
    let build = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let registration = manager
        .provider_store_writer()
        .unwrap()
        .register(
            &registry,
            &serde_json::to_vec(&manifest).unwrap(),
            build,
            ProviderTrustStatus::LocallyTrusted,
            TEST_TIME,
        )
        .unwrap();
    let evidence = |id: &str, result: &str, at: &str| {
        json!({
            "schema_version": "0.1", "result_id": id,
            "provider_id": registration.provider_id, "provider_version": registration.provider_version,
            "provider_build_identity": {"kind": "build_hash", "value": build},
            "semantic_capability_ref": "test.complete@1", "semantic_contract_version": "1.0",
            "semantic_contract_hash": contract_hash,
            "conformance_suite": {"id": "suite:test", "version": "0.1", "hash": SUITE_HASH},
            "harness": {"id": "fixture-harness", "version": "1"},
            "result": result, "tests_total": 2,
            "tests_passed": if result == "pass" {2} else {1},
            "tests_failed": i32::from(result != "pass"),
            "executed_at": at, "expires_at": "2026-09-20T00:00:00Z"
        })
    };
    let record = |manager: &mut TaskManager, id, result, at| {
        manager
            .provider_store_writer()
            .unwrap()
            .record_evidence(
                &registration.registration_id,
                &serde_json::to_vec(&evidence(id, result, at)).unwrap(),
            )
            .unwrap();
    };
    record(&mut manager, "E1", "pass", TEST_TIME);
    manager
        .provider_store_writer()
        .unwrap()
        .enable(&registration.registration_id, TEST_TIME)
        .unwrap();
    let mut validation: Value = serde_json::from_str(&manager.connection.query_row(
        "SELECT result_json FROM validation_results WHERE validation_result_id='validation-completion'",
        [], |row| row.get::<_, String>(0),
    ).unwrap()).unwrap();
    validation["registry_snapshot_id"] = registry.snapshot_id().into();
    manager.connection.execute("UPDATE validation_results SET registry_snapshot_id=?1,result_json=?2 WHERE validation_result_id='validation-completion'",
        params![registry.snapshot_id(), canonical_json(&validation).unwrap()]).unwrap();
    manager.connection.execute("UPDATE semantic_program_revisions SET registry_snapshot_id=?1 WHERE program_id='program-completion'",
        [registry.snapshot_id()]).unwrap();
    let base: Value = serde_json::from_str(
        &manager
            .connection
            .query_row(
                "SELECT binding_json FROM execution_bindings WHERE binding_id='binding-completion'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
    )
    .unwrap();
    let insert = |manager: &TaskManager, attempt: i64, pinned: &str| {
        let binding_id = format!("binding-real-{attempt}");
        let attempt_id = format!("attempt-real-{attempt}");
        let allocation_id = format!("allocation-real-{attempt}");
        let mut receipt = base.clone();
        receipt["binding_id"] = binding_id.clone().into();
        receipt["attempt_id"] = attempt_id.clone().into();
        receipt["attempt"] = attempt.into();
        receipt["registry_snapshot_id"] = registry.snapshot_id().into();
        receipt["capability_contract_hash"] = contract_hash.clone().into();
        receipt["conformance_evidence_id"] = pinned.into();
        receipt["provider_trust_source_id"] = registration.registration_id.clone().into();
        let created_at = match pinned {
            "E2" => "2026-09-19T00:00:00.600Z",
            "E5-unbounded" => "2026-09-19T00:00:00.980Z",
            _ => TEST_TIME,
        };
        receipt["created_at"] = created_at.into();
        receipt["provider"]["id"] = registration.provider_id.clone().into();
        receipt["provider"]["version"] = registration.provider_version.clone().into();
        receipt["provider"]["manifest_hash"] = registration.manifest_hash.clone().into();
        receipt["provider"]["package_or_build_hash"] = registration.build_hash.clone().into();
        receipt["outputs"]["report"]["allocation_ref"] = allocation_id.clone().into();
        let receipt_json = canonical_json(&receipt).unwrap();
        // Formatting is not receipt identity; the typed projection is.
        let receipt_json = if attempt == 14 {
            format!(" \n{receipt_json}")
        } else {
            receipt_json
        };
        manager.connection.execute(
            "INSERT INTO execution_bindings(binding_id,attempt_id,task_id,semantic_program_hash,
             registry_snapshot_id,ir_version,node_id,capability,capability_contract_hash,
             provider_registration_id,provider_id,provider_version,provider_manifest_hash,
             provider_build_hash,attempt,policy_decision_refs_json,grant_refs_json,
             execution_profile_ref,placement_json,binding_json,created_at)
             VALUES (?1,?2,'T-completion',?3,?4,'0.1','node-completion','test.complete@1',
             ?5,?6,?7,?8,?9,?10,?11,'[]','[]','profile:test','{\"locality\":\"local\"}',?12,?13)",
            params![binding_id,attempt_id,HASH,registry.snapshot_id(),contract_hash,
                registration.registration_id,registration.provider_id,registration.provider_version,
                 registration.manifest_hash,registration.build_hash,attempt,receipt_json,created_at],
        ).unwrap();
        manager.connection.execute(
            "INSERT INTO artifact_output_allocations(allocation_id,task_id,semantic_program_hash,node_id,
             binding_id,attempt_id,output_port,expected_semantic_type,sensitivity,retention,state,created_at,expires_at)
             VALUES (?1,'T-completion',?2,'node-completion',?3,?4,'report','artifact.report@1',
             'local','task','ALLOCATED',?5,'2026-09-20T00:00:00Z')",
            params![allocation_id,HASH,binding_id,attempt_id,TEST_TIME],
        ).unwrap();
        binding_id
    };
    let valid =
        |manager: &mut TaskManager, binding_id: &str, attempt_id: &str, checked_at: &str| {
            let transaction = manager.connection.transaction().unwrap();
            binding_grants_valid(
                &transaction,
                &BindingGrantCheck {
                    task_id: "T-completion",
                    semantic_hash: HASH,
                    node_id: "node-completion",
                    binding_id,
                    attempt_id,
                    grant_refs_json: "[]",
                    checked_at,
                },
            )
            .unwrap()
        };
    let first = insert(&manager, 2, "E1");
    assert!(valid(
        &mut manager,
        &first,
        "attempt-real-2",
        "2026-09-19T00:00:00.250Z"
    ));
    let first_receipt: Value = serde_json::from_str(
        &manager
            .connection
            .query_row(
                "SELECT binding_json FROM execution_bindings WHERE binding_id=?1",
                [&first],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
    )
    .unwrap();
    // A globally stored contract is insufficient when the selected snapshot
    // never admitted that contract. The failed insert must publish no markers.
    manager
        .connection
        .execute_batch(
            "SAVEPOINT missing_selected_contract;
             DROP TRIGGER immutable_registry_snapshot_entries_delete;",
        )
        .unwrap();
    manager
        .connection
        .execute(
            "DELETE FROM registry_snapshot_entries
             WHERE snapshot_id=?1 AND contract_class='capability'
             AND semantic_id='test.complete'",
            [registry.snapshot_id()],
        )
        .unwrap();
    let mut absent_receipt = first_receipt.clone();
    absent_receipt["binding_id"] = "binding-absent-selected-contract".into();
    absent_receipt["attempt_id"] = "attempt-absent-selected-contract".into();
    absent_receipt["attempt"] = 99.into();
    let missing_contract_error = manager
        .connection
        .execute(
            "INSERT INTO execution_bindings
         (binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,
          ir_version,node_id,capability,capability_contract_hash,provider_registration_id,
          provider_id,provider_version,provider_manifest_hash,provider_build_hash,
          attempt,policy_decision_refs_json,grant_refs_json,execution_profile_ref,
          placement_json,binding_json,created_at)
         SELECT 'binding-absent-selected-contract','attempt-absent-selected-contract',
                task_id,semantic_program_hash,registry_snapshot_id,ir_version,node_id,
                capability,capability_contract_hash,provider_registration_id,provider_id,
                provider_version,provider_manifest_hash,provider_build_hash,99,
                policy_decision_refs_json,grant_refs_json,execution_profile_ref,
                placement_json,?1,created_at
         FROM execution_bindings WHERE binding_id=?2",
            params![canonical_json(&absent_receipt).unwrap(), first],
        )
        .unwrap_err();
    assert!(
        missing_contract_error
            .to_string()
            .contains("binding conformance evidence was not admitted"),
        "{missing_contract_error}"
    );
    for table in [
        "execution_bindings",
        "execution_binding_admission_markers",
        "execution_binding_trust_markers",
        "execution_binding_enablement_markers",
    ] {
        let count: i64 = manager.connection.query_row(
            &format!("SELECT COUNT(*) FROM {table} WHERE binding_id='binding-absent-selected-contract'"),
            [],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 0, "{table}");
    }
    manager
        .connection
        .execute_batch("ROLLBACK TO missing_selected_contract; RELEASE missing_selected_contract")
        .unwrap();
    // Even a hash/version row selected under a different semantic ID cannot
    // authenticate this provider's claim. This catches accidental reliance on
    // the global contract hash without comparing the claimed capability name.
    manager
        .connection
        .execute_batch(
            "SAVEPOINT mismatched_selected_name;
         DROP TRIGGER immutable_semantic_capability_contracts_update;
         DROP TRIGGER immutable_registry_snapshot_entries_update;",
        )
        .unwrap();
    manager
        .connection
        .execute(
            "UPDATE semantic_capability_contracts SET semantic_id='other.name'
         WHERE content_hash=?1",
            [&contract_hash],
        )
        .unwrap();
    manager
        .connection
        .execute(
            "UPDATE registry_snapshot_entries SET semantic_id='other.name'
         WHERE snapshot_id=?1 AND contract_class='capability'
         AND semantic_id='test.complete'",
            [registry.snapshot_id()],
        )
        .unwrap();
    let mut wrong_name_receipt = first_receipt.clone();
    wrong_name_receipt["binding_id"] = "binding-wrong-selected-name".into();
    wrong_name_receipt["attempt_id"] = "attempt-wrong-selected-name".into();
    wrong_name_receipt["attempt"] = 100.into();
    let wrong_name_error = manager
        .connection
        .execute(
            "INSERT INTO execution_bindings
         (binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,
          ir_version,node_id,capability,capability_contract_hash,provider_registration_id,
          provider_id,provider_version,provider_manifest_hash,provider_build_hash,
          attempt,policy_decision_refs_json,grant_refs_json,execution_profile_ref,
          placement_json,binding_json,created_at)
         SELECT 'binding-wrong-selected-name','attempt-wrong-selected-name',
                task_id,semantic_program_hash,registry_snapshot_id,ir_version,node_id,
                capability,capability_contract_hash,provider_registration_id,provider_id,
                provider_version,provider_manifest_hash,provider_build_hash,100,
                policy_decision_refs_json,grant_refs_json,execution_profile_ref,
                placement_json,?1,created_at
         FROM execution_bindings WHERE binding_id=?2",
            params![canonical_json(&wrong_name_receipt).unwrap(), first],
        )
        .unwrap_err();
    assert!(
        wrong_name_error
            .to_string()
            .contains("binding conformance evidence was not admitted"),
        "{wrong_name_error}"
    );
    for table in [
        "execution_bindings",
        "execution_binding_admission_markers",
        "execution_binding_trust_markers",
        "execution_binding_enablement_markers",
    ] {
        let count: i64 = manager
            .connection
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM {table} WHERE binding_id='binding-wrong-selected-name'"
                ),
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0, "{table}");
    }
    manager
        .connection
        .execute_batch("ROLLBACK TO mismatched_selected_name; RELEASE mismatched_selected_name")
        .unwrap();
    let original_manifest: Value = serde_json::from_str(
        &manager
            .connection
            .query_row(
                "SELECT manifest_json FROM provider_manifest_payloads WHERE registration_id=?1",
                [&registration.registration_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
    )
    .unwrap();
    for (suffix, attempt, hostile_build) in [
        (
            "invalid-schema",
            101,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ),
        (
            "duplicate-claim",
            102,
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        ),
    ] {
        manager
            .connection
            .execute_batch("SAVEPOINT invalid_admission_manifest")
            .unwrap();
        let mut hostile = original_manifest.clone();
        if suffix == "invalid-schema" {
            hostile["forbidden_property"] = json!(true);
        } else {
            let mut repeated = hostile["provides"][0].clone();
            repeated["conformance"]["suite"] = json!("different-suite");
            hostile["provides"].as_array_mut().unwrap().push(repeated);
        }
        let hostile_manifest_json = canonical_json(&hostile).unwrap();
        let hostile_manifest_hash = provider_identity_digest(
            b"AIOS-PROVIDER-MANIFEST\0v0.1\0",
            hostile_manifest_json.as_bytes(),
        );
        let hostile_registration_id = provider_identity_digest(
            b"AIOS-PROVIDER-REGISTRATION\0v0.1\0",
            format!(
                "{}\0{}\0{}\0{hostile_build}",
                registration.provider_id, registration.provider_version, hostile_manifest_hash
            )
            .as_bytes(),
        );
        manager
            .connection
            .execute(
                "INSERT INTO provider_registrations
             (registration_id,provider_id,provider_version,manifest_hash,package_content_hash,
              registry_snapshot_id,state,trust_status,registration_json,registered_at)
             VALUES (?1,?2,?3,?4,?5,?6,'disabled','locally-trusted',
                     '{\"trust\":{\"status\":\"locally-trusted\"}}',?7)",
                params![
                    hostile_registration_id,
                    registration.provider_id,
                    registration.provider_version,
                    hostile_manifest_hash,
                    hostile_build,
                    registry.snapshot_id(),
                    TEST_TIME
                ],
            )
            .unwrap();
        manager.connection.execute(
            "INSERT INTO provider_manifest_payloads(registration_id,manifest_json) VALUES (?1,?2)",
            params![hostile_registration_id,hostile_manifest_json],
        ).unwrap();
        let hostile_evidence_id = format!("evidence-{suffix}");
        let mut hostile_evidence = evidence(&hostile_evidence_id, "pass", TEST_TIME);
        hostile_evidence["provider_build_identity"]["value"] = hostile_build.into();
        manager
            .connection
            .execute(
                "INSERT INTO provider_conformance_evidence
             (evidence_id,registration_id,capability,contract_hash,suite_id,suite_hash,
              status,evidence_json,tested_at)
             VALUES (?1,?2,'test.complete@1',?3,'suite:test',?4,'pass',?5,?6)",
                params![
                    hostile_evidence_id,
                    hostile_registration_id,
                    contract_hash,
                    SUITE_HASH,
                    canonical_json(&hostile_evidence).unwrap(),
                    TEST_TIME
                ],
            )
            .unwrap();
        manager.connection.execute(
            "UPDATE provider_registrations SET state='registered',updated_at=?1 WHERE registration_id=?2",
            params![TEST_TIME,hostile_registration_id],
        ).unwrap();
        let binding_id = format!("binding-{suffix}");
        let attempt_id = format!("attempt-{suffix}");
        let mut hostile_receipt = first_receipt.clone();
        hostile_receipt["binding_id"] = binding_id.clone().into();
        hostile_receipt["attempt_id"] = attempt_id.clone().into();
        hostile_receipt["attempt"] = attempt.into();
        hostile_receipt["conformance_evidence_id"] = hostile_evidence_id.into();
        hostile_receipt["provider_trust_source_id"] = hostile_registration_id.clone().into();
        hostile_receipt["provider"]["manifest_hash"] = hostile_manifest_hash.clone().into();
        hostile_receipt["provider"]["package_or_build_hash"] = hostile_build.into();
        let error = manager
            .connection
            .execute(
                "INSERT INTO execution_bindings
             (binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,
              ir_version,node_id,capability,capability_contract_hash,provider_registration_id,
              provider_id,provider_version,provider_manifest_hash,provider_build_hash,
              attempt,policy_decision_refs_json,grant_refs_json,execution_profile_ref,
              placement_json,binding_json,created_at)
             SELECT ?1,?2,task_id,semantic_program_hash,registry_snapshot_id,ir_version,node_id,
                    capability,capability_contract_hash,?3,provider_id,
                    provider_version,?4,?5,?6,
                    policy_decision_refs_json,grant_refs_json,execution_profile_ref,
                    placement_json,?7,created_at
             FROM execution_bindings WHERE binding_id=?8",
                params![
                    binding_id,
                    attempt_id,
                    hostile_registration_id,
                    hostile_manifest_hash,
                    hostile_build,
                    attempt,
                    canonical_json(&hostile_receipt).unwrap(),
                    first
                ],
            )
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("binding conformance evidence was not admitted"),
            "{suffix}: {error}"
        );
        for table in [
            "execution_bindings",
            "execution_binding_admission_markers",
            "execution_binding_trust_markers",
            "execution_binding_enablement_markers",
        ] {
            let count: i64 = manager
                .connection
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE binding_id=?1"),
                    [&binding_id],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 0, "{suffix}: {table}");
        }
        manager
            .connection
            .execute_batch(
                "ROLLBACK TO invalid_admission_manifest; RELEASE invalid_admission_manifest",
            )
            .unwrap();
    }
    for case in [
        "valid-control",
        "offset-equivalent-tie",
        "wrong-major",
        "duplicate-expiry",
        "nul-prefix-expiry",
        "non-rfc-expiry",
        "malformed-payload",
        "non-rfc-tested-at",
        "result-id",
        "provider-id",
        "provider-version",
        "build-hash",
        "contract-version",
        "suite-version",
        "status",
        "counts",
        "executed-at",
    ] {
        manager
            .connection
            .execute_batch("SAVEPOINT adversarial_evidence_case")
            .unwrap();
        let evidence_id = format!("E-{case}");
        // Each hostile row is uniquely latest at binding creation; an E1 tie
        // must not mask the parser or projection guard under test.
        let evidence_time = "2026-09-19T00:00:00.100Z";
        let binding_time = "2026-09-19T00:00:00.250Z";
        let mut payload = evidence(&evidence_id, "pass", evidence_time);
        let capability = if case == "wrong-major" {
            payload["semantic_capability_ref"] = "test.complete@2".into();
            "test.complete@2"
        } else {
            "test.complete@1"
        };
        let tested_at = if case == "non-rfc-tested-at" {
            payload["executed_at"] = "2026-09-19 00:00:00.100".into();
            "2026-09-19 00:00:00.100"
        } else {
            evidence_time
        };
        match case {
            "result-id" => payload["result_id"] = "E-forged".into(),
            "provider-id" => payload["provider_id"] = "provider:forged".into(),
            "provider-version" => payload["provider_version"] = "9.9.9".into(),
            "build-hash" => payload["provider_build_identity"]["value"] = "build:forged".into(),
            "contract-version" => payload["semantic_contract_version"] = "2.0".into(),
            "suite-version" => payload["conformance_suite"]["version"] = "9.9".into(),
            "status" => payload["result"] = "fail".into(),
            "counts" => payload["tests_passed"] = 1.into(),
            "executed-at" => payload["executed_at"] = "2026-09-19T00:00:00.200Z".into(),
            _ => {}
        }
        let mut raw = canonical_json(&payload).unwrap();
        let expiry = "\"expires_at\":\"2026-09-20T00:00:00Z\"";
        raw = match case {
            "duplicate-expiry" => raw.replacen(
                expiry,
                "\"expires_at\":\"2026-09-20T00:00:00Z\",\"expires_at\":null",
                1,
            ),
            "nul-prefix-expiry" => raw.replacen(
                expiry,
                "\"expires_at\\u0000x\":null,\"expires_at\":\"2026-09-18T00:00:00Z\"",
                1,
            ),
            "non-rfc-expiry" => raw.replacen(expiry, "\"expires_at\":\"2026-09-24 00:00:00\"", 1),
            "malformed-payload" => "{}".into(),
            _ => raw,
        };
        manager
            .connection
            .execute(
                "INSERT INTO provider_conformance_evidence
             (evidence_id,registration_id,capability,contract_hash,suite_id,suite_hash,
              status,evidence_json,tested_at)
             SELECT ?1,registration_id,?2,contract_hash,suite_id,suite_hash,
                    status,?3,?4 FROM provider_conformance_evidence WHERE evidence_id='E1'",
                params![evidence_id, capability, raw, tested_at],
            )
            .unwrap();
        if case == "offset-equivalent-tie" {
            let offset_time = "2026-09-19T01:00:00.100+01:00";
            manager
                .connection
                .execute(
                    "INSERT INTO provider_conformance_evidence
                     (evidence_id,registration_id,capability,contract_hash,suite_id,suite_hash,
                      status,evidence_json,tested_at)
                     SELECT 'E-offset-tie',registration_id,capability,contract_hash,suite_id,
                            suite_hash,status,?1,?2
                     FROM provider_conformance_evidence WHERE evidence_id='E1'",
                    params![
                        canonical_json(&evidence("E-offset-tie", "pass", offset_time)).unwrap(),
                        offset_time
                    ],
                )
                .unwrap();
        }
        let mut receipt = first_receipt.clone();
        receipt["binding_id"] = "binding-real-5".into();
        receipt["attempt_id"] = "attempt-real-5".into();
        receipt["attempt"] = 5.into();
        receipt["capability"] = capability.into();
        receipt["conformance_evidence_id"] = evidence_id.into();
        receipt["created_at"] = binding_time.into();
        let insertion = manager.connection.execute(
            "INSERT INTO execution_bindings
             (binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,
              ir_version,node_id,capability,capability_contract_hash,provider_registration_id,
              provider_id,provider_version,provider_manifest_hash,provider_build_hash,attempt,
              policy_decision_refs_json,grant_refs_json,execution_profile_ref,placement_json,
              binding_json,created_at)
             SELECT 'binding-real-5','attempt-real-5',task_id,semantic_program_hash,
              registry_snapshot_id,ir_version,node_id,?2,capability_contract_hash,
              provider_registration_id,provider_id,provider_version,provider_manifest_hash,
              provider_build_hash,5,policy_decision_refs_json,grant_refs_json,
              execution_profile_ref,placement_json,?3,?4
             FROM execution_bindings WHERE binding_id=?1",
            params![
                first,
                capability,
                canonical_json(&receipt).unwrap(),
                binding_time
            ],
        );
        if case == "valid-control" {
            insertion.unwrap();
            for table in [
                "execution_bindings",
                "execution_binding_admission_markers",
                "execution_binding_trust_markers",
                "execution_binding_enablement_markers",
            ] {
                let count: i64 = manager
                    .connection
                    .query_row(
                        &format!("SELECT COUNT(*) FROM {table} WHERE binding_id='binding-real-5'"),
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(count, 1, "valid control did not create {table}");
            }
            manager
                .connection
                .execute_batch(
                    "ROLLBACK TO adversarial_evidence_case; RELEASE adversarial_evidence_case",
                )
                .unwrap();
            continue;
        }
        let error = insertion.unwrap_err().to_string();
        assert!(
            error.contains("binding conformance evidence")
                || error.contains("binding predates pinned conformance evidence"),
            "{case}: {error}"
        );
        for table in [
            "execution_bindings",
            "execution_binding_admission_markers",
            "execution_binding_trust_markers",
            "execution_binding_enablement_markers",
        ] {
            let count: i64 = manager
                .connection
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE binding_id='binding-real-5'"),
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 0, "{case} retained {table}");
        }
        manager
            .connection
            .execute_batch(
                "ROLLBACK TO adversarial_evidence_case; RELEASE adversarial_evidence_case",
            )
            .unwrap();
    }
    manager
        .connection
        .execute(
            "INSERT INTO provider_conformance_evidence
         (evidence_id,registration_id,capability,contract_hash,suite_id,suite_hash,
          status,evidence_json,tested_at)
         SELECT 'E-other',registration_id,capability,contract_hash,'suite:other',
                suite_hash,
                status,json_set(evidence_json,'$.result_id','E-other',
                                '$.conformance_suite.id','suite:other'),
                tested_at
         FROM provider_conformance_evidence WHERE evidence_id='E1'",
            [],
        )
        .unwrap();
    manager.connection.execute(
        "INSERT INTO provider_conformance_evidence
         (evidence_id,registration_id,capability,contract_hash,suite_id,suite_hash,
          status,evidence_json,tested_at)
         SELECT 'E-other-hash',registration_id,capability,contract_hash,suite_id,
                'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
                status,json_set(evidence_json,'$.result_id','E-other-hash',
                                '$.conformance_suite.hash',
                                'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'),
                tested_at
         FROM provider_conformance_evidence WHERE evidence_id='E1'",
        [],
    ).unwrap();
    for mismatch in [
        "id",
        "version",
        "manifest",
        "build",
        "null-manifest",
        "null-build",
        "missing-manifest",
        "duplicate-provider-id",
        "duplicate-provider-object",
        "schema-version",
        "binding-id",
        "attempt-id",
        "task-id",
        "semantic-program-hash",
        "registry-snapshot-id",
        "ir-version",
        "node-id",
        "capability",
        "contract-hash",
        "attempt",
        "created-at",
        "policy-decisions",
        "grant-refs",
        "execution-profile",
        "placement",
        "inputs",
        "outputs",
        "suite-id",
        "suite-hash",
    ] {
        let mut receipt = first_receipt.clone();
        receipt["binding_id"] = "binding-real-5".into();
        receipt["attempt_id"] = "attempt-real-5".into();
        receipt["attempt"] = 5.into();
        let mut projected_id = registration.provider_id.clone();
        let mut projected_version = registration.provider_version.clone();
        let mut projected_manifest = Some(registration.manifest_hash.clone());
        let mut projected_build = Some(registration.build_hash.clone());
        match mismatch {
            "id" => projected_id = "provider:forged".into(),
            "version" => projected_version = "9.9.9".into(),
            "manifest" => projected_manifest = Some("manifest:forged".into()),
            "build" => projected_build = Some("build:forged".into()),
            "null-manifest" => projected_manifest = None,
            "null-build" => projected_build = None,
            "missing-manifest" => {
                receipt["provider"]
                    .as_object_mut()
                    .unwrap()
                    .remove("manifest_hash");
            }
            "duplicate-provider-id" | "duplicate-provider-object" => {
                receipt["provider"]["id"] = "provider:forged".into();
            }
            "schema-version" => receipt["schema_version"] = "wrong".into(),
            "binding-id" => receipt["binding_id"] = "binding:wrong".into(),
            "attempt-id" => receipt["attempt_id"] = "attempt:wrong".into(),
            "task-id" => receipt["task_id"] = "task:wrong".into(),
            "semantic-program-hash" => receipt["semantic_program_hash"] = "sha256:wrong".into(),
            "registry-snapshot-id" => receipt["registry_snapshot_id"] = "snapshot:wrong".into(),
            "ir-version" => receipt["ir_version"] = "wrong".into(),
            "node-id" => receipt["node_id"] = "node:wrong".into(),
            "capability" => receipt["capability"] = "wrong@1".into(),
            "contract-hash" => receipt["capability_contract_hash"] = "sha256:wrong".into(),
            "attempt" => receipt["attempt"] = "5".into(),
            "created-at" => receipt["created_at"] = "2026-09-19T00:00:00.300Z".into(),
            "policy-decisions" => receipt["policy_decision_refs"] = json!(["wrong"]),
            "grant-refs" => receipt["authority"]["grant_refs"] = json!(["wrong"]),
            "execution-profile" => {
                receipt["execution_profile"]["profile_ref"] = "wrong".into();
            }
            "placement" => receipt["placement"] = json!({"locality":"wrong"}),
            "inputs" => receipt["inputs"] = json!([]),
            "outputs" => receipt["outputs"] = json!([]),
            "suite-id" => receipt["conformance_evidence_id"] = "E-other".into(),
            "suite-hash" => receipt["conformance_evidence_id"] = "E-other-hash".into(),
            _ => unreachable!(),
        }
        let mut binding_json = canonical_json(&receipt).unwrap();
        if mismatch == "duplicate-provider-id" {
            binding_json = binding_json.replacen(
                "\"provider\":{",
                &format!("\"provider\":{{\"id\":\"{}\",", registration.provider_id),
                1,
            );
        } else if mismatch == "duplicate-provider-object" {
            binding_json = binding_json.replacen(
                "\"provider\":",
                &format!(
                    "\"provider\":{},\"provider\":",
                    canonical_json(&first_receipt["provider"]).unwrap()
                ),
                1,
            );
        }
        let error = manager
            .connection
            .execute(
                "INSERT INTO execution_bindings
             (binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,
              ir_version,node_id,capability,capability_contract_hash,provider_registration_id,
              provider_id,provider_version,provider_manifest_hash,provider_build_hash,attempt,
              policy_decision_refs_json,grant_refs_json,execution_profile_ref,placement_json,
              binding_json,created_at)
             SELECT 'binding-real-5','attempt-real-5',task_id,semantic_program_hash,
              registry_snapshot_id,ir_version,node_id,capability,capability_contract_hash,
              provider_registration_id,?2,?3,?4,?5,5,policy_decision_refs_json,
              grant_refs_json,execution_profile_ref,placement_json,?6,created_at
             FROM execution_bindings WHERE binding_id=?1",
                params![
                    first,
                    projected_id,
                    projected_version,
                    projected_manifest,
                    projected_build,
                    binding_json
                ],
            )
            .unwrap_err()
            .to_string();
        let expected_rejection = if matches!(mismatch, "suite-id" | "suite-hash") {
            error.contains("binding conformance evidence was not admitted")
        } else if matches!(
            mismatch,
            "duplicate-provider-id" | "duplicate-provider-object"
        ) {
            // Both guards reject the duplicate; SQLite does not promise trigger order.
            error.contains("binding provider identity")
                || error.contains("binding predates provider trust admission")
        } else {
            error.contains("binding provider identity")
        };
        assert!(expected_rejection, "{mismatch}: {error}");
        for table in [
            "execution_bindings",
            "execution_binding_admission_markers",
            "execution_binding_trust_markers",
            "execution_binding_enablement_markers",
        ] {
            let count: i64 = manager
                .connection
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE binding_id='binding-real-5'"),
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 0, "{mismatch} retained {table}");
        }
    }
    let identity_retry = insert(&manager, 5, "E1");
    assert!(valid(
        &mut manager,
        &identity_retry,
        "attempt-real-5",
        "2026-09-19T00:00:00.250Z"
    ));
    // The baseline permits retained evidence without a suite ID. That older
    // row cannot win latest Stage-1 evidence selection or abort the reader.
    manager
        .connection
        .execute(
            "INSERT INTO provider_conformance_evidence (
            evidence_id,registration_id,capability,contract_hash,suite_id,suite_hash,
            status,evidence_json,tested_at)
         SELECT 'legacy-null-suite',registration_id,capability,contract_hash,NULL,suite_hash,
                status,evidence_json,'2026-09-19T00:00:00.200Z'
         FROM provider_conformance_evidence WHERE evidence_id='E1'",
            [],
        )
        .unwrap();
    assert!(valid(
        &mut manager,
        &first,
        "attempt-real-2",
        "2026-09-19T00:00:00.250Z"
    ));
    let null_suite_error = manager
        .connection
        .execute(
            "INSERT INTO execution_bindings
         (binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,
          ir_version,node_id,capability,capability_contract_hash,provider_registration_id,
          provider_id,provider_version,provider_manifest_hash,provider_build_hash,attempt,
          policy_decision_refs_json,grant_refs_json,execution_profile_ref,placement_json,
          binding_json,created_at)
         SELECT 'binding-null-suite','attempt-null-suite',task_id,semantic_program_hash,
                registry_snapshot_id,ir_version,node_id,capability,capability_contract_hash,
                provider_registration_id,provider_id,provider_version,provider_manifest_hash,
                provider_build_hash,15,policy_decision_refs_json,grant_refs_json,
                execution_profile_ref,placement_json,
                json_set(binding_json,'$.binding_id','binding-null-suite',
                                      '$.attempt_id','attempt-null-suite','$.attempt',15,
                                      '$.conformance_evidence_id','legacy-null-suite'),
                created_at
         FROM execution_bindings WHERE binding_id=?1",
            [&first],
        )
        .unwrap_err()
        .to_string();
    assert!(
        null_suite_error.contains("binding conformance evidence is not latest"),
        "{null_suite_error}"
    );
    manager
        .connection
        .execute_batch("PRAGMA foreign_keys=ON; PRAGMA recursive_triggers=OFF;")
        .unwrap();
    // A result recorded later cannot retroactively authenticate a binding.
    // The trigger checks row existence at the instant the immutable row is inserted.
    let premature_error = manager
        .connection
        .execute(
            "INSERT INTO execution_bindings (
           binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,
           ir_version,node_id,capability,capability_contract_hash,provider_registration_id,
           provider_id,provider_version,provider_manifest_hash,provider_build_hash,attempt,
           policy_decision_refs_json,grant_refs_json,execution_profile_ref,placement_json,
           binding_json,created_at)
         SELECT 'binding-premature','attempt-premature',task_id,semantic_program_hash,
           registry_snapshot_id,ir_version,node_id,capability,capability_contract_hash,
           provider_registration_id,provider_id,provider_version,provider_manifest_hash,
           provider_build_hash,98,policy_decision_refs_json,grant_refs_json,
           execution_profile_ref,placement_json,
            json_set(binding_json,'$.binding_id','binding-premature',
                                  '$.attempt_id','attempt-premature',
                                  '$.attempt',98,
                                  '$.conformance_evidence_id','E2',
                                  '$.created_at','2026-09-19T00:00:00.600Z'),
           '2026-09-19T00:00:00.600Z'
         FROM execution_bindings WHERE binding_id=?1",
            [&first],
        )
        .unwrap_err()
        .to_string();
    assert!(
        premature_error.contains("binding conformance evidence is not latest"),
        "{premature_error}"
    );
    assert!(
        manager
            .connection
            .execute(
                "INSERT OR REPLACE INTO execution_bindings
         SELECT * FROM execution_bindings WHERE binding_id=?1 AND 1=1",
                [&first],
            )
            .is_err()
    );
    assert!(
        manager
            .connection
            .execute(
                "INSERT OR REPLACE INTO execution_bindings (
           binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,
           ir_version,node_id,capability,capability_contract_hash,provider_registration_id,
           provider_id,provider_version,provider_manifest_hash,provider_build_hash,attempt,
           policy_decision_refs_json,grant_refs_json,execution_profile_ref,placement_json,
           binding_json,created_at)
         SELECT 'binding-replaced-attempt',attempt_id,task_id,semantic_program_hash,
           registry_snapshot_id,ir_version,node_id,capability,capability_contract_hash,
           provider_registration_id,provider_id,provider_version,provider_manifest_hash,
           provider_build_hash,99,policy_decision_refs_json,grant_refs_json,
           execution_profile_ref,placement_json,binding_json,created_at
         FROM execution_bindings WHERE binding_id=?1",
                [&first],
            )
            .is_err()
    );
    assert_eq!(manager.connection.query_row(
        "SELECT COUNT(*) FROM execution_bindings WHERE binding_id=?1 AND attempt_id='attempt-real-2'",
        [&first], |row| row.get::<_, i64>(0),
    ).unwrap(), 1);
    let reopened_copy = tempdir().unwrap();
    let copied_path = reopened_copy.path().join("bindings.sqlite3");
    manager
        .connection
        .execute("VACUUM INTO ?1", [copied_path.to_str().unwrap()])
        .unwrap();
    let reopened = Connection::open(copied_path).unwrap();
    assert_eq!(reopened.query_row(
        "SELECT COUNT(*) FROM execution_bindings WHERE binding_id=?1 AND attempt_id='attempt-real-2'",
        [&first], |row| row.get::<_, i64>(0),
    ).unwrap(), 1);
    // Emulate a stamped 0013 database written before the insert guard and
    // admission marker existed. This immutable binding predicts absent E2.
    manager
        .connection
        .execute_batch(
            "DROP TRIGGER execution_binding_evidence_present_at_insert;
         DROP TRIGGER execution_binding_evidence_not_future;
         DROP TRIGGER execution_binding_evidence_unexpired_at_insert;
         DROP TRIGGER execution_binding_evidence_latest_at_insert;
         DROP TRIGGER execution_binding_admission_marker_insert;
         DROP TABLE execution_binding_admission_markers;",
        )
        .unwrap();
    let historical = insert(&manager, 98, "E2");
    manager
        .connection
        .execute_batch(include_str!(
            "../../../specs/persistence-v0.1-0013-provider-registry.sql"
        ))
        .unwrap();
    manager.provider_store_writer().unwrap();
    let old_markers: i64 = manager
        .connection
        .query_row(
            "SELECT COUNT(*) FROM execution_binding_admission_markers WHERE binding_id=?1",
            [&historical],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(old_markers, 0);
    for attack in [
        format!(
            "INSERT INTO execution_binding_admission_markers(binding_id,conformance_evidence_id) VALUES ('{historical}','E2')"
        ),
        format!(
            "INSERT OR REPLACE INTO execution_binding_admission_markers(binding_id,conformance_evidence_id) VALUES ('{historical}','E2')"
        ),
    ] {
        assert!(
            manager.connection.execute_batch(&attack).is_err(),
            "{attack}"
        );
    }
    record(&mut manager, "E2", "pass", "2026-09-19T00:00:00.500Z");
    assert!(!valid(
        &mut manager,
        &historical,
        "attempt-real-98",
        "2026-09-19T00:00:00.750Z"
    ));
    assert!(!valid(
        &mut manager,
        &first,
        "attempt-real-2",
        "2026-09-19T00:00:00.750Z"
    ));
    manager
        .provider_store_writer()
        .unwrap()
        .disable(&registration.registration_id, "2026-09-19T00:00:00.200Z")
        .unwrap();
    manager
        .provider_store_writer()
        .unwrap()
        .enable(&registration.registration_id, "2026-09-19T00:00:00.500Z")
        .unwrap();
    let backdated_enablement = manager.connection.execute(
        "INSERT INTO execution_bindings (
           binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,
           ir_version,node_id,capability,capability_contract_hash,provider_registration_id,
           provider_id,provider_version,provider_manifest_hash,provider_build_hash,attempt,
           policy_decision_refs_json,grant_refs_json,execution_profile_ref,placement_json,
           binding_json,created_at)
         SELECT 'binding-backdated','attempt-backdated',task_id,semantic_program_hash,
           registry_snapshot_id,ir_version,node_id,capability,capability_contract_hash,
           provider_registration_id,provider_id,provider_version,provider_manifest_hash,
           provider_build_hash,4,policy_decision_refs_json,grant_refs_json,
           execution_profile_ref,placement_json,
           json_set(binding_json,'$.binding_id','binding-backdated',
                    '$.attempt_id','attempt-backdated','$.attempt',4,
                    '$.created_at','2026-09-19T00:00:00.400Z'),
           '2026-09-19T00:00:00.400Z'
         FROM execution_bindings WHERE binding_id=?1",
        [&first],
    );
    assert!(
        backdated_enablement
            .unwrap_err()
            .to_string()
            .contains("binding predates provider enablement"),
        "a provider enabled at T2 cannot accept a binding claiming T1"
    );
    let stale = manager.connection.execute(
        "INSERT INTO execution_bindings (
           binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,
           ir_version,node_id,capability,capability_contract_hash,provider_registration_id,
           provider_id,provider_version,provider_manifest_hash,provider_build_hash,attempt,
           policy_decision_refs_json,grant_refs_json,execution_profile_ref,placement_json,
           binding_json,created_at)
         SELECT 'binding-real-3','attempt-real-3',task_id,semantic_program_hash,
           registry_snapshot_id,ir_version,node_id,capability,capability_contract_hash,
           provider_registration_id,provider_id,provider_version,provider_manifest_hash,
           provider_build_hash,3,policy_decision_refs_json,grant_refs_json,
           execution_profile_ref,placement_json,
           json_set(binding_json,'$.binding_id','binding-real-3',
                    '$.attempt_id','attempt-real-3','$.attempt',3,
                    '$.created_at','2026-09-19T00:00:00.600Z'),
           '2026-09-19T00:00:00.600Z'
         FROM execution_bindings WHERE binding_id=?1",
        [&first],
    );
    assert!(
        stale
            .unwrap_err()
            .to_string()
            .contains("binding conformance evidence is not latest"),
        "a superseded pass cannot consume a new attempt identity"
    );
    let second = insert(&manager, 3, "E2");
    assert!(valid(
        &mut manager,
        &second,
        "attempt-real-3",
        "2026-09-19T00:00:00.750Z"
    ));
    // A second disable/enable at exactly the same timestamp still mints a
    // distinct interval. The prior immutable binding cannot ride the new one.
    manager
        .provider_store_writer()
        .unwrap()
        .disable(&registration.registration_id, "2026-09-19T00:00:00.500Z")
        .unwrap();
    manager
        .provider_store_writer()
        .unwrap()
        .enable(&registration.registration_id, "2026-09-19T00:00:00.500Z")
        .unwrap();
    assert!(!valid(
        &mut manager,
        &second,
        "attempt-real-3",
        "2026-09-19T00:00:00.750Z"
    ));
    let new_interval = insert(&manager, 4, "E2");
    assert!(valid(
        &mut manager,
        &new_interval,
        "attempt-real-4",
        "2026-09-19T00:00:00.750Z"
    ));
    // The immutable admission receipt is the trust ceiling. A retained row
    // whose projection was raised by an older writer cannot authorize launch.
    assert!(manager.connection.execute(
        "UPDATE provider_registrations SET trust_status='organization-approved' WHERE registration_id=?1",
        [&registration.registration_id],
    ).is_err());
    manager
        .connection
        .execute_batch("DROP TRIGGER provider_registration_trust_immutable_update")
        .unwrap();
    manager.connection.execute(
        "UPDATE provider_registrations SET trust_status='organization-approved' WHERE registration_id=?1",
        [&registration.registration_id],
    ).unwrap();
    assert!(!valid(
        &mut manager,
        &new_interval,
        "attempt-real-4",
        "2026-09-19T00:00:00.750Z"
    ));
    manager.connection.execute(
        "UPDATE provider_registrations SET trust_status='locally-trusted' WHERE registration_id=?1",
        [&registration.registration_id],
    ).unwrap();
    manager
        .connection
        .execute_batch(include_str!(
            "../../../specs/persistence-v0.1-0013-provider-registry.sql"
        ))
        .unwrap();
    assert!(valid(
        &mut manager,
        &new_interval,
        "attempt-real-4",
        "2026-09-19T00:00:00.750Z"
    ));
    for attack in [
        format!(
            "UPDATE execution_binding_admission_markers SET conformance_evidence_id='E1' WHERE binding_id='{second}'"
        ),
        format!("DELETE FROM execution_binding_admission_markers WHERE binding_id='{second}'"),
        format!(
            "INSERT OR REPLACE INTO execution_binding_admission_markers(binding_id,conformance_evidence_id) VALUES ('{second}','E1')"
        ),
    ] {
        assert!(
            manager.connection.execute_batch(&attack).is_err(),
            "{attack}"
        );
    }
    manager.connection.execute_batch("VACUUM").unwrap();
    assert!(valid(
        &mut manager,
        &new_interval,
        "attempt-real-4",
        "2026-09-19T00:00:00.750Z"
    ));
    record(&mut manager, "E3", "fail", "2026-09-19T00:00:00.875Z");
    assert!(!valid(
        &mut manager,
        &second,
        "attempt-real-3",
        "2026-09-19T00:00:00.900Z"
    ));
    let stored: String = manager
        .connection
        .query_row(
            "SELECT binding_json FROM execution_bindings WHERE binding_id=?1",
            [&first],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&stored).unwrap()["conformance_evidence_id"],
        "E1"
    );
    let mut expiring = evidence("E4-expiring", "pass", "2026-09-19T00:00:00.950Z");
    expiring["expires_at"] = "2026-09-19T01:00:00.960000001+01:00".into();
    manager
        .provider_store_writer()
        .unwrap()
        .record_evidence(
            &registration.registration_id,
            &serde_json::to_vec(&expiring).unwrap(),
        )
        .unwrap();
    let insert_expiry =
        |manager: &TaskManager, id: &str, attempt: i64, pin: &str, created: &str| {
            manager.connection.execute(
                "INSERT INTO execution_bindings (
             binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,
             ir_version,node_id,capability,capability_contract_hash,provider_registration_id,
             provider_id,provider_version,provider_manifest_hash,provider_build_hash,attempt,
             policy_decision_refs_json,grant_refs_json,execution_profile_ref,placement_json,
             binding_json,created_at)
             SELECT ?1,?2,task_id,semantic_program_hash,registry_snapshot_id,
             ir_version,node_id,capability,capability_contract_hash,provider_registration_id,
             provider_id,provider_version,provider_manifest_hash,provider_build_hash,?3,
             policy_decision_refs_json,grant_refs_json,execution_profile_ref,placement_json,
             json_set(binding_json,'$.binding_id',?1,'$.attempt_id',?2,'$.attempt',?3,
                      '$.conformance_evidence_id',?4,'$.created_at',?5),?5
             FROM execution_bindings WHERE binding_id=?6",
                params![
                    id,
                    format!("attempt-{id}"),
                    attempt,
                    pin,
                    created,
                    new_interval
                ],
            )
        };
    for created in [
        "2026-09-19T00:00:00.960000001Z",
        "2026-09-19T00:00:00.960000002Z",
    ] {
        assert!(
            insert_expiry(&manager, "binding-expiry", 10, "E4-expiring", created)
                .unwrap_err()
                .to_string()
                .contains("expired at creation")
        );
        for table in [
            "execution_bindings",
            "execution_binding_admission_markers",
            "execution_binding_trust_markers",
            "execution_binding_enablement_markers",
        ] {
            let count: i64 = manager
                .connection
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE binding_id='binding-expiry'"),
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 0, "{table} retained a failed insert");
        }
    }
    insert_expiry(
        &manager,
        "binding-expiry",
        10,
        "E4-expiring",
        "2026-09-19T00:00:00.960Z",
    )
    .unwrap();
    let mut unbounded = evidence("E5-unbounded", "pass", "2026-09-19T00:00:00.970Z");
    unbounded.as_object_mut().unwrap().remove("expires_at");
    manager
        .provider_store_writer()
        .unwrap()
        .record_evidence(
            &registration.registration_id,
            &serde_json::to_vec(&unbounded).unwrap(),
        )
        .unwrap();
    let fresh = insert(&manager, 12, "E5-unbounded");
    assert!(valid(
        &mut manager,
        &fresh,
        "attempt-real-12",
        "2026-09-19T00:00:00.990Z"
    ));
    manager
        .connection
        .execute_batch("DROP TRIGGER execution_binding_evidence_present_at_insert")
        .unwrap();
    let owner = manager.lease_owner.clone();
    upgrade_stamped_registry_guards_fenced(
        &mut manager.connection,
        &owner,
        manager.lease_epoch,
        TEST_TIME,
    )
    .unwrap();
    assert!(!valid(
        &mut manager,
        &fresh,
        "attempt-real-12",
        "2026-09-19T00:00:00.990Z"
    ));
    assert_eq!(
        manager
            .connection
            .query_row(
                "SELECT state FROM provider_registrations WHERE registration_id=?1",
                [&registration.registration_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "registered"
    );
    let after_repair = insert(&manager, 13, "E5-unbounded");
    assert!(valid(
        &mut manager,
        &after_repair,
        "attempt-real-13",
        "2026-09-19T00:00:00.990Z"
    ));
    let spaced = insert(&manager, 14, "E5-unbounded");
    assert!(valid(
        &mut manager,
        &spaced,
        "attempt-real-14",
        "2026-09-19T00:00:00.990Z"
    ));
    manager
        .connection
        .execute(
            "UPDATE registry_snapshot_admissions SET state='DEPRECATED'
         WHERE snapshot_id=?1",
            [registry.snapshot_id()],
        )
        .unwrap();
    let generation: i64 = manager
        .connection
        .query_row(
            "SELECT MAX(generation) FROM semantic_repair_fences",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(generation, 0);
    let deprecated_error = manager
        .connection
        .execute(
            "INSERT INTO execution_bindings
         (binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,
          ir_version,node_id,capability,capability_contract_hash,provider_registration_id,
          provider_id,provider_version,provider_manifest_hash,provider_build_hash,attempt,
          policy_decision_refs_json,grant_refs_json,execution_profile_ref,placement_json,
          binding_json,created_at)
         SELECT 'binding-real-15','attempt-real-15',task_id,semantic_program_hash,
                registry_snapshot_id,ir_version,node_id,capability,capability_contract_hash,
                provider_registration_id,provider_id,provider_version,provider_manifest_hash,
                provider_build_hash,15,policy_decision_refs_json,grant_refs_json,
                execution_profile_ref,placement_json,
                json_set(binding_json,'$.binding_id','binding-real-15',
                                      '$.attempt_id','attempt-real-15','$.attempt',15),
                created_at
         FROM execution_bindings WHERE binding_id=?1",
            [&spaced],
        )
        .unwrap_err()
        .to_string();
    assert!(
        deprecated_error.contains("binding requires current semantic re-attestation"),
        "{deprecated_error}"
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "keeps the real file-backed admission, repair, re-attestation, and same-build binding chronology together"
)]
fn semantic_repair_allows_fresh_same_build_binding_after_reattest() {
    use aios_contracts::{CapabilityContract, RegistrySnapshot, TypeContract};
    use aios_registry::{
        ProviderTrustStatus, RegistryBuildOptions, SemanticRegistry, SnapshotHashEntry,
    };

    let directory = tempdir().unwrap();
    let path = directory.path().join("same-build-recovery.sqlite3");
    let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
    manager.create_task(&create("T-same-build")).unwrap();
    manager.initialize_provider_store().unwrap();
    let mut snapshot: RegistrySnapshot = serde_json::from_str(include_str!(
        "../../../examples/aios-ir/registry-snapshot.json"
    ))
    .unwrap();
    let types: Vec<TypeContract> = serde_json::from_str(include_str!(
        "../../../examples/aios-ir/type-contracts.json"
    ))
    .unwrap();
    let mut capabilities: Vec<CapabilityContract> = serde_json::from_str(include_str!(
        "../../../examples/aios-ir/capability-contracts.json"
    ))
    .unwrap();
    let claimed = capabilities
        .iter_mut()
        .find(|contract| contract.capability == "artifact.hash")
        .unwrap();
    claimed.conformance.suite_hash = Some(SUITE_HASH.into());
    let contract_hash = aios_registry::capability_contract_hash(claimed)
        .unwrap()
        .to_string();
    snapshot
        .capability_contracts
        .iter_mut()
        .find(|entry| entry.id == "artifact.hash")
        .unwrap()
        .content_hash = contract_hash.clone();
    let view = |entry: &aios_contracts::ContractRef| SnapshotHashEntry {
        id: entry.id.clone(),
        version: entry.version.clone(),
        content_hash: entry.content_hash.clone(),
    };
    snapshot.snapshot_id = aios_registry::registry_snapshot_id(
        &snapshot.schema_version,
        &snapshot.type_contracts.iter().map(view).collect::<Vec<_>>(),
        &snapshot
            .capability_contracts
            .iter()
            .map(view)
            .collect::<Vec<_>>(),
    )
    .unwrap()
    .to_string();
    let mut selected_snapshot = snapshot.clone();
    selected_snapshot
        .capability_contracts
        .retain(|entry| entry.id != "artifact.copy.compat");
    selected_snapshot.snapshot_id = aios_registry::registry_snapshot_id(
        &selected_snapshot.schema_version,
        &selected_snapshot
            .type_contracts
            .iter()
            .map(view)
            .collect::<Vec<_>>(),
        &selected_snapshot
            .capability_contracts
            .iter()
            .map(view)
            .collect::<Vec<_>>(),
    )
    .unwrap()
    .to_string();
    let selected_registry = SemanticRegistry::from_records(
        selected_snapshot,
        types.clone(),
        capabilities
            .iter()
            .filter(|contract| contract.capability != "artifact.copy.compat")
            .cloned()
            .collect(),
        RegistryBuildOptions::default(),
    )
    .unwrap();
    let registry = SemanticRegistry::from_records(
        snapshot,
        types,
        capabilities,
        RegistryBuildOptions::default(),
    )
    .unwrap();
    manager
        .registry_store_writer()
        .unwrap()
        .admit_registry(&registry)
        .unwrap();
    manager
        .registry_store_writer()
        .unwrap()
        .admit_registry(&selected_registry)
        .unwrap();
    let cases: Value = serde_json::from_str(include_str!(
        "../../../examples/aios-ir/provider-conformance-cases.json"
    ))
    .unwrap();
    let mut manifest = cases[0]["provider"].clone();
    manifest["provides"][0]["contract"]["contract_hash"] = contract_hash.clone().into();
    manifest["provides"][0]["conformance"]["suite_hash"] = SUITE_HASH.into();
    let build = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let registration = manager
        .provider_store_writer()
        .unwrap()
        .register(
            &registry,
            &serde_json::to_vec(&manifest).unwrap(),
            build,
            ProviderTrustStatus::LocallyTrusted,
            TEST_TIME,
        )
        .unwrap();
    let evidence = json!({
        "schema_version":"0.1", "result_id":"E-same-build",
        "provider_id":registration.provider_id, "provider_version":registration.provider_version,
        "provider_build_identity":{"kind":"build_hash","value":build},
        "semantic_capability_ref":"artifact.hash@1", "semantic_contract_version":"1.0",
        "semantic_contract_hash":contract_hash,
        "conformance_suite":{"id":manifest["provides"][0]["conformance"]["suite"],
                             "version":"0.1", "hash":SUITE_HASH},
        "harness":{"id":"fixture-harness","version":"1"},
        "result":"pass", "tests_total":1, "tests_passed":1, "tests_failed":0,
        "executed_at":TEST_TIME, "expires_at":"2026-09-20T00:00:00Z"
    });
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
        .enable(&registration.registration_id, TEST_TIME)
        .unwrap();
    let insert = |manager: &TaskManager, attempt: i64| {
        let binding_id = format!("binding-same-build-{attempt}");
        let attempt_id = format!("attempt-same-build-{attempt}");
        let receipt = json!({
            "schema_version":SCHEMA_VERSION, "binding_id":binding_id, "attempt_id":attempt_id,
            "task_id":"T-same-build", "semantic_program_hash":HASH,
            "registry_snapshot_id":registry.snapshot_id(), "ir_version":"0.1",
            "node_id":"node-same-build", "capability":"artifact.hash@1",
            "capability_contract_hash":contract_hash,
            "provider":{"id":registration.provider_id,"version":registration.provider_version,
                        "manifest_hash":registration.manifest_hash,
                        "package_or_build_hash":registration.build_hash},
            "provider_trust_source_id":registration.registration_id,
            "conformance_evidence_id":"E-same-build", "attempt":attempt,
            "policy_decision_refs":[], "authority":{"grant_refs":[]},
            "execution_profile":{"profile_ref":"profile:test"},
            "placement":{"locality":"local"}, "inputs":{}, "outputs":{},
            "created_at":TEST_TIME
        });
        manager.connection.execute(
            "INSERT INTO execution_bindings(binding_id,attempt_id,task_id,semantic_program_hash,
             registry_snapshot_id,ir_version,node_id,capability,capability_contract_hash,
             provider_registration_id,provider_id,provider_version,provider_manifest_hash,
             provider_build_hash,attempt,policy_decision_refs_json,grant_refs_json,
             execution_profile_ref,placement_json,binding_json,created_at)
             VALUES (?1,?2,'T-same-build',?3,?4,'0.1','node-same-build','artifact.hash@1',
             ?5,?6,?7,?8,?9,?10,?11,'[]','[]','profile:test','{\"locality\":\"local\"}',?12,?13)",
            params![binding_id, attempt_id, HASH, registry.snapshot_id(), contract_hash,
                registration.registration_id, registration.provider_id,
                registration.provider_version, registration.manifest_hash,
                registration.build_hash, attempt, canonical_json(&receipt).unwrap(), TEST_TIME],
        ).unwrap();
        (binding_id, attempt_id)
    };
    let accepted = |manager: &mut TaskManager, binding_id: &str, attempt_id: &str| {
        let binding_json: String = manager
            .connection
            .query_row(
                "SELECT binding_json FROM execution_bindings WHERE binding_id=?1",
                [binding_id],
                |row| row.get(0),
            )
            .unwrap();
        let binding = BindingEvidence {
            capability: "artifact.hash@1".into(),
            principal_id: registration.provider_id.clone(),
            program_json: String::new(),
            registry_snapshot_id: registry.snapshot_id().into(),
            contract_hash: Some(contract_hash.clone()),
            snapshot_manifest_json: String::new(),
            ir_version: "0.1".into(),
            provider_version: registration.provider_version.clone(),
            provider_manifest_hash: Some(registration.manifest_hash.clone()),
            provider_build_hash: Some(registration.build_hash.clone()),
            provider_registration_id: Some(registration.registration_id.clone()),
            attempt: if binding_id.ends_with("-1") { 1 } else { 2 },
            policy_decision_refs_json: "[]".into(),
            grant_refs_json: "[]".into(),
            execution_profile_ref: "profile:test".into(),
            placement_json: "{\"locality\":\"local\"}".into(),
            binding_json,
            created_at: TEST_TIME.into(),
            conformance_evidence_id: "E-same-build".into(),
            conformance_suite_id: manifest["provides"][0]["conformance"]["suite"]
                .as_str()
                .map(str::to_owned),
            conformance_suite_hash: Some(SUITE_HASH.into()),
            conformance_status: "pass".into(),
            conformance_json: canonical_json(&evidence).unwrap(),
            conformance_tested_at: Some(TEST_TIME.into()),
        };
        let check = BindingGrantCheck {
            task_id: "T-same-build",
            semantic_hash: HASH,
            node_id: "node-same-build",
            binding_id,
            attempt_id,
            grant_refs_json: "[]",
            checked_at: TEST_TIME,
        };
        let transaction = manager.connection.transaction().unwrap();
        let current_enablement: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM execution_binding_enablement_markers marker
             JOIN provider_state_epochs epoch ON epoch.registration_id=marker.registration_id
               AND epoch.revision=marker.revision
             WHERE marker.binding_id=?1 AND marker.registration_id=?2
               AND epoch.state='registered'
               AND epoch.revision=(SELECT MAX(revision) FROM provider_state_epochs
                                   WHERE registration_id=?2))",
                params![binding_id, registration.registration_id],
                |row| row.get(0),
            )
            .unwrap();
        current_enablement
            && binding_receipt_projection(&binding, &check, true).is_some()
            && verified_provider_admission_from_binding(
                &transaction,
                binding_id,
                &binding,
                TEST_TIME,
            )
            .unwrap()
    };
    let (old_binding, old_attempt) = insert(&manager, 1);
    assert!(accepted(&mut manager, &old_binding, &old_attempt));
    manager
        .connection
        .execute_batch("DROP TRIGGER one_way_registry_snapshot_admissions_update")
        .unwrap();
    drop(manager);
    let mut repaired = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
    assert!(!accepted(&mut repaired, &old_binding, &old_attempt));
    repaired
        .registry_store_writer()
        .unwrap()
        .reattest_snapshot(
            registry.snapshot_id(),
            "decision:same-build-recovery",
            "local-authority",
        )
        .unwrap();
    repaired
        .registry_store_writer()
        .unwrap()
        .reattest_snapshot(
            selected_registry.snapshot_id(),
            "decision:selected-snapshot-recovery",
            "local-authority",
        )
        .unwrap();
    assert!(!accepted(&mut repaired, &old_binding, &old_attempt));
    let candidates = repaired
        .provider_store_writer()
        .unwrap()
        .eligible_candidates(
            "artifact.hash@1",
            &contract_hash,
            registry.snapshot_id(),
            TEST_TIME,
        )
        .unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(
        candidates[0].registration.registration_id,
        registration.registration_id
    );
    let (fresh_binding, fresh_attempt) = insert(&repaired, 2);
    assert!(accepted(&mut repaired, &fresh_binding, &fresh_attempt));
    assert_eq!(
        repaired
            .connection
            .query_row(
                "SELECT package_content_hash FROM provider_registrations WHERE registration_id=?1",
                [&registration.registration_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        build
    );
    drop(repaired);
    let mut stable = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
    assert!(!accepted(&mut stable, &old_binding, &old_attempt));
    assert!(accepted(&mut stable, &fresh_binding, &fresh_attempt));
    stable
        .connection
        .execute(
            "UPDATE registry_snapshot_admissions SET state='DEPRECATED'
         WHERE snapshot_id=?1",
            [registry.snapshot_id()],
        )
        .unwrap();
    let candidates = stable
        .provider_store_writer()
        .unwrap()
        .eligible_candidates(
            "artifact.hash@1",
            &contract_hash,
            selected_registry.snapshot_id(),
            TEST_TIME,
        )
        .unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(
        candidates[0].registration.registration_id,
        registration.registration_id
    );
    let error = stable
        .connection
        .execute(
            "INSERT INTO execution_bindings
         (binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,
          ir_version,node_id,capability,capability_contract_hash,provider_registration_id,
          provider_id,provider_version,provider_manifest_hash,provider_build_hash,attempt,
          policy_decision_refs_json,grant_refs_json,execution_profile_ref,placement_json,
          binding_json,created_at)
         SELECT 'binding-same-build-3','attempt-same-build-3',task_id,semantic_program_hash,
                registry_snapshot_id,ir_version,node_id,capability,capability_contract_hash,
                provider_registration_id,provider_id,provider_version,provider_manifest_hash,
                provider_build_hash,3,policy_decision_refs_json,grant_refs_json,
                execution_profile_ref,placement_json,
                json_set(binding_json,'$.binding_id','binding-same-build-3',
                                      '$.attempt_id','attempt-same-build-3','$.attempt',3),
                created_at
         FROM execution_bindings WHERE binding_id=?1",
            [&fresh_binding],
        )
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("binding requires current semantic re-attestation"),
        "{error}"
    );
    for table in [
        "execution_bindings",
        "execution_binding_admission_markers",
        "execution_binding_trust_markers",
        "execution_binding_enablement_markers",
    ] {
        assert_eq!(
            stable
                .connection
                .query_row(
                    &format!(
                        "SELECT COUNT(*) FROM {table} WHERE binding_id='binding-same-build-3'"
                    ),
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0,
            "{table}"
        );
    }
    drop(stable);
    let stable = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
    stable
        .connection
        .execute(
            "INSERT INTO execution_bindings
         (binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,
          ir_version,node_id,capability,capability_contract_hash,provider_registration_id,
          provider_id,provider_version,provider_manifest_hash,provider_build_hash,attempt,
          policy_decision_refs_json,grant_refs_json,execution_profile_ref,placement_json,
          binding_json,created_at)
         SELECT 'binding-same-build-3','attempt-same-build-3',task_id,semantic_program_hash,
                ?2,ir_version,node_id,capability,capability_contract_hash,
                provider_registration_id,provider_id,provider_version,provider_manifest_hash,
                provider_build_hash,3,policy_decision_refs_json,grant_refs_json,
                execution_profile_ref,placement_json,
                json_set(binding_json,'$.binding_id','binding-same-build-3',
                                      '$.attempt_id','attempt-same-build-3','$.attempt',3,
                                      '$.registry_snapshot_id',?2),
                created_at
         FROM execution_bindings WHERE binding_id=?1",
            params![fresh_binding, selected_registry.snapshot_id()],
        )
        .unwrap();
    assert_eq!(
        stable
            .connection
            .query_row(
                "SELECT COUNT(*) FROM execution_binding_admission_markers
         WHERE binding_id='binding-same-build-3'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "builds and verifies both unstamped quarantine and stamped legacy migration"
)]
fn unstamped_pre_reconciliation_store_is_quarantined_without_mutation() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("legacy.sqlite3");
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE schema_migrations (
                 migration_id TEXT PRIMARY KEY,
                 checksum TEXT NOT NULL,
                 applied_at TEXT NOT NULL
             );
             CREATE TABLE tasks (
                 task_id TEXT PRIMARY KEY,
                 revision INTEGER NOT NULL,
                 state TEXT NOT NULL,
                 state_reason_json TEXT,
                 principal_kind TEXT NOT NULL,
                 principal_id TEXT NOT NULL,
                 workspace_id TEXT,
                 original_intent TEXT NOT NULL,
                 normalized_intent_json TEXT,
                 active_program_revision INTEGER,
                 constraints_json TEXT,
                 failure_json TEXT,
                 recovery_json TEXT,
                 created_at TEXT NOT NULL,
                 updated_at TEXT NOT NULL,
                 completed_at TEXT
             );
             CREATE TABLE task_transitions (
                 transition_id TEXT PRIMARY KEY,
                 task_id TEXT NOT NULL,
                 expected_revision INTEGER NOT NULL,
                 expected_state TEXT NOT NULL,
                 to_state TEXT NOT NULL,
                 result_revision INTEGER,
                 result_state TEXT,
                 outcome TEXT NOT NULL,
                 reason_code TEXT NOT NULL,
                 request_json TEXT NOT NULL,
                 result_json TEXT,
                 provenance_event_id TEXT,
                 requested_at TEXT NOT NULL,
                 committed_at TEXT,
                 FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE
             );
             INSERT INTO tasks (
                 task_id, revision, state, principal_kind, principal_id,
                 original_intent, created_at, updated_at
             ) VALUES (
                 'T-legacy', 1, 'CREATED', 'user', 'user:legacy',
                 'preserve me', '2026-09-19T00:00:00Z', '2026-09-19T00:00:00Z'
             );
             INSERT INTO task_transitions (
                 transition_id, task_id, expected_revision, expected_state,
                 to_state, outcome, reason_code, request_json, requested_at
             ) VALUES (
                 'tr-legacy', 'T-legacy', 1, 'CREATED', 'PLANNING',
                 'PENDING', 'STATE_CHANGE_REQUESTED', '{}',
                 '2026-09-19T00:00:00Z'
             );",
        )
        .unwrap();
    drop(connection);

    assert!(TaskManager::open_with_clock(&path, Box::new(FixedClock)).is_err());
    let connection = Connection::open(&path).unwrap();
    for column in [
        "active_plan_revision",
        "active_step_ids_json",
        "waiting_on_json",
    ] {
        assert!(!table_has_column(&connection, "tasks", column).unwrap());
    }
    let foreign_keys = connection
        .prepare("PRAGMA foreign_key_list(task_transitions)")
        .unwrap()
        .query_map([], |_| Ok(()))
        .unwrap()
        .count();
    assert_eq!(foreign_keys, 1);
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM task_transitions WHERE transition_id = 'tr-legacy'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    connection.execute(
        "INSERT INTO schema_migrations (migration_id, checksum, applied_at) VALUES ('0001_v0_1_trusted_control_plane', 'UNGENERATED-DRAFT-CHECKSUM', '2026-09-15T00:00:00Z')",
        [],
    ).unwrap();
    drop(connection);
    assert!(TaskManager::open_with_clock(&path, Box::new(FixedClock)).is_err());
    let connection = Connection::open(&path).unwrap();
    for column in [
        "active_plan_revision",
        "active_step_ids_json",
        "waiting_on_json",
    ] {
        assert!(table_has_column(&connection, "tasks", column).unwrap());
    }
    let foreign_keys = connection
        .prepare("PRAGMA foreign_key_list(task_transitions)")
        .unwrap()
        .query_map([], |_| Ok(()))
        .unwrap()
        .count();
    assert_eq!(foreign_keys, 0);
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        16
    );
}

fn downgrade_provenance_before_0011(connection: &Connection) {
    connection
        .execute_batch(
            "PRAGMA foreign_keys=OFF;
         DROP INDEX IF EXISTS ix_provenance_task_sequence;
         DROP TRIGGER IF EXISTS provenance_events_no_update;
         DROP TRIGGER IF EXISTS provenance_events_no_delete;
         ALTER TABLE provenance_events RENAME TO provenance_events_modern;
         CREATE TABLE provenance_events (
             event_id TEXT PRIMARY KEY,
             task_id TEXT NOT NULL,
             stream_id TEXT NOT NULL,
             sequence INTEGER NOT NULL CHECK(sequence>=1),
             timestamp TEXT NOT NULL,
             event_type TEXT NOT NULL,
             semantic_program_hash TEXT,
             ir_version TEXT,
             registry_snapshot_id TEXT,
             node_id TEXT,
             execution_binding_id TEXT,
             provider_id TEXT,
             status TEXT,
             previous_event_hash TEXT,
             event_hash TEXT NOT NULL,
             event_json TEXT NOT NULL,
             FOREIGN KEY(task_id) REFERENCES tasks(task_id) ON DELETE CASCADE,
             FOREIGN KEY(registry_snapshot_id) REFERENCES registry_snapshots(snapshot_id),
             FOREIGN KEY(execution_binding_id) REFERENCES execution_bindings(binding_id),
             UNIQUE(task_id,sequence), UNIQUE(stream_id,sequence)
         );
         INSERT INTO provenance_events
         SELECT event_id,task_id,stream_id,sequence,timestamp,event_type,semantic_program_hash,
                ir_version,registry_snapshot_id,node_id,execution_binding_id,provider_id,status,
                previous_event_hash,event_hash,event_json
         FROM provenance_events_modern;
         DROP TABLE provenance_events_modern;
         CREATE INDEX ix_provenance_task_sequence ON provenance_events(task_id,sequence);
         CREATE TRIGGER provenance_events_no_update BEFORE UPDATE ON provenance_events
         BEGIN SELECT RAISE(ABORT,'provenance_events are append-only'); END;
         CREATE TRIGGER provenance_events_no_delete BEFORE DELETE ON provenance_events
         BEGIN SELECT RAISE(ABORT,'provenance_events are append-only'); END;
         DELETE FROM schema_migrations WHERE migration_id='0011_provenance_service_boundary';",
        )
        .unwrap();
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "keeps the legacy table shape and survival assertions together"
)]
fn provenance_service_migration_preserves_task_artifact_rows_and_event_hashes() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("provenance-migration.sqlite3");
    let task_id = "任务-迁移-é";
    let original_records = {
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        manager.create_task(&compatibility_create(task_id)).unwrap();
        let transaction = manager.connection.transaction().unwrap();
        for index in 2..=3 {
            append_event(
                &transaction,
                task_id,
                &serde_json::json!({
                    "schema_version": SCHEMA_VERSION,
                    "event_id": format!("event:legacy-unicode:{index}"),
                    "task_id": task_id,
                    "event_type": "verification.started",
                    "timestamp": TEST_TIME,
                    "actor": {"kind":"system-service","id":"service:test"},
                    "status": "success",
                    "details": {"index": index}
                }),
            )
            .unwrap();
        }
        transaction.commit().unwrap();
        manager.connection.execute(
            "INSERT INTO artifacts (artifact_id,uri,semantic_type,media_type,sensitivity,retention_class,origin_kind,origin_task_id,integrity_state,created_at)
             VALUES (?1,?2,'artifact.test@1','application/octet-stream','local','task','task',?3,'unknown',?4)",
            rusqlite::params![
                format!("artifact:v1:sha256:{}", "a".repeat(64)),
                format!("artifact://artifact:v1:sha256:{}", "a".repeat(64)),
                task_id,
                TEST_TIME,
            ],
        ).unwrap();
        let mut statement = manager
            .connection
            .prepare(
                "SELECT sequence,previous_event_hash,event_hash,event_json
                 FROM provenance_events WHERE task_id=?1 ORDER BY sequence",
            )
            .unwrap();
        statement
            .query_map([task_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    };

    let connection = Connection::open(&path).unwrap();
    downgrade_provenance_before_0011(&connection);
    drop(connection);

    let manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
    assert!(manager.get_task(task_id).unwrap().is_some());
    assert_eq!(
        manager
            .connection
            .query_row(
                "SELECT COUNT(*) FROM artifacts WHERE origin_task_id=?1",
                [task_id],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    let mut statement = manager
        .connection
        .prepare(
            "SELECT sequence,previous_event_hash,event_hash,event_json
             FROM provenance_events WHERE task_id=?1 ORDER BY sequence",
        )
        .unwrap();
    let migrated_records = statement
        .query_map([task_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(migrated_records.len(), 3);
    assert_eq!(migrated_records, original_records);
    assert!(manager.verify_provenance(task_id).unwrap());
    let task = manager.get_task(task_id).unwrap().unwrap();
    assert_eq!(task.principal.id, "user:Alice Smith=👩\u{200d}💻e\u{301}");
    assert_eq!(
        task.workspace_id.as_deref(),
        Some("My Workspace=🧪e\u{301}")
    );
    assert_eq!(
        task.active_step_ids,
        ["step one", "step=two", "step 👣", "step-e\u{301}"]
    );
    let export = manager.export_provenance(task_id).unwrap();
    assert!(!export.records_jsonl.contains("Alice Smith"));
    assert!(!export.records_jsonl.contains("My Workspace"));
    let verification = aios_provenance::verify_jsonl_export(
        &export.manifest_json,
        &export.records_jsonl,
        TEST_TIME,
    )
    .unwrap();
    assert!(verification.valid, "{verification:?}");
    assert_eq!(
        manager.connection.query_row("SELECT schema_version || ':' || hash_profile FROM provenance_events WHERE task_id=?1", [task_id], |row| row.get::<_, String>(0)).unwrap(),
        "0.1:aios-provenance-event-v0.1"
    );
    assert!(provenance_task_fk_is_current(&manager.connection).unwrap());
}

#[test]
fn stamped_provenance_table_without_task_fk_rejects_orphan_stream() {
    let directory = tempdir().unwrap();
    let path = directory
        .path()
        .join("stamped-missing-provenance-fk.sqlite3");
    {
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        manager.create_task(&create("T-fk-original")).unwrap();
        assert!(provenance_task_fk_is_current(&manager.connection).unwrap());
    }
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "PRAGMA foreign_keys=OFF;
         DROP TRIGGER provenance_events_no_update;
         DROP TRIGGER provenance_events_no_delete;
         CREATE TABLE provenance_events_without_fk AS SELECT * FROM provenance_events;
         DROP TABLE provenance_events;
         ALTER TABLE provenance_events_without_fk RENAME TO provenance_events;",
        )
        .unwrap();
    let raw: String = connection
        .query_row(
            "SELECT event_json FROM provenance_events WHERE task_id='T-fk-original'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let mut orphan: Value = serde_json::from_str(&raw).unwrap();
    orphan["task_id"] = serde_json::json!("T-fk-orphan");
    orphan["event_id"] = serde_json::json!("event:fk-orphan");
    let orphan_stream = aios_provenance::stream_id("T-fk-orphan").unwrap();
    let orphan_hash = aios_provenance::hash_record(&orphan_stream, 1, None, &orphan).unwrap();
    connection.execute(
        "UPDATE provenance_events SET task_id='T-fk-orphan',stream_id=?1,event_id='event:fk-orphan',event_hash=?2,event_json=?3",
        rusqlite::params![orphan_stream, orphan_hash, orphan.to_string()],
    ).unwrap();
    assert!(!provenance_task_fk_is_current(&connection).unwrap());
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_foreign_key_check('provenance_events')",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM tasks WHERE task_id='T-fk-orphan'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    drop(connection);

    assert!(matches!(
        TaskManager::open_with_clock(&path, Box::new(FixedClock)),
        Err(TaskManagerError::InvalidRecord(
            "provenance service-boundary migration is incomplete"
        ))
    ));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "covers both auxiliary foreign keys across stamped rejection and unstamped rebuild"
)]
fn provenance_requires_all_declared_foreign_keys_in_stamped_and_unstamped_stores() {
    for (missing_fk, name) in [
        (
            "FOREIGN KEY (registry_snapshot_id) REFERENCES registry_snapshots(snapshot_id),",
            "registry-snapshot",
        ),
        (
            "FOREIGN KEY (execution_binding_id) REFERENCES execution_bindings(binding_id),",
            "execution-binding",
        ),
    ] {
        for stamped in [true, false] {
            let directory = tempdir().unwrap();
            let path = directory.path().join(format!("missing-{name}-fk.sqlite3"));
            let task_id = "T-missing-provenance-fk";
            let original_hash = {
                let mut manager =
                    TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
                manager.create_task(&create(task_id)).unwrap();
                manager
                    .provenance_head(task_id)
                    .unwrap()
                    .unwrap()
                    .event_hash
            };
            let connection = Connection::open(&path).unwrap();
            let schema: String = connection
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name='provenance_events'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let malformed = schema
                .replacen(
                    "CREATE TABLE provenance_events",
                    "CREATE TABLE provenance_events_without_fk",
                    1,
                )
                .replacen(missing_fk, "", 1);
            assert_ne!(malformed, schema, "{name} FK must be present in fixture");
            assert!(!malformed.contains(missing_fk));
            let clear_stamp = if stamped {
                ""
            } else {
                "DELETE FROM schema_migrations WHERE migration_id='0011_provenance_service_boundary';"
            };
            connection
                .execute_batch(&format!(
                    "PRAGMA foreign_keys=OFF;
                     DROP TRIGGER provenance_events_no_update;
                     DROP TRIGGER provenance_events_no_delete;
                     {malformed};
                     INSERT INTO provenance_events_without_fk SELECT * FROM provenance_events;
                     DROP TABLE provenance_events;
                     ALTER TABLE provenance_events_without_fk RENAME TO provenance_events;
                     {clear_stamp}"
                ))
                .unwrap();
            assert!(provenance_task_fk_is_current(&connection).unwrap());
            assert!(!provenance_foreign_keys_are_current(&connection).unwrap());
            assert_eq!(
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM pragma_foreign_key_check('provenance_events')",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                0
            );
            assert!(
                aios_provenance::verify_stream(
                    &connection,
                    &provenance_stream_id(task_id),
                    None,
                    None,
                    TEST_TIME,
                )
                .unwrap()
                .valid
            );
            drop(connection);

            if stamped {
                assert!(matches!(
                    TaskManager::open_with_clock(&path, Box::new(FixedClock)),
                    Err(TaskManagerError::InvalidRecord(
                        "provenance service-boundary migration is incomplete"
                    ))
                ));
            } else {
                let manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
                assert!(provenance_foreign_keys_are_current(&manager.connection).unwrap());
                assert!(manager.verify_provenance(task_id).unwrap());
                assert_eq!(
                    manager
                        .provenance_head(task_id)
                        .unwrap()
                        .unwrap()
                        .event_hash,
                    original_hash
                );
            }
        }
    }
}

#[test]
fn provenance_task_fk_rejects_extra_cascading_constraint() {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "CREATE TABLE tasks(task_id TEXT PRIMARY KEY);
         CREATE TABLE provenance_events(
             task_id TEXT NOT NULL,
             FOREIGN KEY(task_id) REFERENCES tasks(task_id),
             FOREIGN KEY(task_id) REFERENCES tasks(task_id) ON DELETE CASCADE
         );",
        )
        .unwrap();
    assert!(!provenance_task_fk_is_current(&connection).unwrap());
}

fn duplicate_provenance_row(
    connection: &Connection,
    original_task_id: &str,
    event_id: &str,
    task_id: Option<&str>,
    stream_id: &str,
) {
    connection
        .execute(
            "INSERT INTO provenance_events
         SELECT schema_version,hash_profile,?2,?3,?4,2,timestamp,event_type,
                semantic_program_hash,ir_version,registry_snapshot_id,node_id,
                execution_binding_id,provider_id,status,previous_event_hash,event_hash,event_json
         FROM provenance_events WHERE task_id=?1 AND sequence=1",
            rusqlite::params![original_task_id, event_id, task_id, stream_id],
        )
        .unwrap();
}

#[test]
fn stamped_nullable_provenance_task_id_rejects_null_orphan() {
    let directory = tempdir().unwrap();
    let path = directory
        .path()
        .join("stamped-null-provenance-task.sqlite3");
    let task_id = "T-null-provenance-owner";
    {
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        manager.create_task(&create(task_id)).unwrap();
    }
    let connection = Connection::open(&path).unwrap();
    let schema: String = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='provenance_events'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let nullable_schema = schema
        .replacen(
            "CREATE TABLE provenance_events",
            "CREATE TABLE provenance_events_nullable_task",
            1,
        )
        .replacen(
            "task_id                  TEXT NOT NULL",
            "task_id                  TEXT",
            1,
        );
    assert!(nullable_schema.contains("task_id                  TEXT,"));
    connection
        .execute_batch(&format!(
            "PRAGMA foreign_keys=OFF;
         DROP TRIGGER provenance_events_no_update;
         DROP TRIGGER provenance_events_no_delete;
         {nullable_schema};
         INSERT INTO provenance_events_nullable_task SELECT * FROM provenance_events;
         DROP TABLE provenance_events;
         ALTER TABLE provenance_events_nullable_task RENAME TO provenance_events;"
        ))
        .unwrap();
    assert!(provenance_task_fk_is_current(&connection).unwrap());
    assert!(!table_column_not_null(&connection, "provenance_events", "task_id").unwrap());
    duplicate_provenance_row(
        &connection,
        task_id,
        "event:null-provenance-owner",
        None,
        "stream:v1:null-provenance-owner",
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_foreign_key_check('provenance_events')",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
    drop(connection);
    assert!(matches!(
        TaskManager::open_with_clock(&path, Box::new(FixedClock)),
        Err(TaskManagerError::InvalidRecord(
            "provenance service-boundary migration is incomplete"
        ))
    ));
}

#[test]
fn stamped_provenance_rejects_unowned_or_wrong_stream_extra_rows() {
    for (event_id, owner, stream_id, expected_error) in [
        (
            "event:unowned-extra",
            "T-provenance-owner-missing",
            "stream:v1:unowned-extra",
            "provenance event has no owning Task",
        ),
        (
            "event:wrong-stream-extra",
            "T-provenance-owner",
            "stream:v1:wrong-stream-extra",
            "Task provenance chain is missing or invalid before startup reconciliation",
        ),
    ] {
        let directory = tempdir().unwrap();
        let path = directory
            .path()
            .join("stamped-extra-provenance-row.sqlite3");
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        manager.create_task(&create("T-provenance-owner")).unwrap();
        drop(manager);
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
        assert!(provenance_task_fk_is_current(&connection).unwrap());
        duplicate_provenance_row(
            &connection,
            "T-provenance-owner",
            event_id,
            Some(owner),
            stream_id,
        );
        let foreign_key_violations: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_foreign_key_check('provenance_events')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            foreign_key_violations,
            i64::from(owner != "T-provenance-owner")
        );
        drop(connection);
        assert!(matches!(
            TaskManager::open_with_clock(&path, Box::new(FixedClock)),
            Err(TaskManagerError::InvalidRecord(message)) if message == expected_error
        ));
    }
}

#[test]
fn new_task_opaque_identifiers_preserve_exact_hash_and_export_after_reopen() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("opaque-task-identifiers.sqlite3");
    let task_id = "Task = 🧭 e\u{301}";
    let original = compatibility_create(task_id);
    let original_head = {
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        let task = manager.create_task(&original).unwrap();
        assert_eq!(task.principal, original.principal);
        assert_eq!(task.workspace_id, original.workspace_id);
        assert_eq!(task.active_step_ids, original.active_step_ids);
        let mut planning = request(
            "transition = 🧭 e\u{301}",
            task_id,
            1,
            TaskState::Created,
            TaskState::Planning,
        );
        planning.requested_by = original.principal.clone();
        planning.reason.related_ids = vec![String::new(), "related = 🧷 e\u{301}".to_owned()];
        assert!(manager.transition(&planning).unwrap().applied);
        let mut waiting = request(
            "waiting = 🧭 e\u{301}",
            task_id,
            2,
            TaskState::Planning,
            TaskState::WaitingForInput,
        );
        waiting.requested_by = original.principal.clone();
        waiting.mutation.waiting_on = Some(vec![WaitingOn {
            kind: WaitingKind::Input,
            id: "input = 🧩 e\u{301}".to_owned(),
            message: None,
        }]);
        assert!(manager.transition(&waiting).unwrap().applied);
        aios_provenance::get_head(
            &manager.connection,
            &aios_provenance::stream_id(task_id).unwrap(),
        )
        .unwrap()
        .unwrap()
    };

    let manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
    let reopened_head = aios_provenance::get_head(
        &manager.connection,
        &aios_provenance::stream_id(task_id).unwrap(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(reopened_head, original_head);
    assert!(manager.verify_provenance(task_id).unwrap());
    let export = manager.export_provenance(task_id).unwrap();
    assert!(!export.records_jsonl.contains("user:Alice Smith="));
    assert!(!export.records_jsonl.contains("My Workspace="));
    assert!(!export.records_jsonl.contains("step one"));
    let verification = aios_provenance::verify_jsonl_export(
        &export.manifest_json,
        &export.records_jsonl,
        TEST_TIME,
    )
    .unwrap();
    assert!(verification.valid, "{verification:?}");
    assert_eq!(verification.scope, "exported-projection");
    assert!(!verification.original_chain_verified_offline);
    assert!(!verification.original_chain_linkage_proven);
    let unchanged_head = aios_provenance::get_head(
        &manager.connection,
        &aios_provenance::stream_id(task_id).unwrap(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(unchanged_head, original_head);
}

#[test]
fn provenance_migration_rolls_back_when_legacy_details_are_not_privacy_safe() {
    let directory = tempdir().unwrap();
    let path = directory
        .path()
        .join("provenance-invalid-migration.sqlite3");
    let task_id = "T-invalid-legacy-details";
    let (mut event, stream_id) = {
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        manager.create_task(&create(task_id)).unwrap();
        let event_json = manager
            .connection
            .query_row(
                "SELECT event_json FROM provenance_events WHERE task_id=?1",
                [task_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        (
            serde_json::from_str::<serde_json::Value>(&event_json).unwrap(),
            aios_provenance::stream_id(task_id).unwrap(),
        )
    };
    event["details"]["apiKey"] = serde_json::json!("private-legacy-value");
    let forged_hash = aios_provenance::hash_record(&stream_id, 1, None, &event).unwrap();
    let connection = Connection::open(&path).unwrap();
    downgrade_provenance_before_0011(&connection);
    connection
        .execute_batch("DROP TRIGGER provenance_events_no_update;")
        .unwrap();
    connection
        .execute(
            "UPDATE provenance_events SET event_json=?2,event_hash=?3 WHERE task_id=?1",
            rusqlite::params![task_id, event.to_string(), forged_hash],
        )
        .unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER provenance_events_no_update BEFORE UPDATE ON provenance_events
             BEGIN SELECT RAISE(ABORT,'provenance_events are append-only'); END;",
        )
        .unwrap();
    drop(connection);

    assert!(TaskManager::open_with_clock(&path, Box::new(FixedClock)).is_err());
    let connection = Connection::open(&path).unwrap();
    assert!(!table_has_column(&connection, "provenance_events", "schema_version").unwrap());
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations
                 WHERE migration_id='0011_provenance_service_boundary'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT event_json FROM provenance_events WHERE task_id=?1",
                [task_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        event.to_string()
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "checks each legacy provenance reference and its rollback invariants"
)]
fn provenance_migration_rejects_orphaned_legacy_references_without_changing_hashes() {
    for (name, orphan_id) in [
        ("task", "T-missing-parent"),
        ("snapshot", "snapshot:missing-parent"),
        ("binding", "binding:missing-parent"),
    ] {
        let directory = tempdir().unwrap();
        let path = directory.path().join(format!("orphan-{name}.sqlite3"));
        let original_task_id = format!("T-legacy-{name}");
        {
            let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
            manager.create_task(&create(&original_task_id)).unwrap();
        }

        let connection = Connection::open(&path).unwrap();
        downgrade_provenance_before_0011(&connection);
        let mut event: serde_json::Value = connection
            .query_row(
                "SELECT event_json FROM provenance_events WHERE sequence=1",
                [],
                |row| row.get::<_, String>(0),
            )
            .map(|json| serde_json::from_str(&json).unwrap())
            .unwrap();
        let task_id = if name == "task" {
            event["task_id"] = serde_json::json!(orphan_id);
            orphan_id
        } else {
            original_task_id.as_str()
        };
        let snapshot_id = (name == "snapshot").then_some(orphan_id);
        let binding_id = (name == "binding").then_some(orphan_id);
        if let Some(snapshot_id) = snapshot_id {
            event["registry_snapshot_id"] = serde_json::json!(snapshot_id);
        }
        if let Some(binding_id) = binding_id {
            event["execution_binding_id"] = serde_json::json!(binding_id);
        }
        let stream_id = aios_provenance::stream_id(task_id).unwrap();
        let event_hash = aios_provenance::hash_record(&stream_id, 1, None, &event).unwrap();
        let event_json = event.to_string();
        connection
            .execute_batch("DROP TRIGGER provenance_events_no_update")
            .unwrap();
        connection
            .execute(
                "UPDATE provenance_events SET task_id=?1,stream_id=?2,registry_snapshot_id=?3,
                 execution_binding_id=?4,event_hash=?5,event_json=?6 WHERE sequence=1",
                rusqlite::params![
                    task_id,
                    stream_id,
                    snapshot_id,
                    binding_id,
                    event_hash,
                    event_json
                ],
            )
            .unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER provenance_events_no_update BEFORE UPDATE ON provenance_events
                 BEGIN SELECT RAISE(ABORT,'provenance_events are append-only'); END;",
            )
            .unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM pragma_foreign_key_check('provenance_events')",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1,
            "{name}"
        );
        drop(connection);

        let result = TaskManager::open_with_clock(&path, Box::new(FixedClock));
        assert!(
            matches!(
                result,
                Err(TaskManagerError::InvalidRecord(
                    "persistence migration produced invalid foreign-key references"
                ))
            ),
            "{name}"
        );
        let connection = Connection::open(&path).unwrap();
        assert!(!table_has_column(&connection, "provenance_events", "schema_version").unwrap());
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM schema_migrations
                     WHERE migration_id='0011_provenance_service_boundary'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0,
            "{name}"
        );
        let stored: (String, String) = connection
            .query_row(
                "SELECT event_hash,event_json FROM provenance_events WHERE sequence=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(stored, (event_hash, event_json), "{name}");
    }
}

#[test]
fn portable_provenance_export_is_private_and_reverifies_without_task_storage() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    let create_request = create("T-portable-provenance");
    let private_intent = create_request.original_intent.clone();
    manager.create_task(&create_request).unwrap();
    assert!(
        manager
            .transition(&request(
                "tr-portable-provenance",
                "T-portable-provenance",
                1,
                TaskState::Created,
                TaskState::Planning,
            ))
            .unwrap()
            .applied
    );
    let export = manager.export_provenance("T-portable-provenance").unwrap();
    assert!(!export.records_jsonl.contains(&private_intent));
    assert!(!export.records_jsonl.contains("intent_commitment_nonce"));
    assert!(export.records_jsonl.contains("original_intent_ref"));
    let verification = aios_provenance::verify_jsonl_export(
        &export.manifest_json,
        &export.records_jsonl,
        TEST_TIME,
    )
    .unwrap();
    assert!(verification.valid, "{verification:?}");
    assert_eq!(verification.scope, "exported-projection");
    assert!(!verification.original_chain_verified_offline);
    assert!(!verification.original_chain_linkage_proven);
}

#[test]
fn portable_export_rejects_private_task_and_journal_disagreement() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    for (task_id, tamper) in [
        (
            "T-export-bad-nonce",
            "UPDATE tasks SET intent_commitment_nonce = zeroblob(1) WHERE task_id = ?1",
        ),
        (
            "T-export-bad-intent",
            "UPDATE tasks SET original_intent = 'changed' WHERE task_id = ?1",
        ),
        (
            "T-export-bad-normalized-intent",
            "UPDATE tasks SET normalized_intent_json = '{}' WHERE task_id = ?1",
        ),
        (
            "T-export-bad-state",
            "UPDATE tasks SET state = 'PLANNING' WHERE task_id = ?1",
        ),
    ] {
        manager.create_task(&create(task_id)).unwrap();
        assert!(manager.export_provenance(task_id).is_ok());
        manager.connection.execute(tamper, [task_id]).unwrap();
        let error = manager.export_provenance(task_id).unwrap_err();
        assert!(
            matches!(error, TaskManagerError::InvalidRecord(_)),
            "{task_id}: {error}"
        );
    }

    let task_id = "T-export-terminal-bad-nonce";
    manager.create_task(&create(task_id)).unwrap();
    let cancelled = manager
        .transition(&request(
            "tr-export-terminal",
            task_id,
            1,
            TaskState::Created,
            TaskState::Cancelled,
        ))
        .unwrap();
    assert!(cancelled.applied);
    assert!(manager.export_provenance(task_id).is_ok());
    manager
        .connection
        .execute(
            "UPDATE tasks SET intent_commitment_nonce = zeroblob(1) WHERE task_id = ?1",
            [task_id],
        )
        .unwrap();
    assert!(manager.export_provenance(task_id).is_err());
}

#[test]
fn portable_export_preserves_storage_failure_from_task_validation() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    let task_id = "T-export-storage-fault";
    manager.create_task(&create(task_id)).unwrap();
    assert!(manager.export_provenance(task_id).is_ok());
    manager
        .connection
        .execute_batch("DROP TABLE task_artifacts")
        .unwrap();
    let error = manager.export_provenance(task_id).unwrap_err();
    assert!(matches!(error, TaskManagerError::Storage(_)), "{error}");
}

#[test]
fn portable_export_preserves_storage_failure_from_task_row_read() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    let task_id = "T-export-row-read-fault";
    manager.create_task(&create(task_id)).unwrap();
    assert!(manager.export_provenance(task_id).is_ok());
    manager
        .connection
        .execute_batch("PRAGMA foreign_keys=OFF; DROP TABLE tasks")
        .unwrap();
    let error = manager.export_provenance(task_id).unwrap_err();
    assert!(matches!(error, TaskManagerError::Storage(_)), "{error}");
}

#[test]
fn provenance_export_and_replay_bind_completed_at_to_completion_transition() {
    let task_id = "T-completed-at-export";
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_nonterminal_history(&mut manager, task_id, TaskState::Verifying);
    let transaction = manager.connection.transaction().unwrap();
    let completion = serde_json::json!({
        "schema_version":SCHEMA_VERSION,
        "event_id":"event:completed-at:completion",
        "task_id":task_id,
        "event_type":"task.transitioned",
        "timestamp":TEST_TIME,
        "actor":{"kind":"system-service","id":"service:test"},
        "status":"success",
        "task_transition":{
            "transition_id":"transition:completed-at:completion",
            "previous_state":"VERIFYING",
            "new_state":"COMPLETED",
            "previous_revision":5,
            "new_revision":6,
            "reason_code":"STATE_CHANGE_REQUESTED"
        },
        "committed_mutation":{
            "active_plan":null,
            "active_step_ids":null,
            "waiting_on":null,
            "failure":null,
            "recovery":null
        },
        "details":{"reason_message_ref":null,"active_program":null}
    });
    let appended = append_event(&transaction, task_id, &completion).unwrap();
    transaction.execute(
        "UPDATE tasks SET revision=6,state='COMPLETED',state_reason_json=?2,updated_at=?3,completed_at=?3 WHERE task_id=?1",
        rusqlite::params![task_id, serde_json::json!({"code":"STATE_CHANGE_REQUESTED","message":null,"provenance_event_id":appended.event_id}).to_string(), TEST_TIME],
    ).unwrap();
    transaction.commit().unwrap();
    assert!(manager.export_provenance(task_id).is_ok());
    manager
        .connection
        .execute(
            "UPDATE tasks SET completed_at='2026-09-20T00:00:00Z' WHERE task_id=?1",
            [task_id],
        )
        .unwrap();
    assert!(manager.verify_provenance(task_id).unwrap());
    assert!(manager.export_provenance(task_id).is_err());
    manager
        .connection
        .execute(
            "UPDATE tasks SET completed_at=NULL WHERE task_id=?1",
            [task_id],
        )
        .unwrap();
    assert!(manager.export_provenance(task_id).is_err());

    let cancelled_id = "T-noncompleted-at-export";
    manager.create_task(&create(cancelled_id)).unwrap();
    assert!(
        manager
            .transition(&request(
                "tr-noncompleted-at",
                cancelled_id,
                1,
                TaskState::Created,
                TaskState::Cancelled
            ))
            .unwrap()
            .applied
    );
    assert!(manager.export_provenance(cancelled_id).is_ok());
    manager
        .connection
        .execute(
            "UPDATE tasks SET completed_at=?2 WHERE task_id=?1",
            rusqlite::params![cancelled_id, TEST_TIME],
        )
        .unwrap();
    assert!(manager.export_provenance(cancelled_id).is_err());

    let directory = tempdir().unwrap();
    let path = directory.path().join("completed-at-replay.sqlite3");
    {
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        manager
            .create_task(&create("T-completed-at-replay"))
            .unwrap();
    }
    Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE tasks SET completed_at=?1 WHERE task_id='T-completed-at-replay'",
            [TEST_TIME],
        )
        .unwrap();
    assert!(TaskManager::open_with_clock(&path, Box::new(FixedClock)).is_err());
}

#[test]
fn startup_fails_closed_for_missing_corrupt_or_head_mismatched_provenance() {
    let directory = tempdir().unwrap();
    for (name, mutate) in [
        (
            "corrupt",
            "DROP TRIGGER provenance_events_no_update;
             UPDATE provenance_events SET event_hash = 'sha256:bad' WHERE task_id = 'T-integrity' AND sequence = 2",
        ),
        (
            "head",
            "UPDATE tasks SET revision = revision + 1 WHERE task_id = 'T-integrity'",
        ),
    ] {
        let path = directory.path().join(format!("{name}.sqlite3"));
        {
            let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
            seed_nonterminal_history(&mut manager, "T-integrity", TaskState::Running);
        }
        Connection::open(&path)
            .unwrap()
            .execute_batch(mutate)
            .unwrap();
        assert!(TaskManager::open_with_clock(&path, Box::new(FixedClock)).is_err());
    }
}

#[test]
fn spoofed_rollback_metadata_and_rejected_admission_are_durable_and_idempotent() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    manager.create_task(&create("T-rollback-spoof")).unwrap();
    let mut failed = request(
        "tr-fail",
        "T-rollback-spoof",
        1,
        TaskState::Created,
        TaskState::Failed,
    );
    failed.mutation.failure = Some(FailureRecord {
        code: "FAILED".to_owned(),
        summary: "no rollback".to_owned(),
        step_id: None,
        provider_id: None,
        execution_binding_id: None,
        retryable: false,
        safe_to_replan: false,
        unknown_side_effects: false,
        rollback_available: false,
        provenance_event_ids: Vec::new(),
    });
    assert!(manager.transition(&failed).unwrap().applied);
    let mut spoof = request(
        "tr-rollback-spoof",
        "T-rollback-spoof",
        2,
        TaskState::Failed,
        TaskState::RollingBack,
    );
    spoof.mutation.failure = Some(FailureRecord {
        rollback_available: true,
        ..failed.mutation.failure.clone().unwrap()
    });
    assert_eq!(
        manager.transition(&spoof).unwrap().reason_code,
        "TASK_TRANSITION_GUARD_FAILED"
    );

    manager.create_task(&create("T-admission")).unwrap();
    manager
        .connection
        .execute(
            "UPDATE tasks SET revision = 2, state = 'RUNNABLE' WHERE task_id = 'T-admission'",
            [],
        )
        .unwrap();
    let denied = request(
        "tr-admission-denied",
        "T-admission",
        2,
        TaskState::Runnable,
        TaskState::Running,
    );
    let first = manager.transition(&denied).unwrap();
    assert_eq!(first.reason_code, "TASK_PROGRAM_NOT_RUNNABLE");
    assert_eq!(manager.transition(&denied).unwrap(), first);

    manager
        .connection
        .execute(
            "INSERT INTO operations (operation_id, task_id, semantic_program_hash, node_id, effect_class, state, outcome_certainty, prepared_at) VALUES ('operation-unknown', 'T-admission', ?1, 'node-1', 'NETWORK', 'UNKNOWN', 'OUTCOME_UNKNOWN', '2026-09-19T00:00:00Z')",
            [HASH],
        )
        .unwrap();
    let unknown = request(
        "tr-admission-unknown",
        "T-admission",
        2,
        TaskState::Runnable,
        TaskState::Running,
    );
    assert_eq!(
        manager.transition(&unknown).unwrap().reason_code,
        "TASK_UNKNOWN_EXTERNAL_OUTCOME"
    );

    manager.create_task(&create("T-program-spoof")).unwrap();
    manager
        .connection
        .execute(
            "UPDATE tasks SET revision = 2, state = 'PLANNING' WHERE task_id = 'T-program-spoof'",
            [],
        )
        .unwrap();
    let invalid_program = request(
        "tr-invalid-program",
        "T-program-spoof",
        2,
        TaskState::Planning,
        TaskState::Runnable,
    );
    assert_eq!(
        manager.transition(&invalid_program).unwrap().reason_code,
        "TASK_PROGRAM_NOT_RUNNABLE"
    );
}

#[test]
fn fenced_owner_blocks_secondary_manager_and_next_owner_advances_epoch() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("concurrent.sqlite3");
    let mut setup = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
    setup.create_task(&create("T-concurrent")).unwrap();
    drop(setup);

    let mut owner = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
    let first_epoch = owner.lease_epoch;
    assert!(TaskManager::open_with_clock(&path, Box::new(FixedClock)).is_err());
    let alias = directory.path().join("concurrent-hardlink.sqlite3");
    std::fs::hard_link(&path, &alias).unwrap();
    assert!(TaskManager::open_with_clock(&alias, Box::new(FixedClock)).is_err());
    let alternate_temp = directory.path().join("alternate-process-temp");
    std::fs::create_dir(&alternate_temp).unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "adversarial_tests::store_lock_subprocess_helper",
            "--nocapture",
        ])
        .env("AIOS_LOCK_TEST_PATH", &alias)
        .env("TEMP", &alternate_temp)
        .env("TMP", &alternate_temp)
        .env("TMPDIR", &alternate_temp)
        .status()
        .unwrap();
    assert!(child.success());
    assert_eq!(
        owner
            .connection
            .query_row(
                "SELECT fence_epoch FROM task_manager_lease WHERE singleton_id=1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        first_epoch
    );
    assert!(
        owner
            .transition(&request(
                "tr-concurrent-plan",
                "T-concurrent",
                1,
                TaskState::Created,
                TaskState::Planning
            ))
            .unwrap()
            .applied
    );
    drop(owner);
    let manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
    assert!(manager.lease_epoch > first_epoch);
    assert_eq!(
        manager.get_task("T-concurrent").unwrap().unwrap().revision,
        2
    );
    assert_eq!(manager.provenance_count("T-concurrent").unwrap(), 2);
    assert!(manager.verify_provenance("T-concurrent").unwrap());
}

#[test]
fn store_lock_subprocess_helper() {
    let Some(path) = std::env::var_os("AIOS_LOCK_TEST_PATH") else {
        return;
    };
    assert!(TaskManager::open_with_clock(path, Box::new(FixedClock)).is_err());
}

#[test]
fn caller_cannot_clear_pending_approval_or_invent_active_steps_for_admission() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    manager.create_task(&create("T-guard-spoof")).unwrap();
    manager
        .connection
        .execute_batch(
            "INSERT INTO registry_snapshots (
                 snapshot_id, manifest_json, created_at
             ) VALUES ('snapshot-1', '{}', '2026-09-19T00:00:00Z');
             INSERT INTO validation_results (
                 validation_result_id, task_id, valid, semantic_hash,
                 registry_snapshot_id, validator_id, validator_version,
                 result_json, validated_at
             ) VALUES (
                 'validation-1', 'T-guard-spoof', 1,
                 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50',
                 'snapshot-1', 'validator:test', '0.1', '{}',
                 '2026-09-19T00:00:00Z'
             );
             INSERT INTO semantic_program_revisions (
                 task_id, program_revision, program_id, ir_version,
                 semantic_hash, registry_snapshot_id, validation_result_id,
                 status, program_json, created_at
             ) VALUES (
                 'T-guard-spoof', 1, 'program-1', '0.1',
                 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50',
                 'snapshot-1', 'validation-1', 'active', '{}',
                 '2026-09-19T00:00:00Z'
             );
             UPDATE tasks SET
                 revision = 2,
                 state = 'WAITING_FOR_AUTH',
                 active_program_revision = 1,
                 active_step_ids_json = '[\"node-real\"]',
                 waiting_on_json = '[{\"kind\":\"approval\",\"id\":\"approval-1\",\"message\":null}]'
             WHERE task_id = 'T-guard-spoof';
             INSERT INTO authority_requests (
                 request_id, task_id, semantic_program_hash,
                 registry_snapshot_id, node_id, capability, principal_kind,
                 principal_id, action, resolved_resource_kind,
                 resolved_resource_id, request_json, requested_at
             ) VALUES (
                 'authority-1', 'T-guard-spoof',
                 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50',
                 'snapshot-1', 'node-real', 'test.capability', 'user',
                 'user:adversarial', 'test.execute', 'test-resource',
                 'resource-1', '{}', '2026-09-19T00:00:00Z'
             );
             INSERT INTO approval_requests (
                 approval_id, authority_request_id, task_id,
                 semantic_program_hash, node_id, action, status,
                 request_json, created_at
             ) VALUES (
                 'approval-1', 'authority-1', 'T-guard-spoof',
                 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50',
                 'node-real', 'test.execute', 'PENDING', '{}',
                 '2026-09-19T00:00:00Z'
             );
             INSERT INTO step_executions (
                 attempt_id, task_id, semantic_program_hash, node_id,
                 attempt_number, revision, state, input_artifacts_json,
                 output_artifacts_json, created_at, updated_at
             ) VALUES (
                 'attempt-ready', 'T-guard-spoof',
                 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50',
                 'node-real', 1, 1, 'READY', '[]', '[]',
                 '2026-09-19T00:00:00Z', '2026-09-19T00:00:00Z'
             );",
        )
        .unwrap();

    let mut clear_approval = request(
        "tr-clear-approval",
        "T-guard-spoof",
        2,
        TaskState::WaitingForAuth,
        TaskState::Runnable,
    );
    clear_approval.mutation.waiting_on = Some(Vec::new());
    assert_eq!(
        manager.transition(&clear_approval).unwrap().reason_code,
        "TASK_PROGRAM_NOT_RUNNABLE"
    );

    manager
        .connection
        .execute(
            "UPDATE tasks SET revision = 3, state = 'RUNNABLE', waiting_on_json = '[]' WHERE task_id = 'T-guard-spoof'",
            [],
        )
        .unwrap();
    let mut invent_step = request(
        "tr-invent-step",
        "T-guard-spoof",
        3,
        TaskState::Runnable,
        TaskState::Running,
    );
    invent_step.mutation.active_step_ids = Some(vec!["node-invented".to_owned()]);
    assert_eq!(
        manager.transition(&invent_step).unwrap().reason_code,
        "TASK_TRANSITION_GUARD_FAILED"
    );
}

#[test]
fn database_fault_between_event_and_task_update_rolls_back_everything() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    manager.create_task(&create("T-db-fault")).unwrap();
    manager
        .connection
        .execute_batch(
            "CREATE TRIGGER inject_task_update_failure
             BEFORE UPDATE OF revision, state ON tasks
             WHEN OLD.task_id = 'T-db-fault' AND NEW.revision > OLD.revision
             BEGIN
                 SELECT RAISE(ABORT, 'injected task update failure');
             END;",
        )
        .unwrap();
    let result = manager.transition(&request(
        "tr-db-fault",
        "T-db-fault",
        1,
        TaskState::Created,
        TaskState::Planning,
    ));
    assert!(result.is_err());
    let task = manager.get_task("T-db-fault").unwrap().unwrap();
    assert_eq!((task.state, task.revision), (TaskState::Created, 1));
    assert_eq!(manager.provenance_count("T-db-fault").unwrap(), 1);
    assert_eq!(
        manager
            .connection
            .query_row(
                "SELECT COUNT(*) FROM task_transitions WHERE transition_id = 'tr-db-fault'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
}

#[allow(
    clippy::too_many_lines,
    reason = "keeps the complete cross-table completion evidence fixture auditable in one place"
)]
fn seed_completion_fixture(
    manager: &mut TaskManager,
    verification_hash: &str,
    verification_artifacts: &[&str],
    publication_state: &str,
) {
    seed_completion_fixture_with_identity(
        manager,
        verification_hash,
        "snapshot-completion",
        "validation-completion",
        verification_artifacts,
        publication_state,
    );
}

#[allow(
    clippy::too_many_lines,
    reason = "builds one complete durable completion fixture across related tables"
)]
fn seed_completion_fixture_with_identity(
    manager: &mut TaskManager,
    verification_hash: &str,
    verification_snapshot: &str,
    verification_validation: &str,
    verification_artifacts: &[&str],
    publication_state: &str,
) {
    manager.create_task(&create("T-completion")).unwrap();
    manager
        .connection
        .execute_batch(
            "INSERT INTO registry_snapshots (
                 snapshot_id, manifest_json, created_at
             ) VALUES ('snapshot-completion', '{\"capability_contracts\":[{\"content_hash\":\"sha256:2222222222222222222222222222222222222222222222222222222222222222\",\"id\":\"test.complete\",\"version\":\"1.0\"}],\"created_at\":\"2026-09-19T00:00:00Z\",\"schema_version\":\"0.1\",\"snapshot_id\":\"snapshot-completion\",\"type_contracts\":[]}', '2026-09-19T00:00:00Z');
             INSERT INTO plan_revisions (
                 task_id, plan_revision, plan_id, plan_json, created_at
             ) VALUES (
                 'T-completion', 1, 'plan-1', '{}',
                 '2026-09-19T00:00:00Z'
             );
             INSERT INTO validation_results (
                 validation_result_id, task_id, program_id, ir_version, valid, semantic_hash,
                 registry_snapshot_id, validator_id, validator_version,
                 result_json, validated_at
             ) VALUES (
                 'validation-completion', 'T-completion', 'program-completion', '0.1', 1,
                 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50',
                 'snapshot-completion', 'validator:test', '0.1',
                 '{\"diagnostics\":[],\"diagnostics_truncated\":false,\"ir_version\":\"0.1\",\"program_id\":\"program-completion\",\"registry_snapshot_id\":\"snapshot-completion\",\"schema_version\":\"0.1\",\"semantic_hash\":\"sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50\",\"semantic_hash_profile\":\"aios-ir-v0.1\",\"valid\":true,\"validated_at\":\"2026-09-19T00:00:00Z\",\"validator\":{\"build_hash\":null,\"id\":\"validator:test\",\"version\":\"0.1\"}}',
                 '2026-09-19T00:00:00Z'
             );
             INSERT INTO semantic_program_revisions (
                 task_id, program_revision, program_id, ir_version,
                 semantic_hash, registry_snapshot_id, validation_result_id,
                 created_from_plan_revision, status, program_json, created_at
             ) VALUES (
                 'T-completion', 1, 'program-completion', '0.1',
                 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50',
                 'snapshot-completion', 'validation-completion', 1, 'active',
                 '{\"inputs\":{},\"ir_version\":\"0.1\",\"kind\":\"task_graph\",\"nodes\":[{\"authority_requests\":[],\"cache\":\"never\",\"egress\":{\"mode\":\"deny\"},\"execution_class\":\"deterministic\",\"failure\":{\"on_error\":\"stop\"},\"id\":\"node-completion\",\"inputs\":{},\"operation\":{\"capability\":\"test.complete@1\",\"kind\":\"invoke\"},\"outputs\":{\"report\":\"artifact.report@1\"}}],\"outputs\":{\"report\":{\"node\":\"node-completion\",\"port\":\"report\",\"source\":\"node\"}},\"program_id\":\"program-completion\"}',
                 '2026-09-19T00:00:00Z'
             );
             INSERT INTO provider_registrations (
                 registration_id, provider_id, provider_version, manifest_hash,
                 package_content_hash, registry_snapshot_id, state, trust_status,
                 registration_json, registered_at
             ) VALUES (
                 'registration-completion', 'provider:test', '0.1.0',
                 'sha256:manifest', 'sha256:build', 'snapshot-completion',
                 'registered', 'locally-trusted', '{}', '2026-09-19T00:00:00Z'
             );
             INSERT INTO provider_conformance_evidence (
                 evidence_id, registration_id, capability, contract_hash,
                 suite_id, suite_hash, status, evidence_json, tested_at
             ) VALUES (
                 'evidence-completion', 'registration-completion',
                 'test.complete@1', 'sha256:2222222222222222222222222222222222222222222222222222222222222222',
                 'suite:test', 'sha256:3333333333333333333333333333333333333333333333333333333333333333', 'pass',
                 '{\"conformance_suite\":{\"hash\":\"sha256:3333333333333333333333333333333333333333333333333333333333333333\",\"id\":\"suite:test\",\"version\":\"0.1\"},\"executed_at\":\"2026-09-19T00:00:00Z\",\"expires_at\":\"2026-09-20T00:00:00Z\",\"harness\":{\"build_hash\":null,\"id\":\"harness:test\",\"version\":\"0.1\"},\"provider_build_identity\":{\"kind\":\"build_hash\",\"value\":\"sha256:build\"},\"provider_id\":\"provider:test\",\"provider_version\":\"0.1.0\",\"result\":\"pass\",\"result_id\":\"evidence-completion\",\"schema_version\":\"0.1\",\"semantic_capability_ref\":\"test.complete@1\",\"semantic_contract_hash\":\"sha256:2222222222222222222222222222222222222222222222222222222222222222\",\"semantic_contract_version\":\"1.0\"}',
                 '2026-09-19T00:00:00Z'
             );
             INSERT INTO execution_bindings (
                 binding_id, attempt_id, task_id, semantic_program_hash,
                 registry_snapshot_id, ir_version, node_id, capability,
                 capability_contract_hash, provider_registration_id,
                 provider_id, provider_version, provider_manifest_hash,
                 provider_build_hash, attempt,
                 policy_decision_refs_json, grant_refs_json,
                 execution_profile_ref, placement_json, binding_json, created_at
             ) VALUES (
                 'binding-completion', 'attempt-completion', 'T-completion',
                 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50',
                 'snapshot-completion', '0.1', 'node-completion',
                 'test.complete@1', 'sha256:2222222222222222222222222222222222222222222222222222222222222222', 'registration-completion',
                 'provider:test', '0.1.0', 'sha256:manifest', 'sha256:build', 1,
                 '[]', '[]', 'profile:test', '{\"locality\":\"local\"}',
                 '{\"attempt\":1,\"attempt_id\":\"attempt-completion\",\"authority\":{\"grant_refs\":[]},\"binding_id\":\"binding-completion\",\"capability\":\"test.complete@1\",\"capability_contract_hash\":\"sha256:2222222222222222222222222222222222222222222222222222222222222222\",\"created_at\":\"2026-09-19T00:00:00Z\",\"execution_profile\":{\"profile_ref\":\"profile:test\"},\"inputs\":{},\"ir_version\":\"0.1\",\"node_id\":\"node-completion\",\"outputs\":{\"report\":{\"allocation_ref\":\"allocation-completion\",\"semantic_type\":\"artifact.report@1\"}},\"placement\":{\"locality\":\"local\"},\"policy_decision_refs\":[],\"provider\":{\"id\":\"provider:test\",\"manifest_hash\":\"sha256:manifest\",\"package_or_build_hash\":\"sha256:build\",\"version\":\"0.1.0\"},\"registry_snapshot_id\":\"snapshot-completion\",\"schema_version\":\"0.1\",\"semantic_program_hash\":\"sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50\",\"task_id\":\"T-completion\"}',
                 '2026-09-19T00:00:00Z'
             );
             INSERT INTO step_executions (
                 attempt_id, task_id, semantic_program_hash,
                 registry_snapshot_id, node_id, binding_id, provider_id,
                 provider_version, attempt_number, revision, state,
                 outcome_certainty, input_artifacts_json,
                 output_artifacts_json, started_at, finished_at,
                 created_at, updated_at
             ) VALUES (
                 'attempt-completion', 'T-completion',
                 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50',
                 'snapshot-completion', 'node-completion',
                 'binding-completion', 'provider:test', '0.1.0', 1, 3,
                 'SUCCEEDED', 'COMPLETED', '[]', '[\"artifact:v1:sha256:52c0b01bbc16da99f646722fd55c1ca9dc2a03f6186637485da30679c38fdabe\"]',
                 '2026-09-19T00:00:00Z', '2026-09-19T00:00:00Z',
                 '2026-09-19T00:00:00Z', '2026-09-19T00:00:00Z'
             );
             INSERT INTO artifact_blobs (
                 content_hash, size_bytes, storage_ref, durability_state,
                 created_at, verified_at
             ) VALUES (
                 'sha256:4444444444444444444444444444444444444444444444444444444444444444', 42, 'blob://completion/output',
                 'DURABLE', '2026-09-19T00:00:00Z', '2026-09-19T00:00:00Z'
             );
             INSERT INTO artifacts (
                 artifact_id, uri, semantic_type, media_type, sensitivity, retention_class, origin_kind,
                 origin_task_id, origin_program_hash, origin_node_id,
                 origin_binding_id, origin_provider_id, size_bytes, content_hash,
                 integrity_state, integrity_verified_at, integrity_verifier, labels_json, created_at
             ) VALUES (
                 'artifact:v1:sha256:52c0b01bbc16da99f646722fd55c1ca9dc2a03f6186637485da30679c38fdabe',
                 'artifact://artifact:v1:sha256:52c0b01bbc16da99f646722fd55c1ca9dc2a03f6186637485da30679c38fdabe', 'artifact.report@1',
                 'application/json', 'local', 'task', 'task', 'T-completion',
                 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50',
                 'node-completion', 'binding-completion', 'provider:test',
                 42, 'sha256:4444444444444444444444444444444444444444444444444444444444444444', 'verified',
                 '2026-09-19T00:00:00Z', 'artifact-store:sha256', '[]', '2026-09-19T00:00:00Z'
             );
             INSERT INTO artifact_output_allocations (
                 allocation_id, task_id, semantic_program_hash, node_id,
                 binding_id, attempt_id, output_port, expected_semantic_type, sensitivity, retention, state,
                 publication_id, published_artifact_id, created_at, expires_at
             ) VALUES (
                 'allocation-completion', 'T-completion',
                 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50',
                 'node-completion', 'binding-completion',
                 'attempt-completion', 'report', 'artifact.report@1', 'local', 'task', 'PUBLISHED',
                 'publication-completion',
                 'artifact:v1:sha256:52c0b01bbc16da99f646722fd55c1ca9dc2a03f6186637485da30679c38fdabe', '2026-09-19T00:00:00Z',
                 '2026-09-20T00:00:00Z'
             );
             INSERT INTO task_artifacts (
                 task_id, artifact_id, role, node_id, added_at
             ) VALUES (
                 'T-completion', 'artifact:v1:sha256:52c0b01bbc16da99f646722fd55c1ca9dc2a03f6186637485da30679c38fdabe', 'output',
                 'node-completion', '2026-09-19T00:00:00Z'
             );
             UPDATE tasks SET
                 revision = 2,
                 state = 'VERIFYING',
                 active_plan_revision = 1,
                 active_program_revision = 1,
                 active_step_ids_json = '[\"node-completion\"]',
                 waiting_on_json = '[]'
             WHERE task_id = 'T-completion';",
        )
        .unwrap();
    // This fixture condenses a completed execution into revision 2 so the
    // completion guards can be tested without building the whole lifecycle.
    // The synthetic CREATED -> VERIFYING jump still needs an authentic typed
    // transition in the hash chain before later test transitions can append.
    let transaction = manager.connection.transaction().unwrap();
    let verifying_event = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "event_id": "event:seed:completion-verifying",
        "task_id": "T-completion",
        "event_type": "task.transitioned",
        "timestamp": TEST_TIME,
        "actor": {"kind":"system-service","id":"service:test"},
        "status": "success",
        "task_transition": {
            "transition_id": "transition:seed:completion-verifying",
            "previous_state": "CREATED",
            "new_state": "VERIFYING",
            "previous_revision": 1,
            "new_revision": 2,
            "reason_code": "STATE_CHANGE_REQUESTED"
        },
        "committed_mutation": {
            "active_plan": null,
            "active_step_ids": null,
            "waiting_on": null,
            "failure": null,
            "recovery": null
        },
        "details": {"reason_message_ref": null, "active_program": null}
    });
    let appended = append_event(&transaction, "T-completion", &verifying_event).unwrap();
    transaction
        .execute(
            "UPDATE tasks SET state_reason_json=?2 WHERE task_id=?1",
            rusqlite::params![
                "T-completion",
                serde_json::json!({
                    "code":"STATE_CHANGE_REQUESTED",
                    "message":null,
                    "provenance_event_id":appended.event_id
                })
                .to_string()
            ],
        )
        .unwrap();
    transaction.commit().unwrap();
    let publication_request = ArtifactPublicationRequest {
        schema_version: SCHEMA_VERSION.to_owned(),
        publication_id: "publication-completion".to_owned(),
        allocation_id: "allocation-completion".to_owned(),
        task_id: "T-completion".to_owned(),
        expected_allocation_state: ArtifactExpectedState::Writing,
        semantic_type: Some("artifact.report@1".to_owned()),
        media_type: "application/json".to_owned(),
        format: None,
        lineage: ArtifactLineage::default(),
        labels: Vec::new(),
    };
    manager
        .connection
        .execute(
            "INSERT INTO artifact_publications (
                 publication_id, allocation_id, task_id, artifact_id, content_hash,
                 request_json, state, requested_at, committed_at
             ) VALUES (
                 'publication-completion', 'allocation-completion',
                 'T-completion', 'artifact:v1:sha256:52c0b01bbc16da99f646722fd55c1ca9dc2a03f6186637485da30679c38fdabe', 'sha256:4444444444444444444444444444444444444444444444444444444444444444', ?2, ?1,
                 '2026-09-19T00:00:00Z',
                 CASE WHEN ?1 = 'COMMITTED' THEN '2026-09-19T00:00:00Z' END
             )",
            rusqlite::params![
                publication_state,
                canonical_json(&publication_request).unwrap()
            ],
        )
        .unwrap();
    if publication_state == "COMMITTED" {
        let transaction = manager.connection.transaction().unwrap();
        let publication_event = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "event_id": artifact_store::event_id("artifact-created", COMPLETION_ARTIFACT_ID),
            "task_id": "T-completion",
            "event_type": "artifact.created",
            "timestamp": TEST_TIME,
            "actor": {"kind":"system-service","id":"service:artifact-store"},
            "semantic_program_hash": HASH,
            "step_id": "node-completion",
            "execution_binding_id": "binding-completion",
            "provider_id": "provider:test",
            "input_artifacts": [],
            "output_artifacts": [COMPLETION_ARTIFACT_ID],
            "status": "success",
            "details": {
                "publication_id": "publication-completion",
                "allocation_id": "allocation-completion",
                "content_hash": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
                "size_bytes": 42,
                "blob_reused": false
            }
        });
        let appended = append_event(&transaction, "T-completion", &publication_event).unwrap();
        let result = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "publication_id": "publication-completion",
            "allocation_id": "allocation-completion",
            "task_id": "T-completion",
            "published": true,
            "reason_code": "ARTIFACT_PUBLICATION_APPLIED",
            "message": null,
            "artifact_id": COMPLETION_ARTIFACT_ID,
            "artifact_uri": format!("artifact://{COMPLETION_ARTIFACT_ID}"),
            "semantic_type": "artifact.report@1",
            "media_type": "application/json",
            "size_bytes": 42,
            "content_hash": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
            "blob_reused": false,
            "provenance_event_id": appended.event_id,
            "provenance_event_hash": appended.event_hash,
            "resulted_at": TEST_TIME
        });
        transaction
            .execute(
                "UPDATE artifact_publications SET result_json=?2 WHERE publication_id=?1",
                rusqlite::params!["publication-completion", canonical_json(&result).unwrap()],
            )
            .unwrap();
        transaction.commit().unwrap();
    }
    manager
        .connection
        .execute(
            "INSERT OR IGNORE INTO registry_snapshots (snapshot_id, manifest_json, created_at) VALUES (?1, '{}', '2026-09-19T00:00:00Z')",
            [verification_snapshot],
        )
        .unwrap();
    let verification_artifacts = verification_artifacts
        .iter()
        .map(|artifact_id| {
            if *artifact_id == "artifact-output" {
                COMPLETION_ARTIFACT_ID
            } else {
                *artifact_id
            }
        })
        .collect::<Vec<_>>();
    let transaction = manager.connection.transaction().unwrap();
    let verification = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "event_id": "event:verification:completion",
        "task_id": "T-completion",
        "event_type": "verification.completed",
        "timestamp": "2026-09-19T00:00:00Z",
        "actor": {"kind":"system-service","id":"service:verifier"},
        "semantic_program_hash": verification_hash,
        "registry_snapshot_id": verification_snapshot,
        "validation_result_id": verification_validation,
        "input_artifacts": verification_artifacts,
        "output_artifacts": [],
        "status": "success"
    });
    append_event(&transaction, "T-completion", &verification).unwrap();
    transaction.commit().unwrap();
}

fn align_completion_fixture_state(manager: &mut TaskManager, state: TaskState) {
    let transaction = manager.connection.transaction().unwrap();
    transaction
        .execute_batch("DROP TRIGGER provenance_events_no_update")
        .unwrap();
    let rows = {
        let mut statement = transaction
            .prepare(
                "SELECT sequence,event_id,event_json FROM provenance_events
                 WHERE task_id='T-completion' ORDER BY sequence",
            )
            .unwrap();
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .unwrap();
        rows.collect::<std::result::Result<Vec<_>, _>>().unwrap()
    };
    let mut previous_hash = None;
    for (sequence, event_id, raw_event) in rows {
        let mut event: Value = serde_json::from_str(&raw_event).unwrap();
        if event_id == "event:seed:completion-verifying" {
            event["task_transition"]["new_state"] = serde_json::json!(state);
        }
        let sequence = u64::try_from(sequence).unwrap();
        let event_hash =
            provenance_hash("T-completion", sequence, previous_hash.as_deref(), &event).unwrap();
        transaction
            .execute(
                "UPDATE provenance_events
                 SET previous_event_hash=?3,event_hash=?4,event_json=?5
                 WHERE task_id='T-completion' AND sequence=?1 AND event_id=?2",
                rusqlite::params![
                    i64::try_from(sequence).unwrap(),
                    event_id,
                    previous_hash,
                    event_hash,
                    canonical_json(&event).unwrap()
                ],
            )
            .unwrap();
        let publication = transaction
            .query_row(
                "SELECT publication_id,result_json FROM artifact_publications
                 WHERE json_extract(result_json,'$.provenance_event_id')=?1",
                [&event_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .unwrap();
        if let Some((publication_id, raw_result)) = publication {
            let mut result: Value = serde_json::from_str(&raw_result).unwrap();
            result["provenance_event_hash"] = serde_json::json!(event_hash);
            transaction
                .execute(
                    "UPDATE artifact_publications SET result_json=?2 WHERE publication_id=?1",
                    rusqlite::params![publication_id, canonical_json(&result).unwrap()],
                )
                .unwrap();
        }
        previous_hash = Some(event_hash);
    }
    transaction
        .execute(
            "UPDATE tasks SET state=?1 WHERE task_id='T-completion'",
            [state.as_str()],
        )
        .unwrap();
    transaction
        .execute_batch(
            "CREATE TRIGGER provenance_events_no_update
             BEFORE UPDATE ON provenance_events
             BEGIN SELECT RAISE(ABORT, 'provenance_events are append-only'); END;",
        )
        .unwrap();
    transaction.commit().unwrap();
}

fn set_completion_binding_refs(manager: &TaskManager, decisions: &[&str], grants: &[&str]) {
    let raw = manager
        .connection
        .query_row(
            "SELECT binding_json FROM execution_bindings WHERE binding_id='binding-completion'",
            [],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
    let mut binding: Value = serde_json::from_str(&raw).unwrap();
    binding["policy_decision_refs"] = serde_json::json!(decisions);
    binding["authority"]["grant_refs"] = serde_json::json!(grants);
    manager
        .connection
        .execute_batch("DROP TRIGGER IF EXISTS execution_bindings_no_update")
        .unwrap();
    manager
        .connection
        .execute(
            "UPDATE execution_bindings SET policy_decision_refs_json=?2, grant_refs_json=?3, binding_json=?4 WHERE binding_id=?1",
            rusqlite::params![
                "binding-completion",
                serde_json::to_string(decisions).unwrap(),
                serde_json::to_string(grants).unwrap(),
                canonical_json(&binding).unwrap()
            ],
        )
        .unwrap();
}

fn seed_resolved_empty_recovery(manager: &mut TaskManager, task_id: &str, revision: u64) {
    let recovery_ref = recovery_operations_ref(task_id, revision, &[]).unwrap();
    let epoch_id = format!("epoch:{recovery_ref}");
    let assessment = canonical_json(&serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "assessment_id": recovery_ref,
        "recovery_epoch_id": epoch_id,
        "task_id": task_id,
        "subject": {"kind":"task","id":task_id},
        "certainty": "COMPLETED",
        "evidence": [{"kind":"task-record","ref":format!("task:{task_id}:revision:{revision}"),"observation":"trusted reconciliation resolved every consequential subject"}],
        "safe_action": "RECONCILE_STATE",
        "new_binding_required": false,
        "external_reconciliation_required": false,
        "reason_codes": ["RECOVERY_COMPLETED"],
        "created_at": TEST_TIME
    })).unwrap();
    manager
        .connection
        .execute(
            "INSERT OR IGNORE INTO recovery_epochs(recovery_epoch_id,started_at) VALUES (?1,?2)",
            rusqlite::params![epoch_id, TEST_TIME],
        )
        .unwrap();
    manager.connection.execute(
        "INSERT INTO recovery_assessments(assessment_id,recovery_epoch_id,task_id,basis_revision,subject_kind,subject_id,certainty,safe_action,reason_codes_json,assessment_json,created_at) VALUES (?1,?2,?3,?4,'task',?3,'COMPLETED','RECONCILE_STATE','[\"RECOVERY_COMPLETED\"]',?5,?6)",
        rusqlite::params![recovery_ref, epoch_id, task_id, i64::try_from(revision).unwrap(), assessment, TEST_TIME],
    ).unwrap();
    manager.connection.execute(
        "UPDATE tasks SET recovery_json=?2 WHERE task_id=?1",
        rusqlite::params![task_id, serde_json::json!({"unknown_operations_ref":recovery_ref,"last_known_daemon_instance":null}).to_string()],
    ).unwrap();
}

fn completion_request(id: &str) -> TransitionRequest {
    request(
        id,
        "T-completion",
        2,
        TaskState::Verifying,
        TaskState::Completed,
    )
}

#[test]
fn verifying_completes_with_current_program_exact_step_publication_and_coverage() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
    assert!(
        committed_publication_structurally_valid(
            &manager.connection,
            "T-completion",
            "publication-completion"
        )
        .unwrap(),
        "stored result: {}",
        manager
            .connection
            .query_row(
                "SELECT result_json FROM artifact_publications WHERE publication_id='publication-completion'",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap()
    );

    let result = manager
        .transition(&completion_request("tr-completion-valid"))
        .unwrap();
    assert!(result.applied, "{}", result.reason_code);
    assert_eq!(result.current_state, Some(TaskState::Completed));
    assert_eq!(result.current_revision, Some(3));
    assert!(manager.verify_provenance("T-completion").unwrap());
}

#[test]
fn forged_committed_publication_receipt_enters_inventory_and_blocks_completion() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
    let raw = manager
        .connection
        .query_row(
            "SELECT result_json FROM artifact_publications
             WHERE publication_id='publication-completion'",
            [],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
    let mut forged: Value = serde_json::from_str(&raw).unwrap();
    forged["size_bytes"] = serde_json::json!(43);
    manager
        .connection
        .execute(
            "UPDATE artifact_publications SET result_json=?1
             WHERE publication_id='publication-completion'",
            [canonical_json(&forged).unwrap()],
        )
        .unwrap();

    assert!(
        !committed_publication_structurally_valid(
            &manager.connection,
            "T-completion",
            "publication-completion"
        )
        .unwrap()
    );
    assert!(
        unresolved_execution_ids(&manager.connection, "T-completion")
            .unwrap()
            .contains(&"publication:publication-completion".to_owned())
    );
    let result = manager
        .transition(&completion_request("tr-completion-forged-publication"))
        .unwrap();
    assert!(!result.applied);
    let task = manager.get_task("T-completion").unwrap().unwrap();
    assert_eq!(task.state, TaskState::Verifying);
    assert_eq!(task.revision, 2);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "constructs a fully coherent but nondeterministically identified publication to exercise the shared replay/recovery proof"
)]
fn coherent_mislinked_publication_is_rejected_by_replay_inventory_and_completion() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
    let rogue_id =
        "artifact:v1:sha256:9999999999999999999999999999999999999999999999999999999999999999";
    let rogue_uri = format!("artifact://{rogue_id}");
    manager
        .connection
        .execute_batch(
            "DROP TRIGGER provenance_events_no_delete;
             DELETE FROM provenance_events
              WHERE task_id='T-completion'
                AND sequence >= (SELECT sequence FROM provenance_events
                                  WHERE task_id='T-completion'
                                    AND event_type='artifact.created');",
        )
        .unwrap();
    manager
        .connection
        .execute(
            "INSERT INTO artifacts(
                 artifact_id,uri,semantic_type,media_type,format,size_bytes,content_hash,
                 sensitivity,retention_class,expires_at,origin_kind,origin_task_id,
                 origin_program_hash,origin_node_id,origin_binding_id,origin_provider_id,
                 integrity_state,integrity_verified_at,integrity_verifier,labels_json,created_at)
             SELECT ?1,?2,semantic_type,media_type,format,size_bytes,content_hash,
                    sensitivity,retention_class,expires_at,origin_kind,origin_task_id,
                    origin_program_hash,origin_node_id,origin_binding_id,origin_provider_id,
                    integrity_state,integrity_verified_at,integrity_verifier,labels_json,created_at
               FROM artifacts WHERE artifact_id=?3",
            rusqlite::params![rogue_id, rogue_uri, COMPLETION_ARTIFACT_ID],
        )
        .unwrap();
    manager
        .connection
        .execute(
            "INSERT INTO task_artifacts(task_id,artifact_id,role,node_id,added_at)
             SELECT task_id,?1,role,node_id,added_at FROM task_artifacts
              WHERE task_id='T-completion' AND artifact_id=?2",
            rusqlite::params![rogue_id, COMPLETION_ARTIFACT_ID],
        )
        .unwrap();
    manager
        .connection
        .execute_batch(&format!(
            "UPDATE artifact_output_allocations SET published_artifact_id='{rogue_id}'
              WHERE allocation_id='allocation-completion';
             UPDATE artifact_publications SET artifact_id='{rogue_id}'
              WHERE publication_id='publication-completion';
             UPDATE step_executions SET output_artifacts_json='[\"{rogue_id}\"]'
              WHERE attempt_id='attempt-completion';"
        ))
        .unwrap();
    let transaction = manager.connection.transaction().unwrap();
    let publication_event = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "event_id": artifact_store::event_id("artifact-created", rogue_id),
        "task_id": "T-completion",
        "event_type": "artifact.created",
        "timestamp": TEST_TIME,
        "actor": {"kind":"system-service","id":"service:artifact-store"},
        "semantic_program_hash": HASH,
        "step_id": "node-completion",
        "execution_binding_id": "binding-completion",
        "provider_id": "provider:test",
        "input_artifacts": [],
        "output_artifacts": [rogue_id],
        "status": "success",
        "details": {
            "publication_id": "publication-completion",
            "allocation_id": "allocation-completion",
            "content_hash": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
            "size_bytes": 42,
            "blob_reused": false
        }
    });
    let appended = append_event(&transaction, "T-completion", &publication_event).unwrap();
    let raw_result = transaction
        .query_row(
            "SELECT result_json FROM artifact_publications
             WHERE publication_id='publication-completion'",
            [],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
    let mut result: Value = serde_json::from_str(&raw_result).unwrap();
    result["artifact_id"] = serde_json::json!(rogue_id);
    result["artifact_uri"] = serde_json::json!(rogue_uri);
    result["provenance_event_id"] = serde_json::json!(appended.event_id);
    result["provenance_event_hash"] = serde_json::json!(appended.event_hash);
    transaction
        .execute(
            "UPDATE artifact_publications SET result_json=?1
             WHERE publication_id='publication-completion'",
            [canonical_json(&result).unwrap()],
        )
        .unwrap();
    let verification = serde_json::json!({
        "schema_version":SCHEMA_VERSION,
        "event_id":"event:verification:completion",
        "task_id":"T-completion",
        "event_type":"verification.completed",
        "timestamp":TEST_TIME,
        "actor":{"kind":"system-service","id":"service:verifier"},
        "semantic_program_hash":HASH,
        "registry_snapshot_id":"snapshot-completion",
        "validation_result_id":"validation-completion",
        "input_artifacts":[rogue_id],
        "output_artifacts":[],
        "status":"success"
    });
    append_event(&transaction, "T-completion", &verification).unwrap();
    transaction.commit().unwrap();

    assert!(
        !committed_publication_structurally_valid(
            &manager.connection,
            "T-completion",
            "publication-completion"
        )
        .unwrap()
    );
    assert!(
        unresolved_execution_ids(&manager.connection, "T-completion")
            .unwrap()
            .contains(&"publication:publication-completion".to_owned())
    );
    let request_json = manager
        .connection
        .query_row(
            "SELECT request_json FROM artifact_publications
             WHERE publication_id='publication-completion'",
            [],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
    let request: ArtifactPublicationRequest = serde_json::from_str(&request_json).unwrap();
    assert_eq!(
        manager
            .publish_artifact_output(&request)
            .unwrap()
            .reason_code,
        "ARTIFACT_INTEGRITY_FAILED"
    );
    let completion = manager
        .transition(&completion_request("tr-completion-mislinked-publication"))
        .unwrap();
    assert!(!completion.applied);
    assert_eq!(completion.reason_code, "TASK_UNKNOWN_EXTERNAL_OUTCOME");
}

#[test]
fn completion_rejects_stale_verification_missing_or_mismatched_coverage_and_unpublished_output() {
    for (name, verification_hash, artifacts, publication_state) in [
        (
            "stale-program",
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            vec!["artifact-output"],
            "COMMITTED",
        ),
        ("missing-coverage", HASH, Vec::new(), "COMMITTED"),
        (
            "mismatched-coverage",
            HASH,
            vec!["artifact-other"],
            "COMMITTED",
        ),
        (
            "unpublished-output",
            HASH,
            vec!["artifact-output"],
            "PENDING",
        ),
    ] {
        let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
        seed_completion_fixture(
            &mut manager,
            verification_hash,
            &artifacts,
            publication_state,
        );
        let result = manager
            .transition(&completion_request(&format!("tr-completion-{name}")))
            .unwrap();
        assert_eq!(
            result.reason_code,
            if name == "unpublished-output" {
                "TASK_UNKNOWN_EXTERNAL_OUTCOME"
            } else {
                "TASK_COMPLETION_GATE_FAILED"
            },
            "{name}"
        );
        let task = manager.get_task("T-completion").unwrap().unwrap();
        assert_eq!((task.state, task.revision), (TaskState::Verifying, 2));
    }
}

#[test]
fn distinct_pending_publication_blocks_otherwise_valid_completion_until_aborted() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
    manager
        .connection
        .execute(
            "INSERT INTO artifact_output_allocations (
                 allocation_id,task_id,semantic_program_hash,node_id,binding_id,attempt_id,
                 output_port,expected_semantic_type,allowed_media_types_json,max_size_bytes,
                 sensitivity,retention,state,writer_generation,created_at,updated_at,expires_at
             )
             SELECT 'allocation-pending-extra',task_id,semantic_program_hash,node_id,NULL,NULL,
                    'auxiliary',expected_semantic_type,allowed_media_types_json,max_size_bytes,
                    sensitivity,retention,'WRITING',0,created_at,updated_at,expires_at
             FROM artifact_output_allocations WHERE allocation_id='allocation-completion'",
            [],
        )
        .unwrap();
    let pending = ArtifactPublicationRequest {
        schema_version: SCHEMA_VERSION.to_owned(),
        publication_id: "publication-pending-extra".to_owned(),
        allocation_id: "allocation-pending-extra".to_owned(),
        task_id: "T-completion".to_owned(),
        expected_allocation_state: ArtifactExpectedState::Writing,
        semantic_type: Some("artifact.report@1".to_owned()),
        media_type: "application/json".to_owned(),
        format: None,
        lineage: ArtifactLineage::default(),
        labels: Vec::new(),
    };
    let pending_json = canonical_json(&pending).unwrap();
    manager
        .reserve_publication(&pending, &pending_json)
        .unwrap();
    assert!(
        unresolved_execution_ids(&manager.connection, "T-completion")
            .unwrap()
            .contains(&"publication:publication-pending-extra".to_owned())
    );
    assert!(matches!(
        manager.scope_owned_artifact_reads("T-completion", &[COMPLETION_ARTIFACT_ID.to_owned()]),
        Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
    ));

    let blocked = manager
        .transition(&completion_request("tr-completion-pending-extra"))
        .unwrap();
    assert!(!blocked.applied);
    assert_eq!(blocked.reason_code, "TASK_UNKNOWN_EXTERNAL_OUTCOME");
    let unchanged = manager.get_task("T-completion").unwrap().unwrap();
    assert_eq!(
        (unchanged.state, unchanged.revision),
        (TaskState::Verifying, 2)
    );

    manager.abort_pending_publication(&pending).unwrap();
    let completed = manager
        .transition(&completion_request("tr-completion-after-pending-abort"))
        .unwrap();
    assert!(completed.applied);
    assert_eq!(completed.current_state, Some(TaskState::Completed));
}

#[test]
fn completed_and_rolled_back_tasks_cannot_be_reopened() {
    let mut completed = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut completed, HASH, &["artifact-output"], "COMMITTED");
    assert!(
        completed
            .transition(&completion_request("tr-complete-terminal"))
            .unwrap()
            .applied
    );
    let completed_reopen = completed
        .transition(&request(
            "tr-reopen-completed",
            "T-completion",
            3,
            TaskState::Completed,
            TaskState::Planning,
        ))
        .unwrap();
    assert_eq!(completed_reopen.reason_code, "TASK_TERMINAL_STATE");

    let mut rolled_back = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    rolled_back.create_task(&create("T-rolled-back")).unwrap();
    rolled_back
        .connection
        .execute(
            "UPDATE tasks SET revision = 2, state = 'ROLLED_BACK' WHERE task_id = 'T-rolled-back'",
            [],
        )
        .unwrap();
    let rolled_back_reopen = rolled_back
        .transition(&request(
            "tr-reopen-rolled-back",
            "T-rolled-back",
            2,
            TaskState::RolledBack,
            TaskState::Planning,
        ))
        .unwrap();
    assert_eq!(rolled_back_reopen.reason_code, "TASK_TERMINAL_STATE");
}

#[test]
fn provenance_verification_detects_previous_hash_event_json_and_sequence_tampering() {
    for (name, mutation) in [
        (
            "previous-hash",
            "UPDATE provenance_events SET previous_event_hash = 'sha256:bad' WHERE task_id = 'T-tamper' AND sequence = 2",
        ),
        (
            "event-json",
            "UPDATE provenance_events SET event_json = '{}' WHERE task_id = 'T-tamper' AND sequence = 2",
        ),
        (
            "sequence",
            "UPDATE provenance_events SET sequence = 3 WHERE task_id = 'T-tamper' AND sequence = 2",
        ),
        (
            "event-id-column",
            "UPDATE provenance_events SET event_id = 'event:tampered-column' WHERE task_id = 'T-tamper' AND sequence = 2",
        ),
        (
            "stream-column",
            "UPDATE provenance_events SET stream_id = 'task:other' WHERE task_id = 'T-tamper' AND sequence = 2",
        ),
        (
            "timestamp-column",
            "UPDATE provenance_events SET timestamp = '2026-09-20T00:00:00Z' WHERE task_id = 'T-tamper' AND sequence = 2",
        ),
        (
            "event-type-column",
            "UPDATE provenance_events SET event_type = 'task.failed' WHERE task_id = 'T-tamper' AND sequence = 2",
        ),
        (
            "status-column",
            "UPDATE provenance_events SET status = 'failure' WHERE task_id = 'T-tamper' AND sequence = 2",
        ),
    ] {
        let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
        manager.create_task(&create("T-tamper")).unwrap();
        assert!(
            manager
                .transition(&request(
                    &format!("tr-tamper-{name}"),
                    "T-tamper",
                    1,
                    TaskState::Created,
                    TaskState::Planning,
                ))
                .unwrap()
                .applied
        );
        manager
            .connection
            .execute_batch("DROP TRIGGER provenance_events_no_update")
            .unwrap();
        manager.connection.execute(mutation, []).unwrap();
        assert!(!manager.verify_provenance("T-tamper").unwrap(), "{name}");
    }
}

#[test]
fn recovering_to_running_rechecks_durable_approval_blockers_before_admission() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
    manager
        .connection
        .execute_batch(
            "UPDATE tasks SET
                 state = 'RECOVERING',
                 active_step_ids_json = '[\"node-completion\"]',
                 waiting_on_json = '[{\"kind\":\"approval\",\"id\":\"approval-recovery\",\"message\":null}]'
             WHERE task_id = 'T-completion';
             UPDATE step_executions SET state = 'READY', revision = 4
             WHERE attempt_id = 'attempt-completion';
             INSERT INTO authority_requests (
                 request_id, task_id, semantic_program_hash,
                 registry_snapshot_id, node_id, capability, principal_kind,
                 principal_id, action, resolved_resource_kind,
                 resolved_resource_id, request_json, requested_at
             ) VALUES (
                 'authority-recovery', 'T-completion',
                 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50',
                 'snapshot-completion', 'node-completion', 'test.complete',
                 'user', 'user:adversarial', 'test.execute', 'test-resource',
                 'resource-recovery', '{}', '2026-09-19T00:00:00Z'
             );
             INSERT INTO approval_requests (
                 approval_id, authority_request_id, task_id,
                 semantic_program_hash, node_id, action, status,
                 request_json, created_at
             ) VALUES (
                 'approval-recovery', 'authority-recovery', 'T-completion',
                 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50',
                 'node-completion', 'test.execute', 'PENDING', '{}',
                 '2026-09-19T00:00:00Z'
             );",
        )
        .unwrap();
    let result = manager
        .transition(&request(
            "tr-recovery-running-blocked",
            "T-completion",
            2,
            TaskState::Recovering,
            TaskState::Running,
        ))
        .unwrap();
    assert_eq!(result.reason_code, "TASK_TRANSITION_GUARD_FAILED");
    assert_eq!(
        manager
            .get_step_execution("attempt-completion")
            .unwrap()
            .unwrap()
            .state,
        StepState::Ready
    );
}

fn failure_record(unknown_side_effects: bool) -> FailureRecord {
    FailureRecord {
        code: "PROVIDER_FAILED".to_owned(),
        summary: "provider failed".to_owned(),
        step_id: Some("node-1".to_owned()),
        provider_id: Some("provider:test".to_owned()),
        execution_binding_id: Some("binding-1".to_owned()),
        retryable: false,
        safe_to_replan: false,
        unknown_side_effects,
        rollback_available: false,
        provenance_event_ids: vec!["event:provider-failed".to_owned()],
    }
}

#[test]
fn task_and_step_creation_reject_schema_invalid_shapes_and_binding_mismatches() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    let mut invalid_task = create("T-invalid-create");
    invalid_task.normalized_intent = Some(serde_json::json!("scalar"));
    invalid_task.active_step_ids = vec!["node-1".to_owned(), "node-1".to_owned()];
    assert!(manager.create_task(&invalid_task).is_err());

    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
    let mismatched = CreateStepExecution {
        attempt_id: "attempt-other".to_owned(),
        task_id: "T-completion".to_owned(),
        semantic_program_hash: HASH.to_owned(),
        registry_snapshot_id: Some("snapshot-completion".to_owned()),
        node_id: "node-completion".to_owned(),
        binding_id: Some("binding-completion".to_owned()),
        provider_id: Some("provider:test".to_owned()),
        provider_version: Some("0.1.0".to_owned()),
        attempt_number: 1,
        state: StepState::Ready,
        operation_id: None,
        idempotency_key: None,
        outcome_certainty: Some(OutcomeCertainty::NotStarted),
        input_artifacts: vec!["duplicate".to_owned(), "duplicate".to_owned()],
        output_artifacts: Vec::new(),
        failure: None,
        started_at: None,
        finished_at: None,
    };
    assert!(manager.create_step_execution(&mismatched).is_err());
    let mut bounded_but_mismatched = mismatched;
    bounded_but_mismatched.input_artifacts = Vec::new();
    assert!(
        manager
            .create_step_execution(&bounded_but_mismatched)
            .is_err()
    );
    let mut duplicate_tuple = bounded_but_mismatched;
    duplicate_tuple.attempt_id = "attempt-duplicate-api".to_owned();
    duplicate_tuple.binding_id = None;
    duplicate_tuple.provider_id = None;
    duplicate_tuple.provider_version = None;
    assert!(manager.create_step_execution(&duplicate_tuple).is_err());
    assert!(manager.connection.execute(
        "INSERT INTO step_executions (attempt_id, task_id, semantic_program_hash, registry_snapshot_id, node_id, attempt_number, revision, state, outcome_certainty, input_artifacts_json, output_artifacts_json, created_at, updated_at) VALUES ('attempt-duplicate-db', 'T-completion', ?1, 'snapshot-completion', 'node-completion', 1, 1, 'READY', 'NOT_STARTED', '[]', '[]', '2026-09-19T00:00:00Z', '2026-09-19T00:00:00Z')",
        [HASH],
    ).is_err());
}

#[test]
fn task_record_returns_active_program_envelope_and_only_live_current_bindings() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
    manager
        .connection
        .execute(
            "UPDATE step_executions SET state = 'READY' WHERE attempt_id = 'attempt-completion'",
            [],
        )
        .unwrap();
    let task = manager.get_task("T-completion").unwrap().unwrap();
    let serialized = serde_json::to_value(&task).unwrap();
    assert!(serialized.get("constraints").is_none());
    assert!(serialized.get("recovery").is_none());
    let active_program = task.active_program.unwrap();
    assert_eq!(active_program["program_id"], "program-completion");
    assert_eq!(active_program["semantic_hash"], HASH);
    assert_eq!(
        active_program["registry_snapshot_id"],
        "snapshot-completion"
    );
    assert_eq!(
        active_program["validation_result_id"],
        "validation-completion"
    );
    assert!(active_program.get("nodes").is_none());
    assert_eq!(
        task.active_execution_binding_ids,
        vec!["binding-completion"]
    );
    manager
        .connection
        .execute(
            "UPDATE step_executions SET state = 'SUCCEEDED' WHERE attempt_id = 'attempt-completion'",
            [],
        )
        .unwrap();
    assert!(
        manager
            .get_task("T-completion")
            .unwrap()
            .unwrap()
            .active_execution_binding_ids
            .is_empty()
    );
}

#[test]
fn completion_rejects_unknown_attempt_wrong_allocation_identity_and_verification_identity() {
    let mut unknown = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut unknown, HASH, &["artifact-output"], "COMMITTED");
    unknown.connection.execute(
        "INSERT INTO step_executions (attempt_id, task_id, semantic_program_hash, node_id, attempt_number, revision, state, outcome_certainty, input_artifacts_json, output_artifacts_json, created_at, updated_at) VALUES ('attempt-unknown', 'T-completion', ?1, 'node-other', 1, 1, 'UNKNOWN', 'OUTCOME_UNKNOWN', '[]', '[]', '2026-09-19T00:00:00Z', '2026-09-19T00:00:00Z')",
        [HASH],
    ).unwrap();
    assert_eq!(
        unknown
            .transition(&completion_request("tr-unknown-attempt"))
            .unwrap()
            .reason_code,
        "TASK_UNKNOWN_EXTERNAL_OUTCOME"
    );

    let mut wrong_allocation =
        TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(
        &mut wrong_allocation,
        HASH,
        &["artifact-output"],
        "COMMITTED",
    );
    wrong_allocation
        .connection
        .execute(
            "UPDATE artifact_output_allocations SET node_id = 'node-other' WHERE allocation_id = 'allocation-completion'",
            [],
        )
        .unwrap();
    assert_eq!(
        wrong_allocation
            .transition(&completion_request("tr-wrong-allocation"))
            .unwrap()
            .reason_code,
        "TASK_UNKNOWN_EXTERNAL_OUTCOME"
    );

    let mut stale_identity = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture_with_identity(
        &mut stale_identity,
        HASH,
        "snapshot-stale",
        "validation-stale",
        &["artifact-output"],
        "COMMITTED",
    );
    assert_eq!(
        stale_identity
            .transition(&completion_request("tr-stale-identity"))
            .unwrap()
            .reason_code,
        "TASK_COMPLETION_GATE_FAILED"
    );
}

#[test]
fn completion_requires_completed_certainty_no_proposed_blocker_and_coherent_plan() {
    let mut certainty = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut certainty, HASH, &["artifact-output"], "COMMITTED");
    certainty
        .connection
        .execute(
            "UPDATE step_executions SET outcome_certainty = 'FAILED_PARTIAL_EFFECT' WHERE attempt_id = 'attempt-completion'",
            [],
        )
        .unwrap();
    assert_eq!(
        certainty
            .transition(&completion_request("tr-bad-certainty"))
            .unwrap()
            .reason_code,
        "TASK_UNKNOWN_EXTERNAL_OUTCOME"
    );

    let mut blocker = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut blocker, HASH, &["artifact-output"], "COMMITTED");
    let mut completion_with_blocker = completion_request("tr-proposed-blocker");
    completion_with_blocker.mutation.waiting_on = Some(vec![WaitingOn {
        kind: WaitingKind::Input,
        id: "input:missing".to_owned(),
        message: None,
    }]);
    assert_eq!(
        blocker
            .transition(&completion_with_blocker)
            .unwrap()
            .reason_code,
        "TASK_COMPLETION_GATE_FAILED"
    );

    let mut plan = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut plan, HASH, &["artifact-output"], "COMMITTED");
    plan.connection.execute_batch(
        "INSERT INTO plan_revisions (task_id, plan_revision, plan_id, plan_json, created_at) VALUES ('T-completion', 2, 'plan-2', '{}', '2026-09-19T00:00:00Z');",
    ).unwrap();
    let mut incoherent = completion_request("tr-plan-mismatch");
    incoherent.mutation.active_plan = Some(ActivePlan {
        plan_id: "plan-2".to_owned(),
        revision: 2,
    });
    assert_eq!(
        plan.transition(&incoherent).unwrap().reason_code,
        "TASK_PROGRAM_NOT_RUNNABLE"
    );
}

#[test]
fn cancellation_and_failure_preserve_live_or_unknown_effects() {
    let mut cancellation = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut cancellation, HASH, &["artifact-output"], "COMMITTED");
    cancellation.connection.execute(
        "INSERT INTO operations (operation_id, task_id, semantic_program_hash, node_id, effect_class, state, outcome_certainty, prepared_at) VALUES ('operation-live', 'T-completion', ?1, 'node-completion', 'NETWORK', 'STARTED', 'STARTED_NO_EFFECT', '2026-09-19T00:00:00Z')",
        [HASH],
    ).unwrap();
    assert_eq!(
        cancellation
            .transition(&request(
                "tr-cancel-live",
                "T-completion",
                2,
                TaskState::Verifying,
                TaskState::Cancelled,
            ))
            .unwrap()
            .reason_code,
        "TASK_TRANSITION_GUARD_FAILED"
    );

    let mut failure = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    failure.create_task(&create("T-unknown-failure")).unwrap();
    failure.connection.execute(
        "INSERT INTO operations (operation_id, task_id, semantic_program_hash, node_id, effect_class, state, outcome_certainty, prepared_at) VALUES ('operation-unknown-failure', 'T-unknown-failure', ?1, 'node-1', 'NETWORK', 'UNKNOWN', 'OUTCOME_UNKNOWN', '2026-09-19T00:00:00Z')",
        [HASH],
    ).unwrap();
    let mut denied = request(
        "tr-unknown-failed",
        "T-unknown-failure",
        1,
        TaskState::Created,
        TaskState::Failed,
    );
    denied.mutation.failure = Some(failure_record(false));
    assert_eq!(
        failure.transition(&denied).unwrap().reason_code,
        "TASK_UNKNOWN_EXTERNAL_OUTCOME"
    );
    let mut override_recorded = denied;
    override_recorded.transition_id = "tr-unknown-failed-override".to_owned();
    override_recorded.mutation.failure = Some(failure_record(true));
    assert_eq!(
        failure.transition(&override_recorded).unwrap().reason_code,
        "TASK_TRANSITION_GUARD_FAILED"
    );

    let mut live_attempt = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    live_attempt.create_task(&create("T-live-failure")).unwrap();
    live_attempt.connection.execute(
        "INSERT INTO step_executions (attempt_id, task_id, semantic_program_hash, node_id, attempt_number, revision, state, outcome_certainty, input_artifacts_json, output_artifacts_json, created_at, updated_at) VALUES ('attempt-live-failure', 'T-live-failure', ?1, 'node-1', 1, 1, 'READY', 'NOT_STARTED', '[]', '[]', '2026-09-19T00:00:00Z', '2026-09-19T00:00:00Z')",
        [HASH],
    ).unwrap();
    assert!(
        live_attempt
            .transition(&request(
                "tr-live-failed",
                "T-live-failure",
                1,
                TaskState::Created,
                TaskState::Failed,
            ))
            .unwrap()
            .applied
    );
}

#[test]
fn every_cancellation_source_requires_durable_effect_containment() {
    for (name, state) in [
        ("paused", TaskState::Paused),
        ("runnable", TaskState::Runnable),
        ("waiting-input", TaskState::WaitingForInput),
    ] {
        let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
        manager.create_task(&create("T-cancel-source")).unwrap();
        manager
            .connection
            .execute(
                "UPDATE tasks SET revision = 2, state = ?1 WHERE task_id = 'T-cancel-source'",
                [state.as_str()],
            )
            .unwrap();
        manager.connection.execute(
            "INSERT INTO operations (operation_id, task_id, semantic_program_hash, node_id, effect_class, state, outcome_certainty, prepared_at) VALUES ('operation-live', 'T-cancel-source', ?1, 'node-1', 'NETWORK', 'STARTED', 'STARTED_NO_EFFECT', '2026-09-19T00:00:00Z')",
            [HASH],
        ).unwrap();
        let result = manager
            .transition(&request(
                &format!("tr-cancel-{name}"),
                "T-cancel-source",
                2,
                state,
                TaskState::Cancelled,
            ))
            .unwrap();
        assert_eq!(result.reason_code, "TASK_TRANSITION_GUARD_FAILED", "{name}");
    }
}

#[test]
fn terminal_step_state_with_unknown_certainty_still_blocks_indirect_cancellation() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    manager
        .create_task(&create("T-cancel-unknown-step"))
        .unwrap();
    manager
        .connection
        .execute_batch(
            "UPDATE tasks SET revision = 2, state = 'PAUSED'
             WHERE task_id = 'T-cancel-unknown-step';
             INSERT INTO step_executions (
                 attempt_id, task_id, semantic_program_hash, node_id,
                 attempt_number, revision, state, outcome_certainty,
                 input_artifacts_json, output_artifacts_json,
                 created_at, updated_at
             ) VALUES (
                 'attempt-uncertain-terminal', 'T-cancel-unknown-step',
                 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50',
                 'node-1', 1, 2, 'SUCCEEDED', 'OUTCOME_UNKNOWN', '[]', '[]',
                 '2026-09-19T00:00:00Z', '2026-09-19T00:00:00Z'
             );",
        )
        .unwrap();
    let result = manager
        .transition(&request(
            "tr-cancel-unknown-step",
            "T-cancel-unknown-step",
            2,
            TaskState::Paused,
            TaskState::Cancelled,
        ))
        .unwrap();
    assert_eq!(result.reason_code, "TASK_TRANSITION_GUARD_FAILED");
}

#[test]
fn running_cannot_relabel_live_authority_as_runnable_or_waiting() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
    manager
        .connection
        .execute_batch(
            "UPDATE tasks SET state='RUNNING' WHERE task_id='T-completion';
         UPDATE step_executions SET state='READY',outcome_certainty='NOT_STARTED',finished_at=NULL
          WHERE attempt_id='attempt-completion';
         PRAGMA foreign_keys=OFF;
         INSERT INTO authority_grants(
             grant_id,task_id,semantic_program_hash,node_id,capability,principal_kind,
             principal_id,execution_binding_id,attempt_id,policy_decision_id,
             policy_snapshot_id,grants_json,scope,state,issued_at,expires_at
         ) VALUES (
             'grant-live-relabel','T-completion',
             'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50',
             'node-completion','test.complete@1','provider','provider:test',
             'binding-completion','attempt-completion','decision:fixture','policy:fixture',
             '[]','TASK','ACTIVE','2026-09-19T00:00:00Z','2026-09-20T00:00:00Z'
         );
         PRAGMA foreign_keys=ON;",
        )
        .unwrap();
    let runnable = manager
        .transition(&request(
            "tr-running-back-to-runnable-live",
            "T-completion",
            2,
            TaskState::Running,
            TaskState::Runnable,
        ))
        .unwrap();
    assert!(!runnable.applied);
    assert_eq!(runnable.reason_code, "TASK_TRANSITION_GUARD_FAILED");

    let mut waiting = request(
        "tr-running-waiting-live",
        "T-completion",
        2,
        TaskState::Running,
        TaskState::WaitingForInput,
    );
    waiting.mutation.waiting_on = Some(vec![WaitingOn {
        kind: WaitingKind::Input,
        id: "input:required".to_owned(),
        message: None,
    }]);
    let waiting = manager.transition(&waiting).unwrap();
    assert!(!waiting.applied);
    assert_eq!(waiting.reason_code, "TASK_TRANSITION_GUARD_FAILED");
    let task = manager.get_task("T-completion").unwrap().unwrap();
    assert_eq!((task.state, task.revision), (TaskState::Running, 2));
}

#[test]
fn failure_identity_changes_are_not_idempotent_and_are_committed_to_provenance() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    manager.create_task(&create("T-failure-identity")).unwrap();
    let mut first = request(
        "tr-failure-identity",
        "T-failure-identity",
        1,
        TaskState::Created,
        TaskState::Failed,
    );
    first.mutation.failure = Some(failure_record(false));
    assert!(manager.transition(&first).unwrap().applied);
    let event_json: String = manager
        .connection
        .query_row(
            "SELECT event_json FROM provenance_events WHERE task_id = 'T-failure-identity' ORDER BY sequence DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let event: Value = serde_json::from_str(&event_json).unwrap();
    assert_eq!(
        event.pointer("/committed_mutation/failure/step_id"),
        Some(&serde_json::json!("node-1"))
    );
    let mut reused = first;
    reused.mutation.failure.as_mut().unwrap().step_id = Some("node-2".to_owned());
    assert_eq!(
        manager.transition(&reused).unwrap().reason_code,
        "TASK_TRANSITION_ID_REUSE_CONFLICT"
    );
}

#[test]
fn expired_or_revoked_exact_grants_block_point_of_admission() {
    for (name, state, expires_at) in [
        ("revoked", "REVOKED", "2026-09-20T00:00:00Z"),
        ("expired", "ACTIVE", "2026-09-18T00:00:00Z"),
        (
            "positive-offset-expired",
            "ACTIVE",
            "2026-09-19T01:00:00+02:00",
        ),
    ] {
        let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
        seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
        manager.connection.execute_batch(
            "UPDATE semantic_program_revisions SET program_json = '{\"nodes\":[{\"id\":\"node-completion\",\"operation\":{\"kind\":\"invoke\",\"capability\":\"test.complete@1\"},\"outputs\":{\"report\":\"artifact.report@1\"},\"authority_requests\":[{\"action\":\"test.execute\",\"resource\":\"resource:one\"}]}]}' WHERE task_id = 'T-completion' AND program_revision = 1;
             UPDATE tasks SET state = 'RECOVERING', waiting_on_json = '[]' WHERE task_id = 'T-completion';
             UPDATE step_executions SET state = 'READY' WHERE attempt_id = 'attempt-completion';
             DROP TRIGGER execution_bindings_no_update;
             UPDATE execution_bindings SET grant_refs_json = '[\"grant-admission\"]' WHERE binding_id = 'binding-completion';
             INSERT INTO policy_snapshots (snapshot_id, scope_kind, scope_id, policy_language, policy_set_hash, engine_id, engine_version, snapshot_json, created_at) VALUES ('policy-snapshot', 'task', 'T-completion', 'fixture', 'sha256:policy', 'engine:test', '0.1', '{}', '2026-09-19T00:00:00Z');
             INSERT INTO authority_requests (request_id, task_id, semantic_program_hash, registry_snapshot_id, node_id, capability, principal_kind, principal_id, execution_binding_id, attempt_id, action, resolved_resource_kind, resolved_resource_id, semantic_selector, request_json, requested_at) VALUES ('authority-admission', 'T-completion', 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50', 'snapshot-completion', 'node-completion', 'test.complete@1', 'provider', 'provider:test', 'binding-completion', 'attempt-completion', 'test.execute', 'artifact', 'artifact:one', 'resource:one', '{}', '2026-09-19T00:00:00Z');
             INSERT INTO policy_decisions (decision_id, authority_request_id, task_id, semantic_program_hash, node_id, principal_kind, principal_id, action, resolved_resource_kind, resolved_resource_id, decision, policy_snapshot_id, reason_codes_json, decision_json, decided_at) VALUES ('decision-admission', 'authority-admission', 'T-completion', 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50', 'node-completion', 'provider', 'provider:test', 'test.execute', 'artifact', 'artifact:one', 'ALLOW', 'policy-snapshot', '[]', '{}', '2026-09-19T00:00:00Z');",
        ).unwrap();
        manager.connection.execute(
            "INSERT INTO authority_grants (grant_id, task_id, semantic_program_hash, node_id, capability, principal_kind, principal_id, execution_binding_id, attempt_id, policy_decision_id, policy_snapshot_id, grants_json, scope, max_uses, uses_consumed, state, issued_at, expires_at) VALUES ('grant-admission', 'T-completion', ?1, 'node-completion', 'test.complete@1', 'provider', 'provider:test', 'binding-completion', 'attempt-completion', 'decision-admission', 'policy-snapshot', '[{\"action\":\"test.execute\",\"resource_kind\":\"artifact\",\"resource_id\":\"artifact:one\",\"semantic_selector\":\"resource:one\"}]', 'ONE_SHOT', 1, 0, ?2, '2026-09-19T00:00:00Z', ?3)",
            rusqlite::params![HASH, state, expires_at],
        ).unwrap();
        assert_eq!(
            manager
                .transition(&request(
                    &format!("tr-grant-{name}"),
                    "T-completion",
                    2,
                    TaskState::Recovering,
                    TaskState::Running,
                ))
                .unwrap()
                .reason_code,
            "TASK_TRANSITION_GUARD_FAILED",
            "{name}"
        );
    }
}

#[test]
fn migration_quarantines_pending_receipts_and_rejects_checksum_mismatch() {
    let directory = tempdir().unwrap();
    let wrong_v1 = directory.path().join("wrong-v1.sqlite3");
    let connection = Connection::open(&wrong_v1).unwrap();
    connection.execute_batch(
        "CREATE TABLE schema_migrations (migration_id TEXT PRIMARY KEY, checksum TEXT NOT NULL, applied_at TEXT NOT NULL);
         CREATE TABLE operator_marker (value TEXT NOT NULL);
         INSERT INTO operator_marker VALUES ('untouched');
         INSERT INTO schema_migrations VALUES ('0001_v0_1_trusted_control_plane', 'wrong', '2026-09-19T00:00:00Z');",
    ).unwrap();
    drop(connection);
    assert!(TaskManager::open_with_clock(&wrong_v1, Box::new(FixedClock)).is_err());
    let connection = Connection::open(&wrong_v1).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT value FROM operator_marker", [], |row| row
                .get::<_, String>(0))
            .unwrap(),
        "untouched"
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'tasks'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    drop(connection);

    let empty_stamp = directory.path().join("empty-stamp.sqlite3");
    Connection::open(&empty_stamp).unwrap().execute_batch(
        "CREATE TABLE schema_migrations (migration_id TEXT PRIMARY KEY, checksum TEXT NOT NULL, applied_at TEXT NOT NULL);",
    ).unwrap();
    assert!(TaskManager::open_with_clock(&empty_stamp, Box::new(FixedClock)).is_err());
    assert_eq!(
        Connection::open(&empty_stamp)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'tasks'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );

    let path = directory.path().join("checksum.sqlite3");
    {
        let _manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
    }
    Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE schema_migrations SET checksum = 'wrong' WHERE migration_id = '0002_task_manager_contract_reconciliation'",
            [],
        )
        .unwrap();
    assert!(TaskManager::open_with_clock(&path, Box::new(FixedClock)).is_err());

    let legacy = directory.path().join("pending.sqlite3");
    let connection = Connection::open(&legacy).unwrap();
    connection.execute_batch(
        "CREATE TABLE schema_migrations (migration_id TEXT PRIMARY KEY, checksum TEXT NOT NULL, applied_at TEXT NOT NULL);
         CREATE TABLE tasks (task_id TEXT PRIMARY KEY, revision INTEGER NOT NULL, state TEXT NOT NULL, state_reason_json TEXT, principal_kind TEXT NOT NULL, principal_id TEXT NOT NULL, workspace_id TEXT, original_intent TEXT NOT NULL, normalized_intent_json TEXT, active_program_revision INTEGER, constraints_json TEXT, failure_json TEXT, recovery_json TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, completed_at TEXT);
         CREATE TABLE task_transitions (transition_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, expected_revision INTEGER NOT NULL, expected_state TEXT NOT NULL, to_state TEXT NOT NULL, result_revision INTEGER, result_state TEXT, outcome TEXT NOT NULL, reason_code TEXT NOT NULL, request_json TEXT NOT NULL, result_json TEXT, provenance_event_id TEXT, requested_at TEXT NOT NULL, committed_at TEXT, FOREIGN KEY (task_id) REFERENCES tasks(task_id));
         INSERT INTO tasks (task_id, revision, state, principal_kind, principal_id, original_intent, created_at, updated_at) VALUES ('T-pending', 1, 'CREATED', 'user', 'user:test', 'pending', '2026-09-19T00:00:00Z', '2026-09-19T00:00:00Z');
         INSERT INTO task_transitions (transition_id, task_id, expected_revision, expected_state, to_state, outcome, reason_code, request_json, requested_at) VALUES ('tr-pending', 'T-pending', 1, 'CREATED', 'PLANNING', 'PENDING', 'STATE_CHANGE_REQUESTED', '{}', '2026-09-19T00:00:00Z');",
    ).unwrap();
    drop(connection);
    assert!(TaskManager::open_with_clock(&legacy, Box::new(FixedClock)).is_err());
    let connection = Connection::open(&legacy).unwrap();
    let (outcome, result): (String, Option<String>) = connection
        .query_row(
            "SELECT outcome, result_json FROM task_transitions WHERE transition_id = 'tr-pending'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(outcome, "PENDING");
    assert!(result.is_none());
}

#[test]
fn migration_reconstructs_only_provenance_backed_committed_receipts() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("committed-null.sqlite3");
    let transition = request(
        "tr-reconstruct",
        "T-reconstruct",
        1,
        TaskState::Created,
        TaskState::Planning,
    );
    let expected = {
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        manager.create_task(&create("T-reconstruct")).unwrap();
        manager.transition(&transition).unwrap()
    };
    let noncanonical_request =
        serde_json::to_string_pretty(&serde_json::to_value(&transition).unwrap()).unwrap();
    assert_ne!(noncanonical_request, canonical_json(&transition).unwrap());
    Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE task_transitions SET request_json = ?1, result_json = NULL WHERE transition_id = 'tr-reconstruct'",
            [&noncanonical_request],
        )
        .unwrap();
    let mut reopened = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
    assert_eq!(
        reopened
            .connection
            .query_row(
                "SELECT request_json FROM task_transitions WHERE transition_id = 'tr-reconstruct'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        canonical_json(&transition).unwrap()
    );
    assert_eq!(reopened.transition(&transition).unwrap(), expected);

    drop(reopened);
    let connection = Connection::open(&path).unwrap();
    connection
        .execute(
            "UPDATE task_transitions SET result_json = NULL, provenance_event_id = 'event:missing' WHERE transition_id = 'tr-reconstruct'",
            [],
        )
        .unwrap();
    drop(connection);
    assert!(TaskManager::open_with_clock(&path, Box::new(FixedClock)).is_err());
    let (outcome, result): (String, Option<String>) = Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT outcome, result_json FROM task_transitions WHERE transition_id = 'tr-reconstruct'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(outcome, "COMMITTED");
    assert!(result.is_none());
}

#[test]
fn committed_null_terminal_receipt_rejects_an_orphan_transition_event() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("terminal-orphan.sqlite3");
    {
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        manager.create_task(&create("T-terminal-orphan")).unwrap();
        assert!(
            manager
                .transition(&request(
                    "tr-terminal-orphan",
                    "T-terminal-orphan",
                    1,
                    TaskState::Created,
                    TaskState::Failed,
                ))
                .unwrap()
                .applied
        );
    }
    let connection = Connection::open(&path).unwrap();
    connection.execute_batch(
        "DROP TRIGGER provenance_events_no_delete;
         DELETE FROM provenance_events WHERE task_id = 'T-terminal-orphan' AND sequence = 1;
         UPDATE task_transitions SET result_json = NULL WHERE transition_id = 'tr-terminal-orphan';",
    ).unwrap();
    drop(connection);

    assert!(TaskManager::open_with_clock(&path, Box::new(FixedClock)).is_err());
    let result = Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT result_json FROM task_transitions WHERE transition_id = 'tr-terminal-orphan'",
            [],
            |row| row.get::<_, Option<String>>(0),
        )
        .unwrap();
    assert!(result.is_none());
}

#[test]
fn duplicate_legacy_publications_block_index_migration_without_data_loss() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("duplicate-publications.sqlite3");
    let connection = Connection::open(&path).unwrap();
    connection.execute_batch(MIGRATION).unwrap();
    connection.execute_batch(
        "PRAGMA foreign_keys = OFF;
         DROP INDEX IF EXISTS ix_task_transitions_task;
         DROP TABLE task_transitions;
         CREATE TABLE task_transitions (
             transition_id TEXT PRIMARY KEY,
             task_id TEXT NOT NULL,
             expected_revision INTEGER NOT NULL,
             expected_state TEXT NOT NULL,
             to_state TEXT NOT NULL,
             result_revision INTEGER,
             result_state TEXT,
             outcome TEXT NOT NULL,
             reason_code TEXT NOT NULL,
             request_json TEXT NOT NULL,
             result_json TEXT,
             provenance_event_id TEXT,
             requested_at TEXT NOT NULL,
             committed_at TEXT,
             FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE
         );
         CREATE INDEX ix_task_transitions_task ON task_transitions(task_id, requested_at);
         INSERT INTO artifact_publications (publication_id, allocation_id, task_id, artifact_id, request_json, state, requested_at) VALUES ('publication-1', 'allocation-duplicate', 'T-missing', 'artifact-1', '{}', 'PENDING', '2026-09-19T00:00:00Z');
         INSERT INTO artifact_publications (publication_id, allocation_id, task_id, artifact_id, request_json, state, requested_at) VALUES ('publication-2', 'allocation-duplicate', 'T-missing', 'artifact-2', '{}', 'PENDING', '2026-09-19T00:00:00Z');",
    ).unwrap();
    drop(connection);

    assert!(TaskManager::open_with_clock(&path, Box::new(FixedClock)).is_err());
    let connection = Connection::open(&path).unwrap();
    assert_eq!(
        connection
            .prepare("PRAGMA foreign_key_list(task_transitions)")
            .unwrap()
            .query_map([], |_| Ok(()))
            .unwrap()
            .count(),
        1
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'task_transitions_legacy'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM artifact_publications WHERE allocation_id = 'allocation-duplicate'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        2
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'ux_artifact_publications_allocation'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE migration_id = '0002_task_manager_contract_reconciliation'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
}

#[test]
fn identity_coherence_bounds_and_bounded_event_ids_fail_closed() {
    assert_ne!(
        recovery_operations_ref("T-framing", 1, &["operation-ab".to_owned(), "c".to_owned()],)
            .unwrap(),
        recovery_operations_ref("T-framing", 1, &["operation-a".to_owned(), "bc".to_owned()],)
            .unwrap()
    );

    let mut snapshot = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut snapshot, HASH, &["artifact-output"], "COMMITTED");
    snapshot.connection.execute_batch(
        "INSERT INTO registry_snapshots (snapshot_id, manifest_json, created_at) VALUES ('snapshot-stale', '{}', '2026-09-19T00:00:00Z');
         UPDATE tasks SET state = 'RECOVERING' WHERE task_id = 'T-completion';
         UPDATE step_executions SET state = 'READY', registry_snapshot_id = 'snapshot-stale' WHERE attempt_id = 'attempt-completion';",
    ).unwrap();
    assert_eq!(
        snapshot
            .transition(&request(
                "tr-stale-snapshot-admission",
                "T-completion",
                2,
                TaskState::Recovering,
                TaskState::Running,
            ))
            .unwrap()
            .reason_code,
        "TASK_TRANSITION_GUARD_FAILED"
    );

    let mut coherence = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut coherence, HASH, &["artifact-output"], "COMMITTED");
    coherence.connection.execute_batch(
        "INSERT INTO plan_revisions (task_id, plan_revision, plan_id, plan_json, created_at) VALUES ('T-completion', 2, 'plan-2', '{}', '2026-09-19T00:00:00Z');
         UPDATE tasks SET state = 'PLANNING' WHERE task_id = 'T-completion';",
    ).unwrap();
    let mut change_plan = request(
        "tr-plan2-paused",
        "T-completion",
        2,
        TaskState::Planning,
        TaskState::Paused,
    );
    change_plan.mutation.active_plan = Some(ActivePlan {
        plan_id: "plan-2".to_owned(),
        revision: 2,
    });
    assert_eq!(
        coherence.transition(&change_plan).unwrap().reason_code,
        "TASK_PROGRAM_NOT_RUNNABLE"
    );

    let mut mutate_steps = request(
        "tr-proposed-runnable-steps",
        "T-completion",
        2,
        TaskState::Planning,
        TaskState::Runnable,
    );
    mutate_steps.mutation.active_step_ids = Some(vec!["node-completion".to_owned()]);
    assert_eq!(
        coherence.transition(&mutate_steps).unwrap().reason_code,
        "TASK_TRANSITION_GUARD_FAILED"
    );

    let mut overflow = request(
        "tr-plan-overflow",
        "T-completion",
        2,
        TaskState::Planning,
        TaskState::Paused,
    );
    overflow.mutation.active_plan = Some(ActivePlan {
        plan_id: "plan-overflow".to_owned(),
        revision: u64::MAX,
    });
    assert!(coherence.transition(&overflow).is_err());
}

#[test]
fn event_id_namespaces_are_bounded_and_disjoint_for_maximum_contract_ids() {
    let mut event_ids = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    event_ids.create_task(&create("T-long-transition")).unwrap();
    let long_id = "x".repeat(256);
    let transition = request(
        &long_id,
        "T-long-transition",
        1,
        TaskState::Created,
        TaskState::Planning,
    );
    let result = event_ids.transition(&transition).unwrap();
    let event_id = result.provenance_event_id.unwrap();
    assert!(event_id.len() <= 256);
    assert!(event_id.starts_with("event:transition:v1:sha256:"));

    let legacy_long_event_id = hashed_event_id(
        "event:transition:sha256:",
        b"AIOS-TASK-TRANSITION-EVENT-ID\0v0.1\0",
        &long_id,
    );
    let colliding_short_id = legacy_long_event_id
        .strip_prefix("event:transition:")
        .unwrap();
    assert_eq!(
        legacy_long_event_id,
        format!("event:transition:{colliding_short_id}")
    );
    assert_ne!(
        transition_event_id(&long_id),
        transition_event_id(colliding_short_id)
    );

    let maximum_task_id = "T".repeat(256);
    let task = event_ids.create_task(&create(&maximum_task_id)).unwrap();
    let task_schema: Value = serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../specs/task-record.schema.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        jsonschema::validator_for(&task_schema)
            .unwrap()
            .is_valid(&serde_json::to_value(&task).unwrap())
    );
    let creation_event_id = task
        .state_reason
        .as_ref()
        .and_then(|reason| reason.get("provenance_event_id"))
        .and_then(Value::as_str)
        .unwrap();
    assert!(creation_event_id.len() <= 256);
    assert!(creation_event_id.starts_with("event:task-created:v1:sha256:"));
    let stream_id: String = event_ids
        .connection
        .query_row(
            "SELECT stream_id FROM provenance_events WHERE task_id = ?1",
            [&maximum_task_id],
            |row| row.get(0),
        )
        .unwrap();
    assert!(stream_id.starts_with("task:"));
    assert!(stream_id.len() <= 256);
    assert!(event_ids.verify_provenance(&maximum_task_id).unwrap());
}

#[test]
fn runnable_readiness_uses_each_active_nodes_latest_attempt_once() {
    let mut stale = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut stale, HASH, &["artifact-output"], "COMMITTED");
    align_completion_fixture_state(&mut stale, TaskState::Planning);
    stale.connection.execute_batch(
        "UPDATE tasks SET state = 'PLANNING' WHERE task_id = 'T-completion';
         INSERT INTO step_executions (attempt_id, task_id, semantic_program_hash, registry_snapshot_id, node_id, attempt_number, revision, state, outcome_certainty, input_artifacts_json, output_artifacts_json, created_at, updated_at) VALUES ('attempt-ready-old', 'T-completion', 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50', 'snapshot-completion', 'node-completion', 2, 1, 'READY', 'NOT_STARTED', '[]', '[]', '2026-09-19T00:00:00Z', '2026-09-19T00:00:00Z');
         INSERT INTO step_executions (attempt_id, task_id, semantic_program_hash, registry_snapshot_id, node_id, attempt_number, revision, state, outcome_certainty, input_artifacts_json, output_artifacts_json, created_at, updated_at) VALUES ('attempt-failed-new', 'T-completion', 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50', 'snapshot-completion', 'node-completion', 3, 1, 'FAILED', 'FAILED_NO_EFFECT', '[]', '[]', '2026-09-19T00:00:00Z', '2026-09-19T00:00:00Z');",
    ).unwrap();
    assert_eq!(
        stale
            .transition(&request(
                "tr-runnable-stale-ready",
                "T-completion",
                2,
                TaskState::Planning,
                TaskState::Runnable,
            ))
            .unwrap()
            .reason_code,
        "TASK_PROGRAM_NOT_RUNNABLE"
    );

    let mut compensated = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut compensated, HASH, &["artifact-output"], "COMMITTED");
    align_completion_fixture_state(&mut compensated, TaskState::Planning);
    compensated.connection.execute_batch(
        "UPDATE tasks SET state = 'PLANNING', active_step_ids_json = '[\"node-completion\",\"node-missing\"]' WHERE task_id = 'T-completion';
         INSERT INTO step_executions (attempt_id, task_id, semantic_program_hash, registry_snapshot_id, node_id, attempt_number, revision, state, outcome_certainty, input_artifacts_json, output_artifacts_json, created_at, updated_at) VALUES ('attempt-ready-2', 'T-completion', 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50', 'snapshot-completion', 'node-completion', 2, 1, 'READY', 'NOT_STARTED', '[]', '[]', '2026-09-19T00:00:00Z', '2026-09-19T00:00:00Z');
         INSERT INTO step_executions (attempt_id, task_id, semantic_program_hash, registry_snapshot_id, node_id, attempt_number, revision, state, outcome_certainty, input_artifacts_json, output_artifacts_json, created_at, updated_at) VALUES ('attempt-ready-3', 'T-completion', 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50', 'snapshot-completion', 'node-completion', 3, 1, 'READY', 'NOT_STARTED', '[]', '[]', '2026-09-19T00:00:00Z', '2026-09-19T00:00:00Z');",
    ).unwrap();
    assert!(
        compensated
            .transition(&request(
                "tr-runnable-frontier",
                "T-completion",
                2,
                TaskState::Planning,
                TaskState::Runnable,
            ))
            .unwrap()
            .applied
    );
}

#[test]
fn running_and_admission_reject_duplicate_latest_exact_bound_attempts() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
    manager.connection.execute_batch(
        "DROP INDEX ux_step_executions_attempt_tuple;
         UPDATE tasks SET state = 'RECOVERING' WHERE task_id = 'T-completion';
         UPDATE step_executions SET state = 'READY', outcome_certainty = 'NOT_STARTED' WHERE attempt_id = 'attempt-completion';
         INSERT INTO execution_bindings (binding_id, attempt_id, task_id, semantic_program_hash, registry_snapshot_id, ir_version, node_id, capability, provider_id, provider_version, attempt, policy_decision_refs_json, grant_refs_json, execution_profile_ref, placement_json, binding_json, created_at) VALUES ('binding-duplicate-latest', 'attempt-duplicate-latest', 'T-completion', 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50', 'snapshot-completion', '0.1', 'node-completion', 'test.complete', 'provider:test', '0.1.0', 2, '[]', '[]', 'profile:test', '{}', '{}', '2026-09-19T00:00:00Z');
         INSERT INTO step_executions (attempt_id, task_id, semantic_program_hash, registry_snapshot_id, node_id, binding_id, provider_id, provider_version, attempt_number, revision, state, outcome_certainty, input_artifacts_json, output_artifacts_json, created_at, updated_at) VALUES ('attempt-duplicate-latest', 'T-completion', 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50', 'snapshot-completion', 'node-completion', 'binding-duplicate-latest', 'provider:test', '0.1.0', 1, 1, 'READY', 'NOT_STARTED', '[]', '[]', '2026-09-19T00:00:00Z', '2026-09-19T00:00:00Z');",
    ).unwrap();

    let transaction = manager
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    assert!(
        !admit_active_steps(
            &transaction,
            "T-completion",
            &["node-completion".to_owned()],
            "2026-09-19T00:00:00Z",
        )
        .unwrap()
    );
    transaction.rollback().unwrap();

    let result = manager
        .transition(&request(
            "tr-duplicate-latest-running",
            "T-completion",
            2,
            TaskState::Recovering,
            TaskState::Running,
        ))
        .unwrap();
    assert_eq!(result.reason_code, "TASK_TRANSITION_GUARD_FAILED");
    let ready_count = manager
        .connection
        .query_row(
            "SELECT COUNT(*) FROM step_executions WHERE task_id = 'T-completion' AND node_id = 'node-completion' AND state = 'READY'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    assert_eq!(ready_count, 2);
}

#[test]
fn completion_uses_program_ports_and_rejects_self_report_or_artifact_aliasing() {
    let mut wrong_port = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut wrong_port, HASH, &["artifact-output"], "COMMITTED");
    wrong_port.connection.execute_batch(
        "UPDATE step_executions SET output_artifacts_json = '[\"attacker-self-report\"]' WHERE attempt_id = 'attempt-completion';
         UPDATE artifact_output_allocations SET output_port = 'wrong-port' WHERE allocation_id = 'allocation-completion';",
    ).unwrap();
    assert_eq!(
        wrong_port
            .transition(&completion_request("tr-program-port"))
            .unwrap()
            .reason_code,
        "TASK_COMPLETION_GATE_FAILED"
    );

    let mut alias = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut alias, HASH, &["artifact-output"], "COMMITTED");
    alias
        .connection
        .execute_batch(&format!(
            "UPDATE semantic_program_revisions SET program_json = '{{\"nodes\":[{{\"id\":\"node-completion\",\"outputs\":{{\"report\":\"artifact.report@1\",\"receipt\":\"artifact.report@1\"}}}}]}}' WHERE task_id = 'T-completion' AND program_revision = 1;
             INSERT INTO artifact_output_allocations (allocation_id, task_id, semantic_program_hash, node_id, binding_id, attempt_id, output_port, sensitivity, retention, state, publication_id, published_artifact_id, created_at, expires_at) VALUES ('allocation-alias', 'T-completion', 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50', 'node-completion', 'binding-completion', 'attempt-completion', 'receipt', 'local', 'task', 'PUBLISHED', 'publication-alias', '{COMPLETION_ARTIFACT_ID}', '2026-09-19T00:00:00Z', '2026-09-20T00:00:00Z');
             INSERT INTO artifact_publications (publication_id, allocation_id, task_id, artifact_id, request_json, state, requested_at, committed_at) VALUES ('publication-alias', 'allocation-alias', 'T-completion', '{COMPLETION_ARTIFACT_ID}', '{{}}', 'COMMITTED', '2026-09-19T00:00:00Z', '2026-09-19T00:00:00Z');"
        ))
        .unwrap();
    assert_eq!(
        alias
            .transition(&completion_request("tr-output-alias"))
            .unwrap()
            .reason_code,
        "TASK_UNKNOWN_EXTERNAL_OUTCOME"
    );
}

#[test]
fn pause_failure_and_stale_approval_guards_use_durable_current_scope() {
    let mut pause = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut pause, HASH, &["artifact-output"], "COMMITTED");
    pause
        .connection
        .execute(
            "UPDATE tasks SET state = 'RUNNING' WHERE task_id = 'T-completion'",
            [],
        )
        .unwrap();
    pause.connection.execute(
        "INSERT INTO operations (operation_id, task_id, semantic_program_hash, node_id, effect_class, state, outcome_certainty, prepared_at) VALUES ('operation-pause-live', 'T-completion', ?1, 'node-completion', 'NETWORK', 'STARTED', 'STARTED_NO_EFFECT', '2026-09-19T00:00:00Z')",
        [HASH],
    ).unwrap();
    assert_eq!(
        pause
            .transition(&request(
                "tr-pause-live",
                "T-completion",
                2,
                TaskState::Running,
                TaskState::Paused,
            ))
            .unwrap()
            .reason_code,
        "TASK_TRANSITION_GUARD_FAILED"
    );
    for source in [TaskState::Verifying, TaskState::Recovering] {
        let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
        seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
        manager
            .connection
            .execute(
                "UPDATE tasks SET state = ?1 WHERE task_id = 'T-completion'",
                [source.as_str()],
            )
            .unwrap();
        manager.connection.execute(
            "INSERT INTO operations (operation_id, task_id, semantic_program_hash, node_id, effect_class, state, outcome_certainty, prepared_at) VALUES (?1, 'T-completion', ?2, 'node-completion', 'NETWORK', 'STARTED', 'STARTED_NO_EFFECT', '2026-09-19T00:00:00Z')",
            rusqlite::params![format!("operation-pause-{}", source.as_str()), HASH],
        ).unwrap();
        assert_eq!(
            manager
                .transition(&request(
                    &format!("tr-pause-{}", source.as_str()),
                    "T-completion",
                    2,
                    source,
                    TaskState::Paused,
                ))
                .unwrap()
                .reason_code,
            "TASK_TRANSITION_GUARD_FAILED"
        );
    }

    let mut failed = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    failed.create_task(&create("T-failure-required")).unwrap();
    let mut missing = request(
        "tr-failure-missing",
        "T-failure-required",
        1,
        TaskState::Created,
        TaskState::Failed,
    );
    missing.mutation.failure = None;
    assert_eq!(
        failed.transition(&missing).unwrap().reason_code,
        "TASK_TRANSITION_GUARD_FAILED"
    );

    let mut stale = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut stale, HASH, &["artifact-output"], "COMMITTED");
    stale.connection.execute_batch(
        "UPDATE tasks SET waiting_on_json = '[{\"kind\":\"approval\",\"id\":\"approval-stale\",\"message\":null}]' WHERE task_id = 'T-completion';
         INSERT INTO registry_snapshots (snapshot_id, manifest_json, created_at) VALUES ('snapshot-old-approval', '{}', '2026-09-19T00:00:00Z');
         INSERT INTO authority_requests (request_id, task_id, semantic_program_hash, registry_snapshot_id, node_id, capability, principal_kind, principal_id, action, resolved_resource_kind, resolved_resource_id, request_json, requested_at) VALUES ('authority-stale-approval', 'T-completion', 'sha256:2222222222222222222222222222222222222222222222222222222222222222', 'snapshot-old-approval', 'node-old', 'test.old', 'user', 'user:test', 'old.execute', 'resource', 'old', '{}', '2026-09-19T00:00:00Z');
         INSERT INTO approval_requests (approval_id, authority_request_id, task_id, semantic_program_hash, node_id, action, status, request_json, created_at) VALUES ('approval-stale', 'authority-stale-approval', 'T-completion', 'sha256:2222222222222222222222222222222222222222222222222222222222222222', 'node-old', 'old.execute', 'PENDING', '{}', '2026-09-19T00:00:00Z');",
    ).unwrap();
    stale.connection.execute_batch(
        "INSERT INTO authority_requests (request_id, task_id, semantic_program_hash, registry_snapshot_id, node_id, capability, principal_kind, principal_id, action, resolved_resource_kind, resolved_resource_id, request_json, requested_at) VALUES ('authority-inactive-node', 'T-completion', 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50', 'snapshot-completion', 'node-inactive', 'test.old@1', 'user', 'user:test', 'old.execute', 'resource', 'old', '{}', '2026-09-19T00:00:00Z');
         INSERT INTO approval_requests (approval_id, authority_request_id, task_id, semantic_program_hash, node_id, action, status, request_json, created_at) VALUES ('approval-inactive-node', 'authority-inactive-node', 'T-completion', 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50', 'node-inactive', 'old.execute', 'PENDING', '{}', '2026-09-19T00:00:00Z');",
    ).unwrap();
    assert!(
        stale
            .transition(&completion_request("tr-ignore-stale-approval"))
            .unwrap()
            .applied
    );
}

#[test]
fn actual_admission_requires_complete_program_derived_authority_and_keeps_ready_on_rejection() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
    manager.connection.execute_batch(
        "UPDATE semantic_program_revisions SET program_json = '{\"nodes\":[{\"id\":\"node-completion\",\"operation\":{\"kind\":\"invoke\",\"capability\":\"test.complete@1\"},\"outputs\":{\"report\":\"artifact.report@1\"},\"authority_requests\":[{\"action\":\"action.one\",\"resource\":\"resource:one\"},{\"action\":\"action.two\",\"resource\":\"resource:two\"}]}]}' WHERE task_id = 'T-completion' AND program_revision = 1;
         UPDATE tasks SET state = 'RECOVERING' WHERE task_id = 'T-completion';
         UPDATE step_executions SET state = 'READY', outcome_certainty = 'NOT_STARTED' WHERE attempt_id = 'attempt-completion';",
    ).unwrap();
    let empty = manager
        .transition(&request(
            "tr-authority-empty",
            "T-completion",
            2,
            TaskState::Recovering,
            TaskState::Running,
        ))
        .unwrap();
    assert_eq!(empty.reason_code, "TASK_TRANSITION_GUARD_FAILED");
    assert_eq!(
        manager
            .get_step_execution("attempt-completion")
            .unwrap()
            .unwrap()
            .state,
        StepState::Ready
    );

    manager.connection.execute_batch(
        "DROP TRIGGER execution_bindings_no_update;
         UPDATE execution_bindings SET grant_refs_json = '[\"grant-partial\"]' WHERE binding_id = 'binding-completion';
         INSERT INTO policy_snapshots (snapshot_id, scope_kind, scope_id, policy_language, policy_set_hash, engine_id, engine_version, snapshot_json, created_at) VALUES ('policy-partial', 'task', 'T-completion', 'fixture', 'sha256:policy', 'engine:test', '0.1', '{}', '2026-09-19T00:00:00Z');
         INSERT INTO authority_requests (request_id, task_id, semantic_program_hash, registry_snapshot_id, node_id, capability, principal_kind, principal_id, execution_binding_id, attempt_id, action, resolved_resource_kind, resolved_resource_id, semantic_selector, request_json, requested_at) VALUES ('authority-partial', 'T-completion', 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50', 'snapshot-completion', 'node-completion', 'test.complete@1', 'provider', 'provider:test', 'binding-completion', 'attempt-completion', 'action.one', 'artifact', 'artifact:one', 'resource:one', '{}', '2026-09-19T00:00:00Z');
         INSERT INTO policy_decisions (decision_id, authority_request_id, task_id, semantic_program_hash, node_id, principal_kind, principal_id, action, resolved_resource_kind, resolved_resource_id, decision, policy_snapshot_id, reason_codes_json, decision_json, decided_at) VALUES ('decision-partial', 'authority-partial', 'T-completion', 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50', 'node-completion', 'provider', 'provider:test', 'action.one', 'artifact', 'artifact:one', 'ALLOW', 'policy-partial', '[]', '{}', '2026-09-19T00:00:00Z');
         INSERT INTO authority_grants (grant_id, task_id, semantic_program_hash, node_id, capability, principal_kind, principal_id, execution_binding_id, attempt_id, policy_decision_id, policy_snapshot_id, grants_json, scope, max_uses, uses_consumed, state, issued_at, expires_at) VALUES ('grant-partial', 'T-completion', 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50', 'node-completion', 'test.complete@1', 'provider', 'provider:test', 'binding-completion', 'attempt-completion', 'decision-partial', 'policy-partial', '[{\"action\":\"action.one\",\"resource_kind\":\"artifact\",\"resource_id\":\"artifact:one\",\"semantic_selector\":\"resource:one\"}]', 'TASK', 10, 0, 'ACTIVE', '2026-09-19T00:00:00Z', '2026-09-20T00:00:00Z');",
    ).unwrap();
    let partial = manager
        .transition(&request(
            "tr-authority-partial",
            "T-completion",
            2,
            TaskState::Recovering,
            TaskState::Running,
        ))
        .unwrap();
    assert_eq!(partial.reason_code, "TASK_TRANSITION_GUARD_FAILED");
    assert_eq!(
        manager
            .get_step_execution("attempt-completion")
            .unwrap()
            .unwrap()
            .state,
        StepState::Ready
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "keeps the exact authority request, decision, and nondelegable grant matrix together"
)]
fn binding_grants_exactly_cover_current_authority_requests() {
    fn check<'a>(grant_refs_json: &'a str, binding_id: &'a str) -> BindingGrantCheck<'a> {
        BindingGrantCheck {
            task_id: "T-completion",
            semantic_hash: HASH,
            node_id: "node-completion",
            binding_id,
            attempt_id: "attempt-completion",
            grant_refs_json,
            checked_at: "2026-09-19T00:00:00Z",
        }
    }

    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
    manager.connection.execute_batch(
        "UPDATE semantic_program_revisions SET program_json = '{\"nodes\":[{\"id\":\"node-completion\",\"operation\":{\"kind\":\"invoke\",\"capability\":\"test.complete@1\"},\"outputs\":{\"report\":\"artifact.report@1\"},\"authority_requests\":[{\"action\":\"action.one\",\"resource\":\"resource:one\"},{\"action\":\"action.two\",\"resource\":\"resource:two\"}]}]}' WHERE task_id = 'T-completion' AND program_revision = 1;
         INSERT INTO policy_snapshots (snapshot_id, scope_kind, scope_id, policy_language, policy_set_hash, engine_id, engine_version, snapshot_json, created_at) VALUES ('policy-coverage', 'task', 'T-completion', 'fixture', 'sha256:policy', 'engine:test', '0.1', '{}', '2026-09-19T00:00:00Z');
         INSERT INTO authority_requests (request_id, task_id, semantic_program_hash, registry_snapshot_id, node_id, capability, principal_kind, principal_id, execution_binding_id, attempt_id, action, resolved_resource_kind, resolved_resource_id, semantic_selector, request_json, requested_at) VALUES ('authority-cover-1', 'T-completion', 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50', 'snapshot-completion', 'node-completion', 'test.complete@1', 'provider', 'provider:test', 'binding-completion', 'attempt-completion', 'action.one', 'artifact', 'artifact:one', 'resource:one', '{}', '2026-09-19T00:00:00Z');
         INSERT INTO authority_requests (request_id, task_id, semantic_program_hash, registry_snapshot_id, node_id, capability, principal_kind, principal_id, execution_binding_id, attempt_id, action, resolved_resource_kind, resolved_resource_id, semantic_selector, request_json, requested_at) VALUES ('authority-cover-2', 'T-completion', 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50', 'snapshot-completion', 'node-completion', 'test.complete@1', 'provider', 'provider:test', 'binding-completion', 'attempt-completion', 'action.two', 'artifact', 'artifact:two', 'resource:two', '{}', '2026-09-19T00:00:00Z');
         INSERT INTO policy_decisions (decision_id, authority_request_id, task_id, semantic_program_hash, node_id, principal_kind, principal_id, action, resolved_resource_kind, resolved_resource_id, decision, policy_snapshot_id, reason_codes_json, decision_json, decided_at) VALUES ('decision-cover-1', 'authority-cover-1', 'T-completion', 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50', 'node-completion', 'provider', 'provider:test', 'action.one', 'artifact', 'artifact:one', 'ALLOW', 'policy-coverage', '[]', '{}', '2026-09-19T00:00:00Z');
         INSERT INTO policy_decisions (decision_id, authority_request_id, task_id, semantic_program_hash, node_id, principal_kind, principal_id, action, resolved_resource_kind, resolved_resource_id, decision, policy_snapshot_id, reason_codes_json, decision_json, decided_at) VALUES ('decision-cover-2', 'authority-cover-2', 'T-completion', 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50', 'node-completion', 'provider', 'provider:test', 'action.two', 'artifact', 'artifact:two', 'ALLOW', 'policy-coverage', '[]', '{}', '2026-09-19T00:00:00Z');
         INSERT INTO authority_grants (grant_id, task_id, semantic_program_hash, node_id, capability, principal_kind, principal_id, execution_binding_id, attempt_id, policy_decision_id, policy_snapshot_id, grants_json, scope, max_uses, uses_consumed, state, issued_at, expires_at) VALUES ('grant-cover-1', 'T-completion', 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50', 'node-completion', 'test.complete@1', 'provider', 'provider:test', 'binding-completion', 'attempt-completion', 'decision-cover-1', 'policy-coverage', '[{\"action\":\"action.one\",\"resource_kind\":\"artifact\",\"resource_id\":\"artifact:one\",\"semantic_selector\":\"resource:one\"}]', 'TASK', 10, 0, 'ACTIVE', '2026-09-19T00:00:00Z', '2026-09-20T00:00:00Z');
         INSERT INTO authority_grants (grant_id, task_id, semantic_program_hash, node_id, capability, principal_kind, principal_id, execution_binding_id, attempt_id, policy_decision_id, policy_snapshot_id, grants_json, scope, max_uses, uses_consumed, state, issued_at, expires_at) VALUES ('grant-cover-2', 'T-completion', 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50', 'node-completion', 'test.complete@1', 'provider', 'provider:test', 'binding-completion', 'attempt-completion', 'decision-cover-2', 'policy-coverage', '[{\"action\":\"action.two\",\"resource_kind\":\"artifact\",\"resource_id\":\"artifact:two\",\"semantic_selector\":\"resource:two\"}]', 'TASK', 10, 0, 'ACTIVE', '2026-09-19T00:00:00Z', '2026-09-20T00:00:00Z');",
    ).unwrap();
    set_completion_binding_refs(
        &manager,
        &["decision-cover-1", "decision-cover-2"],
        &["grant-cover-1", "grant-cover-2"],
    );
    manager.connection.execute(
        "UPDATE authority_grants SET token_id='fixture:manual-sql' WHERE grant_id='grant-cover-1'",
        [],
    ).unwrap();
    {
        let transaction = manager.connection.transaction().unwrap();
        assert!(
            !binding_grants_valid(
                &transaction,
                &check(
                    "[\"grant-cover-1\",\"grant-cover-2\"]",
                    "binding-completion"
                )
            )
            .unwrap()
        );
    }
    admit_fixture_grant(&manager.connection, "grant-cover-1").unwrap();
    admit_fixture_grant(&manager.connection, "grant-cover-2").unwrap();
    let transaction = manager.connection.transaction().unwrap();
    assert!(!binding_grants_valid(&transaction, &check("[]", "binding-completion")).unwrap());
    assert!(
        !binding_grants_valid(
            &transaction,
            &check("[\"grant-cover-1\"]", "binding-completion")
        )
        .unwrap()
    );
    assert!(
        binding_grants_valid(
            &transaction,
            &check(
                "[\"grant-cover-1\",\"grant-cover-2\"]",
                "binding-completion"
            )
        )
        .unwrap()
    );
    transaction
        .execute(
            "UPDATE authority_grants SET delegable=1 WHERE grant_id='grant-cover-2'",
            [],
        )
        .unwrap();
    assert!(
        !binding_grants_valid(
            &transaction,
            &check(
                "[\"grant-cover-1\",\"grant-cover-2\"]",
                "binding-completion"
            )
        )
        .unwrap()
    );
    transaction
        .execute(
            "UPDATE authority_grants SET delegable=0 WHERE grant_id='grant-cover-2'",
            [],
        )
        .unwrap();
    assert!(
        !binding_grants_valid(
            &transaction,
            &check("[\"grant-cover-1\",\"grant-cover-2\"]", "binding-wrong")
        )
        .unwrap()
    );
    assert!(
        !binding_grants_valid(
            &transaction,
            &check(
                "[\"grant-cover-1\",\"grant-cover-1\"]",
                "binding-completion"
            )
        )
        .unwrap()
    );
    transaction
        .execute(
            "UPDATE policy_decisions SET decision = 'DENY' WHERE decision_id = 'decision-cover-2'",
            [],
        )
        .unwrap();
    assert!(
        !binding_grants_valid(
            &transaction,
            &check(
                "[\"grant-cover-1\",\"grant-cover-2\"]",
                "binding-completion"
            )
        )
        .unwrap()
    );
    transaction
        .execute_batch(
            "UPDATE policy_decisions SET decision = 'ALLOW' WHERE decision_id = 'decision-cover-2'; UPDATE authority_grants SET grants_json = '[{\"action\":\"action.wrong\",\"resource_kind\":\"artifact\",\"resource_id\":\"artifact:two\",\"semantic_selector\":\"resource:two\"}]' WHERE grant_id = 'grant-cover-2'",
        )
        .unwrap();
    assert!(
        !binding_grants_valid(
            &transaction,
            &check(
                "[\"grant-cover-1\",\"grant-cover-2\"]",
                "binding-completion"
            )
        )
        .unwrap()
    );
}

#[test]
fn approval_backed_grants_revalidate_status_expiry_decision_and_identity() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
    manager.connection.execute_batch(
        r#"UPDATE semantic_program_revisions SET program_json='{"nodes":[{"id":"node-completion","operation":{"kind":"invoke","capability":"test.complete@1"},"outputs":{"report":"artifact.report@1"},"authority_requests":[{"action":"action.approved","resource":"resource:approved"}]}]}' WHERE task_id='T-completion';
         DROP TRIGGER execution_bindings_no_update;
         UPDATE execution_bindings SET grant_refs_json='["grant-approved"]' WHERE binding_id='binding-completion';
         INSERT INTO policy_snapshots(snapshot_id,scope_kind,scope_id,policy_language,policy_set_hash,engine_id,engine_version,snapshot_json,created_at) VALUES ('policy-approved','task','T-completion','fixture','sha256:policy','engine:test','0.1','{}','2026-09-19T00:00:00Z');
         INSERT INTO authority_requests(request_id,task_id,semantic_program_hash,registry_snapshot_id,node_id,capability,principal_kind,principal_id,execution_binding_id,attempt_id,action,resolved_resource_kind,resolved_resource_id,semantic_selector,request_json,requested_at) VALUES ('authority-approved','T-completion','sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50','snapshot-completion','node-completion','test.complete@1','provider','provider:test','binding-completion','attempt-completion','action.approved','artifact','artifact:approved','resource:approved','{}','2026-09-19T00:00:00Z');
         INSERT INTO approval_requests(approval_id,authority_request_id,task_id,semantic_program_hash,node_id,action,status,request_json,created_at,expires_at) VALUES ('approval-approved','authority-approved','T-completion','sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50','node-completion','action.approved','APPROVED','{}','2026-09-19T00:00:00Z','2026-09-20T00:00:00Z');
         INSERT INTO approval_requests(approval_id,authority_request_id,task_id,semantic_program_hash,node_id,action,status,request_json,created_at,expires_at) VALUES ('approval-other','authority-approved','T-completion','sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50','node-completion','action.approved','APPROVED','{}','2026-09-19T00:00:00Z','2026-09-20T00:00:00Z');
         INSERT INTO approval_decisions(decision_id,approval_id,task_id,decision,decided_by_kind,decided_by_id,scope,approved_until,decision_json,decided_at) VALUES ('approval-decision','approval-approved','T-completion','APPROVE','user','user:approver','ONE_SHOT','2026-09-20T00:00:00Z','{}','2026-09-19T00:00:00Z');
         INSERT INTO policy_decisions(decision_id,authority_request_id,task_id,semantic_program_hash,node_id,principal_kind,principal_id,action,resolved_resource_kind,resolved_resource_id,decision,policy_snapshot_id,approval_request_id,reason_codes_json,decision_json,decided_at) VALUES ('policy-decision-approved','authority-approved','T-completion','sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50','node-completion','provider','provider:test','action.approved','artifact','artifact:approved','ALLOW','policy-approved','approval-approved','[]','{}','2026-09-19T00:00:00Z');
         INSERT INTO authority_grants(grant_id,task_id,semantic_program_hash,node_id,capability,principal_kind,principal_id,execution_binding_id,attempt_id,policy_decision_id,policy_snapshot_id,approval_id,grants_json,scope,max_uses,uses_consumed,state,issued_at,expires_at) VALUES ('grant-approved','T-completion','sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50','node-completion','test.complete@1','provider','provider:test','binding-completion','attempt-completion','policy-decision-approved','policy-approved','approval-approved','[{"action":"action.approved","resource_kind":"artifact","resource_id":"artifact:approved","semantic_selector":"resource:approved"}]','ONE_SHOT',1,0,'ACTIVE','2026-09-19T00:00:00Z','2026-09-20T00:00:00Z');"#,
    ).unwrap();
    set_completion_binding_refs(&manager, &["policy-decision-approved"], &["grant-approved"]);
    admit_fixture_grant(&manager.connection, "grant-approved").unwrap();
    let check = |transaction: &Transaction<'_>| {
        binding_grants_valid(
            transaction,
            &BindingGrantCheck {
                task_id: "T-completion",
                semantic_hash: HASH,
                node_id: "node-completion",
                binding_id: "binding-completion",
                attempt_id: "attempt-completion",
                grant_refs_json: "[\"grant-approved\"]",
                checked_at: TEST_TIME,
            },
        )
        .unwrap()
    };
    let transaction = manager.connection.transaction().unwrap();
    assert!(check(&transaction));
    for status in ["EXPIRED", "STALE", "CANCELLED", "DENIED"] {
        transaction
            .execute(
                "UPDATE approval_requests SET status=?1 WHERE approval_id='approval-approved'",
                [status],
            )
            .unwrap();
        assert!(!check(&transaction), "{status}");
    }
    transaction.execute("UPDATE approval_requests SET status='APPROVED', expires_at='2026-09-18T00:00:00Z' WHERE approval_id='approval-approved'", []).unwrap();
    assert!(!check(&transaction));
    transaction.execute_batch("UPDATE approval_requests SET expires_at='2026-09-20T00:00:00Z' WHERE approval_id='approval-approved'; UPDATE approval_decisions SET decision='DENY' WHERE approval_id='approval-approved';").unwrap();
    assert!(!check(&transaction));
    transaction.execute_batch("UPDATE approval_decisions SET decision='APPROVE' WHERE approval_id='approval-approved'; UPDATE policy_decisions SET approval_request_id='approval-other' WHERE decision_id='policy-decision-approved';").unwrap();
    assert!(!check(&transaction));
    transaction.execute_batch("UPDATE policy_decisions SET approval_request_id='approval-approved' WHERE decision_id='policy-decision-approved'; UPDATE approval_decisions SET scope='TASK' WHERE approval_id='approval-approved';").unwrap();
    assert!(!check(&transaction));
    transaction.execute_batch("UPDATE approval_decisions SET scope='ONE_SHOT', approved_until='2026-09-19T12:00:00Z' WHERE approval_id='approval-approved';").unwrap();
    assert!(!check(&transaction));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "covers materialized-view and legacy-receipt tampering through one reopen harness"
)]
fn startup_replay_rejects_security_view_tampering_and_receipt_request_forgery() {
    let directory = tempdir().unwrap();
    for (name, mutation) in [
        (
            "waiting",
            "UPDATE tasks SET waiting_on_json = '[{\"kind\":\"input\",\"id\":\"forged\",\"message\":null}]' WHERE task_id = 'T-replay'",
        ),
        (
            "reason",
            "UPDATE tasks SET state_reason_json = '{\"code\":\"FORGED\",\"message\":null}' WHERE task_id = 'T-replay'",
        ),
        (
            "active-plan",
            "INSERT INTO plan_revisions (task_id, plan_revision, plan_id, plan_json, created_at) VALUES ('T-replay', 1, 'plan-forged', '{}', '2026-09-19T00:00:00Z'); UPDATE tasks SET active_plan_revision = 1 WHERE task_id = 'T-replay'",
        ),
        (
            "active-program",
            "INSERT INTO registry_snapshots (snapshot_id, manifest_json, created_at) VALUES ('snapshot-forged', '{}', '2026-09-19T00:00:00Z'); INSERT INTO validation_results (validation_result_id, task_id, valid, semantic_hash, registry_snapshot_id, validator_id, validator_version, result_json, validated_at) VALUES ('validation-forged', 'T-replay', 1, 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50', 'snapshot-forged', 'validator:test', '0.1', '{}', '2026-09-19T00:00:00Z'); INSERT INTO semantic_program_revisions (task_id, program_revision, program_id, ir_version, semantic_hash, registry_snapshot_id, validation_result_id, status, program_json, created_at) VALUES ('T-replay', 1, 'program-forged', '0.1', 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50', 'snapshot-forged', 'validation-forged', 'active', '{}', '2026-09-19T00:00:00Z'); UPDATE tasks SET active_program_revision = 1 WHERE task_id = 'T-replay'",
        ),
        (
            "active-steps",
            "UPDATE tasks SET active_step_ids_json = '[\"node-forged\"]' WHERE task_id = 'T-replay'",
        ),
        (
            "failure",
            "UPDATE tasks SET failure_json = '{\"code\":\"FORGED\",\"summary\":\"forged\",\"step_id\":null,\"provider_id\":null,\"execution_binding_id\":null,\"retryable\":false,\"safe_to_replan\":false,\"unknown_side_effects\":false,\"rollback_available\":false,\"provenance_event_ids\":[]}' WHERE task_id = 'T-replay'",
        ),
        (
            "recovery",
            "UPDATE tasks SET recovery_json = '{\"unknown_operations_ref\":\"forged\"}' WHERE task_id = 'T-replay'",
        ),
    ] {
        let path = directory.path().join(format!("replay-{name}.sqlite3"));
        {
            let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
            manager.create_task(&create("T-replay")).unwrap();
            manager
                .transition(&request(
                    "tr-replay",
                    "T-replay",
                    1,
                    TaskState::Created,
                    TaskState::Planning,
                ))
                .unwrap();
        }
        Connection::open(&path)
            .unwrap()
            .execute_batch(mutation)
            .unwrap();
        assert!(
            TaskManager::open_with_clock(&path, Box::new(FixedClock)).is_err(),
            "{name}"
        );
    }

    for forged_field in ["code", "actor", "message", "related_ids"] {
        let path = directory
            .path()
            .join(format!("forged-request-{forged_field}.sqlite3"));
        let mut original = request(
            "tr-forged-request",
            "T-forged-request",
            1,
            TaskState::Created,
            TaskState::Planning,
        );
        original.reason.message = Some("original message".to_owned());
        original.reason.related_ids = vec!["original-related".to_owned()];
        {
            let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
            manager.create_task(&create("T-forged-request")).unwrap();
            manager.transition(&original).unwrap();
        }
        let connection = Connection::open(&path).unwrap();
        let stored: String = connection
            .query_row(
                "SELECT request_json FROM task_transitions WHERE transition_id = 'tr-forged-request'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let mut forged: Value = serde_json::from_str(&stored).unwrap();
        match forged_field {
            "code" => forged["reason"]["code"] = json!("FORGED_REASON"),
            "actor" => forged["requested_by"]["id"] = json!("service:forged"),
            "message" => forged["reason"]["message"] = json!("forged message"),
            "related_ids" => forged["reason"]["related_ids"] = json!(["forged-related"]),
            _ => unreachable!(),
        }
        connection.execute(
            "UPDATE task_transitions SET request_json = ?1, result_json = NULL WHERE transition_id = 'tr-forged-request'",
            [serde_json::to_string(&forged).unwrap()],
        ).unwrap();
        drop(connection);
        assert!(
            TaskManager::open_with_clock(&path, Box::new(FixedClock)).is_err(),
            "{forged_field}"
        );
        assert!(Connection::open(&path).unwrap().query_row(
            "SELECT result_json FROM task_transitions WHERE transition_id = 'tr-forged-request'",
            [],
            |row| row.get::<_, Option<String>>(0),
        ).unwrap().is_none());
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "table-driven reopen coverage binds every creation field and active program content"
)]
fn startup_replay_binds_creation_payload_and_active_program_content() {
    let directory = tempdir().unwrap();
    for (name, mutation) in [
        (
            "principal-kind",
            "UPDATE tasks SET principal_kind = 'system-service' WHERE task_id = 'T-creation'",
        ),
        (
            "principal-id",
            "UPDATE tasks SET principal_id = 'user:forged' WHERE task_id = 'T-creation'",
        ),
        (
            "workspace",
            "UPDATE tasks SET workspace_id = 'workspace:forged' WHERE task_id = 'T-creation'",
        ),
        (
            "original-intent",
            "UPDATE tasks SET original_intent = 'forged intent' WHERE task_id = 'T-creation'",
        ),
        (
            "normalized-intent",
            "UPDATE tasks SET normalized_intent_json = '{\"forged\":true}' WHERE task_id = 'T-creation'",
        ),
        (
            "constraints",
            "UPDATE tasks SET constraints_json = '{\"forged\":true}' WHERE task_id = 'T-creation'",
        ),
        (
            "created-at",
            "UPDATE tasks SET created_at = '2026-09-18T00:00:00Z' WHERE task_id = 'T-creation'",
        ),
        (
            "updated-at",
            "UPDATE tasks SET updated_at = '2026-09-20T00:00:00Z' WHERE task_id = 'T-creation'",
        ),
    ] {
        let path = directory.path().join(format!("creation-{name}.sqlite3"));
        {
            let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
            manager.create_task(&create("T-creation")).unwrap();
            assert!(
                manager
                    .transition(&request(
                        "tr-creation",
                        "T-creation",
                        1,
                        TaskState::Created,
                        TaskState::Planning,
                    ))
                    .unwrap()
                    .applied
            );
        }
        Connection::open(&path)
            .unwrap()
            .execute(mutation, [])
            .unwrap();
        assert!(
            TaskManager::open_with_clock(&path, Box::new(FixedClock)).is_err(),
            "{name}"
        );
    }

    for (name, changed_program) in [
        (
            "authority-removed",
            r#"{"nodes":[{"id":"node-secure","operation":{"kind":"invoke","capability":"test.secure@1"},"outputs":{"result":"artifact.report@1"},"authority_requests":[]}]}"#,
        ),
        (
            "authority-changed",
            r#"{"nodes":[{"id":"node-secure","operation":{"kind":"invoke","capability":"test.secure@1"},"outputs":{"result":"artifact.report@1"},"authority_requests":[{"action":"artifact.read","resource":"input:other"}]}]}"#,
        ),
    ] {
        let path = directory.path().join(format!("program-{name}.sqlite3"));
        {
            let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
            manager.create_task(&create("T-program-content")).unwrap();
            manager.connection.execute_batch(
                "INSERT INTO registry_snapshots (snapshot_id, manifest_json, created_at) VALUES ('snapshot-program-content', '{}', '2026-09-19T00:00:00Z');
                 INSERT INTO validation_results (validation_result_id, task_id, valid, semantic_hash, registry_snapshot_id, validator_id, validator_version, result_json, validated_at) VALUES ('validation-program-content', 'T-program-content', 1, 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50', 'snapshot-program-content', 'validator:test', '0.1', '{}', '2026-09-19T00:00:00Z');
                 INSERT INTO semantic_program_revisions (task_id, program_revision, program_id, ir_version, semantic_hash, registry_snapshot_id, validation_result_id, status, program_json, created_at) VALUES ('T-program-content', 1, 'program-content', '0.1', 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50', 'snapshot-program-content', 'validation-program-content', 'active', '{\"nodes\":[{\"id\":\"node-secure\",\"operation\":{\"kind\":\"invoke\",\"capability\":\"test.secure@1\"},\"outputs\":{\"result\":\"artifact.report@1\"},\"authority_requests\":[{\"action\":\"artifact.read\",\"resource\":\"input:source\"}]}]}', '2026-09-19T00:00:00Z');
                 UPDATE tasks SET active_program_revision = 1 WHERE task_id = 'T-program-content';",
            ).unwrap();
            assert!(
                manager
                    .transition(&request(
                        "tr-program-content",
                        "T-program-content",
                        1,
                        TaskState::Created,
                        TaskState::Planning,
                    ))
                    .unwrap()
                    .applied
            );
        }
        Connection::open(&path)
            .unwrap()
            .execute(
                "UPDATE semantic_program_revisions SET program_json = ?1 WHERE task_id = 'T-program-content' AND program_revision = 1",
                [changed_program],
            )
            .unwrap();
        assert!(
            TaskManager::open_with_clock(&path, Box::new(FixedClock)).is_err(),
            "{name}"
        );
    }
}

#[test]
fn recovery_assessment_is_schema_shaped_and_collision_safe() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    manager.create_task(&create("T-assessment")).unwrap();
    let operations = ["operation-1".to_owned(), "operation-2".to_owned()];
    let recovery_ref = recovery_operations_ref("T-assessment", 1, &operations).unwrap();
    manager
        .persist_recovery_inventory(
            &recovery_ref,
            "T-assessment",
            1,
            &operations,
            "2026-09-19T00:00:00Z",
        )
        .unwrap();
    manager
        .persist_recovery_inventory(
            &recovery_ref,
            "T-assessment",
            1,
            &operations,
            "2026-09-20T00:00:00Z",
        )
        .unwrap();
    let (assessment, action, subject_kind, reason_codes): (String, String, String, String) = manager.connection.query_row(
        "SELECT assessment_json, safe_action, subject_kind, reason_codes_json FROM recovery_assessments WHERE task_id = 'T-assessment'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    ).unwrap();
    let value: Value = serde_json::from_str(&assessment).unwrap();
    let schema: Value = serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../specs/recovery-assessment.schema.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(jsonschema::validator_for(&schema).unwrap().is_valid(&value));
    assert_eq!(action, "REQUIRE_EXTERNAL_RECONCILIATION");
    assert_eq!(subject_kind, "task");
    assert_eq!(
        serde_json::from_str::<Vec<String>>(&reason_codes).unwrap(),
        vec![
            "RECOVERY_OUTCOME_UNKNOWN",
            "RECOVERY_EXTERNAL_RECONCILIATION_REQUIRED"
        ]
    );
    let registry: Value = serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../specs/recovery-reason-codes.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let registered = registry["codes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entry| entry["code"].as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(registered.contains("RECOVERY_OUTCOME_UNKNOWN"));
    assert!(registered.contains("RECOVERY_EXTERNAL_RECONCILIATION_REQUIRED"));
    assert_eq!(
        manager
            .recovery_unknown_operation_ids(&recovery_ref)
            .unwrap()
            .unwrap(),
        vec!["operation-1", "operation-2"]
    );
    assert!(
        manager
            .persist_recovery_inventory(
                &recovery_ref,
                "T-assessment",
                1,
                &["operation-other".to_owned()],
                "2026-09-19T00:00:00Z",
            )
            .is_err()
    );
}

#[test]
fn startup_recovery_namespace_and_bounded_unknown_reference_resist_squatting_and_scale() {
    let maximum_task_id = "t".repeat(256);
    let bounded_id = startup_recovery_transition_id(&maximum_task_id, u64::MAX);
    assert!(bounded_id.len() <= 256);
    assert_eq!(
        bounded_id,
        startup_recovery_transition_id(&maximum_task_id, u64::MAX)
    );
    assert_ne!(
        bounded_id,
        startup_recovery_transition_id(&maximum_task_id, u64::MAX - 1)
    );

    let mut in_memory = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    let reserved = request(
        "__aios_internal:startup-recovery:attacker",
        "missing",
        1,
        TaskState::Running,
        TaskState::Recovering,
    );
    assert!(in_memory.transition(&reserved).is_err());

    let directory = tempdir().unwrap();
    let path = directory.path().join("many-unknown.sqlite3");
    {
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        seed_nonterminal_history(&mut manager, "T-many-unknown", TaskState::Running);
        let transaction = manager.connection.transaction().unwrap();
        for index in 0..140 {
            transaction.execute(
                "INSERT INTO operations (operation_id, task_id, semantic_program_hash, node_id, effect_class, state, outcome_certainty, prepared_at) VALUES (?1, 'T-many-unknown', ?2, 'node-1', 'NETWORK', 'UNKNOWN', 'OUTCOME_UNKNOWN', '2026-09-19T00:00:00Z')",
                rusqlite::params![format!("operation-{index:03}"), HASH],
            ).unwrap();
        }
        transaction.execute(
            "INSERT INTO task_transitions (transition_id, task_id, expected_revision, expected_state, to_state, outcome, reason_code, request_json, result_json, requested_at, committed_at) VALUES ('startup-recovery:T-many-unknown:4', 'T-many-unknown', 4, 'RUNNING', 'RECOVERING', 'REJECTED', 'TASK_TRANSITION_GUARD_FAILED', '{}', '{}', '2026-09-19T00:00:00Z', '2026-09-19T00:00:00Z')",
            [],
        ).unwrap();
        transaction.commit().unwrap();
    }
    let manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
    let task = manager.get_task("T-many-unknown").unwrap().unwrap();
    assert_eq!(task.state, TaskState::Recovering);
    let recovery = task.recovery.unwrap();
    assert!(recovery.get("unknown_operation_ids").is_none());
    let recovery_ref = recovery["unknown_operations_ref"].as_str().unwrap();
    assert!(recovery_ref.starts_with("recovery-operations:sha256:"));
    let resolved = manager
        .recovery_unknown_operation_ids(recovery_ref)
        .unwrap()
        .unwrap();
    let expected = (0..140)
        .map(|index| format!("operation:operation-{index:03}"))
        .collect::<Vec<_>>();
    assert_eq!(resolved.len(), 140);
    assert_eq!(resolved, expected);
}

#[test]
fn private_intent_commitments_are_nondeterministic_and_authenticate_reopen() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("private-intent.sqlite3");
    {
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        let mut first_request = create("T-private-a");
        first_request.normalized_intent = Some(serde_json::json!({"private":"low-entropy-secret"}));
        manager.create_task(&first_request).unwrap();
        let mut second_request = create("T-private-b");
        second_request.normalized_intent = first_request.normalized_intent.clone();
        manager.create_task(&second_request).unwrap();
        let first: String = manager
            .connection
            .query_row(
                "SELECT event_json FROM provenance_events WHERE task_id = 'T-private-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let second: String = manager
            .connection
            .query_row(
                "SELECT event_json FROM provenance_events WHERE task_id = 'T-private-b'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!first.contains("Exercise durable task controls."));
        assert!(!first.contains("low-entropy-secret"));
        assert_ne!(
            serde_json::from_str::<Value>(&first)
                .unwrap()
                .pointer("/details/creation/original_intent_ref"),
            serde_json::from_str::<Value>(&second)
                .unwrap()
                .pointer("/details/creation/original_intent_ref")
        );
    }
    Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE tasks SET original_intent = 'tampered' WHERE task_id = 'T-private-a'",
            [],
        )
        .unwrap();
    assert!(TaskManager::open_with_clock(&path, Box::new(FixedClock)).is_err());
}

#[test]
fn step_time_attempt_and_transition_revision_bounds_fail_closed() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    manager.create_task(&create("T-bounds-new")).unwrap();
    let mut step = CreateStepExecution {
        attempt_id: "attempt-bounds".to_owned(),
        task_id: "T-bounds-new".to_owned(),
        semantic_program_hash: HASH.to_owned(),
        registry_snapshot_id: None,
        node_id: "node-bounds".to_owned(),
        binding_id: None,
        provider_id: None,
        provider_version: None,
        attempt_number: 1,
        state: StepState::Ready,
        operation_id: None,
        idempotency_key: None,
        outcome_certainty: Some(OutcomeCertainty::NotStarted),
        input_artifacts: Vec::new(),
        output_artifacts: Vec::new(),
        failure: None,
        started_at: None,
        finished_at: None,
    };
    step.started_at = Some("not-a-time".to_owned());
    assert!(manager.create_step_execution(&step).is_err());
    step.started_at = None;
    step.attempt_number = 101;
    assert!(manager.create_step_execution(&step).is_err());
    let mut transition = request(
        "tr-overflow",
        "T-bounds-new",
        1,
        TaskState::Created,
        TaskState::Planning,
    );
    transition.expected_revision = u64::MAX;
    assert!(manager.transition(&transition).is_err());
}

#[test]
fn provider_allocation_blob_and_live_recovery_evidence_are_revalidated() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
    manager.connection.execute(
        "UPDATE artifact_blobs SET durability_state = 'CORRUPT' WHERE content_hash = 'sha256:4444444444444444444444444444444444444444444444444444444444444444'",
        [],
    ).unwrap();
    assert_eq!(
        manager
            .transition(&completion_request("tr-corrupt-blob"))
            .unwrap()
            .reason_code,
        "TASK_UNKNOWN_EXTERNAL_OUTCOME"
    );
    manager
        .connection
        .execute(
            "UPDATE tasks SET state='PAUSED' WHERE task_id='T-completion'",
            [],
        )
        .unwrap();
    let paused = manager.get_task("T-completion").unwrap().unwrap();
    let blocked = manager
        .transition(&request(
            "tr-corrupt-publication-live",
            "T-completion",
            paused.revision,
            TaskState::Paused,
            TaskState::Runnable,
        ))
        .unwrap();
    assert!(!blocked.applied);
    assert_eq!(blocked.reason_code, "TASK_UNKNOWN_EXTERNAL_OUTCOME");
    let still_paused = manager.get_task("T-completion").unwrap().unwrap();
    assert_eq!(
        (still_paused.state, still_paused.revision),
        (TaskState::Paused, paused.revision)
    );

    manager.connection.execute_batch(
        "UPDATE artifact_blobs SET durability_state = 'DURABLE';
         UPDATE tasks SET state = 'RECOVERING';
         UPDATE step_executions SET state = 'READY', outcome_certainty = 'NOT_STARTED';
         UPDATE artifact_output_allocations SET state = 'ALLOCATED', publication_id = NULL, published_artifact_id = NULL;",
    ).unwrap();
    let transaction = manager.connection.transaction().unwrap();
    let check = BindingGrantCheck {
        task_id: "T-completion",
        semantic_hash: HASH,
        node_id: "node-completion",
        binding_id: "binding-completion",
        attempt_id: "attempt-completion",
        grant_refs_json: "[]",
        checked_at: TEST_TIME,
    };
    assert!(binding_grants_valid(&transaction, &check).unwrap());
    assert!(output_allocations_ready(&transaction, &check).unwrap());
    transaction.execute(
        "UPDATE provider_registrations SET state = 'disabled' WHERE registration_id = 'registration-completion'",
        [],
    ).unwrap();
    assert!(!binding_grants_valid(&transaction, &check).unwrap());
    transaction.execute(
        "UPDATE artifact_output_allocations SET expires_at = '2026-09-18T00:00:00Z' WHERE allocation_id = 'allocation-completion'",
        [],
    ).unwrap();
    assert!(!output_allocations_ready(&transaction, &check).unwrap());
    transaction.rollback().unwrap();

    seed_nonterminal_history(&mut manager, "T-live-recovery", TaskState::Running);
    manager.connection.execute(
        "INSERT INTO operations (operation_id, task_id, semantic_program_hash, node_id, effect_class, state, outcome_certainty, prepared_at) VALUES ('operation-live', 'T-live-recovery', ?1, 'node-1', 'NETWORK', 'UNKNOWN', NULL, ?2)",
        rusqlite::params![HASH, TEST_TIME],
    ).unwrap();
    let recovered = manager.reconcile_live_execution("T-live-recovery").unwrap();
    assert!(recovered.applied);
    assert_eq!(recovered.current_state, Some(TaskState::Recovering));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "covers refresh immutability, stale-reference rebasing, and successful recovery exit"
)]
fn refreshed_recovery_inventory_becomes_active_without_rewriting_history() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("refresh-recovery.sqlite3");
    let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
    seed_nonterminal_history(&mut manager, "T-refresh-recovery", TaskState::Running);
    manager
        .connection
        .execute(
            "INSERT INTO operations (
                operation_id,task_id,semantic_program_hash,node_id,effect_class,state,
                outcome_certainty,prepared_at
             ) VALUES (
                'operation-r1','T-refresh-recovery',?1,'node-1','NETWORK','UNKNOWN',
                'OUTCOME_UNKNOWN',?2
             )",
            rusqlite::params![HASH, TEST_TIME],
        )
        .unwrap();
    let recovered = manager
        .reconcile_live_execution("T-refresh-recovery")
        .unwrap();
    assert!(recovered.applied);
    let first = manager.get_task("T-refresh-recovery").unwrap().unwrap();
    assert_eq!(first.state, TaskState::Recovering);
    let first_ref = first
        .recovery
        .as_ref()
        .and_then(|value| value["unknown_operations_ref"].as_str())
        .unwrap()
        .to_owned();
    assert_eq!(
        manager
            .recovery_unknown_operation_ids(&first_ref)
            .unwrap()
            .unwrap(),
        vec!["operation:operation-r1"]
    );

    manager
        .connection
        .execute(
            "INSERT INTO operations (
                operation_id,task_id,semantic_program_hash,node_id,effect_class,state,
                outcome_certainty,prepared_at
             ) VALUES (
                'operation-r2','T-refresh-recovery',?1,'node-1','NETWORK','UNKNOWN',
                'OUTCOME_UNKNOWN',?2
             )",
            rusqlite::params![HASH, TEST_TIME],
        )
        .unwrap();
    drop(manager);
    let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
    let refreshed = manager.get_task("T-refresh-recovery").unwrap().unwrap();
    let second_ref = manager
        .active_recovery_inventory_ref("T-refresh-recovery")
        .unwrap()
        .unwrap();
    assert_eq!(refreshed.state, TaskState::Recovering);
    assert_eq!(refreshed.revision, first.revision);
    assert_ne!(second_ref, first_ref);
    assert_eq!(
        refreshed
            .recovery
            .as_ref()
            .and_then(|value| value["unknown_operations_ref"].as_str()),
        Some(first_ref.as_str())
    );
    assert_eq!(
        manager
            .recovery_unknown_operation_ids(&second_ref)
            .unwrap()
            .unwrap(),
        vec!["operation:operation-r1", "operation:operation-r2"]
    );
    assert_eq!(
        manager
            .recovery_unknown_operation_ids(&first_ref)
            .unwrap()
            .unwrap(),
        vec!["operation:operation-r1"]
    );
    manager
        .connection
        .execute(
            "UPDATE operations SET state='SUCCEEDED',outcome_certainty='COMPLETED',finished_at=?1
             WHERE operation_id IN ('operation-r1','operation-r2')",
            [TEST_TIME],
        )
        .unwrap();
    let first_assessment_id =
        recovery_subject_assessment_id(&first_ref, "external-operation", "operation:operation-r1");
    let first_assessment_before: String = manager
        .connection
        .query_row(
            "SELECT assessment_json FROM recovery_assessments WHERE assessment_id=?1",
            [&first_assessment_id],
            |row| row.get(0),
        )
        .unwrap();
    manager
        .reconcile_recovery_subject(&first_ref, "operation:operation-r1")
        .unwrap();
    manager
        .reconcile_recovery_subject(&second_ref, "operation:operation-r2")
        .unwrap();
    assert_eq!(
        manager
            .connection
            .query_row(
                "SELECT assessment_json FROM recovery_assessments WHERE assessment_id=?1",
                [&first_assessment_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        first_assessment_before,
        "refresh reconciliation must not rewrite historical evidence"
    );
    let current = manager.get_task("T-refresh-recovery").unwrap().unwrap();
    let exited = manager
        .transition(&request(
            "tr-refreshed-recovery-resolved",
            "T-refresh-recovery",
            current.revision,
            TaskState::Recovering,
            TaskState::Planning,
        ))
        .unwrap();
    assert!(exited.applied, "{exited:?}");
}

#[test]
fn refreshed_recovery_inventory_carries_forward_already_resolved_subjects() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("refresh-resolved-recovery.sqlite3");
    let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
    seed_nonterminal_history(&mut manager, "T-refresh-resolved", TaskState::Running);
    manager.connection.execute(
        "INSERT INTO operations (
            operation_id,task_id,semantic_program_hash,node_id,effect_class,state,
            outcome_certainty,prepared_at
         ) VALUES ('operation-r1','T-refresh-resolved',?1,'node-1','NETWORK','UNKNOWN','OUTCOME_UNKNOWN',?2)",
        rusqlite::params![HASH, TEST_TIME],
    ).unwrap();
    manager
        .reconcile_live_execution("T-refresh-resolved")
        .unwrap();
    let first_ref = manager
        .active_recovery_inventory_ref("T-refresh-resolved")
        .unwrap()
        .unwrap();
    manager.connection.execute(
        "UPDATE operations SET state='SUCCEEDED',outcome_certainty='COMPLETED',finished_at=?1 WHERE operation_id='operation-r1'",
        [TEST_TIME],
    ).unwrap();
    manager
        .reconcile_recovery_subject(&first_ref, "operation:operation-r1")
        .unwrap();

    manager.connection.execute(
        "INSERT INTO operations (
            operation_id,task_id,semantic_program_hash,node_id,effect_class,state,
            outcome_certainty,prepared_at
         ) VALUES ('operation-r2','T-refresh-resolved',?1,'node-1','NETWORK','UNKNOWN','OUTCOME_UNKNOWN',?2)",
        rusqlite::params![HASH, TEST_TIME],
    ).unwrap();
    drop(manager);
    let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
    let second_ref = manager
        .active_recovery_inventory_ref("T-refresh-resolved")
        .unwrap()
        .unwrap();
    assert_ne!(second_ref, first_ref);
    assert_eq!(
        manager
            .recovery_unknown_operation_ids(&second_ref)
            .unwrap()
            .unwrap(),
        vec!["operation:operation-r1", "operation:operation-r2"]
    );
    manager.connection.execute(
        "UPDATE operations SET state='SUCCEEDED',outcome_certainty='COMPLETED',finished_at=?1 WHERE operation_id='operation-r2'",
        [TEST_TIME],
    ).unwrap();
    manager
        .reconcile_recovery_subject(&second_ref, "operation:operation-r2")
        .unwrap();
    let current = manager.get_task("T-refresh-resolved").unwrap().unwrap();
    let exited = manager
        .transition(&request(
            "tr-carried-forward-recovery-resolved",
            "T-refresh-resolved",
            current.revision,
            TaskState::Recovering,
            TaskState::Planning,
        ))
        .unwrap();
    assert!(exited.applied, "{exited:?}");
}

#[test]
fn recovery_refresh_materializes_terminal_evidence_that_arrived_before_reconciliation() {
    let directory = tempdir().unwrap();
    let path = directory
        .path()
        .join("refresh-terminal-before-reconcile.sqlite3");
    let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
    seed_nonterminal_history(&mut manager, "T-refresh-terminal", TaskState::Running);
    manager.connection.execute(
        "INSERT INTO operations (
            operation_id,task_id,semantic_program_hash,node_id,effect_class,state,
            outcome_certainty,prepared_at
         ) VALUES ('operation-r1','T-refresh-terminal',?1,'node-1','NETWORK','UNKNOWN','OUTCOME_UNKNOWN',?2)",
        rusqlite::params![HASH, TEST_TIME],
    ).unwrap();
    manager
        .reconcile_live_execution("T-refresh-terminal")
        .unwrap();
    let first_ref = manager
        .active_recovery_inventory_ref("T-refresh-terminal")
        .unwrap()
        .unwrap();
    manager.connection.execute(
        "UPDATE operations SET state='SUCCEEDED',outcome_certainty='COMPLETED',finished_at=?1 WHERE operation_id='operation-r1'",
        [TEST_TIME],
    ).unwrap();
    manager.connection.execute(
        "INSERT INTO operations (
            operation_id,task_id,semantic_program_hash,node_id,effect_class,state,
            outcome_certainty,prepared_at
         ) VALUES ('operation-r2','T-refresh-terminal',?1,'node-1','NETWORK','UNKNOWN','OUTCOME_UNKNOWN',?2)",
        rusqlite::params![HASH, TEST_TIME],
    ).unwrap();

    drop(manager);
    let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
    let second_ref = manager
        .active_recovery_inventory_ref("T-refresh-terminal")
        .unwrap()
        .unwrap();
    assert_ne!(second_ref, first_ref);
    assert_eq!(
        manager
            .recovery_unknown_operation_ids(&second_ref)
            .unwrap()
            .unwrap(),
        vec!["operation:operation-r1", "operation:operation-r2"]
    );
    manager.connection.execute(
        "UPDATE operations SET state='SUCCEEDED',outcome_certainty='COMPLETED',finished_at=?1 WHERE operation_id='operation-r2'",
        [TEST_TIME],
    ).unwrap();
    manager
        .reconcile_recovery_subject(&second_ref, "operation:operation-r2")
        .unwrap();
    let current = manager.get_task("T-refresh-terminal").unwrap().unwrap();
    let exited = manager
        .transition(&request(
            "tr-terminal-before-reconcile-resolved",
            "T-refresh-terminal",
            current.revision,
            TaskState::Recovering,
            TaskState::Planning,
        ))
        .unwrap();
    assert!(exited.applied, "{exited:?}");
}

#[test]
fn unknown_newer_migration_and_recovery_inventory_tamper_fail_closed() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("future.sqlite3");
    let connection = Connection::open(&path).unwrap();
    connection.execute_batch(
        "CREATE TABLE schema_migrations (migration_id TEXT PRIMARY KEY, checksum TEXT NOT NULL, applied_at TEXT NOT NULL);
         INSERT INTO schema_migrations VALUES ('0010_future', 'future', '2026-09-19T00:00:00Z');",
    ).unwrap();
    drop(connection);
    assert!(TaskManager::open_with_clock(&path, Box::new(FixedClock)).is_err());

    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    manager.create_task(&create("T-digest-tamper")).unwrap();
    let ids = vec!["operation-original".to_owned()];
    let recovery_ref = recovery_operations_ref("T-digest-tamper", 1, &ids).unwrap();
    manager
        .persist_recovery_inventory(&recovery_ref, "T-digest-tamper", 1, &ids, TEST_TIME)
        .unwrap();
    manager.connection.execute(
        "UPDATE recovery_unknown_operations SET operation_id = 'operation-forged' WHERE assessment_id = ?1",
        [&recovery_ref],
    ).unwrap();
    assert!(
        manager
            .recovery_unknown_operation_ids(&recovery_ref)
            .is_err()
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "covers aggregate and per-subject certainty plus inventory substitution in one fixture"
)]
fn recovery_is_per_subject_and_empty_inventory_never_proves_not_started() {
    let mut empty = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    empty.create_task(&create("T-empty-recovery")).unwrap();
    let empty_ref = recovery_operations_ref("T-empty-recovery", 1, &[]).unwrap();
    empty
        .persist_recovery_inventory(&empty_ref, "T-empty-recovery", 1, &[], TEST_TIME)
        .unwrap();
    let (certainty, action): (String, String) = empty
        .connection
        .query_row(
            "SELECT certainty, safe_action FROM recovery_assessments WHERE assessment_id = ?1",
            [&empty_ref],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (certainty.as_str(), action.as_str()),
        ("OUTCOME_UNKNOWN", "REQUIRE_EXTERNAL_RECONCILIATION")
    );

    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
    manager.connection.execute_batch(
        "UPDATE step_executions SET state = 'RUNNING', outcome_certainty = NULL WHERE attempt_id = 'attempt-completion';
         INSERT INTO operations (operation_id, task_id, semantic_program_hash, node_id, binding_id, attempt_id, effect_class, state, outcome_certainty, prepared_at)
         VALUES ('operation-recovery', 'T-completion', 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50', 'node-completion', 'binding-completion', 'attempt-completion', 'NETWORK', 'UNKNOWN', NULL, '2026-09-19T00:00:00Z');
         INSERT INTO provider_invocations (invocation_id, attempt_id, binding_id, task_id, provider_id, provider_version, status, request_json)
         VALUES ('invocation-recovery', 'attempt-completion', 'binding-completion', 'T-completion', 'provider:test', '0.1.0', 'PENDING', '{}');",
    ).unwrap();
    let inventory = unresolved_execution_ids(&manager.connection, "T-completion").unwrap();
    let recovery_ref = recovery_operations_ref("T-completion", 2, &inventory).unwrap();
    manager
        .persist_recovery_inventory(&recovery_ref, "T-completion", 2, &inventory, TEST_TIME)
        .unwrap();
    let subjects: Vec<(String, String, String)> = {
        let mut statement = manager.connection.prepare(
            "SELECT subject_kind, subject_id, certainty FROM recovery_assessments WHERE task_id = 'T-completion' AND subject_kind <> 'task' ORDER BY subject_kind, subject_id",
        ).unwrap();
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap()
    };
    assert!(subjects.contains(&(
        "attempt".to_owned(),
        "attempt-completion".to_owned(),
        "OUTCOME_UNKNOWN".to_owned()
    )));
    assert!(subjects.contains(&(
        "external-operation".to_owned(),
        "operation:operation-recovery".to_owned(),
        "OUTCOME_UNKNOWN".to_owned()
    )));
    assert!(subjects.contains(&(
        "external-operation".to_owned(),
        "provider-invocation:invocation-recovery".to_owned(),
        "OUTCOME_UNKNOWN".to_owned()
    )));
    manager
        .connection
        .execute(
            "DELETE FROM recovery_unknown_operations WHERE assessment_id = ?1 AND ordinal = 0",
            [&recovery_ref],
        )
        .unwrap();
    assert!(
        manager
            .recovery_unknown_operation_ids(&recovery_ref)
            .is_err()
    );
    manager.connection.execute(
        "INSERT INTO recovery_unknown_operations(assessment_id, ordinal, operation_id) VALUES (?1, 0, ?2)",
        rusqlite::params![recovery_ref, inventory[0]],
    ).unwrap();
    manager.connection.execute(
        "INSERT INTO recovery_unknown_operations(assessment_id, ordinal, operation_id) VALUES (?1, 999, 'forged-append')",
        [&recovery_ref],
    ).unwrap();
    assert!(
        manager
            .recovery_unknown_operation_ids(&recovery_ref)
            .is_err()
    );
    manager
        .connection
        .execute(
            "DELETE FROM recovery_unknown_operations WHERE assessment_id=?1 AND ordinal=999",
            [&recovery_ref],
        )
        .unwrap();
    manager.connection.execute(
        "UPDATE recovery_unknown_operations SET ordinal=ordinal+100 WHERE assessment_id=?1 AND ordinal IN (0,1)",
        [&recovery_ref],
    ).unwrap();
    manager.connection.execute(
        "UPDATE recovery_unknown_operations SET ordinal=CASE ordinal WHEN 100 THEN 1 WHEN 101 THEN 0 END WHERE assessment_id=?1 AND ordinal IN (100,101)",
        [&recovery_ref],
    ).unwrap();
    assert!(
        manager
            .recovery_unknown_operation_ids(&recovery_ref)
            .is_err()
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "keeps historical inventory, immutable receipt authentication, and ambiguous terminal outcomes together"
)]
fn authenticated_terminal_provider_receipt_resolves_historical_inventory() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
    manager
        .connection
        .execute(
            "INSERT INTO provider_invocations(
            invocation_id,attempt_id,binding_id,task_id,provider_id,provider_version,
            status,request_json,started_at
         ) VALUES ('invocation-terminal','attempt-completion','binding-completion',
            'T-completion','provider:test','0.1.0','PENDING','{}',?1)",
            [TEST_TIME],
        )
        .unwrap();
    manager
        .connection
        .execute(
            "UPDATE step_executions
             SET invocation_id='invocation-terminal',outcome_certainty='OUTCOME_UNKNOWN'
             WHERE task_id='T-completion' AND attempt_id='attempt-completion'",
            [],
        )
        .unwrap();
    let inventory = unresolved_execution_ids(&manager.connection, "T-completion").unwrap();
    assert!(inventory.contains(&"attempt:attempt-completion".to_owned()));
    assert!(inventory.contains(&"provider-invocation:invocation-terminal".to_owned()));
    let recovery_ref = recovery_operations_ref("T-completion", 2, &inventory).unwrap();
    manager
        .persist_recovery_inventory(&recovery_ref, "T-completion", 2, &inventory, TEST_TIME)
        .unwrap();
    {
        let transaction = manager.connection.transaction().unwrap();
        assert!(
            resolved_recovery_subject(&transaction, "T-completion", "attempt:attempt-completion")
                .unwrap()
                .is_none(),
            "a mutable attempt certainty cannot resolve without authenticated provider evidence"
        );
    }
    let result = canonical_json(&serde_json::json!({
        "schema_version":SCHEMA_VERSION,
        "result_id":"provider-result-terminal",
        "invocation_id":"invocation-terminal",
        "task_id":"T-completion",
        "execution_binding_id":"binding-completion",
        "node_id":"node-completion",
        "provider":{"id":"provider:test","version":"0.1.0","package_or_build_hash":"sha256:build"},
        "status":"SUCCEEDED",
        "reason_codes":["PROVIDER_SUCCEEDED"],
        "outputs":{},
        "started_at":TEST_TIME,
        "completed_at":TEST_TIME
    }))
    .unwrap();
    let sibling_result = canonical_json(&serde_json::json!({
        "schema_version":SCHEMA_VERSION,
        "result_id":"provider-result-sibling",
        "invocation_id":"invocation-sibling",
        "task_id":"T-completion",
        "execution_binding_id":"binding-completion",
        "node_id":"node-completion",
        "provider":{"id":"provider:test","version":"0.1.0","package_or_build_hash":"sha256:build"},
        "status":"SUCCEEDED",
        "reason_codes":["PROVIDER_SUCCEEDED"],
        "outputs":{},
        "started_at":TEST_TIME,
        "completed_at":TEST_TIME
    }))
    .unwrap();
    manager
        .connection
        .execute(
            "INSERT INTO provider_invocations(
            invocation_id,attempt_id,binding_id,task_id,provider_id,provider_version,
            status,request_json,result_json,started_at,completed_at
         ) VALUES ('invocation-sibling','attempt-completion','binding-completion',
            'T-completion','provider:test','0.1.0','SUCCEEDED','{}',?1,?2,?2)",
            rusqlite::params![sibling_result, TEST_TIME],
        )
        .unwrap();
    {
        let transaction = manager.connection.transaction().unwrap();
        assert!(
            resolved_recovery_subject(&transaction, "T-completion", "attempt:attempt-completion")
                .unwrap()
                .is_none(),
            "a terminal sibling must not resolve the step's recorded pending invocation"
        );
    }
    manager
        .connection
        .execute(
            "UPDATE provider_invocations SET status='SUCCEEDED',result_json=?1,completed_at=?2
         WHERE invocation_id='invocation-terminal'",
            rusqlite::params![result, TEST_TIME],
        )
        .unwrap();
    {
        let transaction = manager.connection.transaction().unwrap();
        assert!(
            resolved_recovery_subject(&transaction, "T-completion", "attempt:attempt-completion")
                .unwrap()
                .is_some(),
            "the exact authenticated provider result resolves its attempt"
        );
    }
    manager
        .reconcile_recovery_subject(&recovery_ref, "attempt:attempt-completion")
        .unwrap();
    assert_eq!(
        manager
            .get_step_execution("attempt-completion")
            .unwrap()
            .unwrap()
            .outcome_certainty,
        Some(OutcomeCertainty::Completed)
    );
    for (field, forged) in [
        ("id", "provider:forged"),
        ("package_or_build_hash", "sha256:forged-build"),
    ] {
        let mut forged_provider: Value = serde_json::from_str(&result).unwrap();
        forged_provider["provider"][field] = Value::String(forged.to_owned());
        manager.connection.execute(
            "UPDATE provider_invocations SET result_json=?1 WHERE invocation_id='invocation-terminal'",
            [canonical_json(&forged_provider).unwrap()],
        ).unwrap();
        let transaction = manager.connection.transaction().unwrap();
        assert!(
            provider_invocation_resolution(&transaction, "T-completion", "invocation-terminal")
                .unwrap()
                .is_none(),
            "{field}"
        );
    }
    manager.connection.execute(
        "UPDATE provider_invocations SET result_json=?1 WHERE invocation_id='invocation-terminal'",
        [&result],
    ).unwrap();
    manager
        .connection
        .execute_batch(
            "DROP TRIGGER execution_bindings_no_update;
             UPDATE execution_bindings
             SET provider_build_hash=NULL
             WHERE binding_id='binding-completion';",
        )
        .unwrap();
    let mut null_build_hash: Value = serde_json::from_str(&result).unwrap();
    null_build_hash["provider"]["package_or_build_hash"] = Value::Null;
    manager
        .connection
        .execute(
            "UPDATE provider_invocations SET result_json=?1 WHERE invocation_id='invocation-terminal'",
            [canonical_json(&null_build_hash).unwrap()],
        )
        .unwrap();
    {
        let transaction = manager.connection.transaction().unwrap();
        assert!(
            provider_invocation_resolution(&transaction, "T-completion", "invocation-terminal")
                .unwrap()
                .is_some()
        );
    }
    null_build_hash["provider"]
        .as_object_mut()
        .unwrap()
        .remove("package_or_build_hash");
    manager
        .connection
        .execute(
            "UPDATE provider_invocations SET result_json=?1 WHERE invocation_id='invocation-terminal'",
            [canonical_json(&null_build_hash).unwrap()],
        )
        .unwrap();
    {
        let transaction = manager.connection.transaction().unwrap();
        assert!(
            provider_invocation_resolution(&transaction, "T-completion", "invocation-terminal")
                .unwrap()
                .is_none(),
            "an omitted build identity must not equal an explicitly null binding identity"
        );
    }
    manager
        .connection
        .execute(
            "UPDATE execution_bindings SET provider_build_hash='sha256:build'
             WHERE binding_id='binding-completion'",
            [],
        )
        .unwrap();
    manager
        .connection
        .execute(
            "UPDATE provider_invocations SET result_json=?1
             WHERE invocation_id='invocation-terminal'",
            [&result],
        )
        .unwrap();
    manager
        .reconcile_recovery_subject(&recovery_ref, "provider-invocation:invocation-terminal")
        .unwrap();
    let (certainty, action): (String, String) = manager
        .connection
        .query_row(
            "SELECT certainty,safe_action FROM recovery_assessments
         WHERE task_id='T-completion' AND subject_id='provider-invocation:invocation-terminal'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (certainty.as_str(), action.as_str()),
        ("COMPLETED", "RECONCILE_STATE")
    );
    manager.connection.execute(
        "UPDATE tasks SET state='RECOVERING',recovery_json=?1 WHERE task_id='T-completion'",
        [serde_json::json!({"unknown_operations_ref":recovery_ref,"last_known_daemon_instance":null}).to_string()],
    ).unwrap();
    let transaction = manager.connection.transaction().unwrap();
    assert!(recovery_allows_exit(&transaction, "T-completion").unwrap());
    transaction.rollback().unwrap();

    for (status, reason_code) in [
        ("PROVIDER_FAILURE", "PROVIDER_RUNTIME_FAILURE"),
        ("SEMANTIC_FAILURE", "PROVIDER_SEMANTIC_FAILURE"),
    ] {
        let ambiguous = canonical_json(&serde_json::json!({
            "schema_version":SCHEMA_VERSION,"result_id":"provider-result-terminal",
            "invocation_id":"invocation-terminal","task_id":"T-completion",
            "execution_binding_id":"binding-completion","node_id":"node-completion",
            "provider":{"id":"provider:test","version":"0.1.0"},
            "status":status,"reason_codes":[reason_code],
            "outputs":{},"started_at":TEST_TIME,"completed_at":TEST_TIME
        }))
        .unwrap();
        manager.connection.execute(
            "UPDATE provider_invocations SET status=?1,result_json=?2 WHERE invocation_id='invocation-terminal'",
            rusqlite::params![status, ambiguous],
        ).unwrap();
        let transaction = manager.connection.transaction().unwrap();
        assert!(
            provider_invocation_resolution(&transaction, "T-completion", "invocation-terminal")
                .unwrap()
                .is_none(),
            "{status}"
        );
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "compares canonical, malformed, and ambiguous terminal provider receipts across reopen"
)]
fn terminal_provider_receipts_drive_inventory_containment_and_startup_recovery() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("provider-terminal-recovery.sqlite3");
    let cases = [
        ("safe", "SUCCEEDED", true),
        ("malformed", "SUCCEEDED", false),
        ("ambiguous", "PROVIDER_FAILURE", false),
    ];
    {
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        for (name, status, canonical_safe) in cases {
            let task_id = format!("T-provider-{name}");
            let attempt_id = format!("attempt-{name}");
            let binding_id = format!("binding-{name}");
            let invocation_id = format!("invocation-{name}");
            seed_nonterminal_history(&mut manager, &task_id, TaskState::Paused);
            let result_json = if name == "malformed" {
                "{}".to_owned()
            } else {
                canonical_json(&serde_json::json!({
                    "schema_version":SCHEMA_VERSION,
                    "result_id":format!("result-{name}"),
                    "invocation_id":invocation_id,
                    "task_id":task_id,
                    "execution_binding_id":binding_id,
                    "node_id":"node-provider",
                    "provider":{
                        "id":"provider:test","version":"0.1.0",
                        "package_or_build_hash":"sha256:build"
                    },
                    "status":status,
                    "reason_codes":[if canonical_safe {"PROVIDER_SUCCEEDED"} else {"PROVIDER_RUNTIME_FAILURE"}],
                    "outputs":{},"started_at":TEST_TIME,"completed_at":TEST_TIME
                }))
                .unwrap()
            };
            manager
                .connection
                .execute_batch("PRAGMA foreign_keys=OFF;")
                .unwrap();
            manager
                .connection
                .execute(
                    "INSERT INTO execution_bindings(
                    binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,
                    ir_version,node_id,capability,provider_id,provider_version,
                    provider_build_hash,attempt,policy_decision_refs_json,grant_refs_json,
                    execution_profile_ref,placement_json,binding_json,created_at
                 ) VALUES (?1,?2,?3,?4,'snapshot:fixture','0.1','node-provider',
                    'test.provider@1','provider:test','0.1.0','sha256:build',1,
                    '[]','[]','profile:fixture','{}','{}',?5)",
                    rusqlite::params![binding_id, attempt_id, task_id, HASH, TEST_TIME],
                )
                .unwrap();
            manager
                .connection
                .execute(
                    "INSERT INTO provider_invocations(
                    invocation_id,attempt_id,binding_id,task_id,provider_id,provider_version,
                    status,request_json,result_json,started_at,completed_at
                 ) VALUES (?1,?2,?3,?4,'provider:test','0.1.0',?5,'{}',?6,?7,?7)",
                    rusqlite::params![
                        invocation_id,
                        attempt_id,
                        binding_id,
                        task_id,
                        status,
                        result_json,
                        TEST_TIME
                    ],
                )
                .unwrap();
            manager
                .connection
                .execute_batch("PRAGMA foreign_keys=ON;")
                .unwrap();
            let inventory = unresolved_execution_ids(&manager.connection, &task_id).unwrap();
            assert_eq!(inventory.is_empty(), canonical_safe, "pre-reopen {name}");
            let transaction = manager.connection.transaction().unwrap();
            assert_eq!(
                execution_is_contained(&transaction, &task_id).unwrap(),
                canonical_safe,
                "pre-reopen {name}"
            );
        }
    }
    let manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
    for (name, _, canonical_safe) in cases {
        let task = manager
            .get_task(&format!("T-provider-{name}"))
            .unwrap()
            .unwrap();
        assert_eq!(
            task.state,
            if canonical_safe {
                TaskState::Paused
            } else {
                TaskState::Recovering
            },
            "post-reopen {name}"
        );
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "keeps the provider-status containment matrix and startup recovery assertion together"
)]
fn paused_startup_recovery_and_all_planning_entries_require_containment() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("paused-recovery.sqlite3");
    {
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        seed_nonterminal_history(&mut manager, "T-paused-recovery", TaskState::Paused);
    }
    let manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
    assert_eq!(
        manager
            .get_task("T-paused-recovery")
            .unwrap()
            .unwrap()
            .state,
        TaskState::Paused
    );

    for (index, (status, source, target, contained, applies)) in [
        (
            "PENDING",
            TaskState::Paused,
            TaskState::Cancelled,
            false,
            false,
        ),
        (
            "STARTING",
            TaskState::Running,
            TaskState::Failed,
            false,
            false,
        ),
        (
            "RUNNING",
            TaskState::Verifying,
            TaskState::Planning,
            false,
            false,
        ),
        (
            "OUTCOME_UNKNOWN",
            TaskState::Paused,
            TaskState::Planning,
            false,
            false,
        ),
        (
            "TIMED_OUT",
            TaskState::Paused,
            TaskState::Cancelled,
            false,
            false,
        ),
        (
            "PROVIDER_FAILURE",
            TaskState::Running,
            TaskState::Failed,
            false,
            false,
        ),
        (
            "CANCELLED",
            TaskState::Verifying,
            TaskState::Planning,
            false,
            false,
        ),
        (
            "OUTPUT_FINALIZATION_FAILED",
            TaskState::Paused,
            TaskState::Planning,
            false,
            false,
        ),
        (
            "AUTHORITY_REVOKED",
            TaskState::Paused,
            TaskState::Cancelled,
            false,
            false,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
        seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
        manager
            .connection
            .execute(
                "UPDATE tasks SET state = ?1 WHERE task_id = 'T-completion'",
                [source.as_str()],
            )
            .unwrap();
        manager.connection.execute(
            "INSERT INTO provider_invocations (invocation_id, attempt_id, binding_id, task_id, provider_id, provider_version, status, request_json) VALUES (?1, 'attempt-completion', 'binding-completion', 'T-completion', 'provider:test', '0.1.0', ?2, '{}')",
            rusqlite::params![format!("invocation-containment-{index}"), status],
        ).unwrap();
        if status == "PROVIDER_FAILURE" {
            manager.connection.execute(
                "UPDATE step_executions SET state='FAILED', outcome_certainty='FAILED_NO_EFFECT', finished_at=?1 WHERE attempt_id='attempt-completion'",
                [TEST_TIME],
            ).unwrap();
        }
        {
            let transaction = manager.connection.transaction().unwrap();
            let invocation_id = format!("provider-invocation:invocation-containment-{index}");
            assert_eq!(
                unresolved_execution_ids(&transaction, "T-completion")
                    .unwrap()
                    .contains(&invocation_id),
                !contained,
                "{status}"
            );
            assert_eq!(
                load_recovery_subjects(&transaction, "T-completion")
                    .unwrap()
                    .iter()
                    .any(|subject| subject.id == invocation_id),
                !contained,
                "{status}"
            );
            assert_eq!(
                execution_is_contained(&transaction, "T-completion").unwrap(),
                contained,
                "{status}"
            );
            transaction.rollback().unwrap();
        }
        let result = manager
            .transition(&request(
                &format!("tr-containment-{index}"),
                "T-completion",
                2,
                source,
                target,
            ))
            .unwrap();
        assert_eq!(result.applied, applies, "{status}");
        if !applies {
            assert!(
                matches!(
                    result.reason_code.as_str(),
                    "TASK_TRANSITION_GUARD_FAILED" | "TASK_UNKNOWN_EXTERNAL_OUTCOME"
                ),
                "{status}"
            );
        }
    }
}

#[test]
fn recovering_cannot_escape_unknown_assessment_but_resolved_evidence_can_advance() {
    for (name, seed_assessment, target, applies) in [
        ("missing", false, TaskState::Planning, false),
        ("unknown", true, TaskState::Planning, false),
        ("unknown-paused", true, TaskState::Paused, false),
        ("resolved", true, TaskState::Planning, true),
        ("resolved-paused", true, TaskState::Paused, true),
    ] {
        let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
        let revision = seed_recovering_history(&mut manager, "T-recovery-exit");
        if seed_assessment {
            if applies {
                seed_resolved_empty_recovery(&mut manager, "T-recovery-exit", revision);
            } else {
                let recovery_ref =
                    recovery_operations_ref("T-recovery-exit", revision, &[]).unwrap();
                manager
                    .persist_recovery_inventory(
                        &recovery_ref,
                        "T-recovery-exit",
                        revision,
                        &[],
                        TEST_TIME,
                    )
                    .unwrap();
                manager
                    .connection
                    .execute(
                        "UPDATE tasks SET recovery_json=?2 WHERE task_id=?1",
                        rusqlite::params![
                            "T-recovery-exit",
                            serde_json::json!({
                                "unknown_operations_ref": recovery_ref,
                                "last_known_daemon_instance": null
                            })
                            .to_string()
                        ],
                    )
                    .unwrap();
            }
        }
        let result = manager
            .transition(&request(
                &format!("tr-recovery-exit-{name}"),
                "T-recovery-exit",
                revision,
                TaskState::Recovering,
                target,
            ))
            .unwrap();
        assert_eq!(result.applied, applies, "{name}");
        if !applies {
            assert_eq!(result.reason_code, "TASK_TRANSITION_GUARD_FAILED", "{name}");
        }
    }
}

#[test]
fn actual_running_admission_requires_complete_current_output_allocations() {
    for (name, mutation, applies) in [
        (
            "valid",
            "UPDATE artifact_output_allocations SET state='ALLOCATED', publication_id=NULL, published_artifact_id=NULL",
            true,
        ),
        (
            "absent",
            "UPDATE artifact_output_allocations SET state='ABORTED', publication_id=NULL, published_artifact_id=NULL",
            false,
        ),
        (
            "missing-port",
            "UPDATE artifact_output_allocations SET state='ALLOCATED', output_port=NULL, publication_id=NULL, published_artifact_id=NULL",
            false,
        ),
        (
            "wrong-port",
            "UPDATE artifact_output_allocations SET state='ALLOCATED', output_port='wrong', publication_id=NULL, published_artifact_id=NULL",
            false,
        ),
        (
            "wrong-binding",
            "UPDATE artifact_output_allocations SET state='ALLOCATED', binding_id='binding-wrong', publication_id=NULL, published_artifact_id=NULL",
            false,
        ),
        (
            "expired",
            "UPDATE artifact_output_allocations SET state='ALLOCATED', expires_at='2026-09-18T00:00:00Z', publication_id=NULL, published_artifact_id=NULL",
            false,
        ),
    ] {
        let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
        seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
        align_completion_fixture_state(&mut manager, TaskState::Recovering);
        manager.connection.execute_batch(
            "UPDATE tasks SET state='RECOVERING', waiting_on_json='[]' WHERE task_id='T-completion';
             UPDATE step_executions SET state='READY', outcome_certainty='NOT_STARTED' WHERE attempt_id='attempt-completion';
             DELETE FROM artifact_publications WHERE publication_id='publication-completion';",
        ).unwrap();
        seed_resolved_empty_recovery(&mut manager, "T-completion", 2);
        manager.connection.execute(mutation, []).unwrap();
        let result = manager
            .transition(&request(
                &format!("tr-allocation-{name}"),
                "T-completion",
                2,
                TaskState::Recovering,
                TaskState::Running,
            ))
            .unwrap();
        assert_eq!(result.applied, applies, "{name}");
        assert_eq!(
            manager
                .get_step_execution("attempt-completion")
                .unwrap()
                .unwrap()
                .state,
            if applies {
                StepState::Running
            } else {
                StepState::Ready
            },
            "{name}"
        );
    }
}

#[test]
fn persisted_step_timestamp_and_migration_chain_are_strict() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    manager.create_task(&create("T-stored-time")).unwrap();
    let step = CreateStepExecution {
        attempt_id: "attempt-stored-time".to_owned(),
        task_id: "T-stored-time".to_owned(),
        semantic_program_hash: HASH.to_owned(),
        registry_snapshot_id: None,
        node_id: "node-time".to_owned(),
        binding_id: None,
        provider_id: None,
        provider_version: None,
        attempt_number: 1,
        state: StepState::Ready,
        operation_id: None,
        idempotency_key: None,
        outcome_certainty: Some(OutcomeCertainty::NotStarted),
        input_artifacts: vec![],
        output_artifacts: vec![],
        failure: None,
        started_at: None,
        finished_at: None,
    };
    manager.create_step_execution(&step).unwrap();
    manager.connection.execute(
        "UPDATE step_executions SET started_at='not-rfc3339' WHERE attempt_id='attempt-stored-time'", [],
    ).unwrap();
    assert!(manager.get_step_execution("attempt-stored-time").is_err());
    for migration in [
        "0001_v0_1_trusted_control_plane",
        "0002_task_manager_contract_reconciliation",
        "0003_task_manager_recovery_fencing_privacy",
        "0004_task_manager_review_hardening",
        "0005_artifact_store_root_binding",
        "0006_artifact_writer_admission",
        "0007_artifact_owner_export_context",
        "0008_artifact_export_reconciliation_challenge",
    ] {
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM schema_migrations WHERE migration_id=?1",
                    [migration],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }
}

#[test]
fn null_execution_certainty_blocks_runnable_running_and_completed() {
    for (name, source, target) in [
        ("runnable", TaskState::Planning, TaskState::Runnable),
        ("running", TaskState::Recovering, TaskState::Running),
        ("completed", TaskState::Verifying, TaskState::Completed),
    ] {
        let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
        seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
        manager
            .connection
            .execute(
                "UPDATE tasks SET state=?1 WHERE task_id='T-completion'",
                [source.as_str()],
            )
            .unwrap();
        manager.connection.execute(
            "UPDATE step_executions SET state='RUNNING', outcome_certainty=NULL WHERE attempt_id='attempt-completion'", [],
        ).unwrap();
        let result = manager
            .transition(&request(
                &format!("tr-null-certainty-{name}"),
                "T-completion",
                2,
                source,
                target,
            ))
            .unwrap();
        assert!(
            matches!(
                result.reason_code.as_str(),
                "TASK_UNKNOWN_EXTERNAL_OUTCOME" | "TASK_TRANSITION_GUARD_FAILED"
            ),
            "{name}"
        );
    }
}

#[test]
fn null_certainty_started_and_unknown_operations_block_execution_advancement() {
    for operation_state in ["STARTED", "UNKNOWN"] {
        for (name, source, target) in [
            ("runnable", TaskState::Planning, TaskState::Runnable),
            ("running", TaskState::Runnable, TaskState::Running),
            ("completed", TaskState::Verifying, TaskState::Completed),
        ] {
            let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
            seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
            manager
                .connection
                .execute(
                    "UPDATE tasks SET state=?1 WHERE task_id='T-completion'",
                    [source.as_str()],
                )
                .unwrap();
            if target != TaskState::Completed {
                manager
                    .connection
                    .execute(
                        "UPDATE step_executions SET state='READY', outcome_certainty='NOT_STARTED' WHERE attempt_id='attempt-completion'",
                        [],
                    )
                    .unwrap();
            }
            if target == TaskState::Running {
                manager.connection.execute(
                    "UPDATE artifact_output_allocations SET state='ALLOCATED', publication_id=NULL, published_artifact_id=NULL WHERE allocation_id='allocation-completion'",
                    [],
                ).unwrap();
            }
            manager.connection.execute(
                "INSERT INTO operations(operation_id,task_id,semantic_program_hash,node_id,effect_class,state,outcome_certainty,prepared_at) VALUES (?1,'T-completion',?2,'node-completion','NETWORK',?3,NULL,?4)",
                rusqlite::params![
                    format!("operation-null-{operation_state}-{name}"),
                    HASH,
                    operation_state,
                    TEST_TIME
                ],
            ).unwrap();

            let result = manager
                .transition(&request(
                    &format!("tr-operation-null-{operation_state}-{name}"),
                    "T-completion",
                    2,
                    source,
                    target,
                ))
                .unwrap();
            assert!(!result.applied, "{operation_state} -> {name}");
            assert_eq!(
                result.reason_code, "TASK_UNKNOWN_EXTERNAL_OUTCOME",
                "{operation_state} -> {name}"
            );
            let task = manager.get_task("T-completion").unwrap().unwrap();
            assert_eq!(task.state, source, "{operation_state} -> {name}");
            assert_eq!(task.revision, 2, "{operation_state} -> {name}");
        }
    }
}

#[test]
fn provider_admission_rejects_unrecognized_trust_and_nonpassing_conformance() {
    for (name, mutation, admitted) in [
        (
            "unknown-trust",
            "UPDATE provider_registrations SET trust_status='self-declared' WHERE registration_id='registration-completion'",
            false,
        ),
        (
            "nonpass-conformance",
            "UPDATE provider_conformance_evidence SET status='fail' WHERE evidence_id='evidence-completion'",
            false,
        ),
        (
            "organization-approved",
            "UPDATE provider_registrations SET trust_status='organization-approved' WHERE registration_id='registration-completion'",
            true,
        ),
    ] {
        let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
        seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
        align_completion_fixture_state(&mut manager, TaskState::Recovering);
        manager.connection.execute_batch(
            "UPDATE tasks SET state='RECOVERING', waiting_on_json='[]' WHERE task_id='T-completion';
             UPDATE step_executions SET state='READY', outcome_certainty='NOT_STARTED' WHERE attempt_id='attempt-completion';
             UPDATE artifact_output_allocations SET state='ALLOCATED', publication_id=NULL, published_artifact_id=NULL WHERE allocation_id='allocation-completion';
             DELETE FROM artifact_publications WHERE publication_id='publication-completion';",
        ).unwrap();
        seed_resolved_empty_recovery(&mut manager, "T-completion", 2);
        manager.connection.execute(mutation, []).unwrap();

        let result = manager
            .transition(&request(
                &format!("tr-provider-eligibility-{name}"),
                "T-completion",
                2,
                TaskState::Recovering,
                TaskState::Running,
            ))
            .unwrap();
        assert_eq!(result.applied, admitted, "{name}");
        if !admitted {
            assert_eq!(result.reason_code, "TASK_TRANSITION_GUARD_FAILED", "{name}");
        }
        let step = manager
            .get_step_execution("attempt-completion")
            .unwrap()
            .unwrap();
        assert_eq!(
            step.state,
            if admitted {
                StepState::Running
            } else {
                StepState::Ready
            },
            "{name}"
        );
        let task = manager.get_task("T-completion").unwrap().unwrap();
        assert_eq!(
            (task.state, task.revision),
            if admitted {
                (TaskState::Running, 3)
            } else {
                (TaskState::Recovering, 2)
            }
        );
    }
}

#[test]
fn completion_requires_present_durable_hash_matching_verified_blob() {
    for (name, mutation, expected_reason) in [
        (
            "blob-missing",
            "UPDATE artifact_blobs SET durability_state='MISSING' WHERE content_hash='sha256:4444444444444444444444444444444444444444444444444444444444444444'",
            "TASK_UNKNOWN_EXTERNAL_OUTCOME",
        ),
        (
            "integrity-failed",
            "UPDATE artifacts SET integrity_state='failed' WHERE artifact_id='artifact-output'",
            "TASK_UNKNOWN_EXTERNAL_OUTCOME",
        ),
        (
            "hash-mismatch",
            "UPDATE artifact_publications SET content_hash='sha256:mismatch' WHERE publication_id='publication-completion'",
            "TASK_UNKNOWN_EXTERNAL_OUTCOME",
        ),
    ] {
        let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
        seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
        if name == "hash-mismatch" {
            manager.connection.execute(
                "INSERT INTO artifact_blobs(content_hash,size_bytes,storage_ref,durability_state,created_at,verified_at) VALUES ('sha256:mismatch',42,'blob://mismatch','DURABLE',?1,?1)",
                [TEST_TIME],
            ).unwrap();
        }
        if name == "integrity-failed" {
            manager
                .connection
                .execute(
                    "UPDATE artifacts SET integrity_state='failed' WHERE artifact_id=?1",
                    [COMPLETION_ARTIFACT_ID],
                )
                .unwrap();
        } else {
            manager.connection.execute(mutation, []).unwrap();
        }
        assert_eq!(
            manager
                .transition(&completion_request(&format!("tr-blob-{name}")))
                .unwrap()
                .reason_code,
            expected_reason,
            "{name}"
        );
    }
    let mut success = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut success, HASH, &["artifact-output"], "COMMITTED");
    assert!(
        success
            .transition(&completion_request("tr-blob-success"))
            .unwrap()
            .applied
    );
}

#[test]
fn incomplete_credential_use_is_a_recovery_subject_and_blocks_containment() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    manager
        .create_task(&create("T-credential-recovery"))
        .unwrap();
    manager
        .connection
        .execute_batch("PRAGMA foreign_keys=OFF;")
        .unwrap();
    manager.connection.execute(
        "INSERT INTO credential_use_records(request_id,task_id,credential_id,execution_binding_id,authority_grant_id,principal_kind,principal_id,use_mode,status,request_json,requested_at) VALUES ('credential-use-pending','T-credential-recovery','credential:test','binding:test','grant:test','provider','provider:test','inject',NULL,'{}',?1)",
        [TEST_TIME],
    ).unwrap();
    manager.connection.execute(
        "INSERT INTO credential_use_records(request_id,task_id,credential_id,execution_binding_id,authority_grant_id,principal_kind,principal_id,use_mode,status,request_json,result_json,requested_at,completed_at) VALUES ('credential-use-unknown','T-credential-recovery','credential:test','binding:test','grant:test','provider','provider:test','inject','OUTCOME_UNKNOWN','{}','{}',?1,?1)",
        [TEST_TIME],
    ).unwrap();
    manager
        .connection
        .execute_batch("PRAGMA foreign_keys=ON;")
        .unwrap();
    let transaction = manager.connection.transaction().unwrap();
    assert_eq!(
        unresolved_execution_ids(&transaction, "T-credential-recovery").unwrap(),
        vec![
            "credential-use:credential-use-pending",
            "credential-use:credential-use-unknown"
        ]
    );
    let subjects = load_recovery_subjects(&transaction, "T-credential-recovery").unwrap();
    assert!(subjects.iter().any(|subject| {
        subject.id == "credential-use:credential-use-pending"
            && subject.evidence_kind == "credential-record"
            && subject.certainty == "OUTCOME_UNKNOWN"
            && subject.safe_action == "REQUIRE_EXTERNAL_RECONCILIATION"
    }));
    assert!(!execution_is_contained(&transaction, "T-credential-recovery").unwrap());
    drop(transaction);
    let operations = vec![
        "credential-use:credential-use-pending".to_owned(),
        "credential-use:credential-use-unknown".to_owned(),
    ];
    let recovery_ref = recovery_operations_ref("T-credential-recovery", 1, &operations).unwrap();
    manager
        .persist_recovery_inventory(
            &recovery_ref,
            "T-credential-recovery",
            1,
            &operations,
            TEST_TIME,
        )
        .unwrap();
    let assessment: Value = serde_json::from_str(
        &manager
            .connection
            .query_row(
                "SELECT assessment_json FROM recovery_assessments WHERE task_id='T-credential-recovery' AND subject_id='credential-use:credential-use-pending'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
    )
    .unwrap();
    let schema: Value = serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../specs/recovery-assessment.schema.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&assessment)
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "keeps forged and canonical terminal credential rows in one reopen recovery comparison"
)]
fn forged_terminal_credential_result_enters_startup_recovery_and_blocks_exit() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("credential-terminal-auth.sqlite3");
    {
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        seed_nonterminal_history(&mut manager, "T-credential-forged", TaskState::Paused);
        seed_nonterminal_history(&mut manager, "T-credential-wrong-type", TaskState::Paused);
        seed_nonterminal_history(
            &mut manager,
            "T-credential-duplicate-reasons",
            TaskState::Paused,
        );
        seed_nonterminal_history(&mut manager, "T-credential-canonical", TaskState::Paused);
        let forged_result = canonical_json(&serde_json::json!({
            "schema_version":SCHEMA_VERSION,
            "result_id":"credential-result-forged",
            "request_id":"credential-use-forged",
            "task_id":"T-attacker-controlled",
            "credential_handle_id":"credential://fixture",
            "status":"ALLOWED_AND_USED",
            "reason_codes":["CRED_USED"],
            "completed_at":TEST_TIME
        }))
        .unwrap();
        let wrong_type_result = canonical_json(&serde_json::json!({
            "schema_version":SCHEMA_VERSION,
            "result_id":"credential-result-wrong-type",
            "request_id":"credential-use-wrong-type",
            "task_id":"T-credential-wrong-type",
            "credential_handle_id":"credential://fixture",
            "status":"ALLOWED_AND_USED",
            "reason_codes":["CRED_USED"],
            "secret_exposed_to_provider":"false",
            "completed_at":TEST_TIME
        }))
        .unwrap();
        let duplicate_reasons_result = canonical_json(&serde_json::json!({
            "schema_version":SCHEMA_VERSION,
            "result_id":"credential-result-duplicate-reasons",
            "request_id":"credential-use-duplicate-reasons",
            "task_id":"T-credential-duplicate-reasons",
            "credential_handle_id":"credential://fixture",
            "status":"ALLOWED_AND_USED",
            "reason_codes":["CRED_USED","CRED_USED"],
            "completed_at":TEST_TIME
        }))
        .unwrap();
        let canonical_result = canonical_json(&serde_json::json!({
            "schema_version":SCHEMA_VERSION,
            "result_id":"credential-result-canonical",
            "request_id":"credential-use-canonical",
            "task_id":"T-credential-canonical",
            "credential_handle_id":"credential://fixture",
            "status":"ALLOWED_AND_USED",
            "reason_codes":["CRED_USED"],
            "completed_at":TEST_TIME
        }))
        .unwrap();
        manager
            .connection
            .execute_batch("PRAGMA foreign_keys=OFF;")
            .unwrap();
        for (request_id, result_id, task_id, result_json) in [
            (
                "credential-use-forged",
                "credential-result-forged",
                "T-credential-forged",
                forged_result,
            ),
            (
                "credential-use-wrong-type",
                "credential-result-wrong-type",
                "T-credential-wrong-type",
                wrong_type_result,
            ),
            (
                "credential-use-duplicate-reasons",
                "credential-result-duplicate-reasons",
                "T-credential-duplicate-reasons",
                duplicate_reasons_result,
            ),
            (
                "credential-use-canonical",
                "credential-result-canonical",
                "T-credential-canonical",
                canonical_result,
            ),
        ] {
            manager
                .connection
                .execute(
                    "INSERT INTO credential_use_records(
                    request_id,result_id,task_id,credential_id,execution_binding_id,
                    authority_grant_id,principal_kind,principal_id,use_mode,status,
                    request_json,result_json,requested_at,completed_at
                 ) VALUES (?1,?2,?3,'credential://fixture','binding:fixture','grant:fixture',
                    'provider','provider:fixture','inject','ALLOWED_AND_USED','{}',?4,?5,?5)",
                    rusqlite::params![request_id, result_id, task_id, result_json, TEST_TIME],
                )
                .unwrap();
        }
        manager
            .connection
            .execute_batch("PRAGMA foreign_keys=ON;")
            .unwrap();
        for (task_id, request_id) in [
            ("T-credential-forged", "credential-use-forged"),
            ("T-credential-wrong-type", "credential-use-wrong-type"),
            (
                "T-credential-duplicate-reasons",
                "credential-use-duplicate-reasons",
            ),
        ] {
            assert_eq!(
                unresolved_execution_ids(&manager.connection, task_id).unwrap(),
                vec![format!("credential-use:{request_id}")],
                "{task_id}"
            );
        }
        assert!(
            unresolved_execution_ids(&manager.connection, "T-credential-canonical")
                .unwrap()
                .is_empty()
        );
    }

    let mut reopened = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
    let canonical = reopened
        .get_task("T-credential-canonical")
        .unwrap()
        .unwrap();
    assert_eq!(canonical.state, TaskState::Paused);
    let forged_rows = [
        ("T-credential-forged", "credential-use-forged"),
        ("T-credential-wrong-type", "credential-use-wrong-type"),
        (
            "T-credential-duplicate-reasons",
            "credential-use-duplicate-reasons",
        ),
    ];
    for (task_id, request_id) in forged_rows {
        assert_eq!(
            reopened.get_task(task_id).unwrap().unwrap().state,
            TaskState::Recovering,
            "{task_id}"
        );
        let durable_inventory = query_strings(
            &reopened.connection,
            "SELECT inventory.operation_id
             FROM recovery_unknown_operations inventory
             JOIN recovery_assessments assessment
               ON assessment.assessment_id = inventory.assessment_id
             WHERE assessment.task_id=?1 AND assessment.subject_kind='task'
             ORDER BY inventory.ordinal",
            task_id,
        )
        .unwrap();
        assert_eq!(
            durable_inventory,
            vec![format!("credential-use:{request_id}")],
            "{task_id}"
        );
    }
    {
        let transaction = reopened.connection.transaction().unwrap();
        for (task_id, _) in forged_rows {
            assert!(!execution_is_contained(&transaction, task_id).unwrap());
        }
        assert!(execution_is_contained(&transaction, "T-credential-canonical").unwrap());
    }
    for (task_id, _) in forged_rows {
        let before = reopened.get_task(task_id).unwrap().unwrap();
        let rejected = reopened
            .transition(&request(
                &format!("tr-{task_id}-recovery-exit"),
                task_id,
                before.revision,
                TaskState::Recovering,
                TaskState::Planning,
            ))
            .unwrap();
        assert!(!rejected.applied, "{task_id}");
        assert_eq!(
            rejected.reason_code, "TASK_TRANSITION_GUARD_FAILED",
            "{task_id}"
        );
        let unchanged = reopened.get_task(task_id).unwrap().unwrap();
        assert_eq!(
            (unchanged.state, unchanged.revision),
            (TaskState::Recovering, before.revision),
            "{task_id}"
        );
    }
}

#[test]
fn ready_frontier_admits_only_eligible_attempt_and_records_exact_provenance() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
    align_completion_fixture_state(&mut manager, TaskState::Runnable);
    manager.connection.execute_batch(
        r"UPDATE tasks SET state='RUNNABLE' WHERE task_id='T-completion';
           UPDATE step_executions SET state='READY', outcome_certainty='NOT_STARTED' WHERE attempt_id='attempt-completion';
           UPDATE artifact_output_allocations SET state='ALLOCATED', publication_id=NULL, published_artifact_id=NULL WHERE allocation_id='allocation-completion';
           DELETE FROM artifact_publications WHERE publication_id='publication-completion';
           INSERT INTO step_executions(attempt_id,task_id,semantic_program_hash,registry_snapshot_id,node_id,attempt_number,revision,state,outcome_certainty,input_artifacts_json,output_artifacts_json,created_at,updated_at) VALUES ('attempt-later','T-completion','sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50','snapshot-completion','node-later',1,1,'PENDING','NOT_STARTED','[]','[]','2026-09-19T00:00:00Z','2026-09-19T00:00:00Z');",
    ).unwrap();
    let result = manager
        .transition(&request(
            "tr-frontier-running",
            "T-completion",
            2,
            TaskState::Runnable,
            TaskState::Running,
        ))
        .unwrap();
    assert!(result.applied);
    assert_eq!(
        manager
            .get_step_execution("attempt-completion")
            .unwrap()
            .unwrap()
            .state,
        StepState::Running
    );
    assert_eq!(
        manager
            .get_step_execution("attempt-later")
            .unwrap()
            .unwrap()
            .state,
        StepState::Pending
    );
    let event_json = manager.connection.query_row(
        "SELECT event_json FROM provenance_events WHERE task_id='T-completion' AND event_type='execution.started'",
        [],
        |row| row.get::<_, String>(0),
    ).unwrap();
    let event: Value = serde_json::from_str(&event_json).unwrap();
    let schema: Value = serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../specs/provenance-event.schema.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(jsonschema::validator_for(&schema).unwrap().is_valid(&event));
    assert_eq!(
        event.get("step_id").and_then(Value::as_str),
        Some("node-completion")
    );
    assert_eq!(
        event.pointer("/details/attempt_id").and_then(Value::as_str),
        Some("attempt-completion")
    );
    assert_eq!(
        event.pointer("/details/binding_id").and_then(Value::as_str),
        Some("binding-completion")
    );
    assert_ne!(
        attempt_admitted_event_id("a\0b", "c"),
        attempt_admitted_event_id("a", "b\0c")
    );
    assert_eq!(
        event.pointer("/details/node_id").and_then(Value::as_str),
        Some("node-completion")
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "builds a second immutable attempt with opaque IDs and checks public admission"
)]
fn ready_frontier_accepts_opaque_attempt_id_with_whitespace() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
    align_completion_fixture_state(&mut manager, TaskState::Runnable);
    manager
        .connection
        .execute_batch(
            r#"UPDATE tasks SET state='RUNNABLE' WHERE task_id='T-completion';
           INSERT INTO execution_bindings (
               binding_id, attempt_id, task_id, semantic_program_hash,
               registry_snapshot_id, ir_version, node_id, capability,
               capability_contract_hash, provider_registration_id,
               provider_id, provider_version, provider_manifest_hash,
               provider_build_hash, attempt, policy_decision_refs_json,
               grant_refs_json, execution_profile_ref, placement_json,
               binding_json, created_at
           )
           SELECT 'binding opaque 1', 'attempt 1', task_id, semantic_program_hash,
                  registry_snapshot_id, ir_version, node_id, capability,
                  capability_contract_hash, provider_registration_id,
                  provider_id, provider_version, provider_manifest_hash,
                  provider_build_hash, 2, policy_decision_refs_json,
                  grant_refs_json, execution_profile_ref, placement_json,
                  replace(replace(replace(replace(binding_json,
                      'attempt-completion', 'attempt 1'),
                      'binding-completion', 'binding opaque 1'),
                      'allocation-completion', 'allocation-opaque'),
                      '"attempt":1', '"attempt":2'),
                  created_at
           FROM execution_bindings WHERE binding_id='binding-completion';
           INSERT INTO step_executions (
               attempt_id, task_id, semantic_program_hash, registry_snapshot_id,
               node_id, binding_id, provider_id, provider_version, attempt_number,
               revision, state, outcome_certainty, input_artifacts_json,
               output_artifacts_json, created_at, updated_at
           )
           SELECT 'attempt 1', task_id, semantic_program_hash, registry_snapshot_id,
                  node_id, 'binding opaque 1', provider_id, provider_version, 2,
                  1, 'READY', 'NOT_STARTED', '[]', '[]', created_at, updated_at
           FROM step_executions WHERE attempt_id='attempt-completion';
           INSERT INTO artifact_output_allocations (
               allocation_id, task_id, semantic_program_hash, node_id,
               binding_id, attempt_id, output_port, expected_semantic_type,
               sensitivity, retention, state, created_at, expires_at
           )
           SELECT 'allocation-opaque', task_id, semantic_program_hash, node_id,
                  'binding opaque 1', 'attempt 1', output_port, expected_semantic_type,
                  sensitivity, retention, 'ALLOCATED', created_at, expires_at
           FROM artifact_output_allocations WHERE allocation_id='allocation-completion';"#,
        )
        .unwrap();

    let check_tx = manager.connection.transaction().unwrap();
    assert_eq!(
        count_active_steps(
            &check_tx,
            "T-completion",
            &["node-completion".to_owned()],
            "READY"
        )
        .unwrap(),
        1
    );
    let binding_check = BindingGrantCheck {
        task_id: "T-completion",
        semantic_hash: HASH,
        node_id: "node-completion",
        binding_id: "binding opaque 1",
        attempt_id: "attempt 1",
        grant_refs_json: "[]",
        checked_at: TEST_TIME,
    };
    assert!(
        binding_grants_valid(&check_tx, &binding_check).unwrap(),
        "binding grants"
    );
    assert!(
        output_allocations_ready(&check_tx, &binding_check).unwrap(),
        "allocations"
    );
    assert_eq!(
        count_bound_active_steps(
            &check_tx,
            "T-completion",
            &["node-completion".to_owned()],
            &["READY"],
            TEST_TIME
        )
        .unwrap(),
        1
    );
    check_tx.rollback().unwrap();

    let result = manager
        .transition(&request(
            "tr-opaque-attempt-running",
            "T-completion",
            2,
            TaskState::Runnable,
            TaskState::Running,
        ))
        .unwrap();
    assert!(result.applied, "{result:?}");
    assert_eq!(
        manager
            .get_step_execution("attempt 1")
            .unwrap()
            .unwrap()
            .state,
        StepState::Running
    );
    let event_json: String = manager.connection.query_row(
        "SELECT event_json FROM provenance_events WHERE task_id='T-completion' AND event_type='execution.started'",
        [],
        |row| row.get(0),
    ).unwrap();
    let event: Value = serde_json::from_str(&event_json).unwrap();
    assert_eq!(
        event.pointer("/details/attempt_id"),
        Some(&json!("attempt 1"))
    );
    assert!(manager.verify_provenance("T-completion").unwrap());
}

#[test]
fn recovery_inventory_provenance_accepts_prefixed_maximum_attempt_id() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    manager.create_task(&create("T-opaque-recovery")).unwrap();
    let full_attempt = "a".repeat(256);
    let inventory_id = recovery_subject_inventory_id("attempt", &full_attempt).unwrap();
    assert_eq!(inventory_id.chars().count(), 264);

    let event = json!({
        "schema_version": SCHEMA_VERSION,
        "event_id": "event:opaque-recovery",
        "task_id": "T-opaque-recovery",
        "event_type": "execution.completed",
        "timestamp": TEST_TIME,
        "actor": {"kind": "system-service", "id": "service:recovery"},
        "status": "success",
        "details": {"inventory_id": inventory_id}
    });
    let transaction = manager.connection.transaction().unwrap();
    append_event(&transaction, "T-opaque-recovery", &event).unwrap();
    transaction.commit().unwrap();
    assert!(manager.verify_provenance("T-opaque-recovery").unwrap());

    let mut over_bound = event.clone();
    over_bound["event_id"] = json!("event:over-bound-recovery");
    over_bound["details"]["inventory_id"] =
        json!("provider-invocation:".to_owned() + &"a".repeat(257));
    let transaction = manager.connection.transaction().unwrap();
    assert!(append_event(&transaction, "T-opaque-recovery", &over_bound).is_err());
    transaction.rollback().unwrap();
    assert_eq!(manager.provenance_count("T-opaque-recovery").unwrap(), 2);
}

#[test]
fn historical_recovery_inventory_can_exit_only_after_affirmative_resolution() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
    align_completion_fixture_state(&mut manager, TaskState::Running);
    manager.connection.execute_batch(
        "UPDATE tasks SET state='RUNNING' WHERE task_id='T-completion';
         INSERT INTO operations(operation_id,task_id,semantic_program_hash,node_id,effect_class,state,outcome_certainty,prepared_at,started_at) VALUES ('operation-resolve','T-completion','sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50','node-completion','NETWORK','STARTED','OUTCOME_UNKNOWN','2026-09-19T00:00:00Z','2026-09-19T00:00:00Z');",
    ).unwrap();
    assert!(
        manager
            .reconcile_live_execution("T-completion")
            .unwrap()
            .applied
    );
    let blocked = manager
        .transition(&request(
            "tr-recovery-still-unknown",
            "T-completion",
            3,
            TaskState::Recovering,
            TaskState::Planning,
        ))
        .unwrap();
    assert!(!blocked.applied);
    manager.connection.execute(
        "UPDATE operations SET state='SUCCEEDED', outcome_certainty='COMPLETED', finished_at=?1 WHERE operation_id='operation-resolve'",
        [TEST_TIME],
    ).unwrap();
    let recovery_ref = manager
        .get_task("T-completion")
        .unwrap()
        .unwrap()
        .recovery
        .unwrap()["unknown_operations_ref"]
        .as_str()
        .unwrap()
        .to_owned();
    manager
        .reconcile_recovery_subject(&recovery_ref, "operation:operation-resolve")
        .unwrap();
    let resolved = manager
        .transition(&request(
            "tr-recovery-resolved",
            "T-completion",
            3,
            TaskState::Recovering,
            TaskState::Planning,
        ))
        .unwrap();
    assert!(resolved.applied);
}

#[test]
fn verifying_requires_exact_durable_candidate_outputs_for_every_active_port() {
    for (name, mutation, applies) in [
        ("complete", "SELECT 1", true),
        (
            "self-report-only",
            "UPDATE step_executions SET output_artifacts_json='[\"invented\"]'; UPDATE artifact_output_allocations SET output_port='wrong'",
            false,
        ),
        (
            "missing-artifact",
            "DELETE FROM task_artifacts WHERE artifact_id='artifact-output'",
            false,
        ),
    ] {
        let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
        seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
        align_completion_fixture_state(&mut manager, TaskState::Running);
        manager
            .connection
            .execute(
                "UPDATE tasks SET state='RUNNING' WHERE task_id='T-completion'",
                [],
            )
            .unwrap();
        if name == "missing-artifact" {
            manager
                .connection
                .execute(
                    "DELETE FROM task_artifacts WHERE artifact_id=?1",
                    [COMPLETION_ARTIFACT_ID],
                )
                .unwrap();
        } else {
            manager.connection.execute_batch(mutation).unwrap();
        }
        let result = manager
            .transition(&request(
                &format!("tr-verifying-output-{name}"),
                "T-completion",
                2,
                TaskState::Running,
                TaskState::Verifying,
            ))
            .unwrap();
        assert_eq!(result.applied, applies, "{name}");
        if !applies {
            let task = manager.get_task("T-completion").unwrap().unwrap();
            assert_eq!((task.state, task.revision), (TaskState::Running, 2));
        }
    }

    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
    align_completion_fixture_state(&mut manager, TaskState::Running);
    manager.connection.execute_batch(
        r#"UPDATE semantic_program_revisions SET program_json='{"nodes":[{"id":"node-completion","operation":{"kind":"invoke","capability":"test.complete@1"},"outputs":{"report":"artifact.report@1"},"authority_requests":[]},{"id":"node-later","operation":{"kind":"invoke","capability":"test.complete@1"},"outputs":{"later":"artifact.report@1"},"authority_requests":[]}]}' WHERE task_id='T-completion';
           UPDATE tasks SET state='RUNNING', active_step_ids_json='["node-completion","node-later"]' WHERE task_id='T-completion';
           INSERT INTO step_executions(attempt_id,task_id,semantic_program_hash,registry_snapshot_id,node_id,attempt_number,revision,state,outcome_certainty,input_artifacts_json,output_artifacts_json,created_at,updated_at) VALUES ('attempt-later','T-completion','sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50','snapshot-completion','node-later',1,1,'RUNNING',NULL,'[]','["artifact-does-not-exist"]','2026-09-19T00:00:00Z','2026-09-19T00:00:00Z');"#,
    ).unwrap();
    let result = manager
        .transition(&request(
            "tr-verifying-multi-node-incomplete",
            "T-completion",
            2,
            TaskState::Running,
            TaskState::Verifying,
        ))
        .unwrap();
    assert!(!result.applied);
    assert_eq!(
        manager.get_task("T-completion").unwrap().unwrap().state,
        TaskState::Running
    );
}

#[test]
fn queued_not_started_attempts_do_not_prevent_pausing_or_replanning() {
    for state in ["PENDING", "BLOCKED", "READY"] {
        let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
        seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
        align_completion_fixture_state(&mut manager, TaskState::Paused);
        manager
            .connection
            .execute(
                "UPDATE tasks SET state='PAUSED' WHERE task_id='T-completion'",
                [],
            )
            .unwrap();
        manager.connection.execute(
            "UPDATE step_executions SET state=?1, outcome_certainty='NOT_STARTED' WHERE attempt_id='attempt-completion'",
            [state],
        ).unwrap();
        let transaction = manager.connection.transaction().unwrap();
        assert!(
            execution_is_contained(&transaction, "T-completion").unwrap(),
            "{state}"
        );
        transaction.rollback().unwrap();
        assert!(
            manager
                .transition(&request(
                    &format!("tr-queued-{state}"),
                    "T-completion",
                    2,
                    TaskState::Paused,
                    TaskState::Planning,
                ))
                .unwrap()
                .applied,
            "{state}"
        );
    }
}

#[cfg(unix)]
#[test]
fn locked_store_identity_rejects_path_retarget_before_connection_use() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("identity.sqlite3");
    let original = directory.path().join("original.sqlite3");
    assert!(
        open_locked_store(&path, Box::new(FixedClock), Vec::new(), |locked_path| {
            std::fs::rename(locked_path, &original).unwrap();
            OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(locked_path)
                .unwrap();
        })
        .is_err()
    );
}

#[cfg(unix)]
#[test]
fn locked_store_identity_checks_sqlite_main_after_path_swap_back() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().unwrap();
    let original = directory.path().join("identity-original.sqlite3");
    let alternate = directory.path().join("identity-alternate.sqlite3");
    let path = directory.path().join("identity-link.sqlite3");
    Connection::open(&original)
        .unwrap()
        .execute_batch("CREATE TABLE original_marker(value TEXT);")
        .unwrap();
    Connection::open(&alternate)
        .unwrap()
        .execute_batch("CREATE TABLE alternate_marker(value TEXT);")
        .unwrap();
    symlink(&original, &path).unwrap();
    let lock = acquire_store_lock(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    symlink(&alternate, &path).unwrap();
    let connection = Connection::open(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    symlink(&original, &path).unwrap();
    assert!(verify_locked_store_identity(&connection, &lock).is_err());
}

#[cfg(windows)]
#[test]
fn windows_store_identity_rejects_replacement_with_preserved_creation_time() {
    use std::os::windows::fs::MetadataExt as _;

    let directory = tempdir().unwrap();
    let path = directory.path().join("identity.sqlite3");
    let displaced = directory.path().join("identity-original.sqlite3");
    std::fs::write(&path, b"original").unwrap();
    let original_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let original_creation_time = original_file.metadata().unwrap().creation_time();
    let original_identity = store_identity(&path, &original_file).unwrap();
    drop(original_file);

    std::fs::rename(&path, &displaced).unwrap();
    std::fs::write(&path, b"replacement").unwrap();
    let creation_time_argument = original_creation_time.to_string();
    let status = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "& { param($path,$ticks) [System.IO.File]::SetCreationTimeUtc($path,[DateTime]::FromFileTimeUtc([Int64]$ticks)) }",
            path.to_str().unwrap(),
            &creation_time_argument,
        ])
        .status()
        .unwrap();
    assert!(status.success());
    let replacement_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    assert_eq!(
        replacement_file.metadata().unwrap().creation_time(),
        original_creation_time
    );
    let replacement_identity = store_identity(&path, &replacement_file).unwrap();
    assert_ne!(original_identity, replacement_identity);
}

#[test]
fn mutation_provenance_excludes_free_form_waiting_and_failure_text() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    manager.create_task(&create("T-private-mutation")).unwrap();
    assert!(
        manager
            .transition(&request(
                "tr-private-planning",
                "T-private-mutation",
                1,
                TaskState::Created,
                TaskState::Planning,
            ))
            .unwrap()
            .applied
    );
    let mut waiting = request(
        "tr-private-waiting",
        "T-private-mutation",
        2,
        TaskState::Planning,
        TaskState::WaitingForInput,
    );
    waiting.mutation.waiting_on = Some(vec![WaitingOn {
        kind: WaitingKind::Input,
        id: "input:private".to_owned(),
        message: Some("private waiting explanation".to_owned()),
    }]);
    assert!(manager.transition(&waiting).unwrap().applied);
    let mut failed = request(
        "tr-private-failure",
        "T-private-mutation",
        3,
        TaskState::WaitingForInput,
        TaskState::Failed,
    );
    failed.mutation.failure.as_mut().unwrap().summary = "private failure summary".to_owned();
    assert!(manager.transition(&failed).unwrap().applied);
    let events = query_strings(
        &manager.connection,
        "SELECT event_json FROM provenance_events WHERE task_id=?1 ORDER BY sequence",
        "T-private-mutation",
    )
    .unwrap()
    .join("\n");
    assert!(!events.contains("private waiting explanation"));
    assert!(!events.contains("private failure summary"));
    assert!(events.contains("task-field-commitment"));
}

#[test]
fn exact_retry_rejects_forged_stored_result_receipt() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    manager.create_task(&create("T-result-auth")).unwrap();
    let transition = request(
        "tr-result-auth",
        "T-result-auth",
        1,
        TaskState::Created,
        TaskState::Planning,
    );
    assert!(manager.transition(&transition).unwrap().applied);
    let result_json = manager
        .connection
        .query_row(
            "SELECT result_json FROM task_transitions WHERE transition_id='tr-result-auth'",
            [],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
    let mut forged: Value = serde_json::from_str(&result_json).unwrap();
    forged["current_revision"] = json!(999);
    manager
        .connection
        .execute(
            "UPDATE task_transitions SET result_json=?1 WHERE transition_id='tr-result-auth'",
            [forged.to_string()],
        )
        .unwrap();
    assert!(manager.transition(&transition).is_err());
    let task = manager.get_task("T-result-auth").unwrap().unwrap();
    assert_eq!((task.state, task.revision), (TaskState::Planning, 2));

    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    manager.create_task(&create("T-request-auth")).unwrap();
    let transition = request(
        "tr-request-auth",
        "T-request-auth",
        1,
        TaskState::Created,
        TaskState::Planning,
    );
    assert!(manager.transition(&transition).unwrap().applied);
    let mut forged_request = serde_json::to_value(&transition).unwrap();
    forged_request["requested_by"]["id"] = json!("user:forged");
    let forged_request_json = canonical_json(&forged_request).unwrap();
    manager
        .connection
        .execute(
            "UPDATE task_transitions SET request_json=?1 WHERE transition_id='tr-request-auth'",
            [&forged_request_json],
        )
        .unwrap();
    let forged_request: TransitionRequest = serde_json::from_value(forged_request).unwrap();
    assert!(manager.transition(&forged_request).is_err());
}

#[test]
fn upgraded_recovery_basis_is_backfilled_and_trigger_enforced() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("basis-upgrade.sqlite3");
    {
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        manager.create_task(&create("T-basis-upgrade")).unwrap();
    }
    let connection = Connection::open(&path).unwrap();
    connection.execute_batch(
        "PRAGMA foreign_keys=OFF;
         DROP TRIGGER recovery_assessments_basis_insert;
         DROP TRIGGER recovery_assessments_basis_update;
         ALTER TABLE recovery_assessments RENAME TO recovery_assessments_strict;
         CREATE TABLE recovery_assessments(assessment_id TEXT PRIMARY KEY,recovery_epoch_id TEXT NOT NULL,task_id TEXT NOT NULL,basis_revision INTEGER,subject_kind TEXT NOT NULL,subject_id TEXT NOT NULL,certainty TEXT NOT NULL,safe_action TEXT NOT NULL,reason_codes_json TEXT NOT NULL,assessment_json TEXT NOT NULL,created_at TEXT NOT NULL);
         INSERT INTO recovery_epochs(recovery_epoch_id,started_at) VALUES ('epoch:basis','2026-09-19T00:00:00Z');
         INSERT INTO recovery_assessments VALUES ('assessment:basis','epoch:basis','T-basis-upgrade',NULL,'task','T-basis-upgrade','OUTCOME_UNKNOWN','REQUIRE_EXTERNAL_RECONCILIATION','[]','{}','2026-09-19T00:00:00Z');
         DROP TABLE recovery_assessments_strict;
         DELETE FROM schema_migrations WHERE migration_id='0004_task_manager_review_hardening';",
    ).unwrap();
    drop(connection);
    let manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
    assert_eq!(manager.connection.query_row(
        "SELECT basis_revision FROM recovery_assessments WHERE assessment_id='assessment:basis'",
        [],
        |row| row.get::<_, i64>(0),
    ).unwrap(), 1);
    assert!(manager.connection.execute(
        "UPDATE recovery_assessments SET basis_revision=0 WHERE assessment_id='assessment:basis'",
        [],
    ).is_err());
}

#[test]
fn artifact_writer_admission_columns_are_added_by_the_ordered_migration() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("writer-admission-upgrade.sqlite3");
    drop(TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap());
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "ALTER TABLE artifact_output_allocations DROP COLUMN writer_grant_one_shot_consumed;
             ALTER TABLE artifact_output_allocations DROP COLUMN writer_grant_id;
             DELETE FROM schema_migrations WHERE migration_id='0006_artifact_writer_admission';",
        )
        .unwrap();
    drop(connection);

    let manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
    assert!(
        table_has_column(
            &manager.connection,
            "artifact_output_allocations",
            "writer_grant_id"
        )
        .unwrap()
    );
    assert!(
        table_has_column(
            &manager.connection,
            "artifact_output_allocations",
            "writer_grant_one_shot_consumed"
        )
        .unwrap()
    );
    assert_eq!(
        manager
            .connection
            .query_row(
                "SELECT checksum FROM schema_migrations WHERE migration_id='0006_artifact_writer_admission'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "artifact-writer-admission-v0.1"
    );
}

#[test]
fn artifact_writer_session_fencing_columns_are_added_by_the_ordered_migration() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("writer-session-upgrade.sqlite3");
    drop(TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap());
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "ALTER TABLE artifact_output_allocations DROP COLUMN writer_session_id;
             ALTER TABLE artifact_output_allocations DROP COLUMN writer_generation;
             DELETE FROM schema_migrations WHERE migration_id='0009_artifact_writer_session_fencing';",
        )
        .unwrap();
    drop(connection);

    let manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
    assert!(
        table_has_column(
            &manager.connection,
            "artifact_output_allocations",
            "writer_session_id"
        )
        .unwrap()
    );
    assert!(
        table_has_column(
            &manager.connection,
            "artifact_output_allocations",
            "writer_generation"
        )
        .unwrap()
    );
    assert_eq!(
        manager
            .connection
            .query_row(
                "SELECT checksum FROM schema_migrations WHERE migration_id='0009_artifact_writer_session_fencing'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "artifact-writer-session-fencing-v0.1"
    );
}

#[test]
fn export_reconciliation_challenge_migration_is_ordered_and_fail_closed() {
    let directory = tempdir().unwrap();
    let upgrade = directory.path().join("challenge-upgrade.sqlite3");
    drop(TaskManager::open_with_clock(&upgrade, Box::new(FixedClock)).unwrap());
    let connection = Connection::open(&upgrade).unwrap();
    connection
        .execute_batch(
            "DROP TABLE artifact_export_reconciliation_challenges;
             DELETE FROM schema_migrations
             WHERE migration_id='0008_artifact_export_reconciliation_challenge';",
        )
        .unwrap();
    drop(connection);
    let manager = TaskManager::open_with_clock(&upgrade, Box::new(FixedClock)).unwrap();
    assert_eq!(
        manager
            .connection
            .query_row(
                "SELECT (SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='artifact_export_reconciliation_challenges') || ':' ||
                        (SELECT COUNT(*) FROM schema_migrations WHERE migration_id='0008_artifact_export_reconciliation_challenge' AND checksum='artifact-export-reconciliation-challenge-v0.1')",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "1:1"
    );
    drop(manager);

    let stamped = directory.path().join("challenge-stamped-missing.sqlite3");
    drop(TaskManager::open_with_clock(&stamped, Box::new(FixedClock)).unwrap());
    let connection = Connection::open(&stamped).unwrap();
    connection
        .execute_batch("DROP TABLE artifact_export_reconciliation_challenges;")
        .unwrap();
    drop(connection);
    assert!(TaskManager::open_with_clock(&stamped, Box::new(FixedClock)).is_err());

    let base_upgrade = directory.path().join("challenge-base-upgrade.sqlite3");
    drop(TaskManager::open_with_clock(&base_upgrade, Box::new(FixedClock)).unwrap());
    let connection = Connection::open(&base_upgrade).unwrap();
    connection.execute_batch(
        "PRAGMA foreign_keys=OFF;
         DROP TABLE artifact_export_reconciliation_challenges;
         DROP TABLE operations;
         CREATE TABLE operations (
             operation_id TEXT PRIMARY KEY,
             task_id TEXT NOT NULL,
             semantic_program_hash TEXT NOT NULL,
             node_id TEXT NOT NULL,
             binding_id TEXT,
             attempt_id TEXT,
             transaction_class TEXT,
             effect_class TEXT NOT NULL,
             idempotency_key TEXT,
             state TEXT NOT NULL,
             outcome_certainty TEXT,
             external_receipt TEXT,
             details_json TEXT,
             prepared_at TEXT NOT NULL,
             started_at TEXT,
             finished_at TEXT
         );
         CREATE TABLE artifact_export_reconciliation_challenges (
             operation_id TEXT PRIMARY KEY,
             recovery_assessment_id TEXT NOT NULL,
             subject_hash TEXT NOT NULL,
             challenge TEXT NOT NULL UNIQUE,
             issued_at TEXT NOT NULL,
             FOREIGN KEY (operation_id) REFERENCES operations(operation_id) ON DELETE CASCADE,
             FOREIGN KEY (recovery_assessment_id) REFERENCES recovery_assessments(assessment_id)
         );
         DELETE FROM schema_migrations
          WHERE migration_id IN ('0007_artifact_owner_export_context','0008_artifact_export_reconciliation_challenge');",
    ).unwrap();
    drop(connection);

    let upgraded = TaskManager::open_with_clock(&base_upgrade, Box::new(FixedClock)).unwrap();
    let foreign_targets = {
        let mut statement = upgraded
            .connection
            .prepare("PRAGMA foreign_key_list(artifact_export_reconciliation_challenges)")
            .unwrap();
        let rows = statement
            .query_map([], |row| row.get::<_, String>(2))
            .unwrap();
        rows.collect::<std::result::Result<Vec<_>, _>>().unwrap()
    };
    assert!(foreign_targets.iter().any(|target| target == "operations"));
    assert!(
        !foreign_targets
            .iter()
            .any(|target| target == "operations_legacy")
    );
    assert_eq!(
        upgraded
            .connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_foreign_key_check('artifact_export_reconciliation_challenges')",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
}

#[test]
fn proposed_active_steps_scope_initial_waiting_for_auth_lookup() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
    align_completion_fixture_state(&mut manager, TaskState::Planning);
    manager.connection.execute_batch(
        "UPDATE tasks SET state='PLANNING', active_step_ids_json='[]' WHERE task_id='T-completion';
         INSERT INTO authority_requests(request_id,task_id,semantic_program_hash,registry_snapshot_id,node_id,capability,principal_kind,principal_id,action,resolved_resource_kind,resolved_resource_id,request_json,requested_at) VALUES ('authority-proposed','T-completion','sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50','snapshot-completion','node-completion','test.complete@1','user','user:adversarial','test.approve','artifact','artifact:one','{}','2026-09-19T00:00:00Z');
         INSERT INTO approval_requests(approval_id,authority_request_id,task_id,semantic_program_hash,node_id,action,status,request_json,created_at,expires_at) VALUES ('approval-proposed','authority-proposed','T-completion','sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50','node-completion','test.approve','PENDING','{}','2026-09-19T00:00:00Z','2026-09-20T00:00:00Z');",
    ).unwrap();
    let mut transition = request(
        "tr-proposed-auth",
        "T-completion",
        2,
        TaskState::Planning,
        TaskState::WaitingForAuth,
    );
    transition.mutation.active_step_ids = Some(vec!["node-completion".to_owned()]);
    transition.mutation.waiting_on = Some(vec![WaitingOn {
        kind: WaitingKind::Approval,
        id: "approval-proposed".to_owned(),
        message: None,
    }]);
    assert!(manager.transition(&transition).unwrap().applied);
}

#[test]
fn completion_authenticates_verification_event_row_and_chain() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
    manager.connection.execute_batch(
        "DROP TRIGGER provenance_events_no_update;
         UPDATE provenance_events SET event_hash='sha256:forged' WHERE task_id='T-completion' AND event_type='verification.completed';",
    ).unwrap();
    let result = manager
        .transition(&completion_request("tr-verification-row-forged"))
        .unwrap();
    assert!(!result.applied);
    assert_eq!(result.reason_code, "TASK_UNKNOWN_EXTERNAL_OUTCOME");
}

#[test]
fn unicode_identifier_limits_count_scalars_instead_of_utf8_bytes() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    let max_id = "é".repeat(256);
    let too_long = "é".repeat(257);
    manager.create_task(&create(&max_id)).unwrap();
    assert!(manager.create_task(&create(&too_long)).is_err());
    let transition = request(
        &"界".repeat(256),
        &max_id,
        1,
        TaskState::Created,
        TaskState::Planning,
    );
    assert!(manager.transition(&transition).unwrap().applied);
    let step = CreateStepExecution {
        attempt_id: "🙂".repeat(256),
        task_id: max_id,
        semantic_program_hash: HASH.to_owned(),
        registry_snapshot_id: None,
        node_id: "node-unicode".to_owned(),
        binding_id: None,
        provider_id: None,
        provider_version: None,
        attempt_number: 1,
        state: StepState::Ready,
        operation_id: None,
        idempotency_key: None,
        outcome_certainty: Some(OutcomeCertainty::NotStarted),
        input_artifacts: vec![],
        output_artifacts: vec![],
        failure: None,
        started_at: None,
        finished_at: None,
    };
    manager.create_step_execution(&step).unwrap();
    let mut over = step;
    over.attempt_id = "🙂".repeat(257);
    over.attempt_number = 2;
    assert!(manager.create_step_execution(&over).is_err());
}

#[test]
fn clean_nonterminal_execution_states_do_not_enter_empty_startup_recovery() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    for (task_id, state) in [
        ("T-runnable-clean", TaskState::Runnable),
        ("T-running-clean", TaskState::Running),
        ("T-verifying-clean", TaskState::Verifying),
        ("T-paused-clean", TaskState::Paused),
        ("T-waiting-input-clean", TaskState::WaitingForInput),
        ("T-waiting-auth-clean", TaskState::WaitingForAuth),
    ] {
        seed_nonterminal_history(&mut manager, task_id, state);
    }
    assert!(manager.recover_startup().unwrap().is_empty());
    for (task_id, state) in [
        ("T-runnable-clean", TaskState::Runnable),
        ("T-running-clean", TaskState::Running),
        ("T-verifying-clean", TaskState::Verifying),
        ("T-paused-clean", TaskState::Paused),
        ("T-waiting-input-clean", TaskState::WaitingForInput),
        ("T-waiting-auth-clean", TaskState::WaitingForAuth),
    ] {
        assert_eq!(manager.get_task(task_id).unwrap().unwrap().state, state);
    }
}

#[test]
fn startup_quarantines_legacy_runnable_and_waiting_states_with_live_work() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("legacy-waiting-recovery.sqlite3");
    let candidates = [
        ("T-runnable-live", TaskState::Runnable),
        ("T-waiting-input-live", TaskState::WaitingForInput),
        ("T-waiting-auth-live", TaskState::WaitingForAuth),
    ];
    {
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        for (task_id, state) in candidates {
            seed_nonterminal_history(&mut manager, task_id, state);
            manager.connection.execute(
                "INSERT INTO operations(operation_id,task_id,semantic_program_hash,node_id,effect_class,state,outcome_certainty,prepared_at)
                 VALUES (?1,?2,?3,'node-live','NETWORK','STARTED',NULL,?4)",
                rusqlite::params![format!("operation-{task_id}"), task_id, HASH, TEST_TIME],
            ).unwrap();
        }
    }
    assert!(TaskManager::open_with_clock(&path, Box::new(FixedClock)).is_err());
    let connection = Connection::open(&path).unwrap();
    for (task_id, state) in candidates {
        let stored_state: String = connection
            .query_row(
                "SELECT state FROM tasks WHERE task_id=?1",
                [task_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored_state, state.as_str(), "{task_id}");
        assert_eq!(
            unresolved_execution_ids(&connection, task_id).unwrap(),
            vec![format!("operation:operation-{task_id}")],
            "{task_id}"
        );
    }
}

#[test]
fn prepared_operations_have_typed_collision_free_recovery_subjects() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    manager.create_task(&create("T-operation-prefix")).unwrap();
    manager.connection.execute_batch(
        "INSERT INTO operations(operation_id,task_id,semantic_program_hash,node_id,effect_class,state,prepared_at) VALUES ('attempt:same','T-operation-prefix','sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50','node','NETWORK','PREPARED','2026-09-19T00:00:00Z');
         INSERT INTO step_executions(attempt_id,task_id,semantic_program_hash,node_id,attempt_number,revision,state,outcome_certainty,input_artifacts_json,output_artifacts_json,created_at,updated_at) VALUES ('same','T-operation-prefix','sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50','node',1,1,'RUNNING','OUTCOME_UNKNOWN','[]','[]','2026-09-19T00:00:00Z','2026-09-19T00:00:00Z');",
    ).unwrap();
    let inventory = unresolved_execution_ids(&manager.connection, "T-operation-prefix").unwrap();
    assert_eq!(inventory, vec!["attempt:same", "operation:attempt:same"]);
    let transaction = manager.connection.transaction().unwrap();
    let subjects = load_recovery_subjects(&transaction, "T-operation-prefix").unwrap();
    let prepared = subjects
        .iter()
        .find(|subject| subject.id == "operation:attempt:same")
        .unwrap();
    assert_eq!(prepared.certainty, "NOT_STARTED");
    assert_eq!(prepared.safe_action, "CREATE_NEW_ATTEMPT");
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "keeps response-loss replay and both machine-schema validations in one recovery scenario"
)]
fn recovery_exit_requires_a_provenance_backed_resolution_assessment() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    let revision = seed_recovering_history(&mut manager, "T-recovery-auth");
    manager.connection.execute_batch(
        "INSERT INTO operations(operation_id,task_id,semantic_program_hash,node_id,effect_class,state,outcome_certainty,prepared_at) VALUES ('op','T-recovery-auth','sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50','node','NETWORK','UNKNOWN','OUTCOME_UNKNOWN','2026-09-19T00:00:00Z');",
    ).unwrap();
    let inventory = unresolved_execution_ids(&manager.connection, "T-recovery-auth").unwrap();
    let recovery_ref = recovery_operations_ref("T-recovery-auth", revision, &inventory).unwrap();
    manager
        .persist_recovery_inventory(
            &recovery_ref,
            "T-recovery-auth",
            revision,
            &inventory,
            TEST_TIME,
        )
        .unwrap();
    manager.connection.execute(
        "UPDATE tasks SET state='RECOVERING', recovery_json=?2 WHERE task_id=?1",
        rusqlite::params!["T-recovery-auth", serde_json::json!({"unknown_operations_ref":recovery_ref,"last_known_daemon_instance":null}).to_string()],
    ).unwrap();
    manager.connection.execute(
        "UPDATE operations SET state='SUCCEEDED',outcome_certainty='COMPLETED' WHERE operation_id='op'",
        [],
    ).unwrap();
    assert!(
        !manager
            .transition(&request(
                "tr-untrusted-resolution",
                "T-recovery-auth",
                revision,
                TaskState::Recovering,
                TaskState::Planning
            ))
            .unwrap()
            .applied
    );
    manager
        .reconcile_recovery_subject(&recovery_ref, "operation:op")
        .unwrap();
    manager
        .reconcile_recovery_subject(&recovery_ref, "operation:op")
        .unwrap();
    assert_eq!(
        manager
            .connection
            .query_row(
                "SELECT COUNT(*) FROM provenance_events WHERE event_id=?1",
                [recovery_resolution_event_id(&recovery_ref, "operation:op")],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    let resolution_event: Value = serde_json::from_str(
        &manager
            .connection
            .query_row(
                "SELECT event_json FROM provenance_events WHERE event_id=?1",
                [recovery_resolution_event_id(&recovery_ref, "operation:op")],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
    )
    .unwrap();
    let event_schema: Value = serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../specs/provenance-event.schema.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        jsonschema::validator_for(&event_schema)
            .unwrap()
            .is_valid(&resolution_event)
    );
    let assessment: Value = serde_json::from_str(&manager.connection.query_row(
        "SELECT assessment_json FROM recovery_assessments WHERE task_id='T-recovery-auth' AND subject_kind='external-operation'",
        [], |row| row.get::<_,String>(0)).unwrap()).unwrap();
    let assessment_schema: Value = serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../specs/recovery-assessment.schema.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        jsonschema::validator_for(&assessment_schema)
            .unwrap()
            .is_valid(&assessment)
    );
    assert_eq!(
        assessment
            .pointer("/evidence/0/kind")
            .and_then(Value::as_str),
        Some("provenance")
    );
    assert!(
        manager
            .transition(&request(
                "tr-trusted-resolution",
                "T-recovery-auth",
                revision,
                TaskState::Recovering,
                TaskState::Planning
            ))
            .unwrap()
            .applied
    );
}

#[test]
fn recovery_resolution_reader_rejects_duplicate_stored_event_keys() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    let task_id = "T-duplicate-recovery-event";
    manager.create_task(&create(task_id)).unwrap();
    let (event_id, event_json): (String, String) = manager
        .connection
        .query_row(
            "SELECT event_id,event_json FROM provenance_events WHERE task_id=?1",
            [task_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let duplicate_json = event_json.replacen('{', "{\"task_id\":\"T-shadow\",", 1);
    assert!(serde_json::from_str::<Value>(&duplicate_json).is_ok());
    manager
        .connection
        .execute_batch("DROP TRIGGER provenance_events_no_update")
        .unwrap();
    manager
        .connection
        .execute(
            "UPDATE provenance_events SET event_type='execution.completed',event_json=?1 WHERE event_id=?2",
            rusqlite::params![duplicate_json, event_id],
        )
        .unwrap();

    let transaction = manager.connection.transaction().unwrap();
    let assessment = serde_json::json!({"evidence":[{"ref":event_id}]});
    let error = authenticated_recovery_resolution(
        &transaction,
        task_id,
        "recovery:test",
        "operation:test",
        &assessment,
    )
    .unwrap_err();
    assert!(matches!(&error, TaskManagerError::Provenance(_)));
    assert!(error.to_string().contains("duplicate"));
}

#[test]
fn completion_checks_semantic_types_and_the_current_provenance_head() {
    let mut wrong_type = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut wrong_type, HASH, &["artifact-output"], "COMMITTED");
    wrong_type
        .connection
        .execute(
            "UPDATE artifacts SET semantic_type='artifact.wrong@1' WHERE artifact_id=?1",
            [COMPLETION_ARTIFACT_ID],
        )
        .unwrap();
    assert_eq!(
        wrong_type
            .transition(&completion_request("tr-wrong-semantic-type"))
            .unwrap()
            .reason_code,
        "TASK_UNKNOWN_EXTERNAL_OUTCOME"
    );

    let mut corrupt_suffix = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut corrupt_suffix, HASH, &["artifact-output"], "COMMITTED");
    let transaction = corrupt_suffix.connection.transaction().unwrap();
    append_event(&transaction, "T-completion", &serde_json::json!({
        "schema_version":SCHEMA_VERSION,"event_id":"event:suffix","task_id":"T-completion",
        "event_type":"artifact.created","timestamp":TEST_TIME,"actor":{"kind":"system-service","id":"service:test"},"status":"success"
    })).unwrap();
    transaction.commit().unwrap();
    corrupt_suffix.connection.execute_batch("DROP TRIGGER provenance_events_no_update; UPDATE provenance_events SET event_hash='sha256:corrupt' WHERE event_id='event:suffix';").unwrap();
    assert_eq!(
        corrupt_suffix
            .transition(&completion_request("tr-corrupt-suffix"))
            .unwrap()
            .reason_code,
        "TASK_UNKNOWN_EXTERNAL_OUTCOME"
    );
}

#[test]
fn transition_reason_message_is_private_but_replay_authenticated() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    manager.create_task(&create("T-reason-private")).unwrap();
    let mut transition = request(
        "tr-reason-private",
        "T-reason-private",
        1,
        TaskState::Created,
        TaskState::Planning,
    );
    transition.reason.message = Some("private low entropy reason".to_owned());
    assert!(manager.transition(&transition).unwrap().applied);
    let event_json: String = manager.connection.query_row(
        "SELECT event_json FROM provenance_events WHERE task_id='T-reason-private' AND event_type='task.transitioned'",
        [], |row| row.get(0)).unwrap();
    assert!(!event_json.contains("private low entropy reason"));
    let event: Value = serde_json::from_str(&event_json).unwrap();
    assert!(event.pointer("/details/reason_message").is_none());
    assert_eq!(
        event
            .pointer("/details/reason_message_ref/field")
            .and_then(Value::as_str),
        Some("reason_message")
    );
}

#[test]
fn stamped_store_missing_a_core_table_is_not_repaired_on_open() {
    let directory = tempdir().unwrap();
    for table in ["operations", "authority_grants"] {
        let path = directory.path().join(format!("missing-{table}.sqlite3"));
        drop(TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap());
        Connection::open(&path)
            .unwrap()
            .execute(&format!("DROP TABLE {table}"), [])
            .unwrap();
        assert!(TaskManager::open_with_clock(&path, Box::new(FixedClock)).is_err());
        assert_eq!(
            Connection::open(&path)
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [table],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0,
            "{table}"
        );
    }
}

#[test]
fn binding_admission_authenticates_immutable_shape_snapshot_contract_and_allocation_type() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
    manager.connection.execute_batch(
        "UPDATE artifact_output_allocations SET state='ALLOCATED',publication_id=NULL,published_artifact_id=NULL WHERE allocation_id='allocation-completion';
         UPDATE step_executions SET state='READY',outcome_certainty='NOT_STARTED' WHERE attempt_id='attempt-completion';",
    ).unwrap();
    let check = BindingGrantCheck {
        task_id: "T-completion",
        semantic_hash: HASH,
        node_id: "node-completion",
        binding_id: "binding-completion",
        attempt_id: "attempt-completion",
        grant_refs_json: "[]",
        checked_at: TEST_TIME,
    };
    let transaction = manager.connection.transaction().unwrap();
    let program_json: String = transaction
        .query_row(
            "SELECT program_json FROM semantic_program_revisions WHERE task_id='T-completion'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        aios_ir::recompute_semantic_hash(program_json.as_bytes()).unwrap(),
        HASH
    );
    assert!(active_program_validation_valid(&transaction, "T-completion", HASH).unwrap());
    assert!(binding_grants_valid(&transaction, &check).unwrap());
    assert!(output_allocations_ready(&transaction, &check).unwrap());
    transaction
        .execute(
            "UPDATE artifact_output_allocations SET expected_semantic_type='artifact.wrong@1'",
            [],
        )
        .unwrap();
    assert!(!output_allocations_ready(&transaction, &check).unwrap());
    transaction
        .execute(
            "UPDATE artifact_output_allocations SET expected_semantic_type='artifact.report@1'",
            [],
        )
        .unwrap();
    transaction.execute_batch("DROP TRIGGER execution_bindings_no_update; UPDATE execution_bindings SET placement_json='{\"locality\":\"remote\"}' WHERE binding_id='binding-completion';").unwrap();
    assert!(!binding_grants_valid(&transaction, &check).unwrap());
    transaction.execute("UPDATE execution_bindings SET placement_json='{\"locality\":\"local\"}' WHERE binding_id='binding-completion'", []).unwrap();
    transaction.execute("UPDATE registry_snapshots SET manifest_json='{\"capability_contracts\":[{\"content_hash\":\"sha256:3333333333333333333333333333333333333333333333333333333333333333\",\"id\":\"test.complete\",\"version\":\"1.0\"}],\"created_at\":\"2026-09-19T00:00:00Z\",\"schema_version\":\"0.1\",\"snapshot_id\":\"snapshot-completion\",\"type_contracts\":[]}' WHERE snapshot_id='snapshot-completion'", []).unwrap();
    assert!(!binding_grants_valid(&transaction, &check).unwrap());
}

#[test]
fn completion_registry_snapshot_is_schema_valid_and_matches_capability_major() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
    let manifest_json = manager
        .connection
        .query_row(
            "SELECT manifest_json FROM registry_snapshots WHERE snapshot_id='snapshot-completion'",
            [],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
    let manifest: Value = serde_json::from_str(&manifest_json).unwrap();
    let schema: Value = serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../specs/registry-snapshot.schema.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&manifest)
    );
    assert_eq!(
        snapshot_contract_hash(&manifest, "test.complete@1").as_deref(),
        Some(CONTRACT_HASH)
    );

    let mut patch_version = manifest.clone();
    patch_version["capability_contracts"][0]["version"] = serde_json::json!("1.7.3");
    assert_eq!(
        snapshot_contract_hash(&patch_version, "test.complete@1").as_deref(),
        Some(CONTRACT_HASH)
    );
    assert!(snapshot_contract_hash(&manifest, "test.complete@2").is_none());
    assert!(snapshot_contract_hash(&manifest, "test.complete@01").is_none());
    assert!(snapshot_contract_hash(&manifest, "test.complete@1.0").is_none());
    let mut other_major = manifest.clone();
    other_major["capability_contracts"][0]["version"] = serde_json::json!("10.0");
    assert!(snapshot_contract_hash(&other_major, "test.complete@1").is_none());
    assert!(
        snapshot_contract_hash(
            &serde_json::json!({
                "provides": [{"contract": {
                    "capability": "test.complete",
                    "version": "1",
                    "contract_hash": CONTRACT_HASH
                }}]
            }),
            "test.complete@1"
        )
        .is_none()
    );

    let mut duplicate = manifest.clone();
    duplicate["capability_contracts"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "id": "test.complete",
            "version": "1.9",
            "content_hash": CONTRACT_HASH
        }));
    assert!(snapshot_contract_hash(&duplicate, "test.complete@1").is_none());
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "keeps the immutable binding tamper matrix and unchanged-state assertions together"
)]
fn running_admission_rejects_each_forged_binding_identity_without_task_or_step_mutation() {
    enum Tamper {
        PolicyDecisionRefs,
        ExecutionProfile,
        BindingJson(&'static str, Value),
        BindingJsonDuplicate,
        RegistrationProviderIdentity,
    }

    let cases = vec![
        ("policy-decision-refs", Tamper::PolicyDecisionRefs),
        ("execution-profile", Tamper::ExecutionProfile),
        ("duplicate-binding-key", Tamper::BindingJsonDuplicate),
        (
            "binding-id",
            Tamper::BindingJson("/binding_id", serde_json::json!("binding:forged")),
        ),
        (
            "task-id",
            Tamper::BindingJson("/task_id", serde_json::json!("T-forged")),
        ),
        (
            "semantic-program-hash",
            Tamper::BindingJson(
                "/semantic_program_hash",
                serde_json::json!(
                    "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                ),
            ),
        ),
        (
            "registry-snapshot-id",
            Tamper::BindingJson(
                "/registry_snapshot_id",
                serde_json::json!("snapshot-forged"),
            ),
        ),
        (
            "ir-version",
            Tamper::BindingJson("/ir_version", serde_json::json!("9.9")),
        ),
        (
            "node-id",
            Tamper::BindingJson("/node_id", serde_json::json!("node-forged")),
        ),
        (
            "capability",
            Tamper::BindingJson("/capability", serde_json::json!("test.forged@1")),
        ),
        (
            "contract-hash",
            Tamper::BindingJson(
                "/capability_contract_hash",
                serde_json::json!(
                    "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                ),
            ),
        ),
        (
            "attempt-id",
            Tamper::BindingJson("/attempt_id", serde_json::json!("attempt-forged")),
        ),
        (
            "attempt-number",
            Tamper::BindingJson("/attempt", serde_json::json!(2)),
        ),
        (
            "provider-id",
            Tamper::BindingJson("/provider/id", serde_json::json!("provider:forged")),
        ),
        (
            "provider-version",
            Tamper::BindingJson("/provider/version", serde_json::json!("9.9.9")),
        ),
        (
            "provider-manifest-hash",
            Tamper::BindingJson(
                "/provider/manifest_hash",
                serde_json::json!("sha256:forged-manifest"),
            ),
        ),
        (
            "provider-build-hash",
            Tamper::BindingJson(
                "/provider/package_or_build_hash",
                serde_json::json!("sha256:forged-build"),
            ),
        ),
        (
            "registration-provider-identity",
            Tamper::RegistrationProviderIdentity,
        ),
    ];

    for (name, tamper) in cases {
        let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
        seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
        manager
            .connection
            .execute_batch(
                "DROP TRIGGER execution_bindings_no_update;
                 UPDATE tasks SET state='RUNNABLE' WHERE task_id='T-completion';
                 UPDATE step_executions SET state='READY', outcome_certainty='NOT_STARTED' WHERE attempt_id='attempt-completion';
                 UPDATE artifact_output_allocations SET state='ALLOCATED', publication_id=NULL, published_artifact_id=NULL WHERE allocation_id='allocation-completion';
                 DELETE FROM artifact_publications WHERE publication_id='publication-completion';",
            )
            .unwrap();
        match tamper {
            Tamper::PolicyDecisionRefs => {
                manager
                    .connection
                    .execute(
                        "UPDATE execution_bindings SET policy_decision_refs_json='[\"decision:forged\"]' WHERE binding_id='binding-completion'",
                        [],
                    )
                    .unwrap();
            }
            Tamper::ExecutionProfile => {
                manager
                    .connection
                    .execute(
                        "UPDATE execution_bindings SET execution_profile_ref='profile:forged' WHERE binding_id='binding-completion'",
                        [],
                    )
                    .unwrap();
            }
            Tamper::BindingJson(pointer, replacement) => {
                let raw = manager
                    .connection
                    .query_row(
                        "SELECT binding_json FROM execution_bindings WHERE binding_id='binding-completion'",
                        [],
                        |row| row.get::<_, String>(0),
                    )
                    .unwrap();
                let mut binding: Value = serde_json::from_str(&raw).unwrap();
                *binding.pointer_mut(pointer).unwrap() = replacement;
                manager
                    .connection
                    .execute(
                        "UPDATE execution_bindings SET binding_json=?1 WHERE binding_id='binding-completion'",
                        [canonical_json(&binding).unwrap()],
                    )
                    .unwrap();
            }
            Tamper::BindingJsonDuplicate => {
                let raw: String = manager
                    .connection
                    .query_row(
                        "SELECT binding_json FROM execution_bindings
                     WHERE binding_id='binding-completion'",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                let ambiguous = raw.replacen('{', "{\"attempt\":1,", 1);
                manager
                    .connection
                    .execute(
                        "UPDATE execution_bindings SET binding_json=?1
                     WHERE binding_id='binding-completion'",
                        [ambiguous],
                    )
                    .unwrap();
            }
            Tamper::RegistrationProviderIdentity => {
                manager
                    .connection
                    .execute(
                        "UPDATE provider_registrations SET provider_id='provider:forged' WHERE registration_id='registration-completion'",
                        [],
                    )
                    .unwrap();
            }
        }

        let task_before = manager.get_task("T-completion").unwrap().unwrap();
        let step_before = manager
            .get_step_execution("attempt-completion")
            .unwrap()
            .unwrap();
        let provenance_before = manager.provenance_count("T-completion").unwrap();
        let result = manager
            .transition(&request(
                &format!("tr-binding-{name}"),
                "T-completion",
                2,
                TaskState::Runnable,
                TaskState::Running,
            ))
            .unwrap();
        assert_eq!(
            result.reason_code, "TASK_TRANSITION_GUARD_FAILED",
            "case {name}"
        );
        assert_eq!(
            manager.get_task("T-completion").unwrap().unwrap(),
            task_before,
            "case {name} mutated the task"
        );
        assert_eq!(
            manager
                .get_step_execution("attempt-completion")
                .unwrap()
                .unwrap(),
            step_before,
            "case {name} mutated the step"
        );
        assert_eq!(
            manager.provenance_count("T-completion").unwrap(),
            provenance_before,
            "case {name} appended provenance"
        );
    }
}

fn prepare_completion_for_admission(manager: &TaskManager) {
    manager
        .connection
        .execute_batch(
            "UPDATE tasks SET state='RUNNABLE' WHERE task_id='T-completion';
             UPDATE step_executions SET state='READY', outcome_certainty='NOT_STARTED' WHERE attempt_id='attempt-completion';
             UPDATE artifact_output_allocations SET state='ALLOCATED', publication_id=NULL, published_artifact_id=NULL WHERE allocation_id='allocation-completion';
             DELETE FROM artifact_publications WHERE publication_id='publication-completion';",
        )
        .unwrap();
}

#[test]
fn legacy_provider_registration_cannot_cross_the_active_snapshot() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
    prepare_completion_for_admission(&manager);
    // Exercise the pre-0013 launch profile while keeping the otherwise valid
    // completion fixture. The second snapshot retains the capability hash but
    // changes its type catalog, so a registration against it is not authority
    // for the active program's snapshot.
    manager
        .connection
        .execute(
            "DELETE FROM schema_migrations WHERE migration_id='0013_provider_registry'",
            [],
        )
        .unwrap();
    let check = BindingGrantCheck {
        task_id: "T-completion",
        semantic_hash: HASH,
        node_id: "node-completion",
        binding_id: "binding-completion",
        attempt_id: "attempt-completion",
        grant_refs_json: "[]",
        checked_at: TEST_TIME,
    };
    let transaction = manager.connection.transaction().unwrap();
    assert!(binding_grants_valid(&transaction, &check).unwrap());
    transaction.commit().unwrap();

    manager.connection.execute_batch(
        "INSERT INTO registry_snapshots(snapshot_id,manifest_json,created_at)
           SELECT 'snapshot-other',
                  json_set(manifest_json,'$.snapshot_id','snapshot-other',
                           '$.type_contracts',json('[{\"id\":\"artifact.other\",\"version\":\"1.0\",\"content_hash\":\"sha256:4444444444444444444444444444444444444444444444444444444444444444\"}]')),
                  created_at FROM registry_snapshots WHERE snapshot_id='snapshot-completion';
         UPDATE provider_registrations SET registry_snapshot_id='snapshot-other'
           WHERE registration_id='registration-completion';",
    ).unwrap();
    let transaction = manager.connection.transaction().unwrap();
    assert!(!binding_grants_valid(&transaction, &check).unwrap());
    transaction.commit().unwrap();

    let task_before = manager.get_task("T-completion").unwrap().unwrap();
    let step_before = manager
        .get_step_execution("attempt-completion")
        .unwrap()
        .unwrap();
    let provenance_before = manager.provenance_count("T-completion").unwrap();
    let result = manager
        .transition(&request(
            "tr-legacy-snapshot-mismatch",
            "T-completion",
            task_before.revision,
            TaskState::Runnable,
            TaskState::Running,
        ))
        .unwrap();
    assert_eq!(result.reason_code, "TASK_TRANSITION_GUARD_FAILED");
    assert_eq!(
        manager.get_task("T-completion").unwrap().unwrap(),
        task_before
    );
    assert_eq!(
        manager
            .get_step_execution("attempt-completion")
            .unwrap()
            .unwrap(),
        step_before
    );
    assert_eq!(
        manager.provenance_count("T-completion").unwrap(),
        provenance_before
    );
}

fn mutate_json_column(
    manager: &TaskManager,
    select: &str,
    update: &str,
    pointer: &str,
    replacement: Value,
) {
    let raw = manager
        .connection
        .query_row(select, [], |row| row.get::<_, String>(0))
        .unwrap();
    let mut value: Value = serde_json::from_str(&raw).unwrap();
    *value.pointer_mut(pointer).unwrap() = replacement;
    manager
        .connection
        .execute(update, [canonical_json(&value).unwrap()])
        .unwrap();
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "table-driven adversarial coverage authenticates every conformance receipt field"
)]
fn admission_authenticates_complete_conformance_evidence_and_timestamps() {
    enum Tamper {
        Json(&'static str, Value),
        Malformed,
        SuiteColumn,
        InvalidExecutedAt,
    }
    let cases = vec![
        ("malformed", Tamper::Malformed),
        (
            "provider-id",
            Tamper::Json("/provider_id", serde_json::json!("provider:forged")),
        ),
        (
            "provider-version",
            Tamper::Json("/provider_version", serde_json::json!("9.9.9")),
        ),
        (
            "provider-build",
            Tamper::Json(
                "/provider_build_identity/value",
                serde_json::json!("sha256:forged"),
            ),
        ),
        (
            "capability",
            Tamper::Json(
                "/semantic_capability_ref",
                serde_json::json!("test.forged@1"),
            ),
        ),
        (
            "contract-version",
            Tamper::Json("/semantic_contract_version", serde_json::json!("1.1")),
        ),
        (
            "contract-hash",
            Tamper::Json(
                "/semantic_contract_hash",
                serde_json::json!(
                    "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                ),
            ),
        ),
        (
            "suite-id",
            Tamper::Json("/conformance_suite/id", serde_json::json!("suite:forged")),
        ),
        (
            "suite-hash",
            Tamper::Json(
                "/conformance_suite/hash",
                serde_json::json!(
                    "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                ),
            ),
        ),
        ("suite-column", Tamper::SuiteColumn),
        ("result", Tamper::Json("/result", serde_json::json!("fail"))),
        (
            "expired",
            Tamper::Json("/expires_at", serde_json::json!(TEST_TIME)),
        ),
        ("invalid-executed-at", Tamper::InvalidExecutedAt),
    ];
    for (name, tamper) in cases {
        let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
        seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
        let evidence: Value = serde_json::from_str(
            &manager
                .connection
                .query_row(
                    "SELECT evidence_json FROM provider_conformance_evidence WHERE evidence_id='evidence-completion'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            evidence
                .pointer("/conformance_suite/hash")
                .and_then(Value::as_str),
            Some(SUITE_HASH)
        );
        prepare_completion_for_admission(&manager);
        match tamper {
            Tamper::Json(pointer, replacement) => mutate_json_column(
                &manager,
                "SELECT evidence_json FROM provider_conformance_evidence WHERE evidence_id='evidence-completion'",
                "UPDATE provider_conformance_evidence SET evidence_json=?1 WHERE evidence_id='evidence-completion'",
                pointer,
                replacement,
            ),
            Tamper::Malformed => {
                manager
                    .connection
                    .execute(
                        "UPDATE provider_conformance_evidence SET evidence_json='{}' WHERE evidence_id='evidence-completion'",
                        [],
                    )
                    .unwrap();
            }
            Tamper::SuiteColumn => {
                manager
                    .connection
                    .execute(
                        "UPDATE provider_conformance_evidence SET suite_id='suite:forged' WHERE evidence_id='evidence-completion'",
                        [],
                    )
                    .unwrap();
            }
            Tamper::InvalidExecutedAt => {
                mutate_json_column(
                    &manager,
                    "SELECT evidence_json FROM provider_conformance_evidence WHERE evidence_id='evidence-completion'",
                    "UPDATE provider_conformance_evidence SET evidence_json=?1 WHERE evidence_id='evidence-completion'",
                    "/executed_at",
                    serde_json::json!("not-rfc3339"),
                );
                manager
                    .connection
                    .execute(
                        "UPDATE provider_conformance_evidence SET tested_at='not-rfc3339' WHERE evidence_id='evidence-completion'",
                        [],
                    )
                    .unwrap();
            }
        }
        let task_before = manager.get_task("T-completion").unwrap().unwrap();
        let step_before = manager
            .get_step_execution("attempt-completion")
            .unwrap()
            .unwrap();
        let result = manager
            .transition(&request(
                &format!("tr-conformance-{name}"),
                "T-completion",
                2,
                TaskState::Runnable,
                TaskState::Running,
            ))
            .unwrap();
        assert_eq!(result.reason_code, "TASK_TRANSITION_GUARD_FAILED", "{name}");
        assert_eq!(
            manager.get_task("T-completion").unwrap().unwrap(),
            task_before
        );
        assert_eq!(
            manager
                .get_step_execution("attempt-completion")
                .unwrap()
                .unwrap(),
            step_before
        );
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "keeps validation receipt and program-byte tampering across admission and completion together"
)]
fn program_validation_receipt_and_program_bytes_gate_runnable_admission_and_completion() {
    for (name, tamper_program) in [("receipt", false), ("program", true), ("timestamp", false)] {
        let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
        seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
        prepare_completion_for_admission(&manager);
        if tamper_program {
            mutate_json_column(
                &manager,
                "SELECT program_json FROM semantic_program_revisions WHERE task_id='T-completion'",
                "UPDATE semantic_program_revisions SET program_json=?1 WHERE task_id='T-completion'",
                "/nodes/0/execution_class",
                serde_json::json!("opaque_external"),
            );
        } else if name == "timestamp" {
            mutate_json_column(
                &manager,
                "SELECT result_json FROM validation_results WHERE validation_result_id='validation-completion'",
                "UPDATE validation_results SET result_json=?1 WHERE validation_result_id='validation-completion'",
                "/validated_at",
                serde_json::json!("not-rfc3339"),
            );
            manager
                .connection
                .execute(
                    "UPDATE validation_results SET validated_at='not-rfc3339' WHERE validation_result_id='validation-completion'",
                    [],
                )
                .unwrap();
        } else {
            mutate_json_column(
                &manager,
                "SELECT result_json FROM validation_results WHERE validation_result_id='validation-completion'",
                "UPDATE validation_results SET result_json=?1 WHERE validation_result_id='validation-completion'",
                "/validator/id",
                serde_json::json!("validator:forged"),
            );
        }
        let task_before = manager.get_task("T-completion").unwrap().unwrap();
        let step_before = manager
            .get_step_execution("attempt-completion")
            .unwrap()
            .unwrap();
        assert_eq!(
            manager
                .transition(&request(
                    &format!("tr-validation-{name}"),
                    "T-completion",
                    2,
                    TaskState::Runnable,
                    TaskState::Running,
                ))
                .unwrap()
                .reason_code,
            "TASK_TRANSITION_GUARD_FAILED"
        );
        assert_eq!(
            manager.get_task("T-completion").unwrap().unwrap(),
            task_before
        );
        assert_eq!(
            manager
                .get_step_execution("attempt-completion")
                .unwrap()
                .unwrap(),
            step_before
        );
    }

    for (name, source, target) in [
        ("runnable", TaskState::Planning, TaskState::Runnable),
        ("completion", TaskState::Verifying, TaskState::Completed),
    ] {
        let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
        seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
        manager
            .connection
            .execute(
                "UPDATE tasks SET state=?1 WHERE task_id='T-completion'",
                [source.as_str()],
            )
            .unwrap();
        mutate_json_column(
            &manager,
            "SELECT program_json FROM semantic_program_revisions WHERE task_id='T-completion'",
            "UPDATE semantic_program_revisions SET program_json=?1 WHERE task_id='T-completion'",
            "/nodes/0/execution_class",
            serde_json::json!("opaque_external"),
        );
        let transition = if target == TaskState::Completed {
            completion_request(&format!("tr-tampered-program-{name}"))
        } else {
            request(
                &format!("tr-tampered-program-{name}"),
                "T-completion",
                2,
                source,
                target,
            )
        };
        let result = manager.transition(&transition).unwrap();
        assert!(!result.applied, "{name}");
        assert_eq!(
            manager.get_task("T-completion").unwrap().unwrap().state,
            source
        );
    }
}

#[test]
fn failure_code_must_match_machine_reason_code_pattern() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    manager.create_task(&create("T-failure-code")).unwrap();
    let mut failed = request(
        "tr-failure-code",
        "T-failure-code",
        1,
        TaskState::Created,
        TaskState::Failed,
    );
    failed.mutation.failure.as_mut().unwrap().code = "secret-shaped failure".to_owned();
    assert!(manager.transition(&failed).is_err());
    assert_eq!(
        manager.get_task("T-failure-code").unwrap().unwrap().state,
        TaskState::Created
    );
    let schema: Value = serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../specs/task-transition-request.schema.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        !jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&serde_json::to_value(&failed).unwrap())
    );
}

#[test]
fn completion_enforces_every_output_allocation_constraint() {
    for (name, mutation, expected_reason) in [
        (
            "max-size",
            "UPDATE artifact_output_allocations SET max_size_bytes=41 WHERE allocation_id='allocation-completion'",
            "TASK_COMPLETION_GATE_FAILED",
        ),
        (
            "media-type",
            "UPDATE artifact_output_allocations SET allowed_media_types_json='[\"text/plain\"]' WHERE allocation_id='allocation-completion'",
            "TASK_COMPLETION_GATE_FAILED",
        ),
        (
            "malformed-media-types",
            "UPDATE artifact_output_allocations SET allowed_media_types_json='{}' WHERE allocation_id='allocation-completion'",
            "TASK_COMPLETION_GATE_FAILED",
        ),
        (
            "sensitivity",
            "UPDATE artifact_output_allocations SET sensitivity='secret' WHERE allocation_id='allocation-completion'",
            "TASK_UNKNOWN_EXTERNAL_OUTCOME",
        ),
        (
            "retention",
            "UPDATE artifact_output_allocations SET retention='persistent' WHERE allocation_id='allocation-completion'",
            "TASK_UNKNOWN_EXTERNAL_OUTCOME",
        ),
    ] {
        let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
        seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
        manager.connection.execute(mutation, []).unwrap();
        let result = manager
            .transition(&completion_request(&format!("tr-allocation-{name}")))
            .unwrap();
        assert_eq!(result.reason_code, expected_reason, "{name}");
        assert_eq!(
            manager.get_task("T-completion").unwrap().unwrap().state,
            TaskState::Verifying
        );
    }
}

#[test]
fn superseded_plan_or_program_cannot_be_used_for_execution() {
    for column in ["plan_revisions", "semantic_program_revisions"] {
        let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
        seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
        manager.connection.execute(
            &format!("UPDATE {column} SET superseded_at='2026-09-19T00:00:00Z' WHERE task_id='T-completion'"),
            [],
        ).unwrap();
        assert!(
            !manager
                .transition(&completion_request(&format!("tr-superseded-{column}")))
                .unwrap()
                .applied
        );
    }
}

#[test]
fn failed_can_preserve_contained_unknown_effect_with_structured_disclosure() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    manager.create_task(&create("T-failed-contained")).unwrap();
    assert!(
        manager
            .transition(&request(
                "tr-failed-plan",
                "T-failed-contained",
                1,
                TaskState::Created,
                TaskState::Planning
            ))
            .unwrap()
            .applied
    );
    manager.connection.execute(
        "INSERT INTO step_executions(attempt_id,task_id,semantic_program_hash,node_id,attempt_number,revision,state,outcome_certainty,input_artifacts_json,output_artifacts_json,created_at,updated_at) VALUES ('attempt-contained','T-failed-contained',?1,'node',1,1,'FAILED','OUTCOME_UNKNOWN','[]','[]',?2,?2)",
        rusqlite::params![HASH, TEST_TIME],
    ).unwrap();
    let mut failed = request(
        "tr-failed-contained",
        "T-failed-contained",
        2,
        TaskState::Planning,
        TaskState::Failed,
    );
    failed
        .mutation
        .failure
        .as_mut()
        .unwrap()
        .unknown_side_effects = true;
    assert!(manager.transition(&failed).unwrap().applied);
}

#[test]
fn failed_preserves_disclosure_for_succeeded_operation_with_unknown_outcome() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    manager.create_task(&create("T-failed-operation")).unwrap();
    assert!(
        manager
            .transition(&request(
                "tr-failed-operation-plan",
                "T-failed-operation",
                1,
                TaskState::Created,
                TaskState::Planning,
            ))
            .unwrap()
            .applied
    );
    manager.connection.execute(
        "INSERT INTO operations(operation_id,task_id,semantic_program_hash,node_id,effect_class,state,outcome_certainty,prepared_at,finished_at) VALUES ('operation-succeeded-unknown','T-failed-operation',?1,'node','NETWORK','SUCCEEDED','OUTCOME_UNKNOWN',?2,?2)",
        rusqlite::params![HASH, TEST_TIME],
    ).unwrap();
    let mut failed = request(
        "tr-failed-operation",
        "T-failed-operation",
        2,
        TaskState::Planning,
        TaskState::Failed,
    );
    failed
        .mutation
        .failure
        .as_mut()
        .unwrap()
        .unknown_side_effects = true;
    assert!(manager.transition(&failed).unwrap().applied);

    let task = manager.get_task("T-failed-operation").unwrap().unwrap();
    assert_eq!((task.state, task.revision), (TaskState::Failed, 3));
    assert!(task.failure.unwrap().unknown_side_effects);
    let operation = manager
        .connection
        .query_row(
            "SELECT state,outcome_certainty FROM operations WHERE operation_id='operation-succeeded-unknown'",
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .unwrap();
    assert_eq!(
        operation,
        ("SUCCEEDED".to_owned(), "OUTCOME_UNKNOWN".to_owned())
    );
    let event_json = manager
        .connection
        .query_row(
            "SELECT event_json FROM provenance_events WHERE task_id='T-failed-operation' AND event_type='task.transitioned' ORDER BY sequence DESC LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .unwrap();
    let event: Value = serde_json::from_str(&event_json).unwrap();
    assert_eq!(
        event
            .pointer("/committed_mutation/failure/unknown_side_effects")
            .and_then(Value::as_bool),
        Some(true)
    );
}

#[test]
fn live_recovery_committed_null_receipt_reconstructs_after_reopen() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("live-recovery-receipt.sqlite3");
    let transition_id;
    {
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        seed_nonterminal_history(&mut manager, "T-live-receipt", TaskState::Paused);
        let result = manager.reconcile_live_execution("T-live-receipt").unwrap();
        assert!(result.applied);
        transition_id = manager.connection.query_row(
            "SELECT transition_id FROM task_transitions WHERE task_id='T-live-receipt' AND to_state='RECOVERING'",
            [], |row| row.get::<_,String>(0)).unwrap();
    }
    Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE task_transitions SET result_json=NULL WHERE transition_id=?1",
            [&transition_id],
        )
        .unwrap();
    let reopened = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
    let reconstructed: Option<String> = reopened
        .connection
        .query_row(
            "SELECT result_json FROM task_transitions WHERE transition_id=?1",
            [&transition_id],
            |row| row.get(0),
        )
        .unwrap();
    assert!(reconstructed.is_some());
}

#[test]
fn reconciled_operation_preserves_not_started_and_failed_no_effect_dispositions() {
    for (name, initial_state, durable_update, certainty, action, status) in [
        (
            "not-started",
            "PREPARED",
            None,
            "NOT_STARTED",
            "CREATE_NEW_ATTEMPT",
            "cancelled",
        ),
        (
            "failed-no-effect",
            "UNKNOWN",
            Some("FAILED_NO_EFFECT"),
            "FAILED_NO_EFFECT",
            "MARK_ATTEMPT_FAILED",
            "failure",
        ),
    ] {
        let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
        let task_id = format!("T-{name}");
        let revision = seed_recovering_history(&mut manager, &task_id);
        manager.connection.execute(
            "INSERT INTO operations(operation_id,task_id,semantic_program_hash,node_id,effect_class,state,outcome_certainty,prepared_at) VALUES ('op',?1,?2,'node','NETWORK',?3,CASE WHEN ?3='PREPARED' THEN NULL ELSE 'OUTCOME_UNKNOWN' END,?4)",
            rusqlite::params![task_id, HASH, initial_state, TEST_TIME],
        ).unwrap();
        let inventory = unresolved_execution_ids(&manager.connection, &task_id).unwrap();
        let recovery_ref = recovery_operations_ref(&task_id, revision, &inventory).unwrap();
        manager
            .persist_recovery_inventory(&recovery_ref, &task_id, revision, &inventory, TEST_TIME)
            .unwrap();
        manager.connection.execute(
            "UPDATE tasks SET state='RECOVERING',recovery_json=?2 WHERE task_id=?1",
            rusqlite::params![task_id, serde_json::json!({"unknown_operations_ref":recovery_ref,"last_known_daemon_instance":null}).to_string()],
        ).unwrap();
        if let Some(durable_update) = durable_update {
            manager
                .connection
                .execute(
                    "UPDATE operations SET outcome_certainty=?1 WHERE task_id=?2",
                    rusqlite::params![durable_update, task_id],
                )
                .unwrap();
        }
        manager
            .reconcile_recovery_subject(&recovery_ref, "operation:op")
            .unwrap();
        let (stored_certainty, stored_action, assessment_json): (String,String,String) = manager.connection.query_row(
            "SELECT certainty,safe_action,assessment_json FROM recovery_assessments WHERE task_id=?1 AND subject_kind='external-operation'",
            [&task_id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap();
        assert_eq!(stored_certainty, certainty);
        assert_eq!(stored_action, action);
        let assessment: Value = serde_json::from_str(&assessment_json).unwrap();
        assert_eq!(
            assessment
                .pointer("/evidence/0/kind")
                .and_then(Value::as_str),
            Some("provenance")
        );
        let event_status: String = manager
            .connection
            .query_row(
                "SELECT status FROM provenance_events WHERE event_id=?1",
                [recovery_resolution_event_id(&recovery_ref, "operation:op")],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(event_status, status);
        let result = manager
            .transition(&request(
                &format!("tr-{name}-exit"),
                &task_id,
                revision,
                TaskState::Recovering,
                TaskState::Planning,
            ))
            .unwrap();
        assert!(result.applied, "{name}: {}", result.reason_code);
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "builds exact publication, grant, and credential recovery subjects for disposition checks"
)]
fn reconciled_aborted_revoked_and_denied_subjects_keep_failure_dispositions() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "PENDING");
    manager.connection.execute_batch(
        "INSERT INTO policy_snapshots(snapshot_id,scope_kind,scope_id,policy_language,policy_set_hash,engine_id,engine_version,snapshot_json,created_at) VALUES ('policy-recovery','task','T-completion','fixture','sha256:policy','engine:test','0.1','{}','2026-09-19T00:00:00Z');
         INSERT INTO authority_requests(request_id,task_id,semantic_program_hash,registry_snapshot_id,node_id,capability,principal_kind,principal_id,execution_binding_id,attempt_id,action,resolved_resource_kind,resolved_resource_id,semantic_selector,request_json,requested_at) VALUES ('authority-recovery','T-completion','sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50','snapshot-completion','node-completion','test.complete@1','provider','provider:test','binding-completion','attempt-completion','test.execute','artifact','artifact:one','resource:one','{}','2026-09-19T00:00:00Z');
         INSERT INTO policy_decisions(decision_id,authority_request_id,task_id,semantic_program_hash,node_id,principal_kind,principal_id,action,resolved_resource_kind,resolved_resource_id,decision,policy_snapshot_id,reason_codes_json,decision_json,decided_at) VALUES ('decision-recovery','authority-recovery','T-completion','sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50','node-completion','provider','provider:test','test.execute','artifact','artifact:one','ALLOW','policy-recovery','[]','{}','2026-09-19T00:00:00Z');
         INSERT INTO authority_grants(grant_id,task_id,semantic_program_hash,node_id,capability,principal_kind,principal_id,execution_binding_id,attempt_id,policy_decision_id,policy_snapshot_id,grants_json,scope,state,issued_at,expires_at) VALUES ('grant-recovery','T-completion','sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50','node-completion','test.complete@1','provider','provider:test','binding-completion','attempt-completion','decision-recovery','policy-recovery','[]','TASK','ACTIVE','2026-09-19T00:00:00Z','2026-09-20T00:00:00Z');
         INSERT INTO credential_handles(credential_id,owner_principal_kind,owner_principal_id,credential_class,exportability,status,metadata_json,secure_store_ref,created_at) VALUES ('credential://recovery','provider','provider:test','api-token','broker-only','ACTIVE','{}','secure://credential-recovery','2026-09-19T00:00:00Z');
         INSERT INTO credential_use_records(request_id,task_id,credential_id,execution_binding_id,authority_grant_id,principal_kind,principal_id,use_mode,request_json,requested_at) VALUES ('credential-use-recovery','T-completion','credential://recovery','binding-completion','grant-recovery','provider','provider:test','inject','{}','2026-09-19T00:00:00Z');",
    ).unwrap();
    let inventory = unresolved_execution_ids(&manager.connection, "T-completion").unwrap();
    let recovery_ref = recovery_operations_ref("T-completion", 2, &inventory).unwrap();
    manager
        .persist_recovery_inventory(&recovery_ref, "T-completion", 2, &inventory, TEST_TIME)
        .unwrap();
    let publication_request: crate::artifact_store::ArtifactPublicationRequest = manager
        .connection
        .query_row(
            "SELECT request_json FROM artifact_publications
             WHERE publication_id='publication-completion'",
            [],
            |row| row.get::<_, String>(0),
        )
        .map(|json| serde_json::from_str(&json).unwrap())
        .unwrap();
    manager
        .connection
        .execute_batch(
            "UPDATE artifact_output_allocations
             SET state='WRITING',published_artifact_id=NULL
             WHERE allocation_id='allocation-completion';
             UPDATE artifact_publications
             SET artifact_id=NULL,content_hash=NULL
             WHERE publication_id='publication-completion';",
        )
        .unwrap();
    manager
        .abort_pending_publication(&publication_request)
        .unwrap();
    manager.connection.execute_batch(
        "UPDATE authority_grants SET state='REVOKED',revoked_at='2026-09-19T00:00:00Z' WHERE grant_id='grant-recovery';",
    ).unwrap();
    let denied_result = canonical_json(&serde_json::json!({
        "schema_version":SCHEMA_VERSION,
        "result_id":"credential-result-denied",
        "request_id":"credential-use-recovery",
        "task_id":"T-completion",
        "credential_handle_id":"credential://recovery",
        "status":"AUTHORITY_DENIED",
        "reason_codes":["CRED_AUTHORITY_DENIED"],
        "completed_at":TEST_TIME
    }))
    .unwrap();
    manager.connection.execute(
        "UPDATE credential_use_records SET result_id='credential-result-denied',status='AUTHORITY_DENIED',result_json=?1,completed_at=?2 WHERE request_id='credential-use-recovery'",
        rusqlite::params![denied_result, TEST_TIME],
    ).unwrap();
    for inventory_id in [
        "publication:publication-completion",
        "grant:grant-recovery",
        "credential-use:credential-use-recovery",
    ] {
        manager
            .reconcile_recovery_subject(&recovery_ref, inventory_id)
            .unwrap();
    }
    let schema: Value = serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../specs/recovery-assessment.schema.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let mut statement = manager.connection.prepare(
        "SELECT subject_kind,certainty,safe_action,assessment_json FROM recovery_assessments WHERE task_id='T-completion' AND subject_kind IN ('artifact-publication','authority-grant','external-operation') ORDER BY subject_kind"
    ).unwrap();
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .unwrap();
    let resolved = rows.collect::<std::result::Result<Vec<_>, _>>().unwrap();
    assert_eq!(resolved.len(), 3);
    for (kind, certainty, action, assessment) in resolved {
        assert_eq!(certainty, "FAILED_NO_EFFECT", "{kind}");
        assert!(
            matches!(action.as_str(), "CLEAN_STAGING" | "NO_ACTION"),
            "{kind}"
        );
        let assessment: Value = serde_json::from_str(&assessment).unwrap();
        assert!(validator.is_valid(&assessment), "{kind}");
        assert_eq!(
            assessment
                .pointer("/evidence/0/kind")
                .and_then(Value::as_str),
            Some("provenance")
        );
    }
}

#[test]
fn committed_publication_recovery_requires_full_allocation_artifact_and_blob_proof() {
    for (name, mutation) in [
        (
            "missing-blob",
            "UPDATE artifact_blobs SET durability_state='MISSING'
             WHERE content_hash='sha256:4444444444444444444444444444444444444444444444444444444444444444'",
        ),
        (
            "unverified-artifact",
            "UPDATE artifacts SET integrity_state='failed' WHERE artifact_id='artifact-output'",
        ),
        (
            "publication-hash-missing",
            "UPDATE artifact_publications SET content_hash=NULL
             WHERE publication_id='publication-completion'",
        ),
    ] {
        let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
        seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "PENDING");
        let inventory = unresolved_execution_ids(&manager.connection, "T-completion").unwrap();
        assert!(inventory.contains(&"publication:publication-completion".to_owned()));
        manager.connection.execute(
            "UPDATE artifact_publications SET state='COMMITTED',committed_at=?1 WHERE publication_id='publication-completion'",
            [TEST_TIME],
        ).unwrap();
        {
            let transaction = manager.connection.transaction().unwrap();
            assert!(
                resolved_recovery_subject(
                    &transaction,
                    "T-completion",
                    "publication:publication-completion"
                )
                .unwrap()
                .is_some(),
                "valid:{name}"
            );
        }
        if name == "unverified-artifact" {
            manager
                .connection
                .execute(
                    "UPDATE artifacts SET integrity_state='failed' WHERE artifact_id=?1",
                    [COMPLETION_ARTIFACT_ID],
                )
                .unwrap();
        } else {
            manager.connection.execute(mutation, []).unwrap();
        }
        let transaction = manager.connection.transaction().unwrap();
        assert!(
            resolved_recovery_subject(
                &transaction,
                "T-completion",
                "publication:publication-completion"
            )
            .unwrap()
            .is_none(),
            "{name}"
        );
    }
}

#[test]
fn committed_publication_recovery_rejects_rogue_allocation_alias() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
    manager
        .connection
        .execute_batch(&format!(
            "INSERT INTO artifact_output_allocations (
                 allocation_id, task_id, semantic_program_hash, node_id,
                 binding_id, attempt_id, output_port, expected_semantic_type,
                 sensitivity, retention, state, publication_id,
                 published_artifact_id, created_at, expires_at
             ) VALUES (
                 'allocation-rogue', 'T-completion',
                 'sha256:a26d727d3b1a003e872352a31689f73fbfad0e5f24dbb566f28b97f368272c50',
                 'node-completion', 'binding-completion', 'attempt-completion',
                 'rogue', 'artifact.report@1', 'local', 'task', 'PUBLISHED',
                 'publication-rogue', '{COMPLETION_ARTIFACT_ID}',
                 '2026-09-19T00:00:00Z', '2026-09-20T00:00:00Z'
             );
             INSERT INTO artifact_publications (
                 publication_id, allocation_id, task_id, artifact_id, content_hash,
                 request_json, state, requested_at, committed_at
             ) VALUES (
                 'publication-rogue', 'allocation-rogue', 'T-completion',
                 '{COMPLETION_ARTIFACT_ID}', 'sha256:4444444444444444444444444444444444444444444444444444444444444444', '{{}}', 'COMMITTED',
                 '2026-09-19T00:00:00Z', '2026-09-19T00:00:00Z'
             );"
        ))
        .unwrap();
    let transaction = manager.connection.transaction().unwrap();
    assert!(
        resolved_recovery_subject(
            &transaction,
            "T-completion",
            "publication:publication-completion"
        )
        .unwrap()
        .is_some()
    );
    assert!(
        resolved_recovery_subject(
            &transaction,
            "T-completion",
            "publication:publication-rogue"
        )
        .unwrap()
        .is_none(),
        "a committed publication using a legitimate artifact cannot resolve unless its exact allocation is the selected active output"
    );
}

#[test]
fn credential_recovery_authenticates_canonical_result_identity_and_status() {
    let schema: Value = serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../specs/credential-use-result.schema.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    for (status, reason_code, certainty) in [
        ("ALLOWED_AND_USED", "CRED_USED", "COMPLETED"),
        (
            "AUTHORITY_DENIED",
            "CRED_AUTHORITY_DENIED",
            "FAILED_NO_EFFECT",
        ),
    ] {
        let value = serde_json::json!({
            "schema_version":SCHEMA_VERSION,
            "result_id":"result-1",
            "request_id":"request-1",
            "task_id":"T-credential-result",
            "credential_handle_id":"credential://fixture",
            "status":status,
            "reason_codes":[reason_code],
            "completed_at":TEST_TIME
        });
        assert!(validator.is_valid(&value));
        let canonical = canonical_json(&value).unwrap();
        let resolution = credential_use_resolution(
            "T-credential-result",
            "request-1",
            "result-1",
            "credential://fixture",
            status,
            TEST_TIME,
            &canonical,
        )
        .unwrap()
        .unwrap();
        assert_eq!(resolution.certainty, certainty);

        for (field, replacement) in [
            ("result_id", "forged-result"),
            ("request_id", "forged-request"),
            ("task_id", "T-forged"),
            ("credential_handle_id", "credential://forged"),
            ("status", "CANCELLED"),
            ("completed_at", "2026-09-20T00:00:00Z"),
        ] {
            let mut forged = value.clone();
            forged[field] = Value::String(replacement.to_owned());
            assert!(
                credential_use_resolution(
                    "T-credential-result",
                    "request-1",
                    "result-1",
                    "credential://fixture",
                    status,
                    TEST_TIME,
                    &canonical_json(&forged).unwrap(),
                )
                .unwrap()
                .is_none(),
                "{status}:{field}"
            );
        }
    }
    let legacy = canonical_json(&serde_json::json!({
        "schema_version":SCHEMA_VERSION,"result_id":"result-1","request_id":"request-1",
        "task_id":"T-credential-result","credential_handle_id":"credential://fixture",
        "status":"SUCCESS","reason_codes":["CRED_USED"],"completed_at":TEST_TIME
    }))
    .unwrap();
    assert!(
        credential_use_resolution(
            "T-credential-result",
            "request-1",
            "result-1",
            "credential://fixture",
            "SUCCESS",
            TEST_TIME,
            &legacy
        )
        .unwrap()
        .is_none()
    );
}
