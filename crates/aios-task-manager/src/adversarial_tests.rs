use super::*;

use std::sync::{Arc, Barrier};
use std::thread;

use rusqlite::Connection;
use tempfile::tempdir;

const HASH: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> String {
        "2026-09-19T00:00:00Z".to_owned()
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
        mutation: TaskMutation::default(),
    }
}

fn seed_nonterminal_history(manager: &mut TaskManager, task_id: &str, final_state: TaskState) {
    manager.create_task(&create(task_id)).unwrap();
    let path: &[TaskState] = match final_state {
        TaskState::Running => &[TaskState::Planning, TaskState::Runnable, TaskState::Running],
        TaskState::Verifying => &[
            TaskState::Planning,
            TaskState::Runnable,
            TaskState::Running,
            TaskState::Verifying,
        ],
        _ => panic!("fixture only supports running or verifying"),
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
            }
        });
        append_event(&transaction, task_id, &event).unwrap();
        transaction
            .execute(
                "UPDATE tasks SET state = ?2, revision = ?3 WHERE task_id = ?1",
                rusqlite::params![task_id, to.as_str(), i64::try_from(next_revision).unwrap()],
            )
            .unwrap();
        from = *to;
        revision = next_revision;
    }
    transaction.commit().unwrap();
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
fn startup_recovery_moves_running_and_verifying_tasks_through_cas_provenance() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_nonterminal_history(&mut manager, "T-running", TaskState::Running);
    seed_nonterminal_history(&mut manager, "T-verifying", TaskState::Verifying);
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
fn pre_reconciliation_store_migrates_without_losing_task_or_transition() {
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
            .query_row(
                "SELECT COUNT(*) FROM task_transitions WHERE transition_id = 'tr-legacy'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
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
fn barrier_controlled_connections_have_one_cas_winner_and_valid_chain() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("concurrent.sqlite3");
    let mut setup = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
    setup.create_task(&create("T-concurrent")).unwrap();
    drop(setup);

    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for (transition_id, to_state) in [
        ("tr-concurrent-plan", TaskState::Planning),
        ("tr-concurrent-fail", TaskState::Failed),
    ] {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
            barrier.wait();
            manager
                .transition(&request(
                    transition_id,
                    "T-concurrent",
                    1,
                    TaskState::Created,
                    to_state,
                ))
                .unwrap()
        }));
    }
    barrier.wait();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.applied).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| result.reason_code == "TASK_REVISION_CONFLICT")
            .count(),
        1
    );
    let manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
    assert_eq!(
        manager.get_task("T-concurrent").unwrap().unwrap().revision,
        2
    );
    assert_eq!(manager.provenance_count("T-concurrent").unwrap(), 2);
    assert!(manager.verify_provenance("T-concurrent").unwrap());
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
                 'sha256:1111111111111111111111111111111111111111111111111111111111111111',
                 'snapshot-1', 'validator:test', '0.1', '{}',
                 '2026-09-19T00:00:00Z'
             );
             INSERT INTO semantic_program_revisions (
                 task_id, program_revision, program_id, ir_version,
                 semantic_hash, registry_snapshot_id, validation_result_id,
                 status, program_json, created_at
             ) VALUES (
                 'T-guard-spoof', 1, 'program-1', '0.1',
                 'sha256:1111111111111111111111111111111111111111111111111111111111111111',
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
                 'sha256:1111111111111111111111111111111111111111111111111111111111111111',
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
                 'sha256:1111111111111111111111111111111111111111111111111111111111111111',
                 'node-real', 'test.execute', 'PENDING', '{}',
                 '2026-09-19T00:00:00Z'
             );
             INSERT INTO step_executions (
                 attempt_id, task_id, semantic_program_hash, node_id,
                 attempt_number, revision, state, input_artifacts_json,
                 output_artifacts_json, created_at, updated_at
             ) VALUES (
                 'attempt-ready', 'T-guard-spoof',
                 'sha256:1111111111111111111111111111111111111111111111111111111111111111',
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
             ) VALUES ('snapshot-completion', '{}', '2026-09-19T00:00:00Z');
             INSERT INTO plan_revisions (
                 task_id, plan_revision, plan_id, plan_json, created_at
             ) VALUES (
                 'T-completion', 1, 'plan-1', '{}',
                 '2026-09-19T00:00:00Z'
             );
             INSERT INTO validation_results (
                 validation_result_id, task_id, valid, semantic_hash,
                 registry_snapshot_id, validator_id, validator_version,
                 result_json, validated_at
             ) VALUES (
                 'validation-completion', 'T-completion', 1,
                 'sha256:1111111111111111111111111111111111111111111111111111111111111111',
                 'snapshot-completion', 'validator:test', '0.1', '{}',
                 '2026-09-19T00:00:00Z'
             );
             INSERT INTO semantic_program_revisions (
                 task_id, program_revision, program_id, ir_version,
                 semantic_hash, registry_snapshot_id, validation_result_id,
                 created_from_plan_revision, status, program_json, created_at
             ) VALUES (
                 'T-completion', 1, 'program-completion', '0.1',
                 'sha256:1111111111111111111111111111111111111111111111111111111111111111',
                 'snapshot-completion', 'validation-completion', 1, 'active', '{}',
                 '2026-09-19T00:00:00Z'
             );
             INSERT INTO execution_bindings (
                 binding_id, attempt_id, task_id, semantic_program_hash,
                 registry_snapshot_id, ir_version, node_id, capability,
                 provider_id, provider_version, attempt,
                 policy_decision_refs_json, grant_refs_json,
                 execution_profile_ref, placement_json, binding_json, created_at
             ) VALUES (
                 'binding-completion', 'attempt-completion', 'T-completion',
                 'sha256:1111111111111111111111111111111111111111111111111111111111111111',
                 'snapshot-completion', '0.1', 'node-completion',
                 'test.complete', 'provider:test', '0.1.0', 1,
                 '[]', '[]', 'profile:test', '{}', '{}',
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
                 'sha256:1111111111111111111111111111111111111111111111111111111111111111',
                 'snapshot-completion', 'node-completion',
                 'binding-completion', 'provider:test', '0.1.0', 1, 3,
                 'SUCCEEDED', 'COMPLETED', '[]', '[\"artifact-output\"]',
                 '2026-09-19T00:00:00Z', '2026-09-19T00:00:00Z',
                 '2026-09-19T00:00:00Z', '2026-09-19T00:00:00Z'
             );
             INSERT INTO artifacts (
                 artifact_id, uri, media_type, sensitivity, origin_kind,
                 origin_task_id, origin_program_hash, origin_node_id,
                 origin_binding_id, origin_provider_id, integrity_state,
                 created_at
             ) VALUES (
                 'artifact-output', 'artifact://completion/output',
                 'application/json', 'local', 'provider', 'T-completion',
                 'sha256:1111111111111111111111111111111111111111111111111111111111111111',
                 'node-completion', 'binding-completion', 'provider:test',
                 'verified', '2026-09-19T00:00:00Z'
             );
             INSERT INTO artifact_output_allocations (
                 allocation_id, task_id, semantic_program_hash, node_id,
                 binding_id, attempt_id, sensitivity, retention, state,
                 publication_id, published_artifact_id, created_at, expires_at
             ) VALUES (
                 'allocation-completion', 'T-completion',
                 'sha256:1111111111111111111111111111111111111111111111111111111111111111',
                 'node-completion', 'binding-completion',
                 'attempt-completion', 'local', 'task', 'PUBLISHED',
                 'publication-completion',
                 'artifact-output', '2026-09-19T00:00:00Z',
                 '2026-09-20T00:00:00Z'
             );
             INSERT INTO task_artifacts (
                 task_id, artifact_id, role, node_id, added_at
             ) VALUES (
                 'T-completion', 'artifact-output', 'output',
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
    manager
        .connection
        .execute(
            "INSERT INTO artifact_publications (
                 publication_id, allocation_id, task_id, artifact_id,
                 request_json, state, requested_at, committed_at
             ) VALUES (
                 'publication-completion', 'allocation-completion',
                 'T-completion', 'artifact-output', '{}', ?1,
                 '2026-09-19T00:00:00Z',
                 CASE WHEN ?1 = 'COMMITTED' THEN '2026-09-19T00:00:00Z' END
             )",
            [publication_state],
        )
        .unwrap();
    manager
        .connection
        .execute(
            "INSERT OR IGNORE INTO registry_snapshots (snapshot_id, manifest_json, created_at) VALUES (?1, '{}', '2026-09-19T00:00:00Z')",
            [verification_snapshot],
        )
        .unwrap();
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

    let result = manager
        .transition(&completion_request("tr-completion-valid"))
        .unwrap();
    assert!(result.applied);
    assert_eq!(result.current_state, Some(TaskState::Completed));
    assert_eq!(result.current_revision, Some(3));
    assert!(manager.verify_provenance("T-completion").unwrap());
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
        assert_eq!(result.reason_code, "TASK_COMPLETION_GATE_FAILED", "{name}");
        let task = manager.get_task("T-completion").unwrap().unwrap();
        assert_eq!((task.state, task.revision), (TaskState::Verifying, 2));
    }
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
                 'sha256:1111111111111111111111111111111111111111111111111111111111111111',
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
                 'sha256:1111111111111111111111111111111111111111111111111111111111111111',
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
        "TASK_COMPLETION_GATE_FAILED"
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
        "TASK_COMPLETION_GATE_FAILED"
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
    assert_eq!(
        live_attempt
            .transition(&request(
                "tr-live-failed",
                "T-live-failure",
                1,
                TaskState::Created,
                TaskState::Failed,
            ))
            .unwrap()
            .reason_code,
        "TASK_TRANSITION_GUARD_FAILED"
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
                 'sha256:1111111111111111111111111111111111111111111111111111111111111111',
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
            "UPDATE tasks SET state = 'RECOVERING', waiting_on_json = '[]' WHERE task_id = 'T-completion';
             UPDATE step_executions SET state = 'READY' WHERE attempt_id = 'attempt-completion';
             DROP TRIGGER execution_bindings_no_update;
             UPDATE execution_bindings SET grant_refs_json = '[\"grant-admission\"]' WHERE binding_id = 'binding-completion';
             INSERT INTO policy_snapshots (snapshot_id, scope_kind, scope_id, policy_language, policy_set_hash, engine_id, engine_version, snapshot_json, created_at) VALUES ('policy-snapshot', 'task', 'T-completion', 'fixture', 'sha256:policy', 'engine:test', '0.1', '{}', '2026-09-19T00:00:00Z');
             INSERT INTO authority_requests (request_id, task_id, semantic_program_hash, registry_snapshot_id, node_id, capability, principal_kind, principal_id, execution_binding_id, attempt_id, action, resolved_resource_kind, resolved_resource_id, request_json, requested_at) VALUES ('authority-admission', 'T-completion', 'sha256:1111111111111111111111111111111111111111111111111111111111111111', 'snapshot-completion', 'node-completion', 'test.complete@1', 'provider', 'provider:test', 'binding-completion', 'attempt-completion', 'test.execute', 'resource', 'resource-1', '{}', '2026-09-19T00:00:00Z');
             INSERT INTO policy_decisions (decision_id, authority_request_id, task_id, semantic_program_hash, node_id, principal_kind, principal_id, action, resolved_resource_kind, resolved_resource_id, decision, policy_snapshot_id, reason_codes_json, decision_json, decided_at) VALUES ('decision-admission', 'authority-admission', 'T-completion', 'sha256:1111111111111111111111111111111111111111111111111111111111111111', 'node-completion', 'provider', 'provider:test', 'test.execute', 'resource', 'resource-1', 'ALLOW', 'policy-snapshot', '[]', '{}', '2026-09-19T00:00:00Z');",
        ).unwrap();
        manager.connection.execute(
            "INSERT INTO authority_grants (grant_id, task_id, semantic_program_hash, node_id, capability, principal_kind, principal_id, execution_binding_id, attempt_id, policy_decision_id, policy_snapshot_id, grants_json, scope, max_uses, uses_consumed, state, issued_at, expires_at) VALUES ('grant-admission', 'T-completion', ?1, 'node-completion', 'test.complete@1', 'provider', 'provider:test', 'binding-completion', 'attempt-completion', 'decision-admission', 'policy-snapshot', '[]', 'ONE_SHOT', 1, 0, ?2, '2026-09-19T00:00:00Z', ?3)",
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
    assert_eq!(outcome, "REJECTED");
    assert!(result.is_some());
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
    Connection::open(&path)
        .unwrap()
        .execute(
            "UPDATE task_transitions SET result_json = NULL WHERE transition_id = 'tr-reconstruct'",
            [],
        )
        .unwrap();
    let mut reopened = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
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
         INSERT INTO artifact_publications (publication_id, allocation_id, task_id, artifact_id, request_json, state, requested_at) VALUES ('publication-1', 'allocation-duplicate', 'T-missing', 'artifact-1', '{}', 'PENDING', '2026-09-19T00:00:00Z');
         INSERT INTO artifact_publications (publication_id, allocation_id, task_id, artifact_id, request_json, state, requested_at) VALUES ('publication-2', 'allocation-duplicate', 'T-missing', 'artifact-2', '{}', 'PENDING', '2026-09-19T00:00:00Z');",
    ).unwrap();
    drop(connection);

    assert!(TaskManager::open_with_clock(&path, Box::new(FixedClock)).is_err());
    let connection = Connection::open(&path).unwrap();
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
    assert!(event_ids.verify_provenance(&maximum_task_id).unwrap());
}

#[test]
fn runnable_readiness_uses_each_active_nodes_latest_attempt_once() {
    let mut stale = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut stale, HASH, &["artifact-output"], "COMMITTED");
    stale.connection.execute_batch(
        "UPDATE tasks SET state = 'PLANNING' WHERE task_id = 'T-completion';
         INSERT INTO step_executions (attempt_id, task_id, semantic_program_hash, registry_snapshot_id, node_id, attempt_number, revision, state, outcome_certainty, input_artifacts_json, output_artifacts_json, created_at, updated_at) VALUES ('attempt-ready-old', 'T-completion', 'sha256:1111111111111111111111111111111111111111111111111111111111111111', 'snapshot-completion', 'node-completion', 2, 1, 'READY', 'NOT_STARTED', '[]', '[]', '2026-09-19T00:00:00Z', '2026-09-19T00:00:00Z');
         INSERT INTO step_executions (attempt_id, task_id, semantic_program_hash, registry_snapshot_id, node_id, attempt_number, revision, state, outcome_certainty, input_artifacts_json, output_artifacts_json, created_at, updated_at) VALUES ('attempt-failed-new', 'T-completion', 'sha256:1111111111111111111111111111111111111111111111111111111111111111', 'snapshot-completion', 'node-completion', 3, 1, 'FAILED', 'FAILED_NO_EFFECT', '[]', '[]', '2026-09-19T00:00:00Z', '2026-09-19T00:00:00Z');",
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
    compensated.connection.execute_batch(
        "UPDATE tasks SET state = 'PLANNING', active_step_ids_json = '[\"node-completion\",\"node-missing\"]' WHERE task_id = 'T-completion';
         INSERT INTO step_executions (attempt_id, task_id, semantic_program_hash, registry_snapshot_id, node_id, attempt_number, revision, state, outcome_certainty, input_artifacts_json, output_artifacts_json, created_at, updated_at) VALUES ('attempt-ready-2', 'T-completion', 'sha256:1111111111111111111111111111111111111111111111111111111111111111', 'snapshot-completion', 'node-completion', 2, 1, 'READY', 'NOT_STARTED', '[]', '[]', '2026-09-19T00:00:00Z', '2026-09-19T00:00:00Z');
         INSERT INTO step_executions (attempt_id, task_id, semantic_program_hash, registry_snapshot_id, node_id, attempt_number, revision, state, outcome_certainty, input_artifacts_json, output_artifacts_json, created_at, updated_at) VALUES ('attempt-ready-3', 'T-completion', 'sha256:1111111111111111111111111111111111111111111111111111111111111111', 'snapshot-completion', 'node-completion', 3, 1, 'READY', 'NOT_STARTED', '[]', '[]', '2026-09-19T00:00:00Z', '2026-09-19T00:00:00Z');",
    ).unwrap();
    assert_eq!(
        compensated
            .transition(&request(
                "tr-runnable-no-compensation",
                "T-completion",
                2,
                TaskState::Planning,
                TaskState::Runnable,
            ))
            .unwrap()
            .reason_code,
        "TASK_PROGRAM_NOT_RUNNABLE"
    );
}

#[test]
fn running_and_admission_reject_duplicate_latest_exact_bound_attempts() {
    let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
    seed_completion_fixture(&mut manager, HASH, &["artifact-output"], "COMMITTED");
    manager.connection.execute_batch(
        "UPDATE tasks SET state = 'RECOVERING' WHERE task_id = 'T-completion';
         UPDATE step_executions SET state = 'READY', outcome_certainty = 'NOT_STARTED' WHERE attempt_id = 'attempt-completion';
         INSERT INTO execution_bindings (binding_id, attempt_id, task_id, semantic_program_hash, registry_snapshot_id, ir_version, node_id, capability, provider_id, provider_version, attempt, policy_decision_refs_json, grant_refs_json, execution_profile_ref, placement_json, binding_json, created_at) VALUES ('binding-duplicate-latest', 'attempt-duplicate-latest', 'T-completion', 'sha256:1111111111111111111111111111111111111111111111111111111111111111', 'snapshot-completion', '0.1', 'node-completion', 'test.complete', 'provider:test', '0.1.0', 2, '[]', '[]', 'profile:test', '{}', '{}', '2026-09-19T00:00:00Z');
         INSERT INTO step_executions (attempt_id, task_id, semantic_program_hash, registry_snapshot_id, node_id, binding_id, provider_id, provider_version, attempt_number, revision, state, outcome_certainty, input_artifacts_json, output_artifacts_json, created_at, updated_at) VALUES ('attempt-duplicate-latest', 'T-completion', 'sha256:1111111111111111111111111111111111111111111111111111111111111111', 'snapshot-completion', 'node-completion', 'binding-duplicate-latest', 'provider:test', '0.1.0', 1, 1, 'READY', 'NOT_STARTED', '[]', '[]', '2026-09-19T00:00:00Z', '2026-09-19T00:00:00Z');",
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
        .map(|index| format!("operation-{index:03}"))
        .collect::<Vec<_>>();
    assert_eq!(resolved.len(), 140);
    assert_eq!(resolved, expected);
}
