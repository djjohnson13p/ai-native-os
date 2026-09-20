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
        retryable: false,
        safe_to_replan: false,
        unknown_side_effects: false,
        rollback_available: false,
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
    assert_eq!(first.reason_code, "TASK_TRANSITION_GUARD_FAILED");
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
    manager.create_task(&create("T-completion")).unwrap();
    manager
        .connection
        .execute_batch(
            "INSERT INTO registry_snapshots (
                 snapshot_id, manifest_json, created_at
             ) VALUES ('snapshot-completion', '{}', '2026-09-19T00:00:00Z');
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
                 status, program_json, created_at
             ) VALUES (
                 'T-completion', 1, 'program-completion', '0.1',
                 'sha256:1111111111111111111111111111111111111111111111111111111111111111',
                 'snapshot-completion', 'validation-completion', 'active', '{}',
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
                 published_artifact_id, created_at, expires_at
             ) VALUES (
                 'allocation-completion', 'T-completion',
                 'sha256:1111111111111111111111111111111111111111111111111111111111111111',
                 'node-completion', 'binding-completion',
                 'attempt-completion', 'local', 'task', 'PUBLISHED',
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
    let transaction = manager.connection.transaction().unwrap();
    let verification = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "event_id": "event:verification:completion",
        "task_id": "T-completion",
        "event_type": "verification.completed",
        "timestamp": "2026-09-19T00:00:00Z",
        "actor": {"kind":"system-service","id":"service:verifier"},
        "semantic_program_hash": verification_hash,
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
