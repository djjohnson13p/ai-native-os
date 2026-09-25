//! Public restart approval admission and exact waiting-state retry.

use super::*;
use crate::{ArtifactOriginKind, RetentionClass, Sensitivity};
use aios_contracts::{CapabilityContract, ContractRef, TypeContract};
use aios_registry::{
    ProviderTrustStatus, RegistryBuildOptions, SemanticRegistry, SnapshotHashEntry,
};
use serde_json::{Value, json};
use std::io::Cursor;

const SUITE_HASH: &str = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
const BUILD_HASH: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SOURCE: &[u8] = b"exact private export bytes\n";

fn admitted_registry() -> (SemanticRegistry, String) {
    let mut snapshot: aios_contracts::RegistrySnapshot = serde_json::from_str(include_str!(
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
    copy.conformance.suite_version = Some("0.1".into());
    copy.conformance.suite_hash = Some(SUITE_HASH.into());
    copy.allowed_effect_classes
        .push(aios_contracts::EffectClass::DataEgress);
    copy.allowed_authority_classes.push("data.egress".into());
    copy.allowed_egress_modes
        .push(aios_contracts::EgressMode::Policy);
    let contract_hash = aios_registry::capability_contract_hash(copy)
        .unwrap()
        .to_string();
    snapshot
        .capability_contracts
        .iter_mut()
        .find(|e| e.id == "artifact.copy")
        .unwrap()
        .content_hash
        .clone_from(&contract_hash);
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
    (
        SemanticRegistry::from_records(snapshot, types, contracts, RegistryBuildOptions::default())
            .unwrap(),
        contract_hash,
    )
}

fn proposal(snapshot_id: &str, registration_id: &str, contract_hash: &str) -> LocalExportProposal {
    let program = json!({
        "ir_version":"0.1", "program_id":"program:exact-export", "kind":"task_graph",
        "inputs":{"source":{"type":"artifact.file@1"}},
        "nodes":[{"id":"copy", "operation":{"kind":"invoke","capability":"artifact.copy@1"},
            "execution_class":"deterministic",
            "inputs":{"source":{"source":"input","name":"source"}},
            "outputs":{"copy":"artifact.file@1"},
            "authority_requests":[
                {"action":"artifact.read","resource":"input:source"},
                {"action":"artifact.write","resource":"task.output"},
                {"action":"data.egress","resource":"destination:fixture_remote"}],
            "egress":{"mode":"policy","destination_classes":["fixture_remote"]},
            "failure":{"on_error":"stop"},"cache":"never"}],
        "outputs":{"copy":{"source":"node","node":"copy","port":"copy"}}
    });
    LocalExportProposal {
        task: CreateTask {
            task_id: "T-public-exact-export".into(),
            principal: Actor {
                kind: "user".into(),
                id: "user:test".into(),
            },
            workspace_id: None,
            original_intent: "Export an exact local artifact".into(),
            normalized_intent: None,
            active_step_ids: vec!["copy".into()],
        },
        constraints: json!({"privacy":"remote-allowed","preserve_inputs":true}),
        admission_id: "admission:public-exact-export".into(),
        plan_id: "plan:public-exact-export".into(),
        plan_json: json!({
            "schema_version":"0.1", "plan_id":"plan:public-exact-export",
            "task_id":"T-public-exact-export", "revision":1,
            "intent":"Export an exact local artifact",
            "nodes":[{"id":"copy", "capability":"artifact.copy", "capability_version":"1",
                "depends_on":[],
                "inputs":[{"name":"source","ref":"input:source","type":"artifact.file@1"}],
                "outputs":[{"name":"copy","type":"artifact.file@1"}]}]
        })
        .to_string()
        .into_bytes(),
        registry_snapshot_id: snapshot_id.into(),
        program_json: program.to_string().into_bytes(),
        import: ImportArtifactRequest {
            schema_version: "0.1".into(),
            import_id: Some("import:public-exact-export".into()),
            task_id: "T-public-exact-export".into(),
            origin_kind: ArtifactOriginKind::User,
            semantic_type: Some("artifact.file@1".into()),
            media_type: "text/plain".into(),
            format: None,
            sensitivity: Sensitivity::Private,
            retention: RetentionClass::Task,
            expires_at: None,
            labels: vec![],
            max_size_bytes: Some(1024),
        },
        candidate_id: "candidate:public-exact-export".into(),
        binding_id: "binding:public-exact-export".into(),
        attempt_id: "attempt:public-exact-export".into(),
        provider_registration_id: registration_id.into(),
        capability_contract_hash: contract_hash.into(),
        node_id: "copy".into(),
        source_selector: "input:source".into(),
        output_allocation_id: "allocation:public-exact-export".into(),
        output_port: "copy".into(),
        service_id: "service://fixture/exact".into(),
        operation_id: "export:public-exact-export".into(),
        purpose: "test exact export".into(),
        max_size_bytes: 1024,
    }
}

fn fresh_proposal(
    snapshot_id: &str,
    registration_id: &str,
    contract_hash: &str,
    label: &str,
) -> LocalExportProposal {
    let mut fresh = proposal(snapshot_id, registration_id, contract_hash);
    let task_id = format!("T-public-export-{label}");
    fresh.task.task_id.clone_from(&task_id);
    fresh.import.task_id.clone_from(&task_id);
    fresh.import.import_id = Some(format!("import:public-export-{label}"));
    fresh.admission_id = format!("admission:public-export-{label}");
    fresh.plan_id = format!("plan:public-export-{label}");
    let mut plan: Value = serde_json::from_slice(&fresh.plan_json).unwrap();
    plan["plan_id"] = json!(fresh.plan_id);
    plan["task_id"] = json!(task_id);
    fresh.plan_json = plan.to_string().into_bytes();
    let mut program: Value = serde_json::from_slice(&fresh.program_json).unwrap();
    program["program_id"] = json!(format!("program:public-export-{label}"));
    fresh.program_json = program.to_string().into_bytes();
    fresh.candidate_id = format!("candidate:public-export-{label}");
    fresh.binding_id = format!("binding:public-export-{label}");
    fresh.attempt_id = format!("attempt:public-export-{label}");
    fresh.output_allocation_id = format!("allocation:public-export-{label}");
    fresh.operation_id = format!("export:public-export-{label}");
    fresh
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "exercises public approval, restart, and exact retry paths"
)]
fn restarted_export_requires_fresh_approval_and_replays_exact_wait() {
    let directory = tempfile::tempdir().unwrap();
    let db = directory.path().join("provider-rebinding.sqlite3");
    let mut manager = TaskManager::open(&db).unwrap();
    let (registry, contract_hash) = admitted_registry();
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
    manifest["provides"][0]["contract"]["capability"] = json!("artifact.copy");
    manifest["provides"][0]["contract"]["contract_hash"] = json!(contract_hash);
    manifest["provides"][0]["conformance"]["suite"] = json!("conformance://artifact.copy/1");
    manifest["provides"][0]["conformance"]["suite_hash"] = json!(SUITE_HASH);
    manifest["provides"][0]["effect_classes"] =
        json!(["ARTIFACT_READ", "ARTIFACT_WRITE", "DATA_EGRESS"]);
    manifest["provides"][0]["authority"]["actions"] =
        json!(["artifact.read", "artifact.write", "data.egress"]);
    let registration = manager
        .provider_store_writer()
        .unwrap()
        .register(
            &registry,
            &serde_json::to_vec(&manifest).unwrap(),
            BUILD_HASH,
            ProviderTrustStatus::LocallyTrusted,
            "2026-09-24T00:00:00Z",
        )
        .unwrap();
    let evidence = json!({
        "schema_version":"0.1", "result_id":"evidence:rebinding",
        "provider_id":registration.provider_id, "provider_version":registration.provider_version,
        "provider_build_identity":{"kind":"build_hash","value":BUILD_HASH},
        "semantic_capability_ref":"artifact.copy@1", "semantic_contract_version":"1.0",
        "semantic_contract_hash":contract_hash,
        "conformance_suite":{"id":"conformance://artifact.copy/1","version":"0.1","hash":SUITE_HASH},
        "harness":{"id":"fixture-harness","version":"1"},
        "result":"pass","tests_total":1,"tests_passed":1,"tests_failed":0,
        "executed_at":"2026-09-24T00:00:00Z","expires_at":"2030-01-01T00:00:00Z"
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
        .enable(&registration.registration_id, "2026-09-24T00:00:00Z")
        .unwrap();
    let mut coordinator = TrustedLocalCoordinator::from_manager(manager);
    coordinator
        .register_export_service("service://fixture/exact", "fixture_remote", "adapter:exact")
        .unwrap();
    coordinator.activate_policy(json!({"schema_version":"0.1","rules":[
        {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"private"},
        {"effect":"ALLOW","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"},
        {"effect":"ALLOW","action":"data.egress","resource_kind":"external-destination","sensitivity":"private"}
    ]}).to_string().as_bytes()).unwrap();

    let proposal = fresh_proposal(
        registry.snapshot_id(),
        &registration.registration_id,
        &contract_hash,
        "rebind",
    );
    let old = coordinator
        .prepare_local_export(&proposal, &mut Cursor::new(SOURCE))
        .unwrap();
    assert!(old.approval_ids().is_empty());
    coordinator.start_local_export(&old).unwrap();
    let previous = old.replay_reference();
    drop(coordinator);
    let restarted = TaskManager::open(&db).unwrap();
    assert_eq!(
        restarted
            .get_task(&proposal.task.task_id)
            .unwrap()
            .unwrap()
            .state,
        TaskState::Planning
    );
    let mut coordinator = TrustedLocalCoordinator::from_manager(restarted);
    coordinator
        .register_export_service("service://fixture/exact", "fixture_remote", "adapter:exact")
        .unwrap();
    coordinator.activate_policy(json!({"schema_version":"0.1","rules":[
        {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"private"},
        {"effect":"ALLOW","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"},
        {"effect":"REQUIRE_APPROVAL","action":"data.egress","resource_kind":"external-destination","sensitivity":"private"}
    ]}).to_string().as_bytes()).unwrap();
    let next = RestartedLocalExportAttempt {
        candidate_id: "candidate:restart-approval-2".into(),
        binding_id: "binding:restart-approval-2".into(),
        attempt_id: "attempt:restart-approval-2".into(),
        output_allocation_id: "allocation:restart-approval-2".into(),
        operation_id: "export:restart-approval-2".into(),
    };
    let prepared = coordinator
        .prepare_restarted_local_export(&previous, &next)
        .unwrap();
    let [approval_id] = prepared.approval_ids() else {
        panic!("expected one fresh approval");
    };
    let approval_id = approval_id.clone();
    assert_eq!(
        coordinator
            .manager
            .get_task(&proposal.task.task_id)
            .unwrap()
            .unwrap()
            .state,
        TaskState::WaitingForAuth
    );
    let prompt = coordinator
        .approval_prompt(&prepared, &approval_id, "user:test")
        .unwrap();
    assert_eq!(prompt["approval_id"], approval_id.as_str());
    let state = |coordinator: &TrustedLocalCoordinator| -> Vec<i64> {
        coordinator
            .manager
            .connection
            .query_row(
                "SELECT (SELECT revision FROM tasks WHERE task_id=?1),
                    (SELECT COUNT(*) FROM task_transitions WHERE task_id=?1),
                    (SELECT COUNT(*) FROM authority_grants WHERE execution_binding_id=?2),
                    (SELECT COUNT(*) FROM approval_requests WHERE task_id=?1),
                    (SELECT COUNT(*) FROM authority_candidate_reservations WHERE task_id=?1),
                    (SELECT COUNT(*) FROM authority_requests WHERE task_id=?1),
                    (SELECT COUNT(*) FROM policy_decisions WHERE task_id=?1),
                    (SELECT COUNT(*) FROM authority_issuance_receipts WHERE task_id=?1)",
                rusqlite::params![proposal.task.task_id, next.binding_id],
                |row| {
                    (0..8)
                        .map(|index| row.get(index))
                        .collect::<rusqlite::Result<Vec<i64>>>()
                },
            )
            .unwrap()
    };
    let before_retry = state(&coordinator);
    assert_eq!(before_retry[2], 0);
    let different = RestartedLocalExportAttempt {
        candidate_id: "candidate:restart-approval-wrong".into(),
        binding_id: "binding:restart-approval-wrong".into(),
        attempt_id: "attempt:restart-approval-wrong".into(),
        output_allocation_id: "allocation:restart-approval-wrong".into(),
        operation_id: "export:restart-approval-wrong".into(),
    };
    assert!(
        coordinator
            .prepare_restarted_local_export(&previous, &different)
            .is_err()
    );
    assert_eq!(state(&coordinator), before_retry);
    let changed_binding = RestartedLocalExportAttempt {
        candidate_id: next.candidate_id.clone(),
        binding_id: "binding:restart-approval-forged".into(),
        attempt_id: next.attempt_id.clone(),
        output_allocation_id: next.output_allocation_id.clone(),
        operation_id: next.operation_id.clone(),
    };
    assert!(
        coordinator
            .prepare_restarted_local_export(&previous, &changed_binding)
            .is_err()
    );
    assert_eq!(state(&coordinator), before_retry);
    let exact = coordinator
        .prepare_restarted_local_export(&previous, &next)
        .unwrap();
    assert_eq!(exact.approval_ids(), prepared.approval_ids());
    assert_eq!(state(&coordinator), before_retry);
    drop(coordinator);
    let restarted_again = TaskManager::open(&db).unwrap();
    assert_eq!(
        restarted_again
            .get_task(&proposal.task.task_id)
            .unwrap()
            .unwrap()
            .state,
        TaskState::Planning
    );
    let mut coordinator = TrustedLocalCoordinator::from_manager(restarted_again);
    coordinator
        .register_export_service("service://fixture/exact", "fixture_remote", "adapter:exact")
        .unwrap();
    let before_second_wait = state(&coordinator);
    assert!(
        coordinator
            .prepare_restarted_local_export(&previous, &changed_binding)
            .is_err()
    );
    assert!(
        coordinator
            .prepare_restarted_local_export(&previous, &different)
            .is_err()
    );
    assert_eq!(state(&coordinator), before_second_wait);
    let prepared = coordinator
        .prepare_restarted_local_export(&previous, &next)
        .unwrap();
    assert_eq!(prepared.approval_ids(), &[approval_id.clone()]);
    assert_eq!(
        coordinator
            .manager
            .get_task(&proposal.task.task_id)
            .unwrap()
            .unwrap()
            .state,
        TaskState::WaitingForAuth
    );
    let after_second_wait = state(&coordinator);
    assert_eq!(after_second_wait[0], before_second_wait[0] + 1);
    assert_eq!(after_second_wait[1], before_second_wait[1] + 1);
    assert_eq!(&after_second_wait[2..], &before_second_wait[2..]);
    let retired: (i64, i64) = coordinator
        .manager
        .connection
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(CASE WHEN state='REVOKED'
             AND revocation_reason_code='AUTHORITY_SESSION_RETIRED'
             AND uses_consumed=0 THEN 1 ELSE 0 END),0)
             FROM authority_grants WHERE execution_binding_id=?1",
            [&previous.binding_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert!(retired.0 > 0);
    assert_eq!(retired.0, retired.1);
    let waiting_ids: Vec<String> = coordinator
        .manager
        .connection
        .prepare(
            "SELECT transition_id FROM task_transitions WHERE task_id=?1
                  AND json_extract(request_json,'$.reason.code')='APPROVAL_REQUIRED'
                  AND outcome='COMMITTED'
                  ORDER BY result_revision",
        )
        .unwrap()
        .query_map([&proposal.task.task_id], |row| row.get(0))
        .unwrap()
        .map(|row| row.unwrap())
        .collect();
    assert_eq!(waiting_ids.len(), 2);
    assert_ne!(waiting_ids[0], waiting_ids[1]);
    let provenance_before_exact: i64 = coordinator
        .manager
        .connection
        .query_row(
            "SELECT COUNT(*) FROM provenance_events WHERE task_id=?1",
            [&proposal.task.task_id],
            |row| row.get(0),
        )
        .unwrap();
    let second_exact = coordinator
        .prepare_restarted_local_export(&previous, &next)
        .unwrap();
    assert_eq!(second_exact.approval_ids(), prepared.approval_ids());
    assert_eq!(state(&coordinator), after_second_wait);
    let provenance_after_exact: i64 = coordinator
        .manager
        .connection
        .query_row(
            "SELECT COUNT(*) FROM provenance_events WHERE task_id=?1",
            [&proposal.task.task_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(provenance_after_exact, provenance_before_exact);
    assert_eq!(
        coordinator
            .approval_prompt(&prepared, &approval_id, "user:test")
            .unwrap(),
        prompt
    );
    coordinator.manager.stop_local_policy_backend();
    assert_eq!(
        coordinator
            .approval_prompt(&prepared, &approval_id, "user:test")
            .unwrap(),
        prompt
    );
    assert!(
        coordinator
            .decide_approval(&prepared, "user:test", true)
            .is_err()
    );
    assert!(coordinator.start_local_export(&prepared).is_err());
    assert_eq!(state(&coordinator)[2], 0);
    assert_eq!(state(&coordinator)[7], before_retry[7]);
    // Simulate corruption below the immutable SQL guard and prove that the
    // read-only prompt path still authenticates the sealed historical bytes.
    let sealed_prompt: String = coordinator
        .manager
        .connection
        .query_row(
            "SELECT request_json FROM approval_requests WHERE approval_id=?1",
            [approval_id.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    let prompt_trigger: String = coordinator.manager.connection.query_row(
        "SELECT sql FROM sqlite_master WHERE type='trigger' AND name='authority_approval_request_immutable'",
        [], |row| row.get(0),
    ).unwrap();
    coordinator
        .manager
        .connection
        .execute_batch("DROP TRIGGER authority_approval_request_immutable")
        .unwrap();
    coordinator
        .manager
        .connection
        .execute(
            "UPDATE approval_requests SET request_json='{}' WHERE approval_id=?1",
            [approval_id.as_str()],
        )
        .unwrap();
    let bad_prompt = coordinator
        .approval_prompt(&prepared, &approval_id, "user:test")
        .unwrap_err();
    assert!(bad_prompt.authority_denial().is_none());
    coordinator
        .manager
        .connection
        .execute(
            "UPDATE approval_requests SET request_json=?2 WHERE approval_id=?1",
            rusqlite::params![&approval_id, sealed_prompt],
        )
        .unwrap();
    coordinator
        .manager
        .connection
        .execute_batch(&prompt_trigger)
        .unwrap();
    let (policy_hash, policy_json): (String, String) = coordinator
        .manager
        .connection
        .query_row(
            "SELECT p.content_hash,p.policy_json FROM authority_policy_payloads p
         JOIN authority_policy_activations a ON a.content_hash=p.content_hash
         ORDER BY a.revision DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let policy_trigger: String = coordinator.manager.connection.query_row(
        "SELECT sql FROM sqlite_master WHERE type='trigger' AND name='authority_policy_payload_no_update'",
        [], |row| row.get(0),
    ).unwrap();
    coordinator
        .manager
        .connection
        .execute_batch("DROP TRIGGER authority_policy_payload_no_update")
        .unwrap();
    coordinator
        .manager
        .connection
        .execute(
            "UPDATE authority_policy_payloads SET policy_json='{}' WHERE content_hash=?1",
            [&policy_hash],
        )
        .unwrap();
    let bad_policy = coordinator
        .approval_prompt(&prepared, &approval_id, "user:test")
        .unwrap_err();
    assert!(bad_policy.authority_denial().is_none());
    coordinator
        .manager
        .connection
        .execute(
            "UPDATE authority_policy_payloads SET policy_json=?2 WHERE content_hash=?1",
            rusqlite::params![policy_hash, policy_json],
        )
        .unwrap();
    coordinator
        .manager
        .connection
        .execute_batch(&policy_trigger)
        .unwrap();
    assert_eq!(
        coordinator
            .approval_prompt(&prepared, &approval_id, "user:test")
            .unwrap(),
        prompt
    );
    coordinator.manager.restart_local_policy_backend();
    coordinator
        .decide_approval(&prepared, "user:test", true)
        .unwrap();
    coordinator.start_local_export(&prepared).unwrap();
    assert_eq!(
        coordinator
            .manager
            .get_task(&proposal.task.task_id)
            .unwrap()
            .unwrap()
            .state,
        TaskState::Runnable
    );
    assert_eq!(state(&coordinator)[2], 3);
}
