//! Ordinary-crate exercise of the trusted local export boundary.

use std::io::Cursor;

use aios_contracts::{CapabilityContract, ContractRef, TypeContract};
use aios_registry::{
    ProviderTrustStatus, RegistryBuildOptions, SemanticRegistry, SnapshotHashEntry,
};
use aios_task_manager::{
    Actor, ArtifactOriginKind, CompletedLocalExportReference, CreateTask, ImportArtifactRequest,
    LocalExportProposal, RetentionClass, Sensitivity, TaskManager, TaskManagerError, TaskState,
    TrustedLocalCoordinator,
};
use rusqlite::{Connection, OpenFlags};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const SUITE_HASH: &str = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
const BUILD_HASH: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SOURCE: &[u8] = b"exact private export bytes\n";

fn source_hash() -> String {
    let mut value = String::from("sha256:");
    for byte in Sha256::digest(SOURCE) {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").unwrap();
    }
    value
}

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
    reason = "keeps the public admission and export sequence visible in one test"
)]
fn public_coordinator_requires_real_approval_and_exports_exact_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let db = directory.path().join("coordinator.sqlite3");
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
        "schema_version":"0.1", "result_id":"evidence:public-exact-export",
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
    // Catalog identity is immutable: a changed adapter cannot take over the
    // same service, even when the destination class is unchanged.
    assert!(
        coordinator
            .register_export_service(
                "service://fixture/exact",
                "fixture_remote",
                "adapter:substitute",
            )
            .is_err()
    );
    assert!(
        coordinator
            .register_export_service("service://fixture/exact", "fixture_remote", "adapter:exact",)
            .is_err()
    );
    coordinator
        .register_export_service(
            "service://fixture/second",
            "fixture_remote",
            "adapter:second",
        )
        .unwrap();
    let long_service = format!("service://{}", "s".repeat(502));
    assert_eq!(long_service.chars().count(), 512);
    coordinator
        .register_export_service(&long_service, "fixture_remote", "adapter:long")
        .unwrap();
    assert!(
        coordinator
            .register_export_service(
                &format!("{long_service}s"),
                "fixture_remote",
                "adapter:longer"
            )
            .is_err()
    );
    let unicode_service = format!("service://{}", "é".repeat(502));
    assert_eq!(unicode_service.chars().count(), 512);
    assert!(unicode_service.len() > 512);
    coordinator
        .register_export_service(&unicode_service, "fixture_remote", "adapter:unicode")
        .unwrap();
    assert!(
        coordinator
            .register_export_service(
                &format!("{unicode_service}é"),
                "fixture_remote",
                "adapter:too-long"
            )
            .is_err()
    );
    coordinator.activate_policy(json!({"schema_version":"0.1","rules":[
        {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"private"},
        {"effect":"ALLOW","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"},
        {"effect":"REQUIRE_APPROVAL","action":"data.egress","resource_kind":"external-destination","sensitivity":"private"}
    ]}).to_string().as_bytes()).unwrap();

    let proposal = proposal(
        registry.snapshot_id(),
        &registration.registration_id,
        &contract_hash,
    );
    let prepared = coordinator
        .prepare_local_export(&proposal, &mut Cursor::new(SOURCE))
        .unwrap();
    let mut substituted_service = crate::proposal(
        registry.snapshot_id(),
        &registration.registration_id,
        &contract_hash,
    );
    substituted_service.service_id = "service://fixture/second".into();
    let conflict = coordinator
        .prepare_local_export(&substituted_service, &mut Cursor::new(&[]))
        .err()
        .expect("same candidate must reject a same-class service change");
    assert!(matches!(
        conflict,
        TaskManagerError::InvalidRecord("authority candidate reservation is not admissible")
    ));
    assert_eq!(
        coordinator
            .memory_export_observation("service://fixture/second")
            .unwrap()
            .opens,
        0
    );
    let replayed_prepare = coordinator
        .prepare_local_export(&proposal, &mut Cursor::new(&[]))
        .unwrap();
    assert!(prepared.approval_id().is_some());
    assert_eq!(replayed_prepare.approval_id(), prepared.approval_id());
    let prompt = coordinator
        .approval_prompt(
            &replayed_prepare,
            prepared.approval_id().unwrap(),
            "user:test",
        )
        .unwrap();
    assert_eq!(prompt["destination"]["service_id"], proposal.service_id);
    assert_eq!(prompt["export"]["operation_id"], proposal.operation_id);
    assert_eq!(prompt["export"]["source_content_hash"], source_hash());
    assert_eq!(prompt["export"]["purpose"], proposal.purpose);
    assert_eq!(prompt["export"]["max_size_bytes"], proposal.max_size_bytes);
    assert_eq!(prompt["export"]["adapter_id"], "adapter:exact");
    assert_eq!(prompt["resource"]["sensitivity"], "private");
    assert_eq!(prompt["principal"]["id"], registration.provider_id);
    let readonly_prompt =
        Connection::open_with_flags(&db, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let descriptor: String = readonly_prompt
        .query_row(
            "SELECT descriptor_hash FROM authority_candidate_export_pins WHERE candidate_id=?1",
            [&proposal.candidate_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(prompt["export"]["descriptor_hash"], descriptor);
    let replay_reference = serde_json::to_vec(&prepared.replay_reference()).unwrap();
    assert_eq!(
        coordinator
            .memory_export_observation("service://fixture/exact")
            .unwrap()
            .opens,
        0
    );
    coordinator
        .decide_approval(&prepared, "user:test", true)
        .unwrap();
    let approved_replay = coordinator
        .prepare_local_export(&proposal, &mut Cursor::new(&[]))
        .unwrap();
    assert_eq!(approved_replay.approval_ids(), prepared.approval_ids());
    let execution = coordinator.start_local_export(&prepared).unwrap();
    let replayed_start = coordinator.start_local_export(&prepared).unwrap();
    assert_eq!(
        coordinator
            .memory_export_observation("service://fixture/exact")
            .unwrap()
            .opens,
        0
    );
    assert_eq!(
        coordinator.export_local_artifact(&execution).unwrap(),
        SOURCE.len() as u64
    );
    let captured = coordinator
        .memory_export_observation("service://fixture/exact")
        .unwrap();
    assert_eq!(
        (
            captured.opens,
            captured.finalizes,
            captured.completed_size_bytes
        ),
        (1, 1, SOURCE.len() as u64)
    );
    assert_eq!(
        captured.completed_sha256.as_deref(),
        Some(source_hash().as_str())
    );
    assert_eq!(
        coordinator
            .replay_local_artifact_export(&replayed_start)
            .unwrap(),
        SOURCE.len() as u64
    );
    assert_eq!(
        coordinator
            .memory_export_observation("service://fixture/exact")
            .unwrap()
            .opens,
        1
    );

    let readonly = Connection::open_with_flags(&db, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let grants: i64 = readonly
        .query_row(
            "SELECT COUNT(*) FROM authority_grants WHERE task_id=?1",
            [&proposal.task.task_id],
            |row| row.get(0),
        )
        .unwrap();
    let consumed_egress: i64 = readonly.query_row(
        "SELECT COUNT(*) FROM authority_grants WHERE task_id=?1 AND state='CONSUMED' AND grants_json LIKE '%data.egress%'",
        [&proposal.task.task_id], |row| row.get(0)).unwrap();
    let issuance: i64 = readonly
        .query_row(
            "SELECT COUNT(*) FROM authority_issuance_receipts WHERE task_id=?1",
            [&proposal.task.task_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!((grants, issuance), (3, 3));
    assert_eq!(consumed_egress, 1);
    let substituted_grants: i64 = readonly.query_row(
        "SELECT COUNT(*) FROM authority_grants WHERE task_id=?1 AND grants_json LIKE '%service://fixture/second%'",
        [&proposal.task.task_id], |row| row.get(0)).unwrap();
    let substituted_operations: i64 = readonly.query_row(
        "SELECT COUNT(*) FROM operations WHERE task_id=?1 AND details_json LIKE '%service://fixture/second%'",
        [&proposal.task.task_id], |row| row.get(0)).unwrap();
    assert_eq!((substituted_grants, substituted_operations), (0, 0));
    let creation_events: i64 = readonly
        .query_row(
            "SELECT COUNT(*) FROM provenance_events WHERE task_id=?1 AND event_type='task.created'",
            [&proposal.task.task_id],
            |row| row.get(0),
        )
        .unwrap();
    let candidate_count: i64 = readonly
        .query_row(
            "SELECT COUNT(*) FROM authority_candidate_reservations WHERE candidate_id=?1",
            [&proposal.candidate_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!((creation_events, candidate_count), (1, 1));
    let exported_events: Vec<String> = readonly
        .prepare("SELECT event_json FROM provenance_events WHERE task_id=?1 AND event_type='artifact.exported'")
        .unwrap()
        .query_map([&proposal.task.task_id], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(exported_events.len(), 1);
    let exported: Value = serde_json::from_str(&exported_events[0]).unwrap();
    assert_eq!(
        exported["external_transfer"]["destination"],
        "service://fixture/exact"
    );
    let pin = &exported["details"]["export_authority"];
    assert_eq!(pin["service_id"], "service://fixture/exact");
    assert_eq!(pin["destination_class"], "fixture_remote");
    assert_eq!(pin["adapter_id"], "adapter:exact");
    assert_eq!(pin["operation_id"], proposal.operation_id);
    let task_state: String = readonly
        .query_row(
            "SELECT state FROM tasks WHERE task_id=?1",
            [&proposal.task.task_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(task_state, "RUNNING");
    let waiting_on: String = readonly
        .query_row(
            "SELECT waiting_on_json FROM tasks WHERE task_id=?1",
            [&proposal.task.task_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(waiting_on, "[]");

    let mut long_destination = fresh_proposal(
        registry.snapshot_id(),
        &registration.registration_id,
        &contract_hash,
        "long-service",
    );
    long_destination.service_id.clone_from(&long_service);
    let long_prepared = coordinator
        .prepare_local_export(&long_destination, &mut Cursor::new(SOURCE))
        .unwrap();
    coordinator
        .decide_approval(&long_prepared, "user:test", true)
        .unwrap();
    let long_execution = coordinator.start_local_export(&long_prepared).unwrap();
    assert_eq!(
        coordinator.export_local_artifact(&long_execution).unwrap(),
        SOURCE.len() as u64
    );
    assert_eq!(
        coordinator
            .memory_export_observation(&long_service)
            .unwrap()
            .opens,
        1
    );

    let mut unicode_destination = fresh_proposal(
        registry.snapshot_id(),
        &registration.registration_id,
        &contract_hash,
        "unicode-service",
    );
    unicode_destination.service_id.clone_from(&unicode_service);
    let unicode_prepared = coordinator
        .prepare_local_export(&unicode_destination, &mut Cursor::new(SOURCE))
        .unwrap();
    coordinator
        .decide_approval(&unicode_prepared, "user:test", true)
        .unwrap();
    let unicode_execution = coordinator.start_local_export(&unicode_prepared).unwrap();
    assert_eq!(
        coordinator
            .export_local_artifact(&unicode_execution)
            .unwrap(),
        SOURCE.len() as u64
    );
    assert_eq!(
        coordinator
            .memory_export_observation(&unicode_service)
            .unwrap()
            .opens,
        1
    );

    // Three independently required approvals remain visible as Task blockers.
    // Finalization cannot issue grants after just one or two decisions.
    coordinator.activate_policy(json!({"schema_version":"0.1","rules":[
        {"effect":"REQUIRE_APPROVAL","action":"artifact.read","resource_kind":"artifact","sensitivity":"private"},
        {"effect":"REQUIRE_APPROVAL","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"},
        {"effect":"REQUIRE_APPROVAL","action":"data.egress","resource_kind":"external-destination","sensitivity":"private"}
    ]}).to_string().as_bytes()).unwrap();
    let multi = fresh_proposal(
        registry.snapshot_id(),
        &registration.registration_id,
        &contract_hash,
        "multi-approval",
    );
    let multi_prepared = coordinator
        .prepare_local_export(&multi, &mut Cursor::new(SOURCE))
        .unwrap();
    assert_eq!(multi_prepared.approval_ids().len(), 3);
    assert_eq!(
        coordinator
            .memory_export_observation("service://fixture/exact")
            .unwrap()
            .opens,
        1
    );
    let stored_waiting: String = readonly
        .query_row(
            "SELECT waiting_on_json FROM tasks WHERE task_id=?1",
            [&multi.task.task_id],
            |r| r.get(0),
        )
        .unwrap();
    let blockers: Value = serde_json::from_str(&stored_waiting).unwrap();
    assert_eq!(blockers.as_array().unwrap().len(), 3);
    for id in multi_prepared.approval_ids() {
        let prompt = coordinator
            .approval_prompt(&multi_prepared, id, "user:test")
            .unwrap();
        assert_eq!(prompt["approval_id"], id.as_str());
        assert_eq!(prompt["task_id"], multi.task.task_id);
        assert!(
            coordinator
                .approval_prompt(&multi_prepared, id, "user:other")
                .is_err()
        );
    }
    assert!(
        coordinator
            .approval_prompt(&prepared, &multi_prepared.approval_ids()[0], "user:test")
            .is_err()
    );
    assert!(
        coordinator
            .decide_approval_for(
                &multi_prepared,
                &multi_prepared.approval_ids()[0],
                "user:other",
                true
            )
            .is_err()
    );
    assert!(
        coordinator
            .decide_approval(&multi_prepared, "user:test", true)
            .is_err()
    );
    for id in &multi_prepared.approval_ids()[..2] {
        coordinator
            .decide_approval_for(&multi_prepared, id, "user:test", true)
            .unwrap();
        let replay = coordinator
            .prepare_local_export(&multi, &mut Cursor::new(&[]))
            .unwrap();
        assert_eq!(replay.approval_ids(), multi_prepared.approval_ids());
        assert!(coordinator.start_local_export(&multi_prepared).is_err());
    }
    coordinator
        .decide_approval_for(
            &multi_prepared,
            &multi_prepared.approval_ids()[2],
            "user:test",
            true,
        )
        .unwrap();
    let replayed_multi = coordinator
        .prepare_local_export(&multi, &mut Cursor::new(&[]))
        .unwrap();
    assert_eq!(replayed_multi.approval_ids(), multi_prepared.approval_ids());
    coordinator
        .withdraw_approval(
            &replayed_multi,
            &multi_prepared.approval_ids()[2],
            "user:test",
        )
        .unwrap();
    coordinator
        .withdraw_approval(
            &multi_prepared,
            &multi_prepared.approval_ids()[2],
            "user:test",
        )
        .unwrap();
    assert!(coordinator.start_local_export(&multi_prepared).is_err());
    assert!(
        coordinator
            .cancel_local_export(&multi_prepared, "user:other", "transition:foreign-multi")
            .is_err()
    );
    coordinator
        .cancel_local_export(&multi_prepared, "user:test", "transition:cancel-multi")
        .unwrap();
    coordinator
        .cancel_task(&multi.task.task_id, "user:test", "transition:cancel-multi")
        .unwrap();
    assert_eq!(
        coordinator
            .memory_export_observation("service://fixture/exact")
            .unwrap()
            .opens,
        1
    );

    let all = fresh_proposal(
        registry.snapshot_id(),
        &registration.registration_id,
        &contract_hash,
        "multi-all",
    );
    let all_prepared = coordinator
        .prepare_local_export(&all, &mut Cursor::new(SOURCE))
        .unwrap();
    assert_eq!(all_prepared.approval_ids().len(), 3);
    for id in all_prepared.approval_ids().iter().rev() {
        coordinator
            .decide_approval_for(&all_prepared, id, "user:test", true)
            .unwrap();
    }
    let all_replayed = coordinator
        .prepare_local_export(&all, &mut Cursor::new(&[]))
        .unwrap();
    assert_eq!(all_replayed.approval_ids(), all_prepared.approval_ids());
    let all_execution = coordinator.start_local_export(&all_replayed).unwrap();
    assert_eq!(
        coordinator.export_local_artifact(&all_execution).unwrap(),
        SOURCE.len() as u64
    );
    assert_eq!(
        coordinator
            .memory_export_observation("service://fixture/exact")
            .unwrap()
            .opens,
        2
    );

    // The owner can cancel after issuance but before the first effect; this
    // revokes all grants and fences the already returned execution handle.
    coordinator.activate_policy(json!({"schema_version":"0.1","rules":[
        {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"private"},
        {"effect":"ALLOW","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"},
        {"effect":"REQUIRE_APPROVAL","action":"data.egress","resource_kind":"external-destination","sensitivity":"private"}
    ]}).to_string().as_bytes()).unwrap();
    let to_cancel = fresh_proposal(
        registry.snapshot_id(),
        &registration.registration_id,
        &contract_hash,
        "cancel-issued",
    );
    let cancellable = coordinator
        .prepare_local_export(&to_cancel, &mut Cursor::new(SOURCE))
        .unwrap();
    coordinator
        .decide_approval(&cancellable, "user:test", true)
        .unwrap();
    let cancelled_execution = coordinator.start_local_export(&cancellable).unwrap();
    coordinator
        .cancel_local_export(&cancellable, "user:test", "transition:cancel-issued")
        .unwrap();
    let revoked_count: i64 = readonly
        .query_row(
            "SELECT COUNT(*) FROM authority_grants WHERE task_id=?1 AND state='REVOKED'",
            [&to_cancel.task.task_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(revoked_count, 3);
    assert!(
        coordinator
            .cancel_task(
                &to_cancel.task.task_id,
                "user:other",
                "transition:foreign-cancel"
            )
            .is_err()
    );
    assert!(
        coordinator
            .export_local_artifact(&cancelled_execution)
            .is_err()
    );
    assert_eq!(
        coordinator
            .memory_export_observation("service://fixture/exact")
            .unwrap()
            .opens,
        2
    );
    let withdrawal = fresh_proposal(
        registry.snapshot_id(),
        &registration.registration_id,
        &contract_hash,
        "withdraw-issued",
    );
    let withdraw_prepared = coordinator
        .prepare_local_export(&withdrawal, &mut Cursor::new(SOURCE))
        .unwrap();
    coordinator
        .decide_approval(&withdraw_prepared, "user:test", true)
        .unwrap();
    let withdraw_execution = coordinator.start_local_export(&withdraw_prepared).unwrap();
    coordinator
        .withdraw_approval(
            &withdraw_prepared,
            withdraw_prepared.approval_id().unwrap(),
            "user:test",
        )
        .unwrap();
    assert!(
        coordinator
            .export_local_artifact(&withdraw_execution)
            .is_err()
    );
    let withdrawn_state: String = readonly
        .query_row(
            "SELECT state FROM tasks WHERE task_id=?1",
            [&withdrawal.task.task_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(withdrawn_state, "RUNNABLE");
    coordinator
        .cancel_task(
            &withdrawal.task.task_id,
            "user:test",
            "transition:cancel-withdrawn",
        )
        .unwrap();
    assert_eq!(
        coordinator
            .memory_export_observation("service://fixture/exact")
            .unwrap()
            .opens,
        2
    );

    let unaffected = fresh_proposal(
        registry.snapshot_id(),
        &registration.registration_id,
        &contract_hash,
        "unaffected",
    );
    let unaffected_prepared = coordinator
        .prepare_local_export(&unaffected, &mut Cursor::new(SOURCE))
        .unwrap();
    coordinator
        .decide_approval(&unaffected_prepared, "user:test", true)
        .unwrap();
    let unaffected_execution = coordinator
        .start_local_export(&unaffected_prepared)
        .unwrap();
    assert_eq!(
        coordinator
            .export_local_artifact(&unaffected_execution)
            .unwrap(),
        SOURCE.len() as u64
    );
    assert_eq!(
        coordinator
            .memory_export_observation("service://fixture/exact")
            .unwrap()
            .opens,
        3
    );
    let prior_grants: i64 = readonly
        .query_row(
            "SELECT COUNT(*) FROM authority_grants WHERE task_id=?1 AND state='ACTIVE'",
            [&proposal.task.task_id],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        coordinator
            .cancel_task(
                &proposal.task.task_id,
                "user:test",
                "transition:cancel-active"
            )
            .is_err()
    );
    let retained_grants: i64 = readonly
        .query_row(
            "SELECT COUNT(*) FROM authority_grants WHERE task_id=?1 AND state='ACTIVE'",
            [&proposal.task.task_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(retained_grants, prior_grants);
    let still_running: String = readonly
        .query_row(
            "SELECT state FROM tasks WHERE task_id=?1",
            [&proposal.task.task_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(still_running, "RUNNING");
    assert_eq!(
        coordinator
            .memory_export_observation("service://fixture/exact")
            .unwrap()
            .opens,
        3
    );
    let lost_handle = fresh_proposal(
        registry.snapshot_id(),
        &registration.registration_id,
        &contract_hash,
        "lost-handle",
    );
    let _ = coordinator
        .prepare_local_export(&lost_handle, &mut Cursor::new(SOURCE))
        .unwrap();
    drop(readonly);
    drop(coordinator);
    let reopened = TaskManager::open(&db).unwrap();
    assert_eq!(
        reopened
            .get_task(&proposal.task.task_id)
            .unwrap()
            .unwrap()
            .state,
        TaskState::Recovering
    );
    assert!(reopened.verify_provenance(&proposal.task.task_id).unwrap());
    assert!(reopened.provenance_count(&proposal.task.task_id).unwrap() >= 5);
    let mut restarted = TrustedLocalCoordinator::from_manager(reopened);
    restarted
        .cancel_task(
            &lost_handle.task.task_id,
            "user:test",
            "transition:cancel-lost-handle",
        )
        .unwrap();
    restarted
        .cancel_task(
            &lost_handle.task.task_id,
            "user:test",
            "transition:cancel-lost-handle",
        )
        .unwrap();
    restarted
        .register_export_service("service://fixture/exact", "fixture_remote", "adapter:exact")
        .unwrap();
    let reference: CompletedLocalExportReference =
        serde_json::from_slice(&replay_reference).unwrap();
    assert_eq!(
        restarted.replay_completed_local_export(&reference).unwrap(),
        SOURCE.len() as u64
    );
    for (field, replacement) in [
        ("service_id", "service://fixture/other"),
        ("candidate_id", "candidate:other"),
        ("operation_id", "export:other"),
        ("purpose", "other purpose"),
        ("source_artifact_id", "artifact:other"),
        ("source_selector", "input:other"),
        ("destination_selector", "destination:other"),
    ] {
        let mut changed: Value = serde_json::from_slice(&replay_reference).unwrap();
        changed[field] = json!(replacement);
        let substituted: CompletedLocalExportReference = serde_json::from_value(changed).unwrap();
        assert!(
            restarted
                .replay_completed_local_export(&substituted)
                .is_err(),
            "{field}"
        );
    }
    assert_eq!(
        restarted
            .memory_export_observation("service://fixture/exact")
            .unwrap()
            .opens,
        0
    );

    for denied in [
        "wrong-service",
        "local-only",
        "missing-import-id",
        "invalid-ir",
        "policy-deny",
    ] {
        let mut denied_proposal = fresh_proposal(
            registry.snapshot_id(),
            &registration.registration_id,
            &contract_hash,
            denied,
        );
        match denied {
            "wrong-service" => denied_proposal.service_id = "service://fixture/unregistered".into(),
            "local-only" => denied_proposal.constraints["privacy"] = json!("local-only"),
            "missing-import-id" => denied_proposal.import.import_id = None,
            "invalid-ir" => {
                let mut invalid: Value =
                    serde_json::from_slice(&denied_proposal.program_json).unwrap();
                invalid["nodes"][0]["operation"]["capability"] = json!("unknown.copy@1");
                denied_proposal.program_json = invalid.to_string().into_bytes();
            }
            "policy-deny" => {
                restarted.activate_policy(json!({"schema_version":"0.1","rules":[
                    {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"private"},
                    {"effect":"ALLOW","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"},
                    {"effect":"DENY","action":"data.egress","resource_kind":"external-destination","sensitivity":"private"}
                ]}).to_string().as_bytes()).unwrap();
            }
            _ => unreachable!(),
        }
        let error = restarted
            .prepare_local_export(&denied_proposal, &mut Cursor::new(SOURCE))
            .err()
            .expect("denied proposal must fail");
        let expected = if denied == "invalid-ir" {
            "initial semantic program admission is not admissible"
        } else {
            "ARTIFACT_AUTHORITY_DENIED"
        };
        assert!(
            matches!(error, TaskManagerError::InvalidRecord(reason) if reason == expected),
            "{denied}"
        );
        assert_eq!(
            restarted
                .memory_export_observation("service://fixture/exact")
                .unwrap()
                .opens,
            0,
            "{denied}"
        );
        let readonly = Connection::open_with_flags(&db, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        let grants: i64 = readonly
            .query_row(
                "SELECT COUNT(*) FROM authority_grants WHERE task_id=?1",
                [&denied_proposal.task.task_id],
                |row| row.get(0),
            )
            .unwrap();
        let operations: i64 = readonly
            .query_row(
                "SELECT COUNT(*) FROM operations WHERE operation_id=?1",
                [&denied_proposal.operation_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!((grants, operations), (0, 0), "{denied}");
        if denied == "missing-import-id" {
            let tasks: i64 = readonly
                .query_row(
                    "SELECT COUNT(*) FROM tasks WHERE task_id=?1",
                    [&denied_proposal.task.task_id],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(tasks, 0);
        }
    }

    restarted.activate_policy(json!({"schema_version":"0.1","rules":[
        {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"private"},
        {"effect":"ALLOW","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"},
        {"effect":"REQUIRE_APPROVAL","action":"data.egress","resource_kind":"external-destination","sensitivity":"private"}
    ]}).to_string().as_bytes()).unwrap();
    let disabled_proposal = fresh_proposal(
        registry.snapshot_id(),
        &registration.registration_id,
        &contract_hash,
        "disabled",
    );
    let disabled_prepared = restarted
        .prepare_local_export(&disabled_proposal, &mut Cursor::new(SOURCE))
        .unwrap();
    restarted
        .decide_approval(&disabled_prepared, "user:test", true)
        .unwrap();
    let retained_execution = restarted.start_local_export(&disabled_prepared).unwrap();
    restarted
        .disable_export_service("service://fixture/exact")
        .unwrap();
    assert!(
        restarted
            .export_local_artifact(&retained_execution)
            .is_err()
    );
    assert_eq!(
        restarted
            .memory_export_observation("service://fixture/exact")
            .unwrap()
            .opens,
        0
    );
    let readonly = Connection::open_with_flags(&db, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let before_cancel: String = readonly
        .query_row(
            "SELECT state FROM tasks WHERE task_id=?1",
            [&disabled_proposal.task.task_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(before_cancel, "RUNNABLE");
    restarted
        .cancel_task(
            &disabled_proposal.task.task_id,
            "user:test",
            "transition:cancel-disabled",
        )
        .unwrap();
    let after_cancel: String = readonly
        .query_row(
            "SELECT state FROM tasks WHERE task_id=?1",
            [&disabled_proposal.task.task_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(after_cancel, "CANCELLED");

    restarted
        .register_export_service(
            "service://fixture/corrupt",
            "fixture_remote",
            "adapter:corrupt",
        )
        .unwrap();
    let mut corrupt = fresh_proposal(
        registry.snapshot_id(),
        &registration.registration_id,
        &contract_hash,
        "missing-source",
    );
    corrupt.service_id = "service://fixture/corrupt".into();
    let unique_source = b"unique source removed before export";
    let corrupt_prepared = restarted
        .prepare_local_export(&corrupt, &mut Cursor::new(unique_source))
        .unwrap();
    restarted
        .decide_approval(&corrupt_prepared, "user:test", true)
        .unwrap();
    let corrupt_execution = restarted.start_local_export(&corrupt_prepared).unwrap();
    let root: String = readonly
        .query_row(
            "SELECT canonical_root FROM artifact_store_binding WHERE singleton_id=1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let storage_ref: String = readonly.query_row(
        "SELECT b.storage_ref FROM artifacts a JOIN artifact_blobs b ON b.content_hash=a.content_hash
         JOIN task_artifacts t ON t.artifact_id=a.artifact_id WHERE t.task_id=?1 LIMIT 1",
        [&corrupt.task.task_id], |r| r.get(0)).unwrap();
    let blob_path = std::path::Path::new(&root).join(storage_ref);
    let backup_path = blob_path.with_extension("test-backup");
    std::fs::rename(&blob_path, &backup_path).unwrap();
    std::fs::create_dir(&blob_path).unwrap();
    assert!(restarted.export_local_artifact(&corrupt_execution).is_err());
    let no_effect_task: String = readonly
        .query_row(
            "SELECT state FROM tasks WHERE task_id=?1",
            [&corrupt.task.task_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(no_effect_task, "RUNNING");
    std::fs::remove_dir(&blob_path).unwrap();
    std::fs::rename(&backup_path, &blob_path).unwrap();
    assert_eq!(
        restarted
            .memory_export_observation("service://fixture/corrupt")
            .unwrap()
            .opens,
        0
    );
    let no_effect_step: (String, String) = readonly
        .query_row(
            "SELECT state,outcome_certainty FROM step_executions WHERE attempt_id=?1",
            [&corrupt.attempt_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(no_effect_step, ("FAILED".into(), "FAILED_NO_EFFECT".into()));
    let no_operation: i64 = readonly
        .query_row(
            "SELECT COUNT(*) FROM operations WHERE operation_id=?1",
            [&corrupt.operation_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(no_operation, 0);
    restarted
        .cancel_task(
            &corrupt.task.task_id,
            "user:test",
            "transition:cancel-no-effect",
        )
        .unwrap();
    drop(readonly);
    drop(restarted);
    let recovered = TaskManager::open(&db).unwrap();
    assert_eq!(
        recovered
            .get_task(&corrupt.task.task_id)
            .unwrap()
            .unwrap()
            .state,
        TaskState::Cancelled
    );
    assert!(recovered.verify_provenance(&corrupt.task.task_id).unwrap());
}
