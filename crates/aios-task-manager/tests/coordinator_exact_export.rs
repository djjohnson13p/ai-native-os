//! Ordinary-crate exercise of the trusted local export boundary.

use std::io::{self, Cursor, Write};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use aios_contracts::{CapabilityContract, ContractRef, TypeContract};
use aios_registry::{
    ProviderTrustStatus, RegistryBuildOptions, SemanticRegistry, SnapshotHashEntry,
};
use aios_task_manager::{
    Actor, ArtifactExportWriter, ArtifactOriginKind, CompletedLocalExportReference, CreateTask,
    ImportArtifactRequest, LocalExportProposal, RetentionClass, Sensitivity, TaskManager,
    TaskManagerError, TaskState, TrustedExportAdapter, TrustedLocalCoordinator,
};
use rusqlite::{Connection, OpenFlags};
use serde_json::{Value, json};

const SUITE_HASH: &str = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
const BUILD_HASH: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SOURCE: &[u8] = b"exact private export bytes\n";

#[derive(Default)]
struct ObservedExport {
    opens: AtomicUsize,
    finalizes: AtomicUsize,
    bytes: Mutex<Vec<u8>>,
}

struct CapturingWriter(Arc<ObservedExport>);

impl Write for CapturingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.bytes.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl ArtifactExportWriter for CapturingWriter {
    fn finalize(&mut self) -> io::Result<()> {
        self.0.finalizes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct CapturingAdapter(Arc<ObservedExport>);

impl TrustedExportAdapter for CapturingAdapter {
    fn open(&self) -> io::Result<Box<dyn ArtifactExportWriter>> {
        self.0.opens.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(CapturingWriter(Arc::clone(&self.0))))
    }
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

    let observed = Arc::new(ObservedExport::default());
    let other = Arc::new(ObservedExport::default());
    let second_service = Arc::new(ObservedExport::default());
    let mut coordinator = TrustedLocalCoordinator::from_manager(manager);
    coordinator
        .register_export_service(
            "service://fixture/exact",
            "fixture_remote",
            "adapter:exact",
            Arc::new(CapturingAdapter(Arc::clone(&observed))),
        )
        .unwrap();
    // Catalog identity is immutable: a changed adapter cannot take over the
    // same service, even when the destination class is unchanged.
    assert!(
        coordinator
            .register_export_service(
                "service://fixture/exact",
                "fixture_remote",
                "adapter:substitute",
                Arc::new(CapturingAdapter(Arc::clone(&other)))
            )
            .is_err()
    );
    assert!(
        coordinator
            .register_export_service(
                "service://fixture/exact",
                "fixture_remote",
                "adapter:exact",
                Arc::new(CapturingAdapter(Arc::clone(&other)))
            )
            .is_err()
    );
    assert_eq!(other.opens.load(Ordering::SeqCst), 0);
    coordinator
        .register_export_service(
            "service://fixture/second",
            "fixture_remote",
            "adapter:second",
            Arc::new(CapturingAdapter(Arc::clone(&second_service))),
        )
        .unwrap();
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
    assert_eq!(second_service.opens.load(Ordering::SeqCst), 0);
    let replayed_prepare = coordinator
        .prepare_local_export(&proposal, &mut Cursor::new(&[]))
        .unwrap();
    assert!(prepared.approval_id().is_some());
    assert_eq!(replayed_prepare.approval_id(), prepared.approval_id());
    let replay_reference = serde_json::to_vec(&prepared.replay_reference()).unwrap();
    assert_eq!(observed.opens.load(Ordering::SeqCst), 0);
    coordinator
        .decide_approval(&prepared, "user:test", true)
        .unwrap();
    let execution = coordinator.start_local_export(&prepared).unwrap();
    let replayed_start = coordinator.start_local_export(&prepared).unwrap();
    assert_eq!(observed.opens.load(Ordering::SeqCst), 0);
    assert_eq!(
        coordinator.export_local_artifact(&execution).unwrap(),
        SOURCE.len() as u64
    );
    assert_eq!(observed.opens.load(Ordering::SeqCst), 1);
    assert_eq!(observed.finalizes.load(Ordering::SeqCst), 1);
    assert_eq!(*observed.bytes.lock().unwrap(), SOURCE);
    assert_eq!(other.opens.load(Ordering::SeqCst), 0);
    assert_eq!(second_service.opens.load(Ordering::SeqCst), 0);
    assert_eq!(
        coordinator
            .replay_local_artifact_export(&replayed_start)
            .unwrap(),
        SOURCE.len() as u64
    );
    assert_eq!(observed.opens.load(Ordering::SeqCst), 1);
    assert_eq!(observed.finalizes.load(Ordering::SeqCst), 1);

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
    let restarted_writer = Arc::new(ObservedExport::default());
    let mut restarted = TrustedLocalCoordinator::from_manager(reopened);
    restarted
        .register_export_service(
            "service://fixture/exact",
            "fixture_remote",
            "adapter:exact",
            Arc::new(CapturingAdapter(Arc::clone(&restarted_writer))),
        )
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
    assert_eq!(restarted_writer.opens.load(Ordering::SeqCst), 0);

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
        assert_eq!(restarted_writer.opens.load(Ordering::SeqCst), 0, "{denied}");
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
    assert_eq!(restarted_writer.opens.load(Ordering::SeqCst), 0);
}
