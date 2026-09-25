//! Two real coordinator admissions isolate the Task dimension of a read claim.

use super::*;
use crate::{
    ArtifactOriginKind, AuthorityDenial, AuthorityDenialReason, AuthorityDenialStage,
    RetentionClass, Sensitivity,
};
use aios_contracts::{CapabilityContract, ContractRef, TypeContract};
use aios_registry::{
    ProviderTrustStatus, RegistryBuildOptions, SemanticRegistry, SnapshotHashEntry,
};
use rusqlite::{Connection, OpenFlags};
use serde_json::{Value, json};
use std::io::Cursor;

const SUITE_HASH: &str = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
const BUILD_HASH: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SOURCE: &[u8] = b"exact private export bytes\n";

struct UnusedAdapter;

impl TrustedExportAdapter for UnusedAdapter {
    fn open(&self) -> io::Result<Box<dyn ArtifactExportWriter>> {
        panic!("a denied read claim must never open the export destination")
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
    reason = "keeps both real Task admissions and the wrong-Task claim visible together"
)]
fn grant_used_for_wrong_task_denies_before_read_or_grant_use() {
    let directory = tempfile::tempdir().unwrap();
    let db = directory.path().join("wrong-task.sqlite3");
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
        "schema_version":"0.1", "result_id":"evidence:wrong-task",
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
        .register_export_service(
            "service://fixture/exact",
            "fixture_remote",
            "adapter:exact",
            Arc::new(UnusedAdapter),
        )
        .unwrap();
    coordinator
        .activate_policy(
            json!({"schema_version":"0.1","rules":[
                {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"private"},
                {"effect":"ALLOW","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"},
                {"effect":"ALLOW","action":"data.egress","resource_kind":"external-destination","sensitivity":"private"}
            ]})
            .to_string()
            .as_bytes(),
        )
        .unwrap();

    let a = fresh_proposal(
        registry.snapshot_id(),
        &registration.registration_id,
        &contract_hash,
        "wrong-task-a",
    );
    let b = fresh_proposal(
        registry.snapshot_id(),
        &registration.registration_id,
        &contract_hash,
        "wrong-task-b",
    );
    let prepared_a = coordinator
        .prepare_local_export(&a, &mut Cursor::new(SOURCE))
        .unwrap();
    let prepared_b = coordinator
        .prepare_local_export(&b, &mut Cursor::new(SOURCE))
        .unwrap();
    assert!(prepared_a.approval_id().is_none());
    assert!(prepared_b.approval_id().is_none());
    coordinator.start_local_export(&prepared_a).unwrap();
    coordinator.start_local_export(&prepared_b).unwrap();
    assert_ne!(prepared_a.source_artifact_id, prepared_b.source_artifact_id);
    for task_id in [&a.task.task_id, &b.task.task_id] {
        assert_eq!(
            coordinator
                .manager
                .get_task(task_id)
                .unwrap()
                .unwrap()
                .state,
            TaskState::Running
        );
    }
    let session_b = coordinator
        .manager
        .issue_provider_artifact_session(&b.task.task_id, &b.binding_id)
        .unwrap();
    let readonly = Connection::open_with_flags(&db, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let grant_id_a: String = readonly
        .query_row(
            "SELECT grant_id FROM authority_grants WHERE task_id=?1 AND state='ACTIVE' AND grants_json LIKE '%artifact.read%'",
            [&a.task.task_id],
            |row| row.get(0),
        )
        .unwrap();
    let grant_id_b: String = readonly
        .query_row(
            "SELECT grant_id FROM authority_grants WHERE task_id=?1 AND state='ACTIVE' AND grants_json LIKE '%artifact.read%'",
            [&b.task.task_id],
            |row| row.get(0),
        )
        .unwrap();
    let before: (i64, i64, i64, i64) = readonly
        .query_row(
            "SELECT (SELECT COUNT(*) FROM operations WHERE effect_class='ARTIFACT_READ'),
                    (SELECT COUNT(*) FROM provenance_events WHERE event_type='execution.started'),
                    (SELECT uses_consumed FROM authority_grants WHERE grant_id=?1),
                    (SELECT uses_consumed FROM authority_grants WHERE grant_id=?2)",
            rusqlite::params![grant_id_a, grant_id_b],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(before.0, 0);
    assert_eq!((before.2, before.3), (0, 0));

    let denied = coordinator
        .manager
        .scope_artifact_reads_with_claim(
            &session_b,
            std::slice::from_ref(&prepared_a.source_artifact_id),
            &grant_id_a,
        )
        .expect_err("Task A's genuine grant cannot be claimed by Task B");
    assert!(matches!(
        denied,
        TaskManagerError::AuthorityDenied(AuthorityDenial {
            stage: AuthorityDenialStage::ArtifactAdmission,
            reason: AuthorityDenialReason::GrantTaskMismatch,
        })
    ));
    let after: (i64, i64, i64, i64) = readonly
        .query_row(
            "SELECT (SELECT COUNT(*) FROM operations WHERE effect_class='ARTIFACT_READ'),
                    (SELECT COUNT(*) FROM provenance_events WHERE event_type='execution.started'),
                    (SELECT uses_consumed FROM authority_grants WHERE grant_id=?1),
                    (SELECT uses_consumed FROM authority_grants WHERE grant_id=?2)",
            rusqlite::params![grant_id_a, grant_id_b],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        after, before,
        "denial must create no read admission or grant use"
    );

    let own_scope = coordinator
        .manager
        .scope_artifact_reads_with_claim(
            &session_b,
            std::slice::from_ref(&prepared_b.source_artifact_id),
            &grant_id_b,
        )
        .unwrap();
    let mut own_reader = coordinator
        .manager
        .open_artifact_reader(&own_scope, &prepared_b.source_artifact_id)
        .unwrap();
    let mut bytes = Vec::new();
    own_reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, SOURCE);
    assert_eq!(
        readonly
            .query_row(
                "SELECT COUNT(*) FROM operations WHERE effect_class='ARTIFACT_READ' AND task_id=?1",
                [&b.task.task_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
}
