//! Parser robustness and semantic identity invariants.

use std::collections::BTreeSet;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};

use aios_contracts::{
    CapabilityContract, ContractRef, EffectClass, RegistrySnapshot, TypeContract,
    ValidatorReasonCode,
};
use aios_ir::{ValidationLimits, Validator};
use aios_registry::{
    HashVerificationMode, RegistryBuildOptions, RegistryLoadOptions, SemanticRegistry,
};
use proptest::prelude::*;
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const FIXED_TIME: &str = "2026-09-15T00:00:00Z";

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/aios-ir")
}

fn fixed_time() -> OffsetDateTime {
    OffsetDateTime::parse(FIXED_TIME, &Rfc3339).unwrap()
}

fn validator() -> Validator {
    Validator::new(
        SemanticRegistry::load_bundle(fixture_root(), RegistryLoadOptions::default()).unwrap(),
        ValidationLimits::default(),
    )
}

fn validator_with_inputless_capability() -> Validator {
    const PLACEHOLDER: &str =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let mut snapshot: RegistrySnapshot =
        serde_json::from_value(fixture("registry-snapshot.json")).unwrap();
    let types: Vec<TypeContract> = serde_json::from_value(fixture("type-contracts.json")).unwrap();
    let mut capabilities: Vec<CapabilityContract> =
        serde_json::from_value(fixture("capability-contracts.json")).unwrap();
    let mut inputless = capabilities
        .iter()
        .find(|contract| contract.capability == "text.uppercase")
        .unwrap()
        .clone();
    "text.constant".clone_into(&mut inputless.capability);
    inputless.inputs.clear();
    "conformance://text.constant/1".clone_into(&mut inputless.conformance.suite_id);
    capabilities.push(inputless);
    snapshot.capability_contracts.push(ContractRef {
        id: "text.constant".to_owned(),
        version: "1.0".to_owned(),
        content_hash: PLACEHOLDER.to_owned(),
        source: Some("synthetic-test-contract".to_owned()),
    });
    PLACEHOLDER.clone_into(&mut snapshot.snapshot_id);
    let bootstrap = SemanticRegistry::from_records(
        snapshot,
        types,
        capabilities,
        RegistryBuildOptions {
            hash_verification: HashVerificationMode::BootstrapGenerate,
            ..RegistryBuildOptions::default()
        },
    )
    .unwrap();
    let strict = SemanticRegistry::from_records(
        bootstrap.snapshot().clone(),
        bootstrap.type_contracts().cloned().collect(),
        bootstrap.capability_contracts().cloned().collect(),
        RegistryBuildOptions::default(),
    )
    .unwrap();
    Validator::new(strict, ValidationLimits::default())
}

fn fixture(name: &str) -> Value {
    serde_json::from_slice(&std::fs::read(fixture_root().join(name)).unwrap()).unwrap()
}

fn named_program(file: &str, name: &str) -> Value {
    fixture(file)
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap()["program"]
        .clone()
}

fn validate(value: &Value) -> aios_ir::ValidationReport {
    validator().validate_bytes_at(&serde_json::to_vec(value).unwrap(), fixed_time())
}

fn semantic_hash(value: &Value) -> String {
    let report = validate(value);
    assert!(
        report.output.validation.valid,
        "expected valid program, got {:?}",
        report.output.validation.diagnostics
    );
    report.output.validation.semantic_hash.unwrap()
}

fn has_code(report: &aios_ir::ValidationReport, code: ValidatorReasonCode) -> bool {
    report
        .output
        .validation
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == code)
}

fn uppercase_chain(node_count: usize, reverse_authoring_order: bool) -> Value {
    let mut nodes = (0..node_count)
        .map(|index| {
            let input = if index == 0 {
                json!({"source":"input","name":"source"})
            } else {
                json!({"source":"node","node":format!("step_{:03}", index - 1),"port":"text"})
            };
            json!({
                "id": format!("step_{index:03}"),
                "operation": {"kind":"invoke","capability":"text.uppercase@1"},
                "execution_class":"deterministic",
                "inputs":{"text":input},
                "outputs":{"text":"text.plain@1"},
                "authority_requests":[],
                "egress":{"mode":"deny"},
                "failure":{"on_error":"stop"},
                "cache":"content_addressed"
            })
        })
        .collect::<Vec<_>>();
    if reverse_authoring_order {
        nodes.reverse();
    }
    json!({
        "ir_version":"0.1",
        "program_id":"property.generated-dag",
        "kind":"task_graph",
        "inputs":{"source":{"type":"text.plain@1"}},
        "nodes":nodes,
        "outputs":{"text":{"source":"node","node":format!("step_{:03}", node_count - 1),"port":"text"}}
    })
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn arbitrary_bytes_never_panic_and_invalid_results_never_receive_identity(
        bytes in prop::collection::vec(any::<u8>(), 0..4096),
    ) {
        let validator = validator();
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            validator.validate_bytes_at(&bytes, fixed_time())
        }));
        prop_assert!(outcome.is_ok());
        let report = outcome.unwrap();
        if !report.output.validation.valid {
            prop_assert!(report.output.validation.semantic_hash.is_none());
            prop_assert!(report.output.effect_summary.is_none());
            prop_assert!(report.normalized.is_none());
        }
    }

    #[test]
    fn generated_dag_hash_is_independent_of_authoring_order(node_count in 1_usize..24) {
        let forward = uppercase_chain(node_count, false);
        let reversed = uppercase_chain(node_count, true);
        prop_assert_eq!(semantic_hash(&forward), semantic_hash(&reversed));
    }
}

#[test]
fn duplicate_json_members_are_rejected_before_schema_validation() {
    let secret = "Bearer sk-test-duplicate-key-secret";
    let bytes = br#"{
        "Bearer sk-test-duplicate-key-secret":"0.1",
        "Bearer sk-test-duplicate-key-secret":"0.1",
        "program_id":"duplicate",
        "kind":"task_graph",
        "inputs":{},"nodes":[],"outputs":{}
    }"#;
    let report = validator().validate_bytes_at(bytes, fixed_time());
    assert!(!report.output.validation.valid);
    assert_eq!(
        report.output.validation.diagnostics[0].code,
        ValidatorReasonCode::IrParseDuplicateKey
    );
    assert!(report.output.validation.semantic_hash.is_none());
    assert!(
        !serde_json::to_string(&report.output)
            .unwrap()
            .contains(secret)
    );
}

#[test]
fn unsupported_version_is_a_stable_domain_error() {
    let mut program = named_program("valid-cases.json", "minimal-deterministic-copy");
    program["ir_version"] = json!("0.2");
    let report = validate(&program);
    assert_eq!(
        report.output.validation.diagnostics[0].code,
        ValidatorReasonCode::IrVersionUnsupported
    );
    assert!(report.output.validation.semantic_hash.is_none());
}

#[test]
fn malformed_input_classes_have_stable_parse_rejection_without_identity() {
    for bytes in [&b""[..], &b"{"[..], &[0xff, 0xfe, 0xfd][..]] {
        let report = validator().validate_bytes_at(bytes, fixed_time());
        assert!(has_code(&report, ValidatorReasonCode::IrParseInvalid));
        assert!(report.output.validation.semantic_hash.is_none());
        assert!(report.normalized.is_none());
    }
}

#[test]
fn required_structure_and_value_reference_shapes_fail_closed() {
    let base = named_program("valid-cases.json", "minimal-deterministic-copy");
    for field in ["program_id", "nodes"] {
        let mut program = base.clone();
        program.as_object_mut().unwrap().remove(field);
        let report = validate(&program);
        assert!(has_code(&report, ValidatorReasonCode::IrSchemaRequired));
        assert!(report.output.validation.semantic_hash.is_none());
    }

    let mut malformed_reference = base.clone();
    malformed_reference["nodes"][0]["inputs"]["source"] = json!({"source":"input"});
    let report = validate(&malformed_reference);
    assert!(has_code(&report, ValidatorReasonCode::IrSchemaRequired));
    assert!(report.output.validation.semantic_hash.is_none());

    let mut malformed_identifier = base;
    malformed_identifier["nodes"][0]["id"] = json!("not/a/node");
    let report = validate(&malformed_identifier);
    assert!(has_code(&report, ValidatorReasonCode::IrSchemaPattern));
    assert!(report.output.validation.semantic_hash.is_none());
}

#[test]
fn whitespace_and_json_member_order_do_not_change_identity() {
    let left = br#"{
      "ir_version":"0.1","program_id":"left","kind":"task_graph",
      "inputs":{"source":{"type":"artifact.file@1"}},
      "nodes":[{"id":"copy","operation":{"kind":"invoke","capability":"artifact.copy@1"},
        "execution_class":"deterministic","inputs":{"source":{"source":"input","name":"source"}},
        "outputs":{"copy":"artifact.file@1"},"authority_requests":[
          {"action":"artifact.read","resource":"input:source"},
          {"action":"artifact.write","resource":"task.output"}],
        "egress":{"mode":"deny"},"failure":{"on_error":"stop"},"cache":"content_addressed"}],
      "outputs":{"copy":{"source":"node","node":"copy","port":"copy"}}
    }"#;
    let right = br#"{"outputs":{"copy":{"port":"copy","node":"copy","source":"node"}},"nodes":[{
      "cache":"content_addressed","failure":{"on_error":"stop"},"egress":{"mode":"deny"},
      "authority_requests":[{"resource":"task.output","action":"artifact.write"},{"resource":"input:source","action":"artifact.read"}],
      "outputs":{"copy":"artifact.file@1"},"inputs":{"source":{"name":"source","source":"input"}},
      "execution_class":"deterministic","operation":{"capability":"artifact.copy@1","kind":"invoke"},"id":"copy"}],
      "inputs":{"source":{"type":"artifact.file@1","required":true}},"kind":"task_graph",
      "program_id":"right","ir_version":"0.1"}"#;
    let validator = validator();
    let left = validator.validate_bytes_at(left, fixed_time());
    let right = validator.validate_bytes_at(right, fixed_time());
    assert!(left.output.validation.valid);
    assert!(right.output.validation.valid);
    assert_eq!(
        left.output.validation.semantic_hash,
        right.output.validation.semantic_hash
    );
}

#[test]
fn repeated_validation_and_normalization_are_deterministic() {
    let program = named_program(
        "valid-cases.json",
        "probabilistic-output-with-explicit-verifier",
    );
    let validator = validator();
    let first = validator.validate_bytes_at(&serde_json::to_vec(&program).unwrap(), fixed_time());
    let second = validator.validate_bytes_at(&serde_json::to_vec(&program).unwrap(), fixed_time());
    assert_eq!(first, second);
    assert!(first.normalized.is_some());
}

#[test]
fn capability_and_type_mutations_change_identity() {
    let base = named_program("valid-cases.json", "minimal-deterministic-copy");
    let mut capability = base.clone();
    capability["nodes"][0]["operation"]["capability"] = json!("artifact.copy.compat@1");
    assert_ne!(semantic_hash(&base), semantic_hash(&capability));

    let mut left_type = base.clone();
    left_type["inputs"]["unused"] = json!({"type":"artifact.file@1"});
    let mut right_type = base;
    right_type["inputs"]["unused"] = json!({"type":"text.plain@1"});
    assert_ne!(semantic_hash(&left_type), semantic_hash(&right_type));
}

#[test]
fn authority_action_resource_pairs_and_egress_destinations_change_identity() {
    let base = named_program("valid-cases.json", "minimal-deterministic-copy");
    let mut resource = base.clone();
    resource["nodes"][0]["authority_requests"][1]["resource"] = json!("task.temp");
    assert_ne!(semantic_hash(&base), semantic_hash(&resource));

    let policy = named_program(
        "valid-cases.json",
        "policy-controlled-remote-summary-egress",
    );
    let mut alternate_destination = policy.clone();
    let nodes = alternate_destination["nodes"].as_array_mut().unwrap();
    let summary = nodes
        .iter_mut()
        .find(|node| node["operation"]["capability"] == "report.summarize@1")
        .unwrap();
    summary["egress"]["destination_classes"][0] = json!("alternate-model");
    let egress_request = summary["authority_requests"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|request| request["action"] == "data.egress")
        .unwrap();
    egress_request["resource"] = json!("destination:alternate-model");
    assert_ne!(
        semantic_hash(&policy),
        semantic_hash(&alternate_destination)
    );
}

#[test]
fn remaining_semantic_program_fields_change_validated_identity() {
    let base = named_program("valid-cases.json", "minimal-deterministic-copy");

    let mut required = base.clone();
    required["inputs"]["unused"] =
        json!({"type":"text.plain@1","required":true,"media_types":["text/plain"]});
    let mut optional = required.clone();
    optional["inputs"]["unused"]["required"] = json!(false);
    assert_ne!(semantic_hash(&required), semantic_hash(&optional));
    let mut alternate_media = required.clone();
    alternate_media["inputs"]["unused"]["media_types"] = json!(["text/markdown"]);
    assert_ne!(semantic_hash(&required), semantic_hash(&alternate_media));

    let mut renamed = base.clone();
    renamed["nodes"][0]["id"] = json!("renamed_copy");
    renamed["outputs"]["copy"]["node"] = json!("renamed_copy");
    assert_ne!(semantic_hash(&base), semantic_hash(&renamed));

    let mut source_a = base.clone();
    source_a["inputs"]["alternate"] = json!({"type":"artifact.file@1"});
    let mut source_b = source_a.clone();
    source_b["nodes"][0]["inputs"]["source"]["name"] = json!("alternate");
    source_b["nodes"][0]["authority_requests"][0]["resource"] = json!("input:alternate");
    assert_ne!(semantic_hash(&source_a), semantic_hash(&source_b));

    let mut constrained = base.clone();
    constrained["nodes"][0]["constraints"] = json!({"locality":["local"],"max_latency_ms":25});
    assert_ne!(semantic_hash(&base), semantic_hash(&constrained));

    let mut replan_once = base.clone();
    replan_once["nodes"][0]["failure"] = json!({"on_error":"replan","max_replans":1});
    let mut replan_twice = replan_once.clone();
    replan_twice["nodes"][0]["failure"]["max_replans"] = json!(2);
    assert_ne!(semantic_hash(&replan_once), semantic_hash(&replan_twice));

    let mut mapped_left = base.clone();
    let mut first = mapped_left["nodes"][0].clone();
    first["id"] = json!("copy_a");
    let mut second = first.clone();
    second["id"] = json!("copy_b");
    mapped_left["nodes"] = json!([first, second]);
    mapped_left["outputs"]["copy"]["node"] = json!("copy_a");
    let mut mapped_right = mapped_left.clone();
    mapped_right["outputs"]["copy"]["node"] = json!("copy_b");
    assert_ne!(semantic_hash(&mapped_left), semantic_hash(&mapped_right));

    let mut stop = named_program("valid-cases.json", "bounded-provider-fallback");
    let fallback = stop.clone();
    stop["nodes"][0]["failure"] = json!({"on_error":"stop"});
    assert_ne!(semantic_hash(&stop), semantic_hash(&fallback));
}

#[test]
fn execution_class_and_egress_mode_change_validated_identity() {
    let mut deterministic = fixture("demonstration-a.ir.json");
    let chart = deterministic["nodes"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|node| node["id"] == "render_chart")
        .unwrap();
    chart["cache"] = json!("never");
    let mut nondeterministic = deterministic.clone();
    let chart = nondeterministic["nodes"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|node| node["id"] == "render_chart")
        .unwrap();
    chart["execution_class"] = json!("bounded_nondeterministic");
    assert_ne!(
        semantic_hash(&deterministic),
        semantic_hash(&nondeterministic)
    );

    let policy = named_program(
        "valid-cases.json",
        "policy-controlled-remote-summary-egress",
    );
    let mut deny = policy.clone();
    deny["nodes"][0]["authority_requests"] = json!([]);
    deny["nodes"][0]["egress"] = json!({"mode":"deny"});
    deny["nodes"][0]["constraints"]["locality"] = json!(["local"]);
    assert_ne!(semantic_hash(&policy), semantic_hash(&deny));
}

#[test]
fn semantic_set_order_and_safe_accelerator_default_are_hash_equivalent() {
    let policy = named_program(
        "valid-cases.json",
        "policy-controlled-remote-summary-egress",
    );
    let mut left = policy.clone();
    left["nodes"][0]["egress"]["destination_classes"] = json!(["remote-model", "backup-model"]);
    left["nodes"][0]["authority_requests"] = json!([
        {"action":"network.connect","resource":"service:model"},
        {"action":"data.egress","resource":"destination:remote-model"},
        {"action":"data.egress","resource":"destination:backup-model"}
    ]);
    let mut right = left.clone();
    right["nodes"][0]["egress"]["destination_classes"] = json!(["backup-model", "remote-model"]);
    right["nodes"][0]["authority_requests"]
        .as_array_mut()
        .unwrap()
        .reverse();
    assert_eq!(semantic_hash(&left), semantic_hash(&right));

    let base = named_program("valid-cases.json", "minimal-deterministic-copy");
    let mut omitted = base.clone();
    omitted["nodes"][0]["constraints"] = json!({"accelerator":{"kind":"gpu"}});
    let mut explicit = omitted.clone();
    explicit["nodes"][0]["constraints"]["accelerator"]["optional"] = json!(false);
    assert_eq!(semantic_hash(&omitted), semantic_hash(&explicit));
}

#[test]
fn runtime_rebinding_metadata_and_validation_time_do_not_change_identity() {
    let mut left = named_program("valid-cases.json", "minimal-deterministic-copy");
    left["metadata"] = json!({
        "task_id":"task-a","provider_id":"provider-a","provider_build":"build-a",
        "model":"model-a","hardware":"gpu-a","sandbox":"sandbox-a","grant":"grant-a",
        "credential":"credential-a","namespace_path":"/materialized/a","endpoint":"peer-a",
        "cloud_region":"region-a","attempt":1
    });
    let mut right = left.clone();
    right["metadata"] = json!({
        "task_id":"task-b","provider_id":"provider-b","provider_build":"build-b",
        "model":"model-b","hardware":"cpu-b","sandbox":"sandbox-b","grant":"grant-b",
        "credential":"credential-b","namespace_path":"C:\\materialized\\b","endpoint":"peer-b",
        "cloud_region":"region-b","attempt":99
    });
    let validator = validator();
    let early = OffsetDateTime::parse("2026-01-01T00:00:00Z", &Rfc3339).unwrap();
    let late = OffsetDateTime::parse("2026-12-31T23:59:59Z", &Rfc3339).unwrap();
    let left = validator.validate_bytes_at(&serde_json::to_vec(&left).unwrap(), early);
    let right = validator.validate_bytes_at(&serde_json::to_vec(&right).unwrap(), late);
    assert!(left.output.validation.valid && right.output.validation.valid);
    assert_eq!(
        left.output.validation.semantic_hash,
        right.output.validation.semantic_hash
    );
    assert_eq!(left.normalized, right.normalized);
    assert_ne!(
        left.output.validation.validated_at,
        right.output.validation.validated_at
    );
}

#[test]
fn host_and_runtime_selectors_are_rejected_without_identity() {
    let base = named_program("valid-cases.json", "minimal-deterministic-copy");
    for selector in [
        r"C:\Users\person\secret.txt",
        "file://local/path",
        "https://example.test/data",
        "credential://mail-send",
        "secret://actual-handle",
        "token://bearer",
        "provider://runtime-id",
    ] {
        let mut program = base.clone();
        program["nodes"][0]["authority_requests"][0]["resource"] = json!(selector);
        let report = validate(&program);
        assert!(
            has_code(&report, ValidatorReasonCode::IrSchemaPattern),
            "selector {selector:?} produced {:?}",
            report.output.validation.diagnostics
        );
        assert!(report.output.validation.semantic_hash.is_none());
    }

    for field in [
        "provider_id",
        "model_version",
        "process_id",
        "hardware_device",
        "sandbox_id",
        "execution_binding_id",
        "capability_grant",
        "credential_handle",
        "runtime_attempt",
    ] {
        let mut program = base.clone();
        program["nodes"][0][field] = json!("forbidden-runtime-binding");
        let report = validate(&program);
        assert!(has_code(
            &report,
            ValidatorReasonCode::IrSchemaAdditionalProperty
        ));
        assert!(report.output.validation.semantic_hash.is_none());
    }
}

#[test]
fn failure_graph_port_and_egress_edges_are_regression_locked() {
    let base = named_program("valid-cases.json", "minimal-deterministic-copy");

    let mut unbounded_replan = base.clone();
    unbounded_replan["nodes"][0]["failure"] = json!({"on_error":"replan"});
    assert!(has_code(
        &validate(&unbounded_replan),
        ValidatorReasonCode::IrFailurePolicyUnbounded
    ));

    let mut self_cycle = base.clone();
    self_cycle["nodes"][0]["inputs"]["source"] =
        json!({"source":"node","node":"copy","port":"copy"});
    // Keep this mutation focused on cycle detection. The node no longer
    // consumes the top-level input, so input:source would be independently
    // invalid under the node-local authority-scope rule.
    self_cycle["nodes"][0]["authority_requests"] = json!([]);
    assert!(has_code(
        &validate(&self_cycle),
        ValidatorReasonCode::IrGraphCycle
    ));

    let mut missing_port = base.clone();
    missing_port["nodes"][0]["inputs"]
        .as_object_mut()
        .unwrap()
        .remove("source");
    missing_port["nodes"][0]["authority_requests"] = json!([]);
    assert!(has_code(
        &validate(&missing_port),
        ValidatorReasonCode::IrCapabilityPortMismatch
    ));

    let mut extra_port = base.clone();
    extra_port["nodes"][0]["inputs"]["extra"] = json!({"source":"input","name":"source"});
    assert!(has_code(
        &validate(&extra_port),
        ValidatorReasonCode::IrCapabilityPortMismatch
    ));

    let mut incompatible_fallback = named_program(
        "valid-cases.json",
        "policy-controlled-remote-summary-egress",
    );
    incompatible_fallback["nodes"][0]["failure"] =
        json!({"on_error":"fallback","fallback_capabilities":["artifact.copy.compat@1"]});
    assert!(has_code(
        &validate(&incompatible_fallback),
        ValidatorReasonCode::IrExecutionClassIncompatible
    ));

    let policy = named_program(
        "valid-cases.json",
        "policy-controlled-remote-summary-egress",
    );
    let mut missing_destinations = policy.clone();
    missing_destinations["nodes"][0]["egress"]
        .as_object_mut()
        .unwrap()
        .remove("destination_classes");
    assert!(has_code(
        &validate(&missing_destinations),
        ValidatorReasonCode::IrSchemaRequired
    ));
    let mut empty_destinations = policy;
    empty_destinations["nodes"][0]["egress"]["destination_classes"] = json!([]);
    assert!(has_code(
        &validate(&empty_destinations),
        ValidatorReasonCode::IrSchemaRange
    ));

    let mut aliases = base;
    aliases["outputs"]["alias"] = aliases["outputs"]["copy"].clone();
    let alias_report = validate(&aliases);
    assert!(alias_report.output.validation.valid);
    assert!(alias_report.output.validation.semantic_hash.is_some());
}

#[test]
fn inputless_node_is_valid_only_for_a_contract_with_no_required_inputs() {
    let program = json!({
        "ir_version":"0.1",
        "program_id":"edge.inputless-capability",
        "kind":"task_graph",
        "inputs":{},
        "nodes":[{
            "id":"constant",
            "operation":{"kind":"invoke","capability":"text.constant@1"},
            "execution_class":"deterministic",
            "inputs":{},
            "outputs":{"text":"text.plain@1"},
            "authority_requests":[],
            "egress":{"mode":"deny"},
            "failure":{"on_error":"stop"},
            "cache":"content_addressed"
        }],
        "outputs":{"text":{"source":"node","node":"constant","port":"text"}}
    });
    let report = validator_with_inputless_capability()
        .validate_bytes_at(&serde_json::to_vec(&program).unwrap(), fixed_time());
    assert!(
        report.output.validation.valid,
        "unexpected diagnostics: {:?}",
        report.output.validation.diagnostics
    );
    assert!(report.output.validation.semantic_hash.is_some());
}

#[test]
fn effect_summary_is_the_exact_union_and_security_effects_are_explicit() {
    for case in fixture("valid-cases.json").as_array().unwrap() {
        let report = validate(&case["program"]);
        let summary = report.output.effect_summary.unwrap();
        let mut union = summary
            .nodes
            .iter()
            .flat_map(|node| node.effects.iter().copied())
            .collect::<BTreeSet<_>>();
        if union.len() > 1 {
            union.remove(&EffectClass::Pure);
        }
        assert_eq!(summary.effects.into_iter().collect::<BTreeSet<_>>(), union);
    }

    let local = validate(&named_program(
        "valid-cases.json",
        "probabilistic-output-with-explicit-verifier",
    ));
    let local_summary = local.output.effect_summary.unwrap();
    assert_eq!(
        local_summary
            .nodes
            .iter()
            .find(|node| node.node_id == "draft")
            .unwrap()
            .effects,
        [EffectClass::Pure]
    );

    let remote = validate(&named_program(
        "valid-cases.json",
        "policy-controlled-remote-summary-egress",
    ));
    assert_eq!(
        remote
            .output
            .effect_summary
            .unwrap()
            .effects
            .into_iter()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([EffectClass::Network, EffectClass::DataEgress])
    );

    let outside = validate(&named_program(
        "invalid-semantic-cases.json",
        "authority-class-exceeds-capability-contract",
    ));
    assert!(has_code(
        &outside,
        ValidatorReasonCode::IrAuthorityClassNotAllowed
    ));
    assert!(has_code(
        &outside,
        ValidatorReasonCode::IrEffectClassNotAllowed
    ));
}

#[test]
fn normalization_preserves_exact_authority_effect_inputs_egress_and_verification() {
    let value = named_program(
        "valid-cases.json",
        "policy-controlled-remote-summary-egress",
    );
    let normalized = validate(&value).normalized.unwrap();
    assert_eq!(
        normalized.pointer("/nodes/0/operation"),
        Some(&json!({"kind":"invoke","capability":"report.summarize@1"}))
    );
    assert_eq!(
        normalized.pointer("/nodes/0/execution_class"),
        Some(&json!("probabilistic"))
    );
    assert_eq!(
        normalized.pointer("/nodes/0/authority_requests"),
        Some(&json!([
            {"action":"data.egress","resource":"destination:remote-model"},
            {"action":"network.connect","resource":"service:model"}
        ]))
    );
    assert_eq!(
        normalized.pointer("/nodes/0/egress"),
        Some(&json!({"mode":"policy","destination_classes":["remote-model"]}))
    );

    let verified = named_program(
        "valid-cases.json",
        "probabilistic-output-with-explicit-verifier",
    );
    let normalized_verified = validate(&verified).normalized.unwrap();
    assert_eq!(
        normalized_verified.pointer("/nodes/1/id"),
        Some(&json!("verify"))
    );
    assert_eq!(
        normalized_verified.pointer("/nodes/1/operation"),
        Some(&json!({"kind":"verify","capability":"verify.numeric_claims@1"}))
    );
    assert_eq!(
        normalized_verified.pointer("/nodes/1/execution_class"),
        Some(&json!("deterministic"))
    );
    assert_eq!(
        normalized_verified.pointer("/nodes/1/authority_requests"),
        Some(&json!([]))
    );
    assert_eq!(
        normalized_verified.pointer("/nodes/1/egress"),
        Some(&json!({"mode":"deny"}))
    );
}

#[test]
fn removing_a_verification_boundary_changes_validated_identity() {
    let verified = named_program(
        "valid-cases.json",
        "probabilistic-output-with-explicit-verifier",
    );
    let mut unverified = verified.clone();
    unverified["nodes"].as_array_mut().unwrap().pop();
    unverified["outputs"]["narrative"] = json!({"source":"node","node":"draft","port":"narrative"});

    let verified_report = validate(&verified);
    let unverified_report = validate(&unverified);
    assert!(verified_report.output.validation.valid);
    assert!(unverified_report.output.validation.valid);
    assert_ne!(
        verified_report.output.validation.semantic_hash,
        unverified_report.output.validation.semantic_hash
    );
    assert_eq!(
        verified_report
            .output
            .effect_summary
            .unwrap()
            .verification_barriers,
        ["verify"]
    );
    assert!(
        unverified_report
            .output
            .effect_summary
            .unwrap()
            .verification_barriers
            .is_empty()
    );
}
