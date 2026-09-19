//! Generated negative cases that complement the checked-in fixture matrix.

use std::path::{Path, PathBuf};

use aios_contracts::{
    CapabilityContract, CapabilityRole, EffectClass, EgressMode, RegistrySnapshot, TypeContract,
    ValidatorReasonCode,
};
use aios_ir::{ValidationLimits, ValidationReport, Validator};
use aios_registry::{
    HashVerificationMode, RegistryBuildOptions, RegistryLoadOptions, SemanticRegistry,
};
use serde_json::{Value, json};

const FIXED_TIME: &str = "2026-09-15T00:00:00Z";
const PLACEHOLDER: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/aios-ir")
}

fn read<T: serde::de::DeserializeOwned>(name: &str) -> T {
    serde_json::from_slice(&std::fs::read(fixture_root().join(name)).unwrap()).unwrap()
}

fn strict_registry() -> SemanticRegistry {
    SemanticRegistry::load_bundle(fixture_root(), RegistryLoadOptions::default()).unwrap()
}

fn modified_registry(
    capability_id: &str,
    mutate: impl FnOnce(&mut CapabilityContract),
) -> SemanticRegistry {
    let mut snapshot: RegistrySnapshot = read("registry-snapshot.json");
    let types: Vec<TypeContract> = read("type-contracts.json");
    let mut capabilities: Vec<CapabilityContract> = read("capability-contracts.json");
    let contract = capabilities
        .iter_mut()
        .find(|contract| contract.capability == capability_id)
        .unwrap();
    mutate(contract);
    PLACEHOLDER.clone_into(&mut snapshot.snapshot_id);
    let snapshot_contract = snapshot
        .capability_contracts
        .iter_mut()
        .find(|entry| entry.id == capability_id)
        .unwrap();
    PLACEHOLDER.clone_into(&mut snapshot_contract.content_hash);
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
    SemanticRegistry::from_records(
        bootstrap.snapshot().clone(),
        bootstrap.type_contracts().cloned().collect(),
        bootstrap.capability_contracts().cloned().collect(),
        RegistryBuildOptions::default(),
    )
    .unwrap()
}

fn base_copy() -> Value {
    let cases: Vec<Value> = read("valid-cases.json");
    cases
        .into_iter()
        .find(|case| case["name"] == "minimal-deterministic-copy")
        .unwrap()["program"]
        .clone()
}

fn fallback_copy() -> Value {
    let cases: Vec<Value> = read("valid-cases.json");
    cases
        .into_iter()
        .find(|case| case["name"] == "bounded-provider-fallback")
        .unwrap()["program"]
        .clone()
}

fn fixed_time() -> time::OffsetDateTime {
    time::OffsetDateTime::parse(FIXED_TIME, &time::format_description::well_known::Rfc3339).unwrap()
}

fn validate(registry: SemanticRegistry, program: &Value) -> ValidationReport {
    Validator::new(registry, ValidationLimits::default())
        .validate_bytes_at(&serde_json::to_vec(program).unwrap(), fixed_time())
}

fn assert_code(report: &ValidationReport, expected: ValidatorReasonCode) {
    assert!(!report.output.validation.valid);
    assert!(report.output.validation.semantic_hash.is_none());
    assert!(report.output.effect_summary.is_none());
    assert!(report.normalized.is_none());
    assert!(
        report
            .output
            .validation
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == expected),
        "missing {expected}; got {:?}",
        report.output.validation.diagnostics
    );
}

#[test]
fn unknown_type_and_missing_input_fail_closed() {
    let mut unknown_type = base_copy();
    unknown_type["inputs"]["source"]["type"] = json!("unknown.type@1");
    assert_code(
        &validate(strict_registry(), &unknown_type),
        ValidatorReasonCode::IrTypeNotFound,
    );

    let mut missing_input = base_copy();
    missing_input["nodes"][0]["inputs"]["source"]["name"] = json!("missing");
    assert_code(
        &validate(strict_registry(), &missing_input),
        ValidatorReasonCode::IrReferenceInputNotFound,
    );
}

#[test]
fn program_outputs_must_resolve_node_outputs() {
    let mut program = base_copy();
    program["outputs"]["copy"] = json!({"source":"input","name":"source"});
    assert_code(
        &validate(strict_registry(), &program),
        ValidatorReasonCode::IrOutputNotFound,
    );
}

#[test]
fn fallback_port_effect_authority_and_egress_broadening_are_rejected() {
    let program = fallback_copy();

    let prose_registry = modified_registry("artifact.copy.compat", |contract| {
        contract.inputs.get_mut("source").unwrap().description =
            Some("non-semantic wording changed".to_owned());
    });
    assert!(validate(prose_registry, &program).output.validation.valid);

    let port_registry = modified_registry("artifact.copy.compat", |contract| {
        "text.plain@1".clone_into(&mut contract.outputs.get_mut("copy").unwrap().type_ref);
    });
    assert_code(
        &validate(port_registry, &program),
        ValidatorReasonCode::IrFallbackPortMismatch,
    );

    let effect_registry = modified_registry("artifact.copy.compat", |contract| {
        contract.allowed_effect_classes.push(EffectClass::Network);
    });
    assert_code(
        &validate(effect_registry, &program),
        ValidatorReasonCode::IrFallbackEffectBroadening,
    );

    let authority_registry = modified_registry("artifact.copy.compat", |contract| {
        contract.allowed_effect_classes.push(EffectClass::Network);
        contract
            .allowed_authority_classes
            .push("network.connect".to_owned());
    });
    assert_code(
        &validate(authority_registry, &program),
        ValidatorReasonCode::IrFallbackAuthorityBroadening,
    );

    let egress_registry = modified_registry("artifact.copy.compat", |contract| {
        contract
            .allowed_effect_classes
            .push(EffectClass::DataEgress);
        contract
            .allowed_authority_classes
            .push("data.egress".to_owned());
        contract.allowed_egress_modes.push(EgressMode::Policy);
    });
    assert_code(
        &validate(egress_registry, &program),
        ValidatorReasonCode::IrFallbackEgressBroadening,
    );

    let role_registry = modified_registry("artifact.copy.compat", |contract| {
        contract.role = CapabilityRole::Verifier;
    });
    assert_code(
        &validate(role_registry, &program),
        ValidatorReasonCode::IrCapabilityRoleMismatch,
    );
}

#[test]
fn legacy_opaque_effect_sets_program_summary_flag() {
    let registry = modified_registry("table.normalize", |contract| {
        contract.required_effect_classes = vec![EffectClass::LegacyOpaque];
        contract.allowed_effect_classes = vec![EffectClass::LegacyOpaque];
    });
    let program = json!({
        "ir_version":"0.1",
        "program_id":"legacy.opaque.summary",
        "kind":"task_graph",
        "inputs":{"table":{"type":"data.table@1"}},
        "nodes":[{
            "id":"normalize",
            "operation":{"kind":"invoke","capability":"table.normalize@1"},
            "execution_class":"deterministic",
            "inputs":{"table":{"source":"input","name":"table"}},
            "outputs":{"table":"data.table@1"},
            "authority_requests":[],
            "egress":{"mode":"deny"},
            "failure":{"on_error":"stop"},
            "cache":"content_addressed"
        }],
        "outputs":{"table":{"source":"node","node":"normalize","port":"table"}}
    });
    let report = validate(registry, &program);
    assert!(report.output.validation.valid);
    assert!(
        report
            .output
            .effect_summary
            .unwrap()
            .contains_opaque_external
    );
}
