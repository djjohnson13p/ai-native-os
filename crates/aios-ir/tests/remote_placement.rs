//! Regressions for effects and authority implied by non-local-only placement.

use std::path::Path;

use aios_contracts::ValidatorReasonCode;
use aios_ir::{ValidationLimits, Validator};
use aios_registry::{RegistryLoadOptions, SemanticRegistry};
use serde_json::{Value, json};

fn remote_program() -> Value {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/aios-ir");
    let cases: Value =
        serde_json::from_slice(&std::fs::read(root.join("valid-cases.json")).unwrap()).unwrap();
    cases
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "policy-controlled-remote-summary-egress")
        .unwrap()["program"]
        .clone()
}

fn validate(program: &Value) -> aios_ir::ValidationReport {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/aios-ir");
    let registry = SemanticRegistry::load_bundle(root, RegistryLoadOptions::default()).unwrap();
    Validator::new(registry, ValidationLimits::default())
        .validate_bytes(&serde_json::to_vec(program).unwrap())
}

#[test]
fn non_local_only_node_cannot_hide_network_and_egress_effects() {
    for locality in [
        json!(["remote"]),
        json!(["peer"]),
        json!(["hybrid"]),
        json!(["peer", "remote"]),
    ] {
        let mut program = remote_program();
        program["nodes"][0]["constraints"]["locality"] = locality.clone();
        program["nodes"][0]["authority_requests"] = json!([]);
        program["nodes"][0]["egress"] = json!({"mode": "deny"});

        let report = validate(&program);
        assert!(!report.output.validation.valid, "{locality}");
        let diagnostics = &report.output.validation.diagnostics;
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == ValidatorReasonCode::IrRequiredAuthorityMissing
                && diagnostic.message.contains("network.connect")
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == ValidatorReasonCode::IrRequiredAuthorityMissing
                && diagnostic.message.contains("data.egress")
        }));
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == ValidatorReasonCode::IrEgressContradiction)
        );
        assert!(report.output.effect_summary.is_none());
    }
}

#[test]
fn remote_only_node_with_declared_authority_remains_valid() {
    let report = validate(&remote_program());
    assert!(
        report.output.validation.valid,
        "{:?}",
        report.output.validation.diagnostics
    );
}
