//! Boundary and hostile-input tests for every configured validator limit.

use std::path::{Path, PathBuf};

use aios_contracts::ValidatorReasonCode;
use aios_ir::{ValidationLimits, Validator};
use aios_registry::{RegistryLoadOptions, SemanticRegistry};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const FIXED_TIME: &str = "2026-09-15T00:00:00Z";

fn fixed_time() -> OffsetDateTime {
    OffsetDateTime::parse(FIXED_TIME, &Rfc3339).unwrap()
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/aios-ir")
}

fn registry() -> SemanticRegistry {
    SemanticRegistry::load_bundle(fixture_root(), RegistryLoadOptions::default()).unwrap()
}

fn valid_program_named(name: &str) -> Value {
    let cases: Value =
        serde_json::from_slice(&std::fs::read(fixture_root().join("valid-cases.json")).unwrap())
            .unwrap();
    cases
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap()["program"]
        .clone()
}

fn base_program() -> Value {
    valid_program_named("minimal-deterministic-copy")
}

fn report(program: &Value, limits: ValidationLimits) -> aios_ir::ValidationReport {
    Validator::new(registry(), limits)
        .validate_bytes_at(&serde_json::to_vec(program).unwrap(), fixed_time())
}

fn has_code(report: &aios_ir::ValidationReport, code: ValidatorReasonCode) -> bool {
    report
        .output
        .validation
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == code)
}

#[test]
fn document_size_accepts_n_minus_one_and_n_but_rejects_n_plus_one() {
    let bytes = serde_json::to_vec(&base_program()).unwrap();
    for delta in [0_usize, 1] {
        let mut candidate = bytes.clone();
        candidate.extend(std::iter::repeat_n(b' ', delta));
        let limits = ValidationLimits {
            max_document_bytes: bytes.len() + 1,
            ..ValidationLimits::default()
        };
        let result = Validator::new(registry(), limits).validate_bytes_at(&candidate, fixed_time());
        assert!(result.output.validation.valid);
        assert!(!has_code(&result, ValidatorReasonCode::IrLimitDocumentSize));
    }
    let mut oversized = bytes.clone();
    oversized.extend_from_slice(b"  ");
    let limits = ValidationLimits {
        max_document_bytes: bytes.len() + 1,
        ..ValidationLimits::default()
    };
    let result = Validator::new(registry(), limits).validate_bytes_at(&oversized, fixed_time());
    assert!(!result.output.validation.valid);
    assert!(has_code(&result, ValidatorReasonCode::IrLimitDocumentSize));
}

#[test]
fn node_count_boundary_is_inclusive() {
    let base = base_program();
    let node = base["nodes"][0].clone();
    for (count, exceeds) in [(1, false), (2, false), (3, true)] {
        let mut candidate = base.clone();
        let nodes = (0..count)
            .map(|index| {
                let mut candidate_node = node.clone();
                if index != 0 {
                    candidate_node["id"] = json!(format!("copy_{index}"));
                }
                candidate_node
            })
            .collect();
        candidate["nodes"] = Value::Array(nodes);
        let limits = ValidationLimits {
            max_nodes: 2,
            ..ValidationLimits::default()
        };
        let result = report(&candidate, limits);
        assert_eq!(
            has_code(&result, ValidatorReasonCode::IrLimitNodeCount),
            exceeds
        );
        assert_eq!(result.output.validation.valid, !exceeds);
    }
}

#[test]
fn port_count_boundary_is_inclusive() {
    for (count, exceeds) in [(1, false), (2, false), (3, true)] {
        let mut candidate = base_program();
        let inputs = candidate["inputs"].as_object_mut().unwrap();
        for index in 1..count {
            inputs.insert(
                format!("extra{index}"),
                json!({"type": "artifact.file@1", "required": false}),
            );
        }
        let limits = ValidationLimits {
            max_ports_per_interface: 2,
            ..ValidationLimits::default()
        };
        let result = report(&candidate, limits);
        assert_eq!(
            has_code(&result, ValidatorReasonCode::IrLimitPortCount),
            exceeds
        );
        assert_eq!(result.output.validation.valid, !exceeds);
    }
}

#[test]
fn authority_request_count_boundary_is_inclusive() {
    let zero = valid_program_named("probabilistic-output-with-explicit-verifier");
    let mut one = zero.clone();
    one["nodes"][0]["authority_requests"] =
        json!([{"action": "network.connect", "resource": "service:model"}]);
    let two = valid_program_named("policy-controlled-remote-summary-egress");

    for (candidate, exceeds) in [(&zero, false), (&one, false), (&two, true)] {
        let limits = ValidationLimits {
            max_authority_requests_per_node: 1,
            ..ValidationLimits::default()
        };
        let result = report(candidate, limits);
        assert_eq!(
            has_code(&result, ValidatorReasonCode::IrLimitAuthorityRequestCount),
            exceeds
        );
        assert_eq!(result.output.validation.valid, !exceeds);
    }
}

#[test]
fn fallback_count_boundary_is_inclusive() {
    let zero = base_program();
    let one = valid_program_named("bounded-provider-fallback");
    let mut two = one.clone();
    two["nodes"][0]["failure"]["fallback_capabilities"] =
        json!(["artifact.copy.compat@1", "artifact.hash@1"]);

    for (candidate, exceeds) in [(&zero, false), (&one, false), (&two, true)] {
        let limits = ValidationLimits {
            max_fallbacks_per_node: 1,
            ..ValidationLimits::default()
        };
        let result = report(candidate, limits);
        assert_eq!(
            has_code(&result, ValidatorReasonCode::IrLimitFallbackCount),
            exceeds
        );
        assert_eq!(result.output.validation.valid, !exceeds);
    }
}

#[test]
fn string_length_boundary_is_inclusive() {
    for (length, exceeds) in [(511, false), (512, false), (513, true)] {
        let mut candidate = base_program();
        candidate["metadata"] = json!({"payload": "x".repeat(length)});
        let limits = ValidationLimits {
            max_string_chars: 512,
            ..ValidationLimits::default()
        };
        let result = report(&candidate, limits);
        assert_eq!(
            has_code(&result, ValidatorReasonCode::IrLimitStringLength),
            exceeds
        );
        assert_eq!(result.output.validation.valid, !exceeds);
    }
}

#[test]
fn diagnostic_count_is_bounded_and_signaled() {
    let program = json!({
        "ir_version": "0.1",
        "program_id": "many.errors",
        "kind": "not-a-kind",
        "inputs": {"bad-name!": {}},
        "nodes": [{}, {}, {}, {}],
        "outputs": {}
    });
    let limits = ValidationLimits {
        max_diagnostics: 2,
        ..ValidationLimits::default()
    };
    let result = report(&program, limits);
    assert!(!result.output.validation.valid);
    assert!(result.output.validation.diagnostics_truncated);
    assert_eq!(result.output.validation.diagnostics.len(), 2);
    assert!(has_code(&result, ValidatorReasonCode::IrLimitDiagnostics));
}

#[test]
fn zero_diagnostic_budget_is_clamped_to_one_stable_error() {
    let mut program = base_program();
    program["nodes"][0]["operation"]["capability"] = json!("unknown.capability@1");
    let limits = ValidationLimits {
        max_diagnostics: 0,
        ..ValidationLimits::default()
    };
    let result = report(&program, limits);
    assert!(!result.output.validation.valid);
    assert!(!result.output.validation.diagnostics_truncated);
    assert_eq!(result.output.validation.diagnostics.len(), 1);
    assert!(has_code(&result, ValidatorReasonCode::IrCapabilityNotFound));
    assert!(result.output.validation.semantic_hash.is_none());
}
