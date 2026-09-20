//! Independent-review regressions; number spellings must survive fixture decoding.

use std::path::Path;

use aios_contracts::ValidatorReasonCode;
use aios_ir::{ValidationLimits, Validator};
use aios_registry::{RegistryLoadOptions, SemanticRegistry};
use proptest::prelude::*;
use serde_json::{Value, json};

fn fixture(name: &str) -> Value {
    serde_json::from_slice(
        &std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../examples/aios-ir")
                .join(name),
        )
        .unwrap(),
    )
    .unwrap()
}

fn validator() -> Validator {
    validator_with_limits(ValidationLimits::default())
}

fn validator_with_limits(limits: ValidationLimits) -> Validator {
    Validator::new(
        SemanticRegistry::load_bundle(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/aios-ir"),
            RegistryLoadOptions::default(),
        )
        .unwrap(),
        limits,
    )
}

fn program() -> Value {
    fixture("valid-cases.json")[0]["program"].clone()
}

fn with_token(program: &Value, token: &str) -> Vec<u8> {
    serde_json::to_string(program)
        .unwrap()
        .replace("\"RAW_NUMBER\"", token)
        .into_bytes()
}

fn with_raw_value(program: &Value, pointer: &str, raw_value: &str) -> Vec<u8> {
    let mut document = program.clone();
    *document.pointer_mut(pointer).unwrap() = Value::String("AIOS_RAW_VALUE".to_owned());
    serde_json::to_string(&document)
        .unwrap()
        .replace("\"AIOS_RAW_VALUE\"", raw_value)
        .into_bytes()
}

fn diagnostic_codes(report: &aios_ir::ValidationReport) -> Vec<ValidatorReasonCode> {
    report
        .output
        .validation
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code)
        .collect()
}

fn diagnostic_signature(
    report: &aios_ir::ValidationReport,
) -> Vec<(ValidatorReasonCode, Option<String>)> {
    report
        .output
        .validation
        .diagnostics
        .iter()
        .map(|diagnostic| (diagnostic.code, diagnostic.json_pointer.clone()))
        .collect()
}

fn expected_codes(case: &Value) -> Vec<ValidatorReasonCode> {
    case["reason_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|code| code.as_str().unwrap().parse().unwrap())
        .collect()
}

#[test]
fn exact_integer_authoring_fixtures_validate_without_loss() {
    let validator = validator();
    for field in [
        "min_memory_bytes",
        "max_cost_microusd",
        "max_latency_ms",
        "accelerator/min_memory_bytes",
    ] {
        for case in fixture("review-repair-cases.json")["integer_cases"]
            .as_array()
            .unwrap()
        {
            let mut input = program();
            input["nodes"][0]["constraints"] = if field == "accelerator/min_memory_bytes" {
                json!({"accelerator":{"kind":"gpu", "min_memory_bytes":"RAW_NUMBER"}})
            } else {
                json!({field: "RAW_NUMBER"})
            };
            let report =
                validator.validate_bytes(&with_token(&input, case["token"].as_str().unwrap()));
            let valid = case["value"].is_u64() && (field != "max_latency_ms" || case["value"] != 0);
            assert_eq!(
                report.output.validation.valid, valid,
                "{field} {case}: {:?}",
                report.output.validation.diagnostics
            );
            if valid {
                *input
                    .pointer_mut(&format!("/nodes/0/constraints/{field}"))
                    .unwrap() = case["value"].clone();
                let canonical = validator.validate_bytes(&serde_json::to_vec(&input).unwrap());
                assert_eq!(
                    report.output.validation.semantic_hash,
                    canonical.output.validation.semantic_hash,
                    "{case}"
                );
                assert_eq!(report.normalized, canonical.normalized);
            } else {
                assert!(report.output.validation.semantic_hash.is_none());
                assert!(report.normalized.is_none());
            }
        }
    }
}

#[test]
fn accelerator_and_retry_replan_integer_paths_use_exact_tokens() {
    let validator = validator();
    for token in ["1", "1.0", "1e0", "100e-2"] {
        let mut input = program();
        input["nodes"][0]["constraints"] =
            json!({"accelerator":{"kind":"gpu","min_memory_bytes":"RAW_NUMBER"}});
        for failure in [
            json!({"on_error":"retry","max_attempts":"RAW_NUMBER"}),
            json!({"on_error":"replan","max_replans":"RAW_NUMBER"}),
        ] {
            input["nodes"][0]["failure"] = failure;
            let valid = validator.validate_bytes(&with_token(&input, token));
            assert!(valid.output.validation.valid, "{token}");
            assert_eq!(
                valid.output.validation.semantic_hash,
                validator
                    .validate_bytes(&with_token(&input, "1"))
                    .output
                    .validation
                    .semantic_hash
            );
            for invalid in [
                "1.00000000000000000001",
                "1e-9999",
                "9007199254740991.1",
                "4.0",
            ] {
                assert!(
                    !validator
                        .validate_bytes(&with_token(&input, invalid))
                        .output
                        .validation
                        .valid,
                    "{invalid}"
                );
            }
        }
    }
}

#[test]
fn diagnostic_codes_do_not_depend_on_attacker_property_names() {
    let validator = validator();
    for key in fixture("review-repair-cases.json")["diagnostic_property_names"]
        .as_array()
        .unwrap()
    {
        let key = key.as_str().unwrap();
        for (pointer, mut selected) in [
            ("/nodes/0", program()["nodes"][0].clone()),
            (
                "/nodes/0/inputs/source",
                json!({"source":"input","name":"source"}),
            ),
            ("/nodes/0/failure", json!({"on_error":"stop"})),
        ] {
            selected[key] = json!("synthetic");
            let mut input = program();
            *input.pointer_mut(pointer).unwrap() = selected;
            let report = validator.validate_bytes(&serde_json::to_vec(&input).unwrap());
            assert!(!report.output.validation.valid);
            assert!(report.output.validation.semantic_hash.is_none());
            assert_eq!(
                diagnostic_codes(&report),
                [ValidatorReasonCode::IrSchemaAdditionalProperty],
                "{pointer} {key}: {:?}",
                report.output.validation.diagnostics
            );
        }
    }
}

#[test]
fn discriminated_union_diagnostics_retain_specific_structured_codes() {
    let validator = validator();
    for case in fixture("review-repair-cases.json")["nested_diagnostic_cases"]
        .as_array()
        .unwrap()
    {
        let mut input = program();
        *input
            .pointer_mut(case["pointer"].as_str().unwrap())
            .unwrap() = case["value"].clone();
        let report = validator.validate_bytes(&serde_json::to_vec(&input).unwrap());

        assert!(!report.output.validation.valid, "{case}");
        assert!(report.output.validation.semantic_hash.is_none(), "{case}");
        assert!(report.normalized.is_none(), "{case}");
        assert_eq!(diagnostic_codes(&report), expected_codes(case), "{case}");
    }
}

#[test]
fn discriminator_type_and_value_matrix_is_structured() {
    let validator = validator();
    let repair_cases = fixture("review-repair-cases.json");

    for wrong_type in repair_cases["discriminator_wrong_type_values"]
        .as_array()
        .unwrap()
    {
        for (pointer, discriminator, companion) in [
            (
                "/nodes/0/inputs/source",
                "source",
                Some(("name", json!("source"))),
            ),
            ("/nodes/0/failure", "on_error", None),
        ] {
            let mut selected = serde_json::Map::new();
            selected.insert(discriminator.to_owned(), wrong_type.clone());
            if let Some((name, value)) = &companion {
                selected.insert((*name).to_owned(), value.clone());
            }
            let mut input = program();
            *input.pointer_mut(pointer).unwrap() = Value::Object(selected);
            let report = validator.validate_bytes(&serde_json::to_vec(&input).unwrap());
            assert_eq!(
                diagnostic_codes(&report),
                [ValidatorReasonCode::IrSchemaType],
                "{pointer} {wrong_type}: {:?}",
                report.output.validation.diagnostics
            );
            assert!(report.output.validation.semantic_hash.is_none());
        }
    }

    for unsupported in repair_cases["discriminator_unsupported_strings"]
        .as_array()
        .unwrap()
    {
        for (pointer, discriminator, companion) in [
            (
                "/nodes/0/inputs/source",
                "source",
                Some(("name", json!("source"))),
            ),
            ("/nodes/0/failure", "on_error", None),
        ] {
            let mut selected = serde_json::Map::new();
            selected.insert(discriminator.to_owned(), unsupported.clone());
            if let Some((name, value)) = &companion {
                selected.insert((*name).to_owned(), value.clone());
            }
            let mut input = program();
            *input.pointer_mut(pointer).unwrap() = Value::Object(selected);
            let report = validator.validate_bytes(&serde_json::to_vec(&input).unwrap());
            assert_eq!(
                diagnostic_codes(&report),
                [ValidatorReasonCode::IrSchemaEnum],
                "{pointer} {unsupported}: {:?}",
                report.output.validation.diagnostics
            );
            assert!(report.output.validation.semantic_hash.is_none());
        }
    }

    for pointer in ["/nodes/0/inputs/source", "/nodes/0/failure"] {
        let mut input = program();
        *input.pointer_mut(pointer).unwrap() = json!({});
        let report = validator.validate_bytes(&serde_json::to_vec(&input).unwrap());
        assert_eq!(
            diagnostic_codes(&report),
            [ValidatorReasonCode::IrSchemaRequired],
            "{pointer}: {:?}",
            report.output.validation.diagnostics
        );
    }
}

#[test]
fn uniquely_selected_branches_emit_all_actual_failure_families() {
    let validator = validator();
    for case in fixture("review-repair-cases.json")["mixed_diagnostic_cases"]
        .as_array()
        .unwrap()
    {
        let mut input = program();
        *input
            .pointer_mut(case["pointer"].as_str().unwrap())
            .unwrap() = case["value"].clone();
        let report = validator.validate_bytes(&serde_json::to_vec(&input).unwrap());

        assert!(!report.output.validation.valid, "{case}");
        assert!(report.output.validation.semantic_hash.is_none(), "{case}");
        assert!(report.normalized.is_none(), "{case}");
        assert_eq!(diagnostic_codes(&report), expected_codes(case), "{case}");
    }
}

#[test]
fn mixed_failure_order_is_repeatable_and_object_order_independent() {
    let validator = validator();
    for (pointer, left, right, expected) in [
        (
            "/nodes/0/inputs/source",
            r#"{"source":"input","name":"bad/name","required":"attack"}"#,
            r#"{"required":"attack","name":"bad/name","source":"input"}"#,
            vec![
                ValidatorReasonCode::IrSchemaAdditionalProperty,
                ValidatorReasonCode::IrSchemaPattern,
            ],
        ),
        (
            "/nodes/0/failure",
            r#"{"on_error":"retry","max_attempts":0,"required":"attack"}"#,
            r#"{"required":"attack","max_attempts":0,"on_error":"retry"}"#,
            vec![
                ValidatorReasonCode::IrSchemaAdditionalProperty,
                ValidatorReasonCode::IrSchemaRange,
            ],
        ),
    ] {
        let mut baseline = None;
        for raw in [left, right] {
            for _ in 0..8 {
                let report = validator.validate_bytes(&with_raw_value(&program(), pointer, raw));
                assert_eq!(diagnostic_codes(&report), expected, "{pointer} {raw}");
                let signature = diagnostic_signature(&report);
                if let Some(baseline) = &baseline {
                    assert_eq!(&signature, baseline, "{pointer} {raw}");
                } else {
                    baseline = Some(signature);
                }
            }
        }
    }
}

#[test]
fn selected_branch_expansion_respects_diagnostic_limit() {
    let validator = validator_with_limits(ValidationLimits {
        max_diagnostics: 1,
        ..ValidationLimits::default()
    });
    let mut input = program();
    input["nodes"][0]["inputs"]["source"] =
        json!({"source":"input","name":"bad/name","required":"attack"});
    let report = validator.validate_bytes(&serde_json::to_vec(&input).unwrap());

    assert_eq!(
        diagnostic_codes(&report),
        [ValidatorReasonCode::IrSchemaAdditionalProperty]
    );
    assert!(report.output.validation.diagnostics_truncated);
    assert!(report.output.validation.semantic_hash.is_none());
}

#[test]
fn egress_composite_diagnostics_and_precheck_precedence_are_unchanged() {
    let validator = validator();
    for (egress, expected) in [
        (
            json!({"mode":"policy"}),
            ValidatorReasonCode::IrSchemaRequired,
        ),
        (
            json!({"mode":"policy","destination_classes":[]}),
            ValidatorReasonCode::IrSchemaRange,
        ),
        (
            json!({"mode":"deny","destination_classes":["public"]}),
            ValidatorReasonCode::IrEgressContradiction,
        ),
    ] {
        let mut input = program();
        input["nodes"][0]["egress"] = egress;
        let report = validator.validate_bytes(&serde_json::to_vec(&input).unwrap());
        assert_eq!(
            diagnostic_codes(&report),
            [expected],
            "{:?}",
            report.output.validation.diagnostics
        );
        assert!(report.output.validation.semantic_hash.is_none());
    }

    let mut too_many_fallbacks = program();
    too_many_fallbacks["nodes"][0]["failure"] = json!({
        "on_error":"fallback",
        "fallback_capabilities":[
            "artifact.copy@1",
            "artifact.copy.compat@1",
            "artifact.hash@1",
            "table.import@1"
        ]
    });
    let report = validator.validate_bytes(&serde_json::to_vec(&too_many_fallbacks).unwrap());
    assert_eq!(
        diagnostic_codes(&report),
        [ValidatorReasonCode::IrLimitFallbackCount]
    );
}

#[test]
fn verifier_inventory_does_not_claim_all_outputs_are_gated() {
    let validator = validator();
    let case = &fixture("review-repair-cases.json")["verification_case"];
    let mut input = fixture(case["base"].as_str().unwrap());
    let baseline = validator.validate_bytes(&serde_json::to_vec(&input).unwrap());
    input["outputs"]["unverified"] = case["additional_output"].clone();
    let report = validator.validate_bytes(&serde_json::to_vec(&input).unwrap());
    assert!(report.output.validation.valid);
    assert!(report.output.validation.diagnostics.is_empty());
    assert_ne!(
        report.output.validation.semantic_hash,
        baseline.output.validation.semantic_hash
    );
    assert_eq!(
        report.output.effect_summary.unwrap().verification_barriers,
        ["verify_narrative"]
    );
    assert_eq!(
        report.normalized.unwrap()["outputs"]["unverified"],
        case["additional_output"]
    );
}

#[test]
fn schema_diagnostics_never_echo_invalid_instance_values() {
    let validator = validator();
    let secret = "Bearer sk-test-super-secret-do-not-log";
    for (pointer, expected) in [
        ("/program_id", ValidatorReasonCode::IrSchemaPattern),
        (
            "/nodes/0/authority_requests/0/resource",
            ValidatorReasonCode::IrSchemaPattern,
        ),
    ] {
        let mut input = program();
        *input.pointer_mut(pointer).unwrap() = json!(secret);
        let report = validator.validate_bytes(&serde_json::to_vec(&input).unwrap());

        assert_eq!(diagnostic_codes(&report), [expected]);
        assert!(report.output.validation.ir_version.is_none());
        assert!(report.output.validation.program_id.is_none());
        assert!(report.output.validation.semantic_hash.is_none());
        let rendered = serde_json::to_string(&report.output.validation.diagnostics).unwrap();
        assert!(!rendered.contains(secret), "secret leaked for {pointer}");
        assert!(
            report
                .output
                .validation
                .diagnostics
                .iter()
                .all(|diagnostic| !diagnostic.message.contains(secret))
        );
    }
}

#[test]
fn identifiers_are_emitted_only_after_structural_validation() {
    let valid = validator().validate_bytes(&serde_json::to_vec(&program()).unwrap());
    assert_eq!(valid.output.validation.ir_version.as_deref(), Some("0.1"));
    assert_eq!(
        valid.output.validation.program_id.as_deref(),
        program()["program_id"].as_str()
    );

    let mut semantic_rejection = program();
    semantic_rejection["nodes"][0]["inputs"]["source"]["name"] = json!("missing");
    let report = validator().validate_bytes(&serde_json::to_vec(&semantic_rejection).unwrap());
    assert!(!report.output.validation.valid);
    assert_eq!(report.output.validation.ir_version.as_deref(), Some("0.1"));
    assert_eq!(
        report.output.validation.program_id.as_deref(),
        semantic_rejection["program_id"].as_str()
    );

    let mut over_limit = program();
    over_limit["program_id"] = json!("secret-oversized-identifier");
    let report = validator_with_limits(ValidationLimits {
        max_string_chars: 24,
        ..ValidationLimits::default()
    })
    .validate_bytes(&serde_json::to_vec(&over_limit).unwrap());
    assert!(diagnostic_codes(&report).contains(&ValidatorReasonCode::IrLimitStringLength));
    assert!(report.output.validation.ir_version.is_none());
    assert!(report.output.validation.program_id.is_none());
}

#[test]
fn out_of_range_metadata_numbers_are_inert_but_semantic_numbers_stay_bounded() {
    let validator = validator();
    let baseline = validator.validate_bytes(&serde_json::to_vec(&program()).unwrap());
    for node_metadata in [false, true] {
        let mut input = program();
        if node_metadata {
            input["nodes"][0]["metadata"] = json!({"score":"RAW_NUMBER"});
        } else {
            input["metadata"] = json!({"score":"RAW_NUMBER"});
        }
        let report = validator.validate_bytes(&with_token(&input, "1e9999"));
        assert!(report.output.validation.valid);
        assert_eq!(
            report.output.validation.semantic_hash,
            baseline.output.validation.semantic_hash
        );
        assert_eq!(report.normalized, baseline.normalized);
    }

    let mut semantic = program();
    semantic["nodes"][0]["constraints"] = json!({"min_memory_bytes":"RAW_NUMBER"});
    let report = validator.validate_bytes(&with_token(&semantic, "1e9999"));
    assert!(!report.output.validation.valid);
    assert!(report.output.validation.semantic_hash.is_none());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn both_numeric_profiles_are_total_on_bounded_bytes(bytes in prop::collection::vec(any::<u8>(), 0..8192)) {
        use aios_registry::numbers::{NumberProfile, prepare_numbers};
        for profile in [NumberProfile::IrIntegers, NumberProfile::RegistryTolerance] {
            let result = std::panic::catch_unwind(|| prepare_numbers(&bytes, profile));
            prop_assert!(result.is_ok());
        }
    }

    #[test]
    fn exact_decimal_spellings_have_one_identity(value in 0_u64..=9_007_199_254_740_991) {
        let validator = validator();
        let mut input = program();
        input["nodes"][0]["constraints"] = json!({"min_memory_bytes":"RAW_NUMBER"});
        let baseline = validator.validate_bytes(&with_token(&input, &value.to_string()));
        for token in [format!("{value}.000"), format!("{value}e0"), format!("{value}0e-1")] {
            let report = validator.validate_bytes(&with_token(&input, &token));
            prop_assert!(report.output.validation.valid);
            prop_assert_eq!(&report.output.validation.semantic_hash, &baseline.output.validation.semantic_hash);
        }
        let fractional = validator.validate_bytes(&with_token(&input, &format!("{value}.000000000000000000001")));
        prop_assert!(!fractional.output.validation.valid);
        prop_assert!(fractional.output.validation.semantic_hash.is_none());
    }
}
