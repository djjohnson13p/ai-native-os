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
    Validator::new(
        SemanticRegistry::load_bundle(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/aios-ir"),
            RegistryLoadOptions::default(),
        )
        .unwrap(),
        ValidationLimits::default(),
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
        let mut input = program();
        input["nodes"][0][key.as_str().unwrap()] = json!("synthetic");
        let report = validator.validate_bytes(&serde_json::to_vec(&input).unwrap());
        assert!(!report.output.validation.valid);
        assert!(report.output.validation.semantic_hash.is_none());
        assert!(
            report.output.validation.diagnostics.iter().all(
                |diagnostic| diagnostic.code == ValidatorReasonCode::IrSchemaAdditionalProperty
            ),
            "{key}: {:?}",
            report.output.validation.diagnostics
        );
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
        let expected = case["reason_code"]
            .as_str()
            .unwrap()
            .parse::<ValidatorReasonCode>()
            .unwrap();
        let report = validator.validate_bytes(&serde_json::to_vec(&input).unwrap());
        let codes = report
            .output
            .validation
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code)
            .collect::<Vec<_>>();

        assert!(!report.output.validation.valid, "{case}");
        assert!(report.output.validation.semantic_hash.is_none(), "{case}");
        assert!(report.normalized.is_none(), "{case}");
        assert_eq!(codes, vec![expected], "{case}");
    }
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
