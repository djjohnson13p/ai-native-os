//! Cross-language portable projection fixtures checked against the Rust verifier.

use std::{fs, path::PathBuf};

use aios_provenance::verify_jsonl_export;
use serde_json::Value;

const VERIFIED_AT: &str = "2026-09-22T00:00:00Z";

fn fixture_path(case: &str, name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/provenance/portable-v1")
        .join(case)
        .join(name)
}

#[test]
fn portable_projection_fixtures_match_offline_verifier() {
    let result_schema: Value = serde_json::from_str(include_str!(
        "../../../specs/provenance-projection-verification-result.schema.json"
    ))
    .unwrap();
    let result_validator = jsonschema::validator_for(&result_schema).unwrap();

    for case in ["positive", "tampered", "wrong-namespace"] {
        let manifest = fs::read_to_string(fixture_path(case, "manifest.json")).unwrap();
        let records = fs::read_to_string(fixture_path(case, "records.jsonl")).unwrap();
        let expected: Value = serde_json::from_str(
            &fs::read_to_string(fixture_path(case, "expected-result.json")).unwrap(),
        )
        .unwrap();
        assert!(
            result_validator.is_valid(&expected),
            "invalid expected result for {case}"
        );

        let actual = verify_jsonl_export(&manifest, &records, VERIFIED_AT).unwrap();
        let actual = serde_json::to_value(actual).unwrap();
        assert_eq!(actual, expected, "offline verification differed for {case}");
    }
}

#[test]
fn result_schema_rejects_unbounded_diagnostics_and_missing_success_head() {
    let schema: Value = serde_json::from_str(include_str!(
        "../../../specs/provenance-projection-verification-result.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let positive: Value = serde_json::from_str(
        &fs::read_to_string(fixture_path("positive", "expected-result.json")).unwrap(),
    )
    .unwrap();

    let mut missing_head = positive.clone();
    missing_head["computed_projection_head_hash"] = Value::Null;
    assert!(!validator.is_valid(&missing_head));

    let mut extra_field = positive.clone();
    extra_field["valid"] = Value::Bool(false);
    extra_field["diagnostics"] = serde_json::json!([{
        "severity": "error",
        "code": "PROJECTION_RECORD_INVALID",
        "message": "shape invalid",
        "raw_private_value": "must not be allowed"
    }]);
    assert!(!validator.is_valid(&extra_field));

    let mut unknown_code = extra_field.clone();
    unknown_code["diagnostics"][0]
        .as_object_mut()
        .unwrap()
        .remove("raw_private_value");
    unknown_code["diagnostics"][0]["code"] = Value::String("PROJECTION_UNKNOWN".into());
    assert!(!validator.is_valid(&unknown_code));
}
