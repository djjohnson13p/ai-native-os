//! Schema-level regressions for reconciled Task Manager machine contracts.

use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct Cases {
    #[serde(rename = "request_cases")]
    requests: Vec<Case>,
    #[serde(rename = "result_cases")]
    results: Vec<Case>,
    #[serde(rename = "provenance_cases")]
    provenance: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    expected_valid: bool,
    value: Value,
}

#[test]
fn reconciled_task_contract_fixtures_match_their_schemas() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let cases: Cases = serde_json::from_slice(
        &std::fs::read(root.join("examples/task-manager/schema-cases.json")).unwrap(),
    )
    .unwrap();
    for (schema_name, cases) in [
        ("task-transition-request.schema.json", cases.requests),
        ("task-transition-result.schema.json", cases.results),
        ("provenance-event.schema.json", cases.provenance),
    ] {
        let schema: Value =
            serde_json::from_slice(&std::fs::read(root.join("specs").join(schema_name)).unwrap())
                .unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        for case in cases {
            assert_eq!(
                validator.is_valid(&case.value),
                case.expected_valid,
                "{} did not match {schema_name}: {:?}",
                case.name,
                validator.iter_errors(&case.value).collect::<Vec<_>>()
            );
        }
    }
}

#[test]
fn artifact_contract_fixtures_and_reason_codes_are_schema_consistent() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(root.join("examples/artifact-store/publication-cases.json")).unwrap(),
    )
    .unwrap();
    let first = &fixture["cases"][0];
    for (schema_name, value) in [
        (
            "artifact-output-allocation.schema.json",
            first["allocation"].clone(),
        ),
        (
            "artifact-publication-request.schema.json",
            first["request"].clone(),
        ),
    ] {
        let schema: Value =
            serde_json::from_slice(&std::fs::read(root.join("specs").join(schema_name)).unwrap())
                .unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        assert!(
            validator.is_valid(&value),
            "{schema_name}: {:?}",
            validator.iter_errors(&value).collect::<Vec<_>>()
        );
    }

    let handle = serde_json::json!({
        "artifact_id":"artifact:v1:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "uri":"artifact://artifact:v1:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "semantic_type":"artifact.table@1",
        "media_type":"text/csv",
        "format":"csv",
        "size_bytes":4,
        "content_hash":{"algorithm":"sha256","value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        "origin":{"kind":"user","task_id":"T-artifact","semantic_program_hash":null,"step_id":null,"execution_binding_id":null,"provider_id":null},
        "sensitivity":"private",
        "retention":{"class":"task","expires_at":null},
        "integrity":{"state":"verified","verified_at":"2026-09-19T22:00:00Z","verifier":"artifact-store:sha256"},
        "labels":["fixture"],
        "created_at":"2026-09-19T22:00:00Z"
    });
    let schema: Value = serde_json::from_slice(
        &std::fs::read(root.join("specs/artifact-handle.schema.json")).unwrap(),
    )
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(
        validator.is_valid(&handle),
        "artifact handle: {:?}",
        validator.iter_errors(&handle).collect::<Vec<_>>()
    );

    let codes: Value = serde_json::from_slice(
        &std::fs::read(root.join("specs/artifact-reason-codes.json")).unwrap(),
    )
    .unwrap();
    let registered = codes["codes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entry| entry["code"].as_str())
        .collect::<std::collections::BTreeSet<_>>();
    for case in fixture["cases"].as_array().unwrap() {
        if let Some(reason_code) = case
            .pointer("/expected/reason_code")
            .and_then(Value::as_str)
        {
            assert!(
                registered.contains(reason_code),
                "fixture {} uses unregistered {reason_code}",
                case["name"]
            );
        }
    }
}

#[test]
fn artifact_contracts_enforce_exact_type_lineage_and_value_bounds() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let load_validator = |name: &str| {
        let schema: Value =
            serde_json::from_slice(&std::fs::read(root.join("specs").join(name)).unwrap()).unwrap();
        jsonschema::validator_for(&schema).unwrap()
    };
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(root.join("examples/artifact-store/publication-cases.json")).unwrap(),
    )
    .unwrap();
    let first = &fixture["cases"][0];

    let allocation_validator = load_validator("artifact-output-allocation.schema.json");
    let mut allocation = first["allocation"].clone();
    allocation["published_artifact_id"] = Value::String("a".repeat(513));
    assert!(!allocation_validator.is_valid(&allocation));
    allocation = first["allocation"].clone();
    allocation["expected_semantic_type"] = Value::String(format!("{}@0", "a".repeat(254)));
    assert!(allocation_validator.is_valid(&allocation));
    allocation["expected_semantic_type"] = Value::String(format!("{}@0", "a".repeat(255)));
    assert!(!allocation_validator.is_valid(&allocation));

    let request_validator = load_validator("artifact-publication-request.schema.json");
    let mut request = first["request"].clone();
    request["semantic_type"] = Value::String("artifact.report@1@2".to_owned());
    assert!(!request_validator.is_valid(&request));
    request["semantic_type"] = Value::String("artifact.report@1".to_owned());
    request["lineage"]["input_artifact_ids"] = Value::Array(vec![Value::String("a".repeat(513))]);
    assert!(!request_validator.is_valid(&request));
    request["lineage"]["input_artifact_ids"] = Value::Array(Vec::new());
    request["lineage"]["representation_of_object_ids"] =
        Value::Array(vec![Value::String("object://unsupported".to_owned())]);
    assert!(!request_validator.is_valid(&request));

    let handle_validator = load_validator("artifact-handle.schema.json");
    let mut handle = serde_json::json!({
        "artifact_id":"artifact:test",
        "uri":"artifact://artifact:test",
        "semantic_type":"artifact.report@1",
        "media_type":"text/markdown",
        "format":"markdown",
        "size_bytes":1,
        "content_hash":{"algorithm":"sha256","value":"aa"},
        "origin":{"kind":"task"},
        "sensitivity":"private",
        "retention":{"class":"task","expires_at":null},
        "integrity":{"state":"verified","verified_at":null,"verifier":null},
        "labels":["fixture"],
        "created_at":"2026-09-19T22:00:00Z"
    });
    assert!(handle_validator.is_valid(&handle));
    handle["format"] = Value::String("f".repeat(161));
    assert!(!handle_validator.is_valid(&handle));
    handle["format"] = Value::String("markdown".to_owned());
    handle["labels"] = Value::Array(vec![Value::String("l".repeat(257))]);
    assert!(!handle_validator.is_valid(&handle));

    let result_validator = load_validator("artifact-publication-result.schema.json");
    let mut result = serde_json::json!({
        "schema_version":"0.1",
        "publication_id":"pub-bound",
        "allocation_id":"alloc-bound",
        "task_id":"T-bound",
        "published":false,
        "reason_code":"ARTIFACT_AUTHORITY_DENIED",
        "artifact_id":null,
        "resulted_at":"2026-09-19T22:00:00Z"
    });
    assert!(result_validator.is_valid(&result));
    result["artifact_id"] = Value::String("a".repeat(513));
    assert!(!result_validator.is_valid(&result));
}
