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
