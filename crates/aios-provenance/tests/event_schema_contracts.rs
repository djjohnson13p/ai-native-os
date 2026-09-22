//! Standalone provenance payload fixtures and runtime shape bounds.

use serde_json::{Value, json};

fn validator() -> jsonschema::Validator {
    let schema: Value =
        serde_json::from_str(include_str!("../../../specs/provenance-event.schema.json")).unwrap();
    jsonschema::validator_for(&schema).unwrap()
}

fn cases() -> Value {
    serde_json::from_str(include_str!(
        "../../../examples/provenance/event-schema-cases.json"
    ))
    .unwrap()
}

#[test]
fn event_payload_fixtures_match_schema() {
    let validator = validator();
    for case in cases()["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let expected = case["valid"].as_bool().unwrap();
        assert_eq!(
            validator.is_valid(&case["event"]),
            expected,
            "unexpected schema verdict for {name}"
        );
    }
}

#[test]
fn artifact_arrays_obey_runtime_512_item_bound() {
    let validator = validator();
    let fixture = cases();
    let base = &fixture["cases"][0]["event"];

    for field in ["input_artifacts", "output_artifacts"] {
        let mut event = base.clone();
        event[field] = json!(
            (0..512)
                .map(|index| format!("artifact:{index}"))
                .collect::<Vec<_>>()
        );
        assert!(validator.is_valid(&event), "{field} with 512 items");
        event[field]
            .as_array_mut()
            .unwrap()
            .push(json!("artifact:512"));
        assert!(!validator.is_valid(&event), "{field} with 513 items");
    }

    let mut event = base.clone();
    event["external_transfer"] = json!({
        "destination": "local",
        "data_refs": (0..512).map(|index| format!("artifact:{index}")).collect::<Vec<_>>()
    });
    assert!(validator.is_valid(&event), "data_refs with 512 items");
    event["external_transfer"]["data_refs"]
        .as_array_mut()
        .unwrap()
        .push(json!("artifact:512"));
    assert!(!validator.is_valid(&event), "data_refs with 513 items");
}

#[test]
fn strings_obey_runtime_identity_and_global_bounds() {
    let validator = validator();
    let fixture = cases();
    let base = &fixture["cases"][0]["event"];

    for field in ["event_id", "task_id"] {
        let mut event = base.clone();
        event[field] = json!("x".repeat(256));
        assert!(validator.is_valid(&event), "{field} with 256 characters");
        event[field] = json!("x".repeat(257));
        assert!(!validator.is_valid(&event), "{field} with 257 characters");
    }

    let mut event = base.clone();
    event["actor"]["id"] = json!("x".repeat(256));
    assert!(validator.is_valid(&event), "actor.id with 256 characters");
    event["actor"]["id"] = json!("x".repeat(257));
    assert!(!validator.is_valid(&event), "actor.id with 257 characters");

    let mut event = base.clone();
    event["input_artifacts"] = json!(["x".repeat(4096)]);
    assert!(
        validator.is_valid(&event),
        "artifact reference with 4096 characters"
    );
    event["input_artifacts"] = json!(["x".repeat(4097)]);
    assert!(
        !validator.is_valid(&event),
        "artifact reference with 4097 characters"
    );
}
