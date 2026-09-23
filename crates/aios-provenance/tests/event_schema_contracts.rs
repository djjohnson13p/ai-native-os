//! Standalone provenance payload fixtures and runtime shape bounds.

use aios_provenance::{
    HASH_PROFILE, JournalRecord, SCHEMA_VERSION, hash_record, stream_id, verify_records,
};
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
fn event_payload_fixtures_match_runtime_verifier() {
    let fixture = cases();
    let chain: Value = serde_json::from_str(include_str!(
        "../../../examples/provenance/chain-cases.json"
    ))
    .unwrap();
    let mut genesis = chain["base_stream"]["events"][0]["event"].clone();
    genesis["task_id"] = json!("task:fixture");
    genesis["event_id"] = json!("event:genesis");
    let stream = stream_id("task:fixture").unwrap();
    let genesis_hash = hash_record(&stream, 1, None, &genesis).unwrap();
    let first = JournalRecord {
        schema_version: SCHEMA_VERSION.to_owned(),
        hash_profile: HASH_PROFILE.to_owned(),
        stream_id: stream.clone(),
        sequence: 1,
        previous_event_hash: None,
        event: genesis,
        event_hash: genesis_hash.clone(),
    };

    for case in fixture["cases"].as_array().unwrap() {
        let event = &case["event"];
        let second = JournalRecord {
            schema_version: SCHEMA_VERSION.to_owned(),
            hash_profile: HASH_PROFILE.to_owned(),
            stream_id: stream.clone(),
            sequence: 2,
            previous_event_hash: Some(genesis_hash.clone()),
            event: event.clone(),
            event_hash: hash_record(&stream, 2, Some(&genesis_hash), event).unwrap(),
        };
        let result = verify_records(
            &[first.clone(), second],
            &stream,
            None,
            "2026-01-02T00:00:00Z",
        )
        .unwrap();
        assert_eq!(
            result.valid,
            case["valid"].as_bool().unwrap(),
            "{}",
            case["name"]
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
