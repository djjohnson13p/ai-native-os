//! Contracts for the synthetic provenance journal chain fixture.

use aios_provenance::{
    HASH_PROFILE, JournalRecord, SCHEMA_VERSION, hash_record, stream_id, verify_records,
};
use serde_json::Value;

#[test]
fn generated_base_chain_validates() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../examples/provenance/chain-cases.json"
    ))
    .unwrap();
    let base = &fixture["base_stream"];
    let entries = base["events"].as_array().unwrap();
    let task_id = entries[0]["event"]["task_id"].as_str().unwrap();
    let derived_stream_id = stream_id(task_id).unwrap();

    assert_eq!(base["stream_id"].as_str(), Some(derived_stream_id.as_str()));
    assert_eq!(fixture["profile"].as_str(), Some(HASH_PROFILE));
    assert_eq!(fixture["hashes"].as_str(), Some("GENERATE_AT_TEST_TIME"));
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "generated-base-chain-validates")
        .unwrap();
    assert_eq!(case["expected_valid"].as_bool(), Some(true));

    let mut records = Vec::with_capacity(entries.len());
    let mut previous: Option<String> = None;
    for (index, entry) in entries.iter().enumerate() {
        let sequence = u64::try_from(index + 1).unwrap();
        assert_eq!(entry["sequence"].as_u64(), Some(sequence));
        assert_eq!(entry["event"]["task_id"].as_str(), Some(task_id));
        if index == 0 {
            assert!(entry["previous"].is_null());
        } else {
            let symbolic_previous = format!("HASH_OF_SEQUENCE_{index}");
            assert_eq!(entry["previous"].as_str(), Some(symbolic_previous.as_str()));
        }

        let event = entry["event"].clone();
        let event_hash =
            hash_record(&derived_stream_id, sequence, previous.as_deref(), &event).unwrap();
        records.push(JournalRecord {
            schema_version: SCHEMA_VERSION.to_owned(),
            hash_profile: HASH_PROFILE.to_owned(),
            stream_id: derived_stream_id.clone(),
            sequence,
            previous_event_hash: previous.replace(event_hash.clone()),
            event,
            event_hash,
        });
    }

    let result =
        verify_records(&records, &derived_stream_id, None, "2026-09-22T00:00:00Z").unwrap();
    assert!(result.valid, "{result:?}");
    assert_eq!(result.to_sequence, u64::try_from(entries.len()).unwrap());
    assert_eq!(result.computed_head_hash, previous);
}
