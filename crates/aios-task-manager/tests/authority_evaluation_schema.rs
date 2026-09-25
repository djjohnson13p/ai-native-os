//! Sealed external-export authority request schema regressions.

use serde_json::{Value, json};

fn validator() -> jsonschema::Validator {
    let schema: Value = serde_json::from_str(include_str!(
        "../../../specs/authority-evaluation-request.schema.json"
    ))
    .unwrap();
    jsonschema::options()
        .should_validate_formats(true)
        .build(&schema)
        .unwrap()
}

fn exact_export() -> Value {
    serde_json::from_str(include_str!(
        "../../../examples/authority/evaluation-exact-export.json"
    ))
    .unwrap()
}

#[test]
fn exact_export_requires_the_sealed_tuple() {
    let validator = validator();
    let valid = exact_export();
    assert!(
        validator.is_valid(&valid),
        "valid fixture: {:?}",
        validator.iter_errors(&valid).collect::<Vec<_>>()
    );

    let mut missing = valid.clone();
    missing.as_object_mut().unwrap().remove("egress");
    assert!(!validator.is_valid(&missing), "missing egress");

    let mut null = valid.clone();
    null["egress"] = Value::Null;
    assert!(!validator.is_valid(&null), "null egress");

    for field in [
        "destination_class",
        "service_id",
        "data_refs",
        "source_content_hash",
        "operation_id",
        "adapter_id",
        "descriptor_hash",
        "max_size_bytes",
    ] {
        let mut incomplete = valid.clone();
        incomplete["egress"].as_object_mut().unwrap().remove(field);
        assert!(!validator.is_valid(&incomplete), "missing {field}");
    }
}

#[test]
fn egress_action_and_resource_kind_must_match() {
    let validator = validator();
    let valid = exact_export();

    let mut wrong_kind = valid.clone();
    wrong_kind["resource"]["resolved_kind"] = json!("artifact");
    assert!(!validator.is_valid(&wrong_kind));

    let mut wrong_action = valid;
    wrong_action["action"] = json!("artifact.read");
    assert!(!validator.is_valid(&wrong_action));
}

#[test]
fn existing_local_read_with_null_or_missing_egress_remains_valid() {
    let validator = validator();
    let local_read: Value = serde_json::from_str(include_str!(
        "../../../examples/authority/evaluation-local-read.json"
    ))
    .unwrap();
    assert!(validator.is_valid(&local_read));
    let mut omitted = local_read;
    omitted.as_object_mut().unwrap().remove("egress");
    assert!(validator.is_valid(&omitted));
}
