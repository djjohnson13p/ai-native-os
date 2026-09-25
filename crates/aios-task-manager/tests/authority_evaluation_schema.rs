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
        "purpose",
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

    for field in [
        "purpose",
        "source_content_hash",
        "operation_id",
        "adapter_id",
        "descriptor_hash",
        "max_size_bytes",
    ] {
        let mut null_field = valid.clone();
        null_field["egress"][field] = Value::Null;
        assert!(!validator.is_valid(&null_field), "null {field}");
    }

    let mut empty_purpose = valid.clone();
    empty_purpose["egress"]["purpose"] = json!("");
    assert!(!validator.is_valid(&empty_purpose), "empty purpose");

    let mut missing_sensitivity = valid.clone();
    missing_sensitivity["resource"]
        .as_object_mut()
        .unwrap()
        .remove("sensitivity");
    assert!(
        !validator.is_valid(&missing_sensitivity),
        "missing sensitivity"
    );

    let mut null_sensitivity = valid.clone();
    null_sensitivity["resource"]["sensitivity"] = Value::Null;
    assert!(!validator.is_valid(&null_sensitivity), "null sensitivity");

    let mut multiple_sources = valid.clone();
    multiple_sources["egress"]["data_refs"] = json!(["artifact:source", "artifact:other"]);
    assert!(!validator.is_valid(&multiple_sources), "multiple sources");

    let mut empty_source = valid;
    empty_source["egress"]["data_refs"] = json!([""]);
    assert!(!validator.is_valid(&empty_source), "empty source reference");

    let mut class_only = exact_export();
    class_only["resource"]["resolved_id"] = json!("fixture-export");
    class_only["egress"]["service_id"] = json!("fixture-export");
    assert!(!validator.is_valid(&class_only), "class-only destination");
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

fn schema(source: &str) -> jsonschema::Validator {
    let document: Value = serde_json::from_str(source).unwrap();
    jsonschema::options()
        .should_validate_formats(true)
        .build(&document)
        .unwrap()
}

fn export_pin() -> Value {
    let request = exact_export();
    json!({
        "selector": request["resource"]["semantic_selector"],
        "service_id": request["egress"]["service_id"],
        "destination_class": request["egress"]["destination_class"],
        "descriptor_hash": request["egress"]["descriptor_hash"],
        "adapter_id": request["egress"]["adapter_id"],
        "operation_id": request["egress"]["operation_id"],
        "source_artifact_id": request["egress"]["data_refs"][0],
        "source_content_hash": request["egress"]["source_content_hash"],
        "purpose": request["egress"]["purpose"],
        "sensitivity": request["resource"]["sensitivity"],
        "max_size_bytes": request["egress"]["max_size_bytes"]
    })
}

#[test]
fn downstream_egress_records_require_the_exact_export_pin_and_one_shot_scope() {
    let pin = export_pin();
    let grant_schema = schema(include_str!(
        "../../../specs/authority-grant-record.schema.json"
    ));
    let mut grant: Value = serde_json::from_str(include_str!(
        "../../../examples/authority/grant-local-read.json"
    ))
    .unwrap();
    grant["grants"][0] = json!({"action":"data.egress",
        "resource_kind":"external-destination","resource_id":pin["service_id"],
        "external_export":pin});
    assert!(grant_schema.is_valid(&grant));
    let mut missing = grant.clone();
    missing["grants"][0]
        .as_object_mut()
        .unwrap()
        .remove("external_export");
    assert!(!grant_schema.is_valid(&missing));
    let mut wrong_grant_action = grant.clone();
    wrong_grant_action["grants"][0]["action"] = json!("artifact.read");
    assert!(!grant_schema.is_valid(&wrong_grant_action));
    let mut wrong_scope = grant.clone();
    wrong_scope["scope"] = json!("TASK");
    assert!(!grant_schema.is_valid(&wrong_scope));
    let mut unlimited = grant.clone();
    unlimited["max_uses"] = json!(2);
    assert!(!grant_schema.is_valid(&unlimited));

    let decision_schema = schema(include_str!("../../../specs/policy-decision.schema.json"));
    let request = exact_export();
    let mut decision = json!({"schema_version":"0.1","decision_id":"decision:export",
        "authority_request_id":request["request_id"],"task_id":request["task_id"],
        "semantic_program_hash":request["semantic_program_hash"],
        "registry_snapshot_id":request["registry_snapshot_id"],"node_id":request["node_id"],
        "capability":request["capability"],"principal":request["principal"],
        "action":"data.egress","resource":{"resolved_kind":"external-destination",
            "resolved_id":request["resource"]["resolved_id"],"external_export":export_pin()},
        "decision":"DENY","policy_snapshot_id":"policy:fixture",
        "reason_codes":["AUTH_DENY_POLICY"],"decided_at":request["requested_at"]});
    assert!(decision_schema.is_valid(&decision));
    decision["resource"]
        .as_object_mut()
        .unwrap()
        .remove("external_export");
    assert!(!decision_schema.is_valid(&decision));
    decision["resource"]["external_export"] = export_pin();
    decision["action"] = json!("artifact.read");
    assert!(!decision_schema.is_valid(&decision));

    let approval_schema = schema(include_str!("../../../specs/approval-request.schema.json"));
    let mut approval = json!({"schema_version":"0.1","approval_id":"approval:export",
        "authority_request_id":request["request_id"],"task_id":request["task_id"],
        "semantic_program_hash":request["semantic_program_hash"],"node_id":request["node_id"],
        "action":"data.egress","resource":{"kind":"external-destination",
            "id":request["resource"]["resolved_id"],"display_class":"fixture"},
        "principal":request["principal"],"destination":{"class":"fixture",
            "service_id":request["resource"]["resolved_id"]},"export":export_pin(),
        "scope":"ONE_SHOT","effect_classes":["DATA_EGRESS"],"status":"PENDING",
        "created_at":request["requested_at"],"expires_at":request["requested_at"]});
    assert!(approval_schema.is_valid(&approval));
    approval.as_object_mut().unwrap().remove("export");
    assert!(!approval_schema.is_valid(&approval));
    approval["export"] = export_pin();
    approval["action"] = json!("artifact.read");
    assert!(!approval_schema.is_valid(&approval));
    let sample: Value = serde_json::from_str(include_str!(
        "../../../examples/authority/approval-egress.json"
    ))
    .unwrap();
    assert!(
        approval_schema.is_valid(&sample),
        "sample: {:?}",
        approval_schema.iter_errors(&sample).collect::<Vec<_>>()
    );
}
