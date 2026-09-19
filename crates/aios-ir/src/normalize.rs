//! Semantic projection and normalization for AIOS IR v0.1.

use aios_contracts::AiosIr;
use serde_json::Value;

/// Builds the canonical semantic JSON view used for identity and hashing.
///
/// The view excludes authoring identity and prose, materializes schema defaults,
/// sorts set-like collections, sorts nodes by stable node ID, and deliberately
/// preserves the order of fallback capabilities.
///
/// # Errors
///
/// Returns an error if the closed typed program cannot be projected to JSON or
/// if its serialized root does not have the required object shape.
pub(crate) fn normalize_semantic_program(program: &AiosIr) -> Result<Value, String> {
    let mut value = serde_json::to_value(program).map_err(|error| error.to_string())?;
    normalize_semantic_value(&mut value)?;
    Ok(value)
}

fn normalize_semantic_value(value: &mut Value) -> Result<(), String> {
    let root = value
        .as_object_mut()
        .ok_or_else(|| "serialized AIOS IR was not an object".to_owned())?;

    root.remove("program_id");
    root.remove("metadata");

    if let Some(inputs) = root.get_mut("inputs").and_then(Value::as_object_mut) {
        for input in inputs.values_mut() {
            if let Some(input) = input.as_object_mut() {
                input.remove("description");
                sort_string_array(input.get_mut("media_types"));
                remove_empty_array(input, "media_types");
            }
        }
    }

    if let Some(nodes) = root.get_mut("nodes").and_then(Value::as_array_mut) {
        for node in nodes.iter_mut() {
            normalize_node(node);
        }
        nodes.sort_by(|left, right| {
            left.get("id")
                .and_then(Value::as_str)
                .cmp(&right.get("id").and_then(Value::as_str))
        });
    }

    Ok(())
}

fn normalize_node(node: &mut Value) {
    let Some(node) = node.as_object_mut() else {
        return;
    };

    node.remove("description");
    node.remove("metadata");

    if let Some(requests) = node
        .get_mut("authority_requests")
        .and_then(Value::as_array_mut)
    {
        for request in requests.iter_mut() {
            if let Some(request) = request.as_object_mut() {
                request.remove("reason");
            }
        }
        requests.sort_by(|left, right| {
            let left_key = (
                left.get("action").and_then(Value::as_str),
                left.get("resource").and_then(Value::as_str),
            );
            let right_key = (
                right.get("action").and_then(Value::as_str),
                right.get("resource").and_then(Value::as_str),
            );
            left_key.cmp(&right_key)
        });
    }

    if let Some(egress) = node.get_mut("egress").and_then(Value::as_object_mut) {
        sort_string_array(egress.get_mut("destination_classes"));
        remove_empty_array(egress, "destination_classes");
    }

    let remove_constraints =
        if let Some(constraints) = node.get_mut("constraints").and_then(Value::as_object_mut) {
            sort_string_array(constraints.get_mut("locality"));
            remove_empty_array(constraints, "locality");
            constraints.is_empty()
        } else {
            false
        };
    if remove_constraints {
        node.remove("constraints");
    }
}

fn sort_string_array(value: Option<&mut Value>) {
    if let Some(values) = value.and_then(Value::as_array_mut) {
        values.sort_by(|left, right| match (left.as_str(), right.as_str()) {
            (Some(left), Some(right)) => left.encode_utf16().cmp(right.encode_utf16()),
            _ => left.to_string().cmp(&right.to_string()),
        });
    }
}

fn remove_empty_array(object: &mut serde_json::Map<String, Value>, key: &str) {
    if object
        .get(key)
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
    {
        object.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use aios_contracts::AiosIr;

    use super::{normalize_semantic_program, normalize_semantic_value};

    #[test]
    fn excludes_prose_and_sorts_set_like_arrays() {
        let program: AiosIr = serde_json::from_str(
            r#"{
                "ir_version":"0.1",
                "program_id":"authoring-id",
                "kind":"task_graph",
                "inputs":{"source":{"type":"artifact.file@1","media_types":["z","a"],"description":"prose"}},
                "nodes":[{
                    "id":"copy","operation":{"kind":"invoke","capability":"artifact.copy@1"},
                    "execution_class":"deterministic",
                    "inputs":{"source":{"source":"input","name":"source"}},
                    "outputs":{"copy":"artifact.file@1"},
                    "authority_requests":[
                        {"action":"artifact.write","resource":"task.output","reason":"why"},
                        {"action":"artifact.read","resource":"input:source"}
                    ],
                    "egress":{"mode":"deny","destination_classes":[]},
                    "constraints":{},"failure":{"on_error":"stop"},"cache":"content_addressed",
                    "description":"prose","metadata":{"ignored":true}
                }],
                "outputs":{"copy":{"source":"node","node":"copy","port":"copy"}},
                "metadata":{"ignored":true}
            }"#,
        )
        .unwrap();

        let normalized = normalize_semantic_program(&program).unwrap();
        assert!(normalized.get("program_id").is_none());
        assert!(normalized.get("metadata").is_none());
        assert_eq!(
            normalized.pointer("/inputs/source/media_types").unwrap(),
            &serde_json::json!(["a", "z"])
        );
        assert!(normalized.pointer("/nodes/0/constraints").is_none());
        assert!(normalized.pointer("/nodes/0/description").is_none());
        assert_eq!(
            normalized.pointer("/nodes/0/authority_requests/0/action"),
            Some(&serde_json::json!("artifact.read"))
        );

        let mut normalized_twice = normalized.clone();
        normalize_semantic_value(&mut normalized_twice).unwrap();
        assert_eq!(normalized, normalized_twice);
    }

    #[test]
    fn semantic_string_sets_use_jcs_utf16_order() {
        let program: AiosIr = serde_json::from_value(serde_json::json!({
            "ir_version":"0.1",
            "program_id":"unicode-order",
            "kind":"task_graph",
            "inputs":{"source":{
                "type":"artifact.file@1",
                "media_types":["\u{e000}","\u{1f600}"]
            }},
            "nodes":[],
            "outputs":{}
        }))
        .unwrap();
        let normalized = normalize_semantic_program(&program).unwrap();
        assert_eq!(
            normalized.pointer("/inputs/source/media_types"),
            Some(&serde_json::json!(["\u{1f600}", "\u{e000}"]))
        );
    }
}
