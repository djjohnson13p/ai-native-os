//! AIOS IR v0.1 authoring representation.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::serde_support::{default_true, deserialize_non_null_option};

/// Non-authoritative metadata is the sole intentionally generic JSON escape
/// hatch in the semantic IR model. It is inert and excluded from semantic
/// hashing, authority, effects, provider selection, and verification.
pub type Metadata = BTreeMap<String, Value>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiosIr {
    pub ir_version: String,
    pub program_id: String,
    pub kind: ProgramKind,
    pub inputs: BTreeMap<String, ProgramInput>,
    pub nodes: Vec<Node>,
    pub outputs: BTreeMap<String, ValueRef>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub metadata: Option<Metadata>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramKind {
    TaskGraph,
    SkillGraph,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramInput {
    #[serde(rename = "type")]
    pub type_ref: String,
    #[serde(default = "default_true")]
    pub required: bool,
    #[serde(default)]
    pub media_types: Vec<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub id: String,
    pub operation: Operation,
    pub execution_class: ExecutionClass,
    pub inputs: BTreeMap<String, ValueRef>,
    pub outputs: BTreeMap<String, String>,
    pub authority_requests: Vec<AuthorityRequest>,
    pub egress: Egress,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub constraints: Option<Constraints>,
    pub failure: FailurePolicy,
    pub cache: CachePolicy,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub metadata: Option<Metadata>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub kind: OperationKind,
    pub capability: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    Invoke,
    Verify,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionClass {
    Deterministic,
    BoundedNondeterministic,
    Probabilistic,
    OpaqueExternal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum ValueRef {
    Input { name: String },
    Node { node: String, port: String },
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRequest {
    pub action: String,
    pub resource: String,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Egress {
    pub mode: EgressMode,
    #[serde(default)]
    pub destination_classes: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressMode {
    Deny,
    Policy,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Constraints {
    #[serde(default)]
    pub locality: Vec<Locality>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_latency_ms: Option<u64>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_cost_microusd: Option<u64>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub min_memory_bytes: Option<u64>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub accelerator: Option<AcceleratorConstraint>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Locality {
    Local,
    Peer,
    Remote,
    Hybrid,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceleratorConstraint {
    pub kind: AcceleratorKind,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub min_memory_bytes: Option<u64>,
    #[serde(default)]
    pub optional: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceleratorKind {
    Gpu,
    Npu,
    Dsp,
    Fpga,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "on_error", rename_all = "snake_case", deny_unknown_fields)]
pub enum FailurePolicy {
    Stop,
    Retry { max_attempts: u8 },
    Fallback { fallback_capabilities: Vec<String> },
    Replan { max_replans: u8 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CachePolicy {
    Never,
    DeterministicOnly,
    ContentAddressed,
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEMONSTRATION_A: &str = include_str!("../../../examples/aios-ir/demonstration-a.ir.json");
    const VALID_CASES: &str = include_str!("../../../examples/aios-ir/valid-cases.json");

    #[test]
    fn materializes_schema_defaults() {
        let input: ProgramInput = serde_json::from_str(r#"{"type":"artifact.file@1"}"#).unwrap();
        assert!(input.required);

        let accelerator: AcceleratorConstraint = serde_json::from_str(r#"{"kind":"gpu"}"#).unwrap();
        assert!(!accelerator.optional);
    }

    #[test]
    fn rejects_unknown_semantic_fields() {
        let value = r#"{
            "ir_version":"0.1",
            "program_id":"test",
            "kind":"task_graph",
            "inputs":{},
            "nodes":[],
            "outputs":{},
            "task_id":"T-1"
        }"#;
        assert!(serde_json::from_str::<AiosIr>(value).is_err());
    }

    #[test]
    fn rejects_null_for_omittable_non_nullable_fields() {
        assert!(
            serde_json::from_str::<ProgramInput>(
                r#"{"type":"artifact.file@1","description":null}"#
            )
            .is_err()
        );
    }

    #[test]
    fn repository_positive_ir_fixtures_deserialize() {
        serde_json::from_str::<AiosIr>(DEMONSTRATION_A).unwrap();

        let cases: Vec<Value> = serde_json::from_str(VALID_CASES).unwrap();
        for case in cases {
            serde_json::from_value::<AiosIr>(case["program"].clone()).unwrap();
        }
    }
}
