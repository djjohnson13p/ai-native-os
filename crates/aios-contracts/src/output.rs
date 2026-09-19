//! Validator result and derived effect-summary contracts.

use serde::{Deserialize, Serialize};

use crate::diagnostics::Diagnostic;
use crate::ir::{EgressMode, ExecutionClass};
use crate::registry::EffectClass;
use crate::serde_support::{deserialize_non_null_option, deserialize_required_nullable};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationResult {
    pub schema_version: String,
    pub valid: bool,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub ir_version: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub program_id: Option<String>,
    #[serde(default)]
    pub semantic_hash: Option<String>,
    #[serde(default)]
    pub semantic_hash_profile: Option<String>,
    pub validator: ValidatorIdentity,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub registry_snapshot_id: Option<String>,
    pub diagnostics: Vec<Diagnostic>,
    #[serde(default)]
    pub diagnostics_truncated: bool,
    pub validated_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorIdentity {
    pub id: String,
    pub version: String,
    #[serde(default)]
    pub build_hash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectSummary {
    pub schema_version: String,
    pub semantic_program_hash: String,
    pub registry_snapshot_id: String,
    pub effects: Vec<EffectClass>,
    pub authority_classes: Vec<String>,
    pub egress_modes: Vec<EgressMode>,
    pub contains_probabilistic: bool,
    pub contains_opaque_external: bool,
    pub nodes: Vec<NodeEffectSummary>,
    /// Verifier-node inventory, not a proof that every output is gated or verified.
    pub verification_barriers: Vec<String>,
    #[serde(default)]
    pub generated_by: Option<GeneratedBy>,
    #[serde(default)]
    pub generated_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeEffectSummary {
    pub node_id: String,
    pub capability: String,
    pub execution_class: ExecutionClass,
    pub effects: Vec<EffectClass>,
    pub authority_classes: Vec<String>,
    pub egress_mode: EgressMode,
    #[serde(default)]
    /// Identifies a verifier operation, not successful verification of any output.
    pub verification_gate: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedBy {
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub version: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorOutput {
    pub schema_version: String,
    pub validation: ValidationResult,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub effect_summary: Option<EffectSummary>,
}

#[cfg(test)]
mod tests {
    use super::{EffectSummary, ValidationResult, ValidatorOutput};

    const EFFECT_SUMMARY: &str =
        include_str!("../../../examples/aios-ir/demonstration-a.effect-summary.json");
    const VALIDATION_RESULT: &str =
        include_str!("../../../examples/aios-ir/validation-result.json");
    const VALIDATOR_OUTPUT: &str = include_str!("../../../examples/aios-ir/validator-output.json");

    #[test]
    fn repository_validator_output_fixtures_deserialize() {
        serde_json::from_str::<EffectSummary>(EFFECT_SUMMARY).unwrap();
        serde_json::from_str::<ValidationResult>(VALIDATION_RESULT).unwrap();
        serde_json::from_str::<ValidatorOutput>(VALIDATOR_OUTPUT).unwrap();
    }
}
