//! Semantic type, capability, and immutable registry-snapshot contracts.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ir::ExecutionClass;
use crate::serde_support::deserialize_non_null_option;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectClass {
    Pure,
    ArtifactRead,
    ArtifactWrite,
    Network,
    DataEgress,
    ExternalMessage,
    SecretAccess,
    PersistentState,
    DeviceAccess,
    SystemChange,
    LegacyOpaque,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityContract {
    pub capability: String,
    pub version: String,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    #[serde(default)]
    pub role: CapabilityRole,
    pub inputs: BTreeMap<String, PortContract>,
    pub outputs: BTreeMap<String, PortContract>,
    pub allowed_execution_classes: Vec<ExecutionClass>,
    pub required_effect_classes: Vec<EffectClass>,
    pub allowed_effect_classes: Vec<EffectClass>,
    pub required_authority_classes: Vec<String>,
    pub allowed_authority_classes: Vec<String>,
    pub allowed_egress_modes: Vec<crate::ir::EgressMode>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub determinism: Option<Determinism>,
    pub error_classes: Vec<String>,
    pub conformance: Conformance,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityRole {
    #[default]
    Ordinary,
    Verifier,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortContract {
    #[serde(rename = "type")]
    pub type_ref: String,
    pub required: bool,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Determinism {
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub equivalence: Option<DeterminismEquivalence>,
    #[serde(default)]
    pub numeric_absolute_tolerance: Option<f64>,
    #[serde(default)]
    pub numeric_relative_tolerance: Option<f64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeterminismEquivalence {
    ByteIdentical,
    CanonicalValue,
    NumericTolerance,
    Semantic,
    NotApplicable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Conformance {
    pub suite_id: String,
    #[serde(default)]
    pub suite_version: Option<String>,
    #[serde(default)]
    pub suite_hash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypeContract {
    pub type_id: String,
    pub version: String,
    pub kind: TypeKind,
    pub description: String,
    #[serde(default)]
    pub logical_schema_ref: Option<String>,
    #[serde(default)]
    pub nullable: bool,
    pub representations: Vec<Representation>,
    pub equality: TypeEquality,
    #[serde(default)]
    pub unit_semantics: Option<UnitSemantics>,
    #[serde(default)]
    pub conversion_capabilities: Vec<String>,
    pub conformance: Conformance,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeKind {
    Scalar,
    Structured,
    Artifact,
    Stream,
    Handle,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Representation {
    pub id: String,
    #[serde(default)]
    pub media_type: Option<String>,
    #[serde(default)]
    pub schema_ref: Option<String>,
    #[serde(default)]
    pub zero_copy_candidate: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypeEquality {
    pub mode: EqualityMode,
    #[serde(default)]
    pub canonicalizer: Option<String>,
    #[serde(default)]
    pub numeric_absolute_tolerance: Option<f64>,
    #[serde(default)]
    pub numeric_relative_tolerance: Option<f64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EqualityMode {
    ByteIdentical,
    CanonicalValue,
    NumericTolerance,
    Semantic,
    NotDefined,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitSemantics {
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub unit_required: Option<bool>,
    #[serde(default)]
    pub canonical_unit: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrySnapshot {
    pub schema_version: String,
    pub snapshot_id: String,
    #[serde(default)]
    pub generation: Option<String>,
    pub type_contracts: Vec<ContractRef>,
    pub capability_contracts: Vec<ContractRef>,
    pub created_at: String,
    #[serde(default)]
    pub publisher: Option<RegistryPublisher>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractRef {
    pub id: String,
    pub version: String,
    pub content_hash: String,
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryPublisher {
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub id: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAPABILITY_CONTRACTS: &str =
        include_str!("../../../examples/aios-ir/capability-contracts.json");
    const REGISTRY_SNAPSHOT: &str =
        include_str!("../../../examples/aios-ir/registry-snapshot.json");
    const TYPE_CONTRACTS: &str = include_str!("../../../examples/aios-ir/type-contracts.json");

    #[test]
    fn materializes_registry_contract_defaults() {
        let role: CapabilityRole = serde_json::from_str(r#""ordinary""#).unwrap();
        assert_eq!(role, CapabilityRole::Ordinary);

        let representation: Representation =
            serde_json::from_str(r#"{"id":"canonical","media_type":null,"schema_ref":null}"#)
                .unwrap();
        assert!(!representation.zero_copy_candidate);
    }

    #[test]
    fn unit_required_distinguishes_absence_from_explicit_null() {
        let absent: UnitSemantics = serde_json::from_str("{}").unwrap();
        assert_eq!(absent.unit_required, None);
        assert!(
            serde_json::to_value(absent)
                .unwrap()
                .get("unit_required")
                .is_none()
        );
        assert!(serde_json::from_str::<UnitSemantics>(r#"{"unit_required":null}"#).is_err());
        for boolean in [true, false] {
            let unit: UnitSemantics =
                serde_json::from_value(serde_json::json!({"unit_required":boolean})).unwrap();
            assert_eq!(unit.unit_required, Some(boolean));
        }
    }

    #[test]
    fn effect_names_use_the_canonical_vocabulary() {
        assert_eq!(
            serde_json::to_string(&EffectClass::DataEgress).unwrap(),
            r#""DATA_EGRESS""#
        );
    }

    #[test]
    fn repository_registry_fixtures_deserialize() {
        let capabilities: Vec<CapabilityContract> =
            serde_json::from_str(CAPABILITY_CONTRACTS).unwrap();
        let types: Vec<TypeContract> = serde_json::from_str(TYPE_CONTRACTS).unwrap();
        let snapshot: RegistrySnapshot = serde_json::from_str(REGISTRY_SNAPSHOT).unwrap();

        assert_eq!(capabilities.len(), 11);
        assert_eq!(types.len(), 10);
        assert_eq!(snapshot.capability_contracts.len(), capabilities.len());
        assert_eq!(snapshot.type_contracts.len(), types.len());
    }
}
