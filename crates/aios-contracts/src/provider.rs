//! Provider capability-manifest DTOs.
//!
//! These records describe implementation claims only. They never grant Task
//! authority and this crate performs no provider loading or execution.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ir::{ExecutionClass, Locality};
use crate::registry::EffectClass;
use crate::serde_support::{deserialize_non_null_option, deserialize_required_nullable};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityManifest {
    pub schema_version: String,
    pub id: String,
    pub version: String,
    pub publisher: ProviderPublisher,
    pub runtime: ProviderRuntime,
    pub provides: Vec<ProviderCapability>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub trust: Option<ProviderTrust>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderPublisher {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub source_url: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRuntime {
    pub kind: ProviderRuntimeKind,
    #[serde(default)]
    pub entrypoint: Option<String>,
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default)]
    pub digest: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderRuntimeKind {
    Builtin,
    Process,
    Varlink,
    Oci,
    Wasm,
    ModelAdapter,
    LegacyAdapter,
    Remote,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCapability {
    pub contract: ProviderContractClaim,
    pub conformance: ProviderConformance,
    pub effect_classes: Vec<EffectClass>,
    pub execution: ProviderExecution,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub authority: Option<ProviderAuthority>,
    #[serde(default)]
    pub representations: BTreeMap<String, Vec<String>>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub resource_requirements: Option<ProviderResourceRequirements>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderContractClaim {
    pub capability: String,
    pub version: String,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub contract_hash: Option<String>,
    #[serde(default)]
    pub contract_source: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConformance {
    pub suite: String,
    #[serde(default)]
    pub suite_hash: Option<String>,
    pub status: ConformanceStatus,
    #[serde(default)]
    pub tested_at: Option<String>,
    #[serde(default)]
    pub test_environment: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceStatus {
    Declared,
    Tested,
    Certified,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderExecution {
    pub locality: Vec<Locality>,
    pub execution_class: ExecutionClass,
    pub minimum_isolation: IsolationProfile,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub network_default: Option<NetworkDefault>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum IsolationProfile {
    P0,
    P1,
    P2,
    P3,
    P4,
    P5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkDefault {
    None,
    Allowlist,
    Internet,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAuthority {
    #[serde(default)]
    pub actions: Vec<String>,
    #[serde(default)]
    pub resource_classes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderResourceRequirements {
    #[serde(default)]
    pub min_memory_bytes: Option<u64>,
    #[serde(default)]
    pub preferred_accelerators: Vec<String>,
    #[serde(default)]
    pub requires_gpu: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderTrust {
    #[serde(default)]
    pub source_hash: Option<String>,
    #[serde(default)]
    pub build_provenance: Option<String>,
    #[serde(default)]
    pub review_status: Option<ProviderReviewStatus>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderReviewStatus {
    Unreviewed,
    ProjectReviewed,
    ThirdPartyReviewed,
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::CapabilityManifest;

    const PROVIDER_CASES: &str =
        include_str!("../../../examples/aios-ir/provider-conformance-cases.json");

    #[test]
    fn repository_provider_manifest_fixtures_deserialize() {
        let cases: Vec<Value> = serde_json::from_str(PROVIDER_CASES).unwrap();
        for case in cases {
            serde_json::from_value::<CapabilityManifest>(case["provider"].clone()).unwrap();
        }
    }
}
