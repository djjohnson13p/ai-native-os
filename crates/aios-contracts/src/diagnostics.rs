//! Stable machine-readable diagnostics for validator and provider conformance.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

macro_rules! validator_reason_codes {
    ($( $variant:ident => ($code:literal, $severity:ident, $stage:ident) ),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub enum ValidatorReasonCode {
            $(#[serde(rename = $code)] $variant,)+
        }

        impl ValidatorReasonCode {
            pub const ALL: &'static [Self] = &[$(Self::$variant,)+];

            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $code,)+
                }
            }

            pub const fn severity(self) -> Severity {
                match self {
                    $(Self::$variant => Severity::$severity,)+
                }
            }

            pub const fn stage(self) -> ValidationStage {
                match self {
                    $(Self::$variant => ValidationStage::$stage,)+
                }
            }
        }

        impl fmt::Display for ValidatorReasonCode {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl FromStr for ValidatorReasonCode {
            type Err = UnknownReasonCode;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value {
                    $($code => Ok(Self::$variant),)+
                    _ => Err(UnknownReasonCode(value.to_owned())),
                }
            }
        }
    };
}

validator_reason_codes! {
    IrParseInvalid => ("IR_PARSE_INVALID", Error, Parse),
    IrParseDuplicateKey => ("IR_PARSE_DUPLICATE_KEY", Error, Parse),
    IrSchemaRequired => ("IR_SCHEMA_REQUIRED", Error, Schema),
    IrSchemaAdditionalProperty => ("IR_SCHEMA_ADDITIONAL_PROPERTY", Error, Schema),
    IrSchemaEnum => ("IR_SCHEMA_ENUM", Error, Schema),
    IrSchemaPattern => ("IR_SCHEMA_PATTERN", Error, Schema),
    IrSchemaType => ("IR_SCHEMA_TYPE", Error, Schema),
    IrSchemaRange => ("IR_SCHEMA_RANGE", Error, Schema),
    IrVersionUnsupported => ("IR_VERSION_UNSUPPORTED", Error, Schema),
    IrLimitDocumentSize => ("IR_LIMIT_DOCUMENT_SIZE", Error, Limits),
    IrLimitDepth => ("IR_LIMIT_DEPTH", Error, Limits),
    IrLimitNodeCount => ("IR_LIMIT_NODE_COUNT", Error, Limits),
    IrLimitPortCount => ("IR_LIMIT_PORT_COUNT", Error, Limits),
    IrLimitAuthorityRequestCount => ("IR_LIMIT_AUTHORITY_REQUEST_COUNT", Error, Limits),
    IrLimitFallbackCount => ("IR_LIMIT_FALLBACK_COUNT", Error, Limits),
    IrLimitStringLength => ("IR_LIMIT_STRING_LENGTH", Error, Limits),
    IrLimitDiagnostics => ("IR_LIMIT_DIAGNOSTICS", Warning, Limits),
    IrGraphDuplicateNodeId => ("IR_GRAPH_DUPLICATE_NODE_ID", Error, Graph),
    IrGraphCycle => ("IR_GRAPH_CYCLE", Error, Graph),
    IrGraphUnusedPureNode => ("IR_GRAPH_UNUSED_PURE_NODE", Warning, Graph),
    IrReferenceInputNotFound => ("IR_REFERENCE_INPUT_NOT_FOUND", Error, References),
    IrReferenceNodeNotFound => ("IR_REFERENCE_NODE_NOT_FOUND", Error, References),
    IrReferencePortNotFound => ("IR_REFERENCE_PORT_NOT_FOUND", Error, References),
    IrOutputNotFound => ("IR_OUTPUT_NOT_FOUND", Error, References),
    IrTypeNotFound => ("IR_TYPE_NOT_FOUND", Error, Types),
    IrTypeMismatch => ("IR_TYPE_MISMATCH", Error, Types),
    IrOptionalInputToRequiredPort => ("IR_OPTIONAL_INPUT_TO_REQUIRED_PORT", Error, Types),
    IrCapabilityNotFound => ("IR_CAPABILITY_NOT_FOUND", Error, Capabilities),
    IrCapabilityPortMismatch => ("IR_CAPABILITY_PORT_MISMATCH", Error, Capabilities),
    IrCapabilityRoleMismatch => ("IR_CAPABILITY_ROLE_MISMATCH", Error, Capabilities),
    IrExecutionClassIncompatible => ("IR_EXECUTION_CLASS_INCOMPATIBLE", Error, Capabilities),
    IrAuthorityClassNotAllowed => ("IR_AUTHORITY_CLASS_NOT_ALLOWED", Error, EffectsAuthority),
    IrRequiredAuthorityMissing => ("IR_REQUIRED_AUTHORITY_MISSING", Error, EffectsAuthority),
    IrAuthorityDuplicateRequest => ("IR_AUTHORITY_DUPLICATE_REQUEST", Error, EffectsAuthority),
    IrEffectClassNotAllowed => ("IR_EFFECT_CLASS_NOT_ALLOWED", Error, EffectsAuthority),
    IrEgressNotAllowed => ("IR_EGRESS_NOT_ALLOWED", Error, EffectsAuthority),
    IrEgressContradiction => ("IR_EGRESS_CONTRADICTION", Error, EffectsAuthority),
    IrEgressAuthorityMismatch => ("IR_EGRESS_AUTHORITY_MISMATCH", Error, EffectsAuthority),
    IrCacheExecutionClassMismatch => ("IR_CACHE_EXECUTION_CLASS_MISMATCH", Error, EffectsAuthority),
    IrFailurePolicyUnbounded => ("IR_FAILURE_POLICY_UNBOUNDED", Error, FailureFallback),
    IrFailurePolicyRecursiveFallback => ("IR_FAILURE_POLICY_RECURSIVE_FALLBACK", Error, FailureFallback),
    IrFallbackPortMismatch => ("IR_FALLBACK_PORT_MISMATCH", Error, FailureFallback),
    IrFallbackEffectBroadening => ("IR_FALLBACK_EFFECT_BROADENING", Error, FailureFallback),
    IrFallbackAuthorityBroadening => ("IR_FALLBACK_AUTHORITY_BROADENING", Error, FailureFallback),
    IrFallbackEgressBroadening => ("IR_FALLBACK_EGRESS_BROADENING", Error, FailureFallback),
    IrCanonicalizationFailed => ("IR_CANONICALIZATION_FAILED", Error, Canonicalization),
    RegistrySchemaInvalid => ("REGISTRY_SCHEMA_INVALID", Error, Registry),
    RegistryUnsupportedVersion => ("REGISTRY_UNSUPPORTED_VERSION", Error, Registry),
    RegistryDuplicateTypeMajor => ("REGISTRY_DUPLICATE_TYPE_MAJOR", Error, Registry),
    RegistryDuplicateCapabilityMajor => ("REGISTRY_DUPLICATE_CAPABILITY_MAJOR", Error, Registry),
    RegistryEntryNotFound => ("REGISTRY_ENTRY_NOT_FOUND", Error, Registry),
    RegistryContractVersionMismatch => ("REGISTRY_CONTRACT_VERSION_MISMATCH", Error, Registry),
    RegistryContractHashMismatch => ("REGISTRY_CONTRACT_HASH_MISMATCH", Error, Registry),
    RegistrySnapshotHashMismatch => ("REGISTRY_SNAPSHOT_HASH_MISMATCH", Error, Registry),
    RegistryRequiredEffectNotAllowed => ("REGISTRY_REQUIRED_EFFECT_NOT_ALLOWED", Error, Registry),
    RegistryRequiredAuthorityNotAllowed => ("REGISTRY_REQUIRED_AUTHORITY_NOT_ALLOWED", Error, Registry),
    RegistryPureEffectContradiction => ("REGISTRY_PURE_EFFECT_CONTRADICTION", Error, Registry),
}

macro_rules! provider_reason_codes {
    ($( $variant:ident => $code:literal ),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub enum ProviderReasonCode {
            $(#[serde(rename = $code)] $variant,)+
        }

        impl ProviderReasonCode {
            pub const ALL: &'static [Self] = &[$(Self::$variant,)+];

            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $code,)+
                }
            }
        }

        impl fmt::Display for ProviderReasonCode {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl FromStr for ProviderReasonCode {
            type Err = UnknownReasonCode;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value {
                    $($code => Ok(Self::$variant),)+
                    _ => Err(UnknownReasonCode(value.to_owned())),
                }
            }
        }
    };
}

provider_reason_codes! {
    ProviderContractNotFound => "PROVIDER_CONTRACT_NOT_FOUND",
    ProviderContractHashMismatch => "PROVIDER_CONTRACT_HASH_MISMATCH",
    ProviderExecutionClassIncompatible => "PROVIDER_EXECUTION_CLASS_INCOMPATIBLE",
    ProviderEffectNotAllowed => "PROVIDER_EFFECT_NOT_ALLOWED",
    ProviderRequiredEffectMissing => "PROVIDER_REQUIRED_EFFECT_MISSING",
    ProviderAuthorityNotAllowed => "PROVIDER_AUTHORITY_NOT_ALLOWED",
    ProviderRequiredAuthorityMissing => "PROVIDER_REQUIRED_AUTHORITY_MISSING",
    ProviderEgressNotAllowed => "PROVIDER_EGRESS_NOT_ALLOWED",
    ProviderPortOrTypeMismatch => "PROVIDER_PORT_OR_TYPE_MISMATCH",
    ProviderIsolationIncompatible => "PROVIDER_ISOLATION_INCOMPATIBLE",
    ProviderSuiteMismatch => "PROVIDER_SUITE_MISMATCH",
    ProviderBuildIdentityMissing => "PROVIDER_BUILD_IDENTITY_MISSING",
    ProviderConformanceFailed => "PROVIDER_CONFORMANCE_FAILED",
    ProviderConformanceExpired => "PROVIDER_CONFORMANCE_EXPIRED",
    ProviderDeclarationInvalid => "PROVIDER_DECLARATION_INVALID",
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStage {
    Parse,
    Schema,
    Limits,
    Graph,
    References,
    Types,
    Capabilities,
    EffectsAuthority,
    FailureFallback,
    Canonicalization,
    Registry,
}

/// Machine-readable `specs/validator-reason-codes.json` document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorReasonCodeCatalog {
    pub schema_version: String,
    pub profile: String,
    pub codes: Vec<ValidatorReasonCodeEntry>,
}

/// One validator/registry reason-code catalog entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorReasonCodeEntry {
    pub code: ValidatorReasonCode,
    pub severity: Severity,
    pub stage: ValidationStage,
}

/// Machine-readable provider-conformance reason-code catalog document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderReasonCodeCatalog {
    pub schema_version: String,
    pub namespace: String,
    pub profile: String,
    pub codes: Vec<ProviderReasonCodeEntry>,
}

/// One provider-conformance reason-code catalog entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderReasonCodeEntry {
    pub code: ProviderReasonCode,
    pub meaning: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnostic {
    pub severity: Severity,
    pub code: ValidatorReasonCode,
    pub message: String,
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default)]
    pub port: Option<String>,
    #[serde(default)]
    pub capability: Option<String>,
    #[serde(default)]
    pub json_pointer: Option<String>,
    #[serde(default)]
    pub related: Vec<String>,
}

impl Diagnostic {
    pub fn new(code: ValidatorReasonCode, message: impl Into<String>) -> Self {
        Self {
            severity: code.severity(),
            code,
            message: message.into(),
            node_id: None,
            port: None,
            capability: None,
            json_pointer: None,
            related: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownReasonCode(pub String);

impl fmt::Display for UnknownReasonCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "unknown reason code: {}", self.0)
    }
}

impl std::error::Error for UnknownReasonCode {}

#[cfg(test)]
mod tests {
    use super::*;

    const PROVIDER_CATALOG: &str =
        include_str!("../../../specs/provider-conformance-reason-codes.json");
    const VALIDATOR_CATALOG: &str = include_str!("../../../specs/validator-reason-codes.json");

    #[test]
    fn catalogs_are_complete_and_round_trip() {
        assert_eq!(ValidatorReasonCode::ALL.len(), 57);
        assert_eq!(ProviderReasonCode::ALL.len(), 15);

        for code in ValidatorReasonCode::ALL {
            let serialized = serde_json::to_string(code).unwrap();
            assert_eq!(serialized, format!(r#""{}""#, code.as_str()));
            assert_eq!(code.as_str().parse::<ValidatorReasonCode>().unwrap(), *code);
        }

        for code in ProviderReasonCode::ALL {
            let serialized = serde_json::to_string(code).unwrap();
            assert_eq!(serialized, format!(r#""{}""#, code.as_str()));
            assert_eq!(code.as_str().parse::<ProviderReasonCode>().unwrap(), *code);
        }
    }

    #[test]
    fn warning_severity_is_catalog_owned() {
        assert_eq!(
            ValidatorReasonCode::IrGraphUnusedPureNode.severity(),
            Severity::Warning
        );
        assert_eq!(
            ValidatorReasonCode::IrLimitDiagnostics.severity(),
            Severity::Warning
        );
        assert_eq!(
            ValidatorReasonCode::IrGraphCycle.severity(),
            Severity::Error
        );
    }

    #[test]
    fn checked_in_catalogs_match_the_closed_enums() {
        let validator: ValidatorReasonCodeCatalog =
            serde_json::from_str(VALIDATOR_CATALOG).unwrap();
        let provider: ProviderReasonCodeCatalog = serde_json::from_str(PROVIDER_CATALOG).unwrap();

        assert_eq!(validator.codes.len(), ValidatorReasonCode::ALL.len());
        for entry in validator.codes {
            assert!(ValidatorReasonCode::ALL.contains(&entry.code));
            assert_eq!(entry.severity, entry.code.severity());
            assert_eq!(entry.stage, entry.code.stage());
        }

        assert_eq!(provider.codes.len(), ProviderReasonCode::ALL.len());
        for entry in provider.codes {
            assert!(ProviderReasonCode::ALL.contains(&entry.code));
        }
    }
}
