//! End-to-end deterministic validation pipeline.

use aios_contracts::{
    AiosIr, Diagnostic, ValidationResult, ValidatorIdentity, ValidatorOutput, ValidatorReasonCode,
};
use aios_registry::SemanticRegistry;
use serde::Serialize;
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::diagnostics::DiagnosticCollector;
use crate::hash::semantic_hash;
use crate::limits::{LimitViolation, ValidationLimits, inspect_value_limits};
use crate::normalize::normalize_semantic_program;
use crate::parse::{StrictJsonError, parse_strict_json};
use crate::schema::validate_schema;
use crate::semantics::analyze;

const VALIDATOR_ID: &str = "org.ainative.aios-ir-validator";
const HASH_PROFILE: &str = "aios-ir-v0.1";

/// Complete library result. `normalized` is available only for a valid program
/// and is intentionally outside the normative validator-output bundle.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ValidationReport {
    /// Normative validator output defined by `validator-output.schema.json`.
    #[serde(flatten)]
    pub output: ValidatorOutput,
    /// Canonical semantic JSON view, omitted from serialized full validation output.
    #[serde(skip)]
    pub normalized: Option<Value>,
}

/// Immutable registry-backed validator.
pub struct Validator {
    registry: SemanticRegistry,
    limits: ValidationLimits,
}

impl Validator {
    /// Creates a validator using one immutable registry snapshot and fixed limits.
    ///
    /// Diagnostic output is always clamped to the bounds of the normative output
    /// schema. A registry not loaded with strict hash verification is rejected by
    /// every validation call and can never produce executable semantic identity.
    pub fn new(registry: SemanticRegistry, limits: ValidationLimits) -> Self {
        Self {
            registry,
            limits: limits.bounded_for_output(),
        }
    }

    /// Validates bytes and records the current UTC time in the non-semantic result envelope.
    pub fn validate_bytes(&self, bytes: &[u8]) -> ValidationReport {
        self.validate_bytes_at(bytes, OffsetDateTime::now_utc())
    }

    /// Validates bytes with an injected timestamp for reproducible tests and tooling.
    pub fn validate_bytes_at(
        &self,
        bytes: &[u8],
        validated_at: OffsetDateTime,
    ) -> ValidationReport {
        let validated_at = format_timestamp(validated_at);
        self.validate_bytes_at_rfc3339(bytes, &validated_at)
    }

    #[allow(clippy::too_many_lines)]
    fn validate_bytes_at_rfc3339(&self, bytes: &[u8], validated_at: &str) -> ValidationReport {
        let mut collector = DiagnosticCollector::new(self.limits.max_diagnostics);
        if !self.registry.is_strictly_verified() {
            collector.error(
                ValidatorReasonCode::RegistrySnapshotHashMismatch,
                "registry snapshot was not loaded with strict identity verification",
            );
            return invalid_report(None, None, None, collector, validated_at);
        }
        if bytes.len() > self.limits.max_document_bytes {
            collector.error(
                ValidatorReasonCode::IrLimitDocumentSize,
                format!(
                    "document is {} bytes; configured maximum is {}",
                    bytes.len(),
                    self.limits.max_document_bytes
                ),
            );
            return self.invalid_report(None, None, collector, validated_at);
        }

        let value = match parse_strict_json(bytes, self.limits.max_depth) {
            Ok(value) => value,
            Err(StrictJsonError::DepthLimit) => {
                collector.error(
                    ValidatorReasonCode::IrLimitDepth,
                    format!(
                        "document exceeds configured JSON depth {}",
                        self.limits.max_depth
                    ),
                );
                return self.invalid_report(None, None, collector, validated_at);
            }
            Err(StrictJsonError::DuplicateKey(key)) => {
                collector.error(
                    ValidatorReasonCode::IrParseDuplicateKey,
                    format!("JSON object contains duplicate key '{key}'"),
                );
                return self.invalid_report(None, None, collector, validated_at);
            }
            Err(StrictJsonError::Invalid(message)) => {
                collector.error(ValidatorReasonCode::IrParseInvalid, message);
                return self.invalid_report(None, None, collector, validated_at);
            }
        };

        for violation in inspect_value_limits(&value, self.limits) {
            let (code, message) = match violation {
                LimitViolation::NodeCount => (
                    ValidatorReasonCode::IrLimitNodeCount,
                    "program exceeds the configured node limit",
                ),
                LimitViolation::PortCount => (
                    ValidatorReasonCode::IrLimitPortCount,
                    "an interface exceeds the configured port limit",
                ),
                LimitViolation::AuthorityRequestCount => (
                    ValidatorReasonCode::IrLimitAuthorityRequestCount,
                    "a node exceeds the configured authority-request limit",
                ),
                LimitViolation::FallbackCount => (
                    ValidatorReasonCode::IrLimitFallbackCount,
                    "a node exceeds the configured fallback limit",
                ),
                LimitViolation::StringLength => (
                    ValidatorReasonCode::IrLimitStringLength,
                    "a JSON member name or string exceeds the configured string limit",
                ),
            };
            collector.error(code, message);
        }
        if collector.has_errors() {
            return self.invalid_report(None, None, collector, validated_at);
        }

        domain_prechecks(&value, &mut collector);
        if collector.has_errors() {
            return self.invalid_report(None, None, collector, validated_at);
        }

        if let Err(message) = validate_schema(&value, &mut collector) {
            collector.error(ValidatorReasonCode::IrSchemaType, message);
        }
        if collector.has_errors() {
            return self.invalid_report(None, None, collector, validated_at);
        }

        let ir_version = value
            .get("ir_version")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let program_id = value
            .get("program_id")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let program: AiosIr = match serde_json::from_value(value) {
            Ok(program) => program,
            Err(error) => {
                collector.error(
                    ValidatorReasonCode::IrSchemaType,
                    format!("schema-valid document did not decode to the closed IR model: {error}"),
                );
                return self.invalid_report(ir_version, program_id, collector, validated_at);
            }
        };

        let mut summary = analyze(&program, &self.registry, &mut collector);
        if collector.has_errors() {
            return self.invalid_report(
                Some(program.ir_version),
                Some(program.program_id),
                collector,
                validated_at,
            );
        }

        let normalized = match normalize_semantic_program(&program) {
            Ok(normalized) => normalized,
            Err(error) => {
                collector.error(ValidatorReasonCode::IrCanonicalizationFailed, error);
                return self.invalid_report(
                    Some(program.ir_version.clone()),
                    Some(program.program_id.clone()),
                    collector,
                    validated_at,
                );
            }
        };
        let hash = match semantic_hash(&normalized) {
            Ok(hash) => hash,
            Err(error) => {
                collector.error(ValidatorReasonCode::IrCanonicalizationFailed, error);
                return self.invalid_report(
                    Some(program.ir_version.clone()),
                    Some(program.program_id.clone()),
                    collector,
                    validated_at,
                );
            }
        };

        let summary_ref = summary.as_mut().expect("valid analysis has a summary");
        summary_ref.semantic_program_hash.clone_from(&hash);
        summary_ref.generated_at = Some(validated_at.to_owned());

        let (diagnostics, diagnostics_truncated) = collector.finish();
        let validation = ValidationResult {
            schema_version: "0.1".to_owned(),
            valid: true,
            ir_version: Some(program.ir_version),
            program_id: Some(program.program_id),
            semantic_hash: Some(hash),
            semantic_hash_profile: Some(HASH_PROFILE.to_owned()),
            validator: validator_identity(),
            registry_snapshot_id: Some(self.registry.snapshot_id().to_owned()),
            diagnostics,
            diagnostics_truncated,
            validated_at: validated_at.to_owned(),
        };
        ValidationReport {
            output: ValidatorOutput {
                schema_version: "0.1".to_owned(),
                validation,
                effect_summary: summary,
            },
            normalized: Some(normalized),
        }
    }

    fn invalid_report(
        &self,
        ir_version: Option<String>,
        program_id: Option<String>,
        collector: DiagnosticCollector,
        validated_at: &str,
    ) -> ValidationReport {
        invalid_report(
            ir_version,
            program_id,
            Some(self.registry.snapshot_id().to_owned()),
            collector,
            validated_at,
        )
    }
}

/// Builds a normative, bounded rejection report for a registry failure that
/// occurs before a validator can be constructed.
pub fn rejected_registry_report(
    code: ValidatorReasonCode,
    message: impl Into<String>,
) -> ValidationReport {
    let mut collector = DiagnosticCollector::new(1);
    collector.error(code, message);
    invalid_report(
        None,
        None,
        None,
        collector,
        &format_timestamp(OffsetDateTime::now_utc()),
    )
}

fn invalid_report(
    ir_version: Option<String>,
    program_id: Option<String>,
    registry_snapshot_id: Option<String>,
    collector: DiagnosticCollector,
    validated_at: &str,
) -> ValidationReport {
    let (diagnostics, diagnostics_truncated) = collector.finish();
    ValidationReport {
        output: ValidatorOutput {
            schema_version: "0.1".to_owned(),
            validation: ValidationResult {
                schema_version: "0.1".to_owned(),
                valid: false,
                ir_version,
                program_id,
                semantic_hash: None,
                semantic_hash_profile: None,
                validator: validator_identity(),
                registry_snapshot_id,
                diagnostics,
                diagnostics_truncated,
                validated_at: validated_at.to_owned(),
            },
            effect_summary: None,
        },
        normalized: None,
    }
}

fn format_timestamp(timestamp: OffsetDateTime) -> String {
    timestamp
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

fn domain_prechecks(value: &Value, collector: &mut DiagnosticCollector) {
    if let Some(version) = value.get("ir_version").and_then(Value::as_str) {
        if version != "0.1" {
            collector.error(
                ValidatorReasonCode::IrVersionUnsupported,
                format!("IR version '{version}' is not supported; expected 0.1"),
            );
            return;
        }
    }

    let Some(nodes) = value.get("nodes").and_then(Value::as_array) else {
        return;
    };
    for (index, node) in nodes.iter().enumerate() {
        if let Some(failure) = node.get("failure").and_then(Value::as_object) {
            let on_error = failure.get("on_error").and_then(Value::as_str);
            let missing_budget = matches!(on_error, Some("retry"))
                && !failure.contains_key("max_attempts")
                || matches!(on_error, Some("replan")) && !failure.contains_key("max_replans");
            if missing_budget {
                let mut diagnostic = Diagnostic::new(
                    ValidatorReasonCode::IrFailurePolicyUnbounded,
                    "retry and replan failure policies require an explicit finite budget",
                );
                diagnostic.node_id = node.get("id").and_then(Value::as_str).map(str::to_owned);
                diagnostic.json_pointer = Some(format!("/nodes/{index}/failure"));
                collector.push(diagnostic);
            }
        }
        if let Some(egress) = node.get("egress").and_then(Value::as_object) {
            let deny = egress.get("mode").and_then(Value::as_str) == Some("deny");
            let names_destinations = egress
                .get("destination_classes")
                .and_then(Value::as_array)
                .is_some_and(|destinations| !destinations.is_empty());
            if deny && names_destinations {
                let mut diagnostic = Diagnostic::new(
                    ValidatorReasonCode::IrEgressContradiction,
                    "deny egress cannot name destination classes",
                );
                diagnostic.node_id = node.get("id").and_then(Value::as_str).map(str::to_owned);
                diagnostic.json_pointer = Some(format!("/nodes/{index}/egress"));
                collector.push(diagnostic);
            }
        }
    }
}

fn validator_identity() -> ValidatorIdentity {
    ValidatorIdentity {
        id: VALIDATOR_ID.to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        build_hash: option_env!("AIOS_VALIDATOR_BUILD_HASH").map(str::to_owned),
    }
}
