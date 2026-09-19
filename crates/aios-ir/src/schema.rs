//! Embedded, resolver-free JSON Schema validation for AIOS IR v0.1.

use std::sync::OnceLock;

use aios_contracts::{Diagnostic, ValidatorReasonCode};
use serde_json::Value;

use crate::diagnostics::DiagnosticCollector;

const AIOS_IR_SCHEMA: &str = include_str!("../../../specs/aios-ir.schema.json");
static COMPILED_SCHEMA: OnceLock<Result<jsonschema::Validator, String>> = OnceLock::new();

pub(crate) fn validate_schema(
    value: &Value,
    diagnostics: &mut DiagnosticCollector,
) -> Result<(), String> {
    let validator = match COMPILED_SCHEMA.get_or_init(|| {
        let schema: Value = serde_json::from_str(AIOS_IR_SCHEMA)
            .map_err(|error| format!("embedded AIOS IR schema is invalid JSON: {error}"))?;
        jsonschema::validator_for(&schema)
            .map_err(|error| format!("embedded AIOS IR schema could not compile: {error}"))
    }) {
        Ok(validator) => validator,
        Err(message) => return Err(message.clone()),
    };
    // jsonschema yields failures lazily. Feed them directly into the bounded
    // collector and stop after the first suppressed diagnostic, so hostile
    // documents cannot amplify into an unbounded intermediate Vec.
    for error in validator.iter_errors(value) {
        let message = error.to_string();
        let code = classify_schema_failure(error.kind());
        let instance_path = error.instance_path().as_str();
        let mut diagnostic = Diagnostic::new(code, message);
        diagnostic.json_pointer = Some(if instance_path.is_empty() {
            "/".to_owned()
        } else {
            instance_path.to_owned()
        });
        diagnostics.push(diagnostic);
        if diagnostics.is_truncated() {
            break;
        }
    }
    Ok(())
}

fn classify_schema_failure(kind: &jsonschema::error::ValidationErrorKind) -> ValidatorReasonCode {
    use jsonschema::error::ValidationErrorKind as Kind;
    match kind {
        Kind::Required { .. } => ValidatorReasonCode::IrSchemaRequired,
        Kind::Pattern { .. } => ValidatorReasonCode::IrSchemaPattern,
        Kind::PropertyNames { error } => classify_schema_failure(error.kind()),
        Kind::AdditionalProperties { .. } | Kind::UnevaluatedProperties { .. } => {
            ValidatorReasonCode::IrSchemaAdditionalProperty
        }
        Kind::Enum { .. } | Kind::Constant { .. } => ValidatorReasonCode::IrSchemaEnum,
        Kind::Minimum { .. }
        | Kind::Maximum { .. }
        | Kind::ExclusiveMinimum { .. }
        | Kind::ExclusiveMaximum { .. }
        | Kind::MinItems { .. }
        | Kind::MaxItems { .. }
        | Kind::MinLength { .. }
        | Kind::MaxLength { .. }
        | Kind::MinProperties { .. }
        | Kind::MaxProperties { .. }
        | Kind::UniqueItems
        | Kind::MultipleOf { .. } => ValidatorReasonCode::IrSchemaRange,
        _ => ValidatorReasonCode::IrSchemaType,
    }
}
