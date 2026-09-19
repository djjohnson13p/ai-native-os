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
        let schema_path = error.schema_path().as_str();
        let message = error.to_string();
        let code = classify_schema_failure(schema_path, &message);
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

fn classify_schema_failure(schema_path: &str, message: &str) -> ValidatorReasonCode {
    let lower = message.to_ascii_lowercase();
    if schema_path.ends_with("/required") || lower.contains("required propert") {
        ValidatorReasonCode::IrSchemaRequired
    } else if schema_path.ends_with("/pattern")
        || lower.contains("pattern")
        || lower.contains(" does not match ")
    {
        ValidatorReasonCode::IrSchemaPattern
    } else if schema_path.ends_with("/additionalProperties")
        || lower.contains("additional propert")
        || lower.contains("unexpected propert")
    {
        ValidatorReasonCode::IrSchemaAdditionalProperty
    } else if schema_path.ends_with("/enum")
        || schema_path.ends_with("/const")
        || lower.contains("not one of")
        || lower.contains("constant")
    {
        ValidatorReasonCode::IrSchemaEnum
    } else if schema_path.ends_with("/minimum")
        || schema_path.ends_with("/maximum")
        || schema_path.ends_with("/minItems")
        || schema_path.ends_with("/maxItems")
        || schema_path.ends_with("/minLength")
        || schema_path.ends_with("/maxLength")
        || schema_path.ends_with("/minProperties")
        || schema_path.ends_with("/maxProperties")
        || schema_path.ends_with("/uniqueItems")
        || lower.contains("minimum")
        || lower.contains("maximum")
        || lower.contains("too short")
        || lower.contains("too long")
        || lower.contains("not unique")
    {
        ValidatorReasonCode::IrSchemaRange
    } else {
        ValidatorReasonCode::IrSchemaType
    }
}
