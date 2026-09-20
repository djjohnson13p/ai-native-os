//! Embedded, resolver-free JSON Schema validation for AIOS IR v0.1.

use std::collections::BTreeSet;
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
    emit_validator_errors(validator, value, diagnostics);
    Ok(())
}

fn emit_validator_errors(
    validator: &jsonschema::Validator,
    value: &Value,
    diagnostics: &mut DiagnosticCollector,
) {
    // jsonschema yields top-level failures lazily. Feed them into the bounded
    // emitter and stop after the first suppressed diagnostic, so hostile
    // documents cannot amplify into an unbounded intermediate Vec.
    for error in validator.iter_errors(value) {
        emit_schema_failure(&error, diagnostics);
        if diagnostics.is_truncated() {
            break;
        }
    }
}

fn emit_schema_failure(
    error: &jsonschema::ValidationError<'_>,
    diagnostics: &mut DiagnosticCollector,
) {
    use jsonschema::error::ValidationErrorKind as Kind;

    if let Kind::OneOfNotValid { context } = error.kind() {
        match resolve_discriminated_one_of(error, context) {
            OneOfResolution::Selected(branch) => {
                emit_selected_branch_failures(branch, diagnostics);
                return;
            }
            OneOfResolution::Missing => {
                push_schema_diagnostic(error, ValidatorReasonCode::IrSchemaRequired, diagnostics);
                return;
            }
            OneOfResolution::WrongType | OneOfResolution::Ambiguous => {
                push_schema_diagnostic(error, ValidatorReasonCode::IrSchemaType, diagnostics);
                return;
            }
            OneOfResolution::Unsupported => {
                push_schema_diagnostic(error, ValidatorReasonCode::IrSchemaEnum, diagnostics);
                return;
            }
        }
    }

    push_schema_diagnostic(error, classify_schema_failure(error), diagnostics);
}

fn push_schema_diagnostic(
    error: &jsonschema::ValidationError<'_>,
    code: ValidatorReasonCode,
    diagnostics: &mut DiagnosticCollector,
) {
    let instance_path = error.instance_path().as_str();
    let mut diagnostic = Diagnostic::new(code, sanitized_schema_message(code));
    diagnostic.json_pointer = Some(if instance_path.is_empty() {
        "/".to_owned()
    } else {
        instance_path.to_owned()
    });
    diagnostics.push(diagnostic);
}

fn sanitized_schema_message(code: ValidatorReasonCode) -> &'static str {
    match code {
        ValidatorReasonCode::IrSchemaRequired => "a required property is missing",
        ValidatorReasonCode::IrSchemaPattern => "a value does not match the required pattern",
        ValidatorReasonCode::IrSchemaAdditionalProperty => {
            "an object contains an unsupported property"
        }
        ValidatorReasonCode::IrSchemaEnum => "a value is outside the allowed set",
        ValidatorReasonCode::IrSchemaRange => "a value is outside the allowed bounds",
        ValidatorReasonCode::IrSchemaType => "a value has an invalid JSON type or structure",
        _ => "the document violates the AIOS IR schema",
    }
}

fn classify_schema_failure(error: &jsonschema::ValidationError<'_>) -> ValidatorReasonCode {
    use jsonschema::error::ValidationErrorKind as Kind;
    match error.kind() {
        Kind::Required { .. } => ValidatorReasonCode::IrSchemaRequired,
        Kind::Pattern { .. } => ValidatorReasonCode::IrSchemaPattern,
        Kind::PropertyNames { error } => classify_schema_failure(error),
        Kind::AdditionalProperties { .. } | Kind::UnevaluatedProperties { .. } => {
            ValidatorReasonCode::IrSchemaAdditionalProperty
        }
        Kind::Enum { .. } | Kind::Constant { .. } => ValidatorReasonCode::IrSchemaEnum,
        Kind::OneOfNotValid { context } => match resolve_discriminated_one_of(error, context) {
            OneOfResolution::Missing => ValidatorReasonCode::IrSchemaRequired,
            OneOfResolution::Unsupported => ValidatorReasonCode::IrSchemaEnum,
            OneOfResolution::WrongType
            | OneOfResolution::Selected(_)
            | OneOfResolution::Ambiguous => ValidatorReasonCode::IrSchemaType,
        },
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

enum OneOfResolution<'a> {
    Missing,
    WrongType,
    Unsupported,
    Selected(&'a [jsonschema::ValidationError<'static>]),
    Ambiguous,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JsonValueKind {
    Null,
    Boolean,
    Number,
    String,
    Array,
    Object,
}

fn json_value_kind(value: &Value) -> JsonValueKind {
    match value {
        Value::Null => JsonValueKind::Null,
        Value::Bool(_) => JsonValueKind::Boolean,
        Value::Number(_) => JsonValueKind::Number,
        Value::String(_) => JsonValueKind::String,
        Value::Array(_) => JsonValueKind::Array,
        Value::Object(_) => JsonValueKind::Object,
    }
}

fn resolve_discriminated_one_of<'a>(
    error: &jsonschema::ValidationError<'_>,
    branches: &'a [Vec<jsonschema::ValidationError<'static>>],
) -> OneOfResolution<'a> {
    use jsonschema::error::ValidationErrorKind as Kind;

    // AIOS IR v0.1 oneOf definitions are closed, const-discriminated unions.
    // Derive the discriminator and expected JSON type from structured constant
    // failures instead of guessing from branch order or rendered messages.
    if !error.instance().is_object() {
        return OneOfResolution::WrongType;
    }
    if branches_share_missing_required_property(error, branches) {
        return OneOfResolution::Missing;
    }

    let parent_path = error.instance_path().as_str();
    let direct_prefix = format!("{parent_path}/");
    let mut discriminator_path = None;
    let mut expected_kind = None;
    let mut actual_kind = None;
    for child in branches.iter().flat_map(|branch| branch.iter()) {
        let Kind::Constant { expected_value } = child.kind() else {
            continue;
        };
        let path = child.instance_path().as_str();
        let is_direct_child = path
            .strip_prefix(&direct_prefix)
            .is_some_and(|relative| !relative.is_empty() && !relative.contains('/'));
        if !is_direct_child {
            continue;
        }
        if discriminator_path.is_some_and(|candidate| candidate != path) {
            return OneOfResolution::Ambiguous;
        }
        discriminator_path = Some(path);
        let branch_expected_kind = json_value_kind(expected_value);
        let branch_actual_kind = json_value_kind(child.instance().as_ref());
        if expected_kind.is_some_and(|candidate| candidate != branch_expected_kind)
            || actual_kind.is_some_and(|candidate| candidate != branch_actual_kind)
        {
            return OneOfResolution::Ambiguous;
        }
        expected_kind = Some(branch_expected_kind);
        actual_kind = Some(branch_actual_kind);
    }
    let Some(discriminator_path) = discriminator_path else {
        return OneOfResolution::Ambiguous;
    };

    let mut selected = None;
    let mut compatible_count = 0_usize;
    for branch in branches {
        let discriminator_mismatch = branch.iter().any(|child| {
            matches!(child.kind(), Kind::Constant { .. })
                && child.instance_path().as_str() == discriminator_path
        });
        if !discriminator_mismatch {
            compatible_count = compatible_count.saturating_add(1);
            selected = Some(branch.as_slice());
        }
    }

    match (compatible_count, selected) {
        (1, Some(branch)) => OneOfResolution::Selected(branch),
        (0, _) if expected_kind.is_some() && expected_kind != actual_kind => {
            OneOfResolution::WrongType
        }
        (0, _) => OneOfResolution::Unsupported,
        // More than one discriminator-compatible alternative is genuinely
        // ambiguous. Never let schema order choose its machine classification.
        _ => OneOfResolution::Ambiguous,
    }
}

fn branches_share_missing_required_property(
    error: &jsonschema::ValidationError<'_>,
    branches: &[Vec<jsonschema::ValidationError<'static>>],
) -> bool {
    use jsonschema::error::ValidationErrorKind as Kind;

    let parent_path = error.instance_path().as_str();
    let Some(first) = branches.first() else {
        return false;
    };
    let mut common = first
        .iter()
        .filter(|child| child.instance_path().as_str() == parent_path)
        .filter_map(|child| match child.kind() {
            Kind::Required { property } => property.as_str(),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    for branch in &branches[1..] {
        common.retain(|property| {
            branch.iter().any(|child| {
                child.instance_path().as_str() == parent_path
                    && matches!(
                        child.kind(),
                        Kind::Required { property: candidate }
                            if candidate.as_str() == Some(*property)
                    )
            })
        });
    }
    !common.is_empty()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum StructuredErrorDetail<'a> {
    None,
    Required(&'a str),
    Pattern(&'a str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct StructuredErrorKey<'a> {
    instance_path: &'a str,
    reason_code: &'static str,
    schema_path: &'a str,
    detail: StructuredErrorDetail<'a>,
}

fn structured_error_key<'a>(
    error: &'a jsonschema::ValidationError<'static>,
) -> StructuredErrorKey<'a> {
    use jsonschema::error::ValidationErrorKind as Kind;

    let detail = match error.kind() {
        Kind::Required { property } => property
            .as_str()
            .map_or(StructuredErrorDetail::None, StructuredErrorDetail::Required),
        Kind::Pattern { pattern } => StructuredErrorDetail::Pattern(pattern),
        _ => StructuredErrorDetail::None,
    };
    StructuredErrorKey {
        instance_path: error.instance_path().as_str(),
        reason_code: classify_schema_failure(error).as_str(),
        schema_path: error.schema_path().as_str(),
        detail,
    }
}

fn emit_selected_branch_failures(
    errors: &[jsonschema::ValidationError<'static>],
    diagnostics: &mut DiagnosticCollector,
) {
    // Branch contexts are already eagerly materialized by jsonschema. Walk the
    // fixed, small AIOS branch error set in stable machine-key order without
    // allocating a second diagnostics collection. Exact repeated keys are
    // emitted once; distinct missing required properties have distinct details.
    let mut previous = None;
    loop {
        let next = errors
            .iter()
            .map(|error| (structured_error_key(error), error))
            .filter(|(key, _)| previous.is_none_or(|previous| *key > previous))
            .min_by(|(left, _), (right, _)| left.cmp(right));
        let Some((key, error)) = next else {
            break;
        };
        emit_schema_failure(error, diagnostics);
        if diagnostics.is_truncated() {
            break;
        }
        previous = Some(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn base_program() -> Value {
        serde_json::from_str::<Value>(include_str!("../../../examples/aios-ir/valid-cases.json"))
            .unwrap()[0]["program"]
            .clone()
    }

    fn diagnostic_signature(
        validator: &jsonschema::Validator,
        value: &Value,
    ) -> Vec<(ValidatorReasonCode, Option<String>)> {
        let mut diagnostics = DiagnosticCollector::new(64);
        emit_validator_errors(validator, value, &mut diagnostics);
        diagnostics
            .finish()
            .0
            .into_iter()
            .map(|diagnostic| (diagnostic.code, diagnostic.json_pointer))
            .collect()
    }

    #[test]
    fn discriminated_diagnostics_do_not_depend_on_alternative_order() {
        let schema: Value = serde_json::from_str(AIOS_IR_SCHEMA).unwrap();
        let mut reversed = schema.clone();
        for name in ["valueRef", "failurePolicy"] {
            reversed["$defs"][name]["oneOf"]
                .as_array_mut()
                .unwrap()
                .reverse();
        }
        let ordinary = jsonschema::validator_for(&schema).unwrap();
        let reversed = jsonschema::validator_for(&reversed).unwrap();

        for (pointer, value, expected) in [
            (
                "/nodes/0/inputs/source",
                json!({"source":"input","name":"bad/name","required":"attack"}),
                vec![
                    ValidatorReasonCode::IrSchemaAdditionalProperty,
                    ValidatorReasonCode::IrSchemaPattern,
                ],
            ),
            (
                "/nodes/0/failure",
                json!({"on_error":"retry","max_attempts":0,"required":"attack"}),
                vec![
                    ValidatorReasonCode::IrSchemaAdditionalProperty,
                    ValidatorReasonCode::IrSchemaRange,
                ],
            ),
            (
                "/nodes/0/failure",
                json!({"on_error":"fallback","fallback_capabilities":["x"]}),
                vec![
                    ValidatorReasonCode::IrSchemaPattern,
                    ValidatorReasonCode::IrSchemaRange,
                ],
            ),
            (
                "/nodes/0/inputs/source",
                json!({"source":42,"name":"source"}),
                vec![ValidatorReasonCode::IrSchemaType],
            ),
            (
                "/nodes/0/failure",
                json!({"on_error":"retry"}),
                vec![ValidatorReasonCode::IrSchemaRequired],
            ),
            (
                "/nodes/0/failure",
                json!({
                    "on_error":"fallback",
                    "fallback_capabilities":[
                        "artifact.copy@1",
                        "artifact.copy.compat@1",
                        "artifact.hash@1",
                        "table.import@1"
                    ]
                }),
                vec![ValidatorReasonCode::IrSchemaRange],
            ),
            (
                "/nodes/0/egress",
                json!({"mode":"deny","destination_classes":["public"]}),
                vec![ValidatorReasonCode::IrSchemaRange],
            ),
        ] {
            let mut program = base_program();
            *program.pointer_mut(pointer).unwrap() = value;
            let ordinary_signature = diagnostic_signature(&ordinary, &program);
            let reversed_signature = diagnostic_signature(&reversed, &program);
            assert_eq!(ordinary_signature, reversed_signature, "{pointer}");
            assert_eq!(
                ordinary_signature
                    .iter()
                    .map(|(code, _)| *code)
                    .collect::<Vec<_>>(),
                expected,
                "{pointer}"
            );
        }
    }
}
