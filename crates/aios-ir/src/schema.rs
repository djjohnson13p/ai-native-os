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
    // jsonschema yields failures lazily. Feed them directly into the bounded
    // collector and stop after the first suppressed diagnostic, so hostile
    // documents cannot amplify into an unbounded intermediate Vec.
    for error in validator.iter_errors(value) {
        let message = error.to_string();
        let code = classify_schema_failure(&error);
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
        Kind::OneOfNotValid { context } => classify_discriminated_one_of(error, context),
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

fn classify_discriminated_one_of(
    error: &jsonschema::ValidationError<'_>,
    branches: &[Vec<jsonschema::ValidationError<'static>>],
) -> ValidatorReasonCode {
    use jsonschema::error::ValidationErrorKind as Kind;

    // AIOS IR v0.1 oneOf definitions are closed, const-discriminated unions.
    // Derive the discriminator from structured child locations instead of
    // guessing from branch order, authored names, or rendered messages.
    if !error.instance().is_object() {
        return ValidatorReasonCode::IrSchemaType;
    }
    if branches_share_missing_required_property(error, branches) {
        return ValidatorReasonCode::IrSchemaRequired;
    }

    let parent_path = error.instance_path().as_str();
    let direct_prefix = format!("{parent_path}/");
    let discriminator_paths = branches
        .iter()
        .flat_map(|branch| branch.iter())
        .filter(|child| matches!(child.kind(), Kind::Constant { .. }))
        .map(|child| child.instance_path().as_str())
        .filter(|path| {
            path.strip_prefix(&direct_prefix)
                .is_some_and(|relative| !relative.is_empty() && !relative.contains('/'))
        })
        .collect::<BTreeSet<_>>();
    let Some(discriminator_path) = discriminator_paths.iter().copied().next() else {
        return ValidatorReasonCode::IrSchemaType;
    };
    if discriminator_paths.len() != 1 {
        return ValidatorReasonCode::IrSchemaType;
    }
    let compatible = branches
        .iter()
        .filter(|branch| {
            !branch.iter().any(|child| {
                matches!(child.kind(), Kind::Constant { .. })
                    && child.instance_path().as_str() == discriminator_path
            })
        })
        .collect::<Vec<_>>();

    match compatible.as_slice() {
        [branch] => unanimous_branch_code(branch).unwrap_or(ValidatorReasonCode::IrSchemaType),
        [] => ValidatorReasonCode::IrSchemaEnum,
        // More than one discriminator-compatible alternative is genuinely
        // ambiguous. Never let schema order choose its machine classification.
        _ => ValidatorReasonCode::IrSchemaType,
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

fn unanimous_branch_code(
    errors: &[jsonschema::ValidationError<'static>],
) -> Option<ValidatorReasonCode> {
    let mut codes = errors.iter().map(classify_schema_failure);
    let first = codes.next()?;
    codes.all(|code| code == first).then_some(first)
}
