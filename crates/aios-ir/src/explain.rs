//! Stable reason-code introspection for the development CLI.

use std::str::FromStr;

use aios_contracts::{ProviderReasonCode, ValidatorReasonCode};
use serde::Serialize;

/// Serializable explanation of a closed-catalog reason code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReasonExplanation {
    /// Exact stable reason code.
    pub code: String,
    /// Catalog namespace.
    pub namespace: &'static str,
    /// Severity when the validator catalog defines one.
    pub severity: Option<String>,
    /// Validation stage when the validator catalog defines one.
    pub stage: Option<String>,
    /// Short stable description.
    pub meaning: String,
}

/// Explains one validator, registry, or provider-conformance reason code.
pub fn explain_reason(code: &str) -> Option<ReasonExplanation> {
    if let Ok(reason) = ValidatorReasonCode::from_str(code) {
        return Some(ReasonExplanation {
            code: code.to_owned(),
            namespace: if code.starts_with("REGISTRY_") {
                "registry"
            } else {
                "ir"
            },
            severity: Some(enum_json(reason.severity())),
            stage: Some(enum_json(reason.stage())),
            meaning: humanize(code),
        });
    }
    ProviderReasonCode::from_str(code)
        .ok()
        .map(|_| ReasonExplanation {
            code: code.to_owned(),
            namespace: "provider",
            severity: None,
            stage: None,
            meaning: humanize(code),
        })
}

fn enum_json(value: impl Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

fn humanize(code: &str) -> String {
    let words = code
        .split('_')
        .skip(1)
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join(" ");
    format!("The closed v0.1 contract reported: {words}.")
}
