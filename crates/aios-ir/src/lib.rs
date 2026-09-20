//! Deterministic parser, semantic validator, normalizer, and analyzer for AIOS IR v0.1.

mod diagnostics;
mod explain;
mod hash;
mod limits;
mod normalize;
mod parse;
mod schema;
mod semantics;
mod validator;

pub use explain::{ReasonExplanation, explain_reason};
pub use limits::ValidationLimits;
pub use validator::{ValidationReport, Validator, rejected_registry_report};

/// Recomputes the v0.1 semantic identity from persisted AIOS IR bytes.
///
/// This applies the same strict parser, typed semantic projection,
/// normalization, domain separation, and JCS hashing used by validation. It is
/// intended for trusted consumers that must authenticate stored program bytes
/// against a previously issued validation result.
///
/// # Errors
/// Returns an error when the bytes are not strict JSON, do not decode to the
/// closed AIOS IR model, cannot be normalized, or cannot be canonically hashed.
pub fn recompute_semantic_hash(bytes: &[u8]) -> Result<String, String> {
    let value = parse::parse_strict_json(bytes, parse::MAX_SUPPORTED_JSON_DEPTH)
        .map_err(|error| format!("{error:?}"))?;
    let program: aios_contracts::AiosIr =
        serde_json::from_value(value).map_err(|error| error.to_string())?;
    let normalized = normalize::normalize_semantic_program(&program)?;
    hash::semantic_hash(&normalized)
}
