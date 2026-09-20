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
