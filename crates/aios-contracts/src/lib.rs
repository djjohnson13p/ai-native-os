//! Strongly typed, inert data contracts for the AIOS v0.1 trusted boundary.
//!
//! This crate deliberately contains no parser policy, registry I/O, provider
//! execution, authorization, network access, or model integration.  The
//! validator and registry crates consume these types after enforcing their
//! respective trust-boundary checks.

#![allow(
    missing_docs,
    reason = "public DTO members intentionally mirror the machine-readable schema field names"
)]

mod serde_support;

pub mod diagnostics;
pub mod ir;
pub mod output;
pub mod provider;
pub mod registry;

pub use diagnostics::*;
pub use ir::*;
pub use output::*;
pub use provider::*;
pub use registry::*;

/// Bootstrap schema version shared by the v0.1 JSON contracts.
pub const SCHEMA_VERSION_V0_1: &str = "0.1";

/// The only AIOS IR version accepted by the first reference validator.
pub const AIOS_IR_VERSION_V0_1: &str = "0.1";

/// Semantic-program canonicalization and hashing profile identifier.
pub const AIOS_IR_SEMANTIC_HASH_PROFILE_V0_1: &str = "aios-ir-v0.1";
