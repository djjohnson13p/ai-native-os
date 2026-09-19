//! Immutable, offline AIOS semantic registry loading and conformance checks.
//!
//! This crate parses only explicitly supplied local bundle files. It never
//! performs network/catalog resolution, loads provider code, or grants runtime
//! authority.

#![allow(missing_docs)]

mod authority;
mod conformance;
mod error;
mod hash;
mod loader;
mod strict_json;
mod version;

pub use authority::effect_for_authority_class;
pub use conformance::{
    ProviderConformanceDiagnostic, ProviderConformanceOptions, ProviderConformanceReport,
    validate_provider_manifest,
};
pub use error::{RegistryError, RegistryResult};
pub use hash::{
    CAPABILITY_CONTRACT_HASH_DOMAIN, CapabilityContractHash, REGISTRY_SNAPSHOT_HASH_DOMAIN,
    RegistrySnapshotId, SnapshotHashEntry, TYPE_CONTRACT_HASH_DOMAIN, TypeContractHash,
    canonicalize, capability_contract_hash, capability_contract_semantic_view,
    is_obvious_placeholder_hash, is_sha256_id, registry_snapshot_id, type_contract_hash,
    type_contract_semantic_view,
};
pub use loader::{
    DEFAULT_SNAPSHOT_FILE, HashVerificationMode, RegistryBuildOptions, RegistryLimits,
    RegistryLoadOptions, SemanticRegistry, load_registry_bundle,
};
pub use strict_json::{
    StrictJsonError, StrictJsonErrorKind, StrictJsonLimits, parse_strict_json, parse_strict_value,
};
pub use version::{FullVersion, SemanticRef};
