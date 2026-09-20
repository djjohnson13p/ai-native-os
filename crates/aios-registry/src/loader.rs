use crate::hash::{
    CapabilityContractHash, RegistrySnapshotId, SnapshotHashEntry, TypeContractHash,
    capability_contract_hash, is_obvious_placeholder_hash, is_sha256_id, registry_snapshot_id,
    type_contract_hash,
};
use crate::schema::{self, RecordKind};
use crate::strict_json::StrictJsonLimits;
#[cfg(test)]
use crate::strict_json::parse_strict_json;
use crate::version::{FullVersion, SemanticRef, validate_semantic_id};
use crate::{RegistryError, RegistryResult, effect_for_authority_class};
use aios_contracts::{
    CapabilityContract, ContractRef, EffectClass, RegistrySnapshot, SCHEMA_VERSION_V0_1,
    TypeContract, ValidatorReasonCode,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Take};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub const DEFAULT_SNAPSHOT_FILE: &str = "registry-snapshot.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashVerificationMode {
    /// All declared contract and snapshot IDs must match generated identities.
    Strict,
    /// Only obvious zero-prefixed bootstrap fixture sentinels may be regenerated.
    /// Registries returned in this mode remain explicitly marked non-strict and
    /// must never be admitted as production trust evidence.
    BootstrapGenerate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryLimits {
    pub json: StrictJsonLimits,
    pub max_total_bytes: usize,
    pub max_contracts: usize,
    pub max_source_files: usize,
}

impl Default for RegistryLimits {
    fn default() -> Self {
        Self {
            json: StrictJsonLimits::default(),
            max_total_bytes: 32 * 1024 * 1024,
            max_contracts: 4_096,
            max_source_files: 1_024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryBuildOptions {
    pub hash_verification: HashVerificationMode,
    pub max_contracts: usize,
}

impl Default for RegistryBuildOptions {
    fn default() -> Self {
        Self {
            hash_verification: HashVerificationMode::Strict,
            max_contracts: RegistryLimits::default().max_contracts,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryLoadOptions {
    pub snapshot_file: PathBuf,
    pub limits: RegistryLimits,
    pub hash_verification: HashVerificationMode,
}

impl Default for RegistryLoadOptions {
    fn default() -> Self {
        Self {
            snapshot_file: PathBuf::from(DEFAULT_SNAPSHOT_FILE),
            limits: RegistryLimits::default(),
            hash_verification: HashVerificationMode::Strict,
        }
    }
}

/// Immutable, locally materialized semantic registry used by one validation.
#[derive(Debug, Clone)]
pub struct SemanticRegistry {
    snapshot: Arc<RegistrySnapshot>,
    snapshot_id: RegistrySnapshotId,
    hash_verification: HashVerificationMode,
    types: BTreeMap<(String, u64), Arc<TypeContract>>,
    capabilities: BTreeMap<(String, u64), Arc<CapabilityContract>>,
    type_hashes: BTreeMap<(String, u64), TypeContractHash>,
    capability_hashes: BTreeMap<(String, u64), CapabilityContractHash>,
}

impl SemanticRegistry {
    /// Load and strictly validate a registry bundle from a local directory.
    ///
    /// # Errors
    ///
    /// Returns an operational error for local I/O failures or a coded registry
    /// error when the bundle violates its schema, identities, or invariants.
    pub fn load_bundle(
        directory: impl AsRef<Path>,
        options: RegistryLoadOptions,
    ) -> RegistryResult<Self> {
        load_registry_bundle(directory, options)
    }

    /// Build a registry from already decoded immutable records.
    ///
    /// This programmatic API validates structure, values and identities, but cannot
    /// recover duplicate keys or numeric tokens discarded by a caller's decoder.
    /// Untrusted authored JSON must enter through [`Self::load_bundle`], which
    /// enforces lexical numeric rules and raw schemas before typed decoding.
    ///
    /// # Errors
    ///
    /// Returns a coded registry error when records violate limits, references,
    /// content identities, or semantic consistency rules.
    pub fn from_records(
        snapshot: RegistrySnapshot,
        type_contracts: Vec<TypeContract>,
        capability_contracts: Vec<CapabilityContract>,
        options: RegistryBuildOptions,
    ) -> RegistryResult<Self> {
        build_registry(snapshot, type_contracts, capability_contracts, options)
    }

    pub fn snapshot(&self) -> &RegistrySnapshot {
        &self.snapshot
    }

    pub fn snapshot_id(&self) -> &str {
        self.snapshot_id.as_str()
    }

    pub fn snapshot_id_typed(&self) -> &RegistrySnapshotId {
        &self.snapshot_id
    }

    pub fn hash_verification_mode(&self) -> HashVerificationMode {
        self.hash_verification
    }

    pub fn is_strictly_verified(&self) -> bool {
        self.hash_verification == HashVerificationMode::Strict
    }

    /// Resolve a major-version semantic type reference.
    ///
    /// # Errors
    ///
    /// Returns a registry schema error when `semantic_ref` is malformed.
    pub fn resolve_type(&self, semantic_ref: &str) -> RegistryResult<Option<&TypeContract>> {
        let semantic_ref = SemanticRef::parse(semantic_ref)?;
        Ok(self.type_contract(&semantic_ref.id, semantic_ref.major))
    }

    /// Resolve a major-version semantic capability reference.
    ///
    /// # Errors
    ///
    /// Returns a registry schema error when `semantic_ref` is malformed.
    pub fn resolve_capability(
        &self,
        semantic_ref: &str,
    ) -> RegistryResult<Option<&CapabilityContract>> {
        let semantic_ref = SemanticRef::parse(semantic_ref)?;
        Ok(self.capability_contract(&semantic_ref.id, semantic_ref.major))
    }

    pub fn type_contract(&self, id: &str, major: u64) -> Option<&TypeContract> {
        self.types.get(&(id.to_owned(), major)).map(AsRef::as_ref)
    }

    pub fn capability_contract(&self, id: &str, major: u64) -> Option<&CapabilityContract> {
        self.capabilities
            .get(&(id.to_owned(), major))
            .map(AsRef::as_ref)
    }

    pub fn type_contract_hash(&self, id: &str, major: u64) -> Option<&TypeContractHash> {
        self.type_hashes.get(&(id.to_owned(), major))
    }

    pub fn capability_contract_hash(
        &self,
        id: &str,
        major: u64,
    ) -> Option<&CapabilityContractHash> {
        self.capability_hashes.get(&(id.to_owned(), major))
    }

    pub fn type_contracts(&self) -> impl ExactSizeIterator<Item = &TypeContract> {
        self.types.values().map(AsRef::as_ref)
    }

    pub fn capability_contracts(&self) -> impl ExactSizeIterator<Item = &CapabilityContract> {
        self.capabilities.values().map(AsRef::as_ref)
    }
}

/// Load a bounded, immutable registry bundle from an explicitly supplied path.
///
/// # Errors
///
/// Returns an operational error for local I/O failures or a coded registry
/// error when the bundle violates its schema, identities, or invariants.
#[allow(clippy::needless_pass_by_value)]
pub fn load_registry_bundle(
    directory: impl AsRef<Path>,
    options: RegistryLoadOptions,
) -> RegistryResult<SemanticRegistry> {
    let requested_root = directory.as_ref();
    let root = requested_root.canonicalize().map_err(|error| {
        RegistryError::operational(format!("cannot open registry directory: {error}"))
            .at_path(requested_root)
    })?;
    if !root.is_dir() {
        return Err(
            RegistryError::operational("registry bundle path is not a directory").at_path(root),
        );
    }

    validate_relative_source(&options.snapshot_file)?;
    let snapshot_path = resolve_local_source(&root, &options.snapshot_file)?;
    let snapshot_bytes = read_bounded(&snapshot_path, options.limits.json.max_bytes)?;
    let mut total_bytes = snapshot_bytes.len();
    enforce_total_bytes(total_bytes, options.limits.max_total_bytes)?;
    let snapshot: RegistrySnapshot = schema::decode_with_record_limit(
        &snapshot_bytes,
        options.limits.json,
        RecordKind::Snapshot,
        false,
        Some(options.limits.max_contracts),
    )
    .map_err(|error| error.at_path(&snapshot_path))?;
    let snapshot_contract_count = checked_contract_count(
        snapshot.type_contracts.len(),
        snapshot.capability_contracts.len(),
    )?;
    enforce_contract_count(snapshot_contract_count, options.limits.max_contracts)?;

    let type_sources = collect_sources(&snapshot.type_contracts, options.limits.max_source_files)?;
    let capability_sources = collect_sources(
        &snapshot.capability_contracts,
        options.limits.max_source_files,
    )?;
    let source_count = type_sources.union(&capability_sources).count();
    if source_count > options.limits.max_source_files {
        return Err(RegistryError::schema(format!(
            "registry references {source_count} source files; configured maximum is {}",
            options.limits.max_source_files
        )));
    }

    let mut type_contracts = Vec::new();
    for source in type_sources {
        let path = resolve_local_source(&root, &source)?;
        let bytes = read_bounded(&path, options.limits.json.max_bytes)?;
        total_bytes =
            checked_total_bytes(total_bytes, bytes.len(), options.limits.max_total_bytes)?;
        let remaining_contracts = options
            .limits
            .max_contracts
            .saturating_sub(type_contracts.len());
        let mut contracts: Vec<TypeContract> = schema::decode_with_record_limit(
            &bytes,
            options.limits.json,
            RecordKind::Type,
            true,
            Some(remaining_contracts),
        )
        .map_err(|error| error.at_path(&path))?;
        type_contracts.append(&mut contracts);
        enforce_contract_count(type_contracts.len(), options.limits.max_contracts)?;
    }

    let mut capability_contracts = Vec::new();
    for source in capability_sources {
        let path = resolve_local_source(&root, &source)?;
        let bytes = read_bounded(&path, options.limits.json.max_bytes)?;
        total_bytes =
            checked_total_bytes(total_bytes, bytes.len(), options.limits.max_total_bytes)?;
        let loaded_contracts =
            checked_contract_count(type_contracts.len(), capability_contracts.len())?;
        let remaining_contracts = options
            .limits
            .max_contracts
            .saturating_sub(loaded_contracts);
        let mut contracts: Vec<CapabilityContract> = schema::decode_with_record_limit(
            &bytes,
            options.limits.json,
            RecordKind::Capability,
            true,
            Some(remaining_contracts),
        )
        .map_err(|error| error.at_path(&path))?;
        capability_contracts.append(&mut contracts);
        enforce_contract_count(
            type_contracts.len() + capability_contracts.len(),
            options.limits.max_contracts,
        )?;
    }

    build_registry(
        snapshot,
        type_contracts,
        capability_contracts,
        RegistryBuildOptions {
            hash_verification: options.hash_verification,
            max_contracts: options.limits.max_contracts,
        },
    )
}

#[allow(clippy::too_many_lines)]
fn build_registry(
    mut snapshot: RegistrySnapshot,
    type_contracts: Vec<TypeContract>,
    capability_contracts: Vec<CapabilityContract>,
    options: RegistryBuildOptions,
) -> RegistryResult<SemanticRegistry> {
    validate_snapshot_header(&snapshot)?;
    let snapshot_contract_count = checked_contract_count(
        snapshot.type_contracts.len(),
        snapshot.capability_contracts.len(),
    )?;
    enforce_contract_count(snapshot_contract_count, options.max_contracts)?;
    let supplied_contract_count =
        checked_contract_count(type_contracts.len(), capability_contracts.len())?;
    enforce_contract_count(supplied_contract_count, options.max_contracts)?;

    // Typed callers cannot bypass the machine contract either. Semantic checks below
    // remain necessary for cross-record and required/allowed-envelope invariants.
    schema::validate(
        RecordKind::Snapshot,
        &serde_json::to_value(&snapshot)
            .map_err(|error| RegistryError::schema(error.to_string()))?,
    )?;
    for contract in &type_contracts {
        schema::validate(
            RecordKind::Type,
            &serde_json::to_value(contract)
                .map_err(|error| RegistryError::schema(error.to_string()))?,
        )?;
    }
    for contract in &capability_contracts {
        schema::validate(
            RecordKind::Capability,
            &serde_json::to_value(contract)
                .map_err(|error| RegistryError::schema(error.to_string()))?,
        )?;
    }

    let type_entries = index_snapshot_entries(&snapshot.type_contracts, ContractKind::Type)?;
    let capability_entries =
        index_snapshot_entries(&snapshot.capability_contracts, ContractKind::Capability)?;
    let supplied_types = index_supplied_types(type_contracts)?;
    let supplied_capabilities = index_supplied_capabilities(capability_contracts)?;

    let mut active_types = BTreeMap::new();
    let mut active_type_hashes = BTreeMap::new();
    let mut normalized_type_refs = Vec::with_capacity(snapshot.type_contracts.len());
    for ((id, major), entry) in type_entries {
        let exact_key = (entry.id.clone(), entry.version.clone());
        let contract = supplied_types.get(&exact_key).ok_or_else(|| {
            let code = if supplied_types.keys().any(|(id, _)| id == &entry.id) {
                ValidatorReasonCode::RegistryContractVersionMismatch
            } else {
                ValidatorReasonCode::RegistryEntryNotFound
            };
            RegistryError::validation(
                code,
                format!(
                    "snapshot type entry {} {} has no matching loaded contract version",
                    entry.id, entry.version
                ),
            )
        })?;
        validate_type_contract(contract)?;
        let contract_version = FullVersion::parse(&contract.version)?;
        if contract.type_id != entry.id
            || contract.version != entry.version
            || contract_version.major != major
        {
            return Err(RegistryError::validation(
                ValidatorReasonCode::RegistryContractVersionMismatch,
                format!(
                    "type snapshot entry {} {} disagrees with loaded contract {} {}",
                    entry.id, entry.version, contract.type_id, contract.version
                ),
            ));
        }
        let computed = type_contract_hash(contract)?;
        verify_declared_hash(
            &entry.content_hash,
            computed.as_str(),
            options.hash_verification,
            &format!("type contract {} {}", entry.id, entry.version),
        )?;
        normalized_type_refs.push(ContractRef {
            id: entry.id.clone(),
            version: entry.version.clone(),
            content_hash: computed.to_string(),
            source: entry.source.clone(),
        });
        active_type_hashes.insert((id.clone(), major), computed);
        active_types.insert((id, major), Arc::new((*contract).clone()));
    }

    let mut active_capabilities = BTreeMap::new();
    let mut active_capability_hashes = BTreeMap::new();
    let mut normalized_capability_refs = Vec::with_capacity(snapshot.capability_contracts.len());
    for ((id, major), entry) in capability_entries {
        let exact_key = (entry.id.clone(), entry.version.clone());
        let contract = supplied_capabilities.get(&exact_key).ok_or_else(|| {
            let code = if supplied_capabilities.keys().any(|(id, _)| id == &entry.id) {
                ValidatorReasonCode::RegistryContractVersionMismatch
            } else {
                ValidatorReasonCode::RegistryEntryNotFound
            };
            RegistryError::validation(
                code,
                format!(
                    "snapshot capability entry {} {} has no matching loaded contract version",
                    entry.id, entry.version
                ),
            )
        })?;
        validate_capability_contract(contract)?;
        let contract_version = FullVersion::parse(&contract.version)?;
        if contract.capability != entry.id
            || contract.version != entry.version
            || contract_version.major != major
        {
            return Err(RegistryError::validation(
                ValidatorReasonCode::RegistryContractVersionMismatch,
                format!(
                    "capability snapshot entry {} {} disagrees with loaded contract {} {}",
                    entry.id, entry.version, contract.capability, contract.version
                ),
            ));
        }
        let computed = capability_contract_hash(contract)?;
        verify_declared_hash(
            &entry.content_hash,
            computed.as_str(),
            options.hash_verification,
            &format!("capability contract {} {}", entry.id, entry.version),
        )?;
        normalized_capability_refs.push(ContractRef {
            id: entry.id.clone(),
            version: entry.version.clone(),
            content_hash: computed.to_string(),
            source: entry.source.clone(),
        });
        active_capability_hashes.insert((id.clone(), major), computed);
        active_capabilities.insert((id, major), Arc::new((*contract).clone()));
    }

    validate_cross_references(&active_types, &active_capabilities)?;

    let type_hash_entries = normalized_type_refs
        .iter()
        .map(snapshot_hash_entry)
        .collect::<Vec<_>>();
    let capability_hash_entries = normalized_capability_refs
        .iter()
        .map(snapshot_hash_entry)
        .collect::<Vec<_>>();
    let computed_snapshot_id = registry_snapshot_id(
        &snapshot.schema_version,
        &type_hash_entries,
        &capability_hash_entries,
    )?;
    verify_snapshot_hash(
        &snapshot.snapshot_id,
        computed_snapshot_id.as_str(),
        options.hash_verification,
    )?;

    snapshot.type_contracts = normalized_type_refs;
    snapshot.capability_contracts = normalized_capability_refs;
    snapshot.snapshot_id = computed_snapshot_id.to_string();

    Ok(SemanticRegistry {
        snapshot: Arc::new(snapshot),
        snapshot_id: computed_snapshot_id,
        hash_verification: options.hash_verification,
        types: active_types,
        capabilities: active_capabilities,
        type_hashes: active_type_hashes,
        capability_hashes: active_capability_hashes,
    })
}

#[derive(Clone, Copy)]
enum ContractKind {
    Type,
    Capability,
}

fn index_snapshot_entries(
    entries: &[ContractRef],
    kind: ContractKind,
) -> RegistryResult<BTreeMap<(String, u64), &ContractRef>> {
    let mut indexed = BTreeMap::new();
    for entry in entries {
        validate_contract_ref(entry)?;
        let version = FullVersion::parse(&entry.version)?;
        let key = (entry.id.clone(), version.major);
        if indexed.insert(key.clone(), entry).is_some() {
            let code = match kind {
                ContractKind::Type => ValidatorReasonCode::RegistryDuplicateTypeMajor,
                ContractKind::Capability => ValidatorReasonCode::RegistryDuplicateCapabilityMajor,
            };
            return Err(RegistryError::validation(
                code,
                format!(
                    "snapshot contains multiple active contracts for {}@{}",
                    key.0, key.1
                ),
            ));
        }
    }
    Ok(indexed)
}

fn index_supplied_types(
    contracts: Vec<TypeContract>,
) -> RegistryResult<BTreeMap<(String, String), TypeContract>> {
    let mut indexed = BTreeMap::new();
    for contract in contracts {
        let key = (contract.type_id.clone(), contract.version.clone());
        if indexed.insert(key.clone(), contract).is_some() {
            return Err(RegistryError::schema(format!(
                "loaded type contract {} {} appears more than once",
                key.0, key.1
            )));
        }
    }
    Ok(indexed)
}

fn index_supplied_capabilities(
    contracts: Vec<CapabilityContract>,
) -> RegistryResult<BTreeMap<(String, String), CapabilityContract>> {
    let mut indexed = BTreeMap::new();
    for contract in contracts {
        let key = (contract.capability.clone(), contract.version.clone());
        if indexed.insert(key.clone(), contract).is_some() {
            return Err(RegistryError::schema(format!(
                "loaded capability contract {} {} appears more than once",
                key.0, key.1
            )));
        }
    }
    Ok(indexed)
}

fn validate_snapshot_header(snapshot: &RegistrySnapshot) -> RegistryResult<()> {
    if snapshot.schema_version != SCHEMA_VERSION_V0_1 {
        return Err(RegistryError::validation(
            ValidatorReasonCode::RegistryUnsupportedVersion,
            format!(
                "registry schema version {:?} is unsupported",
                snapshot.schema_version
            ),
        ));
    }
    if !is_rfc3339_datetime(&snapshot.created_at) {
        return Err(RegistryError::schema(
            "snapshot created_at must be an RFC 3339 date-time",
        ));
    }
    if snapshot
        .generation
        .as_ref()
        .is_some_and(|value| exceeds_max_length(value, 128))
        || snapshot
            .notes
            .iter()
            .any(|note| exceeds_max_length(note, 2_048))
        || snapshot.publisher.as_ref().is_some_and(|publisher| {
            publisher
                .id
                .as_ref()
                .is_some_and(|id| id.is_empty() || exceeds_max_length(id, 256))
        })
    {
        return Err(RegistryError::schema(
            "snapshot metadata violates schema length constraints",
        ));
    }
    if !is_sha256_id(&snapshot.snapshot_id) && !is_obvious_placeholder_hash(&snapshot.snapshot_id) {
        return Err(RegistryError::schema(
            "snapshot_id must be lowercase sha256:<64 hex>",
        ));
    }
    Ok(())
}

fn validate_contract_ref(entry: &ContractRef) -> RegistryResult<()> {
    validate_semantic_id(&entry.id)?;
    if exceeds_max_length(&entry.version, 64)
        || entry
            .source
            .as_ref()
            .is_some_and(|source| exceeds_max_length(source, 1_024))
    {
        return Err(RegistryError::schema(format!(
            "contract {} reference violates schema length constraints",
            entry.id
        )));
    }
    FullVersion::parse(&entry.version)?;
    if !is_sha256_id(&entry.content_hash) && !is_obvious_placeholder_hash(&entry.content_hash) {
        return Err(RegistryError::schema(format!(
            "contract {} {} content_hash is not lowercase SHA-256",
            entry.id, entry.version
        )));
    }
    Ok(())
}

pub(crate) fn validate_type_contract(contract: &TypeContract) -> RegistryResult<()> {
    validate_semantic_id(&contract.type_id)?;
    if exceeds_max_length(&contract.type_id, 128) {
        return Err(RegistryError::schema(format!(
            "type identifier {:?} exceeds 128 characters",
            contract.type_id
        )));
    }
    FullVersion::parse(&contract.version)?;
    if contract.description.is_empty() || exceeds_max_length(&contract.description, 4_096) {
        return Err(RegistryError::schema(format!(
            "type {} description length is outside 1..=4096",
            contract.type_id
        )));
    }
    if contract
        .logical_schema_ref
        .as_ref()
        .is_some_and(|value| exceeds_max_length(value, 1_024))
        || contract
            .notes
            .iter()
            .any(|note| exceeds_max_length(note, 2_048))
    {
        return Err(RegistryError::schema(format!(
            "type {} metadata violates schema length constraints",
            contract.type_id
        )));
    }
    let mut representation_ids = BTreeSet::new();
    for representation in &contract.representations {
        if representation.id.is_empty() || exceeds_max_length(&representation.id, 160) {
            return Err(RegistryError::schema(format!(
                "type {} has an invalid representation ID",
                contract.type_id
            )));
        }
        if !representation_ids.insert(&representation.id) {
            return Err(RegistryError::schema(format!(
                "type {} repeats representation ID {:?}",
                contract.type_id, representation.id
            )));
        }
        if representation
            .media_type
            .as_ref()
            .is_some_and(|value| exceeds_max_length(value, 160))
            || representation
                .schema_ref
                .as_ref()
                .is_some_and(|value| exceeds_max_length(value, 1_024))
        {
            return Err(RegistryError::schema(format!(
                "type {} representation {:?} violates schema length constraints",
                contract.type_id, representation.id
            )));
        }
    }
    if contract
        .equality
        .canonicalizer
        .as_ref()
        .is_some_and(|value| exceeds_max_length(value, 256))
        || !valid_tolerance(contract.equality.numeric_absolute_tolerance)
        || !valid_tolerance(contract.equality.numeric_relative_tolerance)
        || contract.unit_semantics.as_ref().is_some_and(|unit| {
            unit.canonical_unit
                .as_ref()
                .is_some_and(|value| exceeds_max_length(value, 64))
                || unit
                    .notes
                    .as_ref()
                    .is_some_and(|value| exceeds_max_length(value, 1_024))
        })
    {
        return Err(RegistryError::schema(format!(
            "type {} equality or unit semantics violate schema constraints",
            contract.type_id
        )));
    }
    unique_strings(
        &contract.conversion_capabilities,
        &format!("type {} conversion_capabilities", contract.type_id),
    )?;
    for reference in &contract.conversion_capabilities {
        if exceeds_max_length(reference, 160) {
            return Err(RegistryError::schema(format!(
                "type {} has an overlong conversion capability reference",
                contract.type_id
            )));
        }
        SemanticRef::parse(reference)?;
    }
    validate_conformance(
        &contract.conformance.suite_id,
        contract.conformance.suite_version.as_deref(),
        contract.conformance.suite_hash.as_deref(),
        &format!("type {}", contract.type_id),
    )
}

#[allow(clippy::too_many_lines)]
pub(crate) fn validate_capability_contract(contract: &CapabilityContract) -> RegistryResult<()> {
    validate_semantic_id(&contract.capability)?;
    FullVersion::parse(&contract.version)?;
    if contract
        .description
        .as_ref()
        .is_some_and(|description| exceeds_max_length(description, 4_096))
        || contract
            .notes
            .iter()
            .any(|note| exceeds_max_length(note, 2_048))
    {
        return Err(RegistryError::schema(format!(
            "capability {} metadata violates schema length constraints",
            contract.capability
        )));
    }
    if contract.outputs.is_empty() {
        return Err(RegistryError::schema(format!(
            "capability {} must declare at least one output",
            contract.capability
        )));
    }
    for (name, port) in contract.inputs.iter().chain(&contract.outputs) {
        validate_port_name(name, &contract.capability)?;
        if exceeds_max_length(&port.type_ref, 128) {
            return Err(RegistryError::schema(format!(
                "capability {} port {name:?} has an overlong type reference",
                contract.capability
            )));
        }
        SemanticRef::parse(&port.type_ref)?;
        if port
            .description
            .as_ref()
            .is_some_and(|value| exceeds_max_length(value, 1_024))
        {
            return Err(RegistryError::schema(format!(
                "capability {} port {name:?} description exceeds 1024 characters",
                contract.capability
            )));
        }
    }
    if contract.inputs.iter().any(|(name, input)| {
        contract
            .outputs
            .get(name)
            .is_some_and(|output| output.type_ref != input.type_ref)
    }) {
        return Err(RegistryError::schema(format!(
            "capability {} reuses a port name for different input and output types",
            contract.capability
        )));
    }
    unique_values(
        &contract.allowed_execution_classes,
        &format!(
            "capability {} allowed execution classes",
            contract.capability
        ),
    )?;
    unique_values(
        &contract.required_effect_classes,
        &format!("capability {} required effects", contract.capability),
    )?;
    unique_values(
        &contract.allowed_effect_classes,
        &format!("capability {} allowed effects", contract.capability),
    )?;
    unique_strings(
        &contract.required_authority_classes,
        &format!("capability {} required authority", contract.capability),
    )?;
    unique_strings(
        &contract.allowed_authority_classes,
        &format!("capability {} allowed authority", contract.capability),
    )?;
    unique_values(
        &contract.allowed_egress_modes,
        &format!("capability {} allowed egress", contract.capability),
    )?;
    unique_strings(
        &contract.error_classes,
        &format!("capability {} error classes", contract.capability),
    )?;
    if contract.allowed_execution_classes.is_empty()
        || contract.allowed_effect_classes.is_empty()
        || contract.allowed_egress_modes.is_empty()
    {
        return Err(RegistryError::schema(format!(
            "capability {} has an empty required nonempty envelope",
            contract.capability
        )));
    }
    for authority in contract
        .required_authority_classes
        .iter()
        .chain(&contract.allowed_authority_classes)
    {
        validate_authority_class(authority, &contract.capability)?;
    }
    for error_class in &contract.error_classes {
        if error_class.len() < 3
            || exceeds_max_length(error_class, 160)
            || !error_class.bytes().enumerate().all(|(index, byte)| {
                if index == 0 {
                    byte.is_ascii_uppercase()
                } else {
                    byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'
                }
            })
        {
            return Err(RegistryError::schema(format!(
                "capability {} has invalid error class {error_class:?}",
                contract.capability
            )));
        }
    }
    if contract.determinism.as_ref().is_some_and(|determinism| {
        !valid_tolerance(determinism.numeric_absolute_tolerance)
            || !valid_tolerance(determinism.numeric_relative_tolerance)
    }) {
        return Err(RegistryError::schema(format!(
            "capability {} has an invalid determinism tolerance",
            contract.capability
        )));
    }

    let allowed_effects: BTreeSet<_> = contract.allowed_effect_classes.iter().copied().collect();
    if contract
        .required_effect_classes
        .iter()
        .any(|effect| !allowed_effects.contains(effect))
    {
        return Err(RegistryError::validation(
            ValidatorReasonCode::RegistryRequiredEffectNotAllowed,
            format!(
                "capability {} requires an effect absent from allowed_effect_classes",
                contract.capability
            ),
        ));
    }
    let allowed_authority: BTreeSet<_> = contract.allowed_authority_classes.iter().collect();
    if contract
        .required_authority_classes
        .iter()
        .any(|authority| !allowed_authority.contains(authority))
    {
        return Err(RegistryError::validation(
            ValidatorReasonCode::RegistryRequiredAuthorityNotAllowed,
            format!(
                "capability {} requires authority absent from allowed_authority_classes",
                contract.capability
            ),
        ));
    }
    validate_capability_egress_consistency(contract)?;
    let requires_pure = contract
        .required_effect_classes
        .contains(&EffectClass::Pure);
    let required_non_pure = contract
        .required_effect_classes
        .iter()
        .any(|effect| *effect != EffectClass::Pure);
    let allowed_non_pure = contract
        .allowed_effect_classes
        .iter()
        .any(|effect| *effect != EffectClass::Pure);
    if requires_pure && (required_non_pure || allowed_non_pure) {
        return Err(RegistryError::validation(
            ValidatorReasonCode::RegistryPureEffectContradiction,
            format!(
                "capability {} requires PURE while permitting a non-PURE effect",
                contract.capability
            ),
        ));
    }
    let required_effects: BTreeSet<_> = contract.required_effect_classes.iter().copied().collect();
    for effect in &required_effects {
        if !matches!(effect, EffectClass::Pure | EffectClass::LegacyOpaque)
            && !contract
                .required_authority_classes
                .iter()
                .any(|authority| effect_for_authority_class(authority) == Some(*effect))
        {
            return Err(RegistryError::schema(format!(
                "capability {} requires protected effect {effect:?} without its mapped required authority class",
                contract.capability
            )));
        }
    }
    for authority in &contract.required_authority_classes {
        let Some(implied_effect) = effect_for_authority_class(authority) else {
            return Err(RegistryError::schema(format!(
                "capability {} uses required authority class {authority:?} without a closed-profile effect mapping",
                contract.capability
            )));
        };
        if !required_effects.contains(&implied_effect) {
            return Err(RegistryError::schema(format!(
                "capability {} required authority class {authority:?} is absent from required_effect_classes",
                contract.capability
            )));
        }
    }
    for authority in &contract.allowed_authority_classes {
        let Some(implied_effect) = effect_for_authority_class(authority) else {
            return Err(RegistryError::schema(format!(
                "capability {} uses allowed authority class {authority:?} without a closed-profile effect mapping",
                contract.capability
            )));
        };
        if !allowed_effects.contains(&implied_effect) {
            return Err(RegistryError::schema(format!(
                "capability {} allowed authority class {authority:?} implies an effect outside allowed_effect_classes",
                contract.capability
            )));
        }
    }
    validate_conformance(
        &contract.conformance.suite_id,
        contract.conformance.suite_version.as_deref(),
        contract.conformance.suite_hash.as_deref(),
        &format!("capability {}", contract.capability),
    )
}

fn validate_capability_egress_consistency(contract: &CapabilityContract) -> RegistryResult<()> {
    let permits_deny_egress = contract
        .allowed_egress_modes
        .contains(&aios_contracts::EgressMode::Deny);
    let permits_policy_egress = contract
        .allowed_egress_modes
        .contains(&aios_contracts::EgressMode::Policy);
    let requires_data_egress_effect = contract
        .required_effect_classes
        .contains(&EffectClass::DataEgress);
    let allows_data_egress_effect = contract
        .allowed_effect_classes
        .contains(&EffectClass::DataEgress);
    let requires_data_egress_authority = contract
        .required_authority_classes
        .iter()
        .any(|authority| authority == "data.egress");
    let allows_data_egress_authority = contract
        .allowed_authority_classes
        .iter()
        .any(|authority| authority == "data.egress");

    let requires_policy_egress = !permits_deny_egress;
    if permits_policy_egress != allows_data_egress_effect
        || permits_policy_egress != allows_data_egress_authority
        || requires_policy_egress != requires_data_egress_effect
        || requires_policy_egress != requires_data_egress_authority
    {
        return Err(RegistryError::schema(format!(
            "capability {} has contradictory egress, DATA_EGRESS, or data.egress envelopes",
            contract.capability
        )));
    }

    Ok(())
}

fn validate_cross_references(
    types: &BTreeMap<(String, u64), Arc<TypeContract>>,
    capabilities: &BTreeMap<(String, u64), Arc<CapabilityContract>>,
) -> RegistryResult<()> {
    for contract in types.values() {
        for reference in &contract.conversion_capabilities {
            let reference = SemanticRef::parse(reference)?;
            if !capabilities.contains_key(&(reference.id.clone(), reference.major)) {
                return Err(RegistryError::validation(
                    ValidatorReasonCode::RegistryEntryNotFound,
                    format!(
                        "type {} references missing conversion capability {}@{}",
                        contract.type_id, reference.id, reference.major
                    ),
                ));
            }
        }
    }
    for contract in capabilities.values() {
        for port in contract.inputs.values().chain(contract.outputs.values()) {
            let reference = SemanticRef::parse(&port.type_ref)?;
            if !types.contains_key(&(reference.id.clone(), reference.major)) {
                return Err(RegistryError::validation(
                    ValidatorReasonCode::RegistryEntryNotFound,
                    format!(
                        "capability {} references missing type {}@{}",
                        contract.capability, reference.id, reference.major
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn validate_conformance(
    suite_id: &str,
    suite_version: Option<&str>,
    suite_hash: Option<&str>,
    owner: &str,
) -> RegistryResult<()> {
    if suite_id.is_empty() || exceeds_max_length(suite_id, 256) {
        return Err(RegistryError::schema(format!(
            "{owner} has invalid conformance suite ID"
        )));
    }
    if suite_version.is_some_and(|version| exceeds_max_length(version, 64)) {
        return Err(RegistryError::schema(format!(
            "{owner} conformance suite version exceeds 64 characters"
        )));
    }
    if suite_hash.is_some_and(|hash| exceeds_max_length(hash, 256)) {
        return Err(RegistryError::schema(format!(
            "{owner} conformance suite hash exceeds 256 characters"
        )));
    }
    Ok(())
}

fn valid_tolerance(value: Option<f64>) -> bool {
    value.is_none_or(|value| value.is_finite() && value >= 0.0)
}

fn exceeds_max_length(value: &str, maximum: usize) -> bool {
    value.chars().count() > maximum
}

fn is_rfc3339_datetime(value: &str) -> bool {
    value
        .as_bytes()
        .get(10)
        .is_some_and(|separator| matches!(*separator, b'T' | b't'))
        && OffsetDateTime::parse(value, &Rfc3339).is_ok()
}

fn validate_port_name(name: &str, capability: &str) -> RegistryResult<()> {
    let mut bytes = name.bytes();
    if !bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(RegistryError::schema(format!(
            "capability {capability} has invalid port name {name:?}"
        )));
    }
    Ok(())
}

fn validate_authority_class(authority: &str, capability: &str) -> RegistryResult<()> {
    let mut bytes = authority.bytes();
    if authority.len() < 3
        || exceeds_max_length(authority, 128)
        || !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        || !bytes.all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'_' | b'.' | b':' | b'-')
        })
    {
        return Err(RegistryError::schema(format!(
            "capability {capability} has invalid authority class {authority:?}"
        )));
    }
    Ok(())
}

fn unique_strings(values: &[String], label: &str) -> RegistryResult<()> {
    let unique: BTreeSet<_> = values.iter().collect();
    if unique.len() != values.len() {
        return Err(RegistryError::schema(format!(
            "{label} contains a duplicate"
        )));
    }
    Ok(())
}

fn unique_values<T: Ord>(values: &[T], label: &str) -> RegistryResult<()> {
    let unique: BTreeSet<_> = values.iter().collect();
    if unique.len() != values.len() {
        return Err(RegistryError::schema(format!(
            "{label} contains a duplicate"
        )));
    }
    Ok(())
}

fn verify_declared_hash(
    declared: &str,
    computed: &str,
    mode: HashVerificationMode,
    label: &str,
) -> RegistryResult<()> {
    if declared == computed
        || (mode == HashVerificationMode::BootstrapGenerate
            && is_obvious_placeholder_hash(declared))
    {
        return Ok(());
    }
    Err(RegistryError::validation(
        ValidatorReasonCode::RegistryContractHashMismatch,
        format!("{label} declares {declared}, generated {computed}"),
    ))
}

fn verify_snapshot_hash(
    declared: &str,
    computed: &str,
    mode: HashVerificationMode,
) -> RegistryResult<()> {
    if declared == computed
        || (mode == HashVerificationMode::BootstrapGenerate
            && is_obvious_placeholder_hash(declared))
    {
        return Ok(());
    }
    Err(RegistryError::validation(
        ValidatorReasonCode::RegistrySnapshotHashMismatch,
        format!("snapshot declares {declared}, generated {computed}"),
    ))
}

fn collect_sources(entries: &[ContractRef], maximum: usize) -> RegistryResult<BTreeSet<PathBuf>> {
    let mut sources = BTreeSet::new();
    for entry in entries {
        let source = entry.source.as_ref().ok_or_else(|| {
            RegistryError::validation(
                ValidatorReasonCode::RegistryEntryNotFound,
                format!(
                    "snapshot entry {} {} has no local source",
                    entry.id, entry.version
                ),
            )
        })?;
        let path = PathBuf::from(source);
        validate_relative_source(&path)?;
        sources.insert(path);
        if sources.len() > maximum {
            return Err(RegistryError::schema(format!(
                "registry references more than {maximum} source files"
            )));
        }
    }
    Ok(sources)
}

fn validate_relative_source(source: &Path) -> RegistryResult<()> {
    if source.as_os_str().is_empty() || source.is_absolute() {
        return Err(RegistryError::schema(format!(
            "registry source {} must be a nonempty relative path",
            source.display()
        )));
    }
    if source
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(RegistryError::schema(format!(
            "registry source {} may not contain prefixes, roots, dot, or parent traversal",
            source.display()
        )));
    }
    let source_text = source.to_string_lossy();
    if source_text.contains("://") {
        return Err(RegistryError::schema(format!(
            "registry source {} may not be a network URL",
            source.display()
        )));
    }
    Ok(())
}

fn resolve_local_source(root: &Path, source: &Path) -> RegistryResult<PathBuf> {
    validate_relative_source(source)?;
    let candidate = root.join(source);
    let resolved = candidate.canonicalize().map_err(|error| {
        RegistryError::operational(format!("cannot open registry source: {error}"))
            .at_path(&candidate)
    })?;
    if !resolved.starts_with(root) {
        return Err(RegistryError::schema(format!(
            "registry source {} resolves outside the supplied bundle",
            source.display()
        )));
    }
    if !resolved.is_file() {
        return Err(RegistryError::operational("registry source is not a file").at_path(resolved));
    }
    Ok(resolved)
}

fn read_bounded(path: &Path, maximum: usize) -> RegistryResult<Vec<u8>> {
    let file = File::open(path).map_err(|error| {
        RegistryError::operational(format!("cannot read registry source: {error}")).at_path(path)
    })?;
    let maximum_plus_one = maximum.saturating_add(1);
    let mut reader: Take<File> = file.take(u64::try_from(maximum_plus_one).unwrap_or(u64::MAX));
    let mut bytes = Vec::with_capacity(maximum.min(64 * 1024));
    reader.read_to_end(&mut bytes).map_err(|error| {
        RegistryError::operational(format!("cannot read registry source: {error}")).at_path(path)
    })?;
    if bytes.len() > maximum {
        return Err(RegistryError::schema(format!(
            "registry source exceeds configured {maximum}-byte limit"
        ))
        .at_path(path));
    }
    Ok(bytes)
}

fn enforce_contract_count(actual: usize, maximum: usize) -> RegistryResult<()> {
    if actual > maximum {
        return Err(RegistryError::schema(format!(
            "registry contains {actual} contracts; configured maximum is {maximum}"
        )));
    }
    Ok(())
}

fn checked_contract_count(left: usize, right: usize) -> RegistryResult<usize> {
    left.checked_add(right)
        .ok_or_else(|| RegistryError::schema("registry contract count exceeds platform capacity"))
}

fn checked_total_bytes(current: usize, added: usize, maximum: usize) -> RegistryResult<usize> {
    let total = current.checked_add(added).ok_or_else(|| {
        RegistryError::schema("registry bundle byte count exceeds platform capacity")
    })?;
    enforce_total_bytes(total, maximum)?;
    Ok(total)
}

fn enforce_total_bytes(actual: usize, maximum: usize) -> RegistryResult<()> {
    if actual > maximum {
        return Err(RegistryError::schema(format!(
            "registry bundle contains {actual} bytes; configured maximum is {maximum}"
        )));
    }
    Ok(())
}

fn snapshot_hash_entry(entry: &ContractRef) -> SnapshotHashEntry {
    SnapshotHashEntry {
        id: entry.id.clone(),
        version: entry.version.clone(),
        content_hash: entry.content_hash.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/aios-ir")
    }

    fn fixture_records() -> (RegistrySnapshot, Vec<TypeContract>, Vec<CapabilityContract>) {
        let limits = StrictJsonLimits::default();
        let snapshot = parse_strict_json(
            &std::fs::read(fixture_root().join("registry-snapshot.json")).unwrap(),
            limits,
        )
        .unwrap();
        let types = parse_strict_json(
            &std::fs::read(fixture_root().join("type-contracts.json")).unwrap(),
            limits,
        )
        .unwrap();
        let capabilities = parse_strict_json(
            &std::fs::read(fixture_root().join("capability-contracts.json")).unwrap(),
            limits,
        )
        .unwrap();
        (snapshot, types, capabilities)
    }

    #[test]
    fn repository_bundle_loads_in_strict_mode() {
        let registry =
            SemanticRegistry::load_bundle(fixture_root(), RegistryLoadOptions::default())
                .expect("repository fixtures contain verified content identities");
        assert!(is_sha256_id(registry.snapshot_id()));
        assert!(registry.resolve_type("data.table@1").unwrap().is_some());
        assert!(
            registry
                .resolve_capability("table.import@1")
                .unwrap()
                .is_some()
        );
        assert_eq!(registry.type_contracts().len(), 10);
        assert_eq!(registry.capability_contracts().len(), 11);
    }

    #[test]
    fn missing_bundle_path_is_operational() {
        let missing = fixture_root().join("does-not-exist");
        let error = SemanticRegistry::load_bundle(missing, RegistryLoadOptions::default())
            .expect_err("missing path must fail");
        assert!(error.is_operational());
        assert_eq!(error.reason_code(), None);
    }

    #[test]
    fn semantic_reference_lookup_rejects_non_major_selectors() {
        let registry =
            SemanticRegistry::load_bundle(fixture_root(), RegistryLoadOptions::default()).unwrap();
        assert!(registry.resolve_type("data.table@1.0").is_err());
        assert!(registry.resolve_capability("table.import").is_err());
    }

    #[test]
    fn aggregate_bundle_limit_fails_closed() {
        let error = SemanticRegistry::load_bundle(
            fixture_root(),
            RegistryLoadOptions {
                limits: RegistryLimits {
                    max_total_bytes: 1,
                    ..RegistryLimits::default()
                },
                ..RegistryLoadOptions::default()
            },
        )
        .expect_err("bundle larger than aggregate limit must fail");
        assert_eq!(
            error.reason_code(),
            Some(ValidatorReasonCode::RegistrySchemaInvalid)
        );
    }

    #[test]
    fn duplicate_major_and_identity_mismatches_fail_closed() {
        let (snapshot, types, capabilities) = fixture_records();

        let mut duplicate = snapshot.clone();
        let mut duplicate_entry = duplicate.type_contracts[0].clone();
        duplicate_entry.version = "1.1".to_owned();
        duplicate.type_contracts.push(duplicate_entry);
        let error = SemanticRegistry::from_records(
            duplicate,
            types.clone(),
            capabilities.clone(),
            RegistryBuildOptions::default(),
        )
        .expect_err("duplicate active major must fail");
        assert_eq!(
            error.reason_code(),
            Some(ValidatorReasonCode::RegistryDuplicateTypeMajor)
        );

        let (mut duplicate, types_again, capabilities_again) = fixture_records();
        let mut duplicate_entry = duplicate.capability_contracts[0].clone();
        duplicate_entry.version = "1.1".to_owned();
        duplicate.capability_contracts.push(duplicate_entry);
        let error = SemanticRegistry::from_records(
            duplicate,
            types_again,
            capabilities_again,
            RegistryBuildOptions::default(),
        )
        .expect_err("duplicate active capability major must fail");
        assert_eq!(
            error.reason_code(),
            Some(ValidatorReasonCode::RegistryDuplicateCapabilityMajor)
        );

        let mut bad_contract_hash = snapshot.clone();
        bad_contract_hash.type_contracts[0].content_hash = format!("sha256:{}", "a".repeat(64));
        let error = SemanticRegistry::from_records(
            bad_contract_hash,
            types.clone(),
            capabilities.clone(),
            RegistryBuildOptions::default(),
        )
        .expect_err("contract identity mismatch must fail");
        assert_eq!(
            error.reason_code(),
            Some(ValidatorReasonCode::RegistryContractHashMismatch)
        );

        let mut bad_snapshot_hash = snapshot;
        bad_snapshot_hash.snapshot_id = format!("sha256:{}", "a".repeat(64));
        let error = SemanticRegistry::from_records(
            bad_snapshot_hash,
            types,
            capabilities,
            RegistryBuildOptions::default(),
        )
        .expect_err("snapshot identity mismatch must fail");
        assert_eq!(
            error.reason_code(),
            Some(ValidatorReasonCode::RegistrySnapshotHashMismatch)
        );
    }

    #[test]
    fn capability_lower_bound_contracts_fail_closed() {
        let (snapshot, types, mut capabilities) = fixture_records();
        capabilities[0].required_effect_classes = vec![EffectClass::SystemChange];
        let error = SemanticRegistry::from_records(
            snapshot.clone(),
            types.clone(),
            capabilities,
            RegistryBuildOptions::default(),
        )
        .expect_err("required effect outside allowed envelope must fail");
        assert_eq!(
            error.reason_code(),
            Some(ValidatorReasonCode::RegistryRequiredEffectNotAllowed)
        );

        let (_, _, mut capabilities) = fixture_records();
        capabilities[0]
            .required_authority_classes
            .push("system.change".to_owned());
        let error = SemanticRegistry::from_records(
            snapshot.clone(),
            types.clone(),
            capabilities,
            RegistryBuildOptions::default(),
        )
        .expect_err("required authority outside allowed envelope must fail");
        assert_eq!(
            error.reason_code(),
            Some(ValidatorReasonCode::RegistryRequiredAuthorityNotAllowed)
        );

        let (_, _, mut capabilities) = fixture_records();
        let pure_contract = capabilities
            .iter_mut()
            .find(|contract| contract.capability == "table.normalize")
            .expect("fixture pure capability");
        pure_contract.required_effect_classes = vec![EffectClass::Pure];
        pure_contract.allowed_effect_classes = vec![EffectClass::Pure, EffectClass::Network];
        let error = SemanticRegistry::from_records(
            snapshot,
            types,
            capabilities,
            RegistryBuildOptions::default(),
        )
        .expect_err("required PURE with a non-PURE allowance must fail");
        assert_eq!(
            error.reason_code(),
            Some(ValidatorReasonCode::RegistryPureEffectContradiction)
        );
    }

    #[test]
    fn protected_required_effects_require_mapped_required_authority() {
        let (_, _, capabilities) = fixture_records();
        let mut protected = capabilities
            .iter()
            .find(|contract| contract.capability == "artifact.hash")
            .unwrap()
            .clone();
        protected.required_authority_classes.clear();
        let error = validate_capability_contract(&protected)
            .expect_err("a protected lower-bound effect cannot be grant-free");
        assert_eq!(
            error.reason_code(),
            Some(ValidatorReasonCode::RegistrySchemaInvalid)
        );

        let mut opaque = capabilities
            .iter()
            .find(|contract| contract.capability == "table.normalize")
            .unwrap()
            .clone();
        opaque.required_effect_classes = vec![EffectClass::LegacyOpaque];
        opaque.allowed_effect_classes = vec![EffectClass::LegacyOpaque];
        validate_capability_contract(&opaque)
            .expect("LEGACY_OPAQUE has no closed-profile authority mapping");
    }

    #[test]
    fn bidirectional_port_names_cannot_represent_different_types() {
        let (_, _, capabilities) = fixture_records();
        let baseline = capabilities
            .iter()
            .find(|contract| contract.capability == "artifact.copy")
            .unwrap();

        let mut compatible = baseline.clone();
        compatible
            .outputs
            .insert("source".to_owned(), compatible.inputs["source"].clone());
        validate_capability_contract(&compatible)
            .expect("the same port name and semantic type is representation-unambiguous");

        let mut ambiguous = compatible;
        ambiguous.outputs.get_mut("source").unwrap().type_ref = "text.plain@1".to_owned();
        let error = validate_capability_contract(&ambiguous)
            .expect_err("directionless provider representations cannot cover two semantic types");
        assert_eq!(
            error.reason_code(),
            Some(ValidatorReasonCode::RegistrySchemaInvalid)
        );
    }

    #[test]
    fn capability_egress_envelopes_accept_only_closed_profile_states() {
        let (_, _, capabilities) = fixture_records();
        let baseline = capabilities
            .into_iter()
            .find(|contract| contract.capability == "report.summarize")
            .unwrap();

        let mut deny_only = baseline.clone();
        deny_only.allowed_egress_modes = vec![aios_contracts::EgressMode::Deny];
        deny_only.allowed_effect_classes = vec![EffectClass::Network];
        deny_only.allowed_authority_classes = vec!["network.connect".to_owned()];
        validate_capability_contract(&deny_only).unwrap();

        validate_capability_contract(&baseline).unwrap();

        let mut policy_only = baseline;
        policy_only.allowed_egress_modes = vec![aios_contracts::EgressMode::Policy];
        policy_only.required_effect_classes = vec![EffectClass::DataEgress];
        policy_only.required_authority_classes = vec!["data.egress".to_owned()];
        validate_capability_contract(&policy_only).unwrap();
    }

    #[test]
    fn capability_egress_cross_axis_contradictions_fail_closed() {
        let (_, _, capabilities) = fixture_records();
        let baseline = capabilities
            .into_iter()
            .find(|contract| contract.capability == "report.summarize")
            .unwrap();

        let mut deny_with_allowed_data_egress = baseline.clone();
        deny_with_allowed_data_egress.allowed_egress_modes = vec![aios_contracts::EgressMode::Deny];

        let mut optional_policy_with_required_data_egress = baseline.clone();
        optional_policy_with_required_data_egress.required_effect_classes =
            vec![EffectClass::DataEgress];
        optional_policy_with_required_data_egress.required_authority_classes =
            vec!["data.egress".to_owned()];

        let mut required_policy_without_required_data_egress = baseline.clone();
        required_policy_without_required_data_egress.allowed_egress_modes =
            vec![aios_contracts::EgressMode::Policy];

        let mut policy_without_data_egress_authority = baseline;
        policy_without_data_egress_authority
            .allowed_authority_classes
            .retain(|authority| authority != "data.egress");

        for contradiction in [
            deny_with_allowed_data_egress,
            optional_policy_with_required_data_egress,
            required_policy_without_required_data_egress,
            policy_without_data_egress_authority,
        ] {
            let error = validate_capability_contract(&contradiction)
                .expect_err("cross-axis egress contradiction must fail");
            assert_eq!(
                error.reason_code(),
                Some(ValidatorReasonCode::RegistrySchemaInvalid)
            );
        }
    }

    #[test]
    fn loaded_contract_version_mismatch_has_stable_reason_code() {
        let (mut snapshot, types, capabilities) = fixture_records();
        snapshot.capability_contracts[0].version = "1.1".to_owned();
        let error = SemanticRegistry::from_records(
            snapshot,
            types,
            capabilities,
            RegistryBuildOptions::default(),
        )
        .expect_err("same capability ID with a different loaded version must fail");
        assert_eq!(
            error.reason_code(),
            Some(ValidatorReasonCode::RegistryContractVersionMismatch)
        );
    }

    #[test]
    fn schema_string_limits_count_unicode_scalars_not_utf8_bytes() {
        let (_, mut types, _) = fixture_records();
        let contract = &mut types[0];
        contract.description = "🦀".repeat(4_096);
        validate_type_contract(contract)
            .expect("4096 Unicode scalar values are within schema maxLength");

        contract.description.push('🦀');
        let error = validate_type_contract(contract)
            .expect_err("4097 Unicode scalar values must exceed schema maxLength");
        assert_eq!(
            error.reason_code(),
            Some(ValidatorReasonCode::RegistrySchemaInvalid)
        );
    }

    #[test]
    fn snapshot_created_at_must_be_an_rfc3339_date_time() {
        let (mut snapshot, _, _) = fixture_records();
        for valid in [
            "2026-09-15T00:00:00Z",
            "2026-09-15t00:00:00z",
            "2026-09-14T17:00:00-07:00",
            "2026-09-15T00:00:00.123456789Z",
        ] {
            snapshot.created_at = valid.to_owned();
            validate_snapshot_header(&snapshot).expect("valid RFC 3339 date-time");
        }

        for invalid in [
            "",
            "2026-09-15",
            "2026-09-15 00:00:00Z",
            "2026-13-15T00:00:00Z",
            "2026-09-15T00:00:00",
        ] {
            snapshot.created_at = invalid.to_owned();
            let error = validate_snapshot_header(&snapshot)
                .expect_err("invalid RFC 3339 date-time must fail closed");
            assert_eq!(
                error.reason_code(),
                Some(ValidatorReasonCode::RegistrySchemaInvalid),
                "unexpected result for {invalid:?}"
            );
        }
    }

    #[test]
    fn registry_contract_count_limit_is_inclusive_and_fails_closed_above_it() {
        let (snapshot, _, _) = fixture_records();
        let count = snapshot.type_contracts.len() + snapshot.capability_contracts.len();
        let at_limit = RegistryLoadOptions {
            limits: RegistryLimits {
                max_contracts: count,
                ..RegistryLimits::default()
            },
            ..RegistryLoadOptions::default()
        };
        SemanticRegistry::load_bundle(fixture_root(), at_limit)
            .expect("the exact registry contract limit is inclusive");

        let below_limit = RegistryLoadOptions {
            limits: RegistryLimits {
                max_contracts: count - 1,
                ..RegistryLimits::default()
            },
            ..RegistryLoadOptions::default()
        };
        let error = SemanticRegistry::load_bundle(fixture_root(), below_limit)
            .expect_err("one contract above the configured limit must fail");
        assert_eq!(
            error.reason_code(),
            Some(ValidatorReasonCode::RegistrySchemaInvalid)
        );
    }
}
