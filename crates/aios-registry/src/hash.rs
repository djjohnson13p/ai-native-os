//! Domain-separated semantic content identities for registry contracts.

use crate::version::{FullVersion, validate_semantic_id};
use crate::{RegistryError, RegistryResult};
use aios_contracts::{CapabilityContract, TypeContract};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;

pub const CAPABILITY_CONTRACT_HASH_DOMAIN: &[u8] = b"AIOS-CAPABILITY-CONTRACT\0v0.1\0";
pub const TYPE_CONTRACT_HASH_DOMAIN: &[u8] = b"AIOS-TYPE-CONTRACT\0v0.1\0";
pub const REGISTRY_SNAPSHOT_HASH_DOMAIN: &[u8] = b"AIOS-SEMANTIC-REGISTRY\0v0.1\0";

macro_rules! semantic_id_type {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub(crate) fn from_hash_input(domain: &[u8], canonical: &[u8]) -> Self {
                Self(domain_separated_sha256(domain, canonical))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }
    };
}

semantic_id_type!(CapabilityContractHash);
semantic_id_type!(TypeContractHash);
semantic_id_type!(RegistrySnapshotId);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotHashEntry {
    pub id: String,
    pub version: String,
    pub content_hash: String,
}

/// Compute the domain-separated semantic identity of a capability contract.
///
/// # Errors
///
/// Returns a registry error when the contract is invalid or its semantic view
/// cannot be serialized and canonicalized.
pub fn capability_contract_hash(
    contract: &CapabilityContract,
) -> RegistryResult<CapabilityContractHash> {
    crate::loader::validate_capability_contract(contract)?;
    let view = capability_contract_semantic_view(contract)?;
    let canonical = canonicalize(&view)?;
    Ok(CapabilityContractHash::from_hash_input(
        CAPABILITY_CONTRACT_HASH_DOMAIN,
        &canonical,
    ))
}

/// Compute the domain-separated semantic identity of a type contract.
///
/// # Errors
///
/// Returns a registry error when the contract is invalid or its semantic view
/// cannot be serialized and canonicalized.
pub fn type_contract_hash(contract: &TypeContract) -> RegistryResult<TypeContractHash> {
    crate::loader::validate_type_contract(contract)?;
    let view = type_contract_semantic_view(contract)?;
    let canonical = canonicalize(&view)?;
    Ok(TypeContractHash::from_hash_input(
        TYPE_CONTRACT_HASH_DOMAIN,
        &canonical,
    ))
}

/// Compute the identity of an immutable registry snapshot hash view.
///
/// # Errors
///
/// Returns a registry error for an unsupported profile, malformed entry,
/// duplicate active major, or canonicalization failure.
pub fn registry_snapshot_id(
    schema_version: &str,
    type_contracts: &[SnapshotHashEntry],
    capability_contracts: &[SnapshotHashEntry],
) -> RegistryResult<RegistrySnapshotId> {
    if schema_version != "0.1" {
        return Err(RegistryError::schema(format!(
            "unsupported registry snapshot hash profile {schema_version:?}"
        )));
    }
    validate_snapshot_hash_entries(type_contracts, "type")?;
    validate_snapshot_hash_entries(capability_contracts, "capability")?;
    let mut type_contracts = type_contracts.to_vec();
    let mut capability_contracts = capability_contracts.to_vec();
    sort_snapshot_entries(&mut type_contracts)?;
    sort_snapshot_entries(&mut capability_contracts)?;

    let view = object([
        ("schema_version", Value::String(schema_version.to_owned())),
        (
            "type_contracts",
            Value::Array(type_contracts.iter().map(snapshot_entry_value).collect()),
        ),
        (
            "capability_contracts",
            Value::Array(
                capability_contracts
                    .iter()
                    .map(snapshot_entry_value)
                    .collect(),
            ),
        ),
    ]);
    let canonical = canonicalize(&view)?;
    Ok(RegistrySnapshotId::from_hash_input(
        REGISTRY_SNAPSHOT_HASH_DOMAIN,
        &canonical,
    ))
}

/// Materialize the prose-free semantic hash view of a capability contract.
///
/// # Errors
///
/// Returns a registry error when required fields are absent or have an invalid
/// shape for the v0.1 hash profile.
pub fn capability_contract_semantic_view(contract: &CapabilityContract) -> RegistryResult<Value> {
    let source = serialized_object(contract, "capability contract")?;
    Ok(object([
        ("capability", required(&source, "capability")?),
        ("version", required(&source, "version")?),
        (
            "role",
            source
                .get("role")
                .cloned()
                .unwrap_or_else(|| Value::String("ordinary".to_owned())),
        ),
        ("inputs", normalize_ports(required(&source, "inputs")?)?),
        ("outputs", normalize_ports(required(&source, "outputs")?)?),
        (
            "allowed_execution_classes",
            sorted_string_set(required(&source, "allowed_execution_classes")?)?,
        ),
        (
            "required_effect_classes",
            sorted_string_set(required(&source, "required_effect_classes")?)?,
        ),
        (
            "allowed_effect_classes",
            sorted_string_set(required(&source, "allowed_effect_classes")?)?,
        ),
        (
            "required_authority_classes",
            sorted_string_set(required(&source, "required_authority_classes")?)?,
        ),
        (
            "allowed_authority_classes",
            sorted_string_set(required(&source, "allowed_authority_classes")?)?,
        ),
        (
            "allowed_egress_modes",
            sorted_string_set(required(&source, "allowed_egress_modes")?)?,
        ),
        (
            "determinism",
            normalize_determinism(source.get("determinism"))?,
        ),
        (
            "error_classes",
            sorted_string_set(required(&source, "error_classes")?)?,
        ),
        (
            "conformance",
            normalize_conformance(required(&source, "conformance")?)?,
        ),
    ]))
}

/// Materialize the prose-free semantic hash view of a type contract.
///
/// # Errors
///
/// Returns a registry error when required fields are absent or have an invalid
/// shape for the v0.1 hash profile.
pub fn type_contract_semantic_view(contract: &TypeContract) -> RegistryResult<Value> {
    let source = serialized_object(contract, "type contract")?;
    let Value::Array(mut representations) = required(&source, "representations")? else {
        return Err(RegistryError::schema("representations must be an array"));
    };
    let mut normalized_representations = Vec::with_capacity(representations.len());
    for representation in representations.drain(..) {
        let representation = as_object(representation, "representation")?;
        normalized_representations.push(object([
            ("id", required(&representation, "id")?),
            (
                "media_type",
                representation
                    .get("media_type")
                    .cloned()
                    .unwrap_or(Value::Null),
            ),
            (
                "schema_ref",
                representation
                    .get("schema_ref")
                    .cloned()
                    .unwrap_or(Value::Null),
            ),
            (
                "zero_copy_candidate",
                representation
                    .get("zero_copy_candidate")
                    .cloned()
                    .unwrap_or(Value::Bool(false)),
            ),
        ]));
    }
    normalized_representations.sort_by(|left, right| {
        utf16_code_unit_cmp(
            string_field(left, "id").unwrap_or_default(),
            string_field(right, "id").unwrap_or_default(),
        )
    });

    let conversions = source
        .get("conversion_capabilities")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));

    Ok(object([
        ("type_id", required(&source, "type_id")?),
        ("version", required(&source, "version")?),
        ("kind", required(&source, "kind")?),
        (
            "logical_schema_ref",
            source
                .get("logical_schema_ref")
                .cloned()
                .unwrap_or(Value::Null),
        ),
        (
            "nullable",
            source
                .get("nullable")
                .cloned()
                .unwrap_or(Value::Bool(false)),
        ),
        ("representations", Value::Array(normalized_representations)),
        (
            "equality",
            normalize_equality(required(&source, "equality")?)?,
        ),
        (
            "unit_semantics",
            normalize_unit_semantics(source.get("unit_semantics"))?,
        ),
        ("conversion_capabilities", sorted_string_set(conversions)?),
        (
            "conformance",
            normalize_conformance(required(&source, "conformance")?)?,
        ),
    ]))
}

/// Serialize a JSON value according to RFC 8785 JCS.
///
/// # Errors
///
/// Returns a registry schema error when the value cannot be canonicalized.
pub fn canonicalize(value: &Value) -> RegistryResult<Vec<u8>> {
    serde_json_canonicalizer::to_vec(value)
        .map_err(|error| RegistryError::schema(format!("RFC 8785 JCS failed: {error}")))
}

pub fn is_sha256_id(value: &str) -> bool {
    let Some(digest) = value.strip_prefix("sha256:") else {
        return false;
    };
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// The bootstrap fixtures use hashes with long all-zero prefixes. This helper is
/// intentionally narrow and is consulted only in an explicit bootstrap mode.
pub fn is_obvious_placeholder_hash(value: &str) -> bool {
    let Some(digest) = value.strip_prefix("sha256:") else {
        return false;
    };
    digest.len() == 64
        && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        && digest.as_bytes()[..56].iter().all(|byte| *byte == b'0')
}

fn serialized_object<T: Serialize>(value: &T, label: &str) -> RegistryResult<Map<String, Value>> {
    let serialized = serde_json::to_value(value)
        .map_err(|error| RegistryError::schema(format!("cannot serialize {label}: {error}")))?;
    as_object(serialized, label)
}

fn as_object(value: Value, label: &str) -> RegistryResult<Map<String, Value>> {
    match value {
        Value::Object(object) => Ok(object),
        _ => Err(RegistryError::schema(format!("{label} must be an object"))),
    }
}

fn required(source: &Map<String, Value>, field: &str) -> RegistryResult<Value> {
    source
        .get(field)
        .cloned()
        .ok_or_else(|| RegistryError::schema(format!("required field {field:?} is absent")))
}

fn normalize_ports(value: Value) -> RegistryResult<Value> {
    let ports = as_object(value, "ports")?;
    let mut normalized = Map::new();
    for (name, value) in ports {
        let port = as_object(value, "port")?;
        normalized.insert(
            name,
            object([
                ("type", required(&port, "type")?),
                ("required", required(&port, "required")?),
            ]),
        );
    }
    Ok(Value::Object(normalized))
}

fn normalize_determinism(value: Option<&Value>) -> RegistryResult<Value> {
    let Some(value) = value else {
        return Ok(Value::Null);
    };
    if value.is_null() {
        return Ok(Value::Null);
    }
    let source = as_object(value.clone(), "determinism")?;
    Ok(object([
        (
            "equivalence",
            source.get("equivalence").cloned().unwrap_or(Value::Null),
        ),
        (
            "numeric_absolute_tolerance",
            source
                .get("numeric_absolute_tolerance")
                .cloned()
                .unwrap_or(Value::Null),
        ),
        (
            "numeric_relative_tolerance",
            source
                .get("numeric_relative_tolerance")
                .cloned()
                .unwrap_or(Value::Null),
        ),
    ]))
}

fn normalize_equality(value: Value) -> RegistryResult<Value> {
    let source = as_object(value, "equality")?;
    Ok(object([
        ("mode", required(&source, "mode")?),
        (
            "canonicalizer",
            source.get("canonicalizer").cloned().unwrap_or(Value::Null),
        ),
        (
            "numeric_absolute_tolerance",
            source
                .get("numeric_absolute_tolerance")
                .cloned()
                .unwrap_or(Value::Null),
        ),
        (
            "numeric_relative_tolerance",
            source
                .get("numeric_relative_tolerance")
                .cloned()
                .unwrap_or(Value::Null),
        ),
    ]))
}

fn normalize_unit_semantics(value: Option<&Value>) -> RegistryResult<Value> {
    let Some(value) = value else {
        return Ok(Value::Null);
    };
    if value.is_null() {
        return Ok(Value::Null);
    }
    let source = as_object(value.clone(), "unit semantics")?;
    Ok(object([
        (
            "unit_required",
            source.get("unit_required").cloned().unwrap_or(Value::Null),
        ),
        (
            "canonical_unit",
            source.get("canonical_unit").cloned().unwrap_or(Value::Null),
        ),
    ]))
}

fn normalize_conformance(value: Value) -> RegistryResult<Value> {
    let source = as_object(value, "conformance")?;
    Ok(object([
        ("suite_id", required(&source, "suite_id")?),
        (
            "suite_version",
            source.get("suite_version").cloned().unwrap_or(Value::Null),
        ),
        (
            "suite_hash",
            source.get("suite_hash").cloned().unwrap_or(Value::Null),
        ),
    ]))
}

fn sorted_string_set(value: Value) -> RegistryResult<Value> {
    let Value::Array(mut values) = value else {
        return Err(RegistryError::schema("semantic set must be an array"));
    };
    if !values.iter().all(Value::is_string) {
        return Err(RegistryError::schema(
            "semantic set contains a non-string value",
        ));
    }
    values.sort_by(|left, right| {
        utf16_code_unit_cmp(
            left.as_str().unwrap_or_default(),
            right.as_str().unwrap_or_default(),
        )
    });
    Ok(Value::Array(values))
}

fn utf16_code_unit_cmp(left: &str, right: &str) -> std::cmp::Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn snapshot_entry_value(entry: &SnapshotHashEntry) -> Value {
    object([
        ("id", Value::String(entry.id.clone())),
        ("version", Value::String(entry.version.clone())),
        ("content_hash", Value::String(entry.content_hash.clone())),
    ])
}

fn sort_snapshot_entries(entries: &mut [SnapshotHashEntry]) -> RegistryResult<()> {
    let mut versions = Vec::with_capacity(entries.len());
    for entry in entries.iter() {
        versions.push(FullVersion::parse(&entry.version)?);
    }
    let mut paired: Vec<(SnapshotHashEntry, FullVersion)> =
        entries.iter().cloned().zip(versions).collect();
    paired.sort_by(|(left, left_version), (right, right_version)| {
        (&left.id, left_version, &left.content_hash).cmp(&(
            &right.id,
            right_version,
            &right.content_hash,
        ))
    });
    for (target, (entry, _)) in entries.iter_mut().zip(paired) {
        *target = entry;
    }
    Ok(())
}

fn validate_snapshot_hash_entries(entries: &[SnapshotHashEntry], kind: &str) -> RegistryResult<()> {
    let mut majors = std::collections::BTreeSet::new();
    for entry in entries {
        validate_semantic_id(&entry.id)?;
        let version = FullVersion::parse(&entry.version)?;
        if !is_sha256_id(&entry.content_hash) {
            return Err(RegistryError::schema(format!(
                "{kind} contract {} {} has an invalid generated content hash",
                entry.id, entry.version
            )));
        }
        if !majors.insert((entry.id.as_str(), version.major)) {
            return Err(RegistryError::schema(format!(
                "registry hash view repeats active {kind} family {}@{}",
                entry.id, version.major
            )));
        }
    }
    Ok(())
}

fn string_field<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.as_object()?.get(field)?.as_str()
}

fn object<const N: usize>(entries: [(&str, Value); N]) -> Value {
    let mut object = Map::new();
    for (key, value) in entries {
        object.insert(key.to_owned(), value);
    }
    Value::Object(object)
}

fn domain_separated_sha256(domain: &[u8], canonical: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical);
    let digest = hasher.finalize();
    let mut output = String::with_capacity("sha256:".len() + digest.len() * 2);
    output.push_str("sha256:");
    for byte in digest {
        use fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use aios_contracts::{CapabilityRole, UnitSemantics};

    const CAPABILITY_CONTRACTS: &str =
        include_str!("../../../examples/aios-ir/capability-contracts.json");
    const TYPE_CONTRACTS: &str = include_str!("../../../examples/aios-ir/type-contracts.json");

    #[test]
    fn placeholder_detection_is_explicit_and_narrow() {
        assert!(is_obvious_placeholder_hash(&format!(
            "sha256:{}abcd1234",
            "0".repeat(56)
        )));
        assert!(!is_obvious_placeholder_hash(&format!(
            "sha256:{}",
            "a".repeat(64)
        )));
        assert!(!is_obvious_placeholder_hash("sha256:00"));
    }

    #[test]
    fn domains_produce_distinct_identities() {
        let canonical = br#"{"same":true}"#;
        let capability = domain_separated_sha256(CAPABILITY_CONTRACT_HASH_DOMAIN, canonical);
        let type_hash = domain_separated_sha256(TYPE_CONTRACT_HASH_DOMAIN, canonical);
        let registry = domain_separated_sha256(REGISTRY_SNAPSHOT_HASH_DOMAIN, canonical);
        assert_ne!(capability, type_hash);
        assert_ne!(capability, registry);
        assert_ne!(type_hash, registry);
        assert!(is_sha256_id(&capability));
        assert_eq!(
            capability,
            "sha256:de5f0ddfe98e28c706097e85f9d5422964f6ef1f33ed743c57018adabcb436df"
        );
        assert_eq!(
            type_hash,
            "sha256:55eb52b45bc15f1dc23c7a5b16cb63720653b13ae63718731f506879f1275b61"
        );
        assert_eq!(
            registry,
            "sha256:716d7b8a5bff67fd0386174bf3a4444143af73a96c5c21910200c995c42751be"
        );
    }

    #[test]
    fn semantic_array_sorting_uses_utf16_code_unit_order() {
        // Unicode scalar order places U+E000 before U+10000, while RFC 8785's
        // UTF-16 code-unit order places U+10000's leading surrogate first.
        let supplementary = "\u{10000}";
        let private_use = "\u{e000}";
        assert!(supplementary > private_use);
        assert_eq!(
            utf16_code_unit_cmp(supplementary, private_use),
            std::cmp::Ordering::Less
        );

        let sorted = sorted_string_set(serde_json::json!([private_use, supplementary])).unwrap();
        assert_eq!(sorted, serde_json::json!([supplementary, private_use]));

        let contracts: Vec<TypeContract> = serde_json::from_str(TYPE_CONTRACTS).unwrap();
        let mut contract = contracts.into_iter().next().unwrap();
        let template = contract.representations[0].clone();
        let mut first = template.clone();
        first.id = private_use.to_owned();
        let mut second = template;
        second.id = supplementary.to_owned();
        contract.representations = vec![first, second];

        let semantic = type_contract_semantic_view(&contract).unwrap();
        let representations = semantic["representations"].as_array().unwrap();
        assert_eq!(representations[0]["id"], supplementary);
        assert_eq!(representations[1]["id"], private_use);
    }

    #[test]
    fn capability_hash_excludes_prose_and_normalizes_sets() {
        let contracts: Vec<CapabilityContract> =
            serde_json::from_str(CAPABILITY_CONTRACTS).unwrap();
        let baseline = contracts
            .into_iter()
            .find(|contract| contract.capability == "report.summarize")
            .unwrap();
        let baseline_hash = capability_contract_hash(&baseline).unwrap();

        let mut equivalent = baseline.clone();
        equivalent.description = Some("different explanatory prose".to_owned());
        equivalent.notes = vec!["different authoring note".to_owned()];
        for port in equivalent
            .inputs
            .values_mut()
            .chain(equivalent.outputs.values_mut())
        {
            port.description = Some("different port prose".to_owned());
        }
        equivalent.allowed_execution_classes.reverse();
        equivalent.required_effect_classes.reverse();
        equivalent.allowed_effect_classes.reverse();
        equivalent.required_authority_classes.reverse();
        equivalent.allowed_authority_classes.reverse();
        equivalent.allowed_egress_modes.reverse();
        equivalent.error_classes.reverse();
        assert_eq!(
            capability_contract_hash(&equivalent).unwrap(),
            baseline_hash
        );

        equivalent.role = CapabilityRole::Verifier;
        assert_ne!(
            capability_contract_hash(&equivalent).unwrap(),
            baseline_hash
        );
    }

    #[test]
    fn type_hash_excludes_prose_and_normalizes_sets() {
        let contracts: Vec<TypeContract> = serde_json::from_str(TYPE_CONTRACTS).unwrap();
        let mut baseline = contracts
            .into_iter()
            .find(|contract| contract.type_id == "data.table")
            .unwrap();
        baseline.unit_semantics = Some(UnitSemantics {
            unit_required: Some(true),
            canonical_unit: Some("fixture-unit".to_owned()),
            notes: Some("first explanatory unit note".to_owned()),
        });
        let baseline_hash = type_contract_hash(&baseline).unwrap();

        let mut equivalent = baseline.clone();
        equivalent.description = "different explanatory prose".to_owned();
        equivalent.notes = vec!["different top-level note".to_owned()];
        equivalent.representations.reverse();
        equivalent.conversion_capabilities.reverse();
        equivalent.unit_semantics.as_mut().unwrap().notes =
            Some("different explanatory unit note".to_owned());
        assert_eq!(type_contract_hash(&equivalent).unwrap(), baseline_hash);

        equivalent.nullable = !equivalent.nullable;
        assert_ne!(type_contract_hash(&equivalent).unwrap(), baseline_hash);
    }
}
