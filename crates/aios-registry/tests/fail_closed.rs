//! Fail-closed identity and contract-consistency tests for Registry Snapshots.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use aios_contracts::{
    CapabilityContract, EffectClass, RegistrySnapshot, TypeContract, ValidatorReasonCode,
};
use aios_registry::{RegistryBuildOptions, RegistryLoadOptions, SemanticRegistry};
use serde::Deserialize;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Deserialize)]
struct VersionResolutionFixtures {
    registry_cases: Vec<RegistryFixtureCase>,
}

#[derive(Deserialize)]
struct RegistryFixtureCase {
    name: String,
    expected: String,
    reason_code: String,
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/aios-ir")
}

fn temporary_registry(label: &str) -> PathBuf {
    let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "aios-registry-{label}-{}-{sequence}",
        std::process::id()
    ));
    std::fs::create_dir(&path).expect("create temporary registry");
    path
}

fn read<T: serde::de::DeserializeOwned>(name: &str) -> T {
    serde_json::from_slice(&std::fs::read(fixture_root().join(name)).unwrap()).unwrap()
}

fn records() -> (RegistrySnapshot, Vec<TypeContract>, Vec<CapabilityContract>) {
    (
        read("registry-snapshot.json"),
        read("type-contracts.json"),
        read("capability-contracts.json"),
    )
}

fn assert_registry_code(
    result: Result<SemanticRegistry, aios_registry::RegistryError>,
    code: ValidatorReasonCode,
) {
    let error = result.expect_err("mutated registry must fail closed");
    assert_eq!(error.reason_code(), Some(code), "{error}");
    assert!(!error.is_operational());
}

#[test]
fn duplicate_json_key_text_is_redacted_from_registry_error() {
    let secret = "Bearer sk-test-registry-duplicate-key";
    let directory = temporary_registry("duplicate-key-redaction");
    for name in ["capability-contracts.json", "type-contracts.json"] {
        std::fs::copy(fixture_root().join(name), directory.join(name)).unwrap();
    }
    let snapshot = std::fs::read_to_string(fixture_root().join("registry-snapshot.json")).unwrap();
    let injected = snapshot.replacen('{', &format!("{{\"{secret}\":0,\"{secret}\":1,"), 1);
    std::fs::write(directory.join("registry-snapshot.json"), injected).unwrap();

    let error = SemanticRegistry::load_bundle(&directory, RegistryLoadOptions::default())
        .expect_err("duplicate registry key must fail");

    for name in [
        "capability-contracts.json",
        "type-contracts.json",
        "registry-snapshot.json",
    ] {
        let _ = std::fs::remove_file(directory.join(name));
    }
    let _ = std::fs::remove_dir(directory);

    assert_eq!(
        error.reason_code(),
        Some(ValidatorReasonCode::RegistrySchemaInvalid)
    );
    assert_eq!(error.message, "duplicate JSON key");
    assert!(!error.to_string().contains(secret));
}

#[test]
fn repository_version_resolution_registry_cases_match_expected_codes() {
    let fixtures: VersionResolutionFixtures = read("version-resolution-cases.json");
    for case in fixtures.registry_cases {
        assert_eq!(case.expected, "invalid", "{}", case.name);
        let expected: ValidatorReasonCode = case.reason_code.parse().unwrap();
        let (mut snapshot, types, capabilities) = records();
        let result = match case.name.as_str() {
            "duplicate-capability-major-in-one-snapshot" => {
                let mut duplicate = snapshot
                    .capability_contracts
                    .iter()
                    .find(|entry| entry.id == "artifact.hash")
                    .unwrap()
                    .clone();
                duplicate.version = "1.1".to_owned();
                snapshot.capability_contracts.push(duplicate);
                SemanticRegistry::from_records(
                    snapshot,
                    types,
                    capabilities,
                    RegistryBuildOptions::default(),
                )
            }
            "duplicate-type-major-in-one-snapshot" => {
                let mut duplicate = snapshot
                    .type_contracts
                    .iter()
                    .find(|entry| entry.id == "data.table")
                    .unwrap()
                    .clone();
                duplicate.version = "1.2".to_owned();
                snapshot.type_contracts.push(duplicate);
                SemanticRegistry::from_records(
                    snapshot,
                    types,
                    capabilities,
                    RegistryBuildOptions::default(),
                )
            }
            "snapshot-entry-contract-version-major-mismatch" => {
                snapshot
                    .capability_contracts
                    .iter_mut()
                    .find(|entry| entry.id == "artifact.hash")
                    .unwrap()
                    .version = "2.0".to_owned();
                SemanticRegistry::from_records(
                    snapshot,
                    types,
                    capabilities,
                    RegistryBuildOptions::default(),
                )
            }
            name => panic!("unautomated registry fixture case {name}"),
        };
        assert_registry_code(result, expected);
    }
}

#[test]
fn contract_content_hash_mismatch_fails_closed() {
    let (snapshot, types, mut capabilities) = records();
    capabilities
        .iter_mut()
        .find(|contract| contract.capability == "artifact.hash")
        .unwrap()
        .error_classes
        .push("ARTIFACT_HASH_NEW_SEMANTIC_ERROR".to_owned());
    assert_registry_code(
        SemanticRegistry::from_records(
            snapshot,
            types,
            capabilities,
            RegistryBuildOptions::default(),
        ),
        ValidatorReasonCode::RegistryContractHashMismatch,
    );
}

#[test]
fn snapshot_identity_mismatch_fails_closed() {
    let (mut snapshot, types, capabilities) = records();
    snapshot.snapshot_id = format!("sha256:{}", "a".repeat(64));
    assert_registry_code(
        SemanticRegistry::from_records(
            snapshot,
            types,
            capabilities,
            RegistryBuildOptions::default(),
        ),
        ValidatorReasonCode::RegistrySnapshotHashMismatch,
    );
}

#[test]
fn duplicate_active_major_contracts_fail_closed() {
    let (mut snapshot, types, capabilities) = records();
    let mut duplicate = snapshot
        .capability_contracts
        .iter()
        .find(|entry| entry.id == "artifact.hash")
        .unwrap()
        .clone();
    duplicate.version = "1.1".to_owned();
    snapshot.capability_contracts.push(duplicate);
    assert_registry_code(
        SemanticRegistry::from_records(
            snapshot,
            types.clone(),
            capabilities.clone(),
            RegistryBuildOptions::default(),
        ),
        ValidatorReasonCode::RegistryDuplicateCapabilityMajor,
    );

    let (mut snapshot, _, _) = records();
    let mut duplicate = snapshot
        .type_contracts
        .iter()
        .find(|entry| entry.id == "data.table")
        .unwrap()
        .clone();
    duplicate.version = "1.2".to_owned();
    snapshot.type_contracts.push(duplicate);
    assert_registry_code(
        SemanticRegistry::from_records(
            snapshot,
            types,
            capabilities,
            RegistryBuildOptions::default(),
        ),
        ValidatorReasonCode::RegistryDuplicateTypeMajor,
    );
}

#[test]
fn selected_entry_and_loaded_contract_version_mismatch_fails_closed() {
    let (mut snapshot, types, capabilities) = records();
    let entry = snapshot
        .capability_contracts
        .iter_mut()
        .find(|entry| entry.id == "artifact.hash")
        .unwrap();
    entry.version = "2.0".to_owned();
    assert_registry_code(
        SemanticRegistry::from_records(
            snapshot,
            types,
            capabilities,
            RegistryBuildOptions::default(),
        ),
        ValidatorReasonCode::RegistryContractVersionMismatch,
    );
}

#[test]
fn required_effect_and_authority_must_be_allowed() {
    let (snapshot, types, mut capabilities) = records();
    let normalize = capabilities
        .iter_mut()
        .find(|contract| contract.capability == "table.normalize")
        .unwrap();
    normalize.required_effect_classes = vec![EffectClass::ArtifactRead];
    assert_registry_code(
        SemanticRegistry::from_records(
            snapshot,
            types,
            capabilities,
            RegistryBuildOptions::default(),
        ),
        ValidatorReasonCode::RegistryRequiredEffectNotAllowed,
    );

    let (snapshot, types, mut capabilities) = records();
    let importer = capabilities
        .iter_mut()
        .find(|contract| contract.capability == "table.import")
        .unwrap();
    importer.required_authority_classes = vec!["artifact.write".to_owned()];
    importer
        .allowed_effect_classes
        .push(EffectClass::ArtifactWrite);
    assert_registry_code(
        SemanticRegistry::from_records(
            snapshot,
            types,
            capabilities,
            RegistryBuildOptions::default(),
        ),
        ValidatorReasonCode::RegistryRequiredAuthorityNotAllowed,
    );
}

#[test]
fn pure_contract_cannot_permit_non_pure_effects() {
    let (snapshot, types, mut capabilities) = records();
    capabilities
        .iter_mut()
        .find(|contract| contract.capability == "table.normalize")
        .unwrap()
        .allowed_effect_classes
        .push(EffectClass::Network);
    assert_registry_code(
        SemanticRegistry::from_records(
            snapshot,
            types,
            capabilities,
            RegistryBuildOptions::default(),
        ),
        ValidatorReasonCode::RegistryPureEffectContradiction,
    );
}
