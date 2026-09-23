//! Repository fixture and semantic-hash conformance tests.

use std::fs;
use std::path::{Path, PathBuf};

use aios_contracts::{
    CapabilityContract, RegistrySnapshot, TypeContract, ValidatorOutput, ValidatorReasonCode,
};
use aios_ir::{ValidationLimits, ValidationReport, Validator};
use aios_registry::{
    HashVerificationMode, ProviderStore, ProviderTrustStatus, RegistryBuildOptions,
    RegistryLoadOptions, RegistryStore, SemanticRegistry, SnapshotHashEntry,
};
use jsonschema::Resource;
use proptest::prelude::*;
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const FIXED_TIME: &str = "2026-09-15T00:00:00Z";

#[derive(Debug, Deserialize)]
struct ProgramCase {
    name: String,
    expected: String,
    #[serde(default)]
    reason_code: Option<ValidatorReasonCode>,
    program: Value,
}

#[derive(Debug, Deserialize)]
struct CaseEnvelope {
    cases: Vec<ProgramCase>,
}

#[derive(Debug, Deserialize)]
struct VersionEnvelope {
    program_cases: Vec<ProgramCase>,
    cross_snapshot_cases: Vec<CrossSnapshotCase>,
}

#[derive(Debug, Deserialize)]
struct CrossSnapshotCase {
    name: String,
    #[serde(default)]
    expected_semantic_hash_relation: Option<String>,
    #[serde(default)]
    expected_registry_snapshot_relation: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CanonicalEnvelope {
    cases: Vec<CanonicalCase>,
    invalid_cases: Vec<ProgramCase>,
}

#[derive(Debug, Deserialize)]
struct CanonicalCase {
    name: String,
    expected_relation: String,
    left: Value,
    right: Value,
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/aios-ir")
}

fn fixture_value(name: &str) -> Value {
    serde_json::from_slice(&fs::read(fixture_root().join(name)).unwrap()).unwrap()
}

fn fixed_time() -> OffsetDateTime {
    OffsetDateTime::parse(FIXED_TIME, &Rfc3339).unwrap()
}

fn validator() -> Validator {
    let registry = SemanticRegistry::load_bundle(fixture_root(), RegistryLoadOptions::default())
        .expect("fixture registry must verify strictly");
    Validator::new(registry, ValidationLimits::default())
}

fn registry_with_artifact_hash_versions(versions: &[&str]) -> SemanticRegistry {
    const PLACEHOLDER: &str =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let mut snapshot: RegistrySnapshot =
        serde_json::from_value(fixture_value("registry-snapshot.json")).unwrap();
    let types: Vec<TypeContract> =
        serde_json::from_value(fixture_value("type-contracts.json")).unwrap();
    let mut capabilities: Vec<CapabilityContract> =
        serde_json::from_value(fixture_value("capability-contracts.json")).unwrap();
    let template = capabilities
        .iter()
        .find(|contract| contract.capability == "artifact.hash")
        .unwrap()
        .clone();
    capabilities.retain(|contract| contract.capability != "artifact.hash");
    snapshot
        .capability_contracts
        .retain(|entry| entry.id != "artifact.hash");
    for version in versions {
        let mut contract = template.clone();
        (*version).clone_into(&mut contract.version);
        capabilities.push(contract);
        snapshot
            .capability_contracts
            .push(aios_contracts::ContractRef {
                id: "artifact.hash".to_owned(),
                version: (*version).to_owned(),
                content_hash: PLACEHOLDER.to_owned(),
                source: Some("capability-contracts.json".to_owned()),
            });
    }
    PLACEHOLDER.clone_into(&mut snapshot.snapshot_id);
    let bootstrap = SemanticRegistry::from_records(
        snapshot,
        types,
        capabilities,
        RegistryBuildOptions {
            hash_verification: HashVerificationMode::BootstrapGenerate,
            ..RegistryBuildOptions::default()
        },
    )
    .unwrap();
    SemanticRegistry::from_records(
        bootstrap.snapshot().clone(),
        bootstrap.type_contracts().cloned().collect(),
        bootstrap.capability_contracts().cloned().collect(),
        RegistryBuildOptions::default(),
    )
    .unwrap()
}

fn validate(validator: &Validator, program: &Value) -> ValidationReport {
    validator.validate_bytes_at(&serde_json::to_vec(program).unwrap(), fixed_time())
}

fn assert_cases(cases: &[ProgramCase]) {
    let validator = validator();
    for case in cases {
        let report = validate(&validator, &case.program);
        let validation = &report.output.validation;
        let expected_valid = matches!(case.expected.as_str(), "valid" | "valid_with_warning");
        assert_eq!(
            validation.valid, expected_valid,
            "case {} returned diagnostics: {:?}",
            case.name, validation.diagnostics
        );
        assert_eq!(
            report.output.effect_summary.is_some(),
            expected_valid,
            "case {} effect-summary validity coupling",
            case.name
        );
        assert_eq!(
            validation.semantic_hash.is_some(),
            expected_valid,
            "case {} semantic-hash validity coupling",
            case.name
        );
        if let Some(expected) = case.reason_code {
            assert!(
                validation
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.code == expected),
                "case {} lacked {}; got {:?}",
                case.name,
                expected,
                validation.diagnostics
            );
        }
        if case.expected == "valid_with_warning" {
            assert!(validation.diagnostics.iter().any(|diagnostic| {
                diagnostic.code == ValidatorReasonCode::IrGraphUnusedPureNode
            }));
        }
    }
}

#[test]
fn valid_program_fixtures_pass() {
    let cases: Vec<ProgramCase> =
        serde_json::from_value(fixture_value("valid-cases.json")).unwrap();
    assert_cases(&cases);
}

#[test]
fn bootstrap_registry_cannot_issue_executable_identity() {
    const PLACEHOLDER: &str =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let mut snapshot: RegistrySnapshot =
        serde_json::from_value(fixture_value("registry-snapshot.json")).unwrap();
    PLACEHOLDER.clone_into(&mut snapshot.snapshot_id);
    let registry = SemanticRegistry::from_records(
        snapshot,
        serde_json::from_value(fixture_value("type-contracts.json")).unwrap(),
        serde_json::from_value(fixture_value("capability-contracts.json")).unwrap(),
        RegistryBuildOptions {
            hash_verification: HashVerificationMode::BootstrapGenerate,
            ..RegistryBuildOptions::default()
        },
    )
    .unwrap();
    assert!(!registry.is_strictly_verified());

    let report = validate(
        &Validator::new(registry, ValidationLimits::default()),
        &fixture_value("demonstration-a.ir.json"),
    );
    assert!(!report.output.validation.valid);
    assert!(report.output.validation.semantic_hash.is_none());
    assert!(report.output.validation.registry_snapshot_id.is_none());
    assert!(report.output.effect_summary.is_none());
    assert_eq!(
        report.output.validation.diagnostics[0].code,
        ValidatorReasonCode::RegistrySnapshotHashMismatch
    );
}

#[test]
fn structural_and_graph_rejections_match_reason_codes() {
    let cases: Vec<ProgramCase> =
        serde_json::from_value(fixture_value("invalid-cases.json")).unwrap();
    assert_cases(&cases);
}

#[test]
fn semantic_rejections_match_reason_codes() {
    let cases: Vec<ProgramCase> =
        serde_json::from_value(fixture_value("invalid-semantic-cases.json")).unwrap();
    assert_cases(&cases);
}

#[test]
fn edge_case_contract_is_enforced() {
    let envelope: CaseEnvelope =
        serde_json::from_value(fixture_value("edge-case-cases.json")).unwrap();
    assert_cases(&envelope.cases);
}

#[test]
fn versioned_program_references_follow_major_selector_rules() {
    let envelope: VersionEnvelope =
        serde_json::from_value(fixture_value("version-resolution-cases.json")).unwrap();
    assert_cases(&envelope.program_cases);
}

#[test]
fn cross_snapshot_version_fixtures_preserve_ir_identity_rules() {
    let envelope: VersionEnvelope =
        serde_json::from_value(fixture_value("version-resolution-cases.json")).unwrap();
    let base = envelope
        .program_cases
        .iter()
        .find(|case| case.name == "major-reference-resolves")
        .unwrap()
        .program
        .clone();

    for case in envelope.cross_snapshot_cases {
        match case.name.as_str() {
            "compatible-minor-snapshot-change-does-not-rewrite-ir-hash" => {
                assert_eq!(
                    case.expected_semantic_hash_relation.as_deref(),
                    Some("equal")
                );
                assert_eq!(
                    case.expected_registry_snapshot_relation.as_deref(),
                    Some("different")
                );
                let left = validate(
                    &Validator::new(
                        registry_with_artifact_hash_versions(&["1.0"]),
                        ValidationLimits::default(),
                    ),
                    &base,
                );
                let right = validate(
                    &Validator::new(
                        registry_with_artifact_hash_versions(&["1.1"]),
                        ValidationLimits::default(),
                    ),
                    &base,
                );
                assert!(left.output.validation.valid);
                assert!(right.output.validation.valid);
                assert_eq!(
                    left.output.validation.semantic_hash,
                    right.output.validation.semantic_hash
                );
                assert_ne!(
                    left.output.validation.registry_snapshot_id,
                    right.output.validation.registry_snapshot_id
                );
            }
            "major-reference-change-changes-semantic-hash" => {
                assert_eq!(
                    case.expected_semantic_hash_relation.as_deref(),
                    Some("different")
                );
                let registry = registry_with_artifact_hash_versions(&["1.0", "2.0"]);
                let left = validate(
                    &Validator::new(registry.clone(), ValidationLimits::default()),
                    &base,
                );
                let mut right_program = base.clone();
                right_program["nodes"][0]["operation"]["capability"] =
                    Value::String("artifact.hash@2".to_owned());
                let right = validate(
                    &Validator::new(registry, ValidationLimits::default()),
                    &right_program,
                );
                assert!(left.output.validation.valid);
                assert!(right.output.validation.valid);
                assert_ne!(
                    left.output.validation.semantic_hash,
                    right.output.validation.semantic_hash
                );
            }
            name => panic!("unautomated cross-snapshot fixture case {name}"),
        }
    }
}

#[test]
fn canonicalization_pairs_have_the_declared_relation() {
    let envelope: CanonicalEnvelope =
        serde_json::from_value(fixture_value("canonicalization-cases.json")).unwrap();
    let validator = validator();
    for case in envelope.cases {
        let left = validate(&validator, &case.left);
        let right = validate(&validator, &case.right);
        assert!(left.output.validation.valid, "left side of {}", case.name);
        assert!(right.output.validation.valid, "right side of {}", case.name);
        let left_hash = left.output.validation.semantic_hash.unwrap();
        let right_hash = right.output.validation.semantic_hash.unwrap();
        match case.expected_relation.as_str() {
            "equal" => assert_eq!(left_hash, right_hash, "{}", case.name),
            "different" => assert_ne!(left_hash, right_hash, "{}", case.name),
            relation => panic!("unknown expected relation {relation:?}"),
        }
    }
}

#[test]
fn canonicalization_structural_rejections_are_automated() {
    let envelope: CanonicalEnvelope =
        serde_json::from_value(fixture_value("canonicalization-cases.json")).unwrap();
    assert_cases(&envelope.invalid_cases);
}

#[test]
fn demonstration_effect_summary_has_expected_upper_bound() {
    let program = fixture_value("demonstration-a.ir.json");
    let report = validate(&validator(), &program);
    let expected: ValidatorOutput =
        serde_json::from_value(fixture_value("validator-output.json")).unwrap();
    assert_eq!(
        report.output, expected,
        "checked-in deterministic test vector"
    );
    let summary = report.output.effect_summary.expect("valid effect summary");
    assert_eq!(
        serde_json::to_value(&summary.effects).unwrap(),
        json!(["ARTIFACT_READ", "ARTIFACT_WRITE"])
    );
    assert!(summary.contains_probabilistic);
    assert!(!summary.contains_opaque_external);
    assert_eq!(summary.verification_barriers, ["verify_narrative"]);
    assert_eq!(
        summary.semantic_program_hash,
        "sha256:beac8904db84998c56eca183c0e979f99746da2cec916f58c600416ee5de3cbf"
    );
}

#[test]
fn downstream_examples_reference_generated_semantic_identities() {
    let report = validate(&validator(), &fixture_value("demonstration-a.ir.json"));
    let semantic_hash = report.output.validation.semantic_hash.unwrap();
    let snapshot_id = report.output.validation.registry_snapshot_id.unwrap();
    let binding = fixture_value("execution-binding-import-table.json");
    let skill = fixture_value("skill-manifest-analyze-numbers.json");

    assert_eq!(binding["semantic_program_hash"], semantic_hash);
    assert_eq!(binding["registry_snapshot_id"], snapshot_id);
    assert_eq!(skill["source_ir"]["semantic_hash"], semantic_hash);
    let registry =
        SemanticRegistry::load_bundle(fixture_root(), RegistryLoadOptions::default()).unwrap();
    assert_eq!(
        binding["capability_contract_hash"],
        registry
            .capability_contract_hash("table.import", 1)
            .unwrap()
            .as_str()
    );

    let specs = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../specs");
    for (schema_name, value) in [
        ("execution-binding.schema.json", &binding),
        ("skill-manifest.schema.json", &skill),
    ] {
        let schema: Value =
            serde_json::from_slice(&fs::read(specs.join(schema_name)).unwrap()).unwrap();
        let compiled = jsonschema::validator_for(&schema).unwrap();
        assert!(
            compiled.is_valid(value),
            "{schema_name}: {:?}",
            compiled
                .iter_errors(value)
                .map(|error| error.to_string())
                .collect::<Vec<_>>()
        );
    }
}

const PROVIDER_TEST_SUITE_HASH: &str =
    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn provider_test_registry(authored: &SemanticRegistry) -> (SemanticRegistry, String) {
    let mut snapshot = authored.snapshot().clone();
    let types = authored.type_contracts().cloned().collect::<Vec<_>>();
    let mut capabilities = authored.capability_contracts().cloned().collect::<Vec<_>>();
    let hash_contract = capabilities
        .iter_mut()
        .find(|contract| contract.capability == "artifact.hash")
        .unwrap();
    hash_contract.conformance.suite_hash = Some(PROVIDER_TEST_SUITE_HASH.into());
    let hash = aios_registry::capability_contract_hash(hash_contract)
        .unwrap()
        .to_string();
    let hash_entry = snapshot
        .capability_contracts
        .iter_mut()
        .find(|entry| entry.id == "artifact.hash")
        .unwrap();
    hash_entry.content_hash.clone_from(&hash);
    let view = |entry: &aios_contracts::ContractRef| SnapshotHashEntry {
        id: entry.id.clone(),
        version: entry.version.clone(),
        content_hash: entry.content_hash.clone(),
    };
    snapshot.snapshot_id = aios_registry::registry_snapshot_id(
        &snapshot.schema_version,
        &snapshot.type_contracts.iter().map(view).collect::<Vec<_>>(),
        &snapshot
            .capability_contracts
            .iter()
            .map(view)
            .collect::<Vec<_>>(),
    )
    .unwrap()
    .to_string();
    let registry = SemanticRegistry::from_records(
        snapshot,
        types,
        capabilities,
        RegistryBuildOptions::default(),
    )
    .unwrap();
    assert!(registry.is_strictly_verified());
    (registry, hash)
}

#[test]
fn provider_inventory_changes_do_not_change_validated_semantic_program_hash() {
    let authored =
        SemanticRegistry::load_bundle(fixture_root(), RegistryLoadOptions::default()).unwrap();
    let (registry, hash) = provider_test_registry(&authored);
    let program = fixture_value("canonicalization-cases.json")["cases"][1]["left"].clone();
    let authored_hash = validate(
        &Validator::new(authored, ValidationLimits::default()),
        &program,
    )
    .output
    .validation
    .semantic_hash;
    let baseline = validate(
        &Validator::new(registry.clone(), ValidationLimits::default()),
        &program,
    );
    assert!(baseline.output.validation.valid);
    let expected_hash = baseline.output.validation.semantic_hash.clone();
    assert_eq!(expected_hash, authored_hash);

    let mut connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(include_str!("../../../specs/persistence-v0.1.sql"))
        .unwrap();
    connection.execute(
        "INSERT OR IGNORE INTO schema_migrations(migration_id,checksum,applied_at) VALUES ('0001_v0_1_trusted_control_plane','UNGENERATED-DRAFT-CHECKSUM','2026-09-19T00:00:00Z')",
        [],
    ).unwrap();
    RegistryStore::initialize(&mut connection)
        .unwrap()
        .admit_registry(&registry)
        .unwrap();
    let mut providers = ProviderStore::initialize(&mut connection).unwrap();
    let mut manifest = fixture_value("provider-conformance-cases.json")[0]["provider"].clone();
    manifest["provides"][0]["contract"]["contract_hash"] = hash.into();
    manifest["provides"][0]["conformance"]["suite_hash"] = PROVIDER_TEST_SUITE_HASH.into();
    for (id, build) in [
        (
            "org.ainative.fixture.artifact-hash-a",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        (
            "org.ainative.fixture.artifact-hash-b",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ),
    ] {
        manifest["id"] = id.into();
        let registered = providers
            .register(
                &registry,
                &serde_json::to_vec(&manifest).unwrap(),
                build,
                ProviderTrustStatus::LocallyTrusted,
                FIXED_TIME,
            )
            .unwrap();
        let after_registration = validate(
            &Validator::new(registry.clone(), ValidationLimits::default()),
            &program,
        );
        assert_eq!(
            after_registration.output.validation.semantic_hash,
            expected_hash
        );
        providers
            .revoke(&registered.registration_id, FIXED_TIME)
            .unwrap();
    }
    let after_revocation = validate(
        &Validator::new(registry, ValidationLimits::default()),
        &program,
    );
    assert_eq!(
        after_revocation.output.validation.semantic_hash,
        expected_hash
    );
}

#[test]
fn valid_and_rejected_outputs_conform_to_checked_in_output_schemas() {
    let specs = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../specs");
    let output_schema: Value =
        serde_json::from_slice(&fs::read(specs.join("validator-output.schema.json")).unwrap())
            .unwrap();
    let validation_schema: Value =
        serde_json::from_slice(&fs::read(specs.join("ir-validation-result.schema.json")).unwrap())
            .unwrap();
    let effect_schema: Value =
        serde_json::from_slice(&fs::read(specs.join("effect-summary.schema.json")).unwrap())
            .unwrap();
    let schema_validator = jsonschema::options()
        .with_resources(
            [
                (
                    "https://ai-native-os.example/specs/ir-validation-result.schema.json",
                    Resource::from_contents(validation_schema),
                ),
                (
                    "https://ai-native-os.example/specs/effect-summary.schema.json",
                    Resource::from_contents(effect_schema),
                ),
            ]
            .into_iter(),
        )
        .build(&output_schema)
        .unwrap();

    let valid = validate(&validator(), &fixture_value("demonstration-a.ir.json"));
    let valid_output = serde_json::to_value(&valid.output).unwrap();
    assert!(
        schema_validator.is_valid(&valid_output),
        "valid output schema errors: {:?}",
        schema_validator
            .iter_errors(&valid_output)
            .map(|error| error.to_string())
            .collect::<Vec<_>>()
    );

    let invalid_cases: Vec<ProgramCase> =
        serde_json::from_value(fixture_value("invalid-cases.json")).unwrap();
    let rejected = validate(&validator(), &invalid_cases[0].program);
    let rejected_output = serde_json::to_value(&rejected.output).unwrap();
    assert!(
        schema_validator.is_valid(&rejected_output),
        "rejected output schema errors: {:?}",
        schema_validator
            .iter_errors(&rejected_output)
            .map(|error| error.to_string())
            .collect::<Vec<_>>()
    );
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 32,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn arbitrary_metadata_and_prose_do_not_change_semantic_hash(
        metadata in prop::collection::vec(any::<u8>(), 0..64),
        reason in ".{0,64}",
    ) {
        let cases: Vec<ProgramCase> = serde_json::from_value(fixture_value("valid-cases.json")).unwrap();
        let left = cases[0].program.clone();
        let mut right = left.clone();
        right["metadata"] = json!({"generated": metadata});
        right["nodes"][0]["description"] = Value::String(reason.clone());
        right["nodes"][0]["authority_requests"][0]["reason"] = Value::String(reason);
        let validator = validator();
        let left = validate(&validator, &left);
        let right = validate(&validator, &right);
        prop_assert!(left.output.validation.valid);
        prop_assert!(right.output.validation.valid);
        prop_assert_eq!(left.output.validation.semantic_hash, right.output.validation.semantic_hash);
    }

    #[test]
    fn semantic_retry_budget_mutations_change_hash(max_attempts in 2_u64..=3) {
        let envelope: CanonicalEnvelope = serde_json::from_value(fixture_value("canonicalization-cases.json")).unwrap();
        let retry = envelope.cases.into_iter().find(|case| case.name == "retry-budget-is-semantic").unwrap();
        let mut changed = retry.left.clone();
        changed["nodes"][0]["failure"]["max_attempts"] = Value::from(max_attempts);
        let validator = validator();
        let base = validate(&validator, &retry.left);
        let changed = validate(&validator, &changed);
        prop_assert!(base.output.validation.valid);
        prop_assert!(changed.output.validation.valid);
        prop_assert_ne!(base.output.validation.semantic_hash, changed.output.validation.semantic_hash);
    }
}
