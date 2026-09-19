//! Read-only provider declaration checks against immutable semantic contracts.

use crate::version::{FullVersion, SemanticRef, validate_semantic_id};
use crate::{SemanticRegistry, effect_for_authority_class};
use aios_contracts::{
    CapabilityManifest, EffectClass, EgressMode, NetworkDefault, ProviderCapability,
    ProviderReasonCode, SCHEMA_VERSION_V0_1,
};
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderConformanceOptions {
    /// Permit a missing contract hash only for checked-in pre-canonicalizer fixtures.
    pub allow_bootstrap_missing_contract_hash: bool,
    pub max_diagnostics: usize,
}

impl Default for ProviderConformanceOptions {
    fn default() -> Self {
        Self {
            allow_bootstrap_missing_contract_hash: false,
            max_diagnostics: 64,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderConformanceDiagnostic {
    pub code: ProviderReasonCode,
    pub message: String,
    pub provider_id: String,
    pub capability: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderConformanceReport {
    /// Whether the manifest's declarations fit the selected semantic contract.
    /// This is not provider eligibility, package trust, or executed test evidence.
    pub valid: bool,
    pub diagnostics: Vec<ProviderConformanceDiagnostic>,
    pub diagnostics_truncated: bool,
    /// True when a missing fixture-only contract hash was accepted. Such a
    /// report is not production conformance evidence even when `valid` is true.
    pub bootstrap_contract_hash_bypass_used: bool,
}

impl ProviderConformanceReport {
    pub fn contains(&self, code: ProviderReasonCode) -> bool {
        self.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == code)
    }
}

/// Perform a read-only static compatibility check over provider declarations.
///
/// This function never loads or executes provider code. It does not authenticate
/// build identity, run a conformance suite, establish evidence freshness, or
/// apply deployment isolation/trust policy; those require provider-registration
/// evidence and runtime policy that are deliberately outside Issue #17. A
/// registry loaded in bootstrap hash-generation mode is rejected because it is
/// not production trust evidence.
pub fn validate_provider_manifest(
    registry: &SemanticRegistry,
    manifest: &CapabilityManifest,
    options: ProviderConformanceOptions,
) -> ProviderConformanceReport {
    let mut collector = DiagnosticCollector::new(&manifest.id, options.max_diagnostics);
    if !registry.is_strictly_verified() {
        collector.push(
            ProviderReasonCode::ProviderDeclarationInvalid,
            "provider conformance requires a strictly hash-verified registry",
            None,
        );
    }
    if manifest.schema_version != SCHEMA_VERSION_V0_1
        || validate_provider_id(&manifest.id).is_err()
        || manifest.version.is_empty()
        || manifest.publisher.id.is_empty()
        || manifest.provides.is_empty()
    {
        collector.push(
            ProviderReasonCode::ProviderDeclarationInvalid,
            "provider manifest has an unsupported schema version, invalid identity, or no capability declarations",
            None,
        );
    }

    let mut claims = BTreeSet::new();
    for provider_capability in &manifest.provides {
        let claim_key = (
            provider_capability.contract.capability.clone(),
            provider_capability.contract.version.clone(),
        );
        if !claims.insert(claim_key) {
            collector.push(
                ProviderReasonCode::ProviderDeclarationInvalid,
                "provider repeats the same semantic contract claim",
                Some(provider_capability.contract.capability.clone()),
            );
            continue;
        }
        validate_provider_capability(registry, provider_capability, options, &mut collector);
    }

    collector.finish()
}

#[allow(clippy::too_many_lines)]
fn validate_provider_capability(
    registry: &SemanticRegistry,
    provider: &ProviderCapability,
    options: ProviderConformanceOptions,
    collector: &mut DiagnosticCollector,
) {
    let capability = provider.contract.capability.clone();
    if provider.effect_classes.is_empty()
        || provider.execution.locality.is_empty()
        || has_duplicates(&provider.execution.locality)
        || provider.conformance.suite.is_empty()
        || provider
            .resource_requirements
            .as_ref()
            .is_some_and(|requirements| {
                requirements.min_memory_bytes == Some(0)
                    || has_duplicates(&requirements.preferred_accelerators)
            })
        || provider.authority.as_ref().is_some_and(|authority| {
            has_duplicates(&authority.actions) || has_duplicates(&authority.resource_classes)
        })
    {
        collector.push(
            ProviderReasonCode::ProviderDeclarationInvalid,
            "provider capability declaration violates required nonempty or uniqueness constraints",
            Some(capability.clone()),
        );
    }
    let version = match FullVersion::parse(&provider.contract.version) {
        Ok(version) if validate_semantic_id(&capability).is_ok() => version,
        _ => {
            collector.push(
                ProviderReasonCode::ProviderDeclarationInvalid,
                "provider semantic contract claim has an invalid ID or full version",
                Some(capability),
            );
            return;
        }
    };
    let Some(contract) = registry.capability_contract(&capability, version.major) else {
        collector.push(
            ProviderReasonCode::ProviderContractNotFound,
            format!(
                "semantic contract {}@{} is absent from the selected snapshot",
                capability, version.major
            ),
            Some(capability),
        );
        return;
    };
    if contract.version != provider.contract.version {
        collector.push(
            ProviderReasonCode::ProviderContractNotFound,
            format!(
                "provider claims {} {}, but the snapshot selects {}",
                capability, provider.contract.version, contract.version
            ),
            Some(capability.clone()),
        );
        return;
    }

    let Some(expected_hash) = registry.capability_contract_hash(&capability, version.major) else {
        collector.push(
            ProviderReasonCode::ProviderContractNotFound,
            "resolved semantic contract has no immutable content identity",
            Some(capability),
        );
        return;
    };
    let expected_hash = expected_hash.as_str();
    match provider.contract.contract_hash.as_deref() {
        Some(declared) if declared == expected_hash => {}
        None if options.allow_bootstrap_missing_contract_hash => {
            collector.mark_bootstrap_contract_hash_bypass();
        }
        declared => collector.push(
            ProviderReasonCode::ProviderContractHashMismatch,
            format!("provider contract hash {declared:?} does not match {expected_hash}"),
            Some(capability.clone()),
        ),
    }

    if !contract
        .allowed_execution_classes
        .contains(&provider.execution.execution_class)
    {
        collector.push(
            ProviderReasonCode::ProviderExecutionClassIncompatible,
            "provider execution class is outside the semantic contract envelope",
            Some(capability.clone()),
        );
    }

    let authority_actions = provider
        .authority
        .as_ref()
        .map_or(&[][..], |authority| authority.actions.as_slice());
    if has_duplicates(authority_actions)
        || authority_actions
            .iter()
            .any(|action| !contract.allowed_authority_classes.contains(action))
    {
        collector.push(
            ProviderReasonCode::ProviderAuthorityNotAllowed,
            "provider authority exceeds or ambiguously repeats the semantic contract envelope",
            Some(capability.clone()),
        );
    }
    if contract
        .required_authority_classes
        .iter()
        .any(|required| !authority_actions.contains(required))
    {
        collector.push(
            ProviderReasonCode::ProviderRequiredAuthorityMissing,
            "provider declaration omits authority required by the semantic contract",
            Some(capability.clone()),
        );
    }
    if authority_actions.iter().any(|action| {
        effect_for_authority_class(action)
            .is_none_or(|effect| !provider.effect_classes.contains(&effect))
    }) {
        collector.push(
            ProviderReasonCode::ProviderRequiredEffectMissing,
            "provider authority declaration is not reflected in its effect envelope",
            Some(capability.clone()),
        );
    }

    if has_duplicates(&provider.effect_classes)
        || provider
            .effect_classes
            .iter()
            .any(|effect| !contract.allowed_effect_classes.contains(effect))
        || (provider.effect_classes.contains(&EffectClass::Pure)
            && provider
                .effect_classes
                .iter()
                .any(|effect| *effect != EffectClass::Pure))
    {
        collector.push(
            ProviderReasonCode::ProviderEffectNotAllowed,
            "provider effects exceed or contradict the semantic contract envelope",
            Some(capability.clone()),
        );
    }
    if contract
        .required_effect_classes
        .iter()
        .any(|required| !provider.effect_classes.contains(required))
    {
        collector.push(
            ProviderReasonCode::ProviderRequiredEffectMissing,
            "provider declaration omits an effect required by the semantic contract",
            Some(capability.clone()),
        );
    }

    if matches!(
        provider.execution.network_default,
        Some(NetworkDefault::Allowlist | NetworkDefault::Internet)
    ) {
        if !provider.effect_classes.contains(&EffectClass::Network) {
            collector.push(
                ProviderReasonCode::ProviderRequiredEffectMissing,
                "provider network default requires the NETWORK effect declaration",
                Some(capability.clone()),
            );
        }
        if !authority_actions
            .iter()
            .any(|action| action == "network.connect")
        {
            collector.push(
                ProviderReasonCode::ProviderRequiredAuthorityMissing,
                "provider network default requires network.connect authority",
                Some(capability.clone()),
            );
        }
    }

    let declares_data_egress_effect = provider.effect_classes.contains(&EffectClass::DataEgress);
    let declares_data_egress_authority = authority_actions
        .iter()
        .any(|action| action == "data.egress");
    if declares_data_egress_effect && !declares_data_egress_authority {
        collector.push(
            ProviderReasonCode::ProviderRequiredAuthorityMissing,
            "provider DATA_EGRESS effect requires data.egress authority",
            Some(capability.clone()),
        );
    }
    let provider_egress = if declares_data_egress_effect || declares_data_egress_authority {
        EgressMode::Policy
    } else {
        EgressMode::Deny
    };
    if !contract.allowed_egress_modes.contains(&provider_egress) {
        collector.push(
            ProviderReasonCode::ProviderEgressNotAllowed,
            "provider data-egress declaration is not permitted by the semantic contract",
            Some(capability.clone()),
        );
    }

    if provider.conformance.suite != contract.conformance.suite_id
        || provider.conformance.suite_hash != contract.conformance.suite_hash
    {
        collector.push(
            ProviderReasonCode::ProviderSuiteMismatch,
            "provider conformance suite identity/hash does not match the semantic contract",
            Some(capability.clone()),
        );
    }

    for (port_name, representations) in &provider.representations {
        let port = contract
            .inputs
            .get(port_name)
            .or_else(|| contract.outputs.get(port_name));
        let Some(port) = port else {
            collector.push(
                ProviderReasonCode::ProviderPortOrTypeMismatch,
                format!("provider declares representations for unknown port {port_name:?}"),
                Some(capability.clone()),
            );
            continue;
        };
        let Ok(type_reference) = SemanticRef::parse(&port.type_ref) else {
            collector.push(
                ProviderReasonCode::ProviderPortOrTypeMismatch,
                format!("semantic port {port_name:?} has an invalid type reference"),
                Some(capability.clone()),
            );
            continue;
        };
        let Some(type_contract) = registry.type_contract(&type_reference.id, type_reference.major)
        else {
            collector.push(
                ProviderReasonCode::ProviderPortOrTypeMismatch,
                format!("semantic port {port_name:?} type is absent from the snapshot"),
                Some(capability.clone()),
            );
            continue;
        };
        if has_duplicates(representations)
            || representations.iter().any(|representation| {
                !type_contract
                    .representations
                    .iter()
                    .any(|allowed| allowed.id == *representation)
            })
        {
            collector.push(
                ProviderReasonCode::ProviderPortOrTypeMismatch,
                format!(
                    "provider representations for port {port_name:?} are incompatible with {}",
                    port.type_ref
                ),
                Some(capability.clone()),
            );
        }
    }
}

fn validate_provider_id(id: &str) -> Result<(), ()> {
    if id.len() < 3 {
        return Err(());
    }
    let mut bytes = id.bytes();
    if !bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
        })
    {
        return Err(());
    }
    Ok(())
}

fn has_duplicates<T: Ord>(values: &[T]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() != values.len()
}

struct DiagnosticCollector {
    provider_id: String,
    maximum: usize,
    diagnostics: Vec<ProviderConformanceDiagnostic>,
    truncated: bool,
    invalid: bool,
    bootstrap_contract_hash_bypass_used: bool,
}

impl DiagnosticCollector {
    fn new(provider_id: &str, maximum: usize) -> Self {
        Self {
            provider_id: provider_id.to_owned(),
            maximum,
            diagnostics: Vec::new(),
            truncated: false,
            invalid: false,
            bootstrap_contract_hash_bypass_used: false,
        }
    }

    fn mark_bootstrap_contract_hash_bypass(&mut self) {
        self.bootstrap_contract_hash_bypass_used = true;
    }

    fn push(
        &mut self,
        code: ProviderReasonCode,
        message: impl Into<String>,
        capability: Option<String>,
    ) {
        self.invalid = true;
        if self.diagnostics.len() >= self.maximum {
            self.truncated = true;
            return;
        }
        self.diagnostics.push(ProviderConformanceDiagnostic {
            code,
            message: message.into(),
            provider_id: self.provider_id.clone(),
            capability,
        });
    }

    fn finish(self) -> ProviderConformanceReport {
        ProviderConformanceReport {
            valid: !self.invalid,
            diagnostics: self.diagnostics,
            diagnostics_truncated: self.truncated,
            bootstrap_contract_hash_bypass_used: self.bootstrap_contract_hash_bypass_used,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        RegistryBuildOptions, RegistryLoadOptions, SnapshotHashEntry, StrictJsonLimits,
        capability_contract_hash, parse_strict_json, registry_snapshot_id,
    };
    use aios_contracts::{CapabilityContract, ExecutionClass, RegistrySnapshot, TypeContract};
    use serde::Deserialize;
    use std::path::{Path, PathBuf};

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ProviderCase {
        #[serde(rename = "name")]
        _name: String,
        expected: String,
        reason_code: Option<ProviderReasonCode>,
        provider: CapabilityManifest,
    }

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

    fn provider_cases() -> Vec<ProviderCase> {
        let bytes = std::fs::read(fixture_root().join("provider-conformance-cases.json")).unwrap();
        parse_strict_json(&bytes, StrictJsonLimits::default()).unwrap()
    }

    fn network_only_deny_registry() -> SemanticRegistry {
        let (mut snapshot, types, mut capabilities) = fixture_records();
        let contract = capabilities
            .iter_mut()
            .find(|contract| contract.capability == "report.summarize")
            .unwrap();
        contract.allowed_effect_classes = vec![EffectClass::Network];
        contract.allowed_authority_classes = vec!["network.connect".to_owned()];
        contract.allowed_egress_modes = vec![EgressMode::Deny];

        let contract_hash = capability_contract_hash(contract).unwrap().to_string();
        snapshot
            .capability_contracts
            .iter_mut()
            .find(|entry| entry.id == contract.capability)
            .unwrap()
            .content_hash = contract_hash;

        let type_entries = snapshot
            .type_contracts
            .iter()
            .map(|entry| SnapshotHashEntry {
                id: entry.id.clone(),
                version: entry.version.clone(),
                content_hash: entry.content_hash.clone(),
            })
            .collect::<Vec<_>>();
        let capability_entries = snapshot
            .capability_contracts
            .iter()
            .map(|entry| SnapshotHashEntry {
                id: entry.id.clone(),
                version: entry.version.clone(),
                content_hash: entry.content_hash.clone(),
            })
            .collect::<Vec<_>>();
        snapshot.snapshot_id =
            registry_snapshot_id(&snapshot.schema_version, &type_entries, &capability_entries)
                .unwrap()
                .to_string();

        SemanticRegistry::from_records(
            snapshot,
            types,
            capabilities,
            RegistryBuildOptions::default(),
        )
        .unwrap()
    }

    fn network_summarizer(registry: &SemanticRegistry) -> CapabilityManifest {
        let mut manifest = provider_cases().remove(0).provider;
        let provider = &mut manifest.provides[0];
        provider.contract.capability = "report.summarize".to_owned();
        provider.contract.version = "1.0".to_owned();
        provider.contract.contract_hash = Some(
            registry
                .capability_contract_hash("report.summarize", 1)
                .unwrap()
                .to_string(),
        );
        provider.conformance.suite = "conformance://report.summarize/1".to_owned();
        provider.conformance.suite_hash = None;
        provider.effect_classes = vec![EffectClass::Network];
        provider.execution.execution_class = ExecutionClass::BoundedNondeterministic;
        provider.execution.network_default = Some(NetworkDefault::Allowlist);
        let authority = provider.authority.as_mut().unwrap();
        authority.actions = vec!["network.connect".to_owned()];
        authority.resource_classes = vec!["network".to_owned()];
        manifest
    }

    #[test]
    fn repository_provider_cases_match_expected_codes() {
        let registry =
            SemanticRegistry::load_bundle(fixture_root(), RegistryLoadOptions::default()).unwrap();
        for case in provider_cases() {
            let report = validate_provider_manifest(
                &registry,
                &case.provider,
                ProviderConformanceOptions::default(),
            );
            assert_eq!(report.valid, case.expected == "valid");
            assert!(!report.bootstrap_contract_hash_bypass_used);
            if let Some(reason_code) = case.reason_code {
                assert!(
                    report.contains(reason_code),
                    "expected {} in {:?}",
                    reason_code,
                    report.diagnostics
                );
            }
            if case.expected != "valid" {
                let bounded = validate_provider_manifest(
                    &registry,
                    &case.provider,
                    ProviderConformanceOptions {
                        max_diagnostics: 0,
                        ..ProviderConformanceOptions::default()
                    },
                );
                assert!(!bounded.valid);
                assert!(bounded.diagnostics.is_empty());
                assert!(bounded.diagnostics_truncated);
                assert!(!bounded.bootstrap_contract_hash_bypass_used);
            }
        }
    }

    #[test]
    fn network_default_does_not_infer_data_egress() {
        let registry = network_only_deny_registry();
        let manifest = network_summarizer(&registry);
        let report =
            validate_provider_manifest(&registry, &manifest, ProviderConformanceOptions::default());
        assert!(
            report.valid,
            "unexpected diagnostics: {:?}",
            report.diagnostics
        );
        assert!(!report.contains(ProviderReasonCode::ProviderEgressNotAllowed));
    }

    #[test]
    fn data_egress_effect_requires_matching_authority() {
        let registry =
            SemanticRegistry::load_bundle(fixture_root(), RegistryLoadOptions::default()).unwrap();
        let mut manifest = network_summarizer(&registry);
        manifest.provides[0]
            .effect_classes
            .push(EffectClass::DataEgress);

        let report =
            validate_provider_manifest(&registry, &manifest, ProviderConformanceOptions::default());
        assert!(!report.valid);
        assert!(report.contains(ProviderReasonCode::ProviderRequiredAuthorityMissing));
        assert!(!report.contains(ProviderReasonCode::ProviderEgressNotAllowed));
    }

    #[test]
    fn data_egress_authority_requires_matching_effect() {
        let registry =
            SemanticRegistry::load_bundle(fixture_root(), RegistryLoadOptions::default()).unwrap();
        let mut manifest = network_summarizer(&registry);
        manifest.provides[0]
            .authority
            .as_mut()
            .unwrap()
            .actions
            .push("data.egress".to_owned());

        let report =
            validate_provider_manifest(&registry, &manifest, ProviderConformanceOptions::default());
        assert!(!report.valid);
        assert!(report.contains(ProviderReasonCode::ProviderRequiredEffectMissing));
        assert!(!report.contains(ProviderReasonCode::ProviderEgressNotAllowed));
    }

    #[test]
    fn explicit_data_egress_does_not_require_network_default() {
        let registry =
            SemanticRegistry::load_bundle(fixture_root(), RegistryLoadOptions::default()).unwrap();
        let mut manifest = network_summarizer(&registry);
        let provider = &mut manifest.provides[0];
        provider.effect_classes = vec![EffectClass::DataEgress];
        provider.execution.network_default = Some(NetworkDefault::None);
        provider.authority.as_mut().unwrap().actions = vec!["data.egress".to_owned()];

        let report =
            validate_provider_manifest(&registry, &manifest, ProviderConformanceOptions::default());
        assert!(
            report.valid,
            "unexpected diagnostics: {:?}",
            report.diagnostics
        );
    }

    #[test]
    fn distinct_providers_can_conform_to_the_same_semantic_contract_identity() {
        let registry =
            SemanticRegistry::load_bundle(fixture_root(), RegistryLoadOptions::default()).unwrap();
        let first = provider_cases().remove(0).provider;
        let mut second = first.clone();
        second.id = "org.ainative.fixture.alternate-artifact-hash".to_owned();
        second.version = "9.4.1".to_owned();
        second.runtime.entrypoint = Some("alternate-fixture-artifact-hash".to_owned());

        for manifest in [&first, &second] {
            let report = validate_provider_manifest(
                &registry,
                manifest,
                ProviderConformanceOptions::default(),
            );
            assert!(
                report.valid,
                "unexpected diagnostics: {:?}",
                report.diagnostics
            );
        }
        assert_eq!(
            first.provides[0].contract.contract_hash,
            second.provides[0].contract.contract_hash
        );
    }

    #[test]
    fn bootstrap_registry_cannot_produce_valid_provider_conformance() {
        let (snapshot, types, capabilities) = fixture_records();
        let registry = SemanticRegistry::from_records(
            snapshot,
            types,
            capabilities,
            RegistryBuildOptions {
                hash_verification: crate::HashVerificationMode::BootstrapGenerate,
                ..RegistryBuildOptions::default()
            },
        )
        .unwrap();
        assert!(!registry.is_strictly_verified());

        let manifest = provider_cases().remove(0).provider;
        let report =
            validate_provider_manifest(&registry, &manifest, ProviderConformanceOptions::default());

        assert!(!report.valid);
        assert!(report.contains(ProviderReasonCode::ProviderDeclarationInvalid));
        assert!(!report.bootstrap_contract_hash_bypass_used);
    }

    #[test]
    fn provider_port_representation_and_required_lower_bounds_fail_closed() {
        let registry =
            SemanticRegistry::load_bundle(fixture_root(), RegistryLoadOptions::default()).unwrap();
        let baseline = provider_cases().remove(0).provider;

        let mut bad_representation = baseline.clone();
        bad_representation.provides[0]
            .representations
            .insert("source".to_owned(), vec!["not-a-representation".to_owned()]);
        let report = validate_provider_manifest(
            &registry,
            &bad_representation,
            ProviderConformanceOptions::default(),
        );
        assert!(!report.valid);
        assert!(report.contains(ProviderReasonCode::ProviderPortOrTypeMismatch));

        let mut missing_effect = baseline.clone();
        missing_effect.provides[0].effect_classes = vec![EffectClass::Pure];
        let report = validate_provider_manifest(
            &registry,
            &missing_effect,
            ProviderConformanceOptions::default(),
        );
        assert!(!report.valid);
        assert!(report.contains(ProviderReasonCode::ProviderRequiredEffectMissing));

        let mut missing_authority = baseline;
        missing_authority.provides[0]
            .authority
            .as_mut()
            .unwrap()
            .actions
            .clear();
        let report = validate_provider_manifest(
            &registry,
            &missing_authority,
            ProviderConformanceOptions::default(),
        );
        assert!(!report.valid);
        assert!(report.contains(ProviderReasonCode::ProviderRequiredAuthorityMissing));
    }
}
