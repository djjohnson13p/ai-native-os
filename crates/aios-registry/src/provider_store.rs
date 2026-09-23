//! Durable provider declarations and exact, immutable conformance evidence.
//!
//! This control-plane catalog only reports eligible candidates. It does not
//! execute provider code, choose a provider for a Task, or grant authority.
//! The immutable `registration_json` is the admission receipt; current lifecycle
//! state and trust are the separate `provider_registrations` columns.

#![allow(clippy::missing_errors_doc)]

use std::collections::BTreeSet;
use std::fmt::Write;
use std::sync::OnceLock;
use std::time::Duration;

use aios_contracts::{CapabilityContract, CapabilityManifest, RegistrySnapshot, TypeContract};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::store::{StoreOwner, WriteFence};
use crate::{
    ProviderConformanceOptions, SemanticRegistry, StrictJsonLimits, canonicalize, is_sha256_id,
    parse_strict_value, validate_provider_manifest,
};

const MIGRATION_ID: &str = "0013_provider_registry";
const MIGRATION_CHECKSUM: &str = "provider-registry-v0.1";
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_EVIDENCE_BYTES: usize = 256 * 1024;
static MANIFEST_SCHEMA: OnceLock<std::result::Result<jsonschema::Validator, String>> =
    OnceLock::new();
static REGISTRATION_SCHEMA: OnceLock<std::result::Result<jsonschema::Validator, String>> =
    OnceLock::new();
static EVIDENCE_SCHEMA: OnceLock<std::result::Result<jsonschema::Validator, String>> =
    OnceLock::new();

#[derive(Debug)]
pub enum ProviderStoreError {
    Database(rusqlite::Error),
    Json(String),
    Invalid(&'static str),
    StaticCompatibility(crate::ProviderConformanceReport),
    NotFound,
    Conflict(&'static str),
}

impl std::fmt::Display for ProviderStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(error) => write!(f, "provider registry database error: {error}"),
            Self::Json(error) => write!(f, "provider registry JSON error: {error}"),
            Self::Invalid(message) => write!(f, "invalid provider registry input: {message}"),
            Self::StaticCompatibility(_) => {
                f.write_str("provider manifest is incompatible with the semantic snapshot")
            }
            Self::NotFound => f.write_str("provider registration not found"),
            Self::Conflict(message) => write!(f, "provider registry conflict: {message}"),
        }
    }
}
impl std::error::Error for ProviderStoreError {}
impl From<rusqlite::Error> for ProviderStoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}
type Result<T> = std::result::Result<T, ProviderStoreError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderTrustStatus {
    Unverified,
    LocallyTrusted,
    ProjectReviewed,
    OrganizationApproved,
    Denied,
    Revoked,
}
impl ProviderTrustStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Unverified => "unverified",
            Self::LocallyTrusted => "locally-trusted",
            Self::ProjectReviewed => "project-reviewed",
            Self::OrganizationApproved => "organization-approved",
            Self::Denied => "denied",
            Self::Revoked => "revoked",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "unverified" => Ok(Self::Unverified),
            "locally-trusted" => Ok(Self::LocallyTrusted),
            "project-reviewed" => Ok(Self::ProjectReviewed),
            "organization-approved" => Ok(Self::OrganizationApproved),
            "denied" => Ok(Self::Denied),
            "revoked" => Ok(Self::Revoked),
            _ => Err(ProviderStoreError::Conflict(
                "stored provider trust is invalid",
            )),
        }
    }

    fn permits_execution(self) -> bool {
        matches!(
            self,
            Self::LocallyTrusted | Self::ProjectReviewed | Self::OrganizationApproved
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRegistration {
    pub registration_id: String,
    pub provider_id: String,
    pub provider_version: String,
    pub manifest_hash: String,
    pub build_hash: String,
    pub snapshot_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderCandidate {
    pub registration: ProviderRegistration,
    pub requested_snapshot_id: String,
    pub semantic_capability_ref: String,
    pub contract_hash: String,
    pub suite_id: String,
    pub suite_hash: String,
    pub evidence_id: String,
}

#[derive(Debug, PartialEq, Eq)]
struct EvidenceProjection {
    registration_id: String,
    capability: String,
    contract_hash: Option<String>,
    suite_id: Option<String>,
    suite_hash: Option<String>,
    status: String,
    evidence_json: String,
    tested_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderHealth {
    pub status: String,
    pub checked_at: String,
    pub reason: Option<String>,
}

pub struct ProviderStore<'a> {
    connection: &'a mut Connection,
    write_fence: Option<WriteFence<'a>>,
}

impl<'a> ProviderStore<'a> {
    /// Opens a fully migrated provider registry. Task Manager installs or
    /// upgrades the schema under its store lock and durable ownership fence.
    pub fn initialize(connection: &'a mut Connection) -> Result<Self> {
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.busy_timeout(Duration::from_secs(5))?;
        let baseline: Option<String> = connection.query_row(
            "SELECT checksum FROM schema_migrations WHERE migration_id='0001_v0_1_trusted_control_plane'",
            [], |row| row.get(0),
        ).optional()?;
        if baseline.as_deref() != Some("UNGENERATED-DRAFT-CHECKSUM") {
            return Err(ProviderStoreError::Conflict(
                "trusted control-plane baseline is required",
            ));
        }
        preflight_migrations(connection)?;
        // The provider migration is layered on a complete, stamped semantic
        // registry. Both migrations must already be fenced and committed.
        crate::RegistryStore::initialize(connection).map_err(|_| {
            ProviderStoreError::Conflict("semantic registry migration is incomplete")
        })?;
        Ok(Self {
            connection,
            write_fence: None,
        })
    }

    /// Opens a provider writer using Task Manager's captured ownership lease.
    /// File-backed stores also require the identity-bound owner lock.
    pub fn initialize_writer(
        connection: &'a mut Connection,
        owner: &'a StoreOwner,
    ) -> Result<Self> {
        let mut store = Self::initialize(connection)?;
        store.write_fence = Some(
            WriteFence::new(store.connection, owner)
                .map_err(|_| ProviderStoreError::Conflict("invalid provider write fence"))?,
        );
        Ok(store)
    }

    /// Allows a standalone ephemeral in-memory registry without a Task Manager
    /// lease. A manager-owned in-memory store must use `initialize_writer`.
    pub fn initialize_in_memory(connection: &'a mut Connection) -> Result<Self> {
        let mut store = Self::initialize(connection)?;
        store.write_fence = Some(WriteFence::in_memory(store.connection).map_err(|_| {
            ProviderStoreError::Conflict("provider in-memory writer requires an unowned store")
        })?);
        Ok(store)
    }

    #[cfg(test)]
    pub(crate) fn initialize_unfenced_fixture(connection: &'a mut Connection) -> Result<Self> {
        let mut store = Self::initialize(connection)?;
        store.write_fence = Some(WriteFence::fixture());
        Ok(store)
    }

    /// Register one exact build against one already admitted, strictly verified snapshot.
    /// Registration starts disabled until exact passing suite evidence is recorded.
    #[allow(clippy::too_many_lines)]
    pub fn register(
        &mut self,
        registry: &SemanticRegistry,
        raw_manifest: &[u8],
        build_hash: &str,
        trust: ProviderTrustStatus,
        registered_at: &str,
    ) -> Result<ProviderRegistration> {
        if !registry.is_strictly_verified() {
            return Err(ProviderStoreError::Invalid(
                "semantic snapshot is not strictly verified",
            ));
        }
        if !is_sha256_id(build_hash) {
            return Err(ProviderStoreError::Invalid(
                "build identity must be a sha256 digest",
            ));
        }
        parse_time(registered_at)?;
        let (value, manifest) = parse_manifest(raw_manifest)?;
        let report =
            validate_provider_manifest(registry, &manifest, ProviderConformanceOptions::default());
        if !report.valid || report.bootstrap_contract_hash_bypass_used {
            return Err(ProviderStoreError::StaticCompatibility(report));
        }
        // A static declaration can match a contract whose optional suite
        // identity is incomplete. Such a claim can never produce schema-valid,
        // exact conformance evidence, so do not admit the build.
        for claim in &manifest.provides {
            let major = crate::FullVersion::parse(&claim.contract.version)
                .map_err(|_| ProviderStoreError::Invalid("provider contract version is invalid"))?
                .major;
            let contract = registry
                .capability_contract(&claim.contract.capability, major)
                .ok_or(ProviderStoreError::Invalid("provider contract is absent"))?;
            if contract
                .conformance
                .suite_version
                .as_deref()
                .is_none_or(str::is_empty)
                || contract
                    .conformance
                    .suite_hash
                    .as_deref()
                    .is_none_or(|hash| !is_sha256_id(hash))
                || claim.conformance.suite_hash != contract.conformance.suite_hash
            {
                return Err(ProviderStoreError::Invalid(
                    "complete suite version and hash are required for registration",
                ));
            }
        }
        let manifest_json = canonical_text(&value)?;
        let manifest_hash = digest(b"AIOS-PROVIDER-MANIFEST\0v0.1\0", manifest_json.as_bytes());
        let snapshot_id = registry.snapshot_id().to_owned();
        let registration_id = digest(
            b"AIOS-PROVIDER-REGISTRATION\0v0.1\0",
            format!(
                "{}\0{}\0{}\0{}",
                manifest.id, manifest.version, manifest_hash, build_hash
            )
            .as_bytes(),
        );
        let registration = ProviderRegistration {
            registration_id,
            provider_id: manifest.id.clone(),
            provider_version: manifest.version.clone(),
            manifest_hash,
            build_hash: build_hash.to_owned(),
            snapshot_id,
        };
        let registration_json = registration_record(&registration, &manifest, trust, registered_at);
        let registration_json = canonical_text(&registration_json)?;
        let fence = self
            .write_fence
            .as_ref()
            .ok_or(ProviderStoreError::Conflict(
                "provider mutation requires Task Manager write authority",
            ))?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        fence.verify(&transaction).map_err(|_| {
            ProviderStoreError::Conflict("provider write rejected by stale ownership fence")
        })?;
        // Admission and identity insertion must share the write lock. Otherwise
        // a concurrent containment can commit after this check but before the
        // provider's immutable origin snapshot is recorded.
        let admitted: Option<String> = transaction
            .query_row(
                "SELECT state FROM registry_snapshot_admissions WHERE snapshot_id=?1",
                [&registration.snapshot_id],
                |row| row.get(0),
            )
            .optional()?;
        if admitted.as_deref() != Some("ADMITTED") {
            return Err(ProviderStoreError::Invalid(
                "semantic snapshot has not been admitted",
            ));
        }
        let existing: Option<ProviderRegistration> = transaction.query_row(
            "SELECT registration_id,provider_id,provider_version,manifest_hash,package_content_hash,registry_snapshot_id
             FROM provider_registrations WHERE provider_id=?1 AND provider_version=?2 AND package_content_hash=?3",
            params![registration.provider_id,registration.provider_version,registration.build_hash],
            |row| Ok(ProviderRegistration {
                registration_id: row.get(0)?,provider_id: row.get(1)?,provider_version: row.get(2)?,
                manifest_hash: row.get(3)?,build_hash: row.get(4)?,snapshot_id: row.get(5)?,
            }),
        ).optional()?;
        if existing.is_none() {
            transaction.execute(
                "INSERT INTO provider_registrations
                 (registration_id,provider_id,provider_version,manifest_hash,package_content_hash,
                  registry_snapshot_id,state,trust_status,registration_json,registered_at)
                 VALUES (?1,?2,?3,?4,?5,?6,'disabled',?7,?8,?9)",
                params![
                    registration.registration_id,
                    registration.provider_id,
                    registration.provider_version,
                    registration.manifest_hash,
                    registration.build_hash,
                    registration.snapshot_id,
                    trust.as_str(),
                    registration_json,
                    registered_at
                ],
            )?;
        }
        let was_existing = existing.is_some();
        let stored = existing.unwrap_or_else(|| registration.clone());
        if stored.registration_id != registration.registration_id
            || stored.manifest_hash != registration.manifest_hash
        {
            return Err(ProviderStoreError::Conflict(
                "provider version and build already map to a different manifest",
            ));
        }
        let stored_manifest: Option<String> = transaction
            .query_row(
                "SELECT manifest_json FROM provider_manifest_payloads WHERE registration_id=?1",
                [&stored.registration_id],
                |row| row.get(0),
            )
            .optional()?;
        if stored_manifest
            .as_deref()
            .is_some_and(|payload| payload != manifest_json)
        {
            return Err(ProviderStoreError::Conflict(
                "registration manifest payload differs",
            ));
        }
        if stored_manifest.is_none() {
            transaction.execute(
                "INSERT INTO provider_manifest_payloads(registration_id,manifest_json) VALUES (?1,?2)",
                params![stored.registration_id,manifest_json],
            )?;
        }
        verify_stored_registration_receipt(&transaction, &stored, &manifest)?;
        if was_existing {
            let initial_trust: String = transaction.query_row(
                "SELECT trust_status FROM provider_registrations WHERE registration_id=?1",
                [&stored.registration_id],
                |row| row.get(0),
            )?;
            if initial_trust != trust.as_str() && trust != ProviderTrustStatus::Unverified {
                return Err(ProviderStoreError::Conflict(
                    "same-build trust change requires an explicit admission decision",
                ));
            }
        }
        fence.verify(&transaction).map_err(|_| {
            ProviderStoreError::Conflict("provider write rejected by stale ownership fence")
        })?;
        transaction.commit()?;
        Ok(stored)
    }

    /// Store independently produced, schema-valid suite evidence for this exact build.
    /// The caller must authenticate the harness/source before calling this trusted
    /// control-plane boundary. This store checks identity and consistency; it
    /// never executes provider code or treats a manifest's declared status as proof.
    pub fn record_evidence(
        &mut self,
        registration_id: &str,
        raw_evidence: &[u8],
    ) -> Result<String> {
        let evidence = parse_document(
            raw_evidence,
            MAX_EVIDENCE_BYTES,
            &EVIDENCE_SCHEMA,
            include_str!("../../../specs/provider-conformance-result.schema.json"),
        )?;
        let id = string_at(&evidence, "/result_id")?.to_owned();
        let registration = self.load_registration(registration_id)?;
        if string_at(&evidence, "/provider_id")? != registration.provider_id
            || string_at(&evidence, "/provider_version")? != registration.provider_version
            || string_at(&evidence, "/provider_build_identity/value")? != registration.build_hash
        {
            return Err(ProviderStoreError::Invalid(
                "evidence does not identify this exact provider build",
            ));
        }
        let semantic_ref = string_at(&evidence, "/semantic_capability_ref")?;
        let contract_hash = string_at(&evidence, "/semantic_contract_hash")?;
        let suite_id = string_at(&evidence, "/conformance_suite/id")?;
        let suite_hash = string_at(&evidence, "/conformance_suite/hash")?;
        let suite_version = string_at(&evidence, "/conformance_suite/version")?;
        let tested_at = string_at(&evidence, "/executed_at")?;
        let tested = parse_time(tested_at)?;
        if let Some(expires) = evidence.pointer("/expires_at").and_then(Value::as_str) {
            if parse_time(expires)? <= tested {
                return Err(ProviderStoreError::Invalid(
                    "evidence expiry must follow execution",
                ));
            }
        }
        let manifest = self.verified_manifest(&registration)?;
        let claim = manifest
            .provides
            .iter()
            .find(|claim| {
                let major = claim.contract.version.split('.').next().unwrap_or("");
                semantic_ref == format!("{}@{major}", claim.contract.capability)
            })
            .ok_or(ProviderStoreError::Invalid(
                "evidence capability is not claimed by the manifest",
            ))?;
        if claim.contract.version != string_at(&evidence, "/semantic_contract_version")?
            || claim.contract.contract_hash.as_deref() != Some(contract_hash)
            || claim.conformance.suite != suite_id
            || claim.conformance.suite_hash.as_deref() != Some(suite_hash)
            || self.contract_suite_version(contract_hash)?.as_deref() != Some(suite_version)
        {
            return Err(ProviderStoreError::Invalid(
                "evidence contract or suite differs from the manifest",
            ));
        }
        let result = string_at(&evidence, "/result")?;
        if result == "pass" {
            let total = evidence.get("tests_total").and_then(Value::as_u64);
            let passed = evidence.get("tests_passed").and_then(Value::as_u64);
            let failed = evidence.get("tests_failed").and_then(Value::as_u64);
            if total.is_none() || total != passed || failed != Some(0) || total == Some(0) {
                return Err(ProviderStoreError::Invalid(
                    "passing evidence needs nonzero, complete test counts",
                ));
            }
        }
        let canonical = canonical_text(&evidence)?;
        let fence = self
            .write_fence
            .as_ref()
            .ok_or(ProviderStoreError::Conflict(
                "provider mutation requires Task Manager write authority",
            ))?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        fence.verify(&transaction).map_err(|_| {
            ProviderStoreError::Conflict("provider write rejected by stale ownership fence")
        })?;
        let expected = EvidenceProjection {
            registration_id: registration_id.to_owned(),
            capability: semantic_ref.to_owned(),
            contract_hash: Some(contract_hash.to_owned()),
            suite_id: Some(suite_id.to_owned()),
            suite_hash: Some(suite_hash.to_owned()),
            status: result.to_owned(),
            evidence_json: canonical.clone(),
            tested_at: Some(tested_at.to_owned()),
        };
        if !existing_evidence_matches(&transaction, &id, &expected)? {
            transaction.execute(
                "INSERT INTO provider_conformance_evidence
                 (evidence_id,registration_id,capability,contract_hash,suite_id,suite_hash,status,evidence_json,tested_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![id,registration_id,semantic_ref,contract_hash,suite_id,suite_hash,result,canonical,tested_at],
            )?;
        }
        fence.verify(&transaction).map_err(|_| {
            ProviderStoreError::Conflict("provider write rejected by stale ownership fence")
        })?;
        transaction.commit()?;
        Ok(id)
    }

    pub fn enable(&mut self, registration_id: &str, now: &str) -> Result<()> {
        self.set_state(registration_id, "registered", now)
    }
    pub fn disable(&mut self, registration_id: &str, now: &str) -> Result<()> {
        self.set_state(registration_id, "disabled", now)
    }
    pub fn revoke(&mut self, registration_id: &str, now: &str) -> Result<()> {
        self.set_state(registration_id, "revoked", now)
    }

    /// Append one authenticated review decision for an unchanged exact build.
    /// The caller authenticates `authority_ref`; the original registration
    /// receipt and its initial trust claim remain immutable.
    pub fn admit_trust(
        &mut self,
        registration_id: &str,
        decision_id: &str,
        trust: ProviderTrustStatus,
        authority_ref: &str,
        admitted_at: &str,
    ) -> Result<String> {
        if !trust.permits_execution()
            || decision_id.is_empty()
            || decision_id.len() > 256
            || authority_ref.is_empty()
            || authority_ref.len() > 256
        {
            return Err(ProviderStoreError::Invalid(
                "invalid provider trust decision",
            ));
        }
        let decision_time = parse_time(admitted_at)?;
        let registration = self.load_registration(registration_id)?;
        let manifest = self.verified_manifest(&registration)?;
        let fence = self
            .write_fence
            .as_ref()
            .ok_or(ProviderStoreError::Conflict(
                "provider mutation requires Task Manager write authority",
            ))?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        fence.verify(&transaction).map_err(|_| {
            ProviderStoreError::Conflict("provider write rejected by stale ownership fence")
        })?;
        let (state, original_trust): (String, String) = transaction.query_row(
            "SELECT state,trust_status FROM provider_registrations WHERE registration_id=?1",
            [registration_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if state == "revoked" || matches!(original_trust.as_str(), "denied" | "revoked") {
            return Err(ProviderStoreError::Conflict(
                "provider admission is terminal",
            ));
        }
        verified_provider_effective_trust(&transaction, &registration, &manifest)?;
        let prior: Option<(String, String, i64)> = transaction
            .query_row(
                "SELECT admission_id,receipt_json,revision FROM provider_trust_admissions
             WHERE registration_id=?1 AND decision_id=?2",
                params![registration_id, decision_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if prior.is_none() {
            let previous_at: String = transaction.query_row(
                "SELECT COALESCE(
                    (SELECT admitted_at FROM provider_trust_admissions
                     WHERE registration_id=?1 ORDER BY revision DESC LIMIT 1),
                    (SELECT registered_at FROM provider_registrations WHERE registration_id=?1))",
                [registration_id],
                |row| row.get(0),
            )?;
            if decision_time < parse_time(&previous_at)? {
                return Err(ProviderStoreError::Conflict(
                    "provider trust admission time cannot move backward",
                ));
            }
        }
        let revision: i64 = transaction.query_row(
            "SELECT COALESCE(MAX(revision),0)+1 FROM provider_trust_admissions WHERE registration_id=?1",
            [registration_id], |row| row.get(0),
        )?;
        let expected_revision = prior
            .as_ref()
            .map_or(revision, |(_, _, revision)| *revision);
        let receipt = trust_admission_receipt(
            registration_id,
            decision_id,
            expected_revision,
            trust,
            authority_ref,
            admitted_at,
        )?;
        let admission_id = digest(b"AIOS-PROVIDER-TRUST-ADMISSION\0v0.1\0", receipt.as_bytes());
        if let Some((prior_id, prior_receipt, _)) = prior {
            if prior_id != admission_id || prior_receipt != receipt {
                return Err(ProviderStoreError::Conflict(
                    "trust decision identity already maps to another receipt",
                ));
            }
        } else {
            transaction.execute(
                "INSERT INTO provider_trust_admissions
                 (admission_id,registration_id,decision_id,revision,trust_status,authority_ref,admitted_at,receipt_json)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![admission_id,registration_id,decision_id,revision,trust.as_str(),authority_ref,admitted_at,receipt],
            )?;
        }
        fence.verify(&transaction).map_err(|_| {
            ProviderStoreError::Conflict("provider write rejected by stale ownership fence")
        })?;
        transaction.commit()?;
        Ok(admission_id)
    }

    fn set_state(&mut self, registration_id: &str, state: &str, now: &str) -> Result<()> {
        let at = parse_time(now)?;
        let registration = self.load_registration(registration_id)?;
        let old: String = self.connection.query_row(
            "SELECT state FROM provider_registrations WHERE registration_id=?1",
            [registration_id],
            |row| row.get(0),
        )?;
        if old == "revoked" && state != "revoked" {
            return Err(ProviderStoreError::Conflict("revocation is terminal"));
        }
        if state == "registered" {
            let manifest = self.verified_manifest(&registration)?;
            let trust = verified_provider_effective_trust_at(
                self.connection,
                &registration,
                &manifest,
                now,
            )?;
            if !trust.permits_execution() {
                return Err(ProviderStoreError::Invalid(
                    "trust status does not permit enablement",
                ));
            }
            if !self.has_live_evidence(&registration, at)? {
                return Err(ProviderStoreError::Invalid(
                    "no exact, current passing evidence for every claim",
                ));
            }
        }
        let fence = self
            .write_fence
            .as_ref()
            .ok_or(ProviderStoreError::Conflict(
                "provider mutation requires Task Manager write authority",
            ))?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        fence.verify(&transaction).map_err(|_| {
            ProviderStoreError::Conflict("provider write rejected by stale ownership fence")
        })?;
        let current_state: String = transaction.query_row(
            "SELECT state FROM provider_registrations WHERE registration_id=?1",
            [registration_id],
            |row| row.get(0),
        )?;
        if current_state != old {
            return Err(ProviderStoreError::Conflict(
                "provider lifecycle changed concurrently",
            ));
        }
        if current_state == state {
            fence.verify(&transaction).map_err(|_| {
                ProviderStoreError::Conflict("provider write rejected by stale ownership fence")
            })?;
            transaction.commit()?;
            return Ok(());
        }
        transaction.execute(
            "UPDATE provider_registrations SET state=?2,updated_at=?3 WHERE registration_id=?1",
            params![registration_id, state, now],
        )?;
        fence.verify(&transaction).map_err(|_| {
            ProviderStoreError::Conflict("provider write rejected by stale ownership fence")
        })?;
        transaction.commit()?;
        Ok(())
    }

    /// Candidate metadata only; the Task binding gate and grants remain authoritative.
    pub fn eligible_candidates(
        &self,
        semantic_capability_ref: &str,
        contract_hash: &str,
        snapshot_id: &str,
        at: &str,
    ) -> Result<Vec<ProviderCandidate>> {
        self.eligible_candidates_after_selection(
            semantic_capability_ref,
            contract_hash,
            snapshot_id,
            at,
            || {},
        )
    }

    fn eligible_candidates_after_selection(
        &self,
        semantic_capability_ref: &str,
        contract_hash: &str,
        snapshot_id: &str,
        at: &str,
        after_selection: impl FnOnce(),
    ) -> Result<Vec<ProviderCandidate>> {
        let checked = parse_time(at)?;
        if !is_sha256_id(contract_hash) || !is_sha256_id(snapshot_id) {
            return Err(ProviderStoreError::Invalid(
                "contract and snapshot IDs must be sha256 digests",
            ));
        }
        let semantic = crate::SemanticRef::parse(semantic_capability_ref)
            .map_err(|_| ProviderStoreError::Invalid("semantic capability reference is invalid"))?;
        let major = i64::try_from(semantic.major)
            .map_err(|_| ProviderStoreError::Invalid("semantic major exceeds SQLite range"))?;
        // A candidate is assembled from admission, registry, registration,
        // trust and evidence rows. Keep all those reads on one SQLite snapshot.
        // SAVEPOINT also works when the caller already owns a transaction.
        self.connection
            .execute_batch("SAVEPOINT aios_provider_candidate_read")?;
        let result = (|| {
            let selected: bool = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM registry_snapshot_entries e
             JOIN registry_snapshot_admissions a ON a.snapshot_id=e.snapshot_id
             WHERE e.snapshot_id=?1 AND a.state='ADMITTED' AND e.contract_class='capability'
               AND e.semantic_id=?2 AND e.major=?3 AND e.content_hash=?4)",
                params![snapshot_id, semantic.id, major, contract_hash],
                |row| row.get(0),
            )?;
            after_selection();
            if !selected {
                return Ok(Vec::new());
            }
            let requested_registry = self.reopen_selected_snapshot(snapshot_id)?;
            let mut statement = self.connection.prepare(
                "SELECT r.registration_id,r.updated_at FROM provider_registrations r
             JOIN provider_manifest_payloads m ON m.registration_id=r.registration_id
             JOIN registry_snapshot_admissions a ON a.snapshot_id=r.registry_snapshot_id
             WHERE r.state='registered' AND a.state IN ('ADMITTED','DEPRECATED')
             ORDER BY r.registration_id",
            )?;
            let ids = statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let mut candidates = Vec::new();
            for (id, enabled_at) in ids {
                let Some(enabled_at) = enabled_at else {
                    continue;
                };
                if !parse_time(&enabled_at).is_ok_and(|enabled| enabled <= checked) {
                    continue;
                }
                let registration = self.load_registration(&id)?;
                let mut manifest = self.verified_manifest(&registration)?;
                if !verified_provider_effective_trust_at(
                    self.connection,
                    &registration,
                    &manifest,
                    at,
                )
                .is_ok_and(ProviderTrustStatus::permits_execution)
                {
                    continue;
                }
                manifest.provides.retain(|claim| {
                    let major = claim.contract.version.split('.').next().unwrap_or("");
                    semantic_capability_ref == format!("{}@{major}", claim.contract.capability)
                        && claim.contract.contract_hash.as_deref() == Some(contract_hash)
                });
                if manifest.provides.len() != 1 {
                    continue;
                }
                let report = validate_provider_manifest(
                    &requested_registry,
                    &manifest,
                    ProviderConformanceOptions::default(),
                );
                if !report.valid || report.bootstrap_contract_hash_bypass_used {
                    continue;
                }
                let matching = self.valid_passes(
                    &registration,
                    semantic_capability_ref,
                    contract_hash,
                    checked,
                )?;
                if let [only] = matching.as_slice() {
                    let (evidence_id, suite_id, suite_hash) = only.clone();
                    candidates.push(ProviderCandidate {
                        registration,
                        requested_snapshot_id: snapshot_id.to_owned(),
                        semantic_capability_ref: semantic_capability_ref.to_owned(),
                        contract_hash: contract_hash.to_owned(),
                        suite_id,
                        suite_hash,
                        evidence_id,
                    });
                }
            }
            Ok(candidates)
        })();
        self.connection
            .execute_batch("RELEASE aios_provider_candidate_read")?;
        result
    }

    /// Ephemeral operational observation, intentionally absent from eligibility.
    pub fn observe_health(&mut self, registration_id: &str, health: &ProviderHealth) -> Result<()> {
        self.load_registration(registration_id)?;
        let checked = parse_time(&health.checked_at)?;
        if !matches!(
            health.status.as_str(),
            "unknown" | "ready" | "degraded" | "unavailable" | "blocked"
        ) || health
            .reason
            .as_ref()
            .is_some_and(|reason| reason.len() > 512)
        {
            return Err(ProviderStoreError::Invalid("invalid health observation"));
        }
        // BEGIN IMMEDIATE holds the SQLite write lock across the read and
        // update. OffsetDateTime compares full nanosecond precision even when
        // callers use different RFC 3339 timezone offsets.
        let fence = self
            .write_fence
            .as_ref()
            .ok_or(ProviderStoreError::Conflict(
                "provider mutation requires Task Manager write authority",
            ))?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        fence.verify(&transaction).map_err(|_| {
            ProviderStoreError::Conflict("provider write rejected by stale ownership fence")
        })?;
        let old: Option<String> = transaction
            .query_row(
                "SELECT checked_at FROM provider_health_observations WHERE registration_id=?1",
                [registration_id],
                |row| row.get(0),
            )
            .optional()?;
        if old
            .as_deref()
            .map(parse_time)
            .transpose()?
            .is_some_and(|time| time > checked)
        {
            return Ok(());
        }
        transaction.execute(
            "INSERT INTO provider_health_observations(registration_id,status,checked_at,reason)
             VALUES (?1,?2,?3,?4) ON CONFLICT(registration_id) DO UPDATE SET
             status=excluded.status,checked_at=excluded.checked_at,reason=excluded.reason",
            params![
                registration_id,
                health.status,
                health.checked_at,
                health.reason
            ],
        )?;
        fence.verify(&transaction).map_err(|_| {
            ProviderStoreError::Conflict("provider write rejected by stale ownership fence")
        })?;
        transaction.commit()?;
        Ok(())
    }
    pub fn health(&self, registration_id: &str) -> Result<Option<ProviderHealth>> {
        self.load_registration(registration_id)?;
        self.connection.query_row(
            "SELECT status,checked_at,reason FROM provider_health_observations WHERE registration_id=?1",
            [registration_id],
            |row| Ok(ProviderHealth { status: row.get(0)?,checked_at: row.get(1)?,reason: row.get(2)? }),
        ).optional().map_err(Into::into)
    }

    /// Rebuild the selected registry from immutable DB records so static provider
    /// checks also see the selected snapshot's referenced type contracts.
    #[allow(clippy::too_many_lines)]
    fn reopen_selected_snapshot(&self, snapshot_id: &str) -> Result<SemanticRegistry> {
        let raw: String = self
            .connection
            .query_row(
                "SELECT s.manifest_json FROM registry_snapshots s
             JOIN registry_snapshot_admissions a USING(snapshot_id)
             WHERE s.snapshot_id=?1 AND a.state='ADMITTED'",
                [snapshot_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(ProviderStoreError::Invalid(
                "selected snapshot is not admitted",
            ))?;
        let snapshot: RegistrySnapshot = crate::schema::decode_with_record_limit(
            raw.as_bytes(),
            StrictJsonLimits::default(),
            crate::schema::RecordKind::Snapshot,
            false,
            None,
        )
        .map_err(|error| ProviderStoreError::Json(error.to_string()))?;
        let mut expected: BTreeSet<(String, String, String, String)> = snapshot
            .type_contracts
            .iter()
            .map(|entry| {
                (
                    "type".to_owned(),
                    entry.id.clone(),
                    entry.version.clone(),
                    entry.content_hash.clone(),
                )
            })
            .chain(snapshot.capability_contracts.iter().map(|entry| {
                (
                    "capability".to_owned(),
                    entry.id.clone(),
                    entry.version.clone(),
                    entry.content_hash.clone(),
                )
            }))
            .collect();
        let mut types = Vec::new();
        let mut capabilities = Vec::new();
        let mut statement = self.connection.prepare(
            "SELECT e.contract_class,e.semantic_id,e.major,e.full_version,e.content_hash,
                    t.contract_json,c.contract_json FROM registry_snapshot_entries e
             LEFT JOIN semantic_type_contracts t ON e.contract_class='type' AND t.content_hash=e.content_hash
             LEFT JOIN semantic_capability_contracts c ON e.contract_class='capability' AND c.content_hash=e.content_hash
             WHERE e.snapshot_id=?1 ORDER BY e.contract_class,e.semantic_id,e.major",
        )?;
        let mut rows = statement.query([snapshot_id])?;
        while let Some(row) = rows.next()? {
            let class: String = row.get(0)?;
            let id: String = row.get(1)?;
            let major: i64 = row.get(2)?;
            let version: String = row.get(3)?;
            let hash: String = row.get(4)?;
            if !expected.remove(&(class.clone(), id.clone(), version.clone(), hash.clone()))
                || crate::FullVersion::parse(&version)
                    .map_err(|error| ProviderStoreError::Json(error.to_string()))?
                    .major
                    != u64::try_from(major)
                        .map_err(|_| ProviderStoreError::Conflict("negative stored major"))?
            {
                return Err(ProviderStoreError::Conflict(
                    "selected snapshot entries do not match manifest",
                ));
            }
            match class.as_str() {
                "type" => {
                    let raw: String =
                        row.get::<_, Option<String>>(5)?
                            .ok_or(ProviderStoreError::Conflict(
                                "selected snapshot is missing type bytes",
                            ))?;
                    let contract: TypeContract = crate::schema::decode_with_record_limit(
                        raw.as_bytes(),
                        StrictJsonLimits::default(),
                        crate::schema::RecordKind::Type,
                        false,
                        None,
                    )
                    .map_err(|error| ProviderStoreError::Json(error.to_string()))?;
                    if contract.type_id != id
                        || contract.version != version
                        || crate::type_contract_hash(&contract)
                            .map_err(|error| ProviderStoreError::Json(error.to_string()))?
                            .as_str()
                            != hash
                    {
                        return Err(ProviderStoreError::Conflict(
                            "selected type contract identity mismatch",
                        ));
                    }
                    types.push(contract);
                }
                "capability" => {
                    let raw: String =
                        row.get::<_, Option<String>>(6)?
                            .ok_or(ProviderStoreError::Conflict(
                                "selected snapshot is missing capability bytes",
                            ))?;
                    let contract: CapabilityContract = crate::schema::decode_with_record_limit(
                        raw.as_bytes(),
                        StrictJsonLimits::default(),
                        crate::schema::RecordKind::Capability,
                        false,
                        None,
                    )
                    .map_err(|error| ProviderStoreError::Json(error.to_string()))?;
                    if contract.capability != id
                        || contract.version != version
                        || crate::capability_contract_hash(&contract)
                            .map_err(|error| ProviderStoreError::Json(error.to_string()))?
                            .as_str()
                            != hash
                    {
                        return Err(ProviderStoreError::Conflict(
                            "selected capability contract identity mismatch",
                        ));
                    }
                    capabilities.push(contract);
                }
                _ => {
                    return Err(ProviderStoreError::Conflict(
                        "unknown selected contract class",
                    ));
                }
            }
        }
        if !expected.is_empty() {
            return Err(ProviderStoreError::Conflict(
                "selected snapshot is missing entries",
            ));
        }
        let registry = SemanticRegistry::from_records(
            snapshot,
            types,
            capabilities,
            crate::RegistryBuildOptions::default(),
        )
        .map_err(|error| ProviderStoreError::Json(error.to_string()))?;
        if registry.snapshot_id() != snapshot_id {
            return Err(ProviderStoreError::Conflict(
                "selected snapshot identity mismatch",
            ));
        }
        Ok(registry)
    }

    fn load_registration(&self, id: &str) -> Result<ProviderRegistration> {
        self.connection.query_row(
            "SELECT registration_id,provider_id,provider_version,manifest_hash,package_content_hash,registry_snapshot_id
             FROM provider_registrations WHERE registration_id=?1",
            [id], |row| Ok(ProviderRegistration {
                registration_id: row.get(0)?,provider_id: row.get(1)?,provider_version: row.get(2)?,
                manifest_hash: row.get(3)?,build_hash: row.get(4)?,snapshot_id: row.get(5)?,
            }),
        ).optional()?.ok_or(ProviderStoreError::NotFound)
    }

    fn contract_suite_version(&self, contract_hash: &str) -> Result<Option<String>> {
        let raw: Option<String> = self
            .connection
            .query_row(
                "SELECT contract_json FROM semantic_capability_contracts WHERE content_hash=?1",
                [contract_hash],
                |row| row.get(0),
            )
            .optional()?;
        let Some(raw) = raw else { return Ok(None) };
        let contract: aios_contracts::CapabilityContract = serde_json::from_str(&raw)
            .map_err(|error| ProviderStoreError::Json(error.to_string()))?;
        if crate::capability_contract_hash(&contract)
            .map_err(|error| ProviderStoreError::Json(error.to_string()))?
            .as_str()
            != contract_hash
        {
            return Err(ProviderStoreError::Conflict(
                "stored semantic contract hash mismatch",
            ));
        }
        Ok(contract.conformance.suite_version)
    }

    fn has_live_evidence(
        &self,
        registration: &ProviderRegistration,
        at: OffsetDateTime,
    ) -> Result<bool> {
        // Enablement opens the registration for consideration when at least one
        // claim is proven. Candidate lookup still checks the requested claim's
        // own static compatibility and latest evidence, so another claim cannot
        // rescue a failed or changed one.
        let manifest = self.verified_manifest(registration)?;
        for claim in &manifest.provides {
            let major = claim.contract.version.split('.').next().unwrap_or("");
            let semantic_ref = format!("{}@{major}", claim.contract.capability);
            let Some(hash) = claim.contract.contract_hash.as_deref() else {
                continue;
            };
            if self
                .valid_passes(registration, &semantic_ref, hash, at)?
                .len()
                == 1
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    #[allow(clippy::too_many_lines)]
    fn valid_passes(
        &self,
        registration: &ProviderRegistration,
        semantic_ref: &str,
        contract_hash: &str,
        at: OffsetDateTime,
    ) -> Result<Vec<(String, String, String)>> {
        let manifest = self.verified_manifest(registration)?;
        let matching_claim = manifest.provides.iter().find(|claim| {
            let major = claim.contract.version.split('.').next().unwrap_or("");
            semantic_ref == format!("{}@{major}", claim.contract.capability)
                && claim.contract.contract_hash.as_deref() == Some(contract_hash)
        });
        let Some(claim) = matching_claim else {
            return Ok(Vec::new());
        };
        let suite_id = &claim.conformance.suite;
        let Some(suite_hash) = claim.conformance.suite_hash.as_deref() else {
            return Ok(Vec::new());
        };
        let Some(suite_version) = self.contract_suite_version(contract_hash)? else {
            return Ok(Vec::new());
        };
        let mut statement = self.connection.prepare(
            "SELECT evidence_id,status,evidence_json,tested_at
             FROM provider_conformance_evidence
             WHERE registration_id=?1 AND capability=?2 AND contract_hash=?3
               AND suite_id=?4 AND suite_hash=?5",
        )?;
        let mut rows = statement.query_map(
            params![
                registration.registration_id,
                semantic_ref,
                contract_hash,
                suite_id,
                suite_hash
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            },
        )?;
        let mut latest: Option<(OffsetDateTime, String, String, String, String)> = None;
        let mut ambiguous = false;
        for row in &mut rows {
            let (id, status, raw, tested_at) = row?;
            let Some(tested_at) = tested_at else {
                return Ok(Vec::new());
            };
            let Ok(executed) = parse_time(&tested_at) else {
                return Ok(Vec::new());
            };
            if executed > at {
                continue;
            }
            match &latest {
                Some((prior, _, _, _, _)) if executed < *prior => {}
                Some((prior, _, _, _, _)) if executed == *prior => {
                    ambiguous = true;
                }
                _ => {
                    latest = Some((executed, id, status, raw, tested_at));
                    ambiguous = false;
                }
            }
        }
        if ambiguous {
            return Ok(Vec::new());
        }
        let Some((_, id, status, raw, tested_at)) = latest else {
            return Ok(Vec::new());
        };
        if status != "pass" {
            return Ok(Vec::new());
        }
        let Ok(evidence) = parse_document(
            raw.as_bytes(),
            MAX_EVIDENCE_BYTES,
            &EVIDENCE_SCHEMA,
            include_str!("../../../specs/provider-conformance-result.schema.json"),
        ) else {
            return Ok(Vec::new());
        };
        let expired = evidence
            .pointer("/expires_at")
            .and_then(Value::as_str)
            .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
            .is_some_and(|value| value <= at);
        let counts_valid = evidence
            .get("tests_total")
            .and_then(Value::as_u64)
            .is_some_and(|total| {
                total > 0
                    && evidence.get("tests_passed").and_then(Value::as_u64) == Some(total)
                    && evidence.get("tests_failed").and_then(Value::as_u64) == Some(0)
            });
        let matches = !expired
            && counts_valid
            && evidence.pointer("/executed_at").and_then(Value::as_str) == Some(tested_at.as_str())
            && evidence.pointer("/result_id").and_then(Value::as_str) == Some(id.as_str())
            && evidence.pointer("/provider_id").and_then(Value::as_str)
                == Some(registration.provider_id.as_str())
            && evidence
                .pointer("/provider_version")
                .and_then(Value::as_str)
                == Some(registration.provider_version.as_str())
            && evidence.pointer("/result").and_then(Value::as_str) == Some("pass")
            && evidence
                .pointer("/semantic_capability_ref")
                .and_then(Value::as_str)
                == Some(semantic_ref)
            && evidence
                .pointer("/semantic_contract_version")
                .and_then(Value::as_str)
                == Some(claim.contract.version.as_str())
            && evidence
                .pointer("/semantic_contract_hash")
                .and_then(Value::as_str)
                == Some(contract_hash)
            && evidence
                .pointer("/conformance_suite/id")
                .and_then(Value::as_str)
                == Some(suite_id.as_str())
            && evidence
                .pointer("/conformance_suite/hash")
                .and_then(Value::as_str)
                == Some(suite_hash)
            && evidence
                .pointer("/conformance_suite/version")
                .and_then(Value::as_str)
                == Some(suite_version.as_str())
            && evidence
                .pointer("/provider_build_identity/value")
                .and_then(Value::as_str)
                == Some(registration.build_hash.as_str());
        Ok(if matches {
            vec![(id, suite_id.clone(), suite_hash.to_owned())]
        } else {
            Vec::new()
        })
    }

    fn verified_manifest(&self, registration: &ProviderRegistration) -> Result<CapabilityManifest> {
        let manifest_json: String = self
            .connection
            .query_row(
                "SELECT manifest_json FROM provider_manifest_payloads WHERE registration_id=?1",
                [&registration.registration_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(ProviderStoreError::NotFound)?;
        let (value, manifest) = parse_manifest(manifest_json.as_bytes())?;
        let canonical = canonical_text(&value)?;
        let hash = digest(b"AIOS-PROVIDER-MANIFEST\0v0.1\0", canonical.as_bytes());
        let id = digest(
            b"AIOS-PROVIDER-REGISTRATION\0v0.1\0",
            format!(
                "{}\0{}\0{}\0{}",
                manifest.id, manifest.version, hash, registration.build_hash
            )
            .as_bytes(),
        );
        if canonical != manifest_json
            || hash != registration.manifest_hash
            || id != registration.registration_id
            || manifest.id != registration.provider_id
            || manifest.version != registration.provider_version
        {
            return Err(ProviderStoreError::Conflict(
                "stored provider manifest does not match registration identity",
            ));
        }
        Ok(manifest)
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "keeps migration stamps and required schema objects in one fail-closed preflight"
)]
fn preflight_migrations(connection: &Connection) -> Result<()> {
    const ADDITIVE: &[(&str, &str)] = &[
        ("trigger", "provider_manifest_payload_immutable_update"),
        ("trigger", "provider_manifest_payload_immutable_delete"),
        ("trigger", "provider_registration_identity_immutable"),
        ("trigger", "provider_registration_no_delete"),
        ("trigger", "provider_registration_revocation_terminal"),
        ("trigger", "provider_registration_no_initial_enablement"),
        ("trigger", "provider_registration_state_transition_clock"),
        (
            "trigger",
            "provider_registration_updated_at_requires_transition",
        ),
        ("table", "provider_state_epochs"),
        ("trigger", "provider_state_epoch_no_update"),
        ("trigger", "provider_state_epoch_no_delete"),
        ("trigger", "provider_state_epoch_no_duplicate_insert"),
        ("trigger", "provider_state_epoch_event_insert_guard"),
        ("trigger", "provider_state_epoch_initial"),
        ("trigger", "provider_state_epoch_transition"),
        ("trigger", "provider_evidence_immutable_update"),
        ("trigger", "provider_evidence_immutable_delete"),
        ("trigger", "provider_registration_no_duplicate_insert"),
        ("trigger", "provider_registration_trust_receipt_insert"),
        ("trigger", "provider_registration_trust_immutable_update"),
        ("table", "provider_trust_admissions"),
        ("trigger", "provider_trust_admission_no_update"),
        ("trigger", "provider_trust_admission_no_delete"),
        ("trigger", "provider_trust_admission_no_duplicate_insert"),
        ("trigger", "provider_trust_admission_receipt_insert"),
        ("trigger", "provider_manifest_payload_no_duplicate_insert"),
        ("trigger", "provider_evidence_no_duplicate_insert"),
        ("trigger", "execution_binding_no_duplicate_insert"),
        ("trigger", "execution_binding_evidence_present_at_insert"),
        ("trigger", "execution_binding_evidence_not_future"),
        ("trigger", "execution_binding_evidence_unexpired_at_insert"),
        ("trigger", "execution_binding_evidence_latest_at_insert"),
        (
            "trigger",
            "execution_binding_provider_enablement_not_future",
        ),
        ("trigger", "execution_binding_evidence_pin_required"),
        ("table", "execution_binding_admission_markers"),
        ("table", "execution_binding_trust_markers"),
        ("table", "execution_binding_enablement_markers"),
        ("trigger", "execution_binding_enablement_marker_no_update"),
        ("trigger", "execution_binding_enablement_marker_no_delete"),
        (
            "trigger",
            "execution_binding_enablement_marker_no_duplicate_insert",
        ),
        ("trigger", "execution_binding_enablement_marker_insert"),
        ("table", "execution_binding_legacy_trust_quarantine"),
        ("trigger", "execution_binding_admission_marker_insert"),
        ("trigger", "execution_binding_trust_marker_insert"),
        ("trigger", "execution_binding_trust_not_future"),
        (
            "trigger",
            "execution_binding_legacy_trust_quarantine_no_update",
        ),
        (
            "trigger",
            "execution_binding_legacy_trust_quarantine_no_delete",
        ),
        (
            "trigger",
            "execution_binding_legacy_trust_quarantine_no_duplicate_insert",
        ),
        (
            "trigger",
            "execution_binding_trust_marker_no_duplicate_insert",
        ),
        ("trigger", "execution_binding_trust_marker_no_update"),
        ("trigger", "execution_binding_trust_marker_no_delete"),
        ("trigger", "execution_binding_marker_no_duplicate_insert"),
        ("trigger", "execution_binding_marker_no_update"),
        ("trigger", "execution_binding_marker_no_delete"),
    ];
    const KNOWN: &[(&str, &str)] = &[
        (
            "0001_v0_1_trusted_control_plane",
            "UNGENERATED-DRAFT-CHECKSUM",
        ),
        (
            "0002_task_manager_contract_reconciliation",
            "task-manager-v0.1",
        ),
        (
            "0003_task_manager_recovery_fencing_privacy",
            "task-manager-recovery-fencing-privacy-v0.1",
        ),
        (
            "0004_task_manager_review_hardening",
            "task-manager-review-hardening-v0.1",
        ),
        (
            "0005_artifact_store_root_binding",
            "artifact-store-root-binding-v0.1",
        ),
        (
            "0006_artifact_writer_admission",
            "artifact-writer-admission-v0.1",
        ),
        (
            "0007_artifact_owner_export_context",
            "artifact-owner-export-context-v0.1",
        ),
        (
            "0008_artifact_export_reconciliation_challenge",
            "artifact-export-reconciliation-challenge-v0.1",
        ),
        (
            "0009_artifact_writer_session_fencing",
            "artifact-writer-session-fencing-v0.1",
        ),
        (
            "0010_keyed_import_causal_receipts",
            "keyed-import-causal-receipts-v0.1",
        ),
        (
            "0011_provenance_service_boundary",
            "provenance-service-boundary-v0.1",
        ),
        (
            "0012_semantic_registry_store",
            "semantic-registry-store-v0.1",
        ),
        (MIGRATION_ID, MIGRATION_CHECKSUM),
    ];
    let mut statement =
        connection.prepare("SELECT migration_id,checksum FROM schema_migrations")?;
    let migrations = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut stamped = false;
    let mut semantic_registry_stamped = false;
    for (id, checksum) in migrations {
        let Some((_, expected)) = KNOWN.iter().find(|(known, _)| *known == id) else {
            return Err(ProviderStoreError::Conflict(
                "unknown control-plane migration",
            ));
        };
        if checksum != *expected {
            return Err(ProviderStoreError::Conflict(
                "control-plane migration checksum mismatch",
            ));
        }
        stamped |= id == MIGRATION_ID;
        semantic_registry_stamped |= id == "0012_semantic_registry_store";
    }
    if !semantic_registry_stamped {
        return Err(ProviderStoreError::Conflict(
            "semantic registry migration must precede provider registry",
        ));
    }
    for (kind, name) in [
        ("table", "provider_manifest_payloads"),
        ("table", "provider_health_observations"),
        ("trigger", "provider_manifest_payload_immutable_update"),
        ("trigger", "provider_manifest_payload_immutable_delete"),
        ("trigger", "provider_registration_identity_immutable"),
        ("trigger", "provider_registration_no_delete"),
        ("trigger", "provider_registration_revocation_terminal"),
        ("trigger", "provider_evidence_immutable_update"),
        ("trigger", "provider_evidence_immutable_delete"),
        ("index", "ix_provider_conformance_latest"),
    ] {
        let present: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type=?1 AND name=?2)",
            params![kind, name],
            |row| row.get(0),
        )?;
        if present != stamped {
            return Err(ProviderStoreError::Conflict(
                "provider schema objects and migration stamp disagree",
            ));
        }
    }
    let mut present_objects = Vec::with_capacity(ADDITIVE.len());
    for &(kind, name) in ADDITIVE {
        let sql: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type=?1 AND name=?2",
                params![kind, name],
                |row| row.get(0),
            )
            .optional()?;
        if sql.is_some() && !stamped {
            return Err(ProviderStoreError::Conflict(
                "provider guard exists without migration stamp",
            ));
        }
        present_objects.push((kind, name, sql));
    }
    if stamped && present_objects.iter().any(|(_, _, sql)| sql.is_none()) {
        return Err(ProviderStoreError::Conflict(
            "provider registry migration is incomplete",
        ));
    }
    if stamped {
        let canonical = Connection::open_in_memory()?;
        canonical.execute_batch(include_str!("../../../specs/persistence-v0.1.sql"))?;
        canonical.execute_batch(include_str!(
            "../../../specs/persistence-v0.1-0013-provider-registry.sql"
        ))?;
        let normalize = |sql: &str| sql.split_whitespace().collect::<Vec<_>>().join(" ");
        for (kind, name, actual) in present_objects {
            let Some(actual) = actual else { continue };
            let expected: String = canonical.query_row(
                "SELECT sql FROM sqlite_master WHERE type=?1 AND name=?2",
                params![kind, name],
                |row| row.get(0),
            )?;
            if normalize(&actual) != normalize(&expected) {
                return Err(ProviderStoreError::Conflict(
                    "provider additive guard definition differs",
                ));
            }
        }
    }
    if !stamped {
        return Err(ProviderStoreError::Conflict(
            "Task Manager fenced provider registry migration is required",
        ));
    }
    Ok(())
}

fn parse_manifest(raw: &[u8]) -> Result<(Value, CapabilityManifest)> {
    let value = parse_document(
        raw,
        MAX_MANIFEST_BYTES,
        &MANIFEST_SCHEMA,
        include_str!("../../../specs/capability-manifest.schema.json"),
    )?;
    let manifest = serde_json::from_value(value.clone())
        .map_err(|error| ProviderStoreError::Json(error.to_string()))?;
    Ok((value, manifest))
}

fn parse_document(
    raw: &[u8],
    max_bytes: usize,
    cache: &OnceLock<std::result::Result<jsonschema::Validator, String>>,
    schema_source: &str,
) -> Result<Value> {
    let value = parse_strict_value(
        raw,
        StrictJsonLimits {
            max_bytes,
            max_depth: 32,
        },
    )
    .map_err(|error| ProviderStoreError::Json(error.to_string()))?;
    let validator = cache
        .get_or_init(|| {
            let schema: Value =
                serde_json::from_str(schema_source).map_err(|error| error.to_string())?;
            jsonschema::options()
                .should_validate_formats(true)
                .build(&schema)
                .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|error| ProviderStoreError::Json(format!("embedded schema: {error}")))?;
    if let Some(error) = validator.iter_errors(&value).next() {
        return Err(ProviderStoreError::Json(format!(
            "schema violation at {} ({})",
            error.instance_path(),
            error.schema_path()
        )));
    }
    Ok(value)
}

fn string_at<'a>(value: &'a Value, pointer: &str) -> Result<&'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or(ProviderStoreError::Invalid(
            "evidence is missing a required string",
        ))
}
fn canonical_text(value: &Value) -> Result<String> {
    let bytes = canonicalize(value).map_err(|error| ProviderStoreError::Json(error.to_string()))?;
    String::from_utf8(bytes).map_err(|error| ProviderStoreError::Json(error.to_string()))
}
fn digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    let hash = hasher.finalize();
    let mut result = String::from("sha256:");
    for byte in hash {
        write!(&mut result, "{byte:02x}").expect("writing to String cannot fail");
    }
    result
}
fn parse_time(value: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| ProviderStoreError::Invalid("timestamp must be RFC 3339"))
}
fn registration_record(
    registration: &ProviderRegistration,
    manifest: &CapabilityManifest,
    trust: ProviderTrustStatus,
    registered_at: &str,
) -> Value {
    let capabilities: Vec<Value> = manifest
        .provides
        .iter()
        .map(|claim| {
            json!({
                "capability": claim.contract.capability,
                "version": claim.contract.version,
                "contract_hash": claim.contract.contract_hash,
                "conformance_suite": claim.conformance.suite,
                "conformance_suite_hash": claim.conformance.suite_hash,
                "conformance_status": "declared",
                "eligible": false,
                "representations": claim.representations,
            })
        })
        .collect();
    json!({
        "schema_version": "0.1",
        "registration_id": registration.registration_id,
        "provider": {
            "id": registration.provider_id,
            "version": registration.provider_version,
            "manifest_hash": registration.manifest_hash,
        },
        "package": { "source_kind": "local", "content_hash": registration.build_hash },
        "runtime": {
            "kind": manifest.runtime.kind,
            "minimum_isolation": manifest.provides.iter().map(|claim| claim.execution.minimum_isolation).max(),
        },
        "registry_snapshot_id": registration.snapshot_id,
        "capabilities": capabilities,
        "trust": { "status": trust.as_str() },
        "state": "disabled",
        "registered_at": registered_at,
    })
}

fn verify_stored_registration_receipt(
    connection: &Connection,
    registration: &ProviderRegistration,
    manifest: &CapabilityManifest,
) -> Result<()> {
    let (receipt_json, registered_at, projected_trust): (String, String, String) = connection.query_row(
        "SELECT registration_json,registered_at,trust_status FROM provider_registrations WHERE registration_id=?1",
        [&registration.registration_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    verify_provider_registration_receipt(
        registration,
        manifest,
        &projected_trust,
        &registered_at,
        &receipt_json,
    )
}

fn trust_admission_receipt(
    registration_id: &str,
    decision_id: &str,
    revision: i64,
    trust: ProviderTrustStatus,
    authority_ref: &str,
    admitted_at: &str,
) -> Result<String> {
    canonical_text(&json!({
        "schema_version": "0.1",
        "registration_id": registration_id,
        "decision_id": decision_id,
        "revision": revision,
        "trust_status": trust.as_str(),
        "authority_ref": authority_ref,
        "admitted_at": admitted_at,
    }))
}

/// Reconstructs the original immutable receipt and each appended trust review
/// before returning the effective trust scope for this exact build.
pub fn verified_provider_effective_trust(
    connection: &Connection,
    registration: &ProviderRegistration,
    manifest: &CapabilityManifest,
) -> Result<ProviderTrustStatus> {
    verified_provider_trust_source(connection, registration, manifest).map(|(trust, _)| trust)
}

fn verified_provider_effective_trust_at(
    connection: &Connection,
    registration: &ProviderRegistration,
    manifest: &CapabilityManifest,
    at: &str,
) -> Result<ProviderTrustStatus> {
    verified_provider_trust_source_at(connection, registration, manifest, at)
        .map(|(trust, _)| trust)
}

/// Returns effective trust and the immutable receipt ID that established it.
/// Bind-time and launch gates compare this source with the binding trust marker.
pub fn verified_provider_trust_source(
    connection: &Connection,
    registration: &ProviderRegistration,
    manifest: &CapabilityManifest,
) -> Result<(ProviderTrustStatus, String)> {
    verified_provider_trust_source_checked(connection, registration, manifest, None)
}

/// Resolves the authenticated trust source effective at `at` while validating
/// every immutable admission receipt, including later historical records.
pub fn verified_provider_trust_source_at(
    connection: &Connection,
    registration: &ProviderRegistration,
    manifest: &CapabilityManifest,
    at: &str,
) -> Result<(ProviderTrustStatus, String)> {
    verified_provider_trust_source_checked(
        connection,
        registration,
        manifest,
        Some(parse_time(at)?),
    )
}

fn verified_provider_trust_source_checked(
    connection: &Connection,
    registration: &ProviderRegistration,
    manifest: &CapabilityManifest,
    checked: Option<OffsetDateTime>,
) -> Result<(ProviderTrustStatus, String)> {
    verify_stored_registration_receipt(connection, registration, manifest)?;
    let initial: String = connection.query_row(
        "SELECT trust_status FROM provider_registrations WHERE registration_id=?1",
        [&registration.registration_id],
        |row| row.get(0),
    )?;
    let initial_trust = ProviderTrustStatus::parse(&initial)?;
    let mut effective = initial_trust;
    let mut source_id = registration.registration_id.clone();
    let mut statement = connection.prepare(
        "SELECT admission_id,decision_id,revision,trust_status,authority_ref,admitted_at,receipt_json
         FROM provider_trust_admissions WHERE registration_id=?1 ORDER BY revision",
    )?;
    let mut rows = statement.query([&registration.registration_id])?;
    let mut expected_revision = 1_i64;
    let registered_at: String = connection.query_row(
        "SELECT registered_at FROM provider_registrations WHERE registration_id=?1",
        [&registration.registration_id],
        |row| row.get(0),
    )?;
    let mut latest_time = parse_time(&registered_at)?;
    if checked.is_some_and(|cutoff| latest_time > cutoff) {
        return Err(ProviderStoreError::Conflict(
            "provider registration is in the future",
        ));
    }
    while let Some(row) = rows.next()? {
        let (id, decision, revision, trust, authority, at, receipt): (
            String,
            String,
            i64,
            String,
            String,
            String,
            String,
        ) = (
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
        );
        if matches!(
            initial_trust,
            ProviderTrustStatus::Denied | ProviderTrustStatus::Revoked
        ) || revision != expected_revision
            || decision.is_empty()
            || decision.len() > 256
            || authority.is_empty()
            || authority.len() > 256
        {
            return Err(ProviderStoreError::Conflict(
                "invalid provider trust admission history",
            ));
        }
        let decision_time = parse_time(&at)?;
        if decision_time < latest_time {
            return Err(ProviderStoreError::Conflict(
                "provider trust admission history moves backward in time",
            ));
        }
        let parsed = ProviderTrustStatus::parse(&trust)?;
        if !parsed.permits_execution() {
            return Err(ProviderStoreError::Conflict(
                "trust admission does not permit execution",
            ));
        }
        let expected = trust_admission_receipt(
            &registration.registration_id,
            &decision,
            revision,
            parsed,
            &authority,
            &at,
        )?;
        if receipt != expected
            || id != digest(b"AIOS-PROVIDER-TRUST-ADMISSION\0v0.1\0", receipt.as_bytes())
        {
            return Err(ProviderStoreError::Conflict(
                "provider trust admission receipt mismatch",
            ));
        }
        if checked.is_none_or(|cutoff| decision_time <= cutoff) {
            effective = parsed;
            source_id = id;
        }
        latest_time = decision_time;
        expected_revision =
            expected_revision
                .checked_add(1)
                .ok_or(ProviderStoreError::Conflict(
                    "provider trust admission revision overflow",
                ))?;
    }
    Ok((effective, source_id))
}

/// Verifies the complete immutable registration admission receipt without a
/// database connection. Trusted launch checks can apply this to selected rows.
pub fn verify_provider_registration_receipt(
    registration: &ProviderRegistration,
    manifest: &CapabilityManifest,
    projected_trust: &str,
    registered_at: &str,
    receipt_json: &str,
) -> std::result::Result<(), ProviderStoreError> {
    parse_time(registered_at)?;
    let receipt = parse_document(
        receipt_json.as_bytes(),
        MAX_MANIFEST_BYTES,
        &REGISTRATION_SCHEMA,
        include_str!("../../../specs/provider-registration.schema.json"),
    )?;
    let trust = match receipt.pointer("/trust/status").and_then(Value::as_str) {
        Some("unverified") => ProviderTrustStatus::Unverified,
        Some("locally-trusted") => ProviderTrustStatus::LocallyTrusted,
        Some("project-reviewed") => ProviderTrustStatus::ProjectReviewed,
        Some("organization-approved") => ProviderTrustStatus::OrganizationApproved,
        Some("denied") => ProviderTrustStatus::Denied,
        Some("revoked") => ProviderTrustStatus::Revoked,
        _ => {
            return Err(ProviderStoreError::Conflict(
                "stored registration trust is invalid",
            ));
        }
    };
    if projected_trust != trust.as_str() {
        return Err(ProviderStoreError::Conflict(
            "provider trust differs from immutable admission receipt",
        ));
    }
    let expected = canonical_text(&registration_record(
        registration,
        manifest,
        trust,
        registered_at,
    ))?;
    if receipt_json != expected {
        return Err(ProviderStoreError::Conflict(
            "stored registration receipt differs from its admitted manifest and identity",
        ));
    }
    Ok(())
}

fn existing_evidence_matches(
    connection: &Connection,
    evidence_id: &str,
    expected: &EvidenceProjection,
) -> Result<bool> {
    let stored: Option<EvidenceProjection> = connection
        .query_row(
            "SELECT registration_id,capability,contract_hash,suite_id,suite_hash,status,evidence_json,tested_at FROM provider_conformance_evidence WHERE evidence_id=?1",
            [evidence_id],
            |row| {
                Ok(EvidenceProjection {
                    registration_id: row.get(0)?,
                    capability: row.get(1)?,
                    contract_hash: row.get(2)?,
                    suite_id: row.get(3)?,
                    suite_hash: row.get(4)?,
                    status: row.get(5)?,
                    evidence_json: row.get(6)?,
                    tested_at: row.get(7)?,
                })
            },
        )
        .optional()?;
    if stored.as_ref().is_some_and(|entry| entry != expected) {
        return Err(ProviderStoreError::Conflict(
            "evidence ID already maps to different evidence or projections",
        ));
    }
    Ok(stored.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RegistryBuildOptions, RegistryStore, SnapshotState};
    use aios_contracts::{CapabilityContract, RegistrySnapshot, TypeContract};

    const SNAPSHOT: &str = include_str!("../../../examples/aios-ir/registry-snapshot.json");
    const TYPES: &str = include_str!("../../../examples/aios-ir/type-contracts.json");
    const CAPABILITIES: &str = include_str!("../../../examples/aios-ir/capability-contracts.json");
    const CASES: &str = include_str!("../../../examples/aios-ir/provider-conformance-cases.json");
    const BUILD_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const BUILD_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const SUITE_HASH: &str =
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const SUITE_HASH_B: &str =
        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    const NOW: &str = "2026-09-22T12:00:00Z";

    fn seed_test_registry_schemas(connection: &Connection) {
        connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(migration_id,checksum,applied_at) VALUES ('0001_v0_1_trusted_control_plane','UNGENERATED-DRAFT-CHECKSUM',?1)",
            [NOW],
        ).unwrap();
        connection
            .execute_batch(include_str!(
                "../../../specs/persistence-v0.1-0012-semantic-registry.sql"
            ))
            .unwrap();
        connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(migration_id,checksum,applied_at) VALUES ('0012_semantic_registry_store','semantic-registry-store-v0.1',?1)",
            [NOW],
        ).unwrap();
        connection
            .execute_batch(include_str!(
                "../../../specs/persistence-v0.1-0013-provider-registry.sql"
            ))
            .unwrap();
        connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(migration_id,checksum,applied_at) VALUES (?1,?2,?3)",
            params![MIGRATION_ID, MIGRATION_CHECKSUM, NOW],
        ).unwrap();
    }

    fn setup() -> (Connection, SemanticRegistry) {
        setup_with_provider_migration(true)
    }

    fn setup_with_provider_migration(migrate_provider: bool) -> (Connection, SemanticRegistry) {
        let mut connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(include_str!("../../../specs/persistence-v0.1.sql"))
            .unwrap();
        connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(migration_id,checksum,applied_at) VALUES ('0001_v0_1_trusted_control_plane','UNGENERATED-DRAFT-CHECKSUM',?1)",
            [NOW],
        ).unwrap();
        connection
            .execute_batch(include_str!(
                "../../../specs/persistence-v0.1-0012-semantic-registry.sql"
            ))
            .unwrap();
        connection.execute(
            "INSERT INTO schema_migrations(migration_id,checksum,applied_at) VALUES ('0012_semantic_registry_store','semantic-registry-store-v0.1',?1)",
            [NOW],
        ).unwrap();
        let mut snapshot: RegistrySnapshot = serde_json::from_str(SNAPSHOT).unwrap();
        let types: Vec<TypeContract> = serde_json::from_str(TYPES).unwrap();
        let mut capabilities: Vec<CapabilityContract> = serde_json::from_str(CAPABILITIES).unwrap();
        let contract = capabilities
            .iter_mut()
            .find(|contract| contract.capability == "artifact.hash")
            .unwrap();
        contract.conformance.suite_hash = Some(SUITE_HASH.into());
        let hash = crate::capability_contract_hash(contract)
            .unwrap()
            .to_string();
        let entry = snapshot
            .capability_contracts
            .iter_mut()
            .find(|entry| entry.id == "artifact.hash")
            .unwrap();
        entry.content_hash = hash;
        let other = capabilities
            .iter_mut()
            .find(|contract| contract.capability == "table.normalize")
            .unwrap();
        other.conformance.suite_hash = Some(SUITE_HASH_B.into());
        let other_hash = crate::capability_contract_hash(other).unwrap().to_string();
        snapshot
            .capability_contracts
            .iter_mut()
            .find(|entry| entry.id == "table.normalize")
            .unwrap()
            .content_hash = other_hash;
        let entry_view = |entry: &aios_contracts::ContractRef| crate::SnapshotHashEntry {
            id: entry.id.clone(),
            version: entry.version.clone(),
            content_hash: entry.content_hash.clone(),
        };
        snapshot.snapshot_id = crate::registry_snapshot_id(
            &snapshot.schema_version,
            &snapshot
                .type_contracts
                .iter()
                .map(entry_view)
                .collect::<Vec<_>>(),
            &snapshot
                .capability_contracts
                .iter()
                .map(entry_view)
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
        RegistryStore::initialize_unfenced_fixture(&mut connection)
            .unwrap()
            .admit_registry(&registry)
            .unwrap();
        if migrate_provider {
            connection
                .execute_batch(include_str!(
                    "../../../specs/persistence-v0.1-0013-provider-registry.sql"
                ))
                .unwrap();
            connection.execute(
                "INSERT INTO schema_migrations(migration_id,checksum,applied_at) VALUES (?1,?2,?3)",
                params![MIGRATION_ID, MIGRATION_CHECKSUM, NOW],
            ).unwrap();
        }
        (connection, registry)
    }

    fn manifest(registry: &SemanticRegistry) -> Value {
        let cases: Value = serde_json::from_str(CASES).unwrap();
        let mut value = cases[0]["provider"].clone();
        value["provides"][0]["conformance"]["suite_hash"] = SUITE_HASH.into();
        value["provides"][0]["contract"]["contract_hash"] = registry
            .capability_contract_hash("artifact.hash", 1)
            .unwrap()
            .as_str()
            .into();
        value
    }
    fn two_claim_manifest(registry: &SemanticRegistry) -> Value {
        let mut value = manifest(registry);
        let mut other = value["provides"][0].clone();
        other["contract"]["capability"] = "table.normalize".into();
        other["contract"]["contract_hash"] = registry
            .capability_contract_hash("table.normalize", 1)
            .unwrap()
            .as_str()
            .into();
        other["conformance"]["suite"] = "conformance://table.normalize/1".into();
        other["conformance"]["suite_hash"] = SUITE_HASH_B.into();
        other["effect_classes"] = json!(["PURE"]);
        other["authority"] = json!({"actions":[],"resource_classes":[]});
        value["provides"].as_array_mut().unwrap().push(other);
        value
    }
    fn snapshot_change(first: &SemanticRegistry, changed_capability: &str) -> SemanticRegistry {
        let mut snapshot = first.snapshot().clone();
        let types = first.type_contracts().cloned().collect::<Vec<_>>();
        let mut capabilities = first.capability_contracts().cloned().collect::<Vec<_>>();
        let unrelated = capabilities
            .iter_mut()
            .find(|contract| contract.capability == changed_capability)
            .unwrap();
        unrelated.version = "1.1".into();
        let hash = crate::capability_contract_hash(unrelated)
            .unwrap()
            .to_string();
        let entry = snapshot
            .capability_contracts
            .iter_mut()
            .find(|entry| entry.id == changed_capability)
            .unwrap();
        entry.version = "1.1".into();
        entry.content_hash = hash;
        let entry_view = |entry: &aios_contracts::ContractRef| crate::SnapshotHashEntry {
            id: entry.id.clone(),
            version: entry.version.clone(),
            content_hash: entry.content_hash.clone(),
        };
        snapshot.snapshot_id = crate::registry_snapshot_id(
            &snapshot.schema_version,
            &snapshot
                .type_contracts
                .iter()
                .map(entry_view)
                .collect::<Vec<_>>(),
            &snapshot
                .capability_contracts
                .iter()
                .map(entry_view)
                .collect::<Vec<_>>(),
        )
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
    fn type_representation_change(first: &SemanticRegistry) -> SemanticRegistry {
        let mut snapshot = first.snapshot().clone();
        let mut types = first.type_contracts().cloned().collect::<Vec<_>>();
        let capabilities = first.capability_contracts().cloned().collect::<Vec<_>>();
        let contract = types
            .iter_mut()
            .find(|contract| contract.type_id == "artifact.file")
            .unwrap();
        contract.version = "1.1".into();
        contract.representations[0].id = "artifact-handle-v2".into();
        let hash = crate::type_contract_hash(contract).unwrap().to_string();
        let entry = snapshot
            .type_contracts
            .iter_mut()
            .find(|entry| entry.id == "artifact.file")
            .unwrap();
        entry.version = "1.1".into();
        entry.content_hash = hash;
        let entry_view = |entry: &aios_contracts::ContractRef| crate::SnapshotHashEntry {
            id: entry.id.clone(),
            version: entry.version.clone(),
            content_hash: entry.content_hash.clone(),
        };
        snapshot.snapshot_id = crate::registry_snapshot_id(
            &snapshot.schema_version,
            &snapshot
                .type_contracts
                .iter()
                .map(entry_view)
                .collect::<Vec<_>>(),
            &snapshot
                .capability_contracts
                .iter()
                .map(entry_view)
                .collect::<Vec<_>>(),
        )
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
    fn missing_suite_identity(first: &SemanticRegistry, missing_version: bool) -> SemanticRegistry {
        let mut snapshot = first.snapshot().clone();
        let types = first.type_contracts().cloned().collect::<Vec<_>>();
        let mut capabilities = first.capability_contracts().cloned().collect::<Vec<_>>();
        let contract = capabilities
            .iter_mut()
            .find(|contract| contract.capability == "artifact.hash")
            .unwrap();
        if missing_version {
            contract.conformance.suite_version = None;
        } else {
            contract.conformance.suite_hash = None;
        }
        let hash = crate::capability_contract_hash(contract)
            .unwrap()
            .to_string();
        snapshot
            .capability_contracts
            .iter_mut()
            .find(|entry| entry.id == "artifact.hash")
            .unwrap()
            .content_hash = hash;
        let entry_view = |entry: &aios_contracts::ContractRef| crate::SnapshotHashEntry {
            id: entry.id.clone(),
            version: entry.version.clone(),
            content_hash: entry.content_hash.clone(),
        };
        snapshot.snapshot_id = crate::registry_snapshot_id(
            &snapshot.schema_version,
            &snapshot
                .type_contracts
                .iter()
                .map(entry_view)
                .collect::<Vec<_>>(),
            &snapshot
                .capability_contracts
                .iter()
                .map(entry_view)
                .collect::<Vec<_>>(),
        )
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
    fn evidence(manifest: &Value, build: &str, result: &str) -> Value {
        let claim = &manifest["provides"][0];
        json!({
            "schema_version": "0.1",
            "result_id": "evidence-a",
            "provider_id": manifest["id"],
            "provider_version": manifest["version"],
            "provider_build_identity": { "kind": "build_hash", "value": build },
            "semantic_capability_ref": "artifact.hash@1",
            "semantic_contract_version": claim["contract"]["version"],
            "semantic_contract_hash": claim["contract"]["contract_hash"],
            "conformance_suite": {
                "id": claim["conformance"]["suite"],
                "version": "0.1",
                "hash": SUITE_HASH,
            },
            "harness": { "id": "fixture-harness", "version": "1" },
            "result": result,
            "tests_total": 2,
            "tests_passed": if result == "pass" {2} else {1},
            "tests_failed": i32::from(result != "pass"),
            "executed_at": "2026-09-22T11:00:00Z",
            "expires_at": "2026-09-23T11:00:00Z",
        })
    }
    fn bytes(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).unwrap()
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "keeps fixture execution, evidence admission, and substitution assertions together"
    )]
    fn exact_build_evidence_enables_two_candidates_and_revocation_removes_one() {
        // Execute the same bounded conformance vectors through two fixture
        // implementations before the trusted caller records their results.
        // One buffers the artifact; the other reads it in small chunks.
        fn hex_digest(hash: impl IntoIterator<Item = u8>) -> String {
            let mut result = String::new();
            for byte in hash {
                write!(&mut result, "{byte:02x}").unwrap();
            }
            result
        }
        fn buffered_hash(bytes: &[u8]) -> String {
            hex_digest(Sha256::digest(bytes))
        }
        fn streamed_hash(bytes: &[u8]) -> String {
            let mut digest = Sha256::new();
            for chunk in bytes.chunks(2) {
                digest.update(chunk);
            }
            hex_digest(digest.finalize())
        }
        let (mut connection, registry) = setup();
        let original_snapshot_id = registry.snapshot_id().to_owned();
        let original_contract_hash = registry
            .capability_contract_hash("artifact.hash", 1)
            .unwrap()
            .to_string();
        let mut store = ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
        let first_manifest = manifest(&registry);
        let mut second_manifest = first_manifest.clone();
        second_manifest["id"] = "org.ainative.fixture.artifact-hash-b".into();
        for (manifest, fixture_name, implementation, id) in [
            (
                &first_manifest,
                "buffered-sha256",
                buffered_hash as fn(&[u8]) -> String,
                "evidence-a",
            ),
            (
                &second_manifest,
                "streamed-sha256",
                streamed_hash as fn(&[u8]) -> String,
                "evidence-b",
            ),
        ] {
            // These are stable identities for the two local Stage E fixture
            // implementations, not attestations of compiled provider binaries.
            let build = digest(
                b"AIOS-STAGE-E-FIXTURE-BUILD\0v0.1\0",
                fixture_name.as_bytes(),
            );
            let vectors = [
                (
                    b"".as_slice(),
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                ),
                (
                    b"abc".as_slice(),
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                ),
            ];
            let passed = vectors
                .iter()
                .filter(|(input, expected)| implementation(input) == *expected)
                .count();
            assert_eq!(passed, vectors.len(), "{fixture_name}");
            let registration = store
                .register(
                    &registry,
                    &bytes(manifest),
                    &build,
                    ProviderTrustStatus::LocallyTrusted,
                    NOW,
                )
                .unwrap();
            let mut pass = evidence(manifest, &build, "pass");
            pass["result_id"] = id.into();
            pass["tests_total"] = vectors.len().into();
            pass["tests_passed"] = passed.into();
            pass["tests_failed"] = (vectors.len() - passed).into();
            store
                .record_evidence(&registration.registration_id, &bytes(&pass))
                .unwrap();
            store.enable(&registration.registration_id, NOW).unwrap();
        }
        let hash = first_manifest["provides"][0]["contract"]["contract_hash"]
            .as_str()
            .unwrap();
        let candidates = store
            .eligible_candidates("artifact.hash@1", hash, registry.snapshot_id(), NOW)
            .unwrap();
        assert_eq!(candidates.len(), 2);
        let first_id = candidates[0].registration.registration_id.clone();
        store.revoke(&first_id, NOW).unwrap();
        assert_eq!(
            store
                .eligible_candidates("artifact.hash@1", hash, registry.snapshot_id(), NOW)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(registry.snapshot_id(), original_snapshot_id);
        assert_eq!(
            registry
                .capability_contract_hash("artifact.hash", 1)
                .unwrap()
                .as_str(),
            original_contract_hash
        );
        assert!(store.enable(&first_id, NOW).is_err());
        store
            .observe_health(
                &first_id,
                &ProviderHealth {
                    status: "ready".into(),
                    checked_at: NOW.into(),
                    reason: None,
                },
            )
            .unwrap();
        assert_eq!(
            store
                .eligible_candidates("artifact.hash@1", hash, registry.snapshot_id(), NOW)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn rejects_duplicate_json_invalid_envelope_and_stale_build_or_suite() {
        let (mut connection, registry) = setup();
        let mut store = ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
        let duplicate = br#"{"schema_version":"0.1","schema_version":"0.1"}"#;
        assert!(
            store
                .register(
                    &registry,
                    duplicate,
                    BUILD_A,
                    ProviderTrustStatus::LocallyTrusted,
                    NOW
                )
                .is_err()
        );
        let mut invalid = manifest(&registry);
        invalid["provides"][0]["effect_classes"] = json!(["ARTIFACT_READ", "NETWORK"]);
        assert!(matches!(
            store.register(
                &registry,
                &bytes(&invalid),
                BUILD_A,
                ProviderTrustStatus::LocallyTrusted,
                NOW
            ),
            Err(ProviderStoreError::StaticCompatibility(_))
        ));
        let mut unknown_field = manifest(&registry);
        unknown_field["forged_authority"] = json!({"granted":true});
        assert!(
            store
                .register(
                    &registry,
                    &bytes(&unknown_field),
                    BUILD_A,
                    ProviderTrustStatus::LocallyTrusted,
                    NOW
                )
                .is_err()
        );
        let mut null_hash = manifest(&registry);
        null_hash["provides"][0]["contract"]["contract_hash"] = Value::Null;
        assert!(
            store
                .register(
                    &registry,
                    &bytes(&null_hash),
                    BUILD_A,
                    ProviderTrustStatus::LocallyTrusted,
                    NOW
                )
                .is_err()
        );
        let manifest = manifest(&registry);
        let registration = store
            .register(
                &registry,
                &bytes(&manifest),
                BUILD_A,
                ProviderTrustStatus::LocallyTrusted,
                NOW,
            )
            .unwrap();
        for change in [
            "build",
            "suite",
            "suite-version",
            "contract",
            "partial",
            "fail",
            "expired",
        ] {
            let mut wrong = evidence(&manifest, BUILD_A, "pass");
            wrong["result_id"] = format!("evidence-{change}").into();
            match change {
                "build" => wrong["provider_build_identity"]["value"] = BUILD_B.into(),
                "suite" => wrong["conformance_suite"]["hash"] = BUILD_B.into(),
                "suite-version" => wrong["conformance_suite"]["version"] = "9.9".into(),
                "contract" => wrong["semantic_contract_hash"] = BUILD_B.into(),
                "partial" => wrong["result"] = "partial".into(),
                "fail" => wrong["result"] = "fail".into(),
                _ => wrong["expires_at"] = "2026-09-22T11:30:00Z".into(),
            }
            if matches!(change, "partial" | "fail" | "expired") {
                store
                    .record_evidence(&registration.registration_id, &bytes(&wrong))
                    .unwrap();
                assert!(store.enable(&registration.registration_id, NOW).is_err());
            } else {
                assert!(
                    store
                        .record_evidence(&registration.registration_id, &bytes(&wrong))
                        .is_err(),
                    "{change}"
                );
            }
        }
        let mut first = evidence(&manifest, BUILD_A, "fail");
        first["result_id"] = "same-id".into();
        store
            .record_evidence(&registration.registration_id, &bytes(&first))
            .unwrap();
        first["notes"] = "different bytes".into();
        assert!(matches!(
            store.record_evidence(&registration.registration_id, &bytes(&first)),
            Err(ProviderStoreError::Conflict(_))
        ));
        assert!(store.enable(&registration.registration_id, NOW).is_err());
    }

    #[test]
    fn legacy_mismatched_evidence_and_health_never_grant_eligibility() {
        let (mut connection, registry) = setup();
        let mut store = ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
        let manifest = manifest(&registry);
        let registration = store
            .register(
                &registry,
                &bytes(&manifest),
                BUILD_A,
                ProviderTrustStatus::LocallyTrusted,
                NOW,
            )
            .unwrap();
        let mut wrong = evidence(&manifest, BUILD_A, "pass");
        wrong["provider_id"] = "provider:forged".into();
        let hash = manifest["provides"][0]["contract"]["contract_hash"]
            .as_str()
            .unwrap();
        // Simulates a historical baseline row predating 0013 validation.
        store.connection.execute(
            "INSERT INTO provider_conformance_evidence
             (evidence_id,registration_id,capability,contract_hash,suite_id,suite_hash,status,evidence_json,tested_at)
             VALUES ('legacy',?1,'artifact.hash@1',?2,'conformance://artifact.hash/1',?3,'pass',?4,'2026-09-22T11:00:00Z')",
            params![registration.registration_id,hash,SUITE_HASH,String::from_utf8(bytes(&wrong)).unwrap()],
        ).unwrap();
        assert!(store.enable(&registration.registration_id, NOW).is_err());
        store
            .connection
            .execute(
                "UPDATE provider_registrations SET state='registered',updated_at='2026-09-22T12:00:01Z' WHERE registration_id=?1",
                [&registration.registration_id],
            )
            .unwrap();
        store
            .observe_health(
                &registration.registration_id,
                &ProviderHealth {
                    status: "ready".into(),
                    checked_at: "2026-09-22T10:00:00-07:00".into(),
                    reason: None,
                },
            )
            .unwrap();
        store
            .observe_health(
                &registration.registration_id,
                &ProviderHealth {
                    status: "unavailable".into(),
                    checked_at: "2026-09-22T12:00:00Z".into(),
                    reason: None,
                },
            )
            .unwrap();
        assert_eq!(
            store
                .health(&registration.registration_id)
                .unwrap()
                .unwrap()
                .status,
            "ready"
        );
        assert!(
            store
                .eligible_candidates("artifact.hash@1", hash, registry.snapshot_id(), NOW)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn migration_preflight_rejects_unstamped_or_incomplete_provider_schema() {
        let (mut connection, _) = setup_with_provider_migration(false);
        connection.execute_batch("CREATE TABLE provider_manifest_payloads (registration_id TEXT PRIMARY KEY, manifest_json TEXT NOT NULL)").unwrap();
        assert!(ProviderStore::initialize_unfenced_fixture(&mut connection).is_err());
        connection
            .execute_batch("DROP TABLE provider_manifest_payloads")
            .unwrap();
        assert!(ProviderStore::initialize_unfenced_fixture(&mut connection).is_err());
        connection
            .execute_batch(include_str!(
                "../../../specs/persistence-v0.1-0013-provider-registry.sql"
            ))
            .unwrap();
        connection
            .execute(
                "INSERT INTO schema_migrations(migration_id,checksum,applied_at) VALUES (?1,?2,?3)",
                params![MIGRATION_ID, MIGRATION_CHECKSUM, NOW],
            )
            .unwrap();
        ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
        connection
            .execute_batch("DROP TRIGGER provider_evidence_immutable_update")
            .unwrap();
        assert!(ProviderStore::initialize_unfenced_fixture(&mut connection).is_err());
    }

    #[test]
    fn migration_preflight_authenticates_new_lifecycle_and_binding_guards() {
        for (name, table, event) in [
            (
                "provider_registration_no_initial_enablement",
                "provider_registrations",
                "INSERT",
            ),
            (
                "provider_registration_state_transition_clock",
                "provider_registrations",
                "UPDATE",
            ),
            (
                "provider_registration_updated_at_requires_transition",
                "provider_registrations",
                "UPDATE",
            ),
            (
                "execution_binding_evidence_latest_at_insert",
                "execution_bindings",
                "INSERT",
            ),
            (
                "execution_binding_provider_enablement_not_future",
                "execution_bindings",
                "INSERT",
            ),
        ] {
            let (mut connection, _) = setup();
            connection
                .execute_batch(&format!("DROP TRIGGER {name}"))
                .unwrap();
            assert!(
                matches!(
                    ProviderStore::initialize_unfenced_fixture(&mut connection),
                    Err(ProviderStoreError::Conflict(
                        "provider registry migration is incomplete"
                    ))
                ),
                "missing {name}"
            );
            connection
                .execute_batch(&format!(
                    "CREATE TRIGGER {name} BEFORE {event} ON {table} BEGIN SELECT 1; END;"
                ))
                .unwrap();
            assert!(
                matches!(
                    ProviderStore::initialize_unfenced_fixture(&mut connection),
                    Err(ProviderStoreError::Conflict(
                        "provider additive guard definition differs"
                    ))
                ),
                "no-op {name}"
            );
        }
    }

    #[test]
    fn trust_projection_cannot_be_elevated_past_immutable_admission_receipt() {
        let (mut connection, registry) = setup();
        let manifest = manifest(&registry);
        let registration = ProviderStore::initialize_unfenced_fixture(&mut connection)
            .unwrap()
            .register(
                &registry,
                &bytes(&manifest),
                BUILD_A,
                ProviderTrustStatus::Unverified,
                NOW,
            )
            .unwrap();
        assert!(connection.execute(
            "UPDATE provider_registrations SET trust_status='organization-approved' WHERE registration_id=?1",
            [&registration.registration_id],
        ).is_err());
        assert!(
            connection
                .execute(
                    "INSERT INTO provider_registrations
             (registration_id,provider_id,provider_version,manifest_hash,package_content_hash,
              registry_snapshot_id,state,trust_status,registration_json,registered_at)
             SELECT 'forged-registration',provider_id||'.forged',provider_version,manifest_hash,
                    package_content_hash,registry_snapshot_id,'disabled','organization-approved',
                    registration_json,registered_at
             FROM provider_registrations WHERE registration_id=?1",
                    [&registration.registration_id],
                )
                .is_err()
        );
        let mut store = ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
        store
            .record_evidence(
                &registration.registration_id,
                &bytes(&evidence(&manifest, BUILD_A, "pass")),
            )
            .unwrap();
        assert!(store.enable(&registration.registration_id, NOW).is_err());

        // A trusted admission and ordinary terminal runtime revocation still work.
        let trusted = store
            .register(
                &registry,
                &bytes(&manifest),
                BUILD_B,
                ProviderTrustStatus::LocallyTrusted,
                NOW,
            )
            .unwrap();
        let mut trusted_evidence = evidence(&manifest, BUILD_B, "pass");
        trusted_evidence["result_id"] = "evidence-trusted".into();
        store
            .record_evidence(&trusted.registration_id, &bytes(&trusted_evidence))
            .unwrap();
        store.enable(&trusted.registration_id, NOW).unwrap();
        store.revoke(&trusted.registration_id, NOW).unwrap();
        assert!(store.enable(&trusted.registration_id, NOW).is_err());
    }

    #[test]
    #[allow(clippy::drop_non_drop)]
    fn historical_trust_projection_mismatch_does_not_yield_a_candidate() {
        let (mut connection, registry) = setup();
        let manifest = manifest(&registry);
        let hash = manifest["provides"][0]["contract"]["contract_hash"]
            .as_str()
            .unwrap();
        let mut store = ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
        let registration = store
            .register(
                &registry,
                &bytes(&manifest),
                BUILD_A,
                ProviderTrustStatus::LocallyTrusted,
                NOW,
            )
            .unwrap();
        store
            .record_evidence(
                &registration.registration_id,
                &bytes(&evidence(&manifest, BUILD_A, "pass")),
            )
            .unwrap();
        store.enable(&registration.registration_id, NOW).unwrap();
        assert_eq!(
            store
                .eligible_candidates("artifact.hash@1", hash, registry.snapshot_id(), NOW)
                .unwrap()
                .len(),
            1
        );
        drop(store);

        // Simulate a historical store whose trust projection was changed before
        // the new immutable guard existed. Reinstall the guard without rewriting
        // either the admission receipt or the historical row.
        connection
            .execute_batch("DROP TRIGGER provider_registration_trust_immutable_update")
            .unwrap();
        connection.execute(
            "UPDATE provider_registrations SET trust_status='organization-approved' WHERE registration_id=?1",
            [&registration.registration_id],
        ).unwrap();
        connection
            .execute_batch(include_str!(
                "../../../specs/persistence-v0.1-0013-provider-registry.sql"
            ))
            .unwrap();
        let mut store = ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
        assert!(
            store
                .eligible_candidates("artifact.hash@1", hash, registry.snapshot_id(), NOW)
                .unwrap()
                .is_empty()
        );
        assert!(store.enable(&registration.registration_id, NOW).is_err());
    }

    #[test]
    #[allow(clippy::too_many_lines, clippy::drop_non_drop)]
    fn provider_mutations_require_current_manager_lease_or_unowned_memory() {
        let (mut connection, registry) = setup();
        let manifest = manifest(&registry);
        let mut reader = ProviderStore::initialize(&mut connection).unwrap();
        assert!(
            reader
                .register(
                    &registry,
                    &bytes(&manifest),
                    BUILD_A,
                    ProviderTrustStatus::LocallyTrusted,
                    NOW,
                )
                .is_err()
        );
        drop(reader);
        let mut standalone = ProviderStore::initialize_in_memory(&mut connection).unwrap();
        let registration = standalone
            .register(
                &registry,
                &bytes(&manifest),
                BUILD_A,
                ProviderTrustStatus::LocallyTrusted,
                NOW,
            )
            .unwrap();
        let owner = StoreOwner::claim(standalone.connection, None, NOW).unwrap();
        assert!(
            standalone
                .record_evidence(
                    &registration.registration_id,
                    &bytes(&evidence(&manifest, BUILD_A, "pass")),
                )
                .is_err()
        );
        drop(standalone);
        assert!(ProviderStore::initialize_in_memory(&mut connection).is_err());
        connection
            .execute_batch(
                "CREATE TEMP TABLE aios_task_manager_startup_ready (
                nonce TEXT NOT NULL, owner_id TEXT NOT NULL, fence_epoch INTEGER NOT NULL
            );
             INSERT INTO temp.aios_task_manager_startup_ready(nonce,owner_id,fence_epoch)
             SELECT c.nonce,l.owner_id,l.fence_epoch
             FROM temp.aios_store_owner_capability c CROSS JOIN task_manager_lease l
             WHERE l.singleton_id=1;",
            )
            .unwrap();
        let mut writer = ProviderStore::initialize_writer(&mut connection, &owner).unwrap();
        let evidence_id = writer
            .record_evidence(
                &registration.registration_id,
                &bytes(&evidence(&manifest, BUILD_A, "pass")),
            )
            .unwrap();
        writer.enable(&registration.registration_id, NOW).unwrap();
        writer
            .observe_health(
                &registration.registration_id,
                &ProviderHealth {
                    status: "ready".into(),
                    checked_at: NOW.into(),
                    reason: None,
                },
            )
            .unwrap();
        writer
            .connection
            .execute(
                "UPDATE task_manager_lease SET fence_epoch=fence_epoch+1 WHERE singleton_id=1",
                [],
            )
            .unwrap();
        assert!(
            writer
                .register(
                    &registry,
                    &bytes(&manifest),
                    BUILD_B,
                    ProviderTrustStatus::LocallyTrusted,
                    NOW,
                )
                .is_err()
        );
        let mut later = evidence(&manifest, BUILD_A, "pass");
        later["result_id"] = "later-evidence".into();
        assert!(
            writer
                .record_evidence(&registration.registration_id, &bytes(&later))
                .is_err()
        );
        assert!(writer.disable(&registration.registration_id, NOW).is_err());
        assert!(writer.revoke(&registration.registration_id, NOW).is_err());
        assert!(
            writer
                .observe_health(
                    &registration.registration_id,
                    &ProviderHealth {
                        status: "degraded".into(),
                        checked_at: "2026-09-22T13:00:00Z".into(),
                        reason: None,
                    }
                )
                .is_err()
        );
        let state: String = writer
            .connection
            .query_row(
                "SELECT state FROM provider_registrations WHERE registration_id=?1",
                [&registration.registration_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "registered");
        let evidence_count: i64 = writer
            .connection
            .query_row(
                "SELECT COUNT(*) FROM provider_conformance_evidence WHERE registration_id=?1",
                [&registration.registration_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(evidence_count, 1);
        assert_eq!(evidence_id, "evidence-a");
        writer
            .connection
            .execute(
                "UPDATE provider_registrations SET state='revoked',updated_at='2026-09-22T12:00:01Z' WHERE registration_id=?1",
                [&registration.registration_id],
            )
            .unwrap();
        // An already terminal row must not turn a stale writer into success.
        assert!(writer.revoke(&registration.registration_id, NOW).is_err());
    }

    #[test]
    fn file_backed_provider_writer_cannot_omit_identity_lock() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("provider-lock.db");
        let mut connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(include_str!("../../../specs/persistence-v0.1.sql"))
            .unwrap();
        seed_test_registry_schemas(&connection);
        connection
            .execute_batch(
                "INSERT INTO task_manager_lease VALUES (1,'owner',1,'2026-09-22T00:00:00Z');",
            )
            .unwrap();
        assert!(StoreOwner::claim(&connection, None, NOW).is_err());
        assert!(ProviderStore::initialize_in_memory(&mut connection).is_err());
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "checks disabled rejection and both before/after trust sources in one binding fixture"
    )]
    fn binding_insert_requires_a_valid_text_evidence_pin() {
        let (mut connection, registry) = setup();
        let manifest = manifest(&registry);
        let registration = ProviderStore::initialize_unfenced_fixture(&mut connection)
            .unwrap()
            .register(
                &registry,
                &bytes(&manifest),
                BUILD_A,
                ProviderTrustStatus::LocallyTrusted,
                NOW,
            )
            .unwrap();
        let evidence_id = ProviderStore::initialize_unfenced_fixture(&mut connection)
            .unwrap()
            .record_evidence(
                &registration.registration_id,
                &bytes(&evidence(&manifest, BUILD_A, "pass")),
            )
            .unwrap();
        // The fixture omits Task rows so only the provider admission triggers
        // determine whether each attempted binding is accepted.
        connection
            .pragma_update(None, "foreign_keys", "OFF")
            .unwrap();
        let insert_at = |connection: &Connection,
                         suffix: &str,
                         binding_json: &str,
                         attempt: i64,
                         created_at: &str| {
            connection.execute(
                "INSERT INTO execution_bindings
                 (binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,
                  ir_version,node_id,capability,capability_contract_hash,provider_registration_id,
                  provider_id,provider_version,attempt,policy_decision_refs_json,
                  grant_refs_json,execution_profile_ref,placement_json,binding_json,created_at)
                 VALUES (?1,?2,'synthetic-task','sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         ?3,'0.1','synthetic-node','artifact.hash@1',?4,?5,?6,?7,?10,
                         '[]','[]','synthetic-profile','{}',?8,?9)",
                params![
                    format!("binding-{suffix}"),
                    format!("attempt-{suffix}"),
                    registry.snapshot_id(),
                    manifest["provides"][0]["contract"]["contract_hash"].as_str().unwrap(),
                    registration.registration_id,
                    registration.provider_id,
                    registration.provider_version,
                    binding_json,
                    created_at,
                    attempt,
                ],
            )
        };
        let insert = |connection: &Connection, suffix: &str, binding_json: &str| {
            insert_at(connection, suffix, binding_json, 1, NOW)
        };
        for (name, raw) in [
            ("malformed", "{"),
            ("missing", "{}"),
            ("null", r#"{"conformance_evidence_id":null}"#),
            ("number", r#"{"conformance_evidence_id":1}"#),
            ("array", r#"{"conformance_evidence_id":[]}"#),
            ("empty", r#"{"conformance_evidence_id":""}"#),
        ] {
            assert!(insert(&connection, name, raw).is_err(), "{name}");
        }
        assert!(
            insert(
                &connection,
                "long",
                &json!({"conformance_evidence_id": "x".repeat(257)}).to_string(),
            )
            .is_err()
        );
        let rejected: i64 = connection
            .query_row("SELECT COUNT(*) FROM execution_bindings", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(rejected, 0);
        let valid_pin = json!({"conformance_evidence_id": evidence_id,
            "provider_trust_source_id": registration.registration_id})
        .to_string();
        assert!(insert(&connection, "valid", &valid_pin).is_err());
        let unadmitted: (i64, i64) = connection
            .query_row(
                "SELECT (SELECT COUNT(*) FROM execution_binding_admission_markers),
                    (SELECT COUNT(*) FROM execution_binding_trust_markers)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(unadmitted, (0, 0));
        ProviderStore::initialize_unfenced_fixture(&mut connection)
            .unwrap()
            .enable(&registration.registration_id, NOW)
            .unwrap();
        let future_id = ProviderStore::initialize_unfenced_fixture(&mut connection)
            .unwrap()
            .admit_trust(
                &registration.registration_id,
                "future-review",
                ProviderTrustStatus::ProjectReviewed,
                "authenticated-review",
                "2026-09-22T14:00:00Z",
            )
            .unwrap();
        connection
            .pragma_update(None, "foreign_keys", "OFF")
            .unwrap();
        // A later, already stored review does not displace the original trust
        // source for a binding created before that review's effective time.
        insert(&connection, "valid", &valid_pin).unwrap();
        let marked: String = connection.query_row(
            "SELECT conformance_evidence_id FROM execution_binding_admission_markers WHERE binding_id='binding-valid'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(marked, evidence_id);
        let trust_marked: String = connection.query_row(
            "SELECT trust_source_id FROM execution_binding_trust_markers WHERE binding_id='binding-valid'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(trust_marked, registration.registration_id);
        assert!(
            insert_at(
                &connection,
                "old-source-after-review",
                &valid_pin,
                2,
                "2026-09-22T14:00:00Z"
            )
            .is_err()
        );
        let reviewed_pin = json!({"conformance_evidence_id": evidence_id,
            "provider_trust_source_id": future_id})
        .to_string();
        insert_at(
            &connection,
            "new-source-after-review",
            &reviewed_pin,
            2,
            "2026-09-22T14:00:00Z",
        )
        .unwrap();
    }

    #[test]
    #[allow(clippy::drop_non_drop)]
    fn binding_rejects_future_evidence_with_offsets_and_nanoseconds() {
        let (mut connection, registry) = setup();
        let manifest = manifest(&registry);
        let mut store = ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
        let registration = store
            .register(
                &registry,
                &bytes(&manifest),
                BUILD_A,
                ProviderTrustStatus::LocallyTrusted,
                "2026-09-22T10:00:00Z",
            )
            .unwrap();
        let mut result = evidence(&manifest, BUILD_A, "pass");
        result["executed_at"] = "2026-09-22T12:00:00.999999999+01:00".into();
        let evidence_id = store
            .record_evidence(&registration.registration_id, &bytes(&result))
            .unwrap();
        let mut next_result = evidence(&manifest, BUILD_A, "pass");
        next_result["result_id"] = "evidence-next-second".into();
        next_result["executed_at"] = "2026-09-22T11:00:01.000000001Z".into();
        let next_id = store
            .record_evidence(&registration.registration_id, &bytes(&next_result))
            .unwrap();
        store
            .enable(
                &registration.registration_id,
                "2026-09-22T11:00:00.999999999Z",
            )
            .unwrap();
        drop(store);
        connection
            .pragma_update(None, "foreign_keys", "OFF")
            .unwrap();
        let insert = |suffix: &str, created_at: &str, pin: &str, attempt: i64| {
            connection.execute(
            "INSERT INTO execution_bindings
             (binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,
              ir_version,node_id,capability,capability_contract_hash,provider_registration_id,
              provider_id,provider_version,attempt,policy_decision_refs_json,
              grant_refs_json,execution_profile_ref,placement_json,binding_json,created_at)
             VALUES (?1,?2,'synthetic-task','sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     ?3,'0.1','synthetic-node','artifact.hash@1',?4,?5,?6,?7,?10,
                     '[]','[]','synthetic-profile','{}',?8,?9)",
            params![format!("binding-{suffix}"),format!("attempt-{suffix}"),registry.snapshot_id(),
                manifest["provides"][0]["contract"]["contract_hash"].as_str().unwrap(),
                registration.registration_id,registration.provider_id,registration.provider_version,
                json!({"conformance_evidence_id":pin,
                    "provider_trust_source_id":registration.registration_id}).to_string(),created_at,attempt])
        };
        assert!(insert("before", "2026-09-22T11:00:00.999999998Z", &evidence_id, 1).is_err());
        assert!(
            insert(
                "before-next-second",
                "2026-09-22T11:00:00.999999999Z",
                &next_id,
                1
            )
            .is_err()
        );
        assert!(
            insert(
                "before-registration",
                "2026-09-22T09:59:59Z",
                &evidence_id,
                1
            )
            .is_err()
        );
        assert!(insert("malformed", "not-a-date", &evidence_id, 1).is_err());
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM execution_binding_admission_markers",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
        insert("equal", "2026-09-22T11:00:00.999999999Z", &evidence_id, 1).unwrap();
        insert("after", "2026-09-22T11:00:01Z", &evidence_id, 2).unwrap();
        assert!(
            insert(
                "stale-at-next",
                "2026-09-22T11:00:01.000000001Z",
                &evidence_id,
                3
            )
            .is_err()
        );
        insert("next-equal", "2026-09-22T11:00:01.000000001Z", &next_id, 3).unwrap();
    }

    #[test]
    #[allow(clippy::drop_non_drop)]
    #[allow(
        clippy::too_many_lines,
        reason = "checks trust-source creation, immutability, and retroactive use together"
    )]
    fn binding_trust_marker_requires_existing_review_and_pins_source() {
        let (mut connection, registry) = setup();
        let manifest = manifest(&registry);
        let mut store = ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
        let registration = store
            .register(
                &registry,
                &bytes(&manifest),
                BUILD_A,
                ProviderTrustStatus::Unverified,
                NOW,
            )
            .unwrap();
        let evidence_id = store
            .record_evidence(
                &registration.registration_id,
                &bytes(&evidence(&manifest, BUILD_A, "pass")),
            )
            .unwrap();
        drop(store);
        connection
            .pragma_update(None, "foreign_keys", "OFF")
            .unwrap();
        let insert = |connection: &Connection,
                      suffix: &str,
                      attempt: i64,
                      predicted: &str,
                      created_at: &str| {
            connection.execute(
                "INSERT INTO execution_bindings
                 (binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,
                  ir_version,node_id,capability,capability_contract_hash,provider_registration_id,
                  provider_id,provider_version,attempt,policy_decision_refs_json,
                  grant_refs_json,execution_profile_ref,placement_json,binding_json,created_at)
                 VALUES (?1,?2,'synthetic-task','sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                         ?3,'0.1','synthetic-node','artifact.hash@1',?4,?5,?6,?7,?8,
                         '[]','[]','synthetic-profile','{}',?9,?10)",
                params![format!("binding-{suffix}"),format!("attempt-{suffix}"),registry.snapshot_id(),
                    manifest["provides"][0]["contract"]["contract_hash"].as_str().unwrap(),
                    registration.registration_id,registration.provider_id,registration.provider_version,
                    attempt,json!({"conformance_evidence_id":evidence_id,
                        "provider_trust_source_id":predicted}).to_string(),created_at],
            )
        };
        assert!(insert(&connection, "before", 1, "predictable-future-decision", NOW).is_err());
        let counts: (i64, i64, i64) = connection
            .query_row(
                "SELECT (SELECT COUNT(*) FROM execution_bindings),
                    (SELECT COUNT(*) FROM execution_binding_admission_markers),
                    (SELECT COUNT(*) FROM execution_binding_trust_markers)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(counts, (0, 0, 0));
        let mut store = ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
        let first = store
            .admit_trust(
                &registration.registration_id,
                "review-one",
                ProviderTrustStatus::LocallyTrusted,
                "authenticated-review",
                "2026-09-22T12:00:00.123456789z",
            )
            .unwrap();
        store
            .enable(
                &registration.registration_id,
                "2026-09-22T12:00:00.123456789Z",
            )
            .unwrap();
        store
            .connection
            .pragma_update(None, "foreign_keys", "OFF")
            .unwrap();
        assert!(
            insert(
                &*store.connection,
                "trust-too-early",
                1,
                &first,
                "2026-09-22T12:00:00.123456788Z"
            )
            .is_err()
        );
        assert!(
            insert(
                &*store.connection,
                "wrong-trust-source",
                1,
                &registration.registration_id,
                "2026-09-22T12:00:00.123456789Z"
            )
            .is_err()
        );
        insert(
            &*store.connection,
            "first",
            1,
            &first,
            "2026-09-22T12:00:00.123456789Z",
        )
        .unwrap();
        let first_marker: String = store.connection.query_row(
            "SELECT trust_source_id FROM execution_binding_trust_markers WHERE binding_id='binding-first'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(first_marker, first);
        // The synthetic binding has no Task fixture parent. Continue through
        // this already initialized test handle rather than reopening a store
        // whose startup integrity check correctly rejects the orphan.
        let second = store
            .admit_trust(
                &registration.registration_id,
                "review-two",
                ProviderTrustStatus::ProjectReviewed,
                "authenticated-project-review",
                "2026-09-22T12:00:00.123456789Z",
            )
            .unwrap();
        store
            .connection
            .pragma_update(None, "foreign_keys", "OFF")
            .unwrap();
        insert(
            &*store.connection,
            "second",
            2,
            &second,
            "2026-09-22T12:00:00.123456790Z",
        )
        .unwrap();
        let second_marker: String = store.connection.query_row(
            "SELECT trust_source_id FROM execution_binding_trust_markers WHERE binding_id='binding-second'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(second_marker, second);
        assert_ne!(first_marker, second_marker);
        assert!(store.connection.execute(
            "UPDATE execution_binding_trust_markers SET trust_source_id=?1 WHERE binding_id='binding-first'",
            [&second],
        ).is_err());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn same_build_trust_review_appends_distinct_immutable_receipt() {
        let (mut connection, registry) = setup();
        let manifest = manifest(&registry);
        let hash = manifest["provides"][0]["contract"]["contract_hash"]
            .as_str()
            .unwrap();
        let mut store = ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
        let registration = store
            .register(
                &registry,
                &bytes(&manifest),
                BUILD_A,
                ProviderTrustStatus::Unverified,
                NOW,
            )
            .unwrap();
        let original_receipt: String = store
            .connection
            .query_row(
                "SELECT registration_json FROM provider_registrations WHERE registration_id=?1",
                [&registration.registration_id],
                |row| row.get(0),
            )
            .unwrap();
        store
            .record_evidence(
                &registration.registration_id,
                &bytes(&evidence(&manifest, BUILD_A, "pass")),
            )
            .unwrap();
        assert!(store.enable(&registration.registration_id, NOW).is_err());
        assert!(
            store
                .register(
                    &registry,
                    &bytes(&manifest),
                    BUILD_A,
                    ProviderTrustStatus::LocallyTrusted,
                    NOW
                )
                .is_err()
        );
        let id = store
            .admit_trust(
                &registration.registration_id,
                "review-1",
                ProviderTrustStatus::LocallyTrusted,
                "authenticated-local-review",
                NOW,
            )
            .unwrap();
        assert_eq!(
            store
                .admit_trust(
                    &registration.registration_id,
                    "review-1",
                    ProviderTrustStatus::LocallyTrusted,
                    "authenticated-local-review",
                    NOW
                )
                .unwrap(),
            id
        );
        assert!(
            store
                .admit_trust(
                    &registration.registration_id,
                    "review-1",
                    ProviderTrustStatus::OrganizationApproved,
                    "authenticated-local-review",
                    NOW
                )
                .is_err()
        );
        assert_eq!(
            verified_provider_effective_trust(
                store.connection,
                &registration,
                &serde_json::from_value(manifest.clone()).unwrap()
            )
            .unwrap(),
            ProviderTrustStatus::LocallyTrusted
        );
        store.enable(&registration.registration_id, NOW).unwrap();
        assert_eq!(
            store
                .eligible_candidates("artifact.hash@1", hash, registry.snapshot_id(), NOW)
                .unwrap()
                .len(),
            1
        );
        let unchanged: String = store
            .connection
            .query_row(
                "SELECT registration_json FROM provider_registrations WHERE registration_id=?1",
                [&registration.registration_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(unchanged, original_receipt);
        assert!(store.connection.execute(
            "UPDATE provider_trust_admissions SET trust_status='organization-approved' WHERE admission_id=?1",
            [&id],
        ).is_err());
        assert!(
            store
                .connection
                .execute(
                    "DELETE FROM provider_trust_admissions WHERE admission_id=?1",
                    [&id],
                )
                .is_err()
        );
        assert!(
            store
                .connection
                .execute(
                    "INSERT OR REPLACE INTO provider_trust_admissions
             SELECT * FROM provider_trust_admissions WHERE admission_id=?1",
                    [&id],
                )
                .is_err()
        );
    }

    #[test]
    fn future_trust_decision_cannot_enable_or_yield_past_candidate() {
        let (mut connection, registry) = setup();
        let manifest = manifest(&registry);
        let hash = manifest["provides"][0]["contract"]["contract_hash"]
            .as_str()
            .unwrap();
        let mut store = ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
        let registration = store
            .register(
                &registry,
                &bytes(&manifest),
                BUILD_A,
                ProviderTrustStatus::Unverified,
                NOW,
            )
            .unwrap();
        store
            .record_evidence(
                &registration.registration_id,
                &bytes(&evidence(&manifest, BUILD_A, "pass")),
            )
            .unwrap();
        let future_id = store
            .admit_trust(
                &registration.registration_id,
                "future-review",
                ProviderTrustStatus::LocallyTrusted,
                "authenticated-review",
                "2026-09-22T13:00:00Z",
            )
            .unwrap();
        let parsed: CapabilityManifest = serde_json::from_value(manifest.clone()).unwrap();
        assert_eq!(
            verified_provider_trust_source_at(
                store.connection,
                &registration,
                &parsed,
                "2026-09-22T12:30:00Z"
            )
            .unwrap(),
            (
                ProviderTrustStatus::Unverified,
                registration.registration_id.clone()
            )
        );
        assert_eq!(
            verified_provider_trust_source_at(
                store.connection,
                &registration,
                &parsed,
                "2026-09-22T13:00:00Z"
            )
            .unwrap(),
            (ProviderTrustStatus::LocallyTrusted, future_id)
        );
        assert!(
            store
                .enable(&registration.registration_id, "2026-09-22T12:30:00Z")
                .is_err()
        );
        store
            .enable(&registration.registration_id, "2026-09-22T13:00:00Z")
            .unwrap();
        assert!(
            store
                .eligible_candidates(
                    "artifact.hash@1",
                    hash,
                    registry.snapshot_id(),
                    "2026-09-22T12:30:00Z"
                )
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store
                .eligible_candidates(
                    "artifact.hash@1",
                    hash,
                    registry.snapshot_id(),
                    "2026-09-22T13:00:00Z"
                )
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn repeated_revoke_is_idempotent_but_terminal() {
        let (mut connection, registry) = setup();
        let manifest = manifest(&registry);
        let registration = ProviderStore::initialize_unfenced_fixture(&mut connection)
            .unwrap()
            .register(
                &registry,
                &bytes(&manifest),
                BUILD_A,
                ProviderTrustStatus::LocallyTrusted,
                NOW,
            )
            .unwrap();
        let original_receipt: String = connection
            .query_row(
                "SELECT registration_json FROM provider_registrations WHERE registration_id=?1",
                [&registration.registration_id],
                |row| row.get(0),
            )
            .unwrap();
        ProviderStore::initialize_unfenced_fixture(&mut connection)
            .unwrap()
            .revoke(&registration.registration_id, NOW)
            .unwrap();
        let mut reopened = ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
        reopened
            .revoke(&registration.registration_id, "2026-09-22T13:00:00Z")
            .unwrap();
        assert!(reopened.enable(&registration.registration_id, NOW).is_err());
        assert!(
            reopened
                .disable(&registration.registration_id, NOW)
                .is_err()
        );
        let current_receipt: String = reopened
            .connection
            .query_row(
                "SELECT registration_json FROM provider_registrations WHERE registration_id=?1",
                [&registration.registration_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(current_receipt, original_receipt);
    }

    #[test]
    fn trust_review_history_cannot_move_backward_in_time() {
        let (mut connection, registry) = setup();
        let manifest = manifest(&registry);
        let mut store = ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
        let registration = store
            .register(
                &registry,
                &bytes(&manifest),
                BUILD_A,
                ProviderTrustStatus::Unverified,
                NOW,
            )
            .unwrap();
        assert!(
            store
                .admit_trust(
                    &registration.registration_id,
                    "before-registration",
                    ProviderTrustStatus::LocallyTrusted,
                    "reviewer",
                    "2026-09-22T11:00:00Z"
                )
                .is_err()
        );
        let first = store
            .admit_trust(
                &registration.registration_id,
                "first-review",
                ProviderTrustStatus::LocallyTrusted,
                "reviewer",
                "2026-09-22T14:00:00Z",
            )
            .unwrap();
        assert!(
            store
                .admit_trust(
                    &registration.registration_id,
                    "backdated-review",
                    ProviderTrustStatus::ProjectReviewed,
                    "reviewer",
                    "2026-09-22T11:00:00Z"
                )
                .is_err()
        );
        assert_eq!(
            store
                .admit_trust(
                    &registration.registration_id,
                    "first-review",
                    ProviderTrustStatus::LocallyTrusted,
                    "reviewer",
                    "2026-09-22T14:00:00Z"
                )
                .unwrap(),
            first
        );
        // The complete history verifier also rejects a pre-existing direct-SQL
        // row whose timestamp moves backward despite its valid receipt hash.
        let receipt = trust_admission_receipt(
            &registration.registration_id,
            "backdated-review",
            2,
            ProviderTrustStatus::ProjectReviewed,
            "reviewer",
            "2026-09-22T11:00:00Z",
        )
        .unwrap();
        let forged_id = digest(b"AIOS-PROVIDER-TRUST-ADMISSION\0v0.1\0", receipt.as_bytes());
        store.connection.execute(
            "INSERT INTO provider_trust_admissions
             (admission_id,registration_id,decision_id,revision,trust_status,authority_ref,admitted_at,receipt_json)
             VALUES (?1,?2,'backdated-review',2,'project-reviewed','reviewer','2026-09-22T11:00:00Z',?3)",
            params![forged_id,registration.registration_id,receipt],
        ).unwrap();
        let parsed: CapabilityManifest = serde_json::from_value(manifest).unwrap();
        assert!(verified_provider_trust_source(store.connection, &registration, &parsed).is_err());
    }

    #[test]
    #[allow(clippy::drop_non_drop)]
    fn nullable_legacy_evidence_time_does_not_hide_unrelated_candidate() {
        let (mut connection, registry) = setup();
        let manifest = manifest(&registry);
        let hash = manifest["provides"][0]["contract"]["contract_hash"]
            .as_str()
            .unwrap();
        let mut store = ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
        let first = store
            .register(
                &registry,
                &bytes(&manifest),
                BUILD_A,
                ProviderTrustStatus::LocallyTrusted,
                NOW,
            )
            .unwrap();
        let second = store
            .register(
                &registry,
                &bytes(&manifest),
                BUILD_B,
                ProviderTrustStatus::LocallyTrusted,
                NOW,
            )
            .unwrap();
        let first_id = store
            .record_evidence(
                &first.registration_id,
                &bytes(&evidence(&manifest, BUILD_A, "pass")),
            )
            .unwrap();
        let mut second_result = evidence(&manifest, BUILD_B, "pass");
        second_result["result_id"] = "second-valid-result".into();
        store
            .record_evidence(&second.registration_id, &bytes(&second_result))
            .unwrap();
        store.enable(&first.registration_id, NOW).unwrap();
        store.enable(&second.registration_id, NOW).unwrap();
        drop(store);
        connection
            .execute_batch("DROP TRIGGER provider_evidence_immutable_update")
            .unwrap();
        connection
            .execute(
                "UPDATE provider_conformance_evidence SET tested_at=NULL WHERE evidence_id=?1",
                [&first_id],
            )
            .unwrap();
        connection
            .execute_batch(include_str!(
                "../../../specs/persistence-v0.1-0013-provider-registry.sql"
            ))
            .unwrap();
        let store = ProviderStore::initialize(&mut connection).unwrap();
        let candidates = store
            .eligible_candidates("artifact.hash@1", hash, registry.snapshot_id(), NOW)
            .unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].registration.registration_id,
            second.registration_id
        );
    }

    #[test]
    fn provider_migration_requires_complete_stamped_semantic_registry_first() {
        for stamp_provider in [false, true] {
            let mut connection = Connection::open_in_memory().unwrap();
            connection
                .execute_batch(include_str!("../../../specs/persistence-v0.1.sql"))
                .unwrap();
            connection.execute(
                "INSERT OR IGNORE INTO schema_migrations(migration_id,checksum,applied_at) VALUES ('0001_v0_1_trusted_control_plane','UNGENERATED-DRAFT-CHECKSUM',?1)",
                [NOW],
            ).unwrap();
            if stamp_provider {
                connection
                    .execute_batch(include_str!(
                        "../../../specs/persistence-v0.1-0013-provider-registry.sql"
                    ))
                    .unwrap();
                connection.execute(
                    "INSERT INTO schema_migrations(migration_id,checksum,applied_at) VALUES (?1,?2,?3)",
                    params![MIGRATION_ID,MIGRATION_CHECKSUM,NOW],
                ).unwrap();
            }
            assert!(matches!(
                ProviderStore::initialize_unfenced_fixture(&mut connection),
                Err(ProviderStoreError::Conflict(_))
            ));
            let semantic_stamp: i64 = connection.query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE migration_id='0012_semantic_registry_store'",
                [], |row| row.get(0),
            ).unwrap();
            assert_eq!(semantic_stamp, 0);
            if !stamp_provider {
                let provider_stamp: i64 = connection
                    .query_row(
                        "SELECT COUNT(*) FROM schema_migrations WHERE migration_id=?1",
                        [MIGRATION_ID],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(provider_stamp, 0);
            }
        }
        let (mut incomplete, _) = setup();
        incomplete
            .execute_batch("DROP TRIGGER immutable_registry_snapshot_entries_delete")
            .unwrap();
        assert!(matches!(
            ProviderStore::initialize_unfenced_fixture(&mut incomplete),
            Err(ProviderStoreError::Conflict(
                "semantic registry migration is incomplete"
            ))
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn replace_cannot_reset_revocation_or_rewrite_manifest_payload() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("immutable-registration.db");
        let (_, registry) = setup();
        let manifest = manifest(&registry);
        let mut connection = Connection::open(&database).unwrap();
        connection
            .execute_batch(include_str!("../../../specs/persistence-v0.1.sql"))
            .unwrap();
        seed_test_registry_schemas(&connection);
        RegistryStore::initialize_unfenced_fixture(&mut connection)
            .unwrap()
            .admit_registry(&registry)
            .unwrap();
        let registration = {
            let mut store = ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
            let registration = store
                .register(
                    &registry,
                    &bytes(&manifest),
                    BUILD_A,
                    ProviderTrustStatus::LocallyTrusted,
                    NOW,
                )
                .unwrap();
            assert_eq!(
                store
                    .register(
                        &registry,
                        &bytes(&manifest),
                        BUILD_A,
                        ProviderTrustStatus::LocallyTrusted,
                        NOW,
                    )
                    .unwrap()
                    .registration_id,
                registration.registration_id
            );
            store.revoke(&registration.registration_id, NOW).unwrap();
            registration
        };
        connection
            .execute_batch("PRAGMA foreign_keys=ON; PRAGMA recursive_triggers=OFF")
            .unwrap();
        let id = &registration.registration_id;
        let replace = "INSERT OR REPLACE INTO provider_registrations
            SELECT ?2,provider_id,provider_version,manifest_hash,package_content_hash,
                   registry_snapshot_id,'disabled',trust_status,registration_json,registered_at
            FROM provider_registrations WHERE registration_id=?1";
        assert!(connection.execute(replace, params![id, id]).is_err());
        let alternate_id =
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        assert!(
            connection
                .execute(replace, params![id, alternate_id])
                .is_err()
        );
        assert!(connection
            .execute(
                "INSERT OR REPLACE INTO provider_manifest_payloads(registration_id,manifest_json)
             VALUES (?1,'{}')",
                [id],
            )
            .is_err());
        drop(connection);
        let mut connection = Connection::open(&database).unwrap();
        let store = ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
        let state: String = store
            .connection
            .query_row(
                "SELECT state FROM provider_registrations WHERE registration_id=?1",
                [id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "revoked");
        assert_eq!(store.connection.query_row(
            "SELECT COUNT(*) FROM provider_registrations WHERE provider_id=?1 AND provider_version=?2 AND package_content_hash=?3",
            params![registration.provider_id,registration.provider_version,registration.build_hash],
            |row| row.get::<_, i64>(0),
        ).unwrap(), 1);
        let payload: String = store
            .connection
            .query_row(
                "SELECT manifest_json FROM provider_manifest_payloads WHERE registration_id=?1",
                [id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(payload, canonical_text(&manifest).unwrap());
        let hash = manifest["provides"][0]["contract"]["contract_hash"]
            .as_str()
            .unwrap();
        assert!(
            store
                .eligible_candidates("artifact.hash@1", hash, registry.snapshot_id(), NOW)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn replace_cannot_change_failed_evidence_into_a_pass() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("immutable-evidence.db");
        let (_, registry) = setup();
        let manifest = manifest(&registry);
        let mut connection = Connection::open(&database).unwrap();
        connection
            .execute_batch(include_str!("../../../specs/persistence-v0.1.sql"))
            .unwrap();
        seed_test_registry_schemas(&connection);
        RegistryStore::initialize_unfenced_fixture(&mut connection)
            .unwrap()
            .admit_registry(&registry)
            .unwrap();
        let registration = {
            let mut store = ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
            let registration = store
                .register(
                    &registry,
                    &bytes(&manifest),
                    BUILD_A,
                    ProviderTrustStatus::LocallyTrusted,
                    NOW,
                )
                .unwrap();
            let failed = evidence(&manifest, BUILD_A, "fail");
            store
                .record_evidence(&registration.registration_id, &bytes(&failed))
                .unwrap();
            assert_eq!(
                store
                    .record_evidence(&registration.registration_id, &bytes(&failed))
                    .unwrap(),
                "evidence-a"
            );
            registration
        };
        connection
            .execute_batch("PRAGMA foreign_keys=ON; PRAGMA recursive_triggers=OFF")
            .unwrap();
        let passing = evidence(&manifest, BUILD_A, "pass");
        assert!(
            connection
                .execute(
                    "INSERT OR REPLACE INTO provider_conformance_evidence
             SELECT evidence_id,registration_id,capability,contract_hash,suite_id,suite_hash,
                    'pass',?2,tested_at
             FROM provider_conformance_evidence WHERE evidence_id=?1",
                    params!["evidence-a", canonical_text(&passing).unwrap()],
                )
                .is_err()
        );
        drop(connection);
        let mut connection = Connection::open(&database).unwrap();
        let mut store = ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
        let (status, payload): (String, String) = store.connection.query_row(
            "SELECT status,evidence_json FROM provider_conformance_evidence WHERE evidence_id='evidence-a'",
            [], |row| Ok((row.get(0)?,row.get(1)?)),
        ).unwrap();
        assert_eq!(status, "fail");
        assert_eq!(
            payload,
            canonical_text(&evidence(&manifest, BUILD_A, "fail")).unwrap()
        );
        assert!(store.enable(&registration.registration_id, NOW).is_err());
        let hash = manifest["provides"][0]["contract"]["contract_hash"]
            .as_str()
            .unwrap();
        assert!(
            store
                .eligible_candidates("artifact.hash@1", hash, registry.snapshot_id(), NOW)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn unstamped_provider_duplicate_guard_is_not_silently_adopted() {
        for (name, table) in [
            (
                "provider_registration_no_duplicate_insert",
                "provider_registrations",
            ),
            (
                "provider_evidence_no_duplicate_insert",
                "provider_conformance_evidence",
            ),
            (
                "execution_binding_admission_marker_insert",
                "execution_bindings",
            ),
        ] {
            let (mut connection, _) = setup_with_provider_migration(false);
            connection
                .execute_batch(&format!(
                    "CREATE TRIGGER {name} BEFORE INSERT ON {table} BEGIN SELECT 1; END;"
                ))
                .unwrap();
            assert!(matches!(
                ProviderStore::initialize_unfenced_fixture(&mut connection),
                Err(ProviderStoreError::Conflict(
                    "provider guard exists without migration stamp"
                ))
            ));
        }
        let (mut connection, _) = setup_with_provider_migration(false);
        connection
            .execute_batch(
                "CREATE TABLE execution_binding_admission_markers (
                binding_id TEXT PRIMARY KEY, conformance_evidence_id TEXT NOT NULL)",
            )
            .unwrap();
        assert!(matches!(
            ProviderStore::initialize_unfenced_fixture(&mut connection),
            Err(ProviderStoreError::Conflict(
                "provider guard exists without migration stamp"
            ))
        ));
    }

    #[test]
    fn stamped_provider_store_rejects_same_name_noop_marker_guard() {
        let (mut connection, _) = setup();
        ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
        connection
            .execute_batch(
                "DROP TRIGGER execution_binding_admission_marker_insert;
             CREATE TRIGGER execution_binding_admission_marker_insert
             BEFORE INSERT ON execution_bindings BEGIN SELECT 1; END;",
            )
            .unwrap();
        assert!(matches!(
            ProviderStore::initialize_unfenced_fixture(&mut connection),
            Err(ProviderStoreError::Conflict(
                "provider additive guard definition differs"
            ))
        ));
    }

    #[test]
    fn stamped_provider_store_rejects_same_name_noop_legacy_evidence_guard() {
        let (mut connection, _) = setup();
        ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
        connection
            .execute_batch(
                "DROP TRIGGER provider_evidence_immutable_update;
                 CREATE TRIGGER provider_evidence_immutable_update
                 BEFORE UPDATE ON provider_conformance_evidence BEGIN SELECT 1; END;",
            )
            .unwrap();
        assert!(matches!(
            ProviderStore::initialize_unfenced_fixture(&mut connection),
            Err(ProviderStoreError::Conflict(
                "provider additive guard definition differs"
            ))
        ));
    }

    #[test]
    fn same_evidence_id_rejects_corrupt_legacy_projection() {
        for (column, changed) in [
            ("capability", "table.normalize@1"),
            ("contract_hash", BUILD_B),
            ("suite_id", "conformance://wrong/1"),
            ("suite_hash", BUILD_B),
            ("status", "fail"),
            ("tested_at", "2026-09-22T11:00:00.500Z"),
        ] {
            let (mut connection, registry) = setup();
            let manifest = manifest(&registry);
            let result = evidence(&manifest, BUILD_A, "pass");
            let (registration, id) = {
                let mut store =
                    ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
                let registration = store
                    .register(
                        &registry,
                        &bytes(&manifest),
                        BUILD_A,
                        ProviderTrustStatus::LocallyTrusted,
                        NOW,
                    )
                    .unwrap();
                let id = store
                    .record_evidence(&registration.registration_id, &bytes(&result))
                    .unwrap();
                (registration, id)
            };
            connection
                .execute_batch("DROP TRIGGER provider_evidence_immutable_update")
                .unwrap();
            connection
                .execute(
                    &format!(
                        "UPDATE provider_conformance_evidence SET {column}=?2 WHERE evidence_id=?1"
                    ),
                    params![id, changed],
                )
                .unwrap();
            connection
                .execute_batch(include_str!(
                    "../../../specs/persistence-v0.1-0013-provider-registry.sql"
                ))
                .unwrap();
            let mut reopened = ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
            assert!(
                matches!(
                    reopened.record_evidence(&registration.registration_id, &bytes(&result)),
                    Err(ProviderStoreError::Conflict(_))
                ),
                "{column}"
            );
            let retained: String = reopened
                .connection
                .query_row(
                    &format!(
                        "SELECT {column} FROM provider_conformance_evidence WHERE evidence_id=?1"
                    ),
                    [&id],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(retained, changed, "{column}");
        }
    }

    #[test]
    fn reused_registration_rejects_corrupt_immutable_receipt() {
        for malformed in [true, false] {
            let (mut connection, registry) = setup();
            let manifest = manifest(&registry);
            let registration = ProviderStore::initialize_unfenced_fixture(&mut connection)
                .unwrap()
                .register(
                    &registry,
                    &bytes(&manifest),
                    BUILD_A,
                    ProviderTrustStatus::LocallyTrusted,
                    NOW,
                )
                .unwrap();
            let original: String = connection
                .query_row(
                    "SELECT registration_json FROM provider_registrations WHERE registration_id=?1",
                    [&registration.registration_id],
                    |row| row.get(0),
                )
                .unwrap();
            let corrupted = if malformed {
                "{}".to_owned()
            } else {
                let mut receipt: Value = serde_json::from_str(&original).unwrap();
                receipt["capabilities"][0]["contract_hash"] = BUILD_B.into();
                canonical_text(&receipt).unwrap()
            };
            // Model a legacy damaged row, then restore the 0013 immutability
            // trigger before reopening and attempting same-build reuse.
            connection
                .execute_batch("DROP TRIGGER provider_registration_identity_immutable")
                .unwrap();
            connection.execute(
                "UPDATE provider_registrations SET registration_json=?2 WHERE registration_id=?1",
                params![registration.registration_id,corrupted],
            ).unwrap();
            connection
                .execute_batch(include_str!(
                    "../../../specs/persistence-v0.1-0013-provider-registry.sql"
                ))
                .unwrap();
            let mut store = ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
            assert!(
                store
                    .register(
                        &registry,
                        &bytes(&manifest),
                        BUILD_A,
                        ProviderTrustStatus::LocallyTrusted,
                        NOW,
                    )
                    .is_err()
            );
            let count: i64 = store
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM provider_registrations WHERE registration_id=?1",
                    [&registration.registration_id],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1);
        }
    }

    #[test]
    fn legacy_same_build_retry_rolls_back_new_payload_when_receipt_is_corrupt() {
        let (mut connection, registry) = setup();
        let manifest = manifest(&registry);
        let registration = ProviderStore::initialize_unfenced_fixture(&mut connection)
            .unwrap()
            .register(
                &registry,
                &bytes(&manifest),
                BUILD_A,
                ProviderTrustStatus::LocallyTrusted,
                NOW,
            )
            .unwrap();
        // Model a legacy registration row before 0013 acquired a manifest
        // payload, with a corrupted immutable admission receipt.
        connection
            .execute_batch(
                "DROP TRIGGER provider_manifest_payload_immutable_delete;
             DROP TRIGGER provider_registration_identity_immutable;",
            )
            .unwrap();
        connection
            .execute(
                "DELETE FROM provider_manifest_payloads WHERE registration_id=?1",
                [&registration.registration_id],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE provider_registrations SET registration_json='{}' WHERE registration_id=?1",
                [&registration.registration_id],
            )
            .unwrap();
        connection
            .execute_batch(include_str!(
                "../../../specs/persistence-v0.1-0013-provider-registry.sql"
            ))
            .unwrap();
        let mut store = ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
        assert!(matches!(
            store.register(
                &registry,
                &bytes(&manifest),
                BUILD_A,
                ProviderTrustStatus::LocallyTrusted,
                NOW,
            ),
            Err(ProviderStoreError::Json(_) | ProviderStoreError::Conflict(_))
        ));
        let payloads: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM provider_manifest_payloads WHERE registration_id=?1",
                [&registration.registration_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(payloads, 0, "failed reuse must roll back the new payload");
    }

    #[test]
    fn registration_rejects_contracts_without_evidence_ready_suite_identity() {
        let (mut connection, first) = setup();
        for missing_version in [false, true] {
            let incomplete = missing_suite_identity(&first, missing_version);
            RegistryStore::initialize_unfenced_fixture(&mut connection)
                .unwrap()
                .admit_registry(&incomplete)
                .unwrap();
            let mut manifest = manifest(&incomplete);
            if !missing_version {
                manifest["provides"][0]["conformance"]["suite_hash"] = Value::Null;
            }
            let mut store = ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
            assert!(matches!(
                store.register(
                    &incomplete,
                    &bytes(&manifest),
                    BUILD_A,
                    ProviderTrustStatus::LocallyTrusted,
                    NOW
                ),
                Err(ProviderStoreError::Invalid(
                    "complete suite version and hash are required for registration"
                ))
            ));
        }
    }

    #[test]
    fn concurrent_health_writes_keep_latest_instant_at_nanosecond_precision() {
        use std::sync::{Arc, Barrier};
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("provider-health.db");
        let (_, registry) = setup();
        let registration_id = {
            let mut connection = Connection::open(&database).unwrap();
            connection
                .execute_batch(include_str!("../../../specs/persistence-v0.1.sql"))
                .unwrap();
            seed_test_registry_schemas(&connection);
            RegistryStore::initialize_unfenced_fixture(&mut connection)
                .unwrap()
                .admit_registry(&registry)
                .unwrap();
            ProviderStore::initialize_unfenced_fixture(&mut connection)
                .unwrap()
                .register(
                    &registry,
                    &bytes(&manifest(&registry)),
                    BUILD_A,
                    ProviderTrustStatus::LocallyTrusted,
                    NOW,
                )
                .unwrap()
                .registration_id
        };
        let barrier = Arc::new(Barrier::new(3));
        let mut threads = Vec::new();
        for (status, checked_at) in [
            ("degraded", "2026-09-22T12:00:00.123456788Z"),
            ("ready", "2026-09-22T05:00:00.123456789-07:00"),
        ] {
            let barrier = Arc::clone(&barrier);
            let database = database.clone();
            let registration_id = registration_id.clone();
            threads.push(std::thread::spawn(move || {
                let mut connection = Connection::open(database).unwrap();
                let mut store =
                    ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
                barrier.wait();
                store
                    .observe_health(
                        &registration_id,
                        &ProviderHealth {
                            status: status.into(),
                            checked_at: checked_at.into(),
                            reason: None,
                        },
                    )
                    .unwrap();
            }));
        }
        barrier.wait();
        for thread in threads {
            thread.join().unwrap();
        }
        let mut connection = Connection::open(&database).unwrap();
        let store = ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
        assert_eq!(
            store.health(&registration_id).unwrap().unwrap().status,
            "ready"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn concurrent_snapshot_revocation_precedes_registration_admission() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::mpsc;
        use std::time::Instant;

        static WAITING_FOR_WRITER: AtomicBool = AtomicBool::new(false);
        fn signal_busy(_count: i32) -> bool {
            WAITING_FOR_WRITER.store(true, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(1));
            true
        }

        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("registration-race.db");
        let (_, first) = setup();
        let second = snapshot_change(&first, "table.normalize");
        let first_manifest = manifest(&first);
        let first_id = first.snapshot_id().to_owned();
        let mut writer = Connection::open(&database).unwrap();
        writer
            .execute_batch(include_str!("../../../specs/persistence-v0.1.sql"))
            .unwrap();
        seed_test_registry_schemas(&writer);
        RegistryStore::initialize_unfenced_fixture(&mut writer)
            .unwrap()
            .admit_registry(&first)
            .unwrap();
        RegistryStore::initialize_unfenced_fixture(&mut writer)
            .unwrap()
            .admit_registry(&second)
            .unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (start_tx, start_rx) = mpsc::channel();
        let worker_database = database.clone();
        WAITING_FOR_WRITER.store(false, Ordering::SeqCst);
        let worker = std::thread::spawn(move || {
            let mut connection = Connection::open(worker_database).unwrap();
            let mut store = ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
            store.connection.busy_handler(Some(signal_busy)).unwrap();
            ready_tx.send(()).unwrap();
            start_rx.recv().unwrap();
            matches!(
                store.register(
                    &first,
                    &bytes(&first_manifest),
                    BUILD_A,
                    ProviderTrustStatus::LocallyTrusted,
                    NOW,
                ),
                Err(ProviderStoreError::Invalid(
                    "semantic snapshot has not been admitted"
                ))
            )
        });
        ready_rx.recv().unwrap();
        let transaction = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        transaction
            .execute(
                "UPDATE registry_snapshot_admissions SET state='REVOKED' WHERE snapshot_id=?1",
                [&first_id],
            )
            .unwrap();
        start_tx.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !WAITING_FOR_WRITER.load(Ordering::SeqCst) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(WAITING_FOR_WRITER.load(Ordering::SeqCst));
        transaction.commit().unwrap();
        assert!(worker.join().unwrap());
        let count: i64 = writer
            .query_row("SELECT COUNT(*) FROM provider_registrations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0);
        let mut store = ProviderStore::initialize_unfenced_fixture(&mut writer).unwrap();
        store
            .register(
                &second,
                &bytes(&manifest(&second)),
                BUILD_A,
                ProviderTrustStatus::LocallyTrusted,
                NOW,
            )
            .unwrap();
    }

    #[test]
    fn candidate_reads_reject_impossible_revocation_enablement_interleaving() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("candidate-snapshot.db");
        let (_, registry) = setup();
        let manifest = manifest(&registry);
        let hash = manifest["provides"][0]["contract"]["contract_hash"]
            .as_str()
            .unwrap()
            .to_owned();
        let mut connection = Connection::open(&database).unwrap();
        connection.execute_batch("PRAGMA journal_mode=WAL").unwrap();
        connection
            .execute_batch(include_str!("../../../specs/persistence-v0.1.sql"))
            .unwrap();
        seed_test_registry_schemas(&connection);
        RegistryStore::initialize_unfenced_fixture(&mut connection)
            .unwrap()
            .admit_registry(&registry)
            .unwrap();
        let mut store = ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
        let registration = store
            .register(
                &registry,
                &bytes(&manifest),
                BUILD_A,
                ProviderTrustStatus::LocallyTrusted,
                NOW,
            )
            .unwrap();
        store
            .record_evidence(
                &registration.registration_id,
                &bytes(&evidence(&manifest, BUILD_A, "pass")),
            )
            .unwrap();
        let writer = Connection::open(&database).unwrap();
        let disabled_view = store
            .eligible_candidates_after_selection(
                "artifact.hash@1",
                &hash,
                registry.snapshot_id(),
                "2026-09-22T12:00:01Z",
                || {
                    writer.execute(
                        "UPDATE provider_registrations SET state='registered',updated_at='2026-09-22T12:00:01Z' WHERE registration_id=?1",
                        [&registration.registration_id],
                    ).unwrap();
                },
            )
            .unwrap();
        assert!(disabled_view.is_empty());
        assert_eq!(
            store
                .eligible_candidates(
                    "artifact.hash@1",
                    &hash,
                    registry.snapshot_id(),
                    "2026-09-22T12:00:01Z",
                )
                .unwrap()
                .len(),
            1
        );
        writer.execute(
            "UPDATE provider_registrations SET state='disabled',updated_at='2026-09-22T12:00:02Z' WHERE registration_id=?1",
            [&registration.registration_id],
        ).unwrap();
        let visible = store
            .eligible_candidates_after_selection(
                "artifact.hash@1",
                &hash,
                registry.snapshot_id(),
                "2026-09-22T12:00:03Z",
                || {
                    writer.execute_batch("BEGIN IMMEDIATE").unwrap();
                    writer
                        .execute(
                            "UPDATE registry_snapshot_admissions SET state='REVOKED' WHERE snapshot_id=?1",
                            [registry.snapshot_id()],
                        )
                        .unwrap();
                    writer.execute(
                        "UPDATE provider_registrations SET state='registered',updated_at='2026-09-22T12:00:03Z' WHERE registration_id=?1",
                        [&registration.registration_id],
                    ).unwrap();
                    writer.execute_batch("COMMIT").unwrap();
                },
            )
            .unwrap();
        assert!(visible.is_empty());
        assert!(
            store
                .eligible_candidates(
                    "artifact.hash@1",
                    &hash,
                    registry.snapshot_id(),
                    "2026-09-22T12:00:03Z",
                )
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn repeated_provider_state_calls_preserve_transition_time() {
        let (mut connection, registry) = setup();
        let mut store = ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
        let manifest = manifest(&registry);
        let registration = store
            .register(
                &registry,
                &bytes(&manifest),
                BUILD_A,
                ProviderTrustStatus::LocallyTrusted,
                NOW,
            )
            .unwrap();
        store
            .disable(&registration.registration_id, "2026-09-22T13:00:00Z")
            .unwrap();
        store
            .record_evidence(
                &registration.registration_id,
                &bytes(&evidence(&manifest, BUILD_A, "pass")),
            )
            .unwrap();
        store.enable(&registration.registration_id, NOW).unwrap();
        store
            .enable(&registration.registration_id, "2026-09-22T13:00:00Z")
            .unwrap();
        let updated: String = store
            .connection
            .query_row(
                "SELECT updated_at FROM provider_registrations WHERE registration_id=?1",
                [&registration.registration_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(updated, NOW);
        store
            .revoke(&registration.registration_id, "2026-09-22T13:00:00Z")
            .unwrap();
        store
            .revoke(&registration.registration_id, "2026-09-22T14:00:00Z")
            .unwrap();
        let revoked_at: String = store
            .connection
            .query_row(
                "SELECT updated_at FROM provider_registrations WHERE registration_id=?1",
                [&registration.registration_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(revoked_at, "2026-09-22T13:00:00Z");
    }

    #[test]
    fn candidate_cannot_precede_provider_enablement_time() {
        let (mut connection, registry) = setup();
        let manifest = manifest(&registry);
        let hash = manifest["provides"][0]["contract"]["contract_hash"]
            .as_str()
            .unwrap();
        let mut store = ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
        let registration = store
            .register(
                &registry,
                &bytes(&manifest),
                BUILD_A,
                ProviderTrustStatus::LocallyTrusted,
                "2026-09-22T10:00:00Z",
            )
            .unwrap();
        store
            .record_evidence(
                &registration.registration_id,
                &bytes(&evidence(&manifest, BUILD_A, "pass")),
            )
            .unwrap();
        store.enable(&registration.registration_id, NOW).unwrap();
        assert!(
            store
                .eligible_candidates(
                    "artifact.hash@1",
                    hash,
                    registry.snapshot_id(),
                    "2026-09-22T13:30:00+02:00",
                )
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store
                .eligible_candidates(
                    "artifact.hash@1",
                    hash,
                    registry.snapshot_id(),
                    "2026-09-22T13:00:00+01:00",
                )
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn same_build_is_reused_across_snapshots_with_unchanged_claimed_contract() {
        let (mut connection, first) = setup();
        let second = snapshot_change(&first, "table.normalize");
        let changed_claim = snapshot_change(&first, "artifact.hash");
        assert_ne!(first.snapshot_id(), second.snapshot_id());
        RegistryStore::initialize_unfenced_fixture(&mut connection)
            .unwrap()
            .admit_registry(&second)
            .unwrap();
        RegistryStore::initialize_unfenced_fixture(&mut connection)
            .unwrap()
            .admit_registry(&changed_claim)
            .unwrap();
        let manifest = manifest(&first);
        let hash = manifest["provides"][0]["contract"]["contract_hash"]
            .as_str()
            .unwrap()
            .to_owned();
        let original = {
            let mut store = ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
            let original = store
                .register(
                    &first,
                    &bytes(&manifest),
                    BUILD_A,
                    ProviderTrustStatus::LocallyTrusted,
                    NOW,
                )
                .unwrap();
            store
                .record_evidence(
                    &original.registration_id,
                    &bytes(&evidence(&manifest, BUILD_A, "pass")),
                )
                .unwrap();
            store.enable(&original.registration_id, NOW).unwrap();
            let reused = store
                .register(
                    &second,
                    &bytes(&manifest),
                    BUILD_A,
                    ProviderTrustStatus::Unverified,
                    "2026-09-22T13:00:00Z",
                )
                .unwrap();
            assert_eq!(reused, original);
            let candidates = store
                .eligible_candidates("artifact.hash@1", &hash, second.snapshot_id(), NOW)
                .unwrap();
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].registration.snapshot_id, first.snapshot_id());
            assert_eq!(candidates[0].requested_snapshot_id, second.snapshot_id());
            assert!(
                store
                    .eligible_candidates("artifact.hash@1", BUILD_B, second.snapshot_id(), NOW)
                    .unwrap()
                    .is_empty()
            );
            assert!(
                store
                    .eligible_candidates("artifact.hash@1", &hash, changed_claim.snapshot_id(), NOW)
                    .unwrap()
                    .is_empty()
            );
            assert!(
                store
                    .register(
                        &changed_claim,
                        &bytes(&manifest),
                        BUILD_A,
                        ProviderTrustStatus::LocallyTrusted,
                        NOW
                    )
                    .is_err()
            );
            original
        };
        for (state, visible) in [
            (SnapshotState::Deprecated, 1),
            (SnapshotState::Quarantined, 0),
            (SnapshotState::Revoked, 0),
        ] {
            RegistryStore::initialize_unfenced_fixture(&mut connection)
                .unwrap()
                .set_snapshot_state(first.snapshot_id(), state)
                .unwrap();
            let mut store = ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
            assert_eq!(
                store
                    .eligible_candidates("artifact.hash@1", &hash, second.snapshot_id(), NOW)
                    .unwrap()
                    .len(),
                visible
            );
            if state == SnapshotState::Revoked {
                store.revoke(&original.registration_id, NOW).unwrap();
                assert!(
                    store
                        .eligible_candidates("artifact.hash@1", &hash, second.snapshot_id(), NOW)
                        .unwrap()
                        .is_empty()
                );
            }
        }
    }

    #[test]
    fn latest_exact_result_controls_failure_expiry_and_renewal() {
        let (mut connection, registry) = setup();
        let mut store = ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
        let manifest = manifest(&registry);
        let registration = store
            .register(
                &registry,
                &bytes(&manifest),
                BUILD_A,
                ProviderTrustStatus::LocallyTrusted,
                NOW,
            )
            .unwrap();
        let hash = manifest["provides"][0]["contract"]["contract_hash"]
            .as_str()
            .unwrap();
        let candidates = |store: &ProviderStore<'_>, at| {
            store
                .eligible_candidates("artifact.hash@1", hash, registry.snapshot_id(), at)
                .unwrap()
        };
        store
            .record_evidence(
                &registration.registration_id,
                &bytes(&evidence(&manifest, BUILD_A, "pass")),
            )
            .unwrap();
        store.enable(&registration.registration_id, NOW).unwrap();
        assert_eq!(candidates(&store, NOW).len(), 1);
        let mut failure = evidence(&manifest, BUILD_A, "fail");
        failure["result_id"] = "evidence-fail".into();
        failure["executed_at"] = "2026-09-22T12:30:00Z".into();
        store
            .record_evidence(&registration.registration_id, &bytes(&failure))
            .unwrap();
        assert!(candidates(&store, "2026-09-22T13:00:00Z").is_empty());
        let mut renewed = evidence(&manifest, BUILD_A, "pass");
        renewed["result_id"] = "evidence-renewed".into();
        renewed["executed_at"] = "2026-09-22T13:30:00Z".into();
        renewed["expires_at"] = "2026-09-22T15:00:00Z".into();
        store
            .record_evidence(&registration.registration_id, &bytes(&renewed))
            .unwrap();
        assert_eq!(
            candidates(&store, "2026-09-22T14:00:00Z")[0].evidence_id,
            "evidence-renewed"
        );
        assert!(candidates(&store, "2026-09-22T15:00:00Z").is_empty());
        let mut after_expiry = renewed.clone();
        after_expiry["result_id"] = "evidence-after-expiry".into();
        after_expiry["executed_at"] = "2026-09-22T16:00:00Z".into();
        after_expiry["expires_at"] = "2026-09-23T16:00:00Z".into();
        store
            .record_evidence(&registration.registration_id, &bytes(&after_expiry))
            .unwrap();
        assert_eq!(
            candidates(&store, "2026-09-22T16:10:00Z")[0].evidence_id,
            "evidence-after-expiry"
        );
    }

    #[test]
    fn same_capability_hash_does_not_reuse_incompatible_type_representation() {
        let (mut connection, first) = setup();
        let second = type_representation_change(&first);
        assert_eq!(
            first.capability_contract_hash("artifact.hash", 1),
            second.capability_contract_hash("artifact.hash", 1)
        );
        RegistryStore::initialize_unfenced_fixture(&mut connection)
            .unwrap()
            .admit_registry(&second)
            .unwrap();
        let mut manifest = manifest(&first);
        manifest["provides"][0]["representations"]["source"] = json!(["artifact-handle"]);
        let mut store = ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
        let registration = store
            .register(
                &first,
                &bytes(&manifest),
                BUILD_A,
                ProviderTrustStatus::LocallyTrusted,
                NOW,
            )
            .unwrap();
        store
            .record_evidence(
                &registration.registration_id,
                &bytes(&evidence(&manifest, BUILD_A, "pass")),
            )
            .unwrap();
        store.enable(&registration.registration_id, NOW).unwrap();
        let hash = manifest["provides"][0]["contract"]["contract_hash"]
            .as_str()
            .unwrap();
        assert_eq!(
            store
                .eligible_candidates("artifact.hash@1", hash, first.snapshot_id(), NOW)
                .unwrap()
                .len(),
            1
        );
        assert!(
            store
                .eligible_candidates("artifact.hash@1", hash, second.snapshot_id(), NOW)
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            store.register(
                &second,
                &bytes(&manifest),
                BUILD_A,
                ProviderTrustStatus::LocallyTrusted,
                NOW
            ),
            Err(ProviderStoreError::StaticCompatibility(_))
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn unrelated_claim_change_or_failure_does_not_hide_valid_claim() {
        let (mut connection, first) = setup();
        let second = snapshot_change(&first, "table.normalize");
        RegistryStore::initialize_unfenced_fixture(&mut connection)
            .unwrap()
            .admit_registry(&second)
            .unwrap();
        let manifest = two_claim_manifest(&first);
        let mut store = ProviderStore::initialize_unfenced_fixture(&mut connection).unwrap();
        let registration = store
            .register(
                &first,
                &bytes(&manifest),
                BUILD_A,
                ProviderTrustStatus::LocallyTrusted,
                NOW,
            )
            .unwrap();
        let hash_a = manifest["provides"][0]["contract"]["contract_hash"]
            .as_str()
            .unwrap();
        let hash_b = manifest["provides"][1]["contract"]["contract_hash"]
            .as_str()
            .unwrap();
        let a = evidence(&manifest, BUILD_A, "pass");
        store
            .record_evidence(&registration.registration_id, &bytes(&a))
            .unwrap();
        let mut b = evidence(&manifest, BUILD_A, "pass");
        b["result_id"] = "evidence-b-pass".into();
        b["semantic_capability_ref"] = "table.normalize@1".into();
        b["semantic_contract_hash"] = hash_b.into();
        b["conformance_suite"]["id"] = "conformance://table.normalize/1".into();
        b["conformance_suite"]["hash"] = SUITE_HASH_B.into();
        store
            .record_evidence(&registration.registration_id, &bytes(&b))
            .unwrap();
        store.enable(&registration.registration_id, NOW).unwrap();
        assert_eq!(
            store
                .eligible_candidates("artifact.hash@1", hash_a, second.snapshot_id(), NOW)
                .unwrap()
                .len(),
            1
        );
        assert!(
            store
                .eligible_candidates("table.normalize@1", hash_b, second.snapshot_id(), NOW)
                .unwrap()
                .is_empty()
        );
        let mut b_fail = b.clone();
        b_fail["result_id"] = "evidence-b-fail".into();
        b_fail["result"] = "fail".into();
        b_fail["executed_at"] = "2026-09-22T12:15:00Z".into();
        store
            .record_evidence(&registration.registration_id, &bytes(&b_fail))
            .unwrap();
        assert_eq!(
            store
                .eligible_candidates(
                    "artifact.hash@1",
                    hash_a,
                    second.snapshot_id(),
                    "2026-09-22T12:16:00Z"
                )
                .unwrap()
                .len(),
            1
        );
        assert!(
            store
                .eligible_candidates(
                    "table.normalize@1",
                    hash_b,
                    first.snapshot_id(),
                    "2026-09-22T12:16:00Z"
                )
                .unwrap()
                .is_empty()
        );
        let mut b_renewed = b.clone();
        b_renewed["result_id"] = "evidence-b-renewed".into();
        b_renewed["executed_at"] = "2026-09-22T12:20:00Z".into();
        store
            .record_evidence(&registration.registration_id, &bytes(&b_renewed))
            .unwrap();
        let mut a_fail = a.clone();
        a_fail["result_id"] = "evidence-a-fail".into();
        a_fail["result"] = "fail".into();
        a_fail["executed_at"] = "2026-09-22T12:30:00Z".into();
        store
            .record_evidence(&registration.registration_id, &bytes(&a_fail))
            .unwrap();
        assert!(
            store
                .eligible_candidates(
                    "artifact.hash@1",
                    hash_a,
                    second.snapshot_id(),
                    "2026-09-22T12:31:00Z"
                )
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store
                .eligible_candidates(
                    "table.normalize@1",
                    hash_b,
                    first.snapshot_id(),
                    "2026-09-22T12:31:00Z"
                )
                .unwrap()
                .len(),
            1
        );
    }
}
