//! Local immutable Artifact storage owned by the authoritative Task Manager.

#![allow(
    clippy::missing_errors_doc,
    reason = "the crate-level public DTO/API documentation is tracked with the daemon integration"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

#[cfg(not(unix))]
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions as CapOpenOptions};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::{
    Actor, Clock, Result, SCHEMA_VERSION, StoreIdentity, StoreLock, TaskManager, TaskManagerError,
    append_event, assert_manager_lease, canonical_json, provenance_hash,
};

const IMPORT_LIMIT: u64 = 8 * 1024 * 1024 * 1024;
const COPY_BUFFER_SIZE: usize = 64 * 1024;
const SEALED_STAGING_VERSION: u8 = 1;
const PHASE_AUTHENTICATED_EXPORT_INTENT_VERSION: u8 = 2;

fn deserialize_omittable_non_null<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Sensitivity {
    Public,
    Local,
    Private,
    Confidential,
    Secret,
}

impl Sensitivity {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Local => "local",
            Self::Private => "private",
            Self::Confidential => "confidential",
            Self::Secret => "secret",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        serde_json::from_value(serde_json::Value::String(value.to_owned())).map_err(Into::into)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RetentionClass {
    Ephemeral,
    Task,
    Persistent,
    UserManaged,
}

impl RetentionClass {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Ephemeral => "ephemeral",
            Self::Task => "task",
            Self::Persistent => "persistent",
            Self::UserManaged => "user-managed",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        serde_json::from_value(serde_json::Value::String(value.to_owned())).map_err(Into::into)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ArtifactAllocationState {
    Allocated,
    Writing,
    Finalizing,
    Published,
    Aborted,
    Expired,
    Failed,
}

impl ArtifactAllocationState {
    fn parse(value: &str) -> Result<Self> {
        serde_json::from_value(serde_json::Value::String(value.to_owned())).map_err(Into::into)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ArtifactExpectedState {
    Writing,
    Finalizing,
}

impl ArtifactExpectedState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Writing => "WRITING",
            Self::Finalizing => "FINALIZING",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArtifactOriginKind {
    User,
    Task,
    Provider,
    System,
    Remote,
    Legacy,
}

impl ArtifactOriginKind {
    fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Task => "task",
            Self::Provider => "provider",
            Self::System => "system",
            Self::Remote => "remote",
            Self::Legacy => "legacy",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        serde_json::from_value(serde_json::Value::String(value.to_owned())).map_err(Into::into)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentHash {
    pub algorithm: String,
    pub value: String,
}

impl ContentHash {
    fn from_tagged(tagged: &str) -> Result<Self> {
        let value = tagged
            .strip_prefix("sha256:")
            .ok_or(TaskManagerError::InvalidRecord(
                "stored Artifact content hash is not canonical SHA-256",
            ))?;
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(TaskManagerError::InvalidRecord(
                "stored Artifact content hash is not canonical SHA-256",
            ));
        }
        Ok(Self {
            algorithm: "sha256".to_owned(),
            value: value.to_owned(),
        })
    }

    pub fn tagged(&self) -> String {
        format!("{}:{}", self.algorithm, self.value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ArtifactUri(String);

impl ArtifactUri {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn new(artifact_id: &str) -> Self {
        Self(format!("artifact://{artifact_id}"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactOrigin {
    pub kind: ArtifactOriginKind,
    pub task_id: Option<String>,
    pub semantic_program_hash: Option<String>,
    pub step_id: Option<String>,
    pub execution_binding_id: Option<String>,
    pub provider_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArtifactIntegrityState {
    Unknown,
    Pending,
    Verified,
    Failed,
}

impl ArtifactIntegrityState {
    fn parse(value: &str) -> Result<Self> {
        serde_json::from_value(serde_json::Value::String(value.to_owned())).map_err(Into::into)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactIntegrity {
    #[serde(
        default,
        deserialize_with = "deserialize_omittable_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub state: Option<ArtifactIntegrityState>,
    pub verified_at: Option<String>,
    pub verifier: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRetention {
    #[serde(
        default,
        deserialize_with = "deserialize_omittable_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub class: Option<RetentionClass>,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactHandle {
    pub artifact_id: String,
    pub uri: ArtifactUri,
    pub semantic_type: Option<String>,
    pub media_type: String,
    pub format: Option<String>,
    pub size_bytes: Option<u64>,
    pub content_hash: Option<ContentHash>,
    pub origin: ArtifactOrigin,
    pub sensitivity: Sensitivity,
    #[serde(
        default,
        deserialize_with = "deserialize_omittable_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub retention: Option<ArtifactRetention>,
    #[serde(
        default,
        deserialize_with = "deserialize_omittable_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub integrity: Option<ArtifactIntegrity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    pub created_at: Option<String>,
}

impl ArtifactHandle {
    fn stored_size_bytes(&self) -> Result<u64> {
        self.size_bytes.ok_or(TaskManagerError::InvalidRecord(
            "stored Artifact size is missing",
        ))
    }

    fn stored_content_hash(&self) -> Result<&ContentHash> {
        self.content_hash
            .as_ref()
            .ok_or(TaskManagerError::InvalidRecord(
                "stored Artifact content hash is missing",
            ))
    }

    fn stored_integrity_state(&self) -> Result<ArtifactIntegrityState> {
        self.integrity
            .as_ref()
            .and_then(|integrity| integrity.state)
            .ok_or(TaskManagerError::InvalidRecord(
                "stored Artifact integrity state is missing",
            ))
    }
}

/// Parameters for a trusted control-plane Artifact import.
///
/// This DTO does not authenticate its caller. The import entry point is crate-private so
/// authentication and user-selected source mediation must happen before this request reaches the
/// Artifact Store.
///
/// ```compile_fail
/// use std::io::Cursor;
/// use aios_task_manager::{ImportArtifactRequest, TaskManager};
///
/// fn forge(manager: &mut TaskManager, request: &ImportArtifactRequest) {
///     let _ = manager.import_artifact(request, &mut Cursor::new(b"forged"));
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportArtifactRequest {
    pub schema_version: String,
    /// Optional stable control-plane identity used to replay a committed import after response
    /// loss. Older callers may omit it and retain the original one-shot import behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub import_id: Option<String>,
    pub task_id: String,
    pub origin_kind: ArtifactOriginKind,
    pub semantic_type: Option<String>,
    pub media_type: String,
    pub format: Option<String>,
    pub sensitivity: Sensitivity,
    pub retention: RetentionClass,
    pub expires_at: Option<String>,
    #[serde(default)]
    pub labels: Vec<String>,
    pub max_size_bytes: Option<u64>,
}

/// Parameters for a trusted control-plane output allocation.
///
/// The raw allocation/open/publication entry points are crate-private because an unbound request
/// is authorized by authenticated control-plane context, not by this serializable DTO. External
/// provider callers must use the bound entry points, which require a current Execution Binding
/// and exact grant.
///
/// ```compile_fail
/// use aios_task_manager::{OutputAllocationRequest, TaskManager};
///
/// fn forge(manager: &mut TaskManager, request: &OutputAllocationRequest) {
///     let _ = manager.allocate_artifact_output(request);
/// }
/// ```
///
/// ```compile_fail
/// use aios_task_manager::TaskManager;
///
/// fn forge(manager: &mut TaskManager) {
///     let _ = manager.open_artifact_output("forged-allocation");
/// }
/// ```
///
/// ```compile_fail
/// use aios_task_manager::{ArtifactPublicationRequest, TaskManager};
///
/// fn forge(manager: &mut TaskManager, request: &ArtifactPublicationRequest) {
///     let _ = manager.publish_artifact_output(request);
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputAllocationRequest {
    pub schema_version: String,
    pub allocation_id: String,
    pub task_id: String,
    pub semantic_program_hash: String,
    pub node_id: String,
    pub binding_id: Option<String>,
    pub attempt_id: Option<String>,
    pub output_port: Option<String>,
    pub expected_semantic_type: Option<String>,
    #[serde(default)]
    pub allowed_media_types: Vec<String>,
    pub max_size_bytes: Option<u64>,
    pub sensitivity: Sensitivity,
    pub retention: RetentionClass,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactOutputAllocation {
    pub schema_version: String,
    pub allocation_id: String,
    pub task_id: String,
    pub semantic_program_hash: String,
    pub node_id: String,
    pub binding_id: Option<String>,
    pub attempt_id: Option<String>,
    pub output_port: Option<String>,
    pub expected_semantic_type: Option<String>,
    pub allowed_media_types: Vec<String>,
    pub max_size_bytes: Option<u64>,
    pub sensitivity: Sensitivity,
    pub retention: RetentionClass,
    pub state: ArtifactAllocationState,
    pub publication_id: Option<String>,
    pub published_artifact_id: Option<String>,
    pub created_at: String,
    pub expires_at: String,
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactLineage {
    #[serde(default)]
    pub input_artifact_ids: Vec<String>,
    #[serde(default)]
    pub derived_from_artifact_ids: Vec<String>,
    #[serde(default)]
    pub representation_of_object_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPublicationRequest {
    pub schema_version: String,
    pub publication_id: String,
    pub allocation_id: String,
    pub task_id: String,
    pub expected_allocation_state: ArtifactExpectedState,
    pub semantic_type: Option<String>,
    pub media_type: String,
    pub format: Option<String>,
    pub lineage: ArtifactLineage,
    #[serde(default)]
    pub labels: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPublicationResult {
    pub schema_version: String,
    pub publication_id: String,
    pub allocation_id: String,
    pub task_id: String,
    pub published: bool,
    pub reason_code: String,
    pub message: Option<String>,
    pub artifact_id: Option<String>,
    pub artifact_uri: Option<String>,
    pub semantic_type: Option<String>,
    pub media_type: Option<String>,
    pub size_bytes: Option<u64>,
    pub content_hash: Option<String>,
    pub blob_reused: Option<bool>,
    pub provenance_event_id: Option<String>,
    pub provenance_event_hash: Option<String>,
    pub resulted_at: String,
}

/// A store-issued, non-forgeable scope for a bounded set of Artifact reads.
///
/// Owner inspection scopes are issued only inside the trusted Task Manager crate. A
/// caller cannot obtain owner authority by presenting a plain serialized [`Actor`].
///
/// ```compile_fail
/// use aios_task_manager::TaskManager;
///
/// fn forge(manager: &TaskManager) {
///     let _ = manager.scope_owned_artifact_reads("T-1", &[]);
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactReadScope {
    scope_id: String,
    issuer_id: String,
    task_id: String,
    authority: ReadAuthority,
    artifact_ids: BTreeSet<String>,
    grant_ids: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReadAuthority {
    task_principal_kind: String,
    task_principal_id: String,
    execution: Option<ExecutionAuthority>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExecutionAuthority {
    binding_id: String,
    attempt_id: String,
    semantic_program_hash: String,
    node_id: String,
    capability: String,
    principal_id: String,
    policy_decision_refs_json: String,
    grant_refs_json: String,
}

/// An authenticated provider channel bound to one immutable execution attempt.
///
/// Only the trusted in-crate supervisor can mint this value. Provider-facing Artifact APIs
/// require it so serializable Task/binding identifiers cannot authenticate a caller.
///
/// Downstream callers cannot construct the session from copied identifiers:
///
/// ```compile_fail
/// use aios_task_manager::ProviderArtifactSession;
///
/// let _ = ProviderArtifactSession {
///     issuer_id: "copied".to_owned(),
///     task_id: "T-1".to_owned(),
///     authority: panic!("private authority"),
/// };
/// ```
///
/// Nor can a serialized value be turned into an authenticated session:
///
/// ```compile_fail
/// use aios_task_manager::ProviderArtifactSession;
///
/// let _: ProviderArtifactSession = serde_json::from_str("{}").unwrap();
/// ```
///
/// The issuer is also unavailable outside the trusted Task Manager crate:
///
/// ```compile_fail
/// use aios_task_manager::TaskManager;
///
/// fn forge(manager: &TaskManager) {
///     let _ = manager.issue_provider_artifact_session("T-1", "binding-1");
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderArtifactSession {
    issuer_id: String,
    task_id: String,
    authority: ExecutionAuthority,
}

/// A destination writer whose durable close/finalization can report failure.
///
/// Implementations must complete every fallible close, commit, or finalization step in
/// [`ArtifactExportWriter::finalize`]. Relying on `Drop` is unsafe because the Artifact Store
/// records export success only after this method returns successfully.
///
/// ```
/// use std::io::{self, Write};
/// use aios_task_manager::ArtifactExportWriter;
///
/// struct Destination(Vec<u8>);
///
/// impl Write for Destination {
///     fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
///         self.0.write(bytes)
///     }
///
///     fn flush(&mut self) -> io::Result<()> {
///         self.0.flush()
///     }
/// }
///
/// impl ArtifactExportWriter for Destination {
///     fn finalize(&mut self) -> io::Result<()> {
///         self.flush()
///     }
/// }
/// ```
pub trait ArtifactExportWriter: Write {
    /// Completes every fallible commit/close step needed before success may be recorded.
    fn finalize(&mut self) -> std::io::Result<()>;
}

impl ArtifactExportWriter for Vec<u8> {
    fn finalize(&mut self) -> std::io::Result<()> {
        self.flush()
    }
}

/// An opaque, single-use export destination prepared by the trusted control plane.
///
/// The destination class and exact egress admission are sealed into this handle, so callers of
/// [`TaskManager::export_artifact`] cannot substitute an arbitrary writer or destination label.
pub struct ArtifactExportDestination<W: ArtifactExportWriter> {
    writer_factory: Option<Box<dyn FnOnce() -> std::io::Result<W>>>,
    writer: Option<W>,
    external_effect_possible: bool,
    operation_id: String,
    intent_json: String,
    issuer_id: String,
    scope_id: String,
    task_id: String,
    artifact_id: String,
    destination_class: String,
    authority: ReadAuthority,
    expected_grant_id: Option<String>,
    grant_admission: Option<GrantAdmission>,
    consumed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactExportIntent {
    version: u8,
    task_id: String,
    artifact_id: String,
    content_hash: String,
    destination_class: String,
    max_size_bytes: u64,
    principal_kind: String,
    principal_id: String,
    semantic_program_hash: Option<String>,
    node_id: Option<String>,
    binding_id: Option<String>,
    attempt_id: Option<String>,
    grant_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreDestinationExportAdmission {
    version: u8,
    kind: String,
    operation_id: String,
    intent_hash: String,
    provenance_event_id: String,
    provenance_event_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArmedExportAdmission {
    version: u8,
    kind: String,
    operation_id: String,
    intent_hash: String,
    admission_event_id: String,
    admission_event_hash: String,
    provenance_event_id: String,
    provenance_event_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactReaderAdmission {
    version: u8,
    operation_id: String,
    task_id: String,
    artifact_id: String,
    semantic_program_hash: String,
    node_id: String,
    binding_id: String,
    attempt_id: String,
    principal_id: String,
    grant_id: String,
    one_shot_consumed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactReaderAdmissionReceipt {
    version: u8,
    kind: String,
    operation_id: String,
    admission_event_id: String,
    admission_event_hash: String,
    delivery_event_id: Option<String>,
    delivery_event_hash: Option<String>,
}

/// Exact durable export identity presented to a trusted external-outcome verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArtifactExportReconciliationSubject {
    pub operation_id: String,
    pub task_id: String,
    pub artifact_id: String,
    pub content_hash: String,
    pub destination_class: String,
    pub max_size_bytes: u64,
    pub principal_kind: String,
    pub principal_id: String,
    pub semantic_program_hash: Option<String>,
    pub node_id: Option<String>,
    pub binding_id: Option<String>,
    pub attempt_id: Option<String>,
    pub grant_id: Option<String>,
}

/// Authenticated durable observation returned only by a trusted reconciliation adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedArtifactExportNoEffect {
    pub subject: ArtifactExportReconciliationSubject,
    pub challenge: String,
    pub evidence_ref: String,
    pub proof_hash: String,
    pub observed_at: String,
}

/// Trusted adapter boundary for independently checking external destination state.
///
/// The adapter receives the Task Manager's stored immutable subject and must retrieve and verify
/// durable evidence independently. Callers cannot supply a serializable evidence assertion to the
/// Task Manager reconciliation method.
pub trait ArtifactExportOutcomeVerifier {
    fn verifier_id(&self) -> &str;

    fn destination_class(&self) -> &str;

    fn verify_no_effect(
        &self,
        subject: &ArtifactExportReconciliationSubject,
        challenge: &str,
    ) -> Result<VerifiedArtifactExportNoEffect>;
}

impl ArtifactExportReconciliationSubject {
    fn from_intent(operation_id: &str, intent: &ArtifactExportIntent) -> Self {
        Self {
            operation_id: operation_id.to_owned(),
            task_id: intent.task_id.clone(),
            artifact_id: intent.artifact_id.clone(),
            content_hash: intent.content_hash.clone(),
            destination_class: intent.destination_class.clone(),
            max_size_bytes: intent.max_size_bytes,
            principal_kind: intent.principal_kind.clone(),
            principal_id: intent.principal_id.clone(),
            semantic_program_hash: intent.semantic_program_hash.clone(),
            node_id: intent.node_id.clone(),
            binding_id: intent.binding_id.clone(),
            attempt_id: intent.attempt_id.clone(),
            grant_id: intent.grant_id.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GrantAdmission {
    grant_id: String,
    one_shot_consumed: bool,
}

impl<W: ArtifactExportWriter> ArtifactExportDestination<W> {
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
}

impl ArtifactReadScope {
    pub fn scope_id(&self) -> &str {
        &self.scope_id
    }

    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    pub fn binding_id(&self) -> Option<&str> {
        self.authority
            .execution
            .as_ref()
            .map(|authority| authority.binding_id.as_str())
    }
}

pub struct ArtifactReader {
    file: File,
    handle: ArtifactHandle,
    authority_connection: Connection,
    clock: Arc<dyn Clock>,
    lease_owner: String,
    lease_epoch: i64,
    database_identity: Option<StoreIdentity>,
    task_id: String,
    authority: ReadAuthority,
    artifact_id: String,
    grant_admission: Option<GrantAdmission>,
    _store_cleanup: Option<Arc<EphemeralStoreCleanup>>,
}

struct PreparedArtifactReader {
    file: File,
    handle: ArtifactHandle,
    authority_connection: Connection,
    database_identity: Option<StoreIdentity>,
}

impl ArtifactReader {
    pub fn handle(&self) -> &ArtifactHandle {
        &self.handle
    }
}

impl Read for ArtifactReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        validate_reader_fence(self)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::PermissionDenied, error))?;
        self.file.read(buffer)
    }
}

impl Seek for ArtifactReader {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        validate_reader_fence(self)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::PermissionDenied, error))?;
        self.file.seek(position)
    }
}

pub struct ArtifactStagingWriter {
    file: Option<cap_std::fs::File>,
    store: Dir,
    authority_connection: Connection,
    clock: Arc<dyn Clock>,
    lease_owner: String,
    lease_epoch: i64,
    grant_admission: Option<GrantAdmission>,
    allocation_id: String,
    writer_session_id: String,
    writer_generation: i64,
    seal_ref: String,
    maximum: u64,
    written: u64,
    _store_cleanup: Option<Arc<EphemeralStoreCleanup>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedStaging {
    version: u8,
    allocation_id: String,
    size_bytes: u64,
    content_hash: String,
}

impl ArtifactStagingWriter {
    pub fn allocation_id(&self) -> &str {
        &self.allocation_id
    }

    pub fn bytes_written(&self) -> u64 {
        self.written
    }

    pub fn finish(mut self) -> Result<u64> {
        let transaction = self
            .authority_connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_writer_fence(
            &transaction,
            &self.allocation_id,
            &self.clock.now(),
            &self.lease_owner,
            self.lease_epoch,
            self.grant_admission.as_ref(),
            &self.writer_session_id,
            self.writer_generation,
        )?;
        ensure_writer_unsealed(&self.store, &self.seal_ref)?;
        let mut file = self.file.take().ok_or(TaskManagerError::InvalidRecord(
            "Artifact staging writer is already finalized",
        ))?;
        file.flush()?;
        file.sync_all()?;
        transaction.commit()?;
        file.seek(SeekFrom::Start(0))?;
        let (size_bytes, content_hash) = hash_reader(&mut file)?;
        if size_bytes != self.written {
            return Err(TaskManagerError::InvalidRecord(
                "Artifact staging writer byte count changed before sealing",
            ));
        }
        drop(file);
        writer_finish_step()?;
        let transaction = self
            .authority_connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_writer_fence(
            &transaction,
            &self.allocation_id,
            &self.clock.now(),
            &self.lease_owner,
            self.lease_epoch,
            self.grant_admission.as_ref(),
            &self.writer_session_id,
            self.writer_generation,
        )?;
        ensure_writer_unsealed(&self.store, &self.seal_ref)?;
        let sealed = SealedStaging {
            version: SEALED_STAGING_VERSION,
            allocation_id: self.allocation_id.clone(),
            size_bytes,
            content_hash,
        };
        let bytes = serde_json::to_vec(&sealed)?;
        write_staging_seal_atomically(&self.store, &self.seal_ref, &bytes)?;
        transaction.commit()?;
        Ok(self.written)
    }
}

impl Write for ArtifactStagingWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let transaction = self
            .authority_connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(std::io::Error::other)?;
        validate_writer_fence(
            &transaction,
            &self.allocation_id,
            &self.clock.now(),
            &self.lease_owner,
            self.lease_epoch,
            self.grant_admission.as_ref(),
            &self.writer_session_id,
            self.writer_generation,
        )
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::PermissionDenied, error))?;
        ensure_writer_unsealed(&self.store, &self.seal_ref)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::PermissionDenied, error))?;
        let length = u64::try_from(buffer.len()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "write is too large")
        })?;
        if self.written.saturating_add(length) > self.maximum {
            return Err(std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                "ARTIFACT_SIZE_LIMIT",
            ));
        }
        let written = self
            .file
            .as_mut()
            .ok_or_else(|| std::io::Error::other("staging writer is finalized"))?
            .write(buffer)?;
        let total = self
            .written
            .checked_add(u64::try_from(written).unwrap_or(u64::MAX))
            .ok_or_else(|| std::io::Error::other("staging byte count overflow"))?;
        // The file append is the externally observable effect of `Write`. Once it succeeds,
        // report that exact byte count even if releasing the read-only SQLite fence reports a
        // late error. Returning `Err` here would invite a conforming caller to append the same
        // bytes again while leaving our cursor stale.
        self.written = total;
        if transaction.commit().is_ok() {
            let _ = writer_write_commit_result_step();
        }
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let transaction = self
            .authority_connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(std::io::Error::other)?;
        validate_writer_fence(
            &transaction,
            &self.allocation_id,
            &self.clock.now(),
            &self.lease_owner,
            self.lease_epoch,
            self.grant_admission.as_ref(),
            &self.writer_session_id,
            self.writer_generation,
        )
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::PermissionDenied, error))?;
        ensure_writer_unsealed(&self.store, &self.seal_ref)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::PermissionDenied, error))?;
        self.file
            .as_mut()
            .ok_or_else(|| std::io::Error::other("staging writer is finalized"))?
            .flush()?;
        transaction.commit().map_err(std::io::Error::other)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ArtifactReconciliationKind {
    StagingOrphaned,
    BlobOrphaned,
    BlobMissing,
    BlobCorrupt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactReconciliationFinding {
    pub kind: ArtifactReconciliationKind,
    pub allocation_id: Option<String>,
    pub content_hash: Option<String>,
    pub artifact_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactReconciliationReport {
    pub reconciled_at: String,
    pub findings: Vec<ArtifactReconciliationFinding>,
}

#[allow(
    clippy::too_many_lines,
    reason = "keeps root creation, opened-handle validation, durability, and identity binding in one ordered security boundary"
)]
pub(super) fn initialize_root(
    store_lock: Option<&StoreLock>,
    connection: &Connection,
) -> Result<(PathBuf, Dir, Option<Arc<EphemeralStoreCleanup>>)> {
    let (root, database_identity, stored_root_identity) = if let Some(lock) = store_lock {
        let file_name = lock
            .identity
            .canonical_path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(TaskManagerError::InvalidRecord(
                "Task store path has no portable file name",
            ))?;
        let proposed = lock
            .identity
            .canonical_path
            .with_file_name(format!("{file_name}.artifacts"));
        let identity = lock.identity.persistent_key();
        let stored = connection
            .query_row(
                "SELECT database_identity,canonical_root,root_identity FROM artifact_store_binding WHERE singleton_id=1",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)),
            )
            .optional()?;
        match stored {
            Some((stored_identity, stored_root, root_identity)) => {
                if stored_identity != identity {
                    return Err(TaskManagerError::InvalidRecord(
                        "Artifact store root binding does not match the locked database identity",
                    ));
                }
                (PathBuf::from(stored_root), identity, Some(root_identity))
            }
            None => (proposed, identity, None),
        }
    } else {
        let token = random_token(connection)?;
        (
            std::env::temp_dir().join(format!("aios-task-manager-{token}")),
            format!("memory:{token}"),
            None,
        )
    };
    durability_step("create-root")?;
    let created = match create_store_root(&root) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(error.into()),
    };
    let cleanup = store_lock
        .is_none()
        .then(|| Arc::new(EphemeralStoreCleanup { root: root.clone() }));
    let directory = open_store_root_bound(&root)?;
    root_open_step(&root)?;
    let root_file = directory.try_clone()?.into_std_file();
    validate_opened_store_root(&root, &root_file)?;
    let opened_identity = super::store_identity(&root, &root_file)?;
    reject_reparse_root(&root)?;
    let canonical_root = root.canonicalize()?;
    let current_path = open_store_root_bound(&canonical_root)?;
    let current_path_file = current_path.into_std_file();
    if super::store_identity(&canonical_root, &current_path_file)? != opened_identity {
        return Err(TaskManagerError::InvalidRecord(
            "Artifact store root changed while it was being opened",
        ));
    }
    // A previous attempt may have created the directory and failed before its
    // parent entry was durable. Always repeat both syncs before acknowledging
    // the root, including on retry when it already exists.
    durability_step("sync-root")?;
    sync_store_root(&directory)?;
    durability_step("sync-root-parent")?;
    sync_host_directory(
        canonical_root
            .parent()
            .ok_or(TaskManagerError::InvalidRecord(
                "Artifact store root has no parent directory",
            ))?,
    )?;
    let root_identity = opened_identity.persistent_key();
    if stored_root_identity
        .as_deref()
        .is_some_and(|stored| stored != root_identity)
    {
        return Err(TaskManagerError::InvalidRecord(
            "Artifact store root identity does not match its database binding",
        ));
    }
    secure_store_root(&canonical_root, created)?;
    create_durable_ancestors(&directory, "blobs/sha256")?;
    create_durable_ancestors(&directory, "staging")?;
    create_durable_ancestors(&directory, "quarantine")?;
    create_durable_ancestors(&directory, "blobs/pending")?;
    let canonical_text = canonical_root
        .to_str()
        .ok_or(TaskManagerError::InvalidRecord(
            "Artifact store root is not UTF-8",
        ))?;
    connection.execute(
        "INSERT INTO artifact_store_binding(singleton_id,database_identity,canonical_root,root_identity,bound_at) VALUES (1,?1,?2,?3,?4) ON CONFLICT(singleton_id) DO NOTHING",
        params![database_identity, canonical_text, root_identity, OffsetDateTime::now_utc().format(&Rfc3339).map_err(|_| TaskManagerError::InvalidRecord("Artifact store binding time could not be formatted"))?],
    )?;
    Ok((canonical_root, directory, cleanup))
}

#[cfg(unix)]
fn create_store_root(root: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;

    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700).create(root)
}

#[cfg(windows)]
fn create_store_root(root: &Path) -> std::io::Result<()> {
    create_windows_private_store_root(root)
}

#[cfg(not(any(unix, windows)))]
fn create_store_root(_root: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "private Artifact store root creation is unsupported",
    ))
}

#[cfg(unix)]
fn open_store_root_bound(root: &Path) -> Result<Dir> {
    use rustix::fs::{Mode, OFlags, open};

    let descriptor = open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| {
        if matches!(error, rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) {
            TaskManagerError::InvalidRecord("Artifact store root must be a real directory")
        } else {
            TaskManagerError::Io(std::io::Error::from(error))
        }
    })?;
    Ok(Dir::from_std_file(File::from(descriptor)))
}

#[cfg(not(unix))]
fn open_store_root_bound(root: &Path) -> Result<Dir> {
    Ok(Dir::open_ambient_dir(root, ambient_authority())?)
}

#[cfg(unix)]
fn validate_opened_store_root(_root: &Path, root_file: &File) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let metadata = root_file.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != manager_effective_uid()?
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(TaskManagerError::InvalidRecord(
            "opened Artifact store ownership or permissions are untrusted",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn validate_opened_store_root(root: &Path, root_file: &File) -> Result<()> {
    if !root_file.metadata()?.is_dir() {
        return Err(TaskManagerError::InvalidRecord(
            "opened Artifact store root is not a directory",
        ));
    }
    let information = winx::winapi_util::file::information(root_file)?;
    validate_windows_store_security(
        root,
        Some((information.volume_serial_number(), information.file_index())),
    )
}

#[cfg(not(any(unix, windows)))]
fn validate_opened_store_root(_root: &Path, _root_file: &File) -> Result<()> {
    Err(TaskManagerError::InvalidRecord(
        "opened Artifact store permission validation is unsupported on this platform",
    ))
}

#[cfg(test)]
type RootOpenTestHook = Box<dyn FnOnce(&Path) -> Result<()>>;

#[cfg(test)]
thread_local! {
    static ROOT_OPEN_TEST_HOOK: std::cell::RefCell<Option<RootOpenTestHook>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn root_open_step(root: &Path) -> Result<()> {
    ROOT_OPEN_TEST_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook(root)?;
        }
        Ok(())
    })
}

#[cfg(not(test))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "test root-swap injection shares the production call signature"
)]
fn root_open_step(_root: &Path) -> Result<()> {
    Ok(())
}

pub(super) struct EphemeralStoreCleanup {
    root: PathBuf,
}

impl Drop for EphemeralStoreCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn reject_reparse_root(root: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(root)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(TaskManagerError::InvalidRecord(
            "Artifact store root must be a real directory",
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(TaskManagerError::InvalidRecord(
                "Artifact store root must not be a reparse point",
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn secure_store_root(root: &Path, created: bool) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if created {
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
    }
    let trusted_owner = manager_effective_uid()?;
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink()
            || metadata.uid() != trusted_owner
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(TaskManagerError::InvalidRecord(
                "Artifact store ownership or permissions are untrusted",
            ));
        }
        if metadata.is_dir() {
            for child in std::fs::read_dir(path)? {
                pending.push(child?.path());
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
#[allow(
    clippy::unnecessary_wraps,
    reason = "keeps the Unix and fallible Windows effective-owner query signatures uniform"
)]
fn manager_effective_uid() -> Result<u32> {
    Ok(rustix::process::geteuid().as_raw())
}

#[cfg(windows)]
fn secure_store_root(root: &Path, created: bool) -> Result<()> {
    if created {
        let sid = windows_current_user_sid()?;
        let root_text = root.to_str().ok_or(TaskManagerError::InvalidRecord(
            "Artifact store root is not UTF-8",
        ))?;
        run_windows_acl_command(&[
            root_text,
            "/inheritance:r",
            "/grant:r",
            &format!("*{sid}:(OI)(CI)F"),
            "*S-1-5-18:(OI)(CI)F",
        ])?;
        run_windows_acl_command(&[root_text, "/setowner", &format!("*{sid}")])?;
        return Ok(());
    }
    validate_windows_store_security(root, None)
}

#[cfg(not(any(unix, windows)))]
fn secure_store_root(_root: &Path, _created: bool) -> Result<()> {
    Err(TaskManagerError::InvalidRecord(
        "Artifact store permission validation is unsupported on this platform",
    ))
}

#[cfg(windows)]
fn windows_current_user_sid() -> Result<String> {
    const WHOAMI: &str = r"C:\Windows\System32\whoami.exe";
    static SID: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    if let Some(sid) = SID.get() {
        return Ok(sid.clone());
    }
    validate_trusted_windows_executable(Path::new(WHOAMI))?;
    let output = std::process::Command::new(WHOAMI)
        .args(["/user", "/fo", "csv", "/nh"])
        .env_clear()
        .current_dir(r"C:\Windows\System32")
        .output()?;
    if !output.status.success() {
        return Err(TaskManagerError::InvalidRecord(
            "current Windows user identity could not be resolved",
        ));
    }
    let text = String::from_utf8(output.stdout).map_err(|_| {
        TaskManagerError::InvalidRecord("current Windows user identity is not UTF-8")
    })?;
    let sid = text
        .trim()
        .rsplit_once(',')
        .map(|(_, value)| value.trim().trim_matches('"').to_owned())
        .filter(|value| {
            value.starts_with("S-1-")
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || byte == b'S' || byte == b'-')
        })
        .ok_or(TaskManagerError::InvalidRecord(
            "current Windows user SID is invalid",
        ))?;
    let _ = SID.set(sid.clone());
    Ok(sid)
}

#[cfg(windows)]
fn create_windows_private_store_root(root: &Path) -> std::io::Result<()> {
    const POWERSHELL: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    const SCRIPT: &str = r"
$ErrorActionPreference = 'Stop'
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
$security = New-Object Security.AccessControl.DirectorySecurity
$security.SetAccessRuleProtection($true, $false)
$security.SetOwner($sid)
$inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
$propagation = [Security.AccessControl.PropagationFlags]::None
$full = [Security.AccessControl.FileSystemRights]::FullControl
$allow = [Security.AccessControl.AccessControlType]::Allow
$security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, $full, $inheritance, $propagation, $allow)))
$security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($system, $full, $inheritance, $propagation, $allow)))
try {
  [void][System.IO.Directory]::CreateDirectory($env:AIOS_ARTIFACT_STORE_ROOT, $security)
} catch [System.IO.IOException] {
  if ([System.IO.Directory]::Exists($env:AIOS_ARTIFACT_STORE_ROOT)) { exit 17 }
  throw
}
";
    validate_trusted_windows_executable(Path::new(POWERSHELL)).map_err(|error| {
        std::io::Error::new(std::io::ErrorKind::PermissionDenied, error.to_string())
    })?;
    let output = std::process::Command::new(POWERSHELL)
        .args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
        .env_clear()
        .env("AIOS_ARTIFACT_STORE_ROOT", root)
        .env("PATH", r"C:\Windows\System32")
        .env("SystemRoot", r"C:\Windows")
        .env("windir", r"C:\Windows")
        .current_dir(r"C:\Windows\System32")
        .output()?;
    if output.status.success() {
        Ok(())
    } else if output.status.code() == Some(17) {
        Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists))
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Artifact store root could not be created with a private ACL",
        ))
    }
}

#[cfg(windows)]
fn run_windows_acl_command(arguments: &[&str]) -> Result<()> {
    const ICACLS: &str = r"C:\Windows\System32\icacls.exe";
    validate_trusted_windows_executable(Path::new(ICACLS))?;
    let output = std::process::Command::new(ICACLS)
        .args(arguments)
        .env_clear()
        .current_dir(r"C:\Windows\System32")
        .output()?;
    if !output.status.success() {
        return Err(TaskManagerError::InvalidRecord(
            "Artifact store ACL could not be secured",
        ));
    }
    Ok(())
}

#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "keeps the fixed same-handle Windows identity and ACL inspection script auditable as one security boundary"
)]
fn validate_windows_store_security(
    root: &Path,
    expected_identity: Option<(u64, u64)>,
) -> Result<()> {
    const POWERSHELL: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    const POWERSHELL_MODULES: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\Modules";
    const SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public sealed class AiosOpenedDirectorySecurityResult : IDisposable {
  public UInt32 VolumeSerialNumber { get; set; }
  public UInt64 FileIndex { get; set; }
  public UInt32 FileAttributes { get; set; }
  public UInt32 ReparseTag { get; set; }
  public byte[] Descriptor { get; set; }
  internal SafeFileHandle RootHandle { get; set; }

  public void Dispose() {
    if (RootHandle != null) RootHandle.Dispose();
  }
}

public static class AiosOpenedDirectorySecurity {
  [StructLayout(LayoutKind.Sequential)]
  private struct FILETIME { public UInt32 Low; public UInt32 High; }

  [StructLayout(LayoutKind.Sequential)]
  private struct BY_HANDLE_FILE_INFORMATION {
    public UInt32 FileAttributes;
    public FILETIME CreationTime;
    public FILETIME LastAccessTime;
    public FILETIME LastWriteTime;
    public UInt32 VolumeSerialNumber;
    public UInt32 FileSizeHigh;
    public UInt32 FileSizeLow;
    public UInt32 NumberOfLinks;
    public UInt32 FileIndexHigh;
    public UInt32 FileIndexLow;
  }

  [StructLayout(LayoutKind.Sequential)]
  private struct FILE_ATTRIBUTE_TAG_INFO {
    public UInt32 FileAttributes;
    public UInt32 ReparseTag;
  }

  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  private static extern SafeFileHandle CreateFileW(
    string name, UInt32 access, UInt32 share, IntPtr security,
    UInt32 creation, UInt32 flags, IntPtr template);

  [DllImport("kernel32.dll", SetLastError = true)]
  private static extern bool GetFileInformationByHandle(
    SafeFileHandle handle, out BY_HANDLE_FILE_INFORMATION information);

  [DllImport("kernel32.dll", SetLastError = true)]
  private static extern bool GetFileInformationByHandleEx(
    SafeFileHandle handle, Int32 informationClass,
    out FILE_ATTRIBUTE_TAG_INFO information, UInt32 size);

  [DllImport("advapi32.dll", SetLastError = true)]
  private static extern UInt32 GetSecurityInfo(
    SafeFileHandle handle, UInt32 objectType, UInt32 securityInformation,
    out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl,
    out IntPtr securityDescriptor);

  [DllImport("advapi32.dll")]
  private static extern UInt32 GetSecurityDescriptorLength(IntPtr securityDescriptor);

  [DllImport("kernel32.dll")]
  private static extern IntPtr LocalFree(IntPtr memory);

  public static AiosOpenedDirectorySecurityResult Inspect(string path) {
    const UInt32 READ_CONTROL = 0x00020000;
    const UInt32 FILE_READ_ATTRIBUTES = 0x00000080;
    // Excluding FILE_SHARE_DELETE pins the authenticated root directory entry
    // while PowerShell traverses descendants through its path.
    const UInt32 SHARE_READ_WRITE = 0x00000003;
    const UInt32 OPEN_EXISTING = 3;
    const UInt32 FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    const UInt32 FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    const UInt32 SE_FILE_OBJECT = 1;
    const UInt32 OWNER_AND_DACL = 0x00000001 | 0x00000004;

    SafeFileHandle handle = CreateFileW(
      path, READ_CONTROL | FILE_READ_ATTRIBUTES, SHARE_READ_WRITE, IntPtr.Zero,
      OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
      IntPtr.Zero);
    try {
      if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
      BY_HANDLE_FILE_INFORMATION information;
      if (!GetFileInformationByHandle(handle, out information))
        throw new Win32Exception(Marshal.GetLastWin32Error());
      FILE_ATTRIBUTE_TAG_INFO tagInformation;
      if (!GetFileInformationByHandleEx(
            handle, 9, out tagInformation,
            checked((UInt32)Marshal.SizeOf(typeof(FILE_ATTRIBUTE_TAG_INFO)))))
        throw new Win32Exception(Marshal.GetLastWin32Error());
      IntPtr owner, group, dacl, sacl, descriptor;
      UInt32 status = GetSecurityInfo(
        handle, SE_FILE_OBJECT, OWNER_AND_DACL,
        out owner, out group, out dacl, out sacl, out descriptor);
      if (status != 0) throw new Win32Exception((int)status);
      try {
        UInt32 length = GetSecurityDescriptorLength(descriptor);
        byte[] bytes = new byte[length];
        Marshal.Copy(descriptor, bytes, 0, checked((int)length));
        return new AiosOpenedDirectorySecurityResult {
          VolumeSerialNumber = information.VolumeSerialNumber,
          FileIndex = ((UInt64)information.FileIndexHigh << 32) | information.FileIndexLow,
          FileAttributes = tagInformation.FileAttributes,
          ReparseTag = tagInformation.ReparseTag,
          Descriptor = bytes,
          RootHandle = handle
        };
      } finally {
        LocalFree(descriptor);
      }
    } catch {
      handle.Dispose();
      throw;
    }
  }
}
'@
$current = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$root = Get-Item -LiteralPath $env:AIOS_ARTIFACT_STORE_ROOT -Force
$opened = [AiosOpenedDirectorySecurity]::Inspect($root.FullName)
$openedEntries = New-Object 'System.Collections.Generic.List[System.IDisposable]'
try {
$rootAcl = New-Object Security.AccessControl.DirectorySecurity
$rootAcl.SetSecurityDescriptorBinaryForm($opened.Descriptor)
$rootOwner = $rootAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value
$rootRules = @($rootAcl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object {
  [PSCustomObject]@{ identity = $_.IdentityReference.Value; kind = $_.AccessControlType.ToString() }
})
$entries = New-Object System.Collections.ArrayList
[void]$entries.Add([PSCustomObject]@{
  owner = $rootOwner; protected = $rootAcl.AreAccessRulesProtected; rules = $rootRules;
  file_attributes = [UInt32]$opened.FileAttributes; reparse_tag = [UInt32]$opened.ReparseTag
})
$paths = @(Get-ChildItem -LiteralPath $root.FullName -Force -Recurse |
  ForEach-Object { $_.FullName } | Sort-Object)
foreach ($path in $paths) {
  # Authenticate every descendant's descriptor through its opened handle and
  # retain all handles until a stable second enumeration completes. This
  # prevents a path decoy from replacing any inspected entry mid-traversal.
  $entry = [AiosOpenedDirectorySecurity]::Inspect($path)
  $openedEntries.Add($entry)
  $acl = New-Object Security.AccessControl.FileSecurity
  $acl.SetSecurityDescriptorBinaryForm($entry.Descriptor)
  $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
  $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object {
    $identity = $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    [PSCustomObject]@{ identity = $identity; kind = $_.AccessControlType.ToString() }
  })
  [void]$entries.Add([PSCustomObject]@{
    owner = $owner; protected = $acl.AreAccessRulesProtected; rules = $rules;
    file_attributes = [UInt32]$entry.FileAttributes; reparse_tag = [UInt32]$entry.ReparseTag
  })
}
$pathsAfter = @(Get-ChildItem -LiteralPath $root.FullName -Force -Recurse |
  ForEach-Object { $_.FullName } | Sort-Object)
if (@(Compare-Object -ReferenceObject $paths -DifferenceObject $pathsAfter).Count -ne 0) {
  throw 'Artifact store descendants changed during ACL inspection'
}
$report = [PSCustomObject]@{
  current = $current
  volume_serial_number = [UInt64]$opened.VolumeSerialNumber
  file_index = [UInt64]$opened.FileIndex
  entries = $entries
} | ConvertTo-Json -Compress -Depth 5
} finally {
  foreach ($entry in $openedEntries) { $entry.Dispose() }
  $opened.Dispose()
}
$report
"#;
    validate_trusted_windows_executable(Path::new(POWERSHELL))?;
    let output = std::process::Command::new(POWERSHELL)
        .args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
        .env_clear()
        .env("AIOS_ARTIFACT_STORE_ROOT", root)
        .env("PATH", r"C:\Windows\System32")
        .env("SystemRoot", r"C:\Windows")
        .env("windir", r"C:\Windows")
        .env("PSModulePath", POWERSHELL_MODULES)
        .current_dir(r"C:\Windows\System32")
        .output()?;
    if !output.status.success() {
        return Err(TaskManagerError::InvalidRecord(
            "Artifact store ACL could not be inspected",
        ));
    }
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|_| {
        TaskManagerError::InvalidRecord("Artifact store ACL inspection returned invalid data")
    })?;
    let current = report
        .get("current")
        .and_then(serde_json::Value::as_str)
        .ok_or(TaskManagerError::InvalidRecord(
            "Artifact store ACL inspection omitted current owner",
        ))?;
    let inspected_identity = (
        report
            .get("volume_serial_number")
            .and_then(serde_json::Value::as_u64)
            .ok_or(TaskManagerError::InvalidRecord(
                "Artifact store ACL inspection omitted opened identity",
            ))?,
        report
            .get("file_index")
            .and_then(serde_json::Value::as_u64)
            .ok_or(TaskManagerError::InvalidRecord(
                "Artifact store ACL inspection omitted opened identity",
            ))?,
    );
    if expected_identity.is_some_and(|expected| expected != inspected_identity) {
        return Err(TaskManagerError::InvalidRecord(
            "Artifact store root changed while security was inspected",
        ));
    }
    let entries = report
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .ok_or(TaskManagerError::InvalidRecord(
            "Artifact store ACL inspection omitted entries",
        ))?;
    for (index, entry) in entries.iter().enumerate() {
        const FILE_ATTRIBUTE_REPARSE_POINT: u64 = 0x400;
        let owner = entry.get("owner").and_then(serde_json::Value::as_str);
        let protected = entry.get("protected").and_then(serde_json::Value::as_bool);
        let attributes = entry
            .get("file_attributes")
            .and_then(serde_json::Value::as_u64);
        let reparse_tag = entry.get("reparse_tag").and_then(serde_json::Value::as_u64);
        let trusted_rules = entry
            .get("rules")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|rules| {
                !rules.is_empty()
                    && rules.iter().all(|rule| {
                        rule.get("kind").and_then(serde_json::Value::as_str) == Some("Allow")
                            && rule
                                .get("identity")
                                .and_then(serde_json::Value::as_str)
                                .is_some_and(|identity| {
                                    identity == current || identity == "S-1-5-18"
                                })
                    })
            });
        if !owner
            .is_some_and(|owner| owner == current || owner == "S-1-5-18" || owner == "S-1-5-32-544")
            || (index == 0 && protected != Some(true))
            || attributes.is_none_or(|attributes| attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0)
            || reparse_tag != Some(0)
            || !trusted_rules
        {
            return Err(TaskManagerError::InvalidRecord(
                "Artifact store ownership or ACL is untrusted",
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn validate_trusted_windows_executable(path: &Path) -> Result<()> {
    use std::os::windows::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    let metadata = std::fs::symlink_metadata(path).map_err(|_| {
        TaskManagerError::InvalidRecord("trusted Windows security executable is unavailable")
    })?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(TaskManagerError::InvalidRecord(
            "trusted Windows security executable is unavailable",
        ));
    }
    Ok(())
}

impl TaskManager {
    pub(crate) fn issue_provider_artifact_session(
        &self,
        task_id: &str,
        binding_id: &str,
    ) -> Result<ProviderArtifactSession> {
        validate_id(task_id, 256, "invalid provider Artifact session Task")?;
        validate_id(binding_id, 256, "invalid provider Artifact session binding")?;
        let authority = capture_provider_session_authority(&self.connection, task_id, binding_id)?;
        Ok(ProviderArtifactSession {
            issuer_id: self.artifact_scope_issuer.clone(),
            task_id: task_id.to_owned(),
            authority,
        })
    }

    fn validate_provider_artifact_session(&self, session: &ProviderArtifactSession) -> Result<()> {
        if session.issuer_id != self.artifact_scope_issuer {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        ensure_task_is_not_recovering(&self.connection, &session.task_id)?;
        ensure_no_unknown_artifact_export(&self.connection, &session.task_id)?;
        Ok(())
    }

    /// Imports bytes after the trusted in-crate control plane has authenticated the caller and
    /// mediated the selected source.
    #[allow(
        clippy::too_many_lines,
        reason = "keeps byte placement, keyed replay identity, metadata, and provenance in one commit protocol"
    )]
    pub(crate) fn import_artifact<R: Read>(
        &mut self,
        request: &ImportArtifactRequest,
        reader: &mut R,
    ) -> Result<ArtifactHandle> {
        validate_import_request(request)?;
        ensure_task_is_not_recovering(&self.connection, &request.task_id)?;
        if let Some(replayed) = self.replay_keyed_import(request)? {
            return Ok(replayed);
        }
        let task_state = self
            .connection
            .query_row(
                "SELECT state FROM tasks WHERE task_id=?1",
                [&request.task_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or(TaskManagerError::InvalidRecord(
                "Artifact import Task does not exist",
            ))?;
        if !task_accepts_artifact_import(&task_state) {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        ensure_no_unknown_artifact_export(&self.connection, &request.task_id)?;
        let token = random_token(&self.connection)?;
        let staging_ref = format!("staging/import-{token}");
        let maximum = request
            .max_size_bytes
            .unwrap_or(IMPORT_LIMIT)
            .min(IMPORT_LIMIT);
        let (size, content_hash) =
            stream_into_new_internal_file(reader, &self.artifact_store_dir, &staging_ref, maximum)?;
        let placement = self.place_blob(&staging_ref, &content_hash, size, false, &token);
        let (storage_ref, reused) = match placement {
            Ok(placement) => placement,
            Err(error @ TaskManagerError::InvalidRecord("ARTIFACT_HASH_MISMATCH")) => {
                self.mark_content_hash_failed(&content_hash, "CORRUPT")?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        import_commit_step()?;
        let created_at = self.clock.now();
        let artifact_id = request.import_id.as_ref().map_or_else(
            || artifact_id("import", &token),
            |import_id| artifact_id("import-key", &format!("{}\0{import_id}", request.task_id)),
        );
        let uri = ArtifactUri::new(&artifact_id);
        let labels_json = serde_json::to_string(&request.labels)?;
        let lease_owner = self.lease_owner.clone();
        let lease_epoch = self.lease_epoch;
        let mut commit_attempted = false;
        let committed = (|| -> Result<()> {
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            assert_manager_lease(&transaction, &lease_owner, lease_epoch)?;
            ensure_task_is_not_recovering(&transaction, &request.task_id)?;
            let import_actor = transaction
            .query_row(
                "SELECT principal_kind,principal_id FROM tasks WHERE task_id=?1 AND state NOT IN ('COMPLETED','FAILED','CANCELLED','ROLLED_BACK','ROLLING_BACK')",
                [&request.task_id],
                |row| {
                    Ok(Actor {
                        kind: row.get(0)?,
                        id: row.get(1)?,
                    })
                },
            )
            .optional()?
            .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?;
            upsert_durable_blob(&transaction, &content_hash, size, &storage_ref, &created_at)?;
            transaction.execute(
            "INSERT INTO artifacts (artifact_id,uri,semantic_type,media_type,format,size_bytes,content_hash,sensitivity,retention_class,expires_at,origin_kind,origin_task_id,integrity_state,integrity_verified_at,integrity_verifier,labels_json,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,'verified',?13,'artifact-store:sha256',?14,?13)",
            params![artifact_id, uri.as_str(), request.semantic_type, request.media_type, request.format, to_i64(size)?, content_hash, request.sensitivity.as_str(), request.retention.as_str(), request.expires_at, request.origin_kind.as_str(), request.task_id, created_at, labels_json],
        )?;
            transaction.execute(
            "INSERT INTO task_artifacts(task_id,artifact_id,role,node_id,added_at) VALUES (?1,?2,'input',NULL,?3)",
            params![request.task_id, artifact_id, created_at],
        )?;
            let request_digest = import_request_digest(request)?;
            let event = json!({
                "schema_version": SCHEMA_VERSION,
                "event_id": event_id("artifact-imported", &artifact_id),
                "task_id": request.task_id,
                "event_type": "artifact.imported",
                "timestamp": created_at,
                "actor": import_actor,
                "input_artifacts": [],
                "output_artifacts": [artifact_id],
                "status": "success",
                "details": {"content_hash":content_hash,"size_bytes":size,"blob_reused":reused,"import_id":request.import_id,"request_digest":request_digest}
            });
            append_event(&transaction, &request.task_id, &event)?;
            commit_attempted = true;
            transaction.commit()?;
            import_commit_result_step()?;
            Ok(())
        })();
        if committed.is_err() && !reused && !commit_attempted {
            self.remove_uncommitted_blob_if_unreferenced(&content_hash, &storage_ref)?;
        }
        committed?;
        self.get_artifact(&artifact_id)?
            .ok_or(TaskManagerError::InvalidRecord(
                "imported Artifact disappeared",
            ))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "authenticates every immutable imported Artifact field and its provenance in one replay boundary"
    )]
    fn replay_keyed_import(
        &mut self,
        request: &ImportArtifactRequest,
    ) -> Result<Option<ArtifactHandle>> {
        let Some(import_id) = request.import_id.as_deref() else {
            return Ok(None);
        };
        let artifact_id = artifact_id("import-key", &format!("{}\0{import_id}", request.task_id));
        let Some(artifact) = self.get_artifact(&artifact_id)? else {
            let orphan_event = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM provenance_events
                 WHERE task_id=?1 AND event_type='artifact.imported'
                   AND json_extract(event_json,'$.details.import_id')=?2)",
                params![request.task_id, import_id],
                |row| row.get::<_, bool>(0),
            )?;
            if orphan_event {
                return Err(TaskManagerError::InvalidRecord(
                    "stored Artifact import receipt is invalid",
                ));
            }
            return Ok(None);
        };
        let event_jsons = {
            let mut statement = self.connection.prepare(
                "SELECT event_json FROM provenance_events
                 WHERE task_id=?1 AND event_type='artifact.imported'
                   AND json_extract(event_json,'$.details.import_id')=?2
                 ORDER BY sequence",
            )?;
            let rows = statement.query_map(params![request.task_id, import_id], |row| {
                row.get::<_, String>(0)
            })?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        let event = event_jsons
            .first()
            .and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok());
        let content_hash = artifact.content_hash.as_ref().map(ContentHash::tagged);
        let created_at = artifact.created_at.as_deref();
        let metadata_exact = artifact.artifact_id == artifact_id
            && artifact.uri.as_str() == ArtifactUri::new(&artifact_id).as_str()
            && artifact.semantic_type == request.semantic_type
            && artifact.media_type == request.media_type
            && artifact.format == request.format
            && artifact.sensitivity == request.sensitivity
            && artifact.retention.as_ref().is_some_and(|retention| {
                retention.class.as_ref() == Some(&request.retention)
                    && retention.expires_at == request.expires_at
            })
            && artifact.origin.kind == request.origin_kind
            && artifact.origin.task_id.as_deref() == Some(request.task_id.as_str())
            && artifact.origin.semantic_program_hash.is_none()
            && artifact.origin.step_id.is_none()
            && artifact.origin.execution_binding_id.is_none()
            && artifact.origin.provider_id.is_none()
            && artifact.labels == request.labels
            && artifact.integrity.as_ref().is_some_and(|integrity| {
                integrity.state == Some(ArtifactIntegrityState::Verified)
                    && integrity.verifier.as_deref() == Some("artifact-store:sha256")
                    && match (integrity.verified_at.as_deref(), created_at) {
                        (Some(verified_at), Some(created_at)) => parse_time(verified_at)
                            .and_then(|verified| {
                                parse_time(created_at).map(|created| verified >= created)
                            })
                            .unwrap_or(false),
                        _ => false,
                    }
            });
        let event_exact = event_jsons.len() == 1
            && event.as_ref().is_some_and(|event| {
                event.get("task_id").and_then(serde_json::Value::as_str)
                    == Some(request.task_id.as_str())
                    && event.get("event_type").and_then(serde_json::Value::as_str)
                        == Some("artifact.imported")
                    && event.get("status").and_then(serde_json::Value::as_str) == Some("success")
                    && event.get("timestamp").and_then(serde_json::Value::as_str) == created_at
                    && event
                        .pointer("/details/request_digest")
                        .and_then(serde_json::Value::as_str)
                        == import_request_digest(request).ok().as_deref()
                    && event
                        .get("output_artifacts")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|values| {
                            values.as_slice() == [serde_json::Value::String(artifact_id.clone())]
                        })
                    && event
                        .pointer("/details/content_hash")
                        .and_then(serde_json::Value::as_str)
                        == content_hash.as_deref()
                    && event
                        .pointer("/details/size_bytes")
                        .and_then(serde_json::Value::as_u64)
                        == artifact.size_bytes
            });
        let attachment_exact = self.connection.query_row(
            "SELECT COUNT(*)=1 FROM task_artifacts
             WHERE task_id=?1 AND artifact_id=?2 AND role='input' AND node_id IS NULL",
            params![request.task_id, artifact_id],
            |row| row.get::<_, bool>(0),
        )?;
        let blob = self
            .connection
            .query_row(
                "SELECT size_bytes,storage_ref,durability_state FROM artifact_blobs
             WHERE content_hash=?1 AND size_bytes=?2",
                params![content_hash, artifact.size_bytes.map(to_i64).transpose()?],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        let blob_exact = blob.as_ref().is_some_and(|blob| blob.2 == "DURABLE");
        let exact = metadata_exact
            && event_exact
            && attachment_exact
            && blob_exact
            && super::verify_provenance_through(&self.connection, &request.task_id, None)?;
        if !exact {
            return Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_PUBLICATION_ID_REUSE_CONFLICT",
            ));
        }
        let expected_hash = content_hash.ok_or(TaskManagerError::InvalidRecord(
            "stored Artifact import receipt is invalid",
        ))?;
        let (expected_size, storage_ref, _) = blob.ok_or(TaskManagerError::InvalidRecord(
            "stored Artifact import receipt is invalid",
        ))?;
        match hash_internal_file(&self.artifact_store_dir, &storage_ref) {
            Ok((actual_size, actual_hash))
                if actual_size == u64::try_from(expected_size).unwrap_or(u64::MAX)
                    && actual_hash == expected_hash => {}
            Err(TaskManagerError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                self.mark_content_hash_failed(&expected_hash, "MISSING")?;
                return Err(TaskManagerError::InvalidRecord("ARTIFACT_INTEGRITY_FAILED"));
            }
            Err(error) => return Err(error),
            Ok(_) => {
                self.mark_content_hash_failed(&expected_hash, "CORRUPT")?;
                return Err(TaskManagerError::InvalidRecord("ARTIFACT_INTEGRITY_FAILED"));
            }
        }
        Ok(Some(artifact))
    }

    /// Allocates provider output through a current binding and exact write grant.
    pub fn allocate_bound_artifact_output(
        &mut self,
        session: &ProviderArtifactSession,
        request: &OutputAllocationRequest,
    ) -> Result<ArtifactOutputAllocation> {
        validate_allocation_request_shape(request)?;
        self.validate_provider_artifact_session(session)?;
        if request.task_id != session.task_id
            || request.binding_id.as_deref() != Some(session.authority.binding_id.as_str())
            || request.attempt_id.as_deref() != Some(session.authority.attempt_id.as_str())
        {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        if let Some(existing) = self.get_artifact_output_allocation(&request.allocation_id)? {
            let exact = existing.task_id == request.task_id
                && existing.semantic_program_hash == request.semantic_program_hash
                && existing.node_id == request.node_id
                && existing.binding_id == request.binding_id
                && existing.attempt_id == request.attempt_id
                && existing.output_port == request.output_port
                && existing.expected_semantic_type == request.expected_semantic_type
                && existing.allowed_media_types == request.allowed_media_types
                && existing.max_size_bytes == request.max_size_bytes
                && existing.sensitivity == request.sensitivity
                && existing.retention == request.retention
                && existing.expires_at == request.expires_at;
            return if exact {
                ensure_task_is_not_recovering(&self.connection, &request.task_id)?;
                Ok(existing)
            } else {
                Err(TaskManagerError::InvalidRecord(
                    "ARTIFACT_ALLOCATION_STATE_CONFLICT",
                ))
            };
        }
        validate_allocation_request_expiry(request, &self.clock.now())?;
        self.allocate_artifact_output(request)
    }

    pub(crate) fn allocate_artifact_output(
        &mut self,
        request: &OutputAllocationRequest,
    ) -> Result<ArtifactOutputAllocation> {
        validate_allocation_request_shape(request)?;
        validate_allocation_request_expiry(request, &self.clock.now())?;
        ensure_task_is_not_recovering(&self.connection, &request.task_id)?;
        ensure_no_unknown_artifact_export(&self.connection, &request.task_id)?;
        let created_at = self.clock.now();
        let staging_ref = format!("staging/output-{}", random_token(&self.connection)?);
        allocation_commit_step()?;
        let lease_owner = self.lease_owner.clone();
        let lease_epoch = self.lease_epoch;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_manager_lease(&transaction, &lease_owner, lease_epoch)?;
        ensure_task_is_not_recovering(&transaction, &request.task_id)?;
        validate_requested_execution_scope(&transaction, request, &created_at)?;
        transaction.execute(
            "INSERT INTO artifact_output_allocations (allocation_id,task_id,semantic_program_hash,node_id,binding_id,attempt_id,output_port,expected_semantic_type,allowed_media_types_json,max_size_bytes,sensitivity,retention,state,staging_ref,created_at,expires_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,'ALLOCATED',?13,?14,?15,?14)",
            params![request.allocation_id,request.task_id,request.semantic_program_hash,request.node_id,request.binding_id,request.attempt_id,request.output_port,request.expected_semantic_type,serde_json::to_string(&request.allowed_media_types)?,request.max_size_bytes.map(to_i64).transpose()?,request.sensitivity.as_str(),request.retention.as_str(),staging_ref,created_at,request.expires_at],
        )?;
        transaction.commit()?;
        self.get_artifact_output_allocation(&request.allocation_id)?
            .ok_or(TaskManagerError::InvalidRecord(
                "created Artifact allocation disappeared",
            ))
    }

    /// Opens a provider writer only for an allocation bound to a current attempt.
    pub fn open_bound_artifact_output(
        &mut self,
        session: &ProviderArtifactSession,
        allocation_id: &str,
    ) -> Result<ArtifactStagingWriter> {
        self.validate_provider_artifact_session(session)?;
        validate_id(allocation_id, 256, "invalid Artifact allocation ID")?;
        let allocation = load_allocation_row(&self.connection, allocation_id)?.ok_or(
            TaskManagerError::InvalidRecord("ARTIFACT_ALLOCATION_NOT_FOUND"),
        )?;
        if allocation.task_id != session.task_id
            || allocation.binding_id.as_deref() != Some(session.authority.binding_id.as_str())
            || allocation.attempt_id.as_deref() != Some(session.authority.attempt_id.as_str())
        {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        self.open_artifact_output(allocation_id)
    }

    /// Retries the durable finalization boundary after a lost response or directory-sync error.
    pub fn retry_bound_artifact_output_finish(
        &mut self,
        session: &ProviderArtifactSession,
        allocation_id: &str,
    ) -> Result<u64> {
        self.validate_provider_artifact_session(session)?;
        validate_id(allocation_id, 256, "invalid Artifact allocation ID")?;
        let allocation = load_allocation_row(&self.connection, allocation_id)?.ok_or(
            TaskManagerError::InvalidRecord("ARTIFACT_ALLOCATION_NOT_FOUND"),
        )?;
        if allocation.task_id != session.task_id
            || allocation.binding_id.as_deref() != Some(session.authority.binding_id.as_str())
            || allocation.attempt_id.as_deref() != Some(session.authority.attempt_id.as_str())
            || allocation.state != "WRITING"
        {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        let now = self.clock.now();
        let writer_session_id = random_token(&self.connection)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let allocation = validate_writer_authority(
            &transaction,
            allocation_id,
            &now,
            &self.lease_owner,
            self.lease_epoch,
            allocation.writer_grant_admission.as_ref(),
        )?;
        let writer_generation =
            allocation
                .writer_generation
                .checked_add(1)
                .ok_or(TaskManagerError::InvalidRecord(
                    "Artifact writer generation exhausted",
                ))?;
        let changed = transaction.execute(
            "UPDATE artifact_output_allocations
             SET writer_session_id=?2,writer_generation=?3,updated_at=?4
             WHERE allocation_id=?1 AND state='WRITING'
               AND writer_generation=?5 AND writer_session_id IS ?6",
            params![
                allocation_id,
                writer_session_id,
                writer_generation,
                now,
                allocation.writer_generation,
                allocation.writer_session_id
            ],
        )?;
        if changed != 1 {
            return Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_ALLOCATION_STATE_CONFLICT",
            ));
        }
        let staging_ref =
            allocation
                .staging_ref
                .as_deref()
                .ok_or(TaskManagerError::InvalidRecord(
                    "ARTIFACT_ALLOCATION_STATE_CONFLICT",
                ))?;
        let seal_reference = seal_ref(staging_ref);
        // Read the fsynced pending evidence first. Once present, it is part of
        // the authenticated finish protocol and must not be replaced from
        // subsequently changed staging bytes.
        let pending_reference = format!("{seal_reference}.pending");
        let pending = read_staging_seal_evidence(&self.artifact_store_dir, &pending_reference)?;
        let final_seal = read_staging_seal_evidence(&self.artifact_store_dir, &seal_reference)?;
        let (size, hash) = hash_internal_file(&self.artifact_store_dir, staging_ref)?;
        writer_finish_step()?;
        let final_now = self.clock.now();
        validate_writer_fence(
            &transaction,
            allocation_id,
            &final_now,
            &self.lease_owner,
            self.lease_epoch,
            allocation.writer_grant_admission.as_ref(),
            &writer_session_id,
            writer_generation,
        )?;
        resolve_staging_seal_evidence(
            &self.artifact_store_dir,
            allocation_id,
            &seal_reference,
            &pending,
            &final_seal,
            size,
            &hash,
            true,
        )?;
        transaction.commit()?;
        Ok(size)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "keeps output admission, file issuance, and one-shot consumption in one transaction"
    )]
    pub(crate) fn open_artifact_output(
        &mut self,
        allocation_id: &str,
    ) -> Result<ArtifactStagingWriter> {
        validate_id(allocation_id, 256, "invalid Artifact allocation ID")?;
        let authority_connection = self.database_locator.open()?;
        authority_connection.busy_timeout(std::time::Duration::from_secs(5))?;
        if let Some(lock) = self.store_lock.as_ref() {
            super::verify_locked_store_identity(&authority_connection, lock)?;
        }
        // Prepare every capability required by the returned writer before the
        // transaction consumes finite authority or changes allocation state.
        let writer_store = self.artifact_store_dir.try_clone()?;
        let lease_owner = self.lease_owner.clone();
        let lease_epoch = self.lease_epoch;
        let now = self.clock.now();
        let writer_session_id = random_token(&self.connection)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_manager_lease(&transaction, &lease_owner, lease_epoch)?;
        let Some(allocation) = load_allocation_row(&transaction, allocation_id)? else {
            return Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_ALLOCATION_NOT_FOUND",
            ));
        };
        ensure_task_is_not_recovering(&transaction, &allocation.task_id)?;
        let Some(staging_ref) = allocation.staging_ref.clone() else {
            return Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_ALLOCATION_NOT_FOUND",
            ));
        };
        if allocation.state == "WRITING" {
            validate_writer_authority(
                &transaction,
                allocation_id,
                &now,
                &lease_owner,
                lease_epoch,
                allocation.writer_grant_admission.as_ref(),
            )?;
            let seal = seal_ref(&staging_ref);
            if internal_ref_exists(&self.artifact_store_dir, &seal)?
                || internal_ref_exists(&self.artifact_store_dir, &format!("{seal}.pending"))?
            {
                return Err(TaskManagerError::InvalidRecord(
                    "ARTIFACT_ALLOCATION_STATE_CONFLICT",
                ));
            }
            let mut file = self.artifact_store_dir.open_with(
                safe_internal_ref(&staging_ref)?,
                CapOpenOptions::new().read(true).write(true),
            )?;
            let written = file.metadata()?.len();
            let maximum = allocation
                .max_size_bytes
                .unwrap_or(IMPORT_LIMIT)
                .min(IMPORT_LIMIT);
            if written > maximum {
                return Err(TaskManagerError::InvalidRecord("ARTIFACT_SIZE_LIMIT"));
            }
            let cursor = file.seek(SeekFrom::End(0))?;
            if cursor != written || file.metadata()?.len() != written {
                return Err(TaskManagerError::InvalidRecord(
                    "ARTIFACT_ALLOCATION_STATE_CONFLICT",
                ));
            }
            let writer_generation = allocation.writer_generation.checked_add(1).ok_or(
                TaskManagerError::InvalidRecord("Artifact writer generation exhausted"),
            )?;
            let changed = transaction.execute(
                "UPDATE artifact_output_allocations
                 SET writer_session_id=?2,writer_generation=?3,updated_at=?4
                 WHERE allocation_id=?1 AND state='WRITING'
                   AND writer_generation=?5 AND writer_session_id IS ?6",
                params![
                    allocation_id,
                    writer_session_id,
                    writer_generation,
                    now,
                    allocation.writer_generation,
                    allocation.writer_session_id
                ],
            )?;
            if changed != 1 {
                return Err(TaskManagerError::InvalidRecord(
                    "ARTIFACT_ALLOCATION_STATE_CONFLICT",
                ));
            }
            transaction.commit()?;
            return Ok(ArtifactStagingWriter {
                file: Some(file),
                store: writer_store,
                authority_connection,
                clock: Arc::clone(&self.clock),
                lease_owner,
                lease_epoch,
                grant_admission: allocation.writer_grant_admission,
                allocation_id: allocation_id.to_owned(),
                writer_session_id,
                writer_generation,
                seal_ref: seal,
                maximum,
                written,
                _store_cleanup: self.artifact_store_cleanup.clone(),
            });
        }
        if allocation.state != "ALLOCATED" {
            return Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_ALLOCATION_STATE_CONFLICT",
            ));
        }
        if parse_time(&allocation.expires_at)? <= parse_time(&now)? {
            transaction.execute(
                "UPDATE artifact_output_allocations SET state='EXPIRED',updated_at=?2 WHERE allocation_id=?1",
                params![allocation_id,now],
            )?;
            transaction.commit()?;
            return Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_ALLOCATION_EXPIRED",
            ));
        }
        validate_allocation_execution_scope(&transaction, allocation_id, &allocation, &now)?;
        let file = self.artifact_store_dir.open_with(
            safe_internal_ref(&staging_ref)?,
            CapOpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true),
        )?;
        secure_cap_file_permissions(&file)?;
        let grant_admission_result = (|| -> Result<Option<GrantAdmission>> {
            let Some(binding_id) = allocation.binding_id.as_deref() else {
                return Ok(None);
            };
            let execution =
                capture_execution_authority(&transaction, &allocation.task_id, binding_id, &now)?;
            let grant = exact_operation_grant(
                &transaction,
                &allocation.task_id,
                &execution,
                "artifact.write",
                "output-allocation",
                allocation_id,
                &now,
                None,
            )?
            .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?;
            admit_operation_grant(
                &transaction,
                &allocation.task_id,
                &execution,
                "artifact.write",
                "output-allocation",
                allocation_id,
                &now,
                &grant.grant_id,
            )
            .map(Some)
        })();
        let grant_admission = match grant_admission_result {
            Ok(admission) => admission,
            Err(error) => {
                drop(file);
                let _ = self
                    .artifact_store_dir
                    .remove_file(safe_internal_ref(&staging_ref)?);
                return Err(error);
            }
        };
        let writer_generation =
            allocation
                .writer_generation
                .checked_add(1)
                .ok_or(TaskManagerError::InvalidRecord(
                    "Artifact writer generation exhausted",
                ))?;
        let changed = transaction.execute(
            "UPDATE artifact_output_allocations
             SET state='WRITING',writer_grant_id=?2,writer_grant_one_shot_consumed=?3,
                 writer_session_id=?4,writer_generation=?5,updated_at=?6
             WHERE allocation_id=?1 AND state='ALLOCATED' AND writer_generation=?7",
            params![
                allocation_id,
                grant_admission
                    .as_ref()
                    .map(|admission| &admission.grant_id),
                grant_admission
                    .as_ref()
                    .map(|admission| admission.one_shot_consumed),
                writer_session_id,
                writer_generation,
                now,
                allocation.writer_generation
            ],
        )?;
        if changed != 1 {
            drop(file);
            let _ = self
                .artifact_store_dir
                .remove_file(safe_internal_ref(&staging_ref)?);
            return Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_ALLOCATION_STATE_CONFLICT",
            ));
        }
        let commit_result = transaction
            .commit()
            .map_err(TaskManagerError::from)
            .and_then(|()| writer_admission_commit_result_step());
        if let Err(error) = commit_result {
            let durable = load_allocation_row(&self.connection, allocation_id)?;
            let exact = durable.as_ref().is_some_and(|durable| {
                durable.state == "WRITING"
                    && durable.staging_ref.as_deref() == Some(staging_ref.as_str())
                    && durable.writer_grant_admission == grant_admission
                    && durable.writer_session_id.as_deref() == Some(writer_session_id.as_str())
                    && durable.writer_generation == writer_generation
            });
            if !exact {
                drop(file);
                let _ = self
                    .artifact_store_dir
                    .remove_file(safe_internal_ref(&staging_ref)?);
                return Err(error);
            }
        }
        Ok(ArtifactStagingWriter {
            file: Some(file),
            store: writer_store,
            authority_connection,
            clock: Arc::clone(&self.clock),
            lease_owner: self.lease_owner.clone(),
            lease_epoch: self.lease_epoch,
            grant_admission,
            allocation_id: allocation_id.to_owned(),
            writer_session_id,
            writer_generation,
            seal_ref: seal_ref(&staging_ref),
            maximum: allocation
                .max_size_bytes
                .unwrap_or(IMPORT_LIMIT)
                .min(IMPORT_LIMIT),
            written: 0,
            _store_cleanup: self.artifact_store_cleanup.clone(),
        })
    }

    /// Publishes provider output only from an allocation bound to an execution attempt.
    pub fn publish_bound_artifact_output(
        &mut self,
        session: &ProviderArtifactSession,
        request: &ArtifactPublicationRequest,
    ) -> Result<ArtifactPublicationResult> {
        validate_publication_request(request)?;
        let allocation = load_allocation_row(&self.connection, &request.allocation_id)?.ok_or(
            TaskManagerError::InvalidRecord("ARTIFACT_ALLOCATION_NOT_FOUND"),
        )?;
        if session.issuer_id != self.artifact_scope_issuer
            || request.task_id != session.task_id
            || allocation.task_id != session.task_id
            || allocation.semantic_program_hash != session.authority.semantic_program_hash
            || allocation.node_id != session.authority.node_id
            || allocation.binding_id.as_deref() != Some(session.authority.binding_id.as_str())
            || allocation.attempt_id.as_deref() != Some(session.authority.attempt_id.as_str())
        {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        let terminal_replay = self
            .connection
            .query_row(
                "SELECT state FROM artifact_publications
             WHERE publication_id=?1 AND allocation_id=?2 AND task_id=?3
               AND state IN ('COMMITTED','FAILED')",
                params![
                    request.publication_id,
                    request.allocation_id,
                    request.task_id
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if terminal_replay.is_some() {
            return self.publish_artifact_output(request);
        }
        self.validate_provider_artifact_session(session)?;
        if allocation.writer_grant_admission.is_none() {
            let committed_replay = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM artifact_publications WHERE publication_id=?1 AND allocation_id=?2 AND task_id=?3 AND state='COMMITTED')",
                params![request.publication_id, request.allocation_id, request.task_id],
                |row| row.get::<_, bool>(0),
            )?;
            if !committed_replay {
                return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
            }
        }
        self.publish_artifact_output(request)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "publication is one auditable two-resource protocol"
    )]
    pub(crate) fn publish_artifact_output(
        &mut self,
        request: &ArtifactPublicationRequest,
    ) -> Result<ArtifactPublicationResult> {
        validate_publication_request(request)?;
        let request_json = canonical_json(request)?;
        if let Some((stored_request, state, result_json, stored_hash, committed_at)) = self
            .connection
            .query_row(
                "SELECT request_json,state,result_json,content_hash,committed_at FROM artifact_publications WHERE publication_id=?1",
                [&request.publication_id],
                |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,Option<String>>(2)?,row.get::<_,Option<String>>(3)?,row.get::<_,Option<String>>(4)?)),
            )
            .optional()?
        {
            if stored_request != request_json {
                return Ok(publication_conflict(request, self.clock.now()));
            }
            if state == "COMMITTED" {
                return self.authenticate_committed_publication(
                    request,
                    result_json.as_deref(),
                    stored_hash.as_deref(),
                );
            }
            if state == "FAILED" {
                return authenticate_failed_publication(
                    &self.connection,
                    request,
                    &state,
                    result_json.as_deref(),
                    committed_at.as_deref(),
                );
            }
            if state != "PENDING" {
                return Ok(publication_conflict(request, self.clock.now()));
            }
        }
        ensure_task_is_not_recovering(&self.connection, &request.task_id)?;
        if self.connection.query_row(
            "SELECT NOT EXISTS(SELECT 1 FROM artifact_publications WHERE publication_id=?1)",
            [&request.publication_id],
            |row| row.get::<_, bool>(0),
        )? && let Err(error) = self.reserve_publication(request, &request_json)
        {
            if let Some(code) = artifact_reason(&error) {
                return Ok(publication_failure(request, code, self.clock.now()));
            }
            return Err(error);
        }

        let mut allocation = load_allocation_row(&self.connection, &request.allocation_id)?.ok_or(
            TaskManagerError::InvalidRecord("ARTIFACT_ALLOCATION_NOT_FOUND"),
        )?;
        if !lineage_authorized(&self.connection, request, &allocation)? {
            return self.fail_pending_publication(request, "ARTIFACT_AUTHORITY_DENIED");
        }
        if let Err(error) = self.sealed_staging(&allocation, request) {
            let Some(code) = artifact_reason(&error) else {
                return Err(error);
            };
            return self.fail_pending_publication(request, code);
        }
        if allocation.state == request.expected_allocation_state.as_str() {
            if let Err(error) = self.begin_reserved_publication(request, &request_json) {
                let Some(code) = artifact_reason(&error) else {
                    return Err(error);
                };
                return self.fail_pending_publication(request, code);
            }
            allocation = load_allocation_row(&self.connection, &request.allocation_id)?.ok_or(
                TaskManagerError::InvalidRecord("ARTIFACT_ALLOCATION_NOT_FOUND"),
            )?;
        }
        if let Err(error) = validate_publication_allocation(request, &allocation, &self.clock.now())
        {
            if let Some(code) = artifact_reason(&error) {
                return self.fail_pending_publication(request, code);
            }
            return Err(error);
        }
        let staging_ref =
            allocation
                .staging_ref
                .as_deref()
                .ok_or(TaskManagerError::InvalidRecord(
                    "Artifact allocation has no staging object",
                ))?;
        let sealed = match self.sealed_staging(&allocation, request) {
            Ok(sealed) => sealed,
            Err(error) => {
                let Some(code) = artifact_reason(&error) else {
                    return Err(error);
                };
                return self.fail_pending_publication(request, code);
            }
        };
        let (size, content_hash) = hash_internal_file(&self.artifact_store_dir, staging_ref)?;
        if size != sealed.size_bytes || content_hash != sealed.content_hash {
            return self.fail_pending_publication(request, "ARTIFACT_HASH_MISMATCH");
        }
        let effective_maximum = allocation
            .max_size_bytes
            .unwrap_or(IMPORT_LIMIT)
            .min(IMPORT_LIMIT);
        if size > effective_maximum {
            return self.fail_pending_publication(request, "ARTIFACT_SIZE_LIMIT");
        }
        if let Err(error) =
            self.validate_pending_publication_authority(request, &request_json, &allocation)
        {
            let Some(code) = artifact_reason(&error) else {
                return Err(error);
            };
            return self.fail_pending_publication(request, code);
        }
        let placement = self.place_blob(
            staging_ref,
            &content_hash,
            size,
            true,
            &request.publication_id,
        );
        let (storage_ref, blob_reused) = match placement {
            Ok(placement) => placement,
            Err(TaskManagerError::InvalidRecord("ARTIFACT_HASH_MISMATCH")) => {
                self.mark_content_hash_failed(&content_hash, "CORRUPT")?;
                return self.fail_pending_publication(request, "ARTIFACT_HASH_MISMATCH");
            }
            Err(error) => return Err(error),
        };
        let resulted_at = self.clock.now();
        let artifact_id = artifact_id("publication", &request.publication_id);
        let artifact_uri = ArtifactUri::new(&artifact_id);
        publication_commit_step()?;
        let lease_owner = self.lease_owner.clone();
        let lease_epoch = self.lease_epoch;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_manager_lease(&transaction, &lease_owner, lease_epoch)?;
        if let Err(error) = ensure_task_is_not_recovering(&transaction, &request.task_id) {
            drop(transaction);
            if !blob_reused {
                self.remove_uncommitted_blob(&storage_ref)?;
            }
            return Err(error);
        }
        let pending_exact = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM artifact_publications WHERE publication_id=?1 AND allocation_id=?2 AND task_id=?3 AND request_json=?4 AND state='PENDING')",
            params![request.publication_id,request.allocation_id,request.task_id,request_json],
            |row| row.get::<_,bool>(0),
        )?;
        if !pending_exact {
            return Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_PUBLICATION_ID_REUSE_CONFLICT",
            ));
        }
        let current_allocation = load_allocation_row(&transaction, &request.allocation_id)?.ok_or(
            TaskManagerError::InvalidRecord("ARTIFACT_ALLOCATION_NOT_FOUND"),
        )?;
        if current_allocation != allocation
            || validate_publication_allocation(request, &current_allocation, &resulted_at).is_err()
        {
            drop(transaction);
            return self.fail_pending_publication(request, "ARTIFACT_AUTHORITY_DENIED");
        }
        if let Err(error) =
            validate_publication_authority(&transaction, request, &allocation, &resulted_at)
        {
            drop(transaction);
            let Some(code) = artifact_reason(&error) else {
                return Err(error);
            };
            return self.fail_pending_publication(request, code);
        }
        if !lineage_authorized(&transaction, request, &current_allocation)? {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        upsert_durable_blob(
            &transaction,
            &content_hash,
            size,
            &storage_ref,
            &resulted_at,
        )?;
        let origin_provider_id = allocation
            .binding_id
            .as_deref()
            .map(|binding_id| {
                transaction.query_row(
                    "SELECT provider_id FROM execution_bindings WHERE binding_id=?1 AND attempt_id=?2 AND task_id=?3",
                    params![binding_id, allocation.attempt_id, request.task_id],
                    |row| row.get::<_, String>(0),
                )
            })
            .transpose()?;
        transaction.execute(
            "INSERT INTO artifacts (artifact_id,uri,semantic_type,media_type,format,size_bytes,content_hash,sensitivity,retention_class,origin_kind,origin_task_id,origin_program_hash,origin_node_id,origin_binding_id,origin_provider_id,integrity_state,integrity_verified_at,integrity_verifier,labels_json,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,'task',?10,?11,?12,?13,?14,'verified',?15,'artifact-store:sha256',?16,?15)",
            params![artifact_id,artifact_uri.as_str(),request.semantic_type,request.media_type,request.format,to_i64(size)?,content_hash,allocation.sensitivity,allocation.retention,request.task_id,allocation.semantic_program_hash,allocation.node_id,allocation.binding_id,origin_provider_id,resulted_at,serde_json::to_string(&request.labels)?],
        )?;
        transaction.execute(
            "INSERT INTO task_artifacts(task_id,artifact_id,role,node_id,added_at) VALUES (?1,?2,'output',?3,?4)",
            params![request.task_id,artifact_id,allocation.node_id,resulted_at],
        )?;
        insert_lineage(
            &transaction,
            request,
            &artifact_id,
            &allocation.node_id,
            &resulted_at,
        )?;
        let event = json!({
            "schema_version":SCHEMA_VERSION,
            "event_id":event_id("artifact-created",&artifact_id),
            "task_id":request.task_id,
            "step_id":allocation.node_id,
            "event_type":"artifact.created",
            "timestamp":resulted_at,
            "actor":{"kind":"system-service","id":"service:artifact-store"},
            "semantic_program_hash":allocation.semantic_program_hash,
            "execution_binding_id":allocation.binding_id,
            "provider_id":origin_provider_id,
            "input_artifacts":request.lineage.input_artifact_ids,
            "output_artifacts":[artifact_id],
            "status":"success",
            "details":{"allocation_id":request.allocation_id,"publication_id":request.publication_id,"content_hash":content_hash,"size_bytes":size,"blob_reused":blob_reused}
        });
        let appended = append_event(&transaction, &request.task_id, &event)?;
        let result = ArtifactPublicationResult {
            schema_version: SCHEMA_VERSION.to_owned(),
            publication_id: request.publication_id.clone(),
            allocation_id: request.allocation_id.clone(),
            task_id: request.task_id.clone(),
            published: true,
            reason_code: "ARTIFACT_PUBLICATION_APPLIED".to_owned(),
            message: None,
            artifact_id: Some(artifact_id.clone()),
            artifact_uri: Some(artifact_uri.as_str().to_owned()),
            semantic_type: request.semantic_type.clone(),
            media_type: Some(request.media_type.clone()),
            size_bytes: Some(size),
            content_hash: Some(content_hash.clone()),
            blob_reused: Some(blob_reused),
            provenance_event_id: Some(appended.event_id),
            provenance_event_hash: Some(appended.event_hash),
            resulted_at: resulted_at.clone(),
        };
        transaction.execute(
            "UPDATE artifact_publications SET artifact_id=?2,content_hash=?3,result_json=?4,state='COMMITTED',committed_at=?5 WHERE publication_id=?1 AND state='PENDING'",
            params![request.publication_id,artifact_id,content_hash,serde_json::to_string(&result)?,resulted_at],
        )?;
        transaction.execute(
            "UPDATE artifact_output_allocations SET state='PUBLISHED',publication_id=?2,published_artifact_id=?3,updated_at=?4 WHERE allocation_id=?1 AND state='FINALIZING'",
            params![request.allocation_id,request.publication_id,artifact_id,resulted_at],
        )?;
        transaction.commit()?;
        // Publication is already durable. Failure to remove residue is safe;
        // startup reconciliation will classify and clean it separately.
        let _ = self
            .artifact_store_dir
            .remove_file(safe_internal_ref(staging_ref)?);
        let _ = self
            .artifact_store_dir
            .remove_file(safe_internal_ref(&seal_ref(staging_ref))?);
        Ok(result)
    }

    pub fn get_artifact(&self, artifact_id: &str) -> Result<Option<ArtifactHandle>> {
        self.connection
            .query_row(
                "SELECT artifact_id,uri,semantic_type,media_type,format,size_bytes,content_hash,sensitivity,retention_class,expires_at,origin_kind,origin_task_id,origin_program_hash,origin_node_id,origin_binding_id,origin_provider_id,integrity_state,integrity_verified_at,integrity_verifier,labels_json,created_at FROM artifacts WHERE artifact_id=?1",
                [artifact_id],
                artifact_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn get_artifact_output_allocation(
        &self,
        allocation_id: &str,
    ) -> Result<Option<ArtifactOutputAllocation>> {
        self.connection
            .query_row(
                "SELECT allocation_id,task_id,semantic_program_hash,node_id,binding_id,attempt_id,output_port,expected_semantic_type,allowed_media_types_json,max_size_bytes,sensitivity,retention,state,publication_id,published_artifact_id,created_at,expires_at,updated_at FROM artifact_output_allocations WHERE allocation_id=?1",
                [allocation_id],
                |row| allocation_from_row(row).map_err(|error| rusqlite::Error::FromSqlConversionFailure(0,rusqlite::types::Type::Text,Box::new(error))),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn scope_artifact_reads(
        &self,
        session: &ProviderArtifactSession,
        artifact_ids: &[String],
    ) -> Result<ArtifactReadScope> {
        self.validate_provider_artifact_session(session)?;
        let task_id = session.task_id.as_str();
        validate_id(task_id, 256, "invalid Artifact read Task")?;
        if artifact_ids.is_empty() || artifact_ids.len() > 256 || !all_unique(artifact_ids) {
            return Err(TaskManagerError::InvalidRecord(
                "invalid Artifact read scope",
            ));
        }
        let binding_id = session.authority.binding_id.as_str();
        let now = self.clock.now();
        let authority = capture_read_authority(&self.connection, task_id, Some(binding_id), &now)?;
        let execution = authority
            .execution
            .as_ref()
            .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?;
        let mut grant_ids = BTreeMap::new();
        for artifact_id in artifact_ids {
            if !artifact_read_authorized(&self.connection, task_id, &authority, artifact_id)? {
                return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
            }
            let grant_id = if let Some(grant) = exact_operation_grant(
                &self.connection,
                task_id,
                execution,
                "artifact.read",
                "artifact",
                artifact_id,
                &now,
                None,
            )? {
                grant.grant_id
            } else {
                replayable_reader_admission(
                    &self.connection,
                    task_id,
                    execution,
                    artifact_id,
                    &now,
                )?
                .map(|admission| admission.grant_id)
                .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?
            };
            grant_ids.insert(artifact_id.clone(), grant_id);
        }
        Ok(ArtifactReadScope {
            scope_id: format!("artifact-read-scope:{}", random_token(&self.connection)?),
            issuer_id: self.artifact_scope_issuer.clone(),
            task_id: task_id.to_owned(),
            authority,
            artifact_ids: artifact_ids.iter().cloned().collect(),
            grant_ids,
        })
    }

    /// Creates an owner inspection scope for the trusted in-crate control plane.
    ///
    /// Authentication must be completed before this boundary. Keeping this entry point
    /// crate-private prevents an untrusted caller from asserting ownership by constructing
    /// an [`Actor`] with values copied from a Task record.
    pub(crate) fn scope_owned_artifact_reads(
        &self,
        task_id: &str,
        artifact_ids: &[String],
    ) -> Result<ArtifactReadScope> {
        validate_id(task_id, 256, "invalid Artifact read Task")?;
        ensure_task_is_not_recovering(&self.connection, task_id)?;
        ensure_no_unknown_artifact_export(&self.connection, task_id)?;
        if artifact_ids.is_empty() || artifact_ids.len() > 256 || !all_unique(artifact_ids) {
            return Err(TaskManagerError::InvalidRecord(
                "invalid Artifact read scope",
            ));
        }
        let authority = capture_read_authority(&self.connection, task_id, None, &self.clock.now())?;
        for artifact_id in artifact_ids {
            if !artifact_read_authorized(&self.connection, task_id, &authority, artifact_id)? {
                return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
            }
        }
        Ok(ArtifactReadScope {
            scope_id: format!(
                "artifact-owner-read-scope:{}",
                random_token(&self.connection)?
            ),
            issuer_id: self.artifact_scope_issuer.clone(),
            task_id: task_id.to_owned(),
            authority,
            artifact_ids: artifact_ids.iter().cloned().collect(),
            grant_ids: BTreeMap::new(),
        })
    }

    fn prepare_artifact_reader(
        &mut self,
        scope: &ArtifactReadScope,
        artifact_id: &str,
    ) -> Result<PreparedArtifactReader> {
        ensure_task_is_not_recovering(&self.connection, &scope.task_id)?;
        let now = self.clock.now();
        if scope.issuer_id != self.artifact_scope_issuer
            || !scope.artifact_ids.contains(artifact_id)
            || capture_read_authority(&self.connection, &scope.task_id, scope.binding_id(), &now)?
                != scope.authority
            || !artifact_read_authorized(
                &self.connection,
                &scope.task_id,
                &scope.authority,
                artifact_id,
            )?
        {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        let handle = self
            .get_artifact(artifact_id)?
            .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_NOT_FOUND"))?;
        let (storage_ref, durability_state) = self.connection.query_row(
            "SELECT b.storage_ref,b.durability_state FROM artifacts a JOIN artifact_blobs b ON b.content_hash=a.content_hash WHERE a.artifact_id=?1",
            [artifact_id],
            |row| Ok((row.get::<_,String>(0)?, row.get::<_,String>(1)?)),
        )?;
        if handle.stored_integrity_state()? == ArtifactIntegrityState::Failed
            || matches!(durability_state.as_str(), "CORRUPT" | "MISSING")
        {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_INTEGRITY_FAILED"));
        }
        let mut file = match self
            .artifact_store_dir
            .open(safe_internal_ref(&storage_ref)?)
        {
            Ok(file) => file.into_std(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.mark_content_hash_failed(&handle.stored_content_hash()?.tagged(), "MISSING")?;
                return Err(TaskManagerError::InvalidRecord("ARTIFACT_INTEGRITY_FAILED"));
            }
            Err(error) => return Err(error.into()),
        };
        let length_before = file.metadata()?.len();
        reader_hash_step()?;
        let verified = hash_reader(&mut file);
        let length_after = file.metadata()?.len();
        let expected_hash = handle.stored_content_hash()?.tagged();
        match verified {
            Ok((size, hash))
                if length_before == length_after
                    && size == length_after
                    && size == handle.stored_size_bytes()?
                    && hash == expected_hash =>
            {
                file.seek(SeekFrom::Start(0))?;
                reader_setup_step()?;
                let authority_connection = self.database_locator.open()?;
                authority_connection.busy_timeout(std::time::Duration::from_secs(5))?;
                let database_identity = self.store_lock.as_ref().map(|lock| lock.identity.clone());
                if let Some(identity) = database_identity.as_ref() {
                    verify_database_identity(&authority_connection, identity)?;
                }
                Ok(PreparedArtifactReader {
                    file,
                    handle,
                    authority_connection,
                    database_identity,
                })
            }
            Err(TaskManagerError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                self.mark_content_hash_failed(&expected_hash, "MISSING")?;
                Err(TaskManagerError::InvalidRecord("ARTIFACT_INTEGRITY_FAILED"))
            }
            Err(error) => Err(error),
            Ok(_) => {
                self.mark_content_hash_failed(&expected_hash, "CORRUPT")?;
                Err(TaskManagerError::InvalidRecord("ARTIFACT_INTEGRITY_FAILED"))
            }
        }
    }

    pub fn open_artifact_reader(
        &mut self,
        scope: &ArtifactReadScope,
        artifact_id: &str,
    ) -> Result<ArtifactReader> {
        let prepared = self.prepare_artifact_reader(scope, artifact_id)?;
        let admitted_at = self.clock.now();
        let lease_owner = self.lease_owner.clone();
        let lease_epoch = self.lease_epoch;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_manager_lease(&transaction, &lease_owner, lease_epoch)?;
        let grant_admission = admit_prepared_artifact_reader(
            &transaction,
            scope,
            artifact_id,
            &prepared.handle,
            &admitted_at,
        )?;
        let commit = transaction
            .commit()
            .map_err(TaskManagerError::from)
            .and_then(|()| reader_admission_commit_result_step());
        if let Err(error) = commit {
            if let (Some(execution), Some(admission)) =
                (&scope.authority.execution, grant_admission.as_ref())
            {
                let _ = replayable_reader_admission_for_grant(
                    &self.connection,
                    &scope.task_id,
                    execution,
                    artifact_id,
                    &admission.grant_id,
                    &admitted_at,
                )?;
            }
            return Err(error);
        }
        if let (Some(execution), Some(admission)) =
            (&scope.authority.execution, grant_admission.as_ref())
        {
            mark_reader_admission_delivered(
                &mut self.connection,
                &scope.task_id,
                execution,
                artifact_id,
                admission,
                &self.clock.now(),
            )?;
        }
        Ok(ArtifactReader {
            file: prepared.file,
            handle: prepared.handle,
            authority_connection: prepared.authority_connection,
            clock: Arc::clone(&self.clock),
            lease_owner,
            lease_epoch,
            database_identity: prepared.database_identity,
            task_id: scope.task_id.clone(),
            authority: scope.authority.clone(),
            artifact_id: artifact_id.to_owned(),
            grant_admission,
            _store_cleanup: self.artifact_store_cleanup.clone(),
        })
    }

    /// Seals a provider export writer to the exact Artifact, destination class, attempt, and
    /// `data.egress` grant selected by the trusted control plane.
    #[allow(
        clippy::too_many_lines,
        clippy::too_many_arguments,
        reason = "the trusted destination issuer binds the complete export operation tuple"
    )]
    pub(crate) fn issue_bound_artifact_export_destination<W, F>(
        &self,
        session: &ProviderArtifactSession,
        scope: &ArtifactReadScope,
        operation_id: &str,
        artifact_id: &str,
        destination_class: &str,
        max_size_bytes: u64,
        writer_factory: F,
    ) -> Result<ArtifactExportDestination<W>>
    where
        W: ArtifactExportWriter,
        F: FnOnce() -> std::io::Result<W> + 'static,
    {
        self.validate_provider_artifact_session(session)?;
        validate_id(operation_id, 256, "invalid Artifact export operation ID")?;
        validate_id(
            destination_class,
            256,
            "invalid Artifact export destination class",
        )?;
        let now = self.clock.now();
        let Some(execution) = scope.authority.execution.as_ref() else {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        };
        if scope.issuer_id != self.artifact_scope_issuer
            || scope.task_id != session.task_id
            || scope.authority.execution.as_ref() != Some(&session.authority)
            || !scope.artifact_ids.contains(artifact_id)
            || !artifact_read_authorized(
                &self.connection,
                &scope.task_id,
                &scope.authority,
                artifact_id,
            )?
        {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        if load_execution_authority(
            &self.connection,
            &scope.task_id,
            &execution.binding_id,
            &now,
        )? != *execution
        {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        let stored_intent_json = self
            .connection
            .query_row(
                "SELECT details_json FROM operations WHERE operation_id=?1",
                [operation_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(stored_intent_json) = stored_intent_json {
            let stored: ArtifactExportIntent = serde_json::from_str(&stored_intent_json)?;
            if !matches!(
                stored.version,
                1 | PHASE_AUTHENTICATED_EXPORT_INTENT_VERSION
            ) || stored.task_id != scope.task_id
                || stored.artifact_id != artifact_id
                || stored.destination_class != destination_class
                || stored.max_size_bytes != max_size_bytes
                || stored.principal_kind != "provider"
                || stored.principal_id != execution.principal_id
                || stored.semantic_program_hash.as_deref()
                    != Some(execution.semantic_program_hash.as_str())
                || stored.node_id.as_deref() != Some(execution.node_id.as_str())
                || stored.binding_id.as_deref() != Some(execution.binding_id.as_str())
                || stored.attempt_id.as_deref() != Some(execution.attempt_id.as_str())
                || stored.grant_id.is_none()
            {
                return Err(TaskManagerError::InvalidRecord(
                    "ARTIFACT_EXPORT_OPERATION_ID_REUSE_CONFLICT",
                ));
            }
            let artifact = self
                .get_artifact(artifact_id)?
                .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_NOT_FOUND"))?;
            if stored.content_hash != *artifact.stored_content_hash()?.tagged()
                || artifact.stored_size_bytes()? > max_size_bytes
                || canonical_json(&stored)? != stored_intent_json
                || authenticate_export_operation(
                    &self.connection,
                    operation_id,
                    &stored_intent_json,
                )?
                .is_none()
            {
                return Err(TaskManagerError::InvalidRecord(
                    "ARTIFACT_EXPORT_OPERATION_ID_REUSE_CONFLICT",
                ));
            }
            return Ok(ArtifactExportDestination {
                writer_factory: Some(Box::new(writer_factory)),
                writer: None,
                external_effect_possible: false,
                operation_id: operation_id.to_owned(),
                intent_json: stored_intent_json,
                issuer_id: self.artifact_scope_issuer.clone(),
                scope_id: scope.scope_id.clone(),
                task_id: scope.task_id.clone(),
                artifact_id: artifact_id.to_owned(),
                destination_class: destination_class.to_owned(),
                authority: scope.authority.clone(),
                expected_grant_id: stored.grant_id,
                grant_admission: None,
                consumed: false,
            });
        }
        let grant = exact_operation_grant(
            &self.connection,
            &scope.task_id,
            execution,
            "data.egress",
            "destination",
            destination_class,
            &now,
            None,
        )?
        .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?;
        let artifact = self
            .get_artifact(artifact_id)?
            .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_NOT_FOUND"))?;
        if artifact.stored_size_bytes()? > max_size_bytes {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_SIZE_LIMIT"));
        }
        let intent_json = canonical_json(&ArtifactExportIntent {
            version: PHASE_AUTHENTICATED_EXPORT_INTENT_VERSION,
            task_id: scope.task_id.clone(),
            artifact_id: artifact_id.to_owned(),
            content_hash: artifact.stored_content_hash()?.tagged().clone(),
            destination_class: destination_class.to_owned(),
            max_size_bytes,
            principal_kind: "provider".to_owned(),
            principal_id: execution.principal_id.clone(),
            semantic_program_hash: Some(execution.semantic_program_hash.clone()),
            node_id: Some(execution.node_id.clone()),
            binding_id: Some(execution.binding_id.clone()),
            attempt_id: Some(execution.attempt_id.clone()),
            grant_id: Some(grant.grant_id.clone()),
        })?;
        Ok(ArtifactExportDestination {
            writer_factory: Some(Box::new(writer_factory)),
            writer: None,
            external_effect_possible: false,
            operation_id: operation_id.to_owned(),
            intent_json,
            issuer_id: self.artifact_scope_issuer.clone(),
            scope_id: scope.scope_id.clone(),
            task_id: scope.task_id.clone(),
            artifact_id: artifact_id.to_owned(),
            destination_class: destination_class.to_owned(),
            authority: scope.authority.clone(),
            expected_grant_id: Some(grant.grant_id),
            grant_admission: None,
            consumed: false,
        })
    }

    /// Replays the durable result of an exact provider-bound export operation.
    ///
    /// This boundary performs no Artifact read, destination open, or grant admission. It is
    /// therefore usable after response loss even when the original `artifact.read` and
    /// `data.egress` grants were one-shot and have already been consumed.
    pub fn replay_bound_artifact_export(
        &self,
        session: &ProviderArtifactSession,
        operation_id: &str,
    ) -> Result<u64> {
        validate_id(operation_id, 256, "invalid Artifact export operation ID")?;
        if session.issuer_id != self.artifact_scope_issuer {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        ensure_task_is_not_recovering(&self.connection, &session.task_id)?;
        let intent_json = self
            .connection
            .query_row(
                "SELECT details_json FROM operations WHERE operation_id=?1",
                [operation_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_OPERATION_ID_REUSE_CONFLICT",
            ))?;
        let intent: ArtifactExportIntent = serde_json::from_str(&intent_json)?;
        if !matches!(
            intent.version,
            1 | PHASE_AUTHENTICATED_EXPORT_INTENT_VERSION
        ) || canonical_json(&intent)? != intent_json
            || intent.task_id != session.task_id
            || intent.principal_kind != "provider"
            || intent.principal_id != session.authority.principal_id
            || intent.semantic_program_hash.as_deref()
                != Some(session.authority.semantic_program_hash.as_str())
            || intent.node_id.as_deref() != Some(session.authority.node_id.as_str())
            || intent.binding_id.as_deref() != Some(session.authority.binding_id.as_str())
            || intent.attempt_id.as_deref() != Some(session.authority.attempt_id.as_str())
            || intent.grant_id.is_none()
        {
            return Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_OPERATION_ID_REUSE_CONFLICT",
            ));
        }
        authenticate_export_operation(&self.connection, operation_id, &intent_json)?.ok_or(
            TaskManagerError::InvalidRecord("ARTIFACT_EXPORT_OPERATION_ID_REUSE_CONFLICT"),
        )?
    }

    /// Seals an owner-mediated export writer after owner authentication has already completed.
    pub(crate) fn issue_owned_artifact_export_destination<W, F>(
        &self,
        scope: &ArtifactReadScope,
        operation_id: &str,
        artifact_id: &str,
        destination_class: &str,
        max_size_bytes: u64,
        writer_factory: F,
    ) -> Result<ArtifactExportDestination<W>>
    where
        W: ArtifactExportWriter,
        F: FnOnce() -> std::io::Result<W> + 'static,
    {
        validate_id(operation_id, 256, "invalid Artifact export operation ID")?;
        validate_id(
            destination_class,
            256,
            "invalid Artifact export destination class",
        )?;
        ensure_task_is_not_recovering(&self.connection, &scope.task_id)?;
        let now = self.clock.now();
        if scope.issuer_id != self.artifact_scope_issuer
            || scope.authority.execution.is_some()
            || !scope.artifact_ids.contains(artifact_id)
            || capture_read_authority(&self.connection, &scope.task_id, None, &now)?
                != scope.authority
            || !artifact_read_authorized(
                &self.connection,
                &scope.task_id,
                &scope.authority,
                artifact_id,
            )?
        {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        let artifact = self
            .get_artifact(artifact_id)?
            .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_NOT_FOUND"))?;
        if artifact.stored_size_bytes()? > max_size_bytes {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_SIZE_LIMIT"));
        }
        let intent_json = canonical_json(&ArtifactExportIntent {
            version: PHASE_AUTHENTICATED_EXPORT_INTENT_VERSION,
            task_id: scope.task_id.clone(),
            artifact_id: artifact_id.to_owned(),
            content_hash: artifact.stored_content_hash()?.tagged().clone(),
            destination_class: destination_class.to_owned(),
            max_size_bytes,
            principal_kind: scope.authority.task_principal_kind.clone(),
            principal_id: scope.authority.task_principal_id.clone(),
            semantic_program_hash: None,
            node_id: None,
            binding_id: None,
            attempt_id: None,
            grant_id: None,
        })?;
        Ok(ArtifactExportDestination {
            writer_factory: Some(Box::new(writer_factory)),
            writer: None,
            external_effect_possible: false,
            operation_id: operation_id.to_owned(),
            intent_json,
            issuer_id: self.artifact_scope_issuer.clone(),
            scope_id: scope.scope_id.clone(),
            task_id: scope.task_id.clone(),
            artifact_id: artifact_id.to_owned(),
            destination_class: destination_class.to_owned(),
            authority: scope.authority.clone(),
            expected_grant_id: None,
            grant_admission: None,
            consumed: false,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "keeps egress admission, bounded copy, and its provenance receipt together"
    )]
    pub fn export_artifact<W: ArtifactExportWriter>(
        &mut self,
        scope: &ArtifactReadScope,
        artifact_id: &str,
        destination: &mut ArtifactExportDestination<W>,
    ) -> Result<u64> {
        if destination.issuer_id != self.artifact_scope_issuer
            || destination.scope_id != scope.scope_id
            || destination.task_id != scope.task_id
            || destination.artifact_id != artifact_id
            || destination.authority != scope.authority
        {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        ensure_task_is_not_recovering(&self.connection, &scope.task_id)?;
        if let Some(replay) = authenticate_export_operation(
            &self.connection,
            &destination.operation_id,
            &destination.intent_json,
        )? {
            if matches!(
                &replay,
                Err(TaskManagerError::InvalidRecord(
                    "ARTIFACT_EXPORT_OUTCOME_UNKNOWN"
                ))
            ) {
                self.ensure_unknown_export_recovery_inventory(&scope.task_id)?;
            }
            return replay;
        }
        if destination.consumed {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        let intent: ArtifactExportIntent = serde_json::from_str(&destination.intent_json)?;
        ensure_no_unknown_artifact_export(&self.connection, &intent.task_id)?;
        if unresolved_export_effect_exists(&self.connection, &intent)? {
            return Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_OUTCOME_UNKNOWN",
            ));
        }
        export_reservation_race_step()?;
        let prepared_reader = self.prepare_artifact_reader(scope, artifact_id)?;
        if prepared_reader.handle.stored_size_bytes()? > intent.max_size_bytes
            || prepared_reader.handle.stored_content_hash()?.tagged() != intent.content_hash
        {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_SIZE_LIMIT"));
        }
        let admitted_at = self.clock.now();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_manager_lease(&transaction, &self.lease_owner, self.lease_epoch)?;
        ensure_task_is_not_recovering(&transaction, &scope.task_id)?;
        let unresolved_duplicate = unresolved_export_effect_exists(&transaction, &intent)?;
        if unresolved_duplicate {
            return Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_OUTCOME_UNKNOWN",
            ));
        }
        let intent_hash =
            canonical_text_digest("aios.artifact-export.intent.v1", &destination.intent_json);
        let admission_event = export_phase_event(
            &intent,
            &destination.operation_id,
            "pre-destination-admission",
            &admitted_at,
            &intent_hash,
            None,
        );
        let appended_admission = append_event(&transaction, &intent.task_id, &admission_event)?;
        let pre_destination_receipt = canonical_json(&PreDestinationExportAdmission {
            version: 1,
            kind: "pre-destination-admission".to_owned(),
            operation_id: destination.operation_id.clone(),
            intent_hash,
            provenance_event_id: appended_admission.event_id,
            provenance_event_hash: appended_admission.event_hash,
        })?;
        transaction.execute(
            "INSERT INTO operations(
                operation_id,task_id,semantic_program_hash,node_id,binding_id,attempt_id,
                transaction_class,effect_class,idempotency_key,state,outcome_certainty,
                external_receipt,details_json,prepared_at,started_at,finished_at
             ) VALUES (?1,?2,?3,?4,?5,?6,'irreversible_external','DATA_EGRESS',?1,
                       'STARTED',NULL,?9,?7,?8,?8,NULL)",
            params![
                destination.operation_id,
                intent.task_id,
                intent.semantic_program_hash,
                intent.node_id,
                intent.binding_id,
                intent.attempt_id,
                destination.intent_json,
                admitted_at,
                pre_destination_receipt,
            ],
        )?;
        let reader_grant_admission = admit_prepared_artifact_reader(
            &transaction,
            scope,
            artifact_id,
            &prepared_reader.handle,
            &admitted_at,
        )?;
        destination.grant_admission = match (
            scope.authority.execution.as_ref(),
            destination.expected_grant_id.as_deref(),
        ) {
            (Some(execution), Some(grant_id)) => {
                if load_execution_authority(
                    &transaction,
                    &scope.task_id,
                    &execution.binding_id,
                    &admitted_at,
                )? != *execution
                {
                    return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
                }
                let admission = admit_operation_grant(
                    &transaction,
                    &scope.task_id,
                    execution,
                    "data.egress",
                    "destination",
                    &destination.destination_class,
                    &admitted_at,
                    grant_id,
                )?;
                Some(admission)
            }
            (None, None) => None,
            _ => return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED")),
        };
        let admission_commit = transaction
            .commit()
            .map_err(TaskManagerError::from)
            .and_then(|()| export_admission_commit_result_step());
        if let Err(error) = admission_commit {
            if !authenticate_pre_destination_export_admission(
                &self.connection,
                &destination.operation_id,
                &destination.intent_json,
                &pre_destination_receipt,
            )? {
                return Err(error);
            }
            destination.consumed = true;
            return Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_FAILED_NO_EFFECT",
            ));
        }
        export_before_arm_step()?;
        self.arm_export_effect_boundary(
            &destination.operation_id,
            &destination.intent_json,
            &pre_destination_receipt,
            &scope.authority,
            reader_grant_admission.as_ref(),
            destination.grant_admission.as_ref(),
        )?;
        if let (Some(execution), Some(admission)) = (
            scope.authority.execution.as_ref(),
            reader_grant_admission.as_ref(),
        ) {
            mark_reader_admission_delivered(
                &mut self.connection,
                &scope.task_id,
                execution,
                artifact_id,
                admission,
                &self.clock.now(),
            )?;
        }
        destination.consumed = true;
        let writer_factory =
            destination
                .writer_factory
                .take()
                .ok_or(TaskManagerError::InvalidRecord(
                    "ARTIFACT_EXPORT_OPERATION_ID_REUSE_CONFLICT",
                ))?;
        // Opening or constructing an external destination may itself create,
        // truncate, or otherwise affect it, even when the callback returns an
        // error before yielding a writer.
        destination.external_effect_possible = true;
        destination.writer = if let Ok(writer) = writer_factory() {
            Some(writer)
        } else {
            self.finish_unknown_export_operation(
                &destination.operation_id,
                &destination.intent_json,
                &destination.task_id,
            )?;
            return Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_OUTCOME_UNKNOWN",
            ));
        };
        let mut reader = ArtifactReader {
            file: prepared_reader.file,
            handle: prepared_reader.handle,
            authority_connection: prepared_reader.authority_connection,
            clock: Arc::clone(&self.clock),
            lease_owner: self.lease_owner.clone(),
            lease_epoch: self.lease_epoch,
            database_identity: prepared_reader.database_identity,
            task_id: scope.task_id.clone(),
            authority: scope.authority.clone(),
            artifact_id: artifact_id.to_owned(),
            grant_admission: reader_grant_admission,
            _store_cleanup: self.artifact_store_cleanup.clone(),
        };
        let exported = match copy_export_bounded(
            &mut reader,
            destination
                .writer
                .as_mut()
                .ok_or(TaskManagerError::InvalidRecord(
                    "ARTIFACT_EXPORT_OPERATION_ID_REUSE_CONFLICT",
                ))?,
            destination.external_effect_possible,
            intent.max_size_bytes,
            &self.connection,
            &self.clock,
            &destination.task_id,
            &destination.authority,
            &destination.destination_class,
            destination.grant_admission.as_ref(),
        ) {
            Ok(exported) => exported,
            Err(failure) => {
                drop(reader);
                let uncertain = failure.external_effect_possible;
                let recorded = if uncertain {
                    self.finish_unknown_export_operation(
                        &destination.operation_id,
                        &destination.intent_json,
                        &destination.task_id,
                    )
                } else {
                    self.finish_failed_export_operation(
                        &destination.operation_id,
                        &destination.intent_json,
                        false,
                    )
                };
                return if let Err(error) = recorded {
                    Err(error)
                } else if uncertain {
                    Err(TaskManagerError::InvalidRecord(
                        "ARTIFACT_EXPORT_OUTCOME_UNKNOWN",
                    ))
                } else {
                    Err(failure.error)
                };
            }
        };
        drop(reader);
        let writer = destination
            .writer
            .as_mut()
            .ok_or(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_OPERATION_ID_REUSE_CONFLICT",
            ))?;
        export_pre_finalize_step()?;
        if validate_export_destination_fence(
            &self.connection,
            &self.clock,
            &destination.task_id,
            &destination.authority,
            &destination.destination_class,
            destination.grant_admission.as_ref(),
        )
        .is_err()
            || writer.finalize().is_err()
            || validate_export_destination_fence(
                &self.connection,
                &self.clock,
                &destination.task_id,
                &destination.authority,
                &destination.destination_class,
                destination.grant_admission.as_ref(),
            )
            .is_err()
        {
            self.finish_unknown_export_operation(
                &destination.operation_id,
                &destination.intent_json,
                &destination.task_id,
            )?;
            return Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_OUTCOME_UNKNOWN",
            ));
        }
        let exported_at = self.clock.now();
        let (actor, binding_id, provider_id) = scope.authority.execution.as_ref().map_or_else(
            || {
                (
                    json!({
                        "kind":scope.authority.task_principal_kind,
                        "id":scope.authority.task_principal_id,
                    }),
                    None,
                    None,
                )
            },
            |execution| {
                (
                    json!({"kind":"provider","id":execution.principal_id}),
                    Some(execution.binding_id.clone()),
                    Some(execution.principal_id.clone()),
                )
            },
        );
        let event = json!({
            "schema_version":SCHEMA_VERSION,
            "event_id":event_id("artifact-exported",&destination.operation_id),
            "task_id":scope.task_id,
            "event_type":"artifact.exported",
            "timestamp":exported_at,
            "actor":actor,
            "execution_binding_id":binding_id,
            "provider_id":provider_id,
            "authority_token_id":destination.grant_admission.as_ref().map(|admission| admission.grant_id.clone()),
            "input_artifacts":[artifact_id],
            "output_artifacts":[],
            "external_transfer":{
                "destination":destination.destination_class,
                "data_refs":[artifact_id],
                "purpose":null,
            },
            "status":"success",
            "details":{"operation_id":destination.operation_id,"size_bytes":exported},
        });
        let completion = (|| -> Result<u64> {
            export_completion_step()?;
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            assert_manager_lease(&transaction, &self.lease_owner, self.lease_epoch)?;
            ensure_task_is_not_recovering(&transaction, &scope.task_id)?;
            let appended = append_event(&transaction, &scope.task_id, &event)?;
            let receipt = json!({
                "version":1,
                "size_bytes":exported,
                "provenance_event_id":appended.event_id,
                "provenance_event_hash":appended.event_hash,
            });
            let changed = transaction.execute(
                "UPDATE operations
                 SET state='SUCCEEDED',outcome_certainty='COMPLETED',external_receipt=?3,
                     finished_at=?4
                 WHERE operation_id=?1 AND details_json=?2 AND state='STARTED'
                   AND outcome_certainty IS NULL",
                params![
                    destination.operation_id,
                    destination.intent_json,
                    canonical_json(&receipt)?,
                    exported_at,
                ],
            )?;
            if changed != 1 {
                return Err(TaskManagerError::InvalidRecord(
                    "ARTIFACT_EXPORT_OUTCOME_UNKNOWN",
                ));
            }
            transaction.commit()?;
            Ok(exported)
        })();
        if let Ok(exported) = completion {
            Ok(exported)
        } else {
            self.finish_unknown_export_operation(
                &destination.operation_id,
                &destination.intent_json,
                &destination.task_id,
            )?;
            Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_OUTCOME_UNKNOWN",
            ))
        }
    }

    fn finish_unknown_export_operation(
        &mut self,
        operation_id: &str,
        intent_json: &str,
        task_id: &str,
    ) -> Result<()> {
        self.finish_failed_export_operation(operation_id, intent_json, true)?;
        let state = self
            .connection
            .query_row(
                "SELECT state FROM tasks WHERE task_id=?1",
                [task_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if matches!(state.as_deref(), Some("RUNNING" | "VERIFYING" | "PAUSED")) {
            live_recovery_handoff_step()?;
        }
        self.ensure_unknown_export_recovery_inventory(task_id)
    }

    fn arm_export_effect_boundary(
        &mut self,
        operation_id: &str,
        intent_json: &str,
        pre_destination_receipt: &str,
        authority: &ReadAuthority,
        reader_grant_admission: Option<&GrantAdmission>,
        egress_grant_admission: Option<&GrantAdmission>,
    ) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_manager_lease(&transaction, &self.lease_owner, self.lease_epoch)?;
        let intent: ArtifactExportIntent = serde_json::from_str(intent_json)?;
        ensure_task_is_not_recovering(&transaction, &intent.task_id)?;
        validate_export_destination_fence(
            &transaction,
            &self.clock,
            &intent.task_id,
            authority,
            &intent.destination_class,
            egress_grant_admission,
        )?;
        match (&authority.execution, reader_grant_admission) {
            (Some(execution), Some(admission))
                if exact_operation_grant(
                    &transaction,
                    &intent.task_id,
                    execution,
                    "artifact.read",
                    "artifact",
                    &intent.artifact_id,
                    &self.clock.now(),
                    Some(admission),
                )?
                .is_some() => {}
            (None, None) => {}
            _ => return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED")),
        }
        if !authenticate_pre_destination_export_admission(
            &transaction,
            operation_id,
            intent_json,
            pre_destination_receipt,
        )? {
            return Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_OPERATION_ID_REUSE_CONFLICT",
            ));
        }
        let admission: PreDestinationExportAdmission =
            serde_json::from_str(pre_destination_receipt)?;
        let armed_at = self.clock.now();
        let armed_event = export_phase_event(
            &intent,
            operation_id,
            "effect-boundary-armed",
            &armed_at,
            &admission.intent_hash,
            Some((
                admission.provenance_event_id.as_str(),
                admission.provenance_event_hash.as_str(),
            )),
        );
        let appended_armed = append_event(&transaction, &intent.task_id, &armed_event)?;
        let armed_receipt = canonical_json(&ArmedExportAdmission {
            version: 1,
            kind: "effect-boundary-armed".to_owned(),
            operation_id: operation_id.to_owned(),
            intent_hash: admission.intent_hash,
            admission_event_id: admission.provenance_event_id,
            admission_event_hash: admission.provenance_event_hash,
            provenance_event_id: appended_armed.event_id,
            provenance_event_hash: appended_armed.event_hash,
        })?;
        let changed = transaction.execute(
            "UPDATE operations SET external_receipt=?4
             WHERE operation_id=?1 AND details_json=?2 AND state='STARTED'
               AND outcome_certainty IS NULL AND external_receipt=?3",
            params![
                operation_id,
                intent_json,
                pre_destination_receipt,
                armed_receipt
            ],
        )?;
        if changed != 1 {
            return Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_OPERATION_ID_REUSE_CONFLICT",
            ));
        }
        let commit = transaction.commit();
        if commit.is_ok()
            || authenticate_armed_export_operation(
                &self.connection,
                operation_id,
                intent_json,
                &armed_receipt,
            )?
        {
            Ok(())
        } else {
            Err(commit.err().map_or(
                TaskManagerError::InvalidRecord("ARTIFACT_EXPORT_OUTCOME_UNKNOWN"),
                TaskManagerError::from,
            ))
        }
    }

    fn ensure_unknown_export_recovery_inventory(&mut self, task_id: &str) -> Result<()> {
        let state = self
            .connection
            .query_row(
                "SELECT state FROM tasks WHERE task_id=?1",
                [task_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        match state.as_deref() {
            Some("RUNNING" | "VERIFYING" | "PAUSED") => {
                self.reconcile_live_execution(task_id)?;
            }
            Some("COMPLETED" | "FAILED" | "CANCELLED" | "ROLLED_BACK") => {
                self.persist_terminal_recovery_inventory_for_task(task_id)?;
            }
            Some("RECOVERING") => {
                self.persist_recovery_inventory_for_task(task_id)?;
            }
            None => {}
            Some(_) => {
                self.persist_recovery_inventory_for_task(task_id)?;
            }
        }
        Ok(())
    }

    fn finish_failed_export_operation(
        &mut self,
        operation_id: &str,
        intent_json: &str,
        uncertain: bool,
    ) -> Result<()> {
        let finished_at = self.clock.now();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_manager_lease(&transaction, &self.lease_owner, self.lease_epoch)?;
        transaction.execute(
            "UPDATE operations
             SET state=?3,outcome_certainty=?4,finished_at=?5
             WHERE operation_id=?1 AND details_json=?2 AND state='STARTED'
               AND outcome_certainty IS NULL",
            params![
                operation_id,
                intent_json,
                if uncertain { "UNKNOWN" } else { "FAILED" },
                if uncertain {
                    "OUTCOME_UNKNOWN"
                } else {
                    "FAILED_NO_EFFECT"
                },
                finished_at,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn ensure_export_reconciliation_challenge(
        &mut self,
        operation_id: &str,
        recovery_ref: &str,
        subject_hash: &str,
    ) -> Result<String> {
        let issued_at = self.clock.now();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_manager_lease(&transaction, &self.lease_owner, self.lease_epoch)?;
        let operation = transaction.query_row(
            "SELECT task_id,state,outcome_certainty FROM operations WHERE operation_id=?1",
            [operation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )?;
        if !matches!(
            (operation.1.as_str(), operation.2.as_deref()),
            ("UNKNOWN", Some("OUTCOME_UNKNOWN")) | ("FAILED", Some("FAILED_NO_EFFECT"))
        ) {
            return Err(TaskManagerError::InvalidRecord(
                "Artifact export reconciliation operation is not unknown",
            ));
        }
        if !super::verify_provenance_through(&transaction, &operation.0, None)? {
            return Err(TaskManagerError::InvalidRecord(
                "Artifact export reconciliation requires an intact provenance chain",
            ));
        }
        let challenge = transaction.query_row(
            "SELECT 'challenge:v1:' || lower(hex(randomblob(32)))",
            [],
            |row| row.get::<_, String>(0),
        )?;
        transaction.execute(
            "INSERT OR IGNORE INTO artifact_export_reconciliation_challenges(operation_id,recovery_assessment_id,subject_hash,challenge,issued_at) VALUES (?1,?2,?3,?4,?5)",
            params![operation_id,recovery_ref,subject_hash,challenge,issued_at],
        )?;
        let stored = transaction.query_row(
            "SELECT recovery_assessment_id,subject_hash,challenge FROM artifact_export_reconciliation_challenges WHERE operation_id=?1",
            [operation_id],
            |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?)),
        )?;
        if stored.0 != recovery_ref || stored.1 != subject_hash {
            return Err(TaskManagerError::InvalidRecord(
                "Artifact export reconciliation challenge conflicts with its subject",
            ));
        }
        transaction.commit()?;
        Ok(stored.2)
    }

    fn authenticated_export_reconciliation_replay(
        &mut self,
        operation_id: &str,
        task_id: &str,
        recovery_ref: &str,
        subject_hash: &str,
        challenge: &str,
    ) -> Result<bool> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_manager_lease(&transaction, &self.lease_owner, self.lease_epoch)?;
        let terminal = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM operations WHERE operation_id=?1 AND task_id=?2 AND state='FAILED' AND outcome_certainty='FAILED_NO_EFFECT')",
            params![operation_id,task_id],
            |row| row.get::<_,bool>(0),
        )?;
        if !terminal {
            transaction.commit()?;
            return Ok(false);
        }
        if !super::verify_provenance_through(&transaction, task_id, None)? {
            return Err(TaskManagerError::InvalidRecord(
                "Artifact export reconciliation replay requires an intact provenance chain",
            ));
        }
        let events = {
            let mut statement = transaction.prepare(
                "SELECT event_json FROM provenance_events WHERE task_id=?1 AND event_type='execution.completed' AND json_extract(event_json,'$.details.operation_id')=?2 AND json_extract(event_json,'$.details.export_reconciliation.challenge')=?3",
            )?;
            let rows = statement.query_map(params![task_id, operation_id, challenge], |row| {
                row.get::<_, String>(0)
            })?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        if events.len() != 1 {
            return Err(TaskManagerError::InvalidRecord(
                "Artifact export reconciliation replay lacks exact provenance",
            ));
        }
        let event: serde_json::Value = serde_json::from_str(&events[0])?;
        if event
            .pointer("/details/certainty")
            .and_then(serde_json::Value::as_str)
            != Some("FAILED_NO_EFFECT")
            || event
                .pointer("/details/export_reconciliation/subject_hash")
                .and_then(serde_json::Value::as_str)
                != Some(subject_hash)
            || event
                .pointer("/details/export_reconciliation/recovery_ref")
                .and_then(serde_json::Value::as_str)
                != Some(recovery_ref)
        {
            return Err(TaskManagerError::InvalidRecord(
                "Artifact export reconciliation replay provenance is invalid",
            ));
        }
        let assessed = transaction.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM recovery_assessments subject
                 JOIN recovery_assessments aggregate
                   ON aggregate.assessment_id=?1
                  AND aggregate.recovery_epoch_id=subject.recovery_epoch_id
                  AND aggregate.task_id=subject.task_id
                 WHERE subject.task_id=?2 AND subject.subject_kind='external-operation'
                   AND subject.subject_id=?3 AND subject.certainty='FAILED_NO_EFFECT'
                   AND subject.safe_action='MARK_ATTEMPT_FAILED'
                   AND json_extract(subject.assessment_json,'$.external_reconciliation_required')=0
             )",
            params![recovery_ref, task_id, format!("operation:{operation_id}")],
            |row| row.get::<_, bool>(0),
        )?;
        if !assessed {
            return Err(TaskManagerError::InvalidRecord(
                "Artifact export reconciliation replay lacks its resolved assessment",
            ));
        }
        transaction.commit()?;
        Ok(true)
    }

    /// Records trusted external evidence that an unknown export had no external effect.
    ///
    /// The verifier is selected from the immutable registry installed when this manager opened;
    /// reconciliation callers cannot supply a one-off assertion.
    ///
    /// ```compile_fail
    /// use aios_task_manager::{ArtifactExportOutcomeVerifier, TaskManager};
    /// fn forge(
    ///     manager: &mut TaskManager,
    ///     verifier: &dyn ArtifactExportOutcomeVerifier,
    /// ) {
    ///     let _ = manager.reconcile_unknown_artifact_export_no_effect("operation", verifier);
    /// }
    /// ```
    ///
    /// ```compile_fail
    /// use aios_task_manager::TaskManager;
    /// fn replace_registry(manager: &mut TaskManager) {
    ///     manager.artifact_export_verifiers.clear();
    /// }
    /// ```
    #[allow(
        clippy::too_many_lines,
        reason = "keeps export evidence authentication, idempotent provenance, and certainty transition atomic"
    )]
    pub fn reconcile_unknown_artifact_export_no_effect(
        &mut self,
        operation_id: &str,
    ) -> Result<()> {
        validate_id(operation_id, 256, "invalid Artifact export operation ID")?;
        let row = self
            .connection
            .query_row(
                "SELECT task_id,state,outcome_certainty,details_json,started_at,finished_at FROM operations
                 WHERE operation_id=?1 AND transaction_class='irreversible_external'
                   AND effect_class='DATA_EGRESS'",
                [operation_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                    ))
                },
            )
            .optional()?
            .ok_or(TaskManagerError::InvalidRecord(
                "Artifact export reconciliation operation does not exist",
            ))?;
        let intent: ArtifactExportIntent = serde_json::from_str(&row.3)?;
        if intent.task_id != row.0 || canonical_json(&intent)? != row.3 {
            return Err(TaskManagerError::InvalidRecord(
                "stored Artifact export operation is invalid",
            ));
        }
        if !super::verify_provenance_through(&self.connection, &row.0, None)? {
            return Err(TaskManagerError::InvalidRecord(
                "Artifact export reconciliation requires an intact provenance chain",
            ));
        }
        let operation_authentication =
            authenticate_export_operation(&self.connection, operation_id, &row.3)?;
        let Some(Err(TaskManagerError::InvalidRecord(authenticated_code))) =
            operation_authentication
        else {
            return Err(TaskManagerError::InvalidRecord(
                "stored Artifact export operation is invalid",
            ));
        };
        if !matches!(
            (row.1.as_str(), row.2.as_deref(), authenticated_code),
            (
                "UNKNOWN",
                Some("OUTCOME_UNKNOWN"),
                "ARTIFACT_EXPORT_OUTCOME_UNKNOWN"
            ) | (
                "FAILED",
                Some("FAILED_NO_EFFECT"),
                "ARTIFACT_EXPORT_FAILED_NO_EFFECT"
            )
        ) {
            return Err(TaskManagerError::InvalidRecord(
                "stored Artifact export operation is invalid",
            ));
        }
        let subject = ArtifactExportReconciliationSubject::from_intent(operation_id, &intent);
        let subject_json = canonical_json(&subject)?;
        let mut subject_hasher = Sha256::new();
        subject_hasher.update(b"AIOS-ARTIFACT-EXPORT-RECONCILIATION-SUBJECT\0v1\0");
        subject_hasher.update(subject_json.as_bytes());
        let subject_hash = tagged_digest(subject_hasher);
        let inventory_id = format!("operation:{operation_id}");
        let task = self
            .connection
            .query_row(
                "SELECT state,json_extract(recovery_json,'$.unknown_operations_ref')
                 FROM tasks WHERE task_id=?1",
                [&row.0],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .optional()?
            .ok_or(TaskManagerError::InvalidRecord(
                "Artifact export reconciliation Task does not exist",
            ))?;
        let challenged = self
            .connection
            .query_row(
                "SELECT recovery_assessment_id,subject_hash
                 FROM artifact_export_reconciliation_challenges WHERE operation_id=?1",
                [operation_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let recovery_ref = if let Some((recovery_ref, stored_subject_hash)) = challenged {
            if stored_subject_hash != subject_hash {
                return Err(TaskManagerError::InvalidRecord(
                    "Artifact export reconciliation challenge conflicts with its subject",
                ));
            }
            recovery_ref
        } else {
            let active = if task.0 == "RECOVERING" {
                if let Some(recovery_ref) = task.1 {
                    self.connection
                        .query_row(
                            "SELECT EXISTS(SELECT 1 FROM recovery_unknown_operations
                             WHERE assessment_id=?1 AND operation_id=?2)",
                            params![recovery_ref, inventory_id],
                            |row| row.get::<_, bool>(0),
                        )?
                        .then_some(recovery_ref)
                } else {
                    None
                }
            } else {
                None
            };
            if let Some(active) = active {
                active
            } else {
                self.connection
                    .query_row(
                        "SELECT r.assessment_id
                         FROM recovery_assessments r
                         JOIN recovery_unknown_operations u ON u.assessment_id=r.assessment_id
                         WHERE r.task_id=?1 AND r.subject_kind='task' AND u.operation_id=?2
                         ORDER BY r.created_at DESC,r.assessment_id DESC LIMIT 1",
                        params![row.0, inventory_id],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()?
                    .ok_or(TaskManagerError::InvalidRecord(
                        "Artifact export lacks persisted recovery inventory",
                    ))?
            }
        };
        let inventoried = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM recovery_unknown_operations WHERE assessment_id=?1 AND operation_id=?2)",
            params![recovery_ref, inventory_id],
            |row| row.get::<_, bool>(0),
        )?;
        if !inventoried {
            return Err(TaskManagerError::InvalidRecord(
                "Artifact export reconciliation evidence is outside the recovery inventory",
            ));
        }
        let challenge = self.ensure_export_reconciliation_challenge(
            operation_id,
            &recovery_ref,
            &subject_hash,
        )?;
        if self.authenticated_export_reconciliation_replay(
            operation_id,
            &row.0,
            &recovery_ref,
            &subject_hash,
            &challenge,
        )? {
            return Ok(());
        }
        let verifier = Arc::clone(
            self.artifact_export_verifiers
                .get(&intent.destination_class)
                .ok_or(TaskManagerError::InvalidRecord(
                    "no trusted Artifact export reconciliation adapter is registered",
                ))?,
        );
        let observation = verifier.verify_no_effect(&subject, &challenge)?;
        if observation.subject != subject || observation.challenge != challenge {
            return Err(TaskManagerError::InvalidRecord(
                "Artifact export reconciliation proof does not match its immutable subject and challenge",
            ));
        }
        validate_id(
            verifier.verifier_id(),
            256,
            "invalid Artifact export reconciliation verifier",
        )?;
        validate_id(
            &observation.evidence_ref,
            256,
            "invalid Artifact export reconciliation evidence reference",
        )?;
        validate_hash(&observation.proof_hash)?;
        parse_time(&observation.observed_at)?;
        let event_identity = format!(
            "{operation_id}:{challenge}:{}:{}",
            observation.evidence_ref, observation.proof_hash,
        );
        let reconciliation_event_id = event_id("artifact-export-reconciled", &event_identity);
        let lease_owner = self.lease_owner.clone();
        let lease_epoch = self.lease_epoch;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_manager_lease(&transaction, &lease_owner, lease_epoch)?;
        if !super::verify_provenance_through(&transaction, &row.0, None)? {
            return Err(TaskManagerError::InvalidRecord(
                "Artifact export reconciliation requires an intact provenance chain",
            ));
        }
        let replayed_proof = transaction
            .query_row(
                "SELECT task_id,event_id,event_json FROM provenance_events
                 WHERE event_type='execution.completed' AND (
                   json_extract(event_json,'$.details.export_reconciliation.proof_hash')=?1 OR
                   (json_extract(event_json,'$.details.export_reconciliation.verifier_id')=?2 AND
                    json_extract(event_json,'$.details.export_reconciliation.evidence_ref')=?3)
                 ) ORDER BY task_id,event_id LIMIT 1",
                params![
                    observation.proof_hash,
                    verifier.verifier_id(),
                    observation.evidence_ref
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        if replayed_proof
            .as_ref()
            .is_some_and(|stored| stored.0 != row.0 || stored.1 != reconciliation_event_id)
        {
            return Err(TaskManagerError::InvalidRecord(
                "Artifact export reconciliation proof was replayed for another subject",
            ));
        }
        let existing_event = transaction
            .query_row(
                "SELECT event_json,timestamp FROM provenance_events WHERE task_id=?1 AND event_id=?2",
                params![row.0,reconciliation_event_id],
                |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?)),
            )
            .optional()?;
        let event_timestamp = existing_event
            .as_ref()
            .map_or_else(|| self.clock.now(), |stored| stored.1.clone());
        let event = json!({
            "schema_version":SCHEMA_VERSION,
            "event_id":reconciliation_event_id,
            "task_id":row.0,
            "event_type":"execution.completed",
            "timestamp":event_timestamp,
            "actor":{"kind":"system-service","id":"service:recovery"},
            "status":"failure",
            "details":{
                "operation_id":operation_id,
                "certainty":"FAILED_NO_EFFECT",
                "export_reconciliation":{
                    "verifier_id":verifier.verifier_id(),
                    "evidence_ref":observation.evidence_ref,
                    "proof_hash":observation.proof_hash,
                    "challenge":challenge,
                    "observed_at":observation.observed_at,
                    "subject_hash":subject_hash,
                    "recovery_ref":recovery_ref
                }
            }
        });
        if let Some((stored_event, _)) = existing_event {
            if serde_json::from_str::<serde_json::Value>(&stored_event)? != event
                || !super::verify_provenance_through(&transaction, &row.0, None)?
            {
                return Err(TaskManagerError::InvalidRecord(
                    "Artifact export reconciliation evidence conflicts with provenance",
                ));
            }
        } else {
            append_event(&transaction, &row.0, &event)?;
        }
        let changed = transaction.execute(
            "UPDATE operations SET state='FAILED',outcome_certainty='FAILED_NO_EFFECT',finished_at=COALESCE(finished_at,?2)
             WHERE operation_id=?1 AND state='UNKNOWN' AND outcome_certainty='OUTCOME_UNKNOWN'",
            params![operation_id,observation.observed_at],
        )?;
        if changed == 0 && !(row.1 == "FAILED" && row.2.as_deref() == Some("FAILED_NO_EFFECT")) {
            return Err(TaskManagerError::InvalidRecord(
                "Artifact export reconciliation operation is not unknown",
            ));
        }
        super::reconcile_recovery_subject_in_transaction(
            &transaction,
            &recovery_ref,
            &inventory_id,
            &event_timestamp,
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn reconcile_export_operations_startup(&mut self) -> Result<()> {
        let reconciled_at = self.clock.now();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_manager_lease(&transaction, &self.lease_owner, self.lease_epoch)?;
        let started_exports = {
            let mut statement = transaction.prepare(
                "SELECT operation_id,details_json,external_receipt FROM operations
                 WHERE transaction_class='irreversible_external' AND effect_class='DATA_EGRESS'
                   AND state='STARTED' AND outcome_certainty IS NULL
                 ORDER BY operation_id",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        for (operation_id, intent_json, receipt) in started_exports {
            reconcile_started_export_operation(
                &transaction,
                &operation_id,
                &intent_json,
                receipt.as_deref(),
                &reconciled_at,
            )?;
        }
        transaction.commit()?;
        let task_ids = {
            let mut statement = self.connection.prepare(
                "SELECT DISTINCT task_id FROM operations
                 WHERE transaction_class='irreversible_external' AND effect_class='DATA_EGRESS'
                   AND state='UNKNOWN' AND outcome_certainty='OUTCOME_UNKNOWN'
                 ORDER BY task_id",
            )?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        for task_id in task_ids {
            self.ensure_unknown_export_recovery_inventory(&task_id)?;
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "keeps blob, integrity, and staging reconciliation in one fenced startup audit"
    )]
    pub(crate) fn reconcile_artifacts_startup(&mut self) -> Result<ArtifactReconciliationReport> {
        let reconciled_at = self.clock.now();
        let mut findings = Vec::new();
        for content_hash in reconcile_pending_blob_placements(&self.artifact_store_dir)? {
            findings.push(ArtifactReconciliationFinding {
                kind: ArtifactReconciliationKind::BlobCorrupt,
                allocation_id: None,
                content_hash,
                artifact_ids: Vec::new(),
            });
        }
        let blobs = {
            let mut statement = self.connection.prepare(
                "SELECT content_hash,size_bytes,storage_ref,durability_state FROM artifact_blobs ORDER BY content_hash",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        let known = blobs
            .iter()
            .map(|row| row.0.clone())
            .collect::<BTreeSet<_>>();
        let known_refs = blobs
            .iter()
            .map(|row| row.2.clone())
            .collect::<BTreeSet<_>>();
        for (content_hash, size, storage_ref, durability_state) in blobs {
            let status = match hash_internal_file(&self.artifact_store_dir, &storage_ref) {
                Err(TaskManagerError::Io(error))
                    if error.kind() == std::io::ErrorKind::NotFound =>
                {
                    Some((ArtifactReconciliationKind::BlobMissing, "MISSING"))
                }
                Err(error) => return Err(error),
                Ok((actual_size, actual_hash))
                    if actual_size != u64::try_from(size).unwrap_or(u64::MAX)
                        || actual_hash != content_hash =>
                {
                    Some((ArtifactReconciliationKind::BlobCorrupt, "CORRUPT"))
                }
                Ok(_) => None,
            };
            if let Some((kind, state)) = status {
                let artifact_ids = self.artifact_ids_for_hash(&content_hash)?;
                self.mark_blob_failed(&content_hash, state, &artifact_ids, &reconciled_at)?;
                findings.push(ArtifactReconciliationFinding {
                    kind,
                    allocation_id: None,
                    content_hash: Some(content_hash),
                    artifact_ids,
                });
            } else if durability_state == "ORPHANED" || durability_state == "STAGED" {
                findings.push(ArtifactReconciliationFinding {
                    kind: ArtifactReconciliationKind::BlobOrphaned,
                    allocation_id: None,
                    content_hash: Some(content_hash),
                    artifact_ids: Vec::new(),
                });
            }
        }
        for relative in physical_blob_refs(&self.artifact_store_dir)? {
            if known_refs.contains(&relative) {
                continue;
            }
            let (size, hash) = hash_internal_file(&self.artifact_store_dir, &relative)?;
            let expected_hash = content_hash_from_blob_ref(&relative)?;
            if hash != expected_hash {
                quarantine_orphan_blob_path(&self.artifact_store_dir, &relative, &hash)?;
                findings.push(ArtifactReconciliationFinding {
                    kind: ArtifactReconciliationKind::BlobCorrupt,
                    allocation_id: None,
                    content_hash: Some(expected_hash),
                    artifact_ids: Vec::new(),
                });
                continue;
            }
            if known.contains(&hash) {
                continue;
            }
            let lease_owner = self.lease_owner.clone();
            let lease_epoch = self.lease_epoch;
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            assert_manager_lease(&transaction, &lease_owner, lease_epoch)?;
            transaction.execute("INSERT OR IGNORE INTO artifact_blobs(content_hash,size_bytes,storage_ref,durability_state,created_at,verified_at) VALUES (?1,?2,?3,'ORPHANED',?4,?4)",params![hash,to_i64(size)?,relative,reconciled_at])?;
            transaction.commit()?;
            findings.push(ArtifactReconciliationFinding {
                kind: ArtifactReconciliationKind::BlobOrphaned,
                allocation_id: None,
                content_hash: Some(hash),
                artifact_ids: Vec::new(),
            });
        }
        let staged = {
            let mut statement = self.connection.prepare(
                "SELECT a.allocation_id,a.staging_ref,a.state,a.expires_at,t.state,a.task_id,
                        a.publication_id
                 FROM artifact_output_allocations a
                 JOIN tasks t ON t.task_id=a.task_id
                 WHERE a.staging_ref IS NOT NULL
                 ORDER BY a.allocation_id",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<String>>(6)?,
                ))
            })?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        let mut terminal_cleanup_processed = false;
        let mut staged = staged;
        for (allocation_id, staging_ref, state, expires_at, task_state, task_id, publication_id) in
            &mut staged
        {
            let expired = parse_time(expires_at)? <= parse_time(&reconciled_at)?;
            let terminal_task = matches!(
                task_state.as_str(),
                "COMPLETED" | "FAILED" | "CANCELLED" | "ROLLED_BACK"
            );
            let terminal_allocation = matches!(state.as_str(), "FAILED" | "ABORTED" | "EXPIRED");
            if (matches!(state.as_str(), "WRITING" | "FINALIZING") && (expired || terminal_task))
                || terminal_allocation
            {
                let target_state = if terminal_allocation {
                    state.clone()
                } else if expired {
                    "EXPIRED".to_owned()
                } else {
                    "ABORTED".to_owned()
                };
                let reason_code = if expired || state == "EXPIRED" {
                    "ARTIFACT_ALLOCATION_EXPIRED"
                } else {
                    "ARTIFACT_ALLOCATION_STATE_CONFLICT"
                };
                let transaction = self
                    .connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)?;
                assert_manager_lease(&transaction, &self.lease_owner, self.lease_epoch)?;
                let pending_publications = {
                    let mut statement = transaction.prepare(
                        "SELECT publication_id,task_id,request_json FROM artifact_publications
                         WHERE allocation_id=?1 AND state='PENDING'
                         ORDER BY publication_id LIMIT 2",
                    )?;
                    let rows = statement.query_map([allocation_id.as_str()], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    })?;
                    rows.collect::<std::result::Result<Vec<_>, _>>()?
                };
                if pending_publications.len() > 1 {
                    return Err(TaskManagerError::InvalidRecord(
                        "stored pending Artifact publication is invalid",
                    ));
                }
                let pending_publication = pending_publications.into_iter().next();
                if let Some(expected_publication_id) = publication_id.as_deref() {
                    if pending_publication
                        .as_ref()
                        .is_some_and(|row| row.0 != expected_publication_id)
                    {
                        return Err(TaskManagerError::InvalidRecord(
                            "stored pending Artifact publication is invalid",
                        ));
                    }
                }
                if let Some((pending_publication_id, pending_task_id, request_json)) =
                    pending_publication.as_ref()
                {
                    let request: ArtifactPublicationRequest = serde_json::from_str(request_json)?;
                    validate_publication_request(&request)?;
                    if canonical_json(&request)? != *request_json
                        || request.publication_id != *pending_publication_id
                        || request.allocation_id != *allocation_id
                        || pending_task_id != task_id
                        || request.task_id != *task_id
                    {
                        return Err(TaskManagerError::InvalidRecord(
                            "stored pending Artifact publication is invalid",
                        ));
                    }
                    let result = publication_failure(&request, reason_code, reconciled_at.clone());
                    let publication_state = if expired || state == "EXPIRED" || state == "FAILED" {
                        "FAILED"
                    } else {
                        "ABORTED"
                    };
                    let changed = transaction.execute(
                        "UPDATE artifact_publications
                         SET state=?2,result_json=?3,committed_at=?4
                         WHERE publication_id=?1 AND allocation_id=?5 AND task_id=?6
                           AND state='PENDING'",
                        params![
                            pending_publication_id,
                            publication_state,
                            canonical_json(&result)?,
                            reconciled_at,
                            allocation_id.as_str(),
                            task_id.as_str(),
                        ],
                    )?;
                    if changed != 1 {
                        return Err(TaskManagerError::InvalidRecord(
                            "ARTIFACT_ALLOCATION_STATE_CONFLICT",
                        ));
                    }
                } else if state == "FINALIZING" {
                    return Err(TaskManagerError::InvalidRecord(
                        "stored finalizing Artifact allocation has no publication",
                    ));
                } else if let Some(publication_id) = publication_id.as_deref() {
                    let terminal_publication = transaction.query_row(
                        "SELECT COUNT(*) FROM artifact_publications
                         WHERE publication_id=?1 AND allocation_id=?2 AND task_id=?3
                           AND state IN ('FAILED','ABORTED')
                           AND result_json IS NOT NULL AND committed_at IS NOT NULL",
                        params![publication_id, allocation_id.as_str(), task_id.as_str()],
                        |row| row.get::<_, i64>(0),
                    )?;
                    if terminal_publication != 1 {
                        return Err(TaskManagerError::InvalidRecord(
                            "stored terminal Artifact publication is invalid",
                        ));
                    }
                }
                let resolved_publication_id = pending_publication
                    .as_ref()
                    .map(|row| row.0.as_str())
                    .or(publication_id.as_deref());
                let changed = transaction.execute(
                    "UPDATE artifact_output_allocations
                     SET state=?2,updated_at=?3,publication_id=COALESCE(publication_id,?5)
                     WHERE allocation_id=?1 AND task_id=?6 AND state=?4
                       AND (publication_id IS NULL OR publication_id=?5)",
                    params![
                        allocation_id.as_str(),
                        target_state,
                        reconciled_at,
                        state.as_str(),
                        resolved_publication_id,
                        task_id.as_str(),
                    ],
                )?;
                if changed != 1 {
                    return Err(TaskManagerError::InvalidRecord(
                        "ARTIFACT_ALLOCATION_STATE_CONFLICT",
                    ));
                }
                transaction.commit()?;
                target_state.clone_into(state);
            }
            if matches!(state.as_str(), "WRITING" | "FINALIZING") {
                reconcile_interrupted_staging_seal(
                    &self.artifact_store_dir,
                    allocation_id,
                    staging_ref,
                )?;
            }
            if matches!(
                state.as_str(),
                "ALLOCATED" | "FAILED" | "ABORTED" | "EXPIRED" | "PUBLISHED"
            ) {
                terminal_cleanup_processed = true;
                let seal = seal_ref(staging_ref);
                for residue in [staging_ref.clone(), seal.clone(), format!("{seal}.pending")] {
                    match self
                        .artifact_store_dir
                        .remove_file(safe_internal_ref(&residue)?)
                    {
                        Ok(()) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error.into()),
                    }
                }
            }
        }
        if terminal_cleanup_processed {
            durability_step("sync-terminal-staging-cleanup")?;
            sync_cap_directory(&self.artifact_store_dir, "staging")?;
        }
        let staged_by_ref = staged
            .into_iter()
            .filter(|(_, _, state, _, _, _, _)| {
                !matches!(
                    state.as_str(),
                    "ALLOCATED" | "FAILED" | "ABORTED" | "EXPIRED" | "PUBLISHED"
                )
            })
            .map(|(allocation_id, staging_ref, _, _, _, _, _)| (staging_ref, allocation_id))
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut removed_import_residue = false;
        for entry in self.artifact_store_dir.read_dir("staging")? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    continue;
                };
                if name.ends_with(".sealed") {
                    continue;
                }
                let staging_ref = format!("staging/{name}");
                if name.starts_with("import-") && !staged_by_ref.contains_key(&staging_ref) {
                    self.artifact_store_dir
                        .remove_file(safe_internal_ref(&staging_ref)?)?;
                    removed_import_residue = true;
                }
                findings.push(ArtifactReconciliationFinding {
                    kind: ArtifactReconciliationKind::StagingOrphaned,
                    allocation_id: staged_by_ref.get(&staging_ref).cloned(),
                    content_hash: None,
                    artifact_ids: Vec::new(),
                });
            }
        }
        if removed_import_residue {
            sync_cap_directory(&self.artifact_store_dir, "staging")?;
        }
        Ok(ArtifactReconciliationReport {
            reconciled_at,
            findings,
        })
    }

    fn reserve_publication(
        &mut self,
        request: &ArtifactPublicationRequest,
        request_json: &str,
    ) -> Result<()> {
        publication_reservation_step()?;
        let now = self.clock.now();
        let lease_owner = self.lease_owner.clone();
        let lease_epoch = self.lease_epoch;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_manager_lease(&transaction, &lease_owner, lease_epoch)?;
        ensure_task_is_not_recovering(&transaction, &request.task_id)?;
        let allocation = load_allocation_row(&transaction, &request.allocation_id)?.ok_or(
            TaskManagerError::InvalidRecord("ARTIFACT_ALLOCATION_NOT_FOUND"),
        )?;
        if allocation.task_id != request.task_id {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        if parse_time(&allocation.expires_at)? <= parse_time(&now)? {
            return Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_ALLOCATION_EXPIRED",
            ));
        }
        if matches!(
            allocation.state.as_str(),
            "FAILED" | "ABORTED" | "EXPIRED" | "PUBLISHED"
        ) {
            return Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_ALLOCATION_STATE_CONFLICT",
            ));
        }
        let occupied = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM artifact_publications WHERE allocation_id=?1)",
            [&request.allocation_id],
            |row| row.get::<_, bool>(0),
        )?;
        if occupied {
            return Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_PUBLICATION_ID_REUSE_CONFLICT",
            ));
        }
        transaction.execute("INSERT INTO artifact_publications(publication_id,allocation_id,task_id,request_json,state,requested_at) VALUES (?1,?2,?3,?4,'PENDING',?5)",params![request.publication_id,request.allocation_id,request.task_id,request_json,now])?;
        transaction.commit()?;
        Ok(())
    }

    fn begin_reserved_publication(
        &mut self,
        request: &ArtifactPublicationRequest,
        request_json: &str,
    ) -> Result<()> {
        let now = self.clock.now();
        let lease_owner = self.lease_owner.clone();
        let lease_epoch = self.lease_epoch;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_manager_lease(&transaction, &lease_owner, lease_epoch)?;
        ensure_task_is_not_recovering(&transaction, &request.task_id)?;
        let pending_exact = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM artifact_publications WHERE publication_id=?1 AND allocation_id=?2 AND task_id=?3 AND request_json=?4 AND state='PENDING')",
            params![request.publication_id, request.allocation_id, request.task_id, request_json],
            |row| row.get::<_, bool>(0),
        )?;
        if !pending_exact {
            return Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_PUBLICATION_ID_REUSE_CONFLICT",
            ));
        }
        let allocation = load_allocation_row(&transaction, &request.allocation_id)?.ok_or(
            TaskManagerError::InvalidRecord("ARTIFACT_ALLOCATION_NOT_FOUND"),
        )?;
        validate_publication_allocation(request, &allocation, &now)?;
        transaction.execute("UPDATE artifact_output_allocations SET state='FINALIZING',publication_id=?2,updated_at=?3 WHERE allocation_id=?1 AND state=?4",params![request.allocation_id,request.publication_id,now,request.expected_allocation_state.as_str()])?;
        transaction.commit()?;
        Ok(())
    }

    fn validate_pending_publication_authority(
        &mut self,
        request: &ArtifactPublicationRequest,
        request_json: &str,
        expected_allocation: &AllocationRow,
    ) -> Result<()> {
        let now = self.clock.now();
        let lease_owner = self.lease_owner.clone();
        let lease_epoch = self.lease_epoch;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_manager_lease(&transaction, &lease_owner, lease_epoch)?;
        ensure_task_is_not_recovering(&transaction, &request.task_id)?;
        let pending_exact = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM artifact_publications WHERE publication_id=?1 AND allocation_id=?2 AND task_id=?3 AND request_json=?4 AND state='PENDING')",
            params![request.publication_id,request.allocation_id,request.task_id,request_json],
            |row| row.get::<_,bool>(0),
        )?;
        if !pending_exact {
            return Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_PUBLICATION_ID_REUSE_CONFLICT",
            ));
        }
        let allocation = load_allocation_row(&transaction, &request.allocation_id)?.ok_or(
            TaskManagerError::InvalidRecord("ARTIFACT_ALLOCATION_NOT_FOUND"),
        )?;
        if allocation != *expected_allocation {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        validate_publication_allocation(request, &allocation, &now)?;
        validate_publication_authority(&transaction, request, &allocation, &now)?;
        transaction.commit()?;
        Ok(())
    }

    fn fail_pending_publication(
        &mut self,
        request: &ArtifactPublicationRequest,
        reason_code: &str,
    ) -> Result<ArtifactPublicationResult> {
        let now = self.clock.now();
        let result = publication_failure(request, reason_code, now.clone());
        let lease_owner = self.lease_owner.clone();
        let lease_epoch = self.lease_epoch;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_manager_lease(&transaction, &lease_owner, lease_epoch)?;
        ensure_task_is_not_recovering(&transaction, &request.task_id)?;
        transaction.execute(
            "UPDATE artifact_publications SET state='FAILED',result_json=?2,committed_at=?3 WHERE publication_id=?1 AND state='PENDING'",
            params![request.publication_id, canonical_json(&result)?, now],
        )?;
        transaction.execute(
            "UPDATE artifact_output_allocations
             SET state='FAILED',publication_id=?2,updated_at=?3
             WHERE allocation_id=?1 AND state IN ('ALLOCATED','WRITING','FINALIZING')
               AND (publication_id IS NULL OR publication_id=?2)",
            params![request.allocation_id, request.publication_id, now],
        )?;
        transaction.commit()?;
        Ok(result)
    }

    /// Authenticates and aborts a crash-left pre-effect publication reservation.
    pub(crate) fn abort_pending_publication(
        &mut self,
        request: &ArtifactPublicationRequest,
    ) -> Result<ArtifactPublicationResult> {
        validate_publication_request(request)?;
        let request_json = canonical_json(request)?;
        let now = self.clock.now();
        let result =
            publication_failure(request, "ARTIFACT_ALLOCATION_STATE_CONFLICT", now.clone());
        let lease_owner = self.lease_owner.clone();
        let lease_epoch = self.lease_epoch;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_manager_lease(&transaction, &lease_owner, lease_epoch)?;
        let stored = transaction
            .query_row(
                "SELECT request_json,state,result_json,allocation_id,task_id,committed_at
                 FROM artifact_publications WHERE publication_id=?1",
                [&request.publication_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((stored_request, state, stored_result, allocation_id, task_id, committed_at)) =
            stored
        else {
            return Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_ALLOCATION_NOT_FOUND",
            ));
        };
        if stored_request != request_json
            || allocation_id != request.allocation_id
            || task_id != request.task_id
        {
            return Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_PUBLICATION_ID_REUSE_CONFLICT",
            ));
        }
        if state == "ABORTED" {
            return authenticate_failed_publication(
                &transaction,
                request,
                &state,
                stored_result.as_deref(),
                committed_at.as_deref(),
            );
        }
        if state != "PENDING" {
            return Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_PUBLICATION_ID_REUSE_CONFLICT",
            ));
        }
        let publication_changed = transaction.execute(
            "UPDATE artifact_publications
             SET state='ABORTED',result_json=?2,committed_at=?3
             WHERE publication_id=?1 AND state='PENDING'",
            params![request.publication_id, canonical_json(&result)?, now],
        )?;
        let allocation_changed = transaction.execute(
            "UPDATE artifact_output_allocations
             SET state='ABORTED',publication_id=?2,updated_at=?3
             WHERE allocation_id=?1 AND task_id=?4
               AND state IN ('ALLOCATED','WRITING','FINALIZING')
               AND (publication_id IS NULL OR publication_id=?2)",
            params![
                request.allocation_id,
                request.publication_id,
                now,
                request.task_id
            ],
        )?;
        if publication_changed != 1 || allocation_changed != 1 {
            return Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_ALLOCATION_STATE_CONFLICT",
            ));
        }
        transaction.commit()?;
        Ok(result)
    }

    fn sealed_staging(
        &self,
        allocation: &AllocationRow,
        request: &ArtifactPublicationRequest,
    ) -> Result<SealedStaging> {
        let staging_ref =
            allocation
                .staging_ref
                .as_deref()
                .ok_or(TaskManagerError::InvalidRecord(
                    "ARTIFACT_ALLOCATION_STATE_CONFLICT",
                ))?;
        let file = self
            .artifact_store_dir
            .open(safe_internal_ref(&seal_ref(staging_ref))?)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    TaskManagerError::InvalidRecord("ARTIFACT_ALLOCATION_STATE_CONFLICT")
                } else {
                    TaskManagerError::Io(error)
                }
            })?;
        let mut bytes = Vec::new();
        file.take(16 * 1024).read_to_end(&mut bytes)?;
        let sealed: SealedStaging = serde_json::from_slice(&bytes)
            .map_err(|_| TaskManagerError::InvalidRecord("ARTIFACT_HASH_MISMATCH"))?;
        if sealed.version != SEALED_STAGING_VERSION || sealed.allocation_id != request.allocation_id
        {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_HASH_MISMATCH"));
        }
        if sealed.size_bytes
            > allocation
                .max_size_bytes
                .unwrap_or(IMPORT_LIMIT)
                .min(IMPORT_LIMIT)
        {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_SIZE_LIMIT"));
        }
        validate_hash(&sealed.content_hash)?;
        Ok(sealed)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "authenticates the complete committed publication receipt before replay"
    )]
    fn authenticate_committed_publication(
        &mut self,
        request: &ArtifactPublicationRequest,
        result_json: Option<&str>,
        stored_hash: Option<&str>,
    ) -> Result<ArtifactPublicationResult> {
        let failed_at = self.clock.now();
        let failed =
            || publication_failure(request, "ARTIFACT_INTEGRITY_FAILED", failed_at.clone());
        let Some(result_json) = result_json else {
            return Ok(failed());
        };
        let Ok(result) = serde_json::from_str::<ArtifactPublicationResult>(result_json) else {
            return Ok(failed());
        };
        let row = self
            .connection
            .query_row(
                "SELECT p.artifact_id,p.content_hash,p.committed_at,a.state,a.publication_id,a.published_artifact_id,a.task_id,a.semantic_program_hash,a.node_id,a.binding_id,a.attempt_id,r.uri,r.semantic_type,r.media_type,r.format,r.size_bytes,r.content_hash,r.origin_task_id,r.origin_program_hash,r.origin_node_id,r.origin_binding_id,r.integrity_state,b.size_bytes,b.storage_ref,b.durability_state,t.role,t.node_id,e.event_hash,e.task_id,e.event_type,e.semantic_program_hash,e.node_id,e.execution_binding_id,e.status,e.event_json FROM artifact_publications p JOIN artifact_output_allocations a ON a.allocation_id=p.allocation_id JOIN artifacts r ON r.artifact_id=p.artifact_id JOIN artifact_blobs b ON b.content_hash=p.content_hash JOIN task_artifacts t ON t.task_id=p.task_id AND t.artifact_id=p.artifact_id LEFT JOIN provenance_events e ON e.event_id=?2 WHERE p.publication_id=?1 AND p.allocation_id=?3 AND p.task_id=?4 AND p.state='COMMITTED'",
                params![request.publication_id,result.provenance_event_id,request.allocation_id,request.task_id],
                |row| Ok((
                    row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,Option<String>>(2)?,
                    row.get::<_,String>(3)?,row.get::<_,Option<String>>(4)?,row.get::<_,Option<String>>(5)?,
                    row.get::<_,String>(6)?,row.get::<_,String>(7)?,row.get::<_,String>(8)?,
                    row.get::<_,Option<String>>(9)?,row.get::<_,Option<String>>(10)?,row.get::<_,String>(11)?,
                    row.get::<_,Option<String>>(12)?,row.get::<_,String>(13)?,row.get::<_,Option<String>>(14)?,
                    row.get::<_,i64>(15)?,row.get::<_,String>(16)?,row.get::<_,Option<String>>(17)?,
                    row.get::<_,Option<String>>(18)?,row.get::<_,Option<String>>(19)?,row.get::<_,Option<String>>(20)?,
                    row.get::<_,String>(21)?,row.get::<_,i64>(22)?,row.get::<_,String>(23)?,
                    row.get::<_,String>(24)?,row.get::<_,String>(25)?,row.get::<_,Option<String>>(26)?,
                    row.get::<_,Option<String>>(27)?,row.get::<_,Option<String>>(28)?,row.get::<_,Option<String>>(29)?,
                    row.get::<_,Option<String>>(30)?,row.get::<_,Option<String>>(31)?,row.get::<_,Option<String>>(32)?,
                    row.get::<_,Option<String>>(33)?,row.get::<_,Option<String>>(34)?
                )),
            )
            .optional()?;
        let Some(row) = row else {
            return Ok(failed());
        };
        let size = u64::try_from(row.15).unwrap_or(u64::MAX);
        let blob_size = u64::try_from(row.22).unwrap_or(u64::MAX);
        let event = row
            .34
            .as_deref()
            .and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok());
        let event_exact = event.as_ref().is_some_and(|event| {
            let event_blob_reused = event
                .pointer("/details/blob_reused")
                .map(serde_json::Value::as_bool);
            let historical_blob_reused_compatible = match event_blob_reused {
                None => true,
                Some(Some(value)) => Some(value) == result.blob_reused,
                Some(None) => false,
            };
            event
                .get("output_artifacts")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|artifacts| {
                    artifacts.len() == 1 && artifacts[0].as_str() == Some(row.0.as_str())
                })
                && event
                    .pointer("/details/allocation_id")
                    .and_then(serde_json::Value::as_str)
                    == Some(request.allocation_id.as_str())
                && event
                    .pointer("/details/publication_id")
                    .and_then(serde_json::Value::as_str)
                    == Some(request.publication_id.as_str())
                && event
                    .pointer("/details/content_hash")
                    .and_then(serde_json::Value::as_str)
                    == Some(row.1.as_str())
                && event
                    .pointer("/details/size_bytes")
                    .and_then(serde_json::Value::as_u64)
                    == Some(size)
                && historical_blob_reused_compatible
        });
        let lineage = {
            let mut statement = self.connection.prepare(
                "SELECT parent_artifact_id,relationship FROM artifact_lineage WHERE child_artifact_id=?1 ORDER BY parent_artifact_id,relationship",
            )?;
            statement
                .query_map([&row.0], |lineage_row| {
                    Ok((
                        lineage_row.get::<_, String>(0)?,
                        lineage_row.get::<_, String>(1)?,
                    ))
                })?
                .collect::<std::result::Result<BTreeSet<_>, _>>()?
        };
        let expected_lineage = request
            .lineage
            .input_artifact_ids
            .iter()
            .map(|parent| (parent.clone(), "consumed-by".to_owned()))
            .chain(
                request
                    .lineage
                    .derived_from_artifact_ids
                    .iter()
                    .map(|parent| (parent.clone(), "transformed-to".to_owned())),
            )
            .collect::<BTreeSet<_>>();
        let artifact_exact = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM artifacts r JOIN artifact_output_allocations a ON a.published_artifact_id=r.artifact_id WHERE r.artifact_id=?1 AND r.labels_json=?2 AND r.sensitivity=a.sensitivity AND r.retention_class=a.retention)",
            params![row.0,serde_json::to_string(&request.labels)?],
            |artifact_row| artifact_row.get::<_,bool>(0),
        )?;
        let exact = result.schema_version == SCHEMA_VERSION
            && result.publication_id == request.publication_id
            && result.allocation_id == request.allocation_id
            && result.task_id == request.task_id
            && result.published
            && result.reason_code == "ARTIFACT_PUBLICATION_APPLIED"
            && result.message.is_none()
            && result.blob_reused.is_some()
            && row.0 == artifact_id("publication", &request.publication_id)
            && result.artifact_id.as_deref() == Some(row.0.as_str())
            && row.11 == ArtifactUri::new(&row.0).as_str()
            && result.artifact_uri.as_deref() == Some(row.11.as_str())
            && result.semantic_type == row.12
            && result.media_type.as_deref() == Some(row.13.as_str())
            && result.size_bytes == Some(size)
            && result.content_hash.as_deref() == Some(row.1.as_str())
            && stored_hash == Some(row.1.as_str())
            && row.2.as_deref() == Some(result.resulted_at.as_str())
            && row.3 == "PUBLISHED"
            && row.4.as_deref() == Some(request.publication_id.as_str())
            && row.5.as_deref() == Some(row.0.as_str())
            && row.6 == request.task_id
            && row.12 == request.semantic_type
            && row.13 == request.media_type
            && row.14 == request.format
            && row.16 == row.1
            && row.17.as_deref() == Some(request.task_id.as_str())
            && row.18.as_deref() == Some(row.7.as_str())
            && row.19.as_deref() == Some(row.8.as_str())
            && row.20 == row.9
            && row.21 == "verified"
            && blob_size == size
            && row.24 == "DURABLE"
            && row.25 == "output"
            && row.26.as_deref() == Some(row.8.as_str())
            && result.provenance_event_hash == row.27
            && result.provenance_event_id.as_deref()
                == Some(event_id("artifact-created", &row.0).as_str())
            && row.28.as_deref() == Some(request.task_id.as_str())
            && row.29.as_deref() == Some("artifact.created")
            && row.30.as_deref() == Some(row.7.as_str())
            && row.31.as_deref() == Some(row.8.as_str())
            && row.32 == row.9
            && row.33.as_deref() == Some("success")
            && event_exact
            && lineage == expected_lineage
            && artifact_exact
            && super::verify_provenance_through(&self.connection, &request.task_id, None)?;
        if !exact {
            return Ok(failed());
        }
        publication_replay_hash_step()?;
        match hash_internal_file(&self.artifact_store_dir, &row.23) {
            Ok((actual_size, actual_hash)) if actual_size == size && actual_hash == row.1 => {
                Ok(result)
            }
            Err(TaskManagerError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                self.mark_content_hash_failed(&row.1, "MISSING")?;
                Ok(failed())
            }
            Err(error) => Err(error),
            Ok(_) => {
                self.mark_integrity_failed(&row.0, &request.task_id, &row.1)?;
                Ok(failed())
            }
        }
    }

    fn artifact_ids_for_hash(&self, content_hash: &str) -> Result<Vec<String>> {
        let mut statement = self.connection.prepare(
            "SELECT artifact_id FROM artifacts WHERE content_hash=?1 ORDER BY artifact_id",
        )?;
        let rows = statement.query_map([content_hash], |row| row.get::<_, String>(0))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    fn mark_content_hash_failed(&mut self, content_hash: &str, state: &str) -> Result<()> {
        let artifact_ids = self.artifact_ids_for_hash(content_hash)?;
        self.mark_blob_failed(content_hash, state, &artifact_ids, &self.clock.now())
    }

    fn mark_blob_failed(
        &mut self,
        content_hash: &str,
        state: &str,
        artifact_ids: &[String],
        detected_at: &str,
    ) -> Result<()> {
        let lease_owner = self.lease_owner.clone();
        let lease_epoch = self.lease_epoch;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_manager_lease(&transaction, &lease_owner, lease_epoch)?;
        transaction.execute(
            "UPDATE artifact_blobs SET durability_state=?2,verified_at=?3 WHERE content_hash=?1",
            params![content_hash, state, detected_at],
        )?;
        transaction.execute("UPDATE artifacts SET integrity_state='failed',integrity_verified_at=?2,integrity_verifier='artifact-store:startup' WHERE content_hash=?1",params![content_hash,detected_at])?;
        for artifact_id in artifact_ids {
            let tasks = {
                let mut statement = transaction.prepare(
                    "SELECT task_id FROM task_artifacts WHERE artifact_id=?1 ORDER BY task_id",
                )?;
                let rows = statement.query_map([artifact_id], |row| row.get::<_, String>(0))?;
                rows.collect::<std::result::Result<Vec<_>, _>>()?
            };
            for task_id in tasks {
                let event_identity = format!("{task_id}:{artifact_id}");
                let event = json!({"schema_version":SCHEMA_VERSION,"event_id":event_id("artifact-integrity-failed",&event_identity),"task_id":task_id,"event_type":"artifact.integrity-failed","timestamp":detected_at,"actor":{"kind":"system-service","id":"service:artifact-store"},"input_artifacts":[artifact_id],"output_artifacts":[],"status":"failure","details":{"content_hash":content_hash,"durability_state":state}});
                if !transaction.query_row(
                    "SELECT EXISTS(SELECT 1 FROM provenance_events WHERE event_id=?1)",
                    [event["event_id"].as_str().unwrap_or_default()],
                    |row| row.get::<_, bool>(0),
                )? {
                    append_event(&transaction, &task_id, &event)?;
                }
            }
        }
        transaction.commit()?;
        Ok(())
    }

    fn mark_integrity_failed(
        &mut self,
        artifact_id: &str,
        task_id: &str,
        content_hash: &str,
    ) -> Result<()> {
        let authorized = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM task_artifacts WHERE task_id=?1 AND artifact_id=?2)",
            params![task_id, artifact_id],
            |row| row.get::<_, bool>(0),
        )?;
        if !authorized {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        self.mark_content_hash_failed(content_hash, "CORRUPT")
    }
}

#[derive(Debug, PartialEq, Eq)]
struct AllocationRow {
    task_id: String,
    semantic_program_hash: String,
    node_id: String,
    binding_id: Option<String>,
    attempt_id: Option<String>,
    expected_semantic_type: Option<String>,
    allowed_media_types: Vec<String>,
    max_size_bytes: Option<u64>,
    sensitivity: String,
    retention: String,
    state: String,
    writer_grant_admission: Option<GrantAdmission>,
    writer_session_id: Option<String>,
    writer_generation: i64,
    staging_ref: Option<String>,
    expires_at: String,
}

fn load_allocation_row(
    connection: &Connection,
    allocation_id: &str,
) -> Result<Option<AllocationRow>> {
    let row=connection.query_row("SELECT task_id,semantic_program_hash,node_id,binding_id,attempt_id,expected_semantic_type,allowed_media_types_json,max_size_bytes,sensitivity,retention,state,writer_grant_id,writer_grant_one_shot_consumed,writer_session_id,writer_generation,staging_ref,expires_at FROM artifact_output_allocations WHERE allocation_id=?1",[allocation_id],|row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,Option<String>>(3)?,row.get::<_,Option<String>>(4)?,row.get::<_,Option<String>>(5)?,row.get::<_,Option<String>>(6)?,row.get::<_,Option<i64>>(7)?,row.get::<_,String>(8)?,row.get::<_,String>(9)?,row.get::<_,String>(10)?,row.get::<_,Option<String>>(11)?,row.get::<_,Option<bool>>(12)?,row.get::<_,Option<String>>(13)?,row.get::<_,i64>(14)?,row.get::<_,Option<String>>(15)?,row.get::<_,String>(16)?))).optional()?;
    row.map(|row| {
        if row.14 < 0 {
            return Err(TaskManagerError::InvalidRecord(
                "invalid Artifact writer generation",
            ));
        }
        Ok(AllocationRow {
            task_id: row.0,
            semantic_program_hash: row.1,
            node_id: row.2,
            binding_id: row.3,
            attempt_id: row.4,
            expected_semantic_type: row.5,
            allowed_media_types: row
                .6
                .map(|value| serde_json::from_str(&value))
                .transpose()?
                .unwrap_or_default(),
            max_size_bytes: row
                .7
                .map(|value| {
                    u64::try_from(value).map_err(|_| {
                        TaskManagerError::InvalidRecord("negative Artifact size limit")
                    })
                })
                .transpose()?,
            sensitivity: row.8,
            retention: row.9,
            state: row.10,
            writer_grant_admission: match (row.11, row.12) {
                (Some(grant_id), Some(one_shot_consumed)) => Some(GrantAdmission {
                    grant_id,
                    one_shot_consumed,
                }),
                (None, None) => None,
                _ => {
                    return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
                }
            },
            writer_session_id: row.13,
            writer_generation: row.14,
            staging_ref: row.15,
            expires_at: row.16,
        })
    })
    .transpose()
}

fn validate_requested_execution_scope(
    connection: &Connection,
    request: &OutputAllocationRequest,
    now: &str,
) -> Result<()> {
    let task = current_task_scope(connection, &request.task_id)?;
    if !task_accepts_artifact_import(&task.2) {
        return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
    }
    match (request.binding_id.as_deref(), request.attempt_id.as_deref()) {
        (None, None) => validate_current_program_node(
            connection,
            &request.task_id,
            task.3,
            &request.semantic_program_hash,
            &request.node_id,
        ),
        (Some(binding_id), Some(attempt_id)) => {
            let execution =
                capture_execution_authority(connection, &request.task_id, binding_id, now)?;
            if execution.attempt_id != attempt_id
                || execution.semantic_program_hash != request.semantic_program_hash
                || execution.node_id != request.node_id
            {
                return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
            }
            if exact_operation_grant(
                connection,
                &request.task_id,
                &execution,
                "artifact.write",
                "output-allocation",
                &request.allocation_id,
                now,
                None,
            )?
            .is_none()
            {
                return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
            }
            Ok(())
        }
        _ => Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED")),
    }
}

fn validate_allocation_execution_scope(
    connection: &Connection,
    allocation_id: &str,
    allocation: &AllocationRow,
    now: &str,
) -> Result<()> {
    let request = OutputAllocationRequest {
        schema_version: SCHEMA_VERSION.to_owned(),
        allocation_id: allocation_id.to_owned(),
        task_id: allocation.task_id.clone(),
        semantic_program_hash: allocation.semantic_program_hash.clone(),
        node_id: allocation.node_id.clone(),
        binding_id: allocation.binding_id.clone(),
        attempt_id: allocation.attempt_id.clone(),
        output_port: None,
        expected_semantic_type: None,
        allowed_media_types: Vec::new(),
        max_size_bytes: None,
        sensitivity: Sensitivity::Local,
        retention: RetentionClass::Task,
        expires_at: allocation.expires_at.clone(),
    };
    validate_requested_execution_scope(connection, &request, now)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the writer fence binds manager lease, grant admission, and durable writer generation as one authority tuple"
)]
fn validate_writer_fence(
    connection: &Connection,
    allocation_id: &str,
    now: &str,
    lease_owner: &str,
    lease_epoch: i64,
    grant_admission: Option<&GrantAdmission>,
    writer_session_id: &str,
    writer_generation: i64,
) -> Result<()> {
    let allocation = validate_writer_authority(
        connection,
        allocation_id,
        now,
        lease_owner,
        lease_epoch,
        grant_admission,
    )?;
    if allocation.writer_session_id.as_deref() != Some(writer_session_id)
        || allocation.writer_generation != writer_generation
    {
        return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
    }
    Ok(())
}

fn validate_writer_authority(
    connection: &Connection,
    allocation_id: &str,
    now: &str,
    lease_owner: &str,
    lease_epoch: i64,
    grant_admission: Option<&GrantAdmission>,
) -> Result<AllocationRow> {
    let owns_fence = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM task_manager_lease WHERE singleton_id=1 AND owner_id=?1 AND fence_epoch=?2)",
        params![lease_owner, lease_epoch],
        |row| row.get::<_, bool>(0),
    )?;
    if !owns_fence {
        return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
    }
    let allocation = load_allocation_row(connection, allocation_id)?.ok_or(
        TaskManagerError::InvalidRecord("ARTIFACT_ALLOCATION_NOT_FOUND"),
    )?;
    ensure_task_is_not_recovering(connection, &allocation.task_id)?;
    ensure_no_unknown_artifact_export(connection, &allocation.task_id)?;
    if allocation.state != "WRITING" || parse_time(&allocation.expires_at)? <= parse_time(now)? {
        return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
    }
    if let Some(binding_id) = allocation.binding_id.as_deref() {
        let admission =
            grant_admission.ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?;
        if allocation.writer_grant_admission.as_ref() != Some(admission) {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        let execution = load_execution_authority(connection, &allocation.task_id, binding_id, now)?;
        let valid = exact_operation_grant(
            connection,
            &allocation.task_id,
            &execution,
            "artifact.write",
            "output-allocation",
            allocation_id,
            now,
            Some(admission),
        )?
        .is_some();
        if !valid {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        Ok(allocation)
    } else {
        if allocation.writer_grant_admission.is_some() || grant_admission.is_some() {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        validate_allocation_execution_scope(connection, allocation_id, &allocation, now)?;
        Ok(allocation)
    }
}

fn current_task_scope(
    connection: &Connection,
    task_id: &str,
) -> Result<(String, String, String, Option<i64>, String)> {
    connection
        .query_row(
            "SELECT principal_kind,principal_id,state,active_program_revision,active_step_ids_json FROM tasks WHERE task_id=?1",
            [task_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?
        .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
}

fn validate_current_program_node(
    connection: &Connection,
    task_id: &str,
    active_revision: Option<i64>,
    semantic_hash: &str,
    node_id: &str,
) -> Result<()> {
    let Some(active_revision) = active_revision else {
        // Pre-binding allocations are permitted before a Task has an active program.
        return Ok(());
    };
    let program_json = connection
        .query_row(
            "SELECT program_json FROM semantic_program_revisions WHERE task_id=?1 AND program_revision=?2 AND semantic_hash=?3 AND status='active' AND superseded_at IS NULL",
            params![task_id, active_revision, semantic_hash],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?;
    let program: serde_json::Value = serde_json::from_str(&program_json)?;
    if !program
        .get("nodes")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|nodes| {
            nodes
                .iter()
                .any(|node| node.get("id").and_then(serde_json::Value::as_str) == Some(node_id))
        })
    {
        return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
    }
    Ok(())
}

fn capture_read_authority(
    connection: &Connection,
    task_id: &str,
    binding_id: Option<&str>,
    now: &str,
) -> Result<ReadAuthority> {
    let task = current_task_scope(connection, task_id)?;
    let execution = binding_id
        .map(|binding_id| capture_execution_authority(connection, task_id, binding_id, now))
        .transpose()?;
    Ok(ReadAuthority {
        task_principal_kind: task.0,
        task_principal_id: task.1,
        execution,
    })
}

fn capture_execution_authority(
    connection: &Connection,
    task_id: &str,
    binding_id: &str,
    now: &str,
) -> Result<ExecutionAuthority> {
    let execution = load_execution_authority(connection, task_id, binding_id, now)?;
    if !binding_runtime_authority_valid(connection, task_id, &execution, now)? {
        return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
    }
    Ok(execution)
}

fn capture_provider_session_authority(
    connection: &Connection,
    task_id: &str,
    binding_id: &str,
) -> Result<ExecutionAuthority> {
    connection
        .query_row(
            "SELECT b.attempt_id,b.semantic_program_hash,b.node_id,b.capability,b.provider_id,
                    b.policy_decision_refs_json,b.grant_refs_json
             FROM execution_bindings b
             JOIN step_executions s ON s.binding_id=b.binding_id AND s.attempt_id=b.attempt_id
                AND s.task_id=b.task_id AND s.semantic_program_hash=b.semantic_program_hash
                AND s.node_id=b.node_id
             WHERE b.task_id=?1 AND b.binding_id=?2",
            params![task_id, binding_id],
            |row| {
                Ok(ExecutionAuthority {
                    attempt_id: row.get(0)?,
                    semantic_program_hash: row.get(1)?,
                    node_id: row.get(2)?,
                    binding_id: binding_id.to_owned(),
                    capability: row.get(3)?,
                    principal_id: row.get(4)?,
                    policy_decision_refs_json: row.get(5)?,
                    grant_refs_json: row.get(6)?,
                })
            },
        )
        .optional()?
        .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
}

fn load_execution_authority(
    connection: &Connection,
    task_id: &str,
    binding_id: &str,
    _now: &str,
) -> Result<ExecutionAuthority> {
    let task = current_task_scope(connection, task_id)?;
    if !matches!(
        task.2.as_str(),
        "RUNNABLE" | "RUNNING" | "VERIFYING" | "RECOVERING"
    ) {
        return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
    }
    let active_steps: Vec<String> = serde_json::from_str(&task.4)?;
    let execution = connection
        .query_row(
            "SELECT s.attempt_id,s.semantic_program_hash,s.node_id,b.capability,b.provider_id,b.policy_decision_refs_json,b.grant_refs_json
             FROM step_executions s
             JOIN execution_bindings b ON b.binding_id=s.binding_id AND b.attempt_id=s.attempt_id
                AND b.task_id=s.task_id AND b.semantic_program_hash=s.semantic_program_hash
                AND b.registry_snapshot_id=s.registry_snapshot_id AND b.node_id=s.node_id
             JOIN semantic_program_revisions p ON p.task_id=s.task_id
                AND p.program_revision=?3 AND p.semantic_hash=s.semantic_program_hash
                AND p.registry_snapshot_id=s.registry_snapshot_id AND p.status='active'
                AND p.superseded_at IS NULL
             WHERE s.task_id=?1 AND s.binding_id=?2
                AND s.state IN ('READY','STARTING','RUNNING')
                AND s.attempt_number=(SELECT MAX(latest.attempt_number) FROM step_executions latest
                    WHERE latest.task_id=s.task_id AND latest.semantic_program_hash=s.semantic_program_hash
                    AND latest.registry_snapshot_id=s.registry_snapshot_id AND latest.node_id=s.node_id)",
            params![task_id, binding_id, task.3],
            |row| {
                Ok(ExecutionAuthority {
                    attempt_id: row.get(0)?,
                    semantic_program_hash: row.get(1)?,
                    node_id: row.get(2)?,
                    binding_id: binding_id.to_owned(),
                    capability: row.get(3)?,
                    principal_id: row.get(4)?,
                    policy_decision_refs_json: row.get(5)?,
                    grant_refs_json: row.get(6)?,
                })
            },
        )
        .optional()?
        .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?;
    if !active_steps.iter().any(|step| step == &execution.node_id) {
        return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
    }
    Ok(execution)
}

#[allow(
    clippy::too_many_lines,
    reason = "keeps the durable grant, decision, request, approval, and principal intersection auditable"
)]
fn binding_runtime_authority_valid(
    connection: &Connection,
    task_id: &str,
    execution: &ExecutionAuthority,
    now: &str,
) -> Result<bool> {
    let grant_ids: Vec<String> = serde_json::from_str(&execution.grant_refs_json)?;
    let policy_ids: Vec<String> = serde_json::from_str(&execution.policy_decision_refs_json)?;
    if grant_ids.len() > 64
        || grant_ids.len() != policy_ids.len()
        || !all_unique(&grant_ids)
        || !all_unique(&policy_ids)
    {
        return Ok(false);
    }
    let request_count = connection.query_row(
        "SELECT COUNT(*) FROM authority_requests WHERE task_id=?1 AND semantic_program_hash=?2 AND node_id=?3 AND execution_binding_id=?4 AND attempt_id=?5 AND principal_kind='provider' AND principal_id=?6",
        params![task_id, execution.semantic_program_hash, execution.node_id, execution.binding_id, execution.attempt_id, execution.principal_id],
        |row| row.get::<_, i64>(0),
    )?;
    if usize::try_from(request_count).ok() != Some(grant_ids.len()) {
        return Ok(false);
    }
    let checked_at = parse_time(now)?;
    let mut covered_requests = BTreeSet::new();
    let mut covered_decisions = BTreeSet::new();
    for grant_id in grant_ids {
        let grant = connection
            .query_row(
                "SELECT g.expires_at,g.approval_id,a.status,a.expires_at,
                        d.decision,d.principal_kind,d.principal_id,
                        r.principal_kind,r.principal_id,g.capability,g.grants_json,g.scope,
                        g.delegable,g.max_delegation_depth,d.decision_id,d.action,
                        d.resolved_resource_kind,d.resolved_resource_id,d.approval_request_id,
                        r.request_id,r.capability,r.action,r.resolved_resource_kind,
                        r.resolved_resource_id,r.semantic_selector,g.state,g.max_uses,g.uses_consumed
                 FROM authority_grants g
                 JOIN policy_decisions d ON d.decision_id=g.policy_decision_id
                    AND d.task_id=g.task_id AND d.semantic_program_hash=g.semantic_program_hash
                    AND d.node_id=g.node_id AND d.policy_snapshot_id=g.policy_snapshot_id
                 JOIN authority_requests r ON r.request_id=d.authority_request_id
                    AND r.task_id=g.task_id AND r.semantic_program_hash=g.semantic_program_hash
                    AND r.node_id=g.node_id AND r.execution_binding_id=g.execution_binding_id
                    AND r.attempt_id=g.attempt_id
                 LEFT JOIN approval_requests a ON a.approval_id=g.approval_id
                    AND a.authority_request_id=r.request_id AND a.task_id=g.task_id
                  WHERE g.grant_id=?1 AND g.task_id=?2 AND g.semantic_program_hash=?3
                     AND g.node_id=?4 AND g.execution_binding_id=?5 AND g.attempt_id=?6
                     AND g.principal_kind='provider' AND g.principal_id=?7",
                params![
                    grant_id,
                    task_id,
                    execution.semantic_program_hash,
                    execution.node_id,
                    execution.binding_id,
                    execution.attempt_id,
                    execution.principal_id
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, String>(10)?,
                        row.get::<_, String>(11)?,
                        row.get::<_, bool>(12)?,
                        row.get::<_, i64>(13)?,
                        row.get::<_, String>(14)?,
                        row.get::<_, String>(15)?,
                        row.get::<_, String>(16)?,
                        row.get::<_, String>(17)?,
                        row.get::<_, Option<String>>(18)?,
                        row.get::<_, String>(19)?,
                        row.get::<_, String>(20)?,
                        row.get::<_, String>(21)?,
                        row.get::<_, String>(22)?,
                        row.get::<_, String>(23)?,
                        row.get::<_, Option<String>>(24)?,
                        row.get::<_, String>(25)?,
                        row.get::<_, Option<i64>>(26)?,
                        row.get::<_, i64>(27)?,
                    ))
                },
            )
            .optional()?;
        let Some(grant) = grant else {
            return Ok(false);
        };
        let consumed_one_shot = consumed_one_shot_grant(&grant.11, &grant.25, grant.26, grant.27);
        let exhausted_finite = exhausted_finite_grant(&grant.11, &grant.25, grant.26, grant.27);
        let structurally_exhausted = consumed_one_shot || exhausted_finite;
        let binding_lifecycle_valid =
            (grant_available_for_admission(&grant.11, &grant.25, grant.26, grant.27)
                && parse_time(&grant.0)? > checked_at)
                || structurally_exhausted;
        if !binding_lifecycle_valid
            || grant.4 != "ALLOW"
            || grant.5 != "provider"
            || grant.6 != execution.principal_id
            || grant.7 != "provider"
            || grant.8 != execution.principal_id
            || grant.9 != execution.capability
            || grant.12
            || grant.13 != 0
            || !policy_ids.contains(&grant.14)
            || grant.15 != grant.21
            || grant.16 != grant.22
            || grant.17 != grant.23
            || grant.1 != grant.18
            || grant.20 != execution.capability
            || !covered_decisions.insert(grant.14.clone())
            || !covered_requests.insert(grant.19.clone())
        {
            return Ok(false);
        }
        let items: serde_json::Value = serde_json::from_str(&grant.10)?;
        let Some([item]) = items.as_array().map(Vec::as_slice) else {
            return Ok(false);
        };
        if item.get("action").and_then(serde_json::Value::as_str) != Some(grant.21.as_str())
            || item
                .get("resource_kind")
                .and_then(serde_json::Value::as_str)
                != Some(grant.22.as_str())
            || item.get("resource_id").and_then(serde_json::Value::as_str)
                != Some(grant.23.as_str())
            || item
                .get("semantic_selector")
                .and_then(serde_json::Value::as_str)
                != grant.24.as_deref()
        {
            return Ok(false);
        }
        match (grant.1.as_deref(), grant.2.as_deref()) {
            (None, None) => {}
            (Some(_), Some(status))
                if status == "APPROVED" || structurally_exhausted && status == "EXPIRED" =>
            {
                if !structurally_exhausted
                    && grant.3.as_deref().is_some_and(|expires| {
                        parse_time(expires).map_or(true, |expires| expires <= checked_at)
                    })
                {
                    return Ok(false);
                }
                let approved_until = {
                    let mut statement = connection.prepare(
                        "SELECT approved_until FROM approval_decisions WHERE approval_id=?1 AND task_id=?2 AND decision='APPROVE' AND scope=?3",
                    )?;
                    let rows = statement.query_map(params![grant.1, task_id, grant.11], |row| {
                        row.get::<_, Option<String>>(0)
                    })?;
                    rows.collect::<std::result::Result<Vec<_>, _>>()?
                };
                if approved_until.len() != 1
                    || !structurally_exhausted
                        && approved_until[0].as_deref().is_some_and(|approved_until| {
                            parse_time(approved_until).map_or(true, |expires| expires <= checked_at)
                        })
                {
                    return Ok(false);
                }
            }
            _ => return Ok(false),
        }
    }
    Ok(
        covered_requests.len() == usize::try_from(request_count).unwrap_or(usize::MAX)
            && covered_decisions.len() == policy_ids.len(),
    )
}

#[derive(Debug)]
struct ExactOperationGrant {
    grant_id: String,
    scope: String,
    max_uses: Option<i64>,
}

#[derive(Debug)]
struct OperationGrantRow {
    expires_at: String,
    approval_id: Option<String>,
    approval_status: Option<String>,
    approval_expires_at: Option<String>,
    decision: String,
    decision_principal_kind: String,
    decision_principal_id: String,
    request_principal_kind: String,
    request_principal_id: String,
    capability: String,
    grants_json: String,
    scope: String,
    delegable: bool,
    max_delegation_depth: i64,
    decision_id: String,
    decision_action: String,
    decision_resource_kind: String,
    decision_resource_id: String,
    decision_approval_id: Option<String>,
    _request_id: String,
    request_capability: String,
    request_action: String,
    request_resource_kind: String,
    request_resource_id: String,
    semantic_selector: Option<String>,
    state: String,
    max_uses: Option<i64>,
    uses_consumed: i64,
}

fn consumed_one_shot_grant(
    scope: &str,
    state: &str,
    max_uses: Option<i64>,
    uses_consumed: i64,
) -> bool {
    scope == "ONE_SHOT" && state == "CONSUMED" && max_uses == Some(1) && uses_consumed == 1
}

fn exhausted_finite_grant(
    scope: &str,
    state: &str,
    max_uses: Option<i64>,
    uses_consumed: i64,
) -> bool {
    matches!(scope, "TASK" | "TIME_LIMITED")
        && state == "ACTIVE"
        && max_uses.is_some_and(|maximum| maximum > 0 && uses_consumed == maximum)
}

fn grant_available_for_admission(
    scope: &str,
    state: &str,
    max_uses: Option<i64>,
    uses_consumed: i64,
) -> bool {
    if state != "ACTIVE" {
        return false;
    }
    match scope {
        "ONE_SHOT" => max_uses == Some(1) && uses_consumed == 0,
        "TASK" | "TIME_LIMITED" => match max_uses {
            Some(maximum) => maximum > 0 && uses_consumed >= 0 && uses_consumed < maximum,
            None => uses_consumed == 0,
        },
        _ => false,
    }
}

fn issued_grant_lifecycle_valid(
    scope: &str,
    state: &str,
    max_uses: Option<i64>,
    uses_consumed: i64,
) -> bool {
    consumed_one_shot_grant(scope, state, max_uses, uses_consumed)
        || matches!(scope, "TASK" | "TIME_LIMITED")
            && state == "ACTIVE"
            && match max_uses {
                Some(maximum) => maximum > 0 && uses_consumed >= 0 && uses_consumed <= maximum,
                None => uses_consumed == 0,
            }
}

#[allow(
    clippy::too_many_lines,
    clippy::too_many_arguments,
    reason = "the exact operation tuple is the security boundary being checked"
)]
fn exact_operation_grant(
    connection: &Connection,
    task_id: &str,
    execution: &ExecutionAuthority,
    action: &str,
    resource_kind: &str,
    resource_id: &str,
    now: &str,
    admitted: Option<&GrantAdmission>,
) -> Result<Option<ExactOperationGrant>> {
    let checked_at = parse_time(now)?;
    let grant_ids: Vec<String> = serde_json::from_str(&execution.grant_refs_json)?;
    let policy_ids: Vec<String> = serde_json::from_str(&execution.policy_decision_refs_json)?;
    let mut matching = Vec::new();
    for grant_id in grant_ids {
        if admitted.is_some_and(|admission| admission.grant_id != grant_id) {
            continue;
        }
        let row = connection
            .query_row(
                "SELECT g.expires_at,g.approval_id,a.status,a.expires_at,
                        d.decision,d.principal_kind,d.principal_id,
                        r.principal_kind,r.principal_id,g.capability,g.grants_json,g.scope,
                        g.delegable,g.max_delegation_depth,d.decision_id,d.action,
                        d.resolved_resource_kind,d.resolved_resource_id,d.approval_request_id,
                        r.request_id,r.capability,r.action,r.resolved_resource_kind,
                        r.resolved_resource_id,r.semantic_selector,g.state,g.max_uses,g.uses_consumed
                 FROM authority_grants g
                 JOIN policy_decisions d ON d.decision_id=g.policy_decision_id
                    AND d.task_id=g.task_id AND d.semantic_program_hash=g.semantic_program_hash
                    AND d.node_id=g.node_id AND d.policy_snapshot_id=g.policy_snapshot_id
                 JOIN authority_requests r ON r.request_id=d.authority_request_id
                    AND r.task_id=g.task_id AND r.semantic_program_hash=g.semantic_program_hash
                    AND r.node_id=g.node_id AND r.execution_binding_id=g.execution_binding_id
                    AND r.attempt_id=g.attempt_id
                 LEFT JOIN approval_requests a ON a.approval_id=g.approval_id
                    AND a.authority_request_id=r.request_id AND a.task_id=g.task_id
                    AND a.semantic_program_hash=g.semantic_program_hash AND a.node_id=g.node_id
                    AND a.action=r.action
                 WHERE g.grant_id=?1 AND g.task_id=?2 AND g.semantic_program_hash=?3
                    AND g.node_id=?4 AND g.execution_binding_id=?5 AND g.attempt_id=?6
                    AND g.principal_kind='provider' AND g.principal_id=?7",
                params![
                    grant_id,
                    task_id,
                    execution.semantic_program_hash,
                    execution.node_id,
                    execution.binding_id,
                    execution.attempt_id,
                    execution.principal_id
                ],
                |row| {
                    Ok(OperationGrantRow {
                        expires_at: row.get(0)?,
                        approval_id: row.get(1)?,
                        approval_status: row.get(2)?,
                        approval_expires_at: row.get(3)?,
                        decision: row.get(4)?,
                        decision_principal_kind: row.get(5)?,
                        decision_principal_id: row.get(6)?,
                        request_principal_kind: row.get(7)?,
                        request_principal_id: row.get(8)?,
                        capability: row.get(9)?,
                        grants_json: row.get(10)?,
                        scope: row.get(11)?,
                        delegable: row.get(12)?,
                        max_delegation_depth: row.get(13)?,
                        decision_id: row.get(14)?,
                        decision_action: row.get(15)?,
                        decision_resource_kind: row.get(16)?,
                        decision_resource_id: row.get(17)?,
                        decision_approval_id: row.get(18)?,
                        _request_id: row.get(19)?,
                        request_capability: row.get(20)?,
                        request_action: row.get(21)?,
                        request_resource_kind: row.get(22)?,
                        request_resource_id: row.get(23)?,
                        semantic_selector: row.get(24)?,
                        state: row.get(25)?,
                        max_uses: row.get(26)?,
                        uses_consumed: row.get(27)?,
                    })
                },
            )
            .optional()?;
        let Some(row) = row else {
            continue;
        };
        let lifecycle_valid = match admitted {
            Some(admission) if admission.one_shot_consumed => {
                consumed_one_shot_grant(&row.scope, &row.state, row.max_uses, row.uses_consumed)
            }
            Some(_) => issued_grant_lifecycle_valid(
                &row.scope,
                &row.state,
                row.max_uses,
                row.uses_consumed,
            ),
            None => grant_available_for_admission(
                &row.scope,
                &row.state,
                row.max_uses,
                row.uses_consumed,
            ),
        };
        if !lifecycle_valid
            || parse_time(&row.expires_at)? <= checked_at
            || row.decision != "ALLOW"
            || row.decision_principal_kind != "provider"
            || row.decision_principal_id != execution.principal_id
            || row.request_principal_kind != "provider"
            || row.request_principal_id != execution.principal_id
            || row.capability != execution.capability
            || row.request_capability != execution.capability
            || row.delegable
            || row.max_delegation_depth != 0
            || !policy_ids.contains(&row.decision_id)
            || row.decision_action != action
            || row.request_action != action
            || row.decision_resource_kind != resource_kind
            || row.request_resource_kind != resource_kind
            || row.decision_resource_id != resource_id
            || row.request_resource_id != resource_id
        {
            continue;
        }
        let items: serde_json::Value = serde_json::from_str(&row.grants_json)?;
        let Some([item]) = items.as_array().map(Vec::as_slice) else {
            continue;
        };
        if item.get("action").and_then(serde_json::Value::as_str) != Some(action)
            || item
                .get("resource_kind")
                .and_then(serde_json::Value::as_str)
                != Some(resource_kind)
            || item.get("resource_id").and_then(serde_json::Value::as_str) != Some(resource_id)
            || item
                .get("semantic_selector")
                .and_then(serde_json::Value::as_str)
                != row.semantic_selector.as_deref()
            || !operation_approval_current(connection, task_id, &row, &checked_at)?
        {
            continue;
        }
        matching.push(ExactOperationGrant {
            grant_id,
            scope: row.scope,
            max_uses: row.max_uses,
        });
    }
    if matching.len() == 1 {
        Ok(matching.pop())
    } else {
        Ok(None)
    }
}

fn operation_approval_current(
    connection: &Connection,
    task_id: &str,
    grant: &OperationGrantRow,
    checked_at: &OffsetDateTime,
) -> Result<bool> {
    match (
        grant.approval_id.as_deref(),
        grant.decision_approval_id.as_deref(),
        grant.approval_status.as_deref(),
    ) {
        (None, None, None) => Ok(true),
        (Some(approval_id), Some(decision_approval_id), Some("APPROVED"))
            if approval_id == decision_approval_id =>
        {
            if grant.approval_expires_at.as_deref().is_some_and(|expires| {
                parse_time(expires).map_or(true, |expires| expires <= *checked_at)
            }) {
                return Ok(false);
            }
            let decisions = {
                let mut statement = connection.prepare(
                    "SELECT scope,approved_until FROM approval_decisions WHERE approval_id=?1 AND task_id=?2 AND decision='APPROVE'",
                )?;
                let rows = statement.query_map(params![approval_id, task_id], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
                })?;
                rows.collect::<std::result::Result<Vec<_>, _>>()?
            };
            let Some((scope, approved_until)) = decisions.as_slice().first() else {
                return Ok(false);
            };
            if decisions.len() != 1 || scope != &grant.scope {
                return Ok(false);
            }
            if grant.scope == "TIME_LIMITED" && approved_until.is_none() {
                return Ok(false);
            }
            if let Some(approved_until) = approved_until {
                let approved_until = parse_time(approved_until)?;
                if approved_until <= *checked_at || parse_time(&grant.expires_at)? > approved_until
                {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "grant consumption must repeat the exact protected operation tuple atomically"
)]
fn admit_operation_grant(
    connection: &Connection,
    task_id: &str,
    execution: &ExecutionAuthority,
    action: &str,
    resource_kind: &str,
    resource_id: &str,
    now: &str,
    expected_grant_id: &str,
) -> Result<GrantAdmission> {
    let grant = exact_operation_grant(
        connection,
        task_id,
        execution,
        action,
        resource_kind,
        resource_id,
        now,
        None,
    )?
    .filter(|grant| grant.grant_id == expected_grant_id)
    .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?;
    let one_shot_consumed = grant.scope == "ONE_SHOT";
    if grant.max_uses.is_some() {
        let changed = connection.execute(
            "UPDATE authority_grants
             SET uses_consumed=uses_consumed+1,
                 state=CASE WHEN scope='ONE_SHOT' THEN 'CONSUMED' ELSE state END
             WHERE grant_id=?1 AND state='ACTIVE' AND max_uses IS NOT NULL
               AND uses_consumed < max_uses
               AND (scope <> 'ONE_SHOT' OR (max_uses=1 AND uses_consumed=0))",
            [expected_grant_id],
        )?;
        if changed != 1 {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
    }
    Ok(GrantAdmission {
        grant_id: expected_grant_id.to_owned(),
        one_shot_consumed,
    })
}

fn admit_prepared_artifact_reader(
    connection: &Transaction<'_>,
    scope: &ArtifactReadScope,
    artifact_id: &str,
    handle: &ArtifactHandle,
    admitted_at: &str,
) -> Result<Option<GrantAdmission>> {
    ensure_task_is_not_recovering(connection, &scope.task_id)?;
    let integrity_current = connection.query_row(
        "SELECT a.integrity_state,b.durability_state
         FROM artifacts a JOIN artifact_blobs b ON b.content_hash=a.content_hash
         WHERE a.artifact_id=?1",
        [artifact_id],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    )?;
    if integrity_current.0 == "failed"
        || matches!(integrity_current.1.as_str(), "CORRUPT" | "MISSING")
    {
        return Err(TaskManagerError::InvalidRecord("ARTIFACT_INTEGRITY_FAILED"));
    }
    let grant_admission = if let Some(execution) = &scope.authority.execution {
        let grant_id = scope
            .grant_ids
            .get(artifact_id)
            .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?;
        let current = load_execution_authority(
            connection,
            &scope.task_id,
            &execution.binding_id,
            admitted_at,
        )?;
        if current != *execution
            || !artifact_read_authorized(connection, &scope.task_id, &scope.authority, artifact_id)?
        {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        if let Some(admission) = replayable_reader_admission_for_grant(
            connection,
            &scope.task_id,
            execution,
            artifact_id,
            grant_id,
            admitted_at,
        )? {
            Some(admission)
        } else {
            let admission = admit_operation_grant(
                connection,
                &scope.task_id,
                execution,
                "artifact.read",
                "artifact",
                artifact_id,
                admitted_at,
                grant_id,
            )?;
            persist_reader_admission(
                connection,
                &scope.task_id,
                execution,
                artifact_id,
                &admission,
                admitted_at,
            )?;
            Some(admission)
        }
    } else {
        if capture_read_authority(connection, &scope.task_id, None, admitted_at)? != scope.authority
            || !artifact_read_authorized(connection, &scope.task_id, &scope.authority, artifact_id)?
        {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        None
    };
    connection.execute(
        "UPDATE artifacts
         SET integrity_state='verified',integrity_verified_at=?2,
             integrity_verifier='artifact-store:sha256'
         WHERE artifact_id=?1",
        params![artifact_id, admitted_at],
    )?;
    connection.execute(
        "UPDATE artifact_blobs SET durability_state='DURABLE',verified_at=?2
         WHERE content_hash=?1",
        params![handle.stored_content_hash()?.tagged(), admitted_at],
    )?;
    Ok(grant_admission)
}

fn persist_reader_admission(
    connection: &Transaction<'_>,
    task_id: &str,
    execution: &ExecutionAuthority,
    artifact_id: &str,
    admission: &GrantAdmission,
    admitted_at: &str,
) -> Result<()> {
    let operation_id = event_id(
        "artifact-reader-admission",
        &format!("{task_id}\0{}", random_token(connection)?),
    );
    let stored = ArtifactReaderAdmission {
        version: 1,
        operation_id: operation_id.clone(),
        task_id: task_id.to_owned(),
        artifact_id: artifact_id.to_owned(),
        semantic_program_hash: execution.semantic_program_hash.clone(),
        node_id: execution.node_id.clone(),
        binding_id: execution.binding_id.clone(),
        attempt_id: execution.attempt_id.clone(),
        principal_id: execution.principal_id.clone(),
        grant_id: admission.grant_id.clone(),
        one_shot_consumed: admission.one_shot_consumed,
    };
    let details = canonical_json(&stored)?;
    let event = reader_admission_event(&stored, "admitted", admitted_at, None);
    let appended = append_event(connection, task_id, &event)?;
    let receipt = canonical_json(&ArtifactReaderAdmissionReceipt {
        version: 1,
        kind: "artifact-reader-admission-pending-delivery".to_owned(),
        operation_id: operation_id.clone(),
        admission_event_id: appended.event_id,
        admission_event_hash: appended.event_hash,
        delivery_event_id: None,
        delivery_event_hash: None,
    })?;
    connection.execute(
        "INSERT INTO operations(
            operation_id,task_id,semantic_program_hash,node_id,binding_id,attempt_id,
            transaction_class,effect_class,idempotency_key,state,outcome_certainty,
            external_receipt,details_json,prepared_at,started_at,finished_at
         ) VALUES (?1,?2,?3,?4,?5,?6,'reversible_local','ARTIFACT_READ',?1,
                   'SUCCEEDED','COMPLETED',?9,?7,?8,?8,?8)",
        params![
            operation_id,
            task_id,
            execution.semantic_program_hash,
            execution.node_id,
            execution.binding_id,
            execution.attempt_id,
            details,
            admitted_at,
            receipt,
        ],
    )?;
    Ok(())
}

fn reader_admission_event(
    admission: &ArtifactReaderAdmission,
    phase: &str,
    timestamp: &str,
    admission_event: Option<(&str, &str)>,
) -> serde_json::Value {
    let (event_kind, event_type, status, predecessor_id, predecessor_hash) = match admission_event {
        Some((event_id, event_hash)) => (
            "artifact-reader-delivered",
            "execution.completed",
            "success",
            Some(event_id),
            Some(event_hash),
        ),
        None => (
            "artifact-reader-admitted",
            "execution.started",
            "pending",
            None,
            None,
        ),
    };
    json!({
        "schema_version":SCHEMA_VERSION,
        "event_id":event_id(event_kind,&admission.operation_id),
        "task_id":admission.task_id,
        "step_id":admission.node_id,
        "event_type":event_type,
        "timestamp":timestamp,
        "actor":{"kind":"provider","id":admission.principal_id},
        "semantic_program_hash":admission.semantic_program_hash,
        "execution_binding_id":admission.binding_id,
        "provider_id":admission.principal_id,
        "authority_token_id":admission.grant_id,
        "input_artifacts":[admission.artifact_id],
        "output_artifacts":[],
        "status":status,
        "details":{
            "operation_id":admission.operation_id,
            "phase":phase,
            "admission_event_id":predecessor_id,
            "admission_event_hash":predecessor_hash,
        },
    })
}

fn authenticate_reader_admission_event(
    connection: &Connection,
    admission: &ArtifactReaderAdmission,
    phase: &str,
    event_id: &str,
    event_hash: &str,
    admission_event: Option<(&str, &str)>,
) -> Result<bool> {
    let expected_type = if admission_event.is_some() {
        "execution.completed"
    } else {
        "execution.started"
    };
    let row = connection
        .query_row(
            "SELECT timestamp,event_hash,event_json FROM provenance_events
             WHERE task_id=?1 AND event_id=?2 AND event_type=?3",
            params![admission.task_id, event_id, expected_type],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((timestamp, stored_hash, event_json)) = row else {
        return Ok(false);
    };
    let expected = reader_admission_event(admission, phase, &timestamp, admission_event);
    Ok(
        event_id == expected["event_id"].as_str().unwrap_or_default()
            && stored_hash == event_hash
            && serde_json::from_str::<serde_json::Value>(&event_json)? == expected
            && super::verify_provenance_through(connection, &admission.task_id, None)?,
    )
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "authenticates the complete durable reader admission tuple"
)]
fn authenticate_reader_admission(
    connection: &Connection,
    operation_id: &str,
    task_id: &str,
    execution: &ExecutionAuthority,
    artifact_id: &str,
    admission: &GrantAdmission,
    checked_at: &str,
    require_pending: bool,
) -> Result<bool> {
    let row = connection
        .query_row(
            "SELECT task_id,semantic_program_hash,node_id,binding_id,attempt_id,
                    transaction_class,effect_class,idempotency_key,state,outcome_certainty,
                    external_receipt,details_json,prepared_at,started_at,finished_at
             FROM operations WHERE operation_id=?1",
            [operation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, Option<String>>(13)?,
                    row.get::<_, Option<String>>(14)?,
                ))
            },
        )
        .optional()?;
    let Some(row) = row else {
        return Ok(false);
    };
    let details_json = row.11.as_deref().ok_or(TaskManagerError::InvalidRecord(
        "stored Artifact reader admission is invalid",
    ))?;
    let stored: ArtifactReaderAdmission = serde_json::from_str(details_json)?;
    let receipt_json = row.10.as_deref().ok_or(TaskManagerError::InvalidRecord(
        "stored Artifact reader admission is invalid",
    ))?;
    let receipt: ArtifactReaderAdmissionReceipt = serde_json::from_str(receipt_json)?;
    let pending = receipt.kind == "artifact-reader-admission-pending-delivery";
    let delivered = receipt.kind == "artifact-reader-admission-delivered";
    let admission_event_exact = authenticate_reader_admission_event(
        connection,
        &stored,
        "admitted",
        &receipt.admission_event_id,
        &receipt.admission_event_hash,
        None,
    )?;
    let delivery_event_id = event_id("artifact-reader-delivered", operation_id);
    let delivery_event_exists = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM provenance_events WHERE task_id=?1 AND event_id=?2)",
        params![task_id, delivery_event_id],
        |row| row.get::<_, bool>(0),
    )?;
    let delivery_event_exact = match (
        receipt.delivery_event_id.as_deref(),
        receipt.delivery_event_hash.as_deref(),
    ) {
        (Some(event_id), Some(event_hash)) => authenticate_reader_admission_event(
            connection,
            &stored,
            "delivered",
            event_id,
            event_hash,
            Some((
                receipt.admission_event_id.as_str(),
                receipt.admission_event_hash.as_str(),
            )),
        )?,
        _ => false,
    };
    let receipt_exact = receipt.version == 1
        && receipt.operation_id == operation_id
        && canonical_json(&receipt)? == receipt_json
        && admission_event_exact
        && (pending && !delivery_event_exists && !delivery_event_exact
            || delivered && delivery_event_exists && delivery_event_exact);
    let exact = stored
        == ArtifactReaderAdmission {
            version: 1,
            operation_id: operation_id.to_owned(),
            task_id: task_id.to_owned(),
            artifact_id: artifact_id.to_owned(),
            semantic_program_hash: execution.semantic_program_hash.clone(),
            node_id: execution.node_id.clone(),
            binding_id: execution.binding_id.clone(),
            attempt_id: execution.attempt_id.clone(),
            principal_id: execution.principal_id.clone(),
            grant_id: admission.grant_id.clone(),
            one_shot_consumed: admission.one_shot_consumed,
        }
        && canonical_json(&stored)? == details_json
        && row.0 == task_id
        && row.1.as_deref() == Some(execution.semantic_program_hash.as_str())
        && row.2.as_deref() == Some(execution.node_id.as_str())
        && row.3.as_deref() == Some(execution.binding_id.as_str())
        && row.4.as_deref() == Some(execution.attempt_id.as_str())
        && row.5.as_deref() == Some("reversible_local")
        && row.6 == "ARTIFACT_READ"
        && row.7.as_deref() == Some(operation_id)
        && row.8 == "SUCCEEDED"
        && row.9.as_deref() == Some("COMPLETED")
        && receipt_exact
        && row.13.as_deref() == Some(row.12.as_str())
        && row.14.as_deref() == Some(row.12.as_str());
    if !exact {
        return Err(TaskManagerError::InvalidRecord(
            "stored Artifact reader admission is invalid",
        ));
    }
    if require_pending && !pending {
        return Ok(false);
    }
    Ok(exact_operation_grant(
        connection,
        task_id,
        execution,
        "artifact.read",
        "artifact",
        artifact_id,
        checked_at,
        Some(admission),
    )?
    .is_some())
}

fn replayable_reader_admission_for_grant(
    connection: &Connection,
    task_id: &str,
    execution: &ExecutionAuthority,
    artifact_id: &str,
    grant_id: &str,
    checked_at: &str,
) -> Result<Option<GrantAdmission>> {
    let candidates = {
        let mut statement = connection.prepare(
            "SELECT operation_id,details_json FROM operations
             WHERE task_id=?1 AND semantic_program_hash=?2 AND node_id=?3
               AND binding_id=?4 AND attempt_id=?5
               AND transaction_class='reversible_local' AND effect_class='ARTIFACT_READ'
               AND state='SUCCEEDED' AND outcome_certainty='COMPLETED'
               AND json_extract(external_receipt,'$.kind')='artifact-reader-admission-pending-delivery'
               AND json_extract(details_json,'$.artifact_id')=?6
               AND json_extract(details_json,'$.grant_id')=?7
             ORDER BY operation_id",
        )?;
        let rows = statement.query_map(
            params![
                task_id,
                execution.semantic_program_hash,
                execution.node_id,
                execution.binding_id,
                execution.attempt_id,
                artifact_id,
                grant_id,
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )?;
        rows.collect::<std::result::Result<Vec<_>, _>>()?
    };
    if candidates.len() > 1 {
        return Err(TaskManagerError::InvalidRecord(
            "stored Artifact reader admission is ambiguous",
        ));
    }
    let Some((operation_id, details)) = candidates.into_iter().next() else {
        return Ok(None);
    };
    let stored: ArtifactReaderAdmission = serde_json::from_str(&details)?;
    if stored.grant_id != grant_id {
        return Err(TaskManagerError::InvalidRecord(
            "stored Artifact reader admission is invalid",
        ));
    }
    let admission = GrantAdmission {
        grant_id: grant_id.to_owned(),
        one_shot_consumed: stored.one_shot_consumed,
    };
    if authenticate_reader_admission(
        connection,
        &operation_id,
        task_id,
        execution,
        artifact_id,
        &admission,
        checked_at,
        true,
    )? {
        Ok(Some(admission))
    } else {
        Ok(None)
    }
}

fn mark_reader_admission_delivered(
    connection: &mut Connection,
    task_id: &str,
    execution: &ExecutionAuthority,
    artifact_id: &str,
    admission: &GrantAdmission,
    delivered_at: &str,
) -> Result<()> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let candidates = {
        let mut statement = transaction.prepare(
            "SELECT operation_id,external_receipt FROM operations
             WHERE task_id=?1 AND semantic_program_hash=?2 AND node_id=?3
               AND binding_id=?4 AND attempt_id=?5
               AND transaction_class='reversible_local' AND effect_class='ARTIFACT_READ'
               AND state='SUCCEEDED' AND outcome_certainty='COMPLETED'
               AND json_extract(external_receipt,'$.kind')='artifact-reader-admission-pending-delivery'
               AND json_extract(details_json,'$.artifact_id')=?6
               AND json_extract(details_json,'$.grant_id')=?7
             ORDER BY operation_id",
        )?;
        let rows = statement.query_map(
            params![
                task_id,
                execution.semantic_program_hash,
                execution.node_id,
                execution.binding_id,
                execution.attempt_id,
                artifact_id,
                admission.grant_id,
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )?;
        rows.collect::<std::result::Result<Vec<_>, _>>()?
    };
    if candidates.len() != 1 {
        return Err(TaskManagerError::InvalidRecord(
            "stored Artifact reader admission is invalid",
        ));
    }
    let (operation_id, pending_receipt) = &candidates[0];
    if !authenticate_reader_admission(
        &transaction,
        operation_id,
        task_id,
        execution,
        artifact_id,
        admission,
        delivered_at,
        true,
    )? {
        return Err(TaskManagerError::InvalidRecord(
            "stored Artifact reader admission is invalid",
        ));
    }
    let stored: ArtifactReaderAdmission = transaction
        .query_row(
            "SELECT details_json FROM operations WHERE operation_id=?1",
            [operation_id],
            |row| row.get::<_, String>(0),
        )
        .and_then(|details| {
            serde_json::from_str(&details).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })
        })?;
    let pending: ArtifactReaderAdmissionReceipt = serde_json::from_str(pending_receipt)?;
    let event = reader_admission_event(
        &stored,
        "delivered",
        delivered_at,
        Some((
            pending.admission_event_id.as_str(),
            pending.admission_event_hash.as_str(),
        )),
    );
    let appended = append_event(&transaction, task_id, &event)?;
    let delivered = canonical_json(&ArtifactReaderAdmissionReceipt {
        version: 1,
        kind: "artifact-reader-admission-delivered".to_owned(),
        operation_id: operation_id.clone(),
        admission_event_id: pending.admission_event_id,
        admission_event_hash: pending.admission_event_hash,
        delivery_event_id: Some(appended.event_id),
        delivery_event_hash: Some(appended.event_hash),
    })?;
    let changed = transaction.execute(
        "UPDATE operations SET external_receipt=?2
         WHERE operation_id=?1 AND external_receipt=?3 AND state='SUCCEEDED'
           AND outcome_certainty='COMPLETED'",
        params![operation_id, delivered, pending_receipt],
    )?;
    if changed != 1 {
        return Err(TaskManagerError::InvalidRecord(
            "stored Artifact reader admission is invalid",
        ));
    }
    transaction.commit()?;
    Ok(())
}

fn replayable_reader_admission(
    connection: &Connection,
    task_id: &str,
    execution: &ExecutionAuthority,
    artifact_id: &str,
    checked_at: &str,
) -> Result<Option<GrantAdmission>> {
    let grant_ids: Vec<String> = serde_json::from_str(&execution.grant_refs_json)?;
    let mut matches = Vec::new();
    for grant_id in grant_ids {
        if let Some(admission) = replayable_reader_admission_for_grant(
            connection,
            task_id,
            execution,
            artifact_id,
            &grant_id,
            checked_at,
        )? {
            matches.push(admission);
        }
    }
    if matches.len() > 1 {
        return Err(TaskManagerError::InvalidRecord(
            "stored Artifact reader admission is ambiguous",
        ));
    }
    Ok(matches.pop())
}

fn validate_reader_fence(reader: &ArtifactReader) -> Result<()> {
    if let Some(identity) = reader.database_identity.as_ref() {
        verify_database_identity(&reader.authority_connection, identity)?;
    }
    let owns_fence = reader.authority_connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM task_manager_lease WHERE singleton_id=1 AND owner_id=?1 AND fence_epoch=?2)",
        params![reader.lease_owner, reader.lease_epoch],
        |row| row.get::<_, bool>(0),
    )?;
    if !owns_fence {
        return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
    }
    ensure_task_is_not_recovering(&reader.authority_connection, &reader.task_id)?;
    ensure_no_unknown_artifact_export(&reader.authority_connection, &reader.task_id)?;
    let intact = reader.authority_connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM artifacts a
             JOIN artifact_blobs b ON b.content_hash=a.content_hash
             WHERE a.artifact_id=?1 AND a.integrity_state='verified'
               AND b.durability_state='DURABLE'
         )",
        [&reader.artifact_id],
        |row| row.get::<_, bool>(0),
    )?;
    if !intact {
        return Err(TaskManagerError::InvalidRecord("ARTIFACT_INTEGRITY_FAILED"));
    }
    let now = reader.clock.now();
    match &reader.authority.execution {
        Some(execution) => {
            let current = load_execution_authority(
                &reader.authority_connection,
                &reader.task_id,
                &execution.binding_id,
                &now,
            )?;
            let admission = reader
                .grant_admission
                .as_ref()
                .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?;
            if current != *execution
                || exact_operation_grant(
                    &reader.authority_connection,
                    &reader.task_id,
                    execution,
                    "artifact.read",
                    "artifact",
                    &reader.artifact_id,
                    &now,
                    Some(admission),
                )?
                .is_none()
            {
                return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
            }
        }
        None => {
            if capture_read_authority(&reader.authority_connection, &reader.task_id, None, &now)?
                != reader.authority
            {
                return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
            }
        }
    }
    if !artifact_read_authorized(
        &reader.authority_connection,
        &reader.task_id,
        &reader.authority,
        &reader.artifact_id,
    )? {
        return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
    }
    Ok(())
}

fn verify_database_identity(connection: &Connection, expected: &StoreIdentity) -> Result<()> {
    let main_filename = connection.query_row(
        "SELECT file FROM pragma_database_list WHERE name='main'",
        [],
        |row| row.get::<_, String>(0),
    )?;
    if main_filename.is_empty() {
        return Err(TaskManagerError::InvalidRecord(
            "SQLite main database has no durable file identity",
        ));
    }
    let path = PathBuf::from(main_filename);
    let file = OpenOptions::new().read(true).write(true).open(&path)?;
    if super::store_identity(&path, &file)? != *expected {
        return Err(TaskManagerError::InvalidRecord(
            "SQLite main database identity does not match the reader fence",
        ));
    }
    Ok(())
}

fn artifact_read_authorized(
    connection: &Connection,
    task_id: &str,
    authority: &ReadAuthority,
    artifact_id: &str,
) -> Result<bool> {
    if let Some(execution) = &authority.execution {
        connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM step_executions s
                 WHERE s.task_id=?1 AND s.binding_id=?2 AND s.attempt_id=?3
                   AND EXISTS(SELECT 1 FROM json_each(s.input_artifacts_json) WHERE value=?4)
                   AND EXISTS(SELECT 1 FROM task_artifacts t WHERE t.task_id=s.task_id AND t.artifact_id=?4))",
                params![task_id, execution.binding_id, execution.attempt_id, artifact_id],
                |row| row.get::<_, bool>(0),
            )
            .map_err(Into::into)
    } else {
        connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM task_artifacts WHERE task_id=?1 AND artifact_id=?2)",
                params![task_id, artifact_id],
                |row| row.get::<_, bool>(0),
            )
            .map_err(Into::into)
    }
}

fn validate_publication_allocation(
    request: &ArtifactPublicationRequest,
    allocation: &AllocationRow,
    now: &str,
) -> Result<()> {
    if allocation.task_id != request.task_id {
        return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
    }
    if allocation.state != request.expected_allocation_state.as_str()
        && allocation.state != "FINALIZING"
    {
        return Err(TaskManagerError::InvalidRecord(
            "ARTIFACT_ALLOCATION_STATE_CONFLICT",
        ));
    }
    if parse_time(&allocation.expires_at)? <= parse_time(now)? {
        return Err(TaskManagerError::InvalidRecord(
            "ARTIFACT_ALLOCATION_EXPIRED",
        ));
    }
    if !allocation.allowed_media_types.is_empty()
        && !allocation.allowed_media_types.contains(&request.media_type)
    {
        return Err(TaskManagerError::InvalidRecord(
            "ARTIFACT_MEDIA_TYPE_MISMATCH",
        ));
    }
    if allocation.expected_semantic_type != request.semantic_type {
        return Err(TaskManagerError::InvalidRecord(
            "ARTIFACT_SEMANTIC_TYPE_MISMATCH",
        ));
    }
    Ok(())
}

fn task_accepts_artifact_import(state: &str) -> bool {
    !matches!(
        state,
        "COMPLETED" | "FAILED" | "CANCELLED" | "ROLLED_BACK" | "ROLLING_BACK"
    )
}

fn validate_publication_execution_scope(
    transaction: &Connection,
    request: &ArtifactPublicationRequest,
    allocation: &AllocationRow,
) -> Result<()> {
    let task = transaction
        .query_row(
            "SELECT state,active_program_revision,active_step_ids_json FROM tasks WHERE task_id=?1",
            [&request.task_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?;
    if !task_accepts_artifact_import(&task.0) {
        return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
    }
    match (
        allocation.binding_id.as_deref(),
        allocation.attempt_id.as_deref(),
    ) {
        (None, None) => {
            if let Some(program_revision) = task.1 {
                let current = transaction.query_row(
                    "SELECT EXISTS(SELECT 1 FROM semantic_program_revisions WHERE task_id=?1 AND program_revision=?2 AND semantic_hash=?3 AND status='active' AND superseded_at IS NULL)",
                    params![request.task_id,program_revision,allocation.semantic_program_hash],
                    |row| row.get::<_,bool>(0),
                )?;
                if !current {
                    return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
                }
            }
        }
        (Some(binding_id), Some(attempt_id)) => {
            if !matches!(task.0.as_str(), "RUNNING" | "VERIFYING" | "RECOVERING") {
                return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
            }
            let active_steps: Vec<String> = serde_json::from_str(&task.2)?;
            if !active_steps.iter().any(|step| step == &allocation.node_id) {
                return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
            }
            let Some(program_revision) = task.1 else {
                return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
            };
            let exact = transaction.query_row(
                "SELECT COUNT(*) FROM step_executions s JOIN execution_bindings b ON b.binding_id=s.binding_id AND b.attempt_id=s.attempt_id AND b.task_id=s.task_id AND b.semantic_program_hash=s.semantic_program_hash AND b.registry_snapshot_id=s.registry_snapshot_id AND b.node_id=s.node_id JOIN semantic_program_revisions p ON p.task_id=s.task_id AND p.program_revision=?6 AND p.semantic_hash=s.semantic_program_hash AND p.registry_snapshot_id=s.registry_snapshot_id AND p.status='active' AND p.superseded_at IS NULL WHERE s.task_id=?1 AND s.semantic_program_hash=?2 AND s.node_id=?3 AND s.attempt_id=?4 AND s.binding_id=?5 AND s.state IN ('READY','STARTING','RUNNING','SUCCEEDED') AND s.attempt_number=(SELECT MAX(latest.attempt_number) FROM step_executions latest WHERE latest.task_id=s.task_id AND latest.semantic_program_hash=s.semantic_program_hash AND latest.registry_snapshot_id=s.registry_snapshot_id AND latest.node_id=s.node_id)",
                params![request.task_id,allocation.semantic_program_hash,allocation.node_id,attempt_id,binding_id,program_revision],
                |row| row.get::<_,i64>(0),
            )?;
            if exact != 1 {
                return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
            }
        }
        _ => return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED")),
    }
    Ok(())
}

fn validate_publication_authority(
    connection: &Connection,
    request: &ArtifactPublicationRequest,
    allocation: &AllocationRow,
    now: &str,
) -> Result<()> {
    validate_publication_execution_scope(connection, request, allocation)?;
    match (
        allocation.binding_id.as_deref(),
        allocation.attempt_id.as_deref(),
        allocation.writer_grant_admission.as_ref(),
    ) {
        (None, None, None) => Ok(()),
        (Some(binding_id), Some(attempt_id), Some(admission)) => {
            let execution =
                load_execution_authority(connection, &allocation.task_id, binding_id, now)?;
            if execution.attempt_id != attempt_id
                || execution.semantic_program_hash != allocation.semantic_program_hash
                || execution.node_id != allocation.node_id
                || exact_operation_grant(
                    connection,
                    &allocation.task_id,
                    &execution,
                    "artifact.write",
                    "output-allocation",
                    &request.allocation_id,
                    now,
                    Some(admission),
                )?
                .is_none()
            {
                return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
            }
            Ok(())
        }
        _ => Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED")),
    }
}

fn lineage_authorized(
    connection: &Connection,
    request: &ArtifactPublicationRequest,
    allocation: &AllocationRow,
) -> Result<bool> {
    for source in request
        .lineage
        .input_artifact_ids
        .iter()
        .chain(&request.lineage.derived_from_artifact_ids)
    {
        let authorized = match (
            allocation.binding_id.as_deref(),
            allocation.attempt_id.as_deref(),
        ) {
            (Some(binding_id), Some(attempt_id)) => connection.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM step_executions s
                    JOIN task_artifacts t ON t.task_id=s.task_id AND t.artifact_id=?4
                    WHERE s.task_id=?1 AND s.binding_id=?2 AND s.attempt_id=?3
                      AND EXISTS(SELECT 1 FROM json_each(s.input_artifacts_json) WHERE value=?4)
                )",
                params![request.task_id, binding_id, attempt_id, source],
                |row| row.get::<_, bool>(0),
            )?,
            (None, None) => connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM task_artifacts WHERE task_id=?1 AND artifact_id=?2 AND role IN ('input','intermediate','output'))",
                params![request.task_id, source],
                |row| row.get::<_, bool>(0),
            )?,
            _ => false,
        };
        if !authorized {
            return Ok(false);
        }
    }
    Ok(true)
}

fn validate_import_request(request: &ImportArtifactRequest) -> Result<()> {
    if request.schema_version != SCHEMA_VERSION
        || request.media_type.is_empty()
        || request.media_type.chars().count() > 160
        || request.max_size_bytes == Some(0)
        || !all_unique(&request.labels)
        || request.labels.len() > 64
        || request
            .format
            .as_ref()
            .is_some_and(|value| value.chars().count() > 160)
        || request
            .labels
            .iter()
            .any(|value| value.chars().count() > 256)
        || request
            .expires_at
            .as_deref()
            .is_some_and(|value| OffsetDateTime::parse(value, &Rfc3339).is_err())
    {
        return Err(TaskManagerError::InvalidRecord(
            "invalid Artifact import request",
        ));
    }
    validate_id(&request.task_id, 256, "invalid Artifact import Task")?;
    if let Some(import_id) = request.import_id.as_deref() {
        validate_id(import_id, 256, "invalid Artifact import ID")?;
    }
    validate_optional_semantic_type(request.semantic_type.as_deref())?;
    Ok(())
}

fn validate_allocation_request_shape(request: &OutputAllocationRequest) -> Result<()> {
    if request.schema_version != SCHEMA_VERSION
        || request.allowed_media_types.len() > 32
        || !all_unique(&request.allowed_media_types)
        || request
            .allowed_media_types
            .iter()
            .any(|value| value.is_empty() || value.chars().count() > 160)
        || request
            .output_port
            .as_ref()
            .is_some_and(|value| value.chars().count() > 128)
        || request
            .binding_id
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.chars().count() > 256)
        || request
            .attempt_id
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.chars().count() > 256)
        || request.binding_id.is_some() != request.attempt_id.is_some()
    {
        return Err(TaskManagerError::InvalidRecord(
            "invalid Artifact output allocation",
        ));
    }
    validate_id(
        &request.allocation_id,
        256,
        "invalid Artifact allocation ID",
    )?;
    validate_id(&request.task_id, 256, "invalid Artifact allocation Task")?;
    validate_id(&request.node_id, 128, "invalid Artifact allocation node")?;
    validate_hash(&request.semantic_program_hash)?;
    validate_optional_semantic_type(request.expected_semantic_type.as_deref())?;
    Ok(())
}

fn validate_allocation_request_expiry(request: &OutputAllocationRequest, now: &str) -> Result<()> {
    if parse_time(&request.expires_at)? <= parse_time(now)? {
        return Err(TaskManagerError::InvalidRecord(
            "invalid Artifact output allocation",
        ));
    }
    Ok(())
}

fn validate_publication_request(request: &ArtifactPublicationRequest) -> Result<()> {
    let lineage_unique = all_unique(&request.lineage.input_artifact_ids)
        && all_unique(&request.lineage.derived_from_artifact_ids)
        && all_unique(&request.lineage.representation_of_object_ids);
    if request.schema_version != SCHEMA_VERSION
        || request.media_type.is_empty()
        || request.media_type.chars().count() > 160
        || request.labels.len() > 64
        || !all_unique(&request.labels)
        || request.lineage.input_artifact_ids.len() > 256
        || request.lineage.derived_from_artifact_ids.len() > 256
        || request.lineage.representation_of_object_ids.len() > 64
        || !lineage_unique
        || !request.lineage.representation_of_object_ids.is_empty()
        || request
            .format
            .as_ref()
            .is_some_and(|value| value.chars().count() > 160)
        || request
            .labels
            .iter()
            .any(|value| value.chars().count() > 256)
        || request
            .lineage
            .input_artifact_ids
            .iter()
            .chain(&request.lineage.derived_from_artifact_ids)
            .any(|value| value.is_empty() || value.chars().count() > 512)
        || request
            .lineage
            .representation_of_object_ids
            .iter()
            .any(|value| !value.starts_with("object://") || value.chars().count() > 1024)
    {
        return Err(TaskManagerError::InvalidRecord(
            "invalid Artifact publication request",
        ));
    }
    validate_id(
        &request.publication_id,
        256,
        "invalid Artifact publication ID",
    )?;
    validate_id(
        &request.allocation_id,
        256,
        "invalid Artifact allocation ID",
    )?;
    validate_id(&request.task_id, 256, "invalid Artifact publication Task")?;
    validate_optional_semantic_type(request.semantic_type.as_deref())?;
    Ok(())
}

fn publication_conflict(
    request: &ArtifactPublicationRequest,
    resulted_at: String,
) -> ArtifactPublicationResult {
    ArtifactPublicationResult {
        schema_version: SCHEMA_VERSION.to_owned(),
        publication_id: request.publication_id.clone(),
        allocation_id: request.allocation_id.clone(),
        task_id: request.task_id.clone(),
        published: false,
        reason_code: "ARTIFACT_PUBLICATION_ID_REUSE_CONFLICT".to_owned(),
        message: None,
        artifact_id: None,
        artifact_uri: None,
        semantic_type: None,
        media_type: None,
        size_bytes: None,
        content_hash: None,
        blob_reused: None,
        provenance_event_id: None,
        provenance_event_hash: None,
        resulted_at,
    }
}

fn publication_failure(
    request: &ArtifactPublicationRequest,
    reason_code: &str,
    resulted_at: String,
) -> ArtifactPublicationResult {
    ArtifactPublicationResult {
        schema_version: SCHEMA_VERSION.to_owned(),
        publication_id: request.publication_id.clone(),
        allocation_id: request.allocation_id.clone(),
        task_id: request.task_id.clone(),
        published: false,
        reason_code: reason_code.to_owned(),
        message: None,
        artifact_id: None,
        artifact_uri: None,
        semantic_type: None,
        media_type: None,
        size_bytes: None,
        content_hash: None,
        blob_reused: None,
        provenance_event_id: None,
        provenance_event_hash: None,
        resulted_at,
    }
}

fn authenticate_failed_publication(
    connection: &Connection,
    request: &ArtifactPublicationRequest,
    stored_state: &str,
    result_json: Option<&str>,
    committed_at: Option<&str>,
) -> Result<ArtifactPublicationResult> {
    let result_json = result_json.ok_or(TaskManagerError::InvalidRecord(
        "stored Artifact publication failure receipt is missing",
    ))?;
    let result: ArtifactPublicationResult = serde_json::from_str(result_json)?;
    let committed_at = committed_at.ok_or(TaskManagerError::InvalidRecord(
        "stored Artifact publication failure receipt is missing its commit time",
    ))?;
    let registered_failure = matches!(
        result.reason_code.as_str(),
        "ARTIFACT_NOT_FOUND"
            | "ARTIFACT_AUTHORITY_DENIED"
            | "ARTIFACT_ALLOCATION_NOT_FOUND"
            | "ARTIFACT_ALLOCATION_EXPIRED"
            | "ARTIFACT_ALLOCATION_STATE_CONFLICT"
            | "ARTIFACT_SIZE_LIMIT"
            | "ARTIFACT_HASH_MISMATCH"
            | "ARTIFACT_MEDIA_TYPE_MISMATCH"
            | "ARTIFACT_SEMANTIC_TYPE_MISMATCH"
            | "ARTIFACT_PUBLICATION_ID_REUSE_CONFLICT"
            | "ARTIFACT_BLOB_DURABILITY_FAILED"
            | "ARTIFACT_METADATA_COMMIT_FAILED"
            | "ARTIFACT_INTEGRITY_FAILED"
            | "ARTIFACT_EXPORT_FAILED"
            | "ARTIFACT_EXPORT_FAILED_NO_EFFECT"
            | "ARTIFACT_EXPORT_OUTCOME_UNKNOWN"
            | "ARTIFACT_EXPORT_OPERATION_ID_REUSE_CONFLICT"
    );
    if result.schema_version != SCHEMA_VERSION
        || !matches!(stored_state, "FAILED" | "ABORTED")
        || (stored_state == "ABORTED" && result.reason_code != "ARTIFACT_ALLOCATION_STATE_CONFLICT")
        || result.publication_id != request.publication_id
        || result.allocation_id != request.allocation_id
        || result.task_id != request.task_id
        || result.published
        || !registered_failure
        || result.message.is_some()
        || result.artifact_id.is_some()
        || result.artifact_uri.is_some()
        || result.semantic_type.is_some()
        || result.media_type.is_some()
        || result.size_bytes.is_some()
        || result.content_hash.is_some()
        || result.blob_reused.is_some()
        || result.provenance_event_id.is_some()
        || result.provenance_event_hash.is_some()
        || OffsetDateTime::parse(&result.resulted_at, &Rfc3339).is_err()
        || result.resulted_at != committed_at
        || canonical_json(&result)? != result_json
        || !super::verify_provenance_through(connection, &request.task_id, None)?
    {
        return Err(TaskManagerError::InvalidRecord(
            "stored Artifact publication failure receipt is invalid",
        ));
    }
    Ok(result)
}

fn artifact_reason(error: &TaskManagerError) -> Option<&'static str> {
    match error {
        TaskManagerError::InvalidRecord(code) if code.starts_with("ARTIFACT_") => Some(code),
        _ => None,
    }
}

fn insert_lineage(
    transaction: &rusqlite::Transaction<'_>,
    request: &ArtifactPublicationRequest,
    child: &str,
    node_id: &str,
    created_at: &str,
) -> Result<()> {
    for (sources, relationship) in [
        (&request.lineage.input_artifact_ids, "consumed-by"),
        (&request.lineage.derived_from_artifact_ids, "transformed-to"),
    ] {
        for source in sources {
            transaction.execute("INSERT OR IGNORE INTO artifact_lineage(parent_artifact_id,child_artifact_id,task_id,node_id,relationship,created_at) VALUES (?1,?2,?3,?4,?5,?6)",params![source,child,request.task_id,node_id,relationship,created_at])?;
        }
    }
    Ok(())
}

fn artifact_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ArtifactHandle> {
    let size: i64 = row.get(5)?;
    let content_hash: String = row.get(6)?;
    let sensitivity: String = row.get(7)?;
    let retention: String = row.get(8)?;
    let origin_kind: String = row.get(10)?;
    let integrity: String = row.get(16)?;
    let labels: Option<String> = row.get(19)?;
    let convert = || -> Result<ArtifactHandle> {
        Ok(ArtifactHandle {
            artifact_id: row.get(0)?,
            uri: ArtifactUri(row.get(1)?),
            semantic_type: row.get(2)?,
            media_type: row.get(3)?,
            format: row.get(4)?,
            size_bytes: Some(
                u64::try_from(size)
                    .map_err(|_| TaskManagerError::InvalidRecord("negative Artifact size"))?,
            ),
            content_hash: Some(ContentHash::from_tagged(&content_hash)?),
            origin: ArtifactOrigin {
                kind: ArtifactOriginKind::parse(&origin_kind)?,
                task_id: row.get(11)?,
                semantic_program_hash: row.get(12)?,
                step_id: row.get(13)?,
                execution_binding_id: row.get(14)?,
                provider_id: row.get(15)?,
            },
            sensitivity: Sensitivity::parse(&sensitivity)?,
            retention: Some(ArtifactRetention {
                class: Some(RetentionClass::parse(&retention)?),
                expires_at: row.get(9)?,
            }),
            integrity: Some(ArtifactIntegrity {
                state: Some(ArtifactIntegrityState::parse(&integrity)?),
                verified_at: row.get(17)?,
                verifier: row.get(18)?,
            }),
            labels: labels
                .map(|value| serde_json::from_str(&value))
                .transpose()?
                .unwrap_or_default(),
            created_at: Some(row.get(20)?),
        })
    };
    convert().map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })
}

fn allocation_from_row(row: &rusqlite::Row<'_>) -> Result<ArtifactOutputAllocation> {
    let allowed: Option<String> = row.get(8)?;
    let max: Option<i64> = row.get(9)?;
    Ok(ArtifactOutputAllocation {
        schema_version: SCHEMA_VERSION.to_owned(),
        allocation_id: row.get(0)?,
        task_id: row.get(1)?,
        semantic_program_hash: row.get(2)?,
        node_id: row.get(3)?,
        binding_id: row.get(4)?,
        attempt_id: row.get(5)?,
        output_port: row.get(6)?,
        expected_semantic_type: row.get(7)?,
        allowed_media_types: allowed
            .map(|value| serde_json::from_str(&value))
            .transpose()?
            .unwrap_or_default(),
        max_size_bytes: max
            .map(|value| {
                u64::try_from(value)
                    .map_err(|_| TaskManagerError::InvalidRecord("negative Artifact size limit"))
            })
            .transpose()?,
        sensitivity: Sensitivity::parse(&row.get::<_, String>(10)?)?,
        retention: RetentionClass::parse(&row.get::<_, String>(11)?)?,
        state: ArtifactAllocationState::parse(&row.get::<_, String>(12)?)?,
        publication_id: row.get(13)?,
        published_artifact_id: row.get(14)?,
        created_at: row.get(15)?,
        expires_at: row.get(16)?,
        updated_at: row.get(17)?,
    })
}

fn upsert_durable_blob(
    transaction: &rusqlite::Transaction<'_>,
    content_hash: &str,
    size: u64,
    storage_ref: &str,
    verified_at: &str,
) -> Result<()> {
    if let Some((stored_size, stored_ref)) = transaction
        .query_row(
            "SELECT size_bytes,storage_ref FROM artifact_blobs WHERE content_hash=?1",
            [content_hash],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
    {
        if stored_size != to_i64(size)? || stored_ref != storage_ref {
            return Err(TaskManagerError::InvalidRecord(
                "Artifact blob identity collision",
            ));
        }
        transaction.execute("UPDATE artifact_blobs SET durability_state='DURABLE',verified_at=?2 WHERE content_hash=?1",params![content_hash,verified_at])?;
    } else {
        transaction.execute("INSERT INTO artifact_blobs(content_hash,size_bytes,storage_ref,durability_state,created_at,verified_at) VALUES (?1,?2,?3,'DURABLE',?4,?4)",params![content_hash,to_i64(size)?,storage_ref,verified_at])?;
    }
    Ok(())
}

impl TaskManager {
    fn remove_uncommitted_blob_if_unreferenced(
        &self,
        content_hash: &str,
        storage_ref: &str,
    ) -> Result<()> {
        let adopted = self.connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM artifact_blobs WHERE content_hash=?1 AND storage_ref=?2
                UNION ALL
                SELECT 1 FROM artifacts WHERE content_hash=?1
             )",
            params![content_hash, storage_ref],
            |row| row.get::<_, bool>(0),
        )?;
        if adopted {
            Ok(())
        } else {
            self.remove_uncommitted_blob(storage_ref)
        }
    }

    fn remove_uncommitted_blob(&self, storage_ref: &str) -> Result<()> {
        match self
            .artifact_store_dir
            .remove_file(safe_internal_ref(storage_ref)?)
        {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        }
        let parent = Path::new(storage_ref)
            .parent()
            .and_then(Path::to_str)
            .ok_or(TaskManagerError::InvalidRecord(
                "invalid Artifact blob reference",
            ))?;
        sync_cap_directory(&self.artifact_store_dir, parent)
    }

    fn place_blob(
        &mut self,
        staging_ref: &str,
        content_hash: &str,
        size: u64,
        preserve_staging: bool,
        placement_identity: &str,
    ) -> Result<(String, bool)> {
        let store = self.artifact_store_dir.try_clone()?;
        validate_hash(content_hash)?;
        let digest = content_hash.strip_prefix("sha256:").unwrap_or_default();
        let storage_ref = format!(
            "blobs/sha256/{}/{}/{}",
            &digest[0..2],
            &digest[2..4],
            digest
        );
        let parent_ref = format!("blobs/sha256/{}/{}", &digest[0..2], &digest[2..4]);
        create_durable_ancestors(&store, &parent_ref)?;
        let pending_ref = format!(
            "blobs/pending/{}-{}",
            digest,
            placement_token(placement_identity)
        );
        let mut source = store.open(safe_internal_ref(staging_ref)?)?;
        let mut pending = store.open_with(
            safe_internal_ref(&pending_ref)?,
            CapOpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true),
        )?;
        secure_cap_file_permissions(&pending)?;
        let mut hasher = Sha256::new();
        let mut copied = 0_u64;
        let mut buffer = vec![0_u8; COPY_BUFFER_SIZE];
        loop {
            let count = source.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            copied = copied
                .checked_add(
                    u64::try_from(count)
                        .map_err(|_| TaskManagerError::InvalidRecord("Artifact size overflow"))?,
                )
                .ok_or(TaskManagerError::InvalidRecord("Artifact size overflow"))?;
            pending.write_all(&buffer[..count])?;
            hasher.update(&buffer[..count]);
        }
        pending.flush()?;
        pending.sync_all()?;
        if copied != size || tagged_digest(hasher) != content_hash {
            drop(pending);
            let _ = store.remove_file(safe_internal_ref(&pending_ref)?);
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_HASH_MISMATCH"));
        }
        sync_cap_directory(&store, "blobs/pending")?;
        pending_placement_step(&store, &pending_ref)?;
        let reused = match store.hard_link(
            safe_internal_ref(&pending_ref)?,
            &store,
            safe_internal_ref(&storage_ref)?,
        ) {
            Ok(()) => {
                let mut promoted = store.open(safe_internal_ref(&storage_ref)?)?;
                let same_identity = same_open_file_identity(&pending, &promoted)?;
                let (promoted_size, promoted_hash) = hash_reader(&mut promoted)?;
                if !same_identity || promoted_size != size || promoted_hash != content_hash {
                    drop(promoted);
                    drop(pending);
                    let _ = store.remove_file(safe_internal_ref(&storage_ref)?);
                    let _ = store.remove_file(safe_internal_ref(&pending_ref)?);
                    return Err(TaskManagerError::InvalidRecord("ARTIFACT_HASH_MISMATCH"));
                }
                false
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let (existing_size, existing_hash) = hash_internal_file(&store, &storage_ref)?;
                if existing_size != size || existing_hash != content_hash {
                    drop(pending);
                    self.mark_content_hash_failed(content_hash, "CORRUPT")?;
                    quarantine_blob_collision(&store, &pending_ref, &storage_ref, digest)?;
                    return Err(TaskManagerError::InvalidRecord("ARTIFACT_HASH_MISMATCH"));
                }
                true
            }
            Err(error) => return Err(error.into()),
        };
        drop(pending);
        durability_step("sync-promoted-blob-parent")?;
        sync_cap_directory(&store, &parent_ref)?;
        durability_step("unlink-promoted-blob-pending")?;
        store.remove_file(safe_internal_ref(&pending_ref)?)?;
        durability_step("sync-promoted-blob-pending")?;
        sync_cap_directory(&store, "blobs/pending")?;
        if !preserve_staging {
            store.remove_file(safe_internal_ref(staging_ref)?)?;
            sync_cap_directory(&store, "staging")?;
        }
        Ok((storage_ref, reused))
    }
}

fn quarantine_blob_collision(
    store: &Dir,
    pending_ref: &str,
    final_ref: &str,
    digest: &str,
) -> Result<()> {
    let token = placement_token(pending_ref);
    for (source, kind) in [(final_ref, "final"), (pending_ref, "pending")] {
        let target = format!("quarantine/blob-collision-{kind}-{digest}-{token}");
        match store.rename(
            safe_internal_ref(source)?,
            store,
            safe_internal_ref(&target)?,
        ) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                store.remove_file(safe_internal_ref(source)?)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    if let Some(parent) = Path::new(final_ref).parent().and_then(Path::to_str) {
        sync_cap_directory(store, parent)?;
    }
    sync_cap_directory(store, "blobs/pending")?;
    sync_cap_directory(store, "quarantine")?;
    Ok(())
}

fn same_open_file_identity(left: &cap_std::fs::File, right: &cap_std::fs::File) -> Result<bool> {
    let left = left.try_clone()?.into_std();
    let right = right.try_clone()?.into_std();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        let left = left.metadata()?;
        let right = right.metadata()?;
        Ok(left.dev() == right.dev() && left.ino() == right.ino())
    }
    #[cfg(windows)]
    {
        let left = winx::winapi_util::file::information(&left)?;
        let right = winx::winapi_util::file::information(&right)?;
        Ok(left.volume_serial_number() == right.volume_serial_number()
            && left.file_index() == right.file_index())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (left, right);
        Ok(true)
    }
}

fn placement_token(identity: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut hasher = Sha256::new();
    hasher.update(b"AIOS-ARTIFACT-BLOB-PLACEMENT\0v1\0");
    hasher.update(identity.as_bytes());
    hasher.update(std::process::id().to_be_bytes());
    hasher.update(NEXT.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    tagged_digest(hasher)
        .strip_prefix("sha256:")
        .unwrap_or_default()
        .to_owned()
}

fn stream_into_new_internal_file<R: Read>(
    reader: &mut R,
    store: &Dir,
    reference: &str,
    maximum: u64,
) -> Result<(u64, String)> {
    let relative = safe_internal_ref(reference)?;
    let mut file = store.open_with(
        &relative,
        CapOpenOptions::new().write(true).create_new(true),
    )?;
    secure_cap_file_permissions(&file)?;
    let result = stream_into_file(reader, &mut file, maximum);
    if result.is_err() {
        drop(file);
        match store.remove_file(&relative) {
            Ok(()) => sync_cap_directory(store, "staging")?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    result
}

#[cfg(unix)]
fn secure_cap_file_permissions(file: &cap_std::fs::File) -> Result<()> {
    use cap_std::fs::PermissionsExt as _;

    file.set_permissions(cap_std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "matches the fallible Unix permission hardening interface"
)]
fn secure_cap_file_permissions(_file: &cap_std::fs::File) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn secure_std_file_permissions(file: &File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "matches the fallible Unix permission hardening interface"
)]
fn secure_std_file_permissions(_file: &File) -> Result<()> {
    Ok(())
}

fn stream_into_new_file<R: Read>(
    reader: &mut R,
    path: &Path,
    maximum: u64,
) -> Result<(u64, String)> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    secure_std_file_permissions(&file)?;
    let result = stream_into_file(reader, &mut file, maximum);
    if result.is_err() {
        drop(file);
        let _ = std::fs::remove_file(path);
    }
    result
}

fn stream_into_file<R: Read, W: Write + SyncFile>(
    reader: &mut R,
    file: &mut W,
    maximum: u64,
) -> Result<(u64, String)> {
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = vec![0_u8; COPY_BUFFER_SIZE];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        size = size
            .checked_add(
                u64::try_from(count)
                    .map_err(|_| TaskManagerError::InvalidRecord("Artifact size overflow"))?,
            )
            .ok_or(TaskManagerError::InvalidRecord("Artifact size overflow"))?;
        if size > maximum {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_SIZE_LIMIT"));
        }
        file.write_all(&buffer[..count])?;
        hasher.update(&buffer[..count]);
    }
    file.flush()?;
    file.sync_all()?;
    Ok((size, tagged_digest(hasher)))
}

trait SyncFile {
    fn sync_all(&self) -> std::io::Result<()>;
}

impl SyncFile for File {
    fn sync_all(&self) -> std::io::Result<()> {
        File::sync_all(self)
    }
}

impl SyncFile for cap_std::fs::File {
    fn sync_all(&self) -> std::io::Result<()> {
        cap_std::fs::File::sync_all(self)
    }
}

fn hash_file(path: &Path) -> Result<(u64, String)> {
    let mut file = File::open(path)?;
    hash_reader(&mut file)
}

fn hash_internal_file(store: &Dir, reference: &str) -> Result<(u64, String)> {
    let mut file = store.open(safe_internal_ref(reference)?)?;
    hash_reader(&mut file)
}

fn hash_reader<R: Read>(file: &mut R) -> Result<(u64, String)> {
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = vec![0_u8; COPY_BUFFER_SIZE];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        size = size
            .checked_add(
                u64::try_from(count)
                    .map_err(|_| TaskManagerError::InvalidRecord("Artifact size overflow"))?,
            )
            .ok_or(TaskManagerError::InvalidRecord("Artifact size overflow"))?;
        hasher.update(&buffer[..count]);
    }
    Ok((size, tagged_digest(hasher)))
}

fn tagged_digest(hasher: Sha256) -> String {
    let mut hex = String::with_capacity(64);
    for byte in hasher.finalize() {
        write!(&mut hex, "{byte:02x}").expect("writing to String cannot fail");
    }
    format!("sha256:{hex}")
}

fn canonical_text_digest(domain: &str, value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(value.as_bytes());
    tagged_digest(hasher)
}

fn import_request_digest(request: &ImportArtifactRequest) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"AIOS-ARTIFACT-IMPORT-REQUEST\0v1\0");
    hasher.update(canonical_json(request)?.as_bytes());
    Ok(tagged_digest(hasher))
}

struct ExportCopyFailure {
    error: TaskManagerError,
    external_effect_possible: bool,
}

#[allow(
    clippy::too_many_arguments,
    reason = "the export copy fence must carry the exact sealed authority tuple"
)]
fn copy_export_bounded<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    external_effect_possible: bool,
    maximum: u64,
    connection: &Connection,
    clock: &Arc<dyn Clock>,
    task_id: &str,
    authority: &ReadAuthority,
    destination_class: &str,
    grant_admission: Option<&GrantAdmission>,
) -> std::result::Result<u64, ExportCopyFailure> {
    let mut size = 0_u64;
    let mut buffer = vec![0_u8; COPY_BUFFER_SIZE];
    export_copy_step().map_err(|error| ExportCopyFailure {
        error,
        external_effect_possible,
    })?;
    loop {
        if let Err(error) = validate_export_destination_fence(
            connection,
            clock,
            task_id,
            authority,
            destination_class,
            grant_admission,
        ) {
            return Err(ExportCopyFailure {
                error,
                external_effect_possible,
            });
        }
        let count = reader
            .read(&mut buffer)
            .map_err(|error| ExportCopyFailure {
                error: error.into(),
                external_effect_possible,
            })?;
        if count == 0 {
            break;
        }
        size = size
            .checked_add(u64::try_from(count).map_err(|_| ExportCopyFailure {
                error: TaskManagerError::InvalidRecord("Artifact size overflow"),
                external_effect_possible,
            })?)
            .ok_or(ExportCopyFailure {
                error: TaskManagerError::InvalidRecord("Artifact size overflow"),
                external_effect_possible,
            })?;
        if size > maximum {
            return Err(ExportCopyFailure {
                error: TaskManagerError::InvalidRecord("ARTIFACT_SIZE_LIMIT"),
                external_effect_possible,
            });
        }
        if let Err(error) = validate_export_destination_fence(
            connection,
            clock,
            task_id,
            authority,
            destination_class,
            grant_admission,
        ) {
            return Err(ExportCopyFailure {
                error,
                external_effect_possible,
            });
        }
        writer
            .write_all(&buffer[..count])
            .map_err(|error| ExportCopyFailure {
                error: error.into(),
                external_effect_possible,
            })?;
    }
    writer.flush().map_err(|error| ExportCopyFailure {
        error: error.into(),
        // A destination may perform its external effect during flush, including
        // for an empty payload, and may fail after that effect became visible.
        external_effect_possible,
    })?;
    validate_export_destination_fence(
        connection,
        clock,
        task_id,
        authority,
        destination_class,
        grant_admission,
    )
    .map_err(|error| ExportCopyFailure {
        error,
        external_effect_possible,
    })?;
    Ok(size)
}

fn validate_export_destination_fence(
    connection: &Connection,
    clock: &Arc<dyn Clock>,
    task_id: &str,
    authority: &ReadAuthority,
    destination_class: &str,
    grant_admission: Option<&GrantAdmission>,
) -> Result<()> {
    ensure_task_is_not_recovering(connection, task_id)?;
    let now = clock.now();
    match (&authority.execution, grant_admission) {
        (Some(execution), Some(admission)) => {
            if load_execution_authority(connection, task_id, &execution.binding_id, &now)?
                != *execution
                || exact_operation_grant(
                    connection,
                    task_id,
                    execution,
                    "data.egress",
                    "destination",
                    destination_class,
                    &now,
                    Some(admission),
                )?
                .is_none()
            {
                return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
            }
        }
        (None, None) => {
            if capture_read_authority(connection, task_id, None, &now)? != *authority {
                return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
            }
        }
        _ => return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED")),
    }
    Ok(())
}

fn unresolved_export_effect_exists(
    connection: &Connection,
    intent: &ArtifactExportIntent,
) -> Result<bool> {
    let rows = {
        let mut statement = connection.prepare(
            "SELECT operation_id,state,outcome_certainty,details_json FROM operations
             WHERE task_id=?1
               AND transaction_class='irreversible_external'
               AND effect_class='DATA_EGRESS'
               AND json_extract(details_json,'$.version') IN (1,2)
               AND json_extract(details_json,'$.task_id')=?1
               AND json_extract(details_json,'$.artifact_id')=?2
               AND json_extract(details_json,'$.content_hash')=?3
               AND json_extract(details_json,'$.destination_class')=?4",
        )?;
        let rows = statement.query_map(
            params![
                &intent.task_id,
                &intent.artifact_id,
                &intent.content_hash,
                &intent.destination_class,
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )?;
        rows.collect::<std::result::Result<Vec<_>, _>>()?
    };
    for (operation_id, state, certainty, details_json) in rows {
        if matches!(state.as_str(), "PREPARED" | "STARTED" | "UNKNOWN")
            || matches!(
                certainty.as_deref(),
                Some("FAILED_PARTIAL_EFFECT" | "OUTCOME_UNKNOWN")
            )
        {
            return Ok(true);
        }
        if state == "FAILED" && certainty.as_deref() == Some("FAILED_NO_EFFECT") {
            let authenticated =
                authenticate_export_operation(connection, &operation_id, &details_json)?;
            if !matches!(
                authenticated,
                Some(Err(TaskManagerError::InvalidRecord(
                    "ARTIFACT_EXPORT_FAILED_NO_EFFECT"
                )))
            ) {
                return Err(TaskManagerError::InvalidRecord(
                    "stored Artifact export reconciliation is invalid",
                ));
            }
        }
    }
    Ok(false)
}

fn ensure_no_unknown_artifact_export(connection: &Connection, task_id: &str) -> Result<()> {
    let unresolved = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM operations
             WHERE task_id=?1
               AND transaction_class='irreversible_external'
               AND effect_class='DATA_EGRESS'
               AND state='UNKNOWN' AND outcome_certainty='OUTCOME_UNKNOWN'
               AND json_extract(details_json,'$.version') IN (1,2)
               AND json_type(details_json,'$.artifact_id')='text'
               AND json_type(details_json,'$.destination_class')='text'
         )",
        [task_id],
        |row| row.get::<_, bool>(0),
    )?;
    if unresolved {
        Err(TaskManagerError::InvalidRecord(
            "ARTIFACT_EXPORT_OUTCOME_UNKNOWN",
        ))
    } else {
        Ok(())
    }
}

fn ensure_task_is_not_recovering(connection: &Connection, task_id: &str) -> Result<()> {
    let recovering = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM tasks WHERE task_id=?1 AND state='RECOVERING')",
        [task_id],
        |row| row.get::<_, bool>(0),
    )?;
    if recovering {
        Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
    } else {
        Ok(())
    }
}

fn reconcile_started_export_operation(
    transaction: &Transaction<'_>,
    operation_id: &str,
    intent_json: &str,
    receipt: Option<&str>,
    reconciled_at: &str,
) -> Result<()> {
    let intent: ArtifactExportIntent = serde_json::from_str(intent_json)?;
    if canonical_json(&intent)? != intent_json
        || !matches!(
            intent.version,
            1 | PHASE_AUTHENTICATED_EXPORT_INTENT_VERSION
        )
    {
        return Err(TaskManagerError::InvalidRecord(
            "stored Artifact export operation is invalid",
        ));
    }
    let phase_history = export_phase_history_exists(transaction, &intent.task_id, operation_id)?;
    let phase_aware = intent.version == PHASE_AUTHENTICATED_EXPORT_INTENT_VERSION || phase_history;
    if !phase_aware {
        if !super::verify_provenance_through(transaction, &intent.task_id, None)?
            || !matches!(
                authenticate_export_operation(transaction, operation_id, intent_json)?,
                Some(Err(TaskManagerError::InvalidRecord(
                    "ARTIFACT_EXPORT_OUTCOME_UNKNOWN"
                )))
            )
        {
            return Err(TaskManagerError::InvalidRecord(
                "stored legacy Artifact export operation is invalid",
            ));
        }
        let changed = transaction.execute(
            "UPDATE operations
             SET state='UNKNOWN',outcome_certainty='OUTCOME_UNKNOWN',finished_at=?4
             WHERE operation_id=?1 AND details_json=?2 AND external_receipt IS ?3
               AND state='STARTED' AND outcome_certainty IS NULL",
            params![operation_id, intent_json, receipt, reconciled_at],
        )?;
        if changed != 1 {
            return Err(TaskManagerError::InvalidRecord(
                "stored legacy Artifact export operation is invalid",
            ));
        }
        return Ok(());
    }
    let receipt = receipt.ok_or(TaskManagerError::InvalidRecord(
        "stored Artifact export effect phase is invalid",
    ))?;
    let pre_destination = authenticate_pre_destination_export_admission(
        transaction,
        operation_id,
        intent_json,
        receipt,
    )?;
    let armed =
        authenticate_armed_export_operation(transaction, operation_id, intent_json, receipt)?;
    if pre_destination == armed {
        return Err(TaskManagerError::InvalidRecord(
            "stored Artifact export effect phase is invalid",
        ));
    }
    let failure = if pre_destination {
        "stored Artifact export pre-destination admission is invalid"
    } else {
        "stored Artifact export armed phase is invalid"
    };
    let changed = transaction.execute(
        "UPDATE operations
         SET state=CASE WHEN ?4 THEN 'FAILED' ELSE 'UNKNOWN' END,
             outcome_certainty=CASE WHEN ?4 THEN 'FAILED_NO_EFFECT' ELSE 'OUTCOME_UNKNOWN' END,
             finished_at=CASE WHEN ?4 THEN started_at ELSE ?5 END
         WHERE operation_id=?1 AND details_json=?2 AND external_receipt=?3
           AND state='STARTED' AND outcome_certainty IS NULL",
        params![
            operation_id,
            intent_json,
            receipt,
            pre_destination,
            reconciled_at
        ],
    )?;
    if changed != 1 {
        return Err(TaskManagerError::InvalidRecord(failure));
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "replay authenticates the complete operation intent, receipt, and provenance row"
)]
fn authenticate_export_operation(
    connection: &Connection,
    operation_id: &str,
    intent_json: &str,
) -> Result<Option<std::result::Result<u64, TaskManagerError>>> {
    let intent: ArtifactExportIntent = serde_json::from_str(intent_json)?;
    let row = connection
        .query_row(
            "SELECT task_id,semantic_program_hash,node_id,binding_id,attempt_id,
                    transaction_class,effect_class,idempotency_key,state,outcome_certainty,
                    external_receipt,details_json,finished_at
             FROM operations WHERE operation_id=?1",
            [operation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, Option<String>>(12)?,
                ))
            },
        )
        .optional()?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.0 != intent.task_id
        || !matches!(
            intent.version,
            1 | PHASE_AUTHENTICATED_EXPORT_INTENT_VERSION
        )
        || row.1 != intent.semantic_program_hash
        || row.2 != intent.node_id
        || row.3 != intent.binding_id
        || row.4 != intent.attempt_id
        || row.5.as_deref() != Some("irreversible_external")
        || row.6 != "DATA_EGRESS"
        || row.7.as_deref() != Some(operation_id)
        || row.11.as_deref() != Some(intent_json)
    {
        return Err(TaskManagerError::InvalidRecord(
            "ARTIFACT_EXPORT_OPERATION_ID_REUSE_CONFLICT",
        ));
    }
    let phase_history = export_phase_history_exists(connection, &intent.task_id, operation_id)?;
    let phase_aware = intent.version == PHASE_AUTHENTICATED_EXPORT_INTENT_VERSION || phase_history;
    let pre_destination_admission = if phase_aware {
        row.10.as_deref().map_or(Ok(false), |receipt| {
            authenticate_pre_destination_export_admission(
                connection,
                operation_id,
                intent_json,
                receipt,
            )
        })?
    } else {
        false
    };
    let armed_admission = if phase_aware {
        row.10.as_deref().map_or(Ok(false), |receipt| {
            authenticate_armed_export_operation(connection, operation_id, intent_json, receipt)
        })?
    } else {
        false
    };
    let replay = match (row.8.as_str(), row.9.as_deref()) {
        ("SUCCEEDED", Some("COMPLETED")) => {
            let receipt: serde_json::Value = serde_json::from_str(row.10.as_deref().ok_or(
                TaskManagerError::InvalidRecord("stored Artifact export receipt is invalid"),
            )?)?;
            if receipt.get("version").and_then(serde_json::Value::as_u64) != Some(1) {
                return Err(TaskManagerError::InvalidRecord(
                    "stored Artifact export receipt is invalid",
                ));
            }
            let size = receipt
                .get("size_bytes")
                .and_then(serde_json::Value::as_u64)
                .ok_or(TaskManagerError::InvalidRecord(
                    "stored Artifact export receipt is invalid",
                ))?;
            let event_id = receipt
                .get("provenance_event_id")
                .and_then(serde_json::Value::as_str)
                .ok_or(TaskManagerError::InvalidRecord(
                    "stored Artifact export receipt is invalid",
                ))?;
            let expected_event_hash = receipt
                .get("provenance_event_hash")
                .and_then(serde_json::Value::as_str)
                .ok_or(TaskManagerError::InvalidRecord(
                    "stored Artifact export receipt is invalid",
                ))?;
            let (stored_event_hash, stored_event_json, sequence, previous_event_hash) = connection
                .query_row(
                    "SELECT event_hash,event_json,sequence,previous_event_hash FROM provenance_events
                     WHERE task_id=?1 AND event_id=?2 AND event_type='artifact.exported'",
                    params![intent.task_id, event_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, Option<String>>(3)?,
                        ))
                    },
                )
                .optional()?
                .ok_or(TaskManagerError::InvalidRecord(
                    "stored Artifact export receipt is invalid",
                ))?;
            let stored_event: serde_json::Value = serde_json::from_str(&stored_event_json)?;
            if stored_event_hash != expected_event_hash
                || !super::verify_provenance_through(connection, &intent.task_id, Some(sequence))?
                || u64::try_from(sequence).map_or(true, |sequence| {
                    provenance_hash(
                        &intent.task_id,
                        sequence,
                        previous_event_hash.as_deref(),
                        &stored_event,
                    )
                    .map_or(true, |computed| computed != stored_event_hash)
                })
                || stored_event
                    .pointer("/details/operation_id")
                    .and_then(serde_json::Value::as_str)
                    != Some(operation_id)
                || stored_event
                    .pointer("/details/size_bytes")
                    .and_then(serde_json::Value::as_u64)
                    != Some(size)
                || stored_event
                    .pointer("/external_transfer/destination")
                    .and_then(serde_json::Value::as_str)
                    != Some(intent.destination_class.as_str())
                || stored_event.get("authority_token_id").and_then(|value| {
                    if value.is_null() {
                        None
                    } else {
                        value.as_str()
                    }
                }) != intent.grant_id.as_deref()
                || stored_event
                    .pointer("/actor/kind")
                    .and_then(serde_json::Value::as_str)
                    != Some(intent.principal_kind.as_str())
                || stored_event
                    .pointer("/actor/id")
                    .and_then(serde_json::Value::as_str)
                    != Some(intent.principal_id.as_str())
                || stored_event
                    .get("execution_binding_id")
                    .and_then(serde_json::Value::as_str)
                    != intent.binding_id.as_deref()
                || stored_event
                    .get("input_artifacts")
                    .and_then(serde_json::Value::as_array)
                    .is_none_or(|values| {
                        values.as_slice() != [serde_json::Value::String(intent.artifact_id.clone())]
                    })
            {
                return Err(TaskManagerError::InvalidRecord(
                    "stored Artifact export receipt is invalid",
                ));
            }
            Ok(size)
        }
        ("FAILED", Some("FAILED_NO_EFFECT")) => {
            let receipt_kind = row.10.as_deref().and_then(|receipt| {
                serde_json::from_str::<serde_json::Value>(receipt)
                    .ok()
                    .and_then(|receipt| {
                        receipt
                            .get("kind")
                            .and_then(serde_json::Value::as_str)
                            .map(ToOwned::to_owned)
                    })
            });
            if receipt_kind.as_deref() == Some("pre-destination-no-effect") {
                authenticate_unopened_export_no_effect(
                    connection,
                    operation_id,
                    &intent,
                    row.10.as_deref().unwrap_or_default(),
                    row.12.as_deref(),
                )?;
            } else if receipt_kind.as_deref() == Some("pre-destination-admission") {
                if !pre_destination_admission {
                    return Err(TaskManagerError::InvalidRecord(
                        "stored Artifact export reconciliation is invalid",
                    ));
                }
            } else {
                authenticate_reconciled_export_no_effect(connection, operation_id, &intent)?;
            }
            Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_FAILED_NO_EFFECT",
            ))
        }
        ("STARTED", None) if pre_destination_admission => Err(TaskManagerError::InvalidRecord(
            "ARTIFACT_EXPORT_FAILED_NO_EFFECT",
        )),
        ("STARTED", None) | ("UNKNOWN", Some("OUTCOME_UNKNOWN")) if armed_admission => Err(
            TaskManagerError::InvalidRecord("ARTIFACT_EXPORT_OUTCOME_UNKNOWN"),
        ),
        ("STARTED", None) | ("UNKNOWN", Some("OUTCOME_UNKNOWN")) if !phase_aware => Err(
            TaskManagerError::InvalidRecord("ARTIFACT_EXPORT_OUTCOME_UNKNOWN"),
        ),
        ("STARTED" | "PREPARED" | "UNKNOWN", None | Some("OUTCOME_UNKNOWN"))
        | ("FAILED", Some("FAILED_PARTIAL_EFFECT")) => Err(TaskManagerError::InvalidRecord(
            "stored Artifact export effect phase is invalid",
        )),
        _ => {
            return Err(TaskManagerError::InvalidRecord(
                "stored Artifact export operation is invalid",
            ));
        }
    };
    Ok(Some(replay))
}

fn export_phase_history_exists(
    connection: &Connection,
    task_id: &str,
    operation_id: &str,
) -> Result<bool> {
    connection
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM provenance_events
                 WHERE task_id=?1 AND event_id IN (?2,?3)
             )",
            params![
                task_id,
                event_id("artifact-export-pre-destination", operation_id),
                event_id("artifact-export-effect-armed", operation_id),
            ],
            |row| row.get::<_, bool>(0),
        )
        .map_err(Into::into)
}

fn export_phase_event(
    intent: &ArtifactExportIntent,
    operation_id: &str,
    phase: &str,
    timestamp: &str,
    intent_hash: &str,
    admission_event: Option<(&str, &str)>,
) -> serde_json::Value {
    let (actor, provider_id) = if intent.principal_kind == "provider" {
        (
            json!({"kind":"provider","id":intent.principal_id}),
            Some(intent.principal_id.clone()),
        )
    } else {
        (
            json!({"kind":intent.principal_kind,"id":intent.principal_id}),
            None,
        )
    };
    let (event_kind, predecessor_id, predecessor_hash) = match admission_event {
        Some((event_id, event_hash)) => (
            "artifact-export-effect-armed",
            Some(event_id),
            Some(event_hash),
        ),
        None => ("artifact-export-pre-destination", None, None),
    };
    json!({
        "schema_version":SCHEMA_VERSION,
        "event_id":event_id(event_kind,operation_id),
        "task_id":intent.task_id,
        "step_id":intent.node_id,
        "event_type":"execution.started",
        "timestamp":timestamp,
        "actor":actor,
        "semantic_program_hash":intent.semantic_program_hash,
        "execution_binding_id":intent.binding_id,
        "provider_id":provider_id,
        "authority_token_id":intent.grant_id,
        "input_artifacts":[intent.artifact_id],
        "output_artifacts":[],
        "status":"pending",
        "details":{
            "operation_id":operation_id,
            "phase":phase,
            "intent_hash":intent_hash,
            "admission_event_id":predecessor_id,
            "admission_event_hash":predecessor_hash,
        },
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "authenticates the complete immutable export phase tuple"
)]
fn authenticate_export_phase_event(
    connection: &Connection,
    intent: &ArtifactExportIntent,
    operation_id: &str,
    phase: &str,
    intent_hash: &str,
    event_id: &str,
    event_hash: &str,
    admission_event: Option<(&str, &str)>,
) -> Result<bool> {
    let row = connection
        .query_row(
            "SELECT timestamp,event_hash,event_json FROM provenance_events
             WHERE task_id=?1 AND event_id=?2 AND event_type='execution.started'",
            params![intent.task_id, event_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((timestamp, stored_hash, event_json)) = row else {
        return Ok(false);
    };
    let expected = export_phase_event(
        intent,
        operation_id,
        phase,
        &timestamp,
        intent_hash,
        admission_event,
    );
    Ok(
        event_id == expected["event_id"].as_str().unwrap_or_default()
            && stored_hash == event_hash
            && serde_json::from_str::<serde_json::Value>(&event_json)? == expected
            && super::verify_provenance_through(connection, &intent.task_id, None)?,
    )
}

fn authenticate_pre_destination_export_admission(
    connection: &Connection,
    operation_id: &str,
    intent_json: &str,
    receipt_json: &str,
) -> Result<bool> {
    let receipt: PreDestinationExportAdmission = match serde_json::from_str(receipt_json) {
        Ok(receipt) => receipt,
        Err(_) => return Ok(false),
    };
    if receipt.version != 1
        || receipt.kind != "pre-destination-admission"
        || receipt.operation_id != operation_id
        || receipt.intent_hash
            != canonical_text_digest("aios.artifact-export.intent.v1", intent_json)
        || canonical_json(&receipt)? != receipt_json
    {
        return Ok(false);
    }
    let intent: ArtifactExportIntent = serde_json::from_str(intent_json)?;
    if !authenticate_export_phase_event(
        connection,
        &intent,
        operation_id,
        "pre-destination-admission",
        &receipt.intent_hash,
        &receipt.provenance_event_id,
        &receipt.provenance_event_hash,
        None,
    )? {
        return Ok(false);
    }
    let armed_event_id = event_id("artifact-export-effect-armed", operation_id);
    let armed_exists = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM provenance_events WHERE task_id=?1 AND event_id=?2)",
        params![intent.task_id, armed_event_id],
        |row| row.get::<_, bool>(0),
    )?;
    if armed_exists {
        return Ok(false);
    }
    let exact = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM operations
         WHERE operation_id=?1 AND details_json=?2 AND external_receipt=?3
           AND ((state='STARTED' AND outcome_certainty IS NULL)
                OR (state='FAILED' AND outcome_certainty='FAILED_NO_EFFECT'))
           AND transaction_class='irreversible_external' AND effect_class='DATA_EGRESS')",
        params![operation_id, intent_json, receipt_json],
        |row| row.get::<_, bool>(0),
    )?;
    Ok(exact)
}

fn authenticate_armed_export_operation(
    connection: &Connection,
    operation_id: &str,
    intent_json: &str,
    receipt_json: &str,
) -> Result<bool> {
    let receipt: ArmedExportAdmission = match serde_json::from_str(receipt_json) {
        Ok(receipt) => receipt,
        Err(_) => return Ok(false),
    };
    let intent: ArtifactExportIntent = serde_json::from_str(intent_json)?;
    if receipt.version != 1
        || receipt.kind != "effect-boundary-armed"
        || receipt.operation_id != operation_id
        || receipt.intent_hash
            != canonical_text_digest("aios.artifact-export.intent.v1", intent_json)
        || canonical_json(&receipt)? != receipt_json
        || !authenticate_export_phase_event(
            connection,
            &intent,
            operation_id,
            "pre-destination-admission",
            &receipt.intent_hash,
            &receipt.admission_event_id,
            &receipt.admission_event_hash,
            None,
        )?
        || !authenticate_export_phase_event(
            connection,
            &intent,
            operation_id,
            "effect-boundary-armed",
            &receipt.intent_hash,
            &receipt.provenance_event_id,
            &receipt.provenance_event_hash,
            Some((
                receipt.admission_event_id.as_str(),
                receipt.admission_event_hash.as_str(),
            )),
        )?
    {
        return Ok(false);
    }
    let exact = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM operations
         WHERE operation_id=?1 AND details_json=?2 AND external_receipt=?3
           AND ((state='STARTED' AND outcome_certainty IS NULL)
                OR (state='UNKNOWN' AND outcome_certainty='OUTCOME_UNKNOWN'))
           AND transaction_class='irreversible_external' AND effect_class='DATA_EGRESS')",
        params![operation_id, intent_json, receipt_json],
        |row| row.get::<_, bool>(0),
    )?;
    Ok(exact)
}

fn authenticate_unopened_export_no_effect(
    connection: &Connection,
    operation_id: &str,
    intent: &ArtifactExportIntent,
    receipt_json: &str,
    finished_at: Option<&str>,
) -> Result<()> {
    let receipt: serde_json::Value = serde_json::from_str(receipt_json)?;
    let event_id = receipt
        .get("provenance_event_id")
        .and_then(serde_json::Value::as_str);
    let event_hash = receipt
        .get("provenance_event_hash")
        .and_then(serde_json::Value::as_str);
    if receipt.as_object().map(serde_json::Map::len) != Some(4)
        || receipt.get("version").and_then(serde_json::Value::as_u64) != Some(1)
        || receipt.get("kind").and_then(serde_json::Value::as_str)
            != Some("pre-destination-no-effect")
        || finished_at.is_none()
    {
        return Err(TaskManagerError::InvalidRecord(
            "stored Artifact export reconciliation is invalid",
        ));
    }
    let Some((event_json, stored_hash, sequence, previous_hash)) = event_id
        .zip(event_hash)
        .and_then(|(event_id, _)| {
            connection
                .query_row(
                    "SELECT event_json,event_hash,sequence,previous_event_hash
                     FROM provenance_events WHERE task_id=?1 AND event_id=?2
                       AND event_type='execution.completed'",
                    params![intent.task_id, event_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, Option<String>>(3)?,
                        ))
                    },
                )
                .optional()
                .transpose()
        })
        .transpose()?
    else {
        return Err(TaskManagerError::InvalidRecord(
            "stored Artifact export reconciliation is invalid",
        ));
    };
    let event: serde_json::Value = serde_json::from_str(&event_json)?;
    if Some(stored_hash.as_str()) != event_hash
        || event.get("timestamp").and_then(serde_json::Value::as_str) != finished_at
        || event
            .pointer("/actor/id")
            .and_then(serde_json::Value::as_str)
            != Some("service:artifact-store")
        || event
            .pointer("/details/operation_id")
            .and_then(serde_json::Value::as_str)
            != Some(operation_id)
        || event
            .pointer("/details/outcome_certainty")
            .and_then(serde_json::Value::as_str)
            != Some("FAILED_NO_EFFECT")
        || event
            .pointer("/details/effect_boundary")
            .and_then(serde_json::Value::as_str)
            != Some("destination-not-invoked")
        || u64::try_from(sequence).map_or(true, |sequence| {
            provenance_hash(&intent.task_id, sequence, previous_hash.as_deref(), &event)
                .map_or(true, |computed| computed != stored_hash)
        })
        || !super::verify_provenance_through(connection, &intent.task_id, None)?
    {
        return Err(TaskManagerError::InvalidRecord(
            "stored Artifact export reconciliation is invalid",
        ));
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "replay checks the challenge, full provenance, evidence fields, inventory, and resolved assessment as one authentication boundary"
)]
fn authenticate_reconciled_export_no_effect(
    connection: &Connection,
    operation_id: &str,
    intent: &ArtifactExportIntent,
) -> Result<()> {
    let challenged = connection
        .query_row(
            "SELECT recovery_assessment_id,subject_hash,challenge
             FROM artifact_export_reconciliation_challenges WHERE operation_id=?1",
            [operation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    // Every reachable export failure after durable admission crossed an
    // external-effect-capable callback boundary. Mutable operation columns can never establish
    // no-effect certainty without the challenge-bound immutable reconciliation evidence.
    let Some((recovery_ref, stored_subject_hash, challenge)) = challenged else {
        return Err(TaskManagerError::InvalidRecord(
            "stored Artifact export reconciliation is invalid",
        ));
    };
    let subject = ArtifactExportReconciliationSubject::from_intent(operation_id, intent);
    let mut subject_hasher = Sha256::new();
    subject_hasher.update(b"AIOS-ARTIFACT-EXPORT-RECONCILIATION-SUBJECT\0v1\0");
    subject_hasher.update(canonical_json(&subject)?.as_bytes());
    let subject_hash = tagged_digest(subject_hasher);
    if stored_subject_hash != subject_hash
        || !super::verify_provenance_through(connection, &intent.task_id, None)?
    {
        return Err(TaskManagerError::InvalidRecord(
            "stored Artifact export reconciliation is invalid",
        ));
    }
    let event_jsons = {
        let mut statement = connection.prepare(
            "SELECT event_json FROM provenance_events
             WHERE task_id=?1 AND event_type='execution.completed'
               AND json_extract(event_json,'$.details.operation_id')=?2
               AND json_extract(event_json,'$.details.export_reconciliation.challenge')=?3",
        )?;
        let rows = statement
            .query_map(params![intent.task_id, operation_id, challenge], |row| {
                row.get::<_, String>(0)
            })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()?
    };
    if event_jsons.len() != 1 {
        return Err(TaskManagerError::InvalidRecord(
            "stored Artifact export reconciliation is invalid",
        ));
    }
    let event: serde_json::Value = serde_json::from_str(&event_jsons[0])?;
    let evidence_ref = event
        .pointer("/details/export_reconciliation/evidence_ref")
        .and_then(serde_json::Value::as_str);
    let verifier_id = event
        .pointer("/details/export_reconciliation/verifier_id")
        .and_then(serde_json::Value::as_str);
    let proof_hash = event
        .pointer("/details/export_reconciliation/proof_hash")
        .and_then(serde_json::Value::as_str);
    let observed_at = event
        .pointer("/details/export_reconciliation/observed_at")
        .and_then(serde_json::Value::as_str);
    if event
        .pointer("/actor/kind")
        .and_then(serde_json::Value::as_str)
        != Some("system-service")
        || event
            .pointer("/actor/id")
            .and_then(serde_json::Value::as_str)
            != Some("service:recovery")
        || event.get("status").and_then(serde_json::Value::as_str) != Some("failure")
        || event
            .pointer("/details/certainty")
            .and_then(serde_json::Value::as_str)
            != Some("FAILED_NO_EFFECT")
        || event
            .pointer("/details/export_reconciliation/subject_hash")
            .and_then(serde_json::Value::as_str)
            != Some(subject_hash.as_str())
        || event
            .pointer("/details/export_reconciliation/recovery_ref")
            .and_then(serde_json::Value::as_str)
            != Some(recovery_ref.as_str())
        || verifier_id.is_none()
        || evidence_ref.is_none()
        || proof_hash.is_none()
        || observed_at.is_none()
    {
        return Err(TaskManagerError::InvalidRecord(
            "stored Artifact export reconciliation is invalid",
        ));
    }
    validate_id(
        verifier_id.unwrap_or_default(),
        256,
        "invalid Artifact export reconciliation verifier",
    )?;
    validate_id(
        evidence_ref.unwrap_or_default(),
        256,
        "invalid Artifact export reconciliation evidence reference",
    )?;
    validate_hash(proof_hash.unwrap_or_default())?;
    parse_time(observed_at.unwrap_or_default())?;
    let assessed = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM recovery_assessments subject
             JOIN recovery_assessments aggregate
               ON aggregate.assessment_id=?1
              AND aggregate.recovery_epoch_id=subject.recovery_epoch_id
              AND aggregate.task_id=subject.task_id
             JOIN recovery_unknown_operations inventory
               ON inventory.assessment_id=aggregate.assessment_id
              AND inventory.operation_id=?3
             WHERE subject.task_id=?2 AND subject.subject_kind='external-operation'
               AND subject.subject_id=?3 AND subject.certainty='FAILED_NO_EFFECT'
               AND subject.safe_action='MARK_ATTEMPT_FAILED'
               AND json_extract(subject.assessment_json,'$.external_reconciliation_required')=0
         )",
        params![
            recovery_ref,
            intent.task_id,
            format!("operation:{operation_id}")
        ],
        |row| row.get::<_, bool>(0),
    )?;
    if !assessed {
        return Err(TaskManagerError::InvalidRecord(
            "stored Artifact export reconciliation is invalid",
        ));
    }
    Ok(())
}

fn physical_blob_refs(store: &Dir) -> Result<Vec<String>> {
    let mut paths = Vec::new();
    for first in store.read_dir("blobs/sha256")? {
        let first = first?;
        if !first.file_type()?.is_dir() {
            continue;
        }
        let Some(first_name) = first.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        if first_name.len() != 2 {
            continue;
        }
        for second in store.read_dir(format!("blobs/sha256/{first_name}"))? {
            let second = second?;
            if !second.file_type()?.is_dir() {
                continue;
            }
            let Some(second_name) = second.file_name().to_str().map(ToOwned::to_owned) else {
                continue;
            };
            if second_name.len() != 2 {
                continue;
            }
            for blob in store.read_dir(format!("blobs/sha256/{first_name}/{second_name}"))? {
                let blob = blob?;
                if blob.file_type()?.is_file() {
                    let Some(blob_name) = blob.file_name().to_str().map(ToOwned::to_owned) else {
                        continue;
                    };
                    paths.push(format!(
                        "blobs/sha256/{first_name}/{second_name}/{blob_name}"
                    ));
                }
            }
        }
    }
    paths.sort();
    Ok(paths)
}

fn content_hash_from_blob_ref(reference: &str) -> Result<String> {
    let parts = reference.split('/').collect::<Vec<_>>();
    let digest = parts.get(4).copied().unwrap_or_default();
    if parts.len() != 5
        || parts[0] != "blobs"
        || parts[1] != "sha256"
        || parts[2].len() != 2
        || parts[3].len() != 2
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        || parts[2] != &digest[..2]
        || parts[3] != &digest[2..4]
    {
        return Err(TaskManagerError::InvalidRecord(
            "Artifact blob path does not encode a canonical content hash",
        ));
    }
    Ok(format!("sha256:{digest}"))
}

fn quarantine_orphan_blob_path(store: &Dir, reference: &str, actual_hash: &str) -> Result<()> {
    let digest = actual_hash
        .strip_prefix("sha256:")
        .ok_or(TaskManagerError::InvalidRecord(
            "Artifact content hash is invalid",
        ))?;
    let target = format!(
        "quarantine/orphan-path-hash-{}-{}",
        digest,
        placement_token(reference)
    );
    store.rename(
        safe_internal_ref(reference)?,
        store,
        safe_internal_ref(&target)?,
    )?;
    if let Some(parent) = Path::new(reference).parent().and_then(Path::to_str) {
        sync_cap_directory(store, parent)?;
    }
    sync_cap_directory(store, "quarantine")?;
    Ok(())
}

fn reconcile_pending_blob_placements(store: &Dir) -> Result<Vec<Option<String>>> {
    let mut invalid = Vec::new();
    let pending = store
        .read_dir("blobs/pending")?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for entry in pending {
        if !entry.file_type()?.is_file() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        let digest = name.split('-').next().unwrap_or_default();
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            remove_pending_blob_durably(store, &format!("blobs/pending/{name}"))?;
            invalid.push(None);
            continue;
        }
        let pending_ref = format!("blobs/pending/{name}");
        let expected = format!("sha256:{digest}");
        let (_, actual) = hash_internal_file(store, &pending_ref)?;
        if actual != expected {
            remove_pending_blob_durably(store, &pending_ref)?;
            invalid.push(Some(expected));
            continue;
        }
        let parent_ref = format!("blobs/sha256/{}/{}", &digest[0..2], &digest[2..4]);
        let final_ref = format!("{parent_ref}/{digest}");
        create_durable_ancestors(store, &parent_ref)?;
        recovery_pending_placement_step(store, &pending_ref)?;
        match store.hard_link(
            safe_internal_ref(&pending_ref)?,
            store,
            safe_internal_ref(&final_ref)?,
        ) {
            Ok(()) => {
                let (_, final_hash) = hash_internal_file(store, &final_ref)?;
                if final_hash != expected {
                    let _ = store.remove_file(safe_internal_ref(&final_ref)?);
                    return Err(TaskManagerError::InvalidRecord("ARTIFACT_HASH_MISMATCH"));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let (_, final_hash) = hash_internal_file(store, &final_ref)?;
                if final_hash != expected {
                    quarantine_replaced_blob(store, &final_ref, digest, &pending_ref)?;
                    store.hard_link(
                        safe_internal_ref(&pending_ref)?,
                        store,
                        safe_internal_ref(&final_ref)?,
                    )?;
                    let (_, restored_hash) = hash_internal_file(store, &final_ref)?;
                    if restored_hash != expected {
                        return Err(TaskManagerError::InvalidRecord("ARTIFACT_HASH_MISMATCH"));
                    }
                }
            }
            Err(error) => return Err(error.into()),
        }
        durability_step("sync-recovered-blob-parent")?;
        sync_cap_directory(store, &parent_ref)?;
        durability_step("unlink-recovered-blob-pending")?;
        store.remove_file(safe_internal_ref(&pending_ref)?)?;
        durability_step("sync-recovered-blob-pending")?;
        sync_cap_directory(store, "blobs/pending")?;
    }
    // A prior process may have unlinked an invalid entry and failed before syncing the
    // directory. Repeat this sync even when enumeration is now empty.
    durability_step("sync-invalid-blob-pending")?;
    sync_cap_directory(store, "blobs/pending")?;
    Ok(invalid)
}

fn remove_pending_blob_durably(store: &Dir, pending_ref: &str) -> Result<()> {
    match store.remove_file(safe_internal_ref(pending_ref)?) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    durability_step("sync-invalid-blob-pending")?;
    sync_cap_directory(store, "blobs/pending")
}

fn quarantine_replaced_blob(
    store: &Dir,
    final_ref: &str,
    digest: &str,
    pending_ref: &str,
) -> Result<()> {
    let target = format!(
        "quarantine/replaced-corrupt-blob-{digest}-{}",
        placement_token(pending_ref)
    );
    store.rename(
        safe_internal_ref(final_ref)?,
        store,
        safe_internal_ref(&target)?,
    )?;
    if let Some(parent) = Path::new(final_ref).parent().and_then(Path::to_str) {
        sync_cap_directory(store, parent)?;
    }
    sync_cap_directory(store, "quarantine")?;
    Ok(())
}

#[cfg(test)]
fn resolve_internal_ref(root: &Path, reference: &str) -> Result<PathBuf> {
    Ok(root.join(safe_internal_ref(reference)?))
}

fn safe_internal_ref(reference: &str) -> Result<PathBuf> {
    if reference.is_empty() || reference.contains('\\') {
        return Err(TaskManagerError::InvalidRecord(
            "Artifact storage reference is invalid",
        ));
    }
    let relative = Path::new(reference);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(TaskManagerError::InvalidRecord(
            "Artifact storage reference escaped store root",
        ));
    }
    Ok(relative.to_path_buf())
}

fn internal_ref_exists(store: &Dir, reference: &str) -> Result<bool> {
    match store.metadata(safe_internal_ref(reference)?) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn ensure_writer_unsealed(store: &Dir, seal_reference: &str) -> Result<()> {
    if internal_ref_exists(store, seal_reference)?
        || internal_ref_exists(store, &format!("{seal_reference}.pending"))?
    {
        return Err(TaskManagerError::InvalidRecord(
            "ARTIFACT_ALLOCATION_STATE_CONFLICT",
        ));
    }
    Ok(())
}

fn seal_ref(staging_ref: &str) -> String {
    format!("{staging_ref}.sealed")
}

#[derive(Debug)]
enum StagingSealEvidence {
    Absent,
    Truncated,
    Complete(SealedStaging),
}

fn read_staging_seal_evidence(store: &Dir, reference: &str) -> Result<StagingSealEvidence> {
    let file = match store.open(safe_internal_ref(reference)?) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(StagingSealEvidence::Absent);
        }
        Err(error) => return Err(error.into()),
    };
    let mut bytes = Vec::new();
    file.take(16 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 16 * 1024 {
        return Err(TaskManagerError::InvalidRecord("ARTIFACT_HASH_MISMATCH"));
    }
    let value = match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(value) => value,
        Err(error) if error.is_eof() => return Ok(StagingSealEvidence::Truncated),
        Err(_) => return Err(TaskManagerError::InvalidRecord("ARTIFACT_HASH_MISMATCH")),
    };
    let sealed = serde_json::from_value::<SealedStaging>(value)
        .map_err(|_| TaskManagerError::InvalidRecord("ARTIFACT_HASH_MISMATCH"))?;
    Ok(StagingSealEvidence::Complete(sealed))
}

fn validate_staging_seal(
    sealed: &SealedStaging,
    allocation_id: &str,
    size_bytes: u64,
    content_hash: &str,
) -> Result<()> {
    if sealed.version != SEALED_STAGING_VERSION
        || sealed.allocation_id != allocation_id
        || sealed.size_bytes != size_bytes
        || sealed.content_hash != content_hash
    {
        Err(TaskManagerError::InvalidRecord("ARTIFACT_HASH_MISMATCH"))
    } else {
        Ok(())
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the resolver authenticates both durable seal names against one exact staging fact"
)]
fn resolve_staging_seal_evidence(
    store: &Dir,
    allocation_id: &str,
    seal_reference: &str,
    pending: &StagingSealEvidence,
    final_seal: &StagingSealEvidence,
    size_bytes: u64,
    content_hash: &str,
    reconstruct_when_absent: bool,
) -> Result<()> {
    let pending_reference = format!("{seal_reference}.pending");
    if let StagingSealEvidence::Complete(sealed) = pending {
        validate_staging_seal(sealed, allocation_id, size_bytes, content_hash)?;
    }
    if let StagingSealEvidence::Complete(sealed) = final_seal {
        validate_staging_seal(sealed, allocation_id, size_bytes, content_hash)?;
    }

    if matches!(pending, StagingSealEvidence::Complete(_)) {
        match final_seal {
            StagingSealEvidence::Complete(_) => {
                store.remove_file(safe_internal_ref(&pending_reference)?)?;
                return sync_completed_staging_seal_directory(store);
            }
            StagingSealEvidence::Truncated => {
                store.remove_file(safe_internal_ref(seal_reference)?)?;
                sync_cap_directory(store, "staging")?;
            }
            StagingSealEvidence::Absent => {}
        }
        store.rename(
            safe_internal_ref(&pending_reference)?,
            store,
            safe_internal_ref(seal_reference)?,
        )?;
        return sync_completed_staging_seal_directory(store);
    }

    if matches!(final_seal, StagingSealEvidence::Complete(_)) {
        if matches!(pending, StagingSealEvidence::Truncated) {
            store.remove_file(safe_internal_ref(&pending_reference)?)?;
        }
        return sync_completed_staging_seal_directory(store);
    }

    let has_incomplete_evidence = matches!(pending, StagingSealEvidence::Truncated)
        || matches!(final_seal, StagingSealEvidence::Truncated);
    if !has_incomplete_evidence && !reconstruct_when_absent {
        return Ok(());
    }
    for (reference, evidence) in [
        (pending_reference.as_str(), pending),
        (seal_reference, final_seal),
    ] {
        if matches!(evidence, StagingSealEvidence::Truncated) {
            store.remove_file(safe_internal_ref(reference)?)?;
        }
    }
    if has_incomplete_evidence {
        sync_cap_directory(store, "staging")?;
    }
    let sealed = SealedStaging {
        version: SEALED_STAGING_VERSION,
        allocation_id: allocation_id.to_owned(),
        size_bytes,
        content_hash: content_hash.to_owned(),
    };
    write_staging_seal_atomically(store, seal_reference, &serde_json::to_vec(&sealed)?)
}

fn write_staging_seal_atomically(store: &Dir, seal_reference: &str, bytes: &[u8]) -> Result<()> {
    let temporary = format!("{seal_reference}.pending");
    let mut seal = store.open_with(
        safe_internal_ref(&temporary)?,
        CapOpenOptions::new().write(true).create_new(true),
    )?;
    secure_cap_file_permissions(&seal)?;
    seal.write_all(bytes)?;
    seal.flush()?;
    seal.sync_all()?;
    durability_step("sync-staging-seal")?;
    sync_cap_directory(store, "staging")?;
    store.rename(
        safe_internal_ref(&temporary)?,
        store,
        safe_internal_ref(seal_reference)?,
    )?;
    sync_completed_staging_seal_directory(store)
}

fn sync_completed_staging_seal_directory(store: &Dir) -> Result<()> {
    durability_step("sync-staging-seal-final")?;
    sync_cap_directory(store, "staging")
}

fn reconcile_interrupted_staging_seal(
    store: &Dir,
    allocation_id: &str,
    staging_ref: &str,
) -> Result<()> {
    let seal_reference = seal_ref(staging_ref);
    let pending_reference = format!("{seal_reference}.pending");
    let pending = read_staging_seal_evidence(store, &pending_reference)?;
    let final_seal = read_staging_seal_evidence(store, &seal_reference)?;
    if matches!(&pending, StagingSealEvidence::Absent)
        && matches!(&final_seal, StagingSealEvidence::Absent)
    {
        return Ok(());
    }
    let (size_bytes, content_hash) = hash_internal_file(store, staging_ref)?;
    resolve_staging_seal_evidence(
        store,
        allocation_id,
        &seal_reference,
        &pending,
        &final_seal,
        size_bytes,
        &content_hash,
        false,
    )
}

fn random_token(connection: &Connection) -> Result<String> {
    connection
        .query_row("SELECT lower(hex(randomblob(16)))", [], |row| {
            row.get::<_, String>(0)
        })
        .map_err(Into::into)
}

fn artifact_id(kind: &str, nonce: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"AIOS-ARTIFACT-ID\0v1\0");
    hasher.update(kind.as_bytes());
    hasher.update([0]);
    hasher.update(nonce.as_bytes());
    format!("artifact:v1:{}", tagged_digest(hasher))
}

fn event_id(kind: &str, identity: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"AIOS-ARTIFACT-EVENT-ID\0v1\0");
    hasher.update(kind.as_bytes());
    hasher.update([0]);
    hasher.update(identity.as_bytes());
    format!("event:{kind}:v1:{}", tagged_digest(hasher))
}

pub(crate) fn validate_id(value: &str, maximum: usize, message: &'static str) -> Result<()> {
    if value.is_empty() || value.chars().count() > maximum || value.chars().any(char::is_control) {
        Err(TaskManagerError::InvalidRecord(message))
    } else {
        Ok(())
    }
}

fn validate_hash(value: &str) -> Result<()> {
    let digest = value
        .strip_prefix("sha256:")
        .ok_or(TaskManagerError::InvalidRecord(
            "invalid canonical SHA-256 hash",
        ))?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(TaskManagerError::InvalidRecord(
            "invalid canonical SHA-256 hash",
        ));
    }
    Ok(())
}

fn validate_optional_semantic_type(value: Option<&str>) -> Result<()> {
    let valid = value.is_none_or(|value| {
        if value.is_empty() {
            return true;
        }
        let Some((name, version)) = value.split_once('@') else {
            return false;
        };
        value.chars().count() <= 256
            && !name.is_empty()
            && name
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_lowercase())
            && name.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'_' | b'.' | b'-')
            })
            && !version.is_empty()
            && version.bytes().all(|byte| byte.is_ascii_digit())
            && (version == "0" || !version.starts_with('0'))
    });
    if valid {
        Ok(())
    } else {
        Err(TaskManagerError::InvalidRecord(
            "invalid Artifact semantic type",
        ))
    }
}

fn parse_time(value: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| TaskManagerError::InvalidRecord("Artifact timestamp is not RFC 3339"))
}

fn to_i64(value: u64) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| TaskManagerError::InvalidRecord("Artifact size exceeds SQLite range"))
}

fn all_unique(values: &[String]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn create_durable_ancestors(store: &Dir, reference: &str) -> Result<()> {
    let relative = safe_internal_ref(reference)?;
    let mut current = PathBuf::new();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(TaskManagerError::InvalidRecord(
                "Artifact storage reference is invalid",
            ));
        };
        let parent = current.clone();
        current.push(component);
        let current_ref = current
            .to_str()
            .ok_or(TaskManagerError::InvalidRecord(
                "Artifact directory reference is not UTF-8",
            ))?
            .replace('\\', "/");
        durability_step(&format!("create:{current_ref}"))?;
        match store.create_dir(&current) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        secure_cap_directory_permissions(store, &current)?;
        // Repeat the child and parent syncs when the directory already exists:
        // it may be residue from an earlier attempt that failed between them.
        durability_step(&format!("sync:{current_ref}"))?;
        sync_cap_directory(store, &current_ref)?;
        let parent_ref = parent
            .to_str()
            .ok_or(TaskManagerError::InvalidRecord(
                "Artifact directory reference is not UTF-8",
            ))?
            .replace('\\', "/");
        durability_step(&format!(
            "sync-parent:{}",
            if parent_ref.is_empty() {
                "."
            } else {
                &parent_ref
            }
        ))?;
        if parent_ref.is_empty() {
            sync_store_root(store)?;
        } else {
            sync_cap_directory(store, &parent_ref)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn secure_cap_directory_permissions(store: &Dir, path: &Path) -> Result<()> {
    use cap_std::fs::PermissionsExt as _;

    store.set_permissions(path, cap_std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "matches the fallible Unix permission hardening interface"
)]
fn secure_cap_directory_permissions(_store: &Dir, _path: &Path) -> Result<()> {
    Ok(())
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "directory synchronization is fallible on supported durable filesystems and a portability no-op elsewhere"
)]
fn sync_store_root(store: &Dir) -> Result<()> {
    #[cfg(unix)]
    store.open(".")?.into_std().sync_all()?;
    #[cfg(windows)]
    sync_windows_directory(store, ".")?;
    #[cfg(not(any(unix, windows)))]
    let _ = store;
    Ok(())
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "directory synchronization is fallible on Unix and a portability no-op elsewhere"
)]
fn sync_host_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;

        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)?
            .sync_all()?;
    }
    #[cfg(not(any(unix, windows)))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
thread_local! {
    static DURABILITY_TEST_CONTROL: std::cell::RefCell<Option<(Vec<String>, Option<String>)>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn durability_step(operation: &str) -> Result<()> {
    DURABILITY_TEST_CONTROL.with(|control| {
        let mut control = control.borrow_mut();
        if let Some((operations, failure)) = control.as_mut() {
            operations.push(operation.to_owned());
            if failure.as_deref() == Some(operation) {
                return Err(TaskManagerError::Io(std::io::Error::other(
                    "injected directory durability failure",
                )));
            }
        }
        Ok(())
    })
}

#[cfg(not(test))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "test fault injection shares the production call signature"
)]
fn durability_step(_operation: &str) -> Result<()> {
    Ok(())
}

#[cfg(test)]
type PendingPlacementTestHook = Box<dyn FnOnce(&Dir, &str) -> Result<()>>;

#[cfg(test)]
thread_local! {
    static PENDING_PLACEMENT_TEST_HOOK: std::cell::RefCell<Option<PendingPlacementTestHook>> =
        const { std::cell::RefCell::new(None) };
    static RECOVERY_PENDING_PLACEMENT_TEST_HOOK: std::cell::RefCell<Option<PendingPlacementTestHook>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn pending_placement_step(store: &Dir, pending_ref: &str) -> Result<()> {
    PENDING_PLACEMENT_TEST_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook(store, pending_ref)?;
        }
        Ok(())
    })
}

#[cfg(not(test))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "test path replacement injection shares the production call signature"
)]
fn pending_placement_step(_store: &Dir, _pending_ref: &str) -> Result<()> {
    Ok(())
}

#[cfg(test)]
fn recovery_pending_placement_step(store: &Dir, pending_ref: &str) -> Result<()> {
    RECOVERY_PENDING_PLACEMENT_TEST_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook(store, pending_ref)?;
        }
        Ok(())
    })
}

#[cfg(not(test))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "recovery path replacement injection shares the production call signature"
)]
fn recovery_pending_placement_step(_store: &Dir, _pending_ref: &str) -> Result<()> {
    Ok(())
}

#[cfg(test)]
type ReaderSetupTestHook = Box<dyn FnOnce() -> Result<()>>;

#[cfg(test)]
thread_local! {
    static READER_HASH_TEST_HOOK: std::cell::RefCell<Option<ReaderSetupTestHook>> =
        const { std::cell::RefCell::new(None) };
    static READER_SETUP_TEST_HOOK: std::cell::RefCell<Option<ReaderSetupTestHook>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn reader_hash_step() -> Result<()> {
    READER_HASH_TEST_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook()?;
        }
        Ok(())
    })
}

#[cfg(not(test))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "reader hash failure injection shares the production call signature"
)]
fn reader_hash_step() -> Result<()> {
    Ok(())
}

#[cfg(test)]
fn reader_setup_step() -> Result<()> {
    READER_SETUP_TEST_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook()?;
        }
        Ok(())
    })
}

#[cfg(not(test))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "reader setup failure injection shares the production call signature"
)]
fn reader_setup_step() -> Result<()> {
    Ok(())
}

#[cfg(test)]
type ExportCompletionTestHook = Box<dyn FnOnce() -> Result<()>>;

#[cfg(test)]
thread_local! {
    static IMPORT_COMMIT_TEST_HOOK: std::cell::RefCell<Option<ExportCompletionTestHook>> =
        const { std::cell::RefCell::new(None) };
    static IMPORT_COMMIT_RESULT_TEST_HOOK: std::cell::RefCell<Option<ExportCompletionTestHook>> =
        const { std::cell::RefCell::new(None) };
    static ALLOCATION_COMMIT_TEST_HOOK: std::cell::RefCell<Option<ExportCompletionTestHook>> =
        const { std::cell::RefCell::new(None) };
    static PUBLICATION_RESERVATION_TEST_HOOK: std::cell::RefCell<Option<ExportCompletionTestHook>> =
        const { std::cell::RefCell::new(None) };
    static PUBLICATION_COMMIT_TEST_HOOK: std::cell::RefCell<Option<ExportCompletionTestHook>> =
        const { std::cell::RefCell::new(None) };
    static WRITER_FINISH_TEST_HOOK: std::cell::RefCell<Option<ExportCompletionTestHook>> =
        const { std::cell::RefCell::new(None) };
    static WRITER_WRITE_COMMIT_RESULT_TEST_HOOK: std::cell::RefCell<Option<ExportCompletionTestHook>> =
        const { std::cell::RefCell::new(None) };
    static READER_ADMISSION_COMMIT_RESULT_TEST_HOOK: std::cell::RefCell<Option<ExportCompletionTestHook>> =
        const { std::cell::RefCell::new(None) };
    static WRITER_ADMISSION_COMMIT_RESULT_TEST_HOOK: std::cell::RefCell<Option<ExportCompletionTestHook>> =
        const { std::cell::RefCell::new(None) };
    static EXPORT_ADMISSION_COMMIT_RESULT_TEST_HOOK: std::cell::RefCell<Option<ExportCompletionTestHook>> =
        const { std::cell::RefCell::new(None) };
    static EXPORT_BEFORE_ARM_TEST_HOOK: std::cell::RefCell<Option<ExportCompletionTestHook>> =
        const { std::cell::RefCell::new(None) };
    static EXPORT_RESERVATION_RACE_TEST_HOOK: std::cell::RefCell<Option<ExportCompletionTestHook>> =
        const { std::cell::RefCell::new(None) };
    static EXPORT_COPY_TEST_HOOK: std::cell::RefCell<Option<ExportCompletionTestHook>> =
        const { std::cell::RefCell::new(None) };
    static EXPORT_PRE_FINALIZE_TEST_HOOK: std::cell::RefCell<Option<ExportCompletionTestHook>> =
        const { std::cell::RefCell::new(None) };
    static EXPORT_COMPLETION_TEST_HOOK: std::cell::RefCell<Option<ExportCompletionTestHook>> =
        const { std::cell::RefCell::new(None) };
    static PUBLICATION_REPLAY_HASH_TEST_HOOK: std::cell::RefCell<Option<ExportCompletionTestHook>> =
        const { std::cell::RefCell::new(None) };
    static LIVE_RECOVERY_HANDOFF_TEST_HOOK: std::cell::RefCell<Option<ExportCompletionTestHook>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn import_commit_step() -> Result<()> {
    IMPORT_COMMIT_TEST_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook()?;
        }
        Ok(())
    })
}

#[cfg(test)]
fn import_commit_result_step() -> Result<()> {
    IMPORT_COMMIT_RESULT_TEST_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook()?;
        }
        Ok(())
    })
}

#[cfg(test)]
fn allocation_commit_step() -> Result<()> {
    ALLOCATION_COMMIT_TEST_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook()?;
        }
        Ok(())
    })
}

#[cfg(test)]
fn publication_reservation_step() -> Result<()> {
    PUBLICATION_RESERVATION_TEST_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook()?;
        }
        Ok(())
    })
}

#[cfg(test)]
fn publication_commit_step() -> Result<()> {
    PUBLICATION_COMMIT_TEST_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook()?;
        }
        Ok(())
    })
}

#[cfg(test)]
fn writer_finish_step() -> Result<()> {
    WRITER_FINISH_TEST_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook()?;
        }
        Ok(())
    })
}

#[cfg(test)]
fn writer_write_commit_result_step() -> Result<()> {
    WRITER_WRITE_COMMIT_RESULT_TEST_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook()?;
        }
        Ok(())
    })
}

#[cfg(test)]
fn reader_admission_commit_result_step() -> Result<()> {
    READER_ADMISSION_COMMIT_RESULT_TEST_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook()?;
        }
        Ok(())
    })
}

#[cfg(test)]
fn writer_admission_commit_result_step() -> Result<()> {
    WRITER_ADMISSION_COMMIT_RESULT_TEST_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook()?;
        }
        Ok(())
    })
}

#[cfg(test)]
fn export_admission_commit_result_step() -> Result<()> {
    EXPORT_ADMISSION_COMMIT_RESULT_TEST_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook()?;
        }
        Ok(())
    })
}

#[cfg(test)]
fn export_before_arm_step() -> Result<()> {
    EXPORT_BEFORE_ARM_TEST_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook()?;
        }
        Ok(())
    })
}

#[cfg(test)]
fn export_reservation_race_step() -> Result<()> {
    EXPORT_RESERVATION_RACE_TEST_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook()?;
        }
        Ok(())
    })
}

#[cfg(not(test))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "test import race injection shares the production commit boundary"
)]
fn import_commit_step() -> Result<()> {
    Ok(())
}

#[cfg(not(test))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "test import response-loss injection shares the production commit result boundary"
)]
fn import_commit_result_step() -> Result<()> {
    Ok(())
}

#[cfg(not(test))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "test allocation race injection shares the production commit boundary"
)]
fn allocation_commit_step() -> Result<()> {
    Ok(())
}

#[cfg(not(test))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "test publication race injection shares the production reservation boundary"
)]
fn publication_reservation_step() -> Result<()> {
    Ok(())
}

#[cfg(not(test))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "test publication race injection shares the production commit boundary"
)]
fn publication_commit_step() -> Result<()> {
    Ok(())
}

#[cfg(not(test))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "test writer race injection shares the production post-hash boundary"
)]
fn writer_finish_step() -> Result<()> {
    Ok(())
}

#[cfg(not(test))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "test response-loss injection shares the staging write commit-result boundary"
)]
fn writer_write_commit_result_step() -> Result<()> {
    Ok(())
}

#[cfg(not(test))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "test response-loss injection shares the reader admission commit-result boundary"
)]
fn reader_admission_commit_result_step() -> Result<()> {
    Ok(())
}

#[cfg(not(test))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "test response-loss injection shares the production writer admission commit boundary"
)]
fn writer_admission_commit_result_step() -> Result<()> {
    Ok(())
}

#[cfg(not(test))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "test response-loss injection shares the production export admission commit boundary"
)]
fn export_admission_commit_result_step() -> Result<()> {
    Ok(())
}

#[cfg(not(test))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "test race injection shares the production export arming boundary"
)]
fn export_before_arm_step() -> Result<()> {
    Ok(())
}

#[cfg(test)]
fn export_copy_step() -> Result<()> {
    EXPORT_COPY_TEST_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook()?;
        }
        Ok(())
    })
}

#[cfg(test)]
fn export_completion_step() -> Result<()> {
    EXPORT_COMPLETION_TEST_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook()?;
        }
        Ok(())
    })
}

#[cfg(test)]
fn export_pre_finalize_step() -> Result<()> {
    EXPORT_PRE_FINALIZE_TEST_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook()?;
        }
        Ok(())
    })
}

#[cfg(test)]
fn publication_replay_hash_step() -> Result<()> {
    PUBLICATION_REPLAY_HASH_TEST_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook()?;
        }
        Ok(())
    })
}

#[cfg(test)]
fn live_recovery_handoff_step() -> Result<()> {
    LIVE_RECOVERY_HANDOFF_TEST_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook()?;
        }
        Ok(())
    })
}

#[cfg(not(test))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "test race injection shares the production reservation boundary"
)]
fn export_reservation_race_step() -> Result<()> {
    Ok(())
}

#[cfg(not(test))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "test failure injection shares the production copy boundary"
)]
fn export_copy_step() -> Result<()> {
    Ok(())
}

#[cfg(not(test))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "test crash injection shares the production completion boundary"
)]
fn export_completion_step() -> Result<()> {
    Ok(())
}

#[cfg(not(test))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "test authority race injection shares the production pre-finalize boundary"
)]
fn export_pre_finalize_step() -> Result<()> {
    Ok(())
}

#[cfg(not(test))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "test transient I/O injection shares the publication replay hash boundary"
)]
fn publication_replay_hash_step() -> Result<()> {
    Ok(())
}

#[cfg(not(test))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "test failure injection shares the live recovery handoff boundary"
)]
fn live_recovery_handoff_step() -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_cap_directory(store: &Dir, reference: &str) -> Result<()> {
    store
        .open(safe_internal_ref(reference)?)?
        .into_std()
        .sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "keeps the platform-specific durability helper signature uniform"
)]
fn sync_cap_directory(store: &Dir, reference: &str) -> Result<()> {
    #[cfg(windows)]
    sync_windows_directory(store, reference)?;
    #[cfg(not(windows))]
    let _ = (store, reference);
    Ok(())
}

#[cfg(windows)]
fn sync_windows_directory(store: &Dir, reference: &str) -> Result<()> {
    use cap_std::fs::OpenOptionsExt as _;

    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    let mut options = CapOpenOptions::new();
    options
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    store
        .open_with(reference, &options)?
        .into_std()
        .sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read as _, Write as _};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier, Mutex};

    use tempfile::TempDir;

    use super::*;
    use crate::{Actor, Clock, CreateTask};

    struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> String {
            "2026-09-19T22:00:00Z".to_owned()
        }
    }

    struct MutableClock {
        now: Arc<Mutex<String>>,
    }

    impl Clock for MutableClock {
        fn now(&self) -> String {
            self.now.lock().unwrap().clone()
        }
    }

    fn deferred<W: ArtifactExportWriter + 'static>(
        writer: W,
    ) -> impl FnOnce() -> std::io::Result<W> {
        move || Ok(writer)
    }

    #[derive(Default)]
    struct PrefixThenErrorWriter {
        bytes: Vec<u8>,
        accepted_prefix: bool,
    }

    impl Write for PrefixThenErrorWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.accepted_prefix {
                return Err(std::io::Error::other("injected partial export failure"));
            }
            let accepted = bytes.len().min(3);
            self.bytes.extend_from_slice(&bytes[..accepted]);
            self.accepted_prefix = true;
            Ok(accepted)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl ArtifactExportWriter for PrefixThenErrorWriter {
        fn finalize(&mut self) -> std::io::Result<()> {
            self.flush()
        }
    }

    #[derive(Default)]
    struct FlushFailureWriter {
        bytes: Vec<u8>,
    }

    impl Write for FlushFailureWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("injected export flush failure"))
        }
    }

    impl ArtifactExportWriter for FlushFailureWriter {
        fn finalize(&mut self) -> std::io::Result<()> {
            self.flush()
        }
    }

    struct AuthorityRevokingWriter {
        database: PathBuf,
        flushed: bool,
    }

    impl Write for AuthorityRevokingWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            let connection = Connection::open(&self.database)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            connection
                .execute(
                    "UPDATE tasks SET principal_id='user:revoked-after-flush' WHERE task_id='T-artifact'",
                    [],
                )
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            self.flushed = true;
            Ok(())
        }
    }

    impl ArtifactExportWriter for AuthorityRevokingWriter {
        fn finalize(&mut self) -> std::io::Result<()> {
            self.flush()
        }
    }

    #[derive(Default)]
    struct FinalizeFailureWriter {
        bytes: Vec<u8>,
    }

    impl Write for FinalizeFailureWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl ArtifactExportWriter for FinalizeFailureWriter {
        fn finalize(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other(
                "injected destination finalization failure",
            ))
        }
    }

    struct FinalizeTrackingWriter {
        finalized: Arc<AtomicUsize>,
    }

    impl Write for FinalizeTrackingWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl ArtifactExportWriter for FinalizeTrackingWriter {
        fn finalize(&mut self) -> std::io::Result<()> {
            self.finalized.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct TestExportOutcomeVerifier {
        verifier_id: &'static str,
        destination_class: &'static str,
        evidence_ref: String,
        proof_hash: String,
        observed_at: String,
        challenge_override: Mutex<Option<String>>,
        calls: AtomicUsize,
    }

    impl ArtifactExportOutcomeVerifier for TestExportOutcomeVerifier {
        fn verifier_id(&self) -> &str {
            self.verifier_id
        }

        fn destination_class(&self) -> &str {
            self.destination_class
        }

        fn verify_no_effect(
            &self,
            subject: &ArtifactExportReconciliationSubject,
            challenge: &str,
        ) -> Result<VerifiedArtifactExportNoEffect> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(VerifiedArtifactExportNoEffect {
                subject: subject.clone(),
                challenge: self
                    .challenge_override
                    .lock()
                    .unwrap()
                    .clone()
                    .unwrap_or_else(|| challenge.to_owned()),
                evidence_ref: self.evidence_ref.clone(),
                proof_hash: self.proof_hash.clone(),
                observed_at: self.observed_at.clone(),
            })
        }
    }

    fn export_no_effect_verifier(
        destination_class: &'static str,
        evidence_ref: &str,
        proof_digit: char,
    ) -> TestExportOutcomeVerifier {
        TestExportOutcomeVerifier {
            verifier_id: "adapter:test-destination-status",
            destination_class,
            evidence_ref: evidence_ref.to_owned(),
            proof_hash: format!("sha256:{}", proof_digit.to_string().repeat(64)),
            observed_at: "2026-09-19T22:00:00Z".to_owned(),
            challenge_override: Mutex::new(None),
            calls: AtomicUsize::new(0),
        }
    }

    struct SwapClock {
        state: Arc<Mutex<SwapClockState>>,
    }

    struct SwapClockState {
        armed_calls: Option<u8>,
        blob: Option<PathBuf>,
        replacement: Vec<u8>,
        error: Option<String>,
    }

    impl Clock for SwapClock {
        fn now(&self) -> String {
            let mut state = self.state.lock().unwrap();
            if let Some(calls) = state.armed_calls.as_mut() {
                *calls -= 1;
                if *calls == 0 {
                    let blob = state.blob.clone().unwrap();
                    let displaced = blob.with_extension("verified-open-handle");
                    if let Err(error) = std::fs::rename(&blob, &displaced)
                        .and_then(|()| std::fs::write(&blob, &state.replacement))
                    {
                        state.error = Some(error.to_string());
                    }
                    state.armed_calls = None;
                }
            }
            "2026-09-19T22:00:00Z".to_owned()
        }
    }

    struct BlobRevokingClock {
        state: Arc<Mutex<BlobRevokingClockState>>,
    }

    struct BlobRevokingClockState {
        armed: bool,
        database: PathBuf,
        blob: Option<PathBuf>,
        grant_id: Option<String>,
        revoked: bool,
        error: Option<String>,
    }

    impl Clock for BlobRevokingClock {
        fn now(&self) -> String {
            let mut state = self.state.lock().unwrap();
            if state.armed && state.blob.as_ref().is_some_and(|blob| blob.exists()) {
                let result = (|| -> rusqlite::Result<()> {
                    let connection = Connection::open(&state.database)?;
                    connection.execute(
                        "UPDATE authority_grants SET state='REVOKED',revoked_at='2026-09-19T22:00:00Z' WHERE grant_id=?1",
                        [state.grant_id.as_deref().unwrap()],
                    )?;
                    Ok(())
                })();
                match result {
                    Ok(()) => state.revoked = true,
                    Err(error) => state.error = Some(error.to_string()),
                }
                state.armed = false;
            }
            "2026-09-19T22:00:00Z".to_owned()
        }
    }

    fn manager(temp: &TempDir) -> TaskManager {
        let mut manager = TaskManager::open_with_clock(
            temp.path().join("task-manager.sqlite"),
            Box::new(FixedClock),
        )
        .unwrap();
        manager
            .create_task(&CreateTask {
                task_id: "T-artifact".to_owned(),
                principal: Actor {
                    kind: "user".to_owned(),
                    id: "user:test".to_owned(),
                },
                workspace_id: None,
                original_intent: "exercise Artifact storage".to_owned(),
                normalized_intent: None,
                active_step_ids: Vec::new(),
            })
            .unwrap();
        manager
    }

    fn manager_with_mutable_clock(temp: &TempDir, now: &Arc<Mutex<String>>) -> TaskManager {
        let mut manager = TaskManager::open_with_clock(
            temp.path().join("task-manager.sqlite"),
            Box::new(MutableClock {
                now: Arc::clone(now),
            }),
        )
        .unwrap();
        manager
            .create_task(&CreateTask {
                task_id: "T-artifact".to_owned(),
                principal: Actor {
                    kind: "user".to_owned(),
                    id: "user:test".to_owned(),
                },
                workspace_id: None,
                original_intent: "exercise Artifact storage".to_owned(),
                normalized_intent: None,
                active_step_ids: Vec::new(),
            })
            .unwrap();
        manager
    }

    fn manager_with_export_verifiers(
        temp: &TempDir,
        verifiers: Vec<Arc<dyn ArtifactExportOutcomeVerifier>>,
    ) -> TaskManager {
        let mut manager = TaskManager::open_with_clock_and_export_verifiers(
            temp.path().join("task-manager.sqlite"),
            Box::new(FixedClock),
            verifiers,
        )
        .unwrap();
        manager
            .create_task(&CreateTask {
                task_id: "T-artifact".to_owned(),
                principal: Actor {
                    kind: "user".to_owned(),
                    id: "user:test".to_owned(),
                },
                workspace_id: None,
                original_intent: "exercise Artifact storage".to_owned(),
                normalized_intent: None,
                active_step_ids: Vec::new(),
            })
            .unwrap();
        manager
    }

    fn session_for_binding(
        manager: &TaskManager,
        task_id: &str,
        binding_id: &str,
    ) -> ProviderArtifactSession {
        let authority = manager
            .connection
            .query_row(
                "SELECT attempt_id,semantic_program_hash,node_id,capability,provider_id,policy_decision_refs_json,grant_refs_json FROM execution_bindings WHERE task_id=?1 AND binding_id=?2",
                params![task_id, binding_id],
                |row| {
                    Ok(ExecutionAuthority {
                        binding_id: binding_id.to_owned(),
                        attempt_id: row.get(0)?,
                        semantic_program_hash: row.get(1)?,
                        node_id: row.get(2)?,
                        capability: row.get(3)?,
                        principal_id: row.get(4)?,
                        policy_decision_refs_json: row.get(5)?,
                        grant_refs_json: row.get(6)?,
                    })
                },
            )
            .unwrap();
        ProviderArtifactSession {
            issuer_id: manager.artifact_scope_issuer.clone(),
            task_id: task_id.to_owned(),
            authority,
        }
    }

    fn session_for_allocation(
        manager: &TaskManager,
        allocation_id: &str,
    ) -> ProviderArtifactSession {
        let allocation = load_allocation_row(&manager.connection, allocation_id)
            .unwrap()
            .unwrap();
        session_for_binding(
            manager,
            &allocation.task_id,
            allocation.binding_id.as_deref().unwrap(),
        )
    }

    fn allocate_bound(
        manager: &mut TaskManager,
        request: &OutputAllocationRequest,
    ) -> ArtifactOutputAllocation {
        let session = session_for_binding(
            manager,
            &request.task_id,
            request.binding_id.as_deref().unwrap(),
        );
        manager
            .allocate_bound_artifact_output(&session, request)
            .unwrap()
    }

    fn open_bound(manager: &mut TaskManager, allocation_id: &str) -> ArtifactStagingWriter {
        let session = session_for_allocation(manager, allocation_id);
        manager
            .open_bound_artifact_output(&session, allocation_id)
            .unwrap()
    }

    fn publish_bound(
        manager: &mut TaskManager,
        request: &ArtifactPublicationRequest,
    ) -> Result<ArtifactPublicationResult> {
        let session = session_for_allocation(manager, &request.allocation_id);
        manager.publish_bound_artifact_output(&session, request)
    }

    fn scope_bound_reads(
        manager: &TaskManager,
        task_id: &str,
        binding_id: &str,
        artifact_ids: &[String],
    ) -> Result<ArtifactReadScope> {
        let session = session_for_binding(manager, task_id, binding_id);
        manager.scope_artifact_reads(&session, artifact_ids)
    }

    fn forged_provider_session() -> ProviderArtifactSession {
        ProviderArtifactSession {
            issuer_id: "forged".to_owned(),
            task_id: "T-artifact".to_owned(),
            authority: ExecutionAuthority {
                binding_id: "binding:forged".to_owned(),
                attempt_id: "attempt:forged".to_owned(),
                semantic_program_hash: allocation("unused").semantic_program_hash,
                node_id: "compose_report".to_owned(),
                capability: "document.compose".to_owned(),
                principal_id: "provider:forged".to_owned(),
                policy_decision_refs_json: "[]".to_owned(),
                grant_refs_json: "[]".to_owned(),
            },
        }
    }

    fn import_request() -> ImportArtifactRequest {
        ImportArtifactRequest {
            schema_version: "0.1".to_owned(),
            import_id: None,
            task_id: "T-artifact".to_owned(),
            origin_kind: ArtifactOriginKind::User,
            semantic_type: Some("artifact.table@1".to_owned()),
            media_type: "text/csv".to_owned(),
            format: Some("csv".to_owned()),
            sensitivity: Sensitivity::Private,
            retention: RetentionClass::Task,
            expires_at: None,
            labels: vec!["fixture".to_owned()],
            max_size_bytes: Some(1_024),
        }
    }

    fn allocation(id: &str) -> OutputAllocationRequest {
        OutputAllocationRequest {
            schema_version: "0.1".to_owned(),
            allocation_id: id.to_owned(),
            task_id: "T-artifact".to_owned(),
            semantic_program_hash:
                "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
            node_id: "compose_report".to_owned(),
            binding_id: None,
            attempt_id: None,
            output_port: Some("report".to_owned()),
            expected_semantic_type: Some("artifact.report@1".to_owned()),
            allowed_media_types: vec!["text/markdown".to_owned()],
            max_size_bytes: Some(1_024),
            sensitivity: Sensitivity::Private,
            retention: RetentionClass::Task,
            expires_at: "2026-09-19T23:00:00Z".to_owned(),
        }
    }

    fn install_one_shot_binding(
        manager: &TaskManager,
        fixture: &str,
        input_artifact_ids: &[String],
        operations: &[(&str, &str, &str)],
    ) -> (String, String) {
        let program_hash = allocation("unused").semantic_program_hash;
        let registry_id = format!("registry-{fixture}");
        let policy_id = format!("policy-{fixture}");
        let binding_id = format!("binding-{fixture}");
        let attempt_id = format!("attempt-{fixture}");
        let request_ids = (0..operations.len())
            .map(|index| format!("request-{fixture}-{index}"))
            .collect::<Vec<_>>();
        let decision_ids = (0..operations.len())
            .map(|index| format!("decision-{fixture}-{index}"))
            .collect::<Vec<_>>();
        let grant_ids = (0..operations.len())
            .map(|index| format!("grant-{fixture}-{index}"))
            .collect::<Vec<_>>();
        manager
            .connection
            .execute(
                "INSERT INTO registry_snapshots(snapshot_id,manifest_json,created_at) VALUES (?1,'{}','2026-09-19T00:00:00Z')",
                [&registry_id],
            )
            .unwrap();
        manager
            .connection
            .execute(
                "INSERT INTO semantic_program_revisions(task_id,program_revision,program_id,ir_version,semantic_hash,registry_snapshot_id,status,program_json,created_at) VALUES ('T-artifact',1,?1,'0.1',?2,?3,'active','{\"nodes\":[{\"id\":\"compose_report\"}]}','2026-09-19T00:00:00Z')",
                params![format!("program-{fixture}"), program_hash, registry_id],
            )
            .unwrap();
        manager
            .connection
            .execute(
                "UPDATE tasks SET state='RUNNING',active_program_revision=1,active_step_ids_json='[\"compose_report\"]' WHERE task_id='T-artifact'",
                [],
            )
            .unwrap();
        manager
            .connection
            .execute(
                "INSERT INTO execution_bindings(binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,ir_version,node_id,capability,provider_id,provider_version,attempt,policy_decision_refs_json,grant_refs_json,execution_profile_ref,placement_json,binding_json,created_at) VALUES (?1,?2,'T-artifact',?3,?4,'0.1','compose_report','document.compose','provider:sequential','1',1,?5,?6,'profile:test','{}','{}','2026-09-19T00:00:00Z')",
                params![
                    binding_id,
                    attempt_id,
                    program_hash,
                    registry_id,
                    serde_json::to_string(&decision_ids).unwrap(),
                    serde_json::to_string(&grant_ids).unwrap()
                ],
            )
            .unwrap();
        manager
            .connection
            .execute(
                "INSERT INTO step_executions(attempt_id,task_id,semantic_program_hash,registry_snapshot_id,node_id,binding_id,attempt_number,revision,state,input_artifacts_json,output_artifacts_json,created_at,updated_at) VALUES (?1,'T-artifact',?2,?3,'compose_report',?4,1,1,'RUNNING',?5,'[]','2026-09-19T00:00:00Z','2026-09-19T00:00:00Z')",
                params![
                    attempt_id,
                    program_hash,
                    registry_id,
                    binding_id,
                    serde_json::to_string(input_artifact_ids).unwrap()
                ],
            )
            .unwrap();
        manager
            .connection
            .execute(
                "INSERT INTO policy_snapshots(snapshot_id,scope_kind,scope_id,policy_language,policy_set_hash,engine_id,engine_version,snapshot_json,created_at) VALUES (?1,'task','T-artifact','cedar','sha256:policy','test','1','{}','2026-09-19T00:00:00Z')",
                [&policy_id],
            )
            .unwrap();

        for (index, (action, resource_kind, resource_id)) in operations.iter().enumerate() {
            manager
                .connection
                .execute(
                    "INSERT INTO authority_requests(request_id,task_id,semantic_program_hash,registry_snapshot_id,node_id,capability,principal_kind,principal_id,execution_binding_id,attempt_id,action,resolved_resource_kind,resolved_resource_id,semantic_selector,request_json,requested_at) VALUES (?1,'T-artifact',?2,?3,'compose_report','document.compose','provider','provider:sequential',?4,?5,?6,?7,?8,'fixture','{}','2026-09-19T00:00:00Z')",
                    params![request_ids[index], program_hash, registry_id, binding_id, attempt_id, action, resource_kind, resource_id],
                )
                .unwrap();
            manager
                .connection
                .execute(
                    "INSERT INTO policy_decisions(decision_id,authority_request_id,task_id,semantic_program_hash,node_id,principal_kind,principal_id,action,resolved_resource_kind,resolved_resource_id,decision,policy_snapshot_id,reason_codes_json,decision_json,decided_at) VALUES (?1,?2,'T-artifact',?3,'compose_report','provider','provider:sequential',?4,?5,?6,'ALLOW',?7,'[]','{}','2026-09-19T00:00:00Z')",
                    params![decision_ids[index], request_ids[index], program_hash, action, resource_kind, resource_id, policy_id],
                )
                .unwrap();
            let grants = json!([{
                "action": action,
                "resource_kind": resource_kind,
                "resource_id": resource_id,
                "semantic_selector": "fixture"
            }]);
            manager
                .connection
                .execute(
                    "INSERT INTO authority_grants(grant_id,task_id,semantic_program_hash,node_id,capability,principal_kind,principal_id,execution_binding_id,attempt_id,policy_decision_id,policy_snapshot_id,grants_json,scope,max_uses,uses_consumed,state,issued_at,expires_at) VALUES (?1,'T-artifact',?2,'compose_report','document.compose','provider','provider:sequential',?3,?4,?5,?6,?7,'ONE_SHOT',1,0,'ACTIVE','2026-09-19T00:00:00Z','2026-09-20T00:00:00Z')",
                    params![grant_ids[index], program_hash, binding_id, attempt_id, decision_ids[index], policy_id, grants.to_string()],
                )
                .unwrap();
        }
        (binding_id, attempt_id)
    }

    fn publication(id: &str, allocation_id: &str) -> ArtifactPublicationRequest {
        ArtifactPublicationRequest {
            schema_version: "0.1".to_owned(),
            publication_id: id.to_owned(),
            allocation_id: allocation_id.to_owned(),
            task_id: "T-artifact".to_owned(),
            expected_allocation_state: ArtifactExpectedState::Writing,
            semantic_type: Some("artifact.report@1".to_owned()),
            media_type: "text/markdown".to_owned(),
            format: Some("markdown".to_owned()),
            lineage: ArtifactLineage::default(),
            labels: vec!["fixture".to_owned()],
        }
    }

    fn write_output(manager: &mut TaskManager, allocation_id: &str, bytes: &[u8]) {
        let mut writer = manager.open_artifact_output(allocation_id).unwrap();
        writer.write_all(bytes).unwrap();
        assert_eq!(writer.finish().unwrap(), bytes.len() as u64);
    }

    fn finish_bound_output(
        manager: &mut TaskManager,
        fixture: &str,
        scope: &str,
    ) -> (String, String) {
        let allocation_id = format!("alloc-{fixture}");
        let (binding_id, attempt_id) = install_one_shot_binding(
            manager,
            fixture,
            &[],
            &[("artifact.write", "output-allocation", &allocation_id)],
        );
        let grant_id = format!("grant-{fixture}-0");
        manager
            .connection
            .execute(
                "UPDATE authority_grants SET scope=?1 WHERE grant_id=?2",
                params![scope, grant_id],
            )
            .unwrap();
        let mut request = allocation(&allocation_id);
        request.binding_id = Some(binding_id);
        request.attempt_id = Some(attempt_id);
        allocate_bound(manager, &request);
        let mut writer = open_bound(manager, &allocation_id);
        writer.write_all(fixture.as_bytes()).unwrap();
        writer.finish().unwrap();
        (allocation_id, grant_id)
    }

    fn assert_publication_not_committed(
        manager: &TaskManager,
        allocation_id: &str,
        publication_id: &str,
    ) {
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM artifact_publications WHERE publication_id=?1 AND state='COMMITTED'",
                    [publication_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            manager
                .connection
                .query_row("SELECT COUNT(*) FROM artifacts", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM task_artifacts WHERE role='output'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM provenance_events WHERE event_type='artifact.created'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_ne!(
            manager
                .connection
                .query_row(
                    "SELECT state FROM artifact_output_allocations WHERE allocation_id=?1",
                    [allocation_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "PUBLISHED"
        );
    }

    fn assert_no_created_artifact_metadata(manager: &TaskManager) {
        for query in [
            "SELECT COUNT(*) FROM artifacts",
            "SELECT COUNT(*) FROM task_artifacts WHERE role='output'",
            "SELECT COUNT(*) FROM provenance_events WHERE event_type='artifact.created'",
            "SELECT COUNT(*) FROM artifact_publications WHERE state='COMMITTED'",
        ] {
            assert_eq!(
                manager
                    .connection
                    .query_row(query, [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
    }

    fn write_manual_seal(manager: &TaskManager, allocation_id: &str, staging_ref: &str) {
        let staging_path = resolve_internal_ref(&manager.artifact_store_root, staging_ref).unwrap();
        let (size_bytes, content_hash) = hash_file(&staging_path).unwrap();
        std::fs::write(
            resolve_internal_ref(&manager.artifact_store_root, &seal_ref(staging_ref)).unwrap(),
            serde_json::to_vec(&SealedStaging {
                version: SEALED_STAGING_VERSION,
                allocation_id: allocation_id.to_owned(),
                size_bytes,
                content_hash,
            })
            .unwrap(),
        )
        .unwrap();
    }

    fn assert_matches_schema<T: Serialize>(schema_name: &str, value: &T) {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let schema: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("specs").join(schema_name)).unwrap())
                .unwrap();
        let instance = serde_json::to_value(value).unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();
        assert!(
            validator.is_valid(&instance),
            "{schema_name}: {:?}",
            validator.iter_errors(&instance).collect::<Vec<_>>()
        );
    }

    #[test]
    fn imports_are_copy_isolated_and_deduplicate_only_the_blob() {
        let temp = TempDir::new().unwrap();
        let source = temp.path().join("source.csv");
        std::fs::write(&source, b"a,b\n1,2\n").unwrap();
        let mut manager = manager(&temp);
        let first = manager
            .import_artifact(&import_request(), &mut File::open(&source).unwrap())
            .unwrap();
        assert_matches_schema("artifact-handle.schema.json", &first);
        std::fs::write(&source, b"changed").unwrap();
        let second = manager
            .import_artifact(
                &import_request(),
                &mut Cursor::new(b"a,b\n1,2\n".as_slice()),
            )
            .unwrap();
        assert_ne!(first.artifact_id, second.artifact_id);
        assert_eq!(first.content_hash, second.content_hash);
        let blob_count = manager
            .connection
            .query_row("SELECT COUNT(*) FROM artifact_blobs", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap();
        assert_eq!(blob_count, 1);
        let scope = manager
            .scope_owned_artifact_reads("T-artifact", &[first.artifact_id.clone()])
            .unwrap();
        let mut reader = manager
            .open_artifact_reader(&scope, &first.artifact_id)
            .unwrap();
        let mut stored = Vec::new();
        reader.read_to_end(&mut stored).unwrap();
        assert_eq!(stored, b"a,b\n1,2\n");
        let mut export_one = manager
            .issue_owned_artifact_export_destination(
                &scope,
                "export-copy-one",
                &first.artifact_id,
                "user-selected-file",
                1_024,
                deferred(Vec::new()),
            )
            .unwrap();
        let mut export_two = manager
            .issue_owned_artifact_export_destination(
                &scope,
                "export-copy-two",
                &first.artifact_id,
                "user-selected-file",
                1_024,
                deferred(Vec::new()),
            )
            .unwrap();
        assert_eq!(
            manager
                .export_artifact(&scope, &first.artifact_id, &mut export_one)
                .unwrap(),
            8
        );
        assert_eq!(
            manager
                .export_artifact(&scope, &first.artifact_id, &mut export_two)
                .unwrap(),
            8
        );
        assert!(export_two.writer.is_some());
        assert_eq!(
            manager
                .get_artifact(&first.artifact_id)
                .unwrap()
                .unwrap()
                .artifact_id,
            first.artifact_id
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "covers exact egress admission, transfer provenance, and authenticated replay"
    )]
    fn provider_export_requires_exact_destination_grant_and_records_typed_transfer() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let artifact = manager
            .import_artifact(
                &import_request(),
                &mut Cursor::new(b"exported bytes".as_slice()),
            )
            .unwrap();
        let (binding_id, _) = install_one_shot_binding(
            &manager,
            "export-authorized",
            std::slice::from_ref(&artifact.artifact_id),
            &[
                ("artifact.read", "artifact", &artifact.artifact_id),
                ("data.egress", "destination", "user-selected-file"),
            ],
        );
        let session = manager
            .issue_provider_artifact_session("T-artifact", &binding_id)
            .unwrap();
        let scope = manager
            .scope_artifact_reads(&session, std::slice::from_ref(&artifact.artifact_id))
            .unwrap();
        assert!(matches!(
            manager.issue_bound_artifact_export_destination(
                &session,
                &scope,
                "export-operation-wrong-destination",
                &artifact.artifact_id,
                "remote-model",
                1_024,
                deferred(Vec::new()),
            ),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
        let mut destination = manager
            .issue_bound_artifact_export_destination(
                &session,
                &scope,
                "export-operation-authorized",
                &artifact.artifact_id,
                "user-selected-file",
                1_024,
                deferred(Vec::new()),
            )
            .unwrap();
        assert_eq!(
            manager
                .export_artifact(&scope, &artifact.artifact_id, &mut destination)
                .unwrap(),
            14
        );
        assert_eq!(
            destination.writer.as_deref(),
            Some(b"exported bytes".as_slice())
        );
        assert_eq!(
            manager
                .export_artifact(&scope, &artifact.artifact_id, &mut destination)
                .unwrap(),
            14
        );
        assert_eq!(
            destination.writer.as_deref(),
            Some(b"exported bytes".as_slice())
        );
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT uses_consumed FROM authority_grants WHERE grant_id='grant-export-authorized-1'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        let stored_event: serde_json::Value = serde_json::from_str(
            &manager
                .connection
                .query_row(
                    "SELECT event_json FROM provenance_events WHERE task_id='T-artifact' AND event_type='artifact.exported'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            stored_event["external_transfer"],
            json!({
                "destination":"user-selected-file",
                "data_refs":[artifact.artifact_id],
                "purpose":null,
            })
        );
        assert_eq!(
            stored_event["authority_token_id"],
            "grant-export-authorized-1"
        );
        assert_eq!(
            stored_event["details"]["operation_id"],
            "export-operation-authorized"
        );
        assert_matches_schema("provenance-event.schema.json", &stored_event);
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT state || ':' || outcome_certainty FROM operations WHERE operation_id='export-operation-authorized'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "SUCCEEDED:COMPLETED"
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "covers exact replay, changed-intent conflict, and fresh-operation retransmission fencing together"
    )]
    fn completed_export_replays_to_fresh_destination_and_rejects_changed_intent() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let artifact = manager
            .import_artifact(
                &import_request(),
                &mut Cursor::new(b"exported once".as_slice()),
            )
            .unwrap();
        let scope = manager
            .scope_owned_artifact_reads("T-artifact", &[artifact.artifact_id.clone()])
            .unwrap();
        let mut original = manager
            .issue_owned_artifact_export_destination(
                &scope,
                "export-fresh-replay",
                &artifact.artifact_id,
                "user-selected-file",
                1_024,
                deferred(Vec::new()),
            )
            .unwrap();
        assert_eq!(
            manager
                .export_artifact(&scope, &artifact.artifact_id, &mut original)
                .unwrap(),
            13
        );
        assert_eq!(
            original.writer.as_deref(),
            Some(b"exported once".as_slice())
        );

        let mut fresh_replay = manager
            .issue_owned_artifact_export_destination(
                &scope,
                "export-fresh-replay",
                &artifact.artifact_id,
                "user-selected-file",
                1_024,
                deferred(Vec::new()),
            )
            .unwrap();
        assert_eq!(
            manager
                .export_artifact(&scope, &artifact.artifact_id, &mut fresh_replay)
                .unwrap(),
            13
        );
        assert!(fresh_replay.writer.is_none());

        let mut changed_intent = manager
            .issue_owned_artifact_export_destination(
                &scope,
                "export-fresh-replay",
                &artifact.artifact_id,
                "user-selected-file",
                2_048,
                deferred(Vec::new()),
            )
            .unwrap();
        assert!(matches!(
            manager.export_artifact(&scope, &artifact.artifact_id, &mut changed_intent),
            Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_OPERATION_ID_REUSE_CONFLICT"
            ))
        ));
        assert!(changed_intent.writer.is_none());
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM provenance_events WHERE event_type='artifact.exported'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM operations WHERE operation_id='export-fresh-replay'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );

        let fresh_opens = Arc::new(AtomicUsize::new(0));
        let factory_opens = Arc::clone(&fresh_opens);
        let mut fresh_operation = manager
            .issue_owned_artifact_export_destination(
                &scope,
                "export-fresh-operation-after-success",
                &artifact.artifact_id,
                "user-selected-file",
                1_024,
                move || {
                    factory_opens.fetch_add(1, Ordering::SeqCst);
                    Ok(Vec::new())
                },
            )
            .unwrap();
        assert_eq!(
            manager
                .export_artifact(&scope, &artifact.artifact_id, &mut fresh_operation)
                .unwrap(),
            13
        );
        assert_eq!(fresh_opens.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn completed_export_replay_authenticates_the_full_provenance_prefix() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let artifact = manager
            .import_artifact(
                &import_request(),
                &mut Cursor::new(b"chain bound".as_slice()),
            )
            .unwrap();
        let scope = manager
            .scope_owned_artifact_reads("T-artifact", &[artifact.artifact_id.clone()])
            .unwrap();
        let mut first = manager
            .issue_owned_artifact_export_destination(
                &scope,
                "export-chain-bound",
                &artifact.artifact_id,
                "user-selected-file",
                1_024,
                deferred(Vec::new()),
            )
            .unwrap();
        manager
            .export_artifact(&scope, &artifact.artifact_id, &mut first)
            .unwrap();
        manager
            .connection
            .execute_batch(
                "DROP TRIGGER provenance_events_no_update;
                 UPDATE provenance_events SET event_hash='sha256:corrupt-prefix'
                 WHERE task_id='T-artifact' AND sequence=1;",
            )
            .unwrap();
        let mut replay = manager
            .issue_owned_artifact_export_destination(
                &scope,
                "export-chain-bound",
                &artifact.artifact_id,
                "user-selected-file",
                1_024,
                deferred(Vec::new()),
            )
            .unwrap();
        assert!(matches!(
            manager.export_artifact(&scope, &artifact.artifact_id, &mut replay),
            Err(TaskManagerError::InvalidRecord(
                "stored Artifact export receipt is invalid"
            ))
        ));
        assert!(replay.writer.is_none());
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "covers initial one-shot admission, in-process replay, and restart replay in one protocol regression"
    )]
    fn bound_export_exact_replay_reconstructs_after_one_shot_grant_consumption() {
        let temp = TempDir::new().unwrap();
        let database = temp.path().join("task-manager.sqlite");
        let mut manager = manager(&temp);
        let artifact = manager
            .import_artifact(
                &import_request(),
                &mut Cursor::new(b"one shot export replay".as_slice()),
            )
            .unwrap();
        let (binding_id, _) = install_one_shot_binding(
            &manager,
            "export-consumed-replay",
            std::slice::from_ref(&artifact.artifact_id),
            &[
                ("artifact.read", "artifact", &artifact.artifact_id),
                ("data.egress", "destination", "user-selected-file"),
            ],
        );
        let session = manager
            .issue_provider_artifact_session("T-artifact", &binding_id)
            .unwrap();
        let scope = manager
            .scope_artifact_reads(&session, std::slice::from_ref(&artifact.artifact_id))
            .unwrap();
        let mut first = manager
            .issue_bound_artifact_export_destination(
                &session,
                &scope,
                "export-consumed-replay",
                &artifact.artifact_id,
                "user-selected-file",
                1_024,
                deferred(Vec::new()),
            )
            .unwrap();
        assert_eq!(
            manager
                .export_artifact(&scope, &artifact.artifact_id, &mut first)
                .unwrap(),
            22
        );
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT state || ':' || uses_consumed FROM authority_grants
                     WHERE grant_id='grant-export-consumed-replay-1'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "CONSUMED:1"
        );

        manager
            .connection
            .execute(
                "UPDATE tasks SET state='RECOVERING' WHERE task_id='T-artifact'",
                [],
            )
            .unwrap();
        assert!(matches!(
            manager.replay_bound_artifact_export(&session, "export-consumed-replay"),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
        manager
            .connection
            .execute(
                "UPDATE tasks SET state='RUNNING' WHERE task_id='T-artifact'",
                [],
            )
            .unwrap();
        assert_eq!(
            manager
                .replay_bound_artifact_export(&session, "export-consumed-replay")
                .unwrap(),
            22
        );

        let opened = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&opened);
        let mut replay = manager
            .issue_bound_artifact_export_destination(
                &session,
                &scope,
                "export-consumed-replay",
                &artifact.artifact_id,
                "user-selected-file",
                1_024,
                move || {
                    observed.fetch_add(1, Ordering::SeqCst);
                    Ok(Vec::new())
                },
            )
            .unwrap();
        assert_eq!(
            manager
                .export_artifact(&scope, &artifact.artifact_id, &mut replay)
                .unwrap(),
            22
        );
        assert_eq!(opened.load(Ordering::SeqCst), 0);

        // The binding fixture installs execution state directly. Restore the provenance-backed
        // Task view before reopening, then re-establish the fixture's execution view afterward.
        manager
            .connection
            .execute(
                "UPDATE tasks
                 SET state='CREATED',active_program_revision=NULL,active_step_ids_json='[]'
                 WHERE task_id='T-artifact'",
                [],
            )
            .unwrap();
        drop(replay);
        drop(first);
        drop(scope);
        drop(session);
        drop(manager);
        let reopened = TaskManager::open_with_clock(&database, Box::new(FixedClock)).unwrap();
        reopened
            .connection
            .execute(
                "UPDATE tasks
                 SET state='RUNNING',active_program_revision=1,
                     active_step_ids_json='[\"compose_report\"]'
                 WHERE task_id='T-artifact'",
                [],
            )
            .unwrap();
        let session = reopened
            .issue_provider_artifact_session("T-artifact", &binding_id)
            .unwrap();
        assert!(matches!(
            reopened.scope_artifact_reads(&session, std::slice::from_ref(&artifact.artifact_id)),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
        assert_eq!(
            reopened
                .replay_bound_artifact_export(&session, "export-consumed-replay")
                .unwrap(),
            22
        );
    }

    #[test]
    fn revoked_egress_after_destination_issuance_fails_before_copy() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let artifact = manager
            .import_artifact(
                &import_request(),
                &mut Cursor::new(b"confidential".as_slice()),
            )
            .unwrap();
        let (binding_id, _) = install_one_shot_binding(
            &manager,
            "export-revoked",
            std::slice::from_ref(&artifact.artifact_id),
            &[
                ("artifact.read", "artifact", &artifact.artifact_id),
                ("data.egress", "destination", "user-selected-file"),
            ],
        );
        let session = manager
            .issue_provider_artifact_session("T-artifact", &binding_id)
            .unwrap();
        let scope = manager
            .scope_artifact_reads(&session, std::slice::from_ref(&artifact.artifact_id))
            .unwrap();
        let factory_opens = Arc::new(AtomicUsize::new(0));
        let observed_opens = Arc::clone(&factory_opens);
        let mut destination = manager
            .issue_bound_artifact_export_destination(
                &session,
                &scope,
                "export-operation-revoked",
                &artifact.artifact_id,
                "user-selected-file",
                1_024,
                move || {
                    observed_opens.fetch_add(1, Ordering::SeqCst);
                    Ok(Vec::new())
                },
            )
            .unwrap();
        manager
            .connection
            .execute(
                "UPDATE authority_grants SET state='REVOKED' WHERE grant_id='grant-export-revoked-1'",
                [],
            )
            .unwrap();
        assert!(matches!(
            manager.export_artifact(&scope, &artifact.artifact_id, &mut destination),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
        assert!(destination.writer.is_none());
        assert_eq!(factory_opens.load(Ordering::SeqCst), 0);
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM provenance_events WHERE event_type='artifact.exported'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn succeeded_attempt_allows_durable_replay_but_denies_fresh_protected_work() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let input = manager
            .import_artifact(&import_request(), &mut Cursor::new(b"input".as_slice()))
            .unwrap();
        let existing_id = "alloc-before-success";
        let unopened_id = "alloc-unopened-before-success";
        let (binding_id, attempt_id) = install_one_shot_binding(
            &manager,
            "post-success-fence",
            std::slice::from_ref(&input.artifact_id),
            &[
                ("artifact.read", "artifact", &input.artifact_id),
                ("artifact.write", "output-allocation", existing_id),
                ("artifact.write", "output-allocation", unopened_id),
                ("data.egress", "destination", "user-selected-file"),
            ],
        );
        let session = manager
            .issue_provider_artifact_session("T-artifact", &binding_id)
            .unwrap();
        let scope = manager
            .scope_artifact_reads(&session, std::slice::from_ref(&input.artifact_id))
            .unwrap();
        let mut existing = allocation(existing_id);
        existing.binding_id = Some(binding_id.clone());
        existing.attempt_id = Some(attempt_id.clone());
        let mut unopened = allocation(unopened_id);
        unopened.binding_id = Some(binding_id.clone());
        unopened.attempt_id = Some(attempt_id.clone());
        let original = manager
            .allocate_bound_artifact_output(&session, &existing)
            .unwrap();
        manager
            .allocate_bound_artifact_output(&session, &unopened)
            .unwrap();
        let factory_opens = Arc::new(AtomicUsize::new(0));
        let observed_opens = Arc::clone(&factory_opens);
        let mut destination = manager
            .issue_bound_artifact_export_destination(
                &session,
                &scope,
                "export-after-attempt-success",
                &input.artifact_id,
                "user-selected-file",
                1_024,
                move || {
                    observed_opens.fetch_add(1, Ordering::SeqCst);
                    Ok(Vec::new())
                },
            )
            .unwrap();
        manager
            .connection
            .execute(
                "UPDATE step_executions SET state='SUCCEEDED',outcome_certainty='COMPLETED',finished_at='2026-09-19T22:00:00Z' WHERE attempt_id=?1",
                [&attempt_id],
            )
            .unwrap();

        assert_eq!(
            manager
                .allocate_bound_artifact_output(&session, &existing)
                .unwrap(),
            original
        );
        let mut fresh = existing.clone();
        fresh.allocation_id = "alloc-fresh-after-success".to_owned();
        assert!(matches!(
            manager.allocate_bound_artifact_output(&session, &fresh),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
        assert!(matches!(
            manager.open_artifact_output(unopened_id),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
        assert!(matches!(
            manager.open_artifact_reader(&scope, &input.artifact_id),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
        assert!(matches!(
            manager.export_artifact(&scope, &input.artifact_id, &mut destination),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
        assert_eq!(factory_opens.load(Ordering::SeqCst), 0);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "covers stable-effect fencing across changed owner and provider admissions"
    )]
    fn partial_and_flush_export_failures_are_durable_unknown_outcomes() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let artifact = manager
            .import_artifact(
                &import_request(),
                &mut Cursor::new(b"confidential".as_slice()),
            )
            .unwrap();
        let scope = manager
            .scope_owned_artifact_reads("T-artifact", &[artifact.artifact_id.clone()])
            .unwrap();
        let mut partial = manager
            .issue_owned_artifact_export_destination(
                &scope,
                "export-partial-write",
                &artifact.artifact_id,
                "user-selected-file",
                1_024,
                deferred(PrefixThenErrorWriter::default()),
            )
            .unwrap();
        assert!(matches!(
            manager.export_artifact(&scope, &artifact.artifact_id, &mut partial),
            Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_OUTCOME_UNKNOWN"
            ))
        ));
        assert_eq!(partial.writer.as_ref().unwrap().bytes, b"con");
        assert!(matches!(
            manager.export_artifact(&scope, &artifact.artifact_id, &mut partial),
            Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_OUTCOME_UNKNOWN"
            ))
        ));
        assert_eq!(partial.writer.as_ref().unwrap().bytes, b"con");

        let mut duplicate = manager
            .issue_owned_artifact_export_destination(
                &scope,
                "export-partial-write-duplicate",
                &artifact.artifact_id,
                "user-selected-file",
                2_048,
                deferred(Vec::new()),
            )
            .unwrap();
        assert!(matches!(
            manager.export_artifact(&scope, &artifact.artifact_id, &mut duplicate),
            Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_OUTCOME_UNKNOWN"
            ))
        ));
        assert!(duplicate.writer.is_none());

        let (binding_id, _) = install_one_shot_binding(
            &manager,
            "export-replacement-admission",
            std::slice::from_ref(&artifact.artifact_id),
            &[
                ("artifact.read", "artifact", &artifact.artifact_id),
                ("data.egress", "destination", "user-selected-file"),
            ],
        );
        let session = manager
            .issue_provider_artifact_session("T-artifact", &binding_id)
            .unwrap();
        assert!(matches!(
            manager.scope_artifact_reads(&session, std::slice::from_ref(&artifact.artifact_id)),
            Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_OUTCOME_UNKNOWN"
            ))
        ));
        for grant_id in [
            "grant-export-replacement-admission-0",
            "grant-export-replacement-admission-1",
        ] {
            assert_eq!(
                manager
                    .connection
                    .query_row(
                        "SELECT uses_consumed FROM authority_grants WHERE grant_id=?1",
                        [grant_id],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                0
            );
        }
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM operations WHERE operation_id IN (
                         'export-partial-write-duplicate',
                         'export-partial-write-replacement-admission'
                     )",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );

        let flush_temp = TempDir::new().unwrap();
        let mut flush_manager = self::manager(&flush_temp);
        let flush_artifact = flush_manager
            .import_artifact(
                &import_request(),
                &mut Cursor::new(b"confidential".as_slice()),
            )
            .unwrap();
        let flush_scope = flush_manager
            .scope_owned_artifact_reads("T-artifact", &[flush_artifact.artifact_id.clone()])
            .unwrap();
        let mut flush = flush_manager
            .issue_owned_artifact_export_destination(
                &flush_scope,
                "export-flush-failure",
                &flush_artifact.artifact_id,
                "backup-file",
                1_024,
                deferred(FlushFailureWriter::default()),
            )
            .unwrap();
        assert!(matches!(
            flush_manager.export_artifact(&flush_scope, &flush_artifact.artifact_id, &mut flush),
            Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_OUTCOME_UNKNOWN"
            ))
        ));
        assert_eq!(flush.writer.as_ref().unwrap().bytes, b"confidential");

        let empty_temp = TempDir::new().unwrap();
        let mut empty_manager = self::manager(&empty_temp);
        let empty = empty_manager
            .import_artifact(&import_request(), &mut Cursor::new([]))
            .unwrap();
        let empty_scope = empty_manager
            .scope_owned_artifact_reads("T-artifact", &[empty.artifact_id.clone()])
            .unwrap();
        let mut empty_flush = empty_manager
            .issue_owned_artifact_export_destination(
                &empty_scope,
                "export-empty-flush-failure",
                &empty.artifact_id,
                "empty-backup-file",
                1_024,
                deferred(FlushFailureWriter::default()),
            )
            .unwrap();
        assert!(matches!(
            empty_manager.export_artifact(&empty_scope, &empty.artifact_id, &mut empty_flush),
            Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_OUTCOME_UNKNOWN"
            ))
        ));
        assert!(empty_flush.writer.as_ref().unwrap().bytes.is_empty());
        for (connection, operation_id) in [
            (&manager.connection, "export-partial-write"),
            (&flush_manager.connection, "export-flush-failure"),
            (&empty_manager.connection, "export-empty-flush-failure"),
        ] {
            assert_eq!(
                connection
                    .query_row(
                        "SELECT state || ':' || outcome_certainty FROM operations WHERE operation_id=?1",
                        [operation_id],
                        |row| row.get::<_, String>(0),
                    )
                    .unwrap(),
                "UNKNOWN:OUTCOME_UNKNOWN"
            );
        }
        for connection in [
            &manager.connection,
            &flush_manager.connection,
            &empty_manager.connection,
        ] {
            assert_eq!(
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM provenance_events WHERE event_type='artifact.exported'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                0
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "constructs both racing admissions and verifies every rolled-back side effect"
    )]
    fn export_reservation_race_consumes_neither_losing_grant() {
        let temp = TempDir::new().unwrap();
        let database = temp.path().join("task-manager.sqlite");
        let mut manager = manager(&temp);
        let artifact = manager
            .import_artifact(
                &import_request(),
                &mut Cursor::new(b"race fenced".as_slice()),
            )
            .unwrap();
        let (binding_id, _) = install_one_shot_binding(
            &manager,
            "export-reservation-race",
            std::slice::from_ref(&artifact.artifact_id),
            &[
                ("artifact.read", "artifact", &artifact.artifact_id),
                ("data.egress", "destination", "user-selected-file"),
            ],
        );
        let session = manager
            .issue_provider_artifact_session("T-artifact", &binding_id)
            .unwrap();
        let scope = manager
            .scope_artifact_reads(&session, std::slice::from_ref(&artifact.artifact_id))
            .unwrap();
        let mut losing_destination = manager
            .issue_bound_artifact_export_destination(
                &session,
                &scope,
                "export-race-loser",
                &artifact.artifact_id,
                "user-selected-file",
                1_024,
                deferred(Vec::new()),
            )
            .unwrap();
        let owner_scope = manager
            .scope_owned_artifact_reads("T-artifact", &[artifact.artifact_id.clone()])
            .unwrap();
        let competing_destination = manager
            .issue_owned_artifact_export_destination(
                &owner_scope,
                "export-race-winner",
                &artifact.artifact_id,
                "user-selected-file",
                2_048,
                deferred(Vec::new()),
            )
            .unwrap();
        let competing_intent_json = competing_destination.intent_json.clone();
        let competing_intent: ArtifactExportIntent =
            serde_json::from_str(&competing_intent_json).unwrap();
        EXPORT_RESERVATION_RACE_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                let connection = Connection::open(database)?;
                connection.execute(
                    "INSERT INTO operations(
                        operation_id,task_id,semantic_program_hash,node_id,binding_id,attempt_id,
                        transaction_class,effect_class,idempotency_key,state,outcome_certainty,
                        external_receipt,details_json,prepared_at,started_at,finished_at
                     ) VALUES (
                        'export-race-winner',?1,?2,?3,NULL,NULL,
                        'irreversible_external','DATA_EGRESS','export-race-winner',
                        'UNKNOWN','OUTCOME_UNKNOWN',NULL,?4,?5,?5,?5
                     )",
                    params![
                        competing_intent.task_id,
                        competing_intent.semantic_program_hash,
                        competing_intent.node_id,
                        competing_intent_json,
                        "2026-09-19T22:00:00Z",
                    ],
                )?;
                Ok(())
            }));
        });

        assert!(matches!(
            manager.export_artifact(&scope, &artifact.artifact_id, &mut losing_destination,),
            Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_OUTCOME_UNKNOWN"
            ))
        ));
        assert!(losing_destination.writer.is_none());
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM operations WHERE operation_id='export-race-loser'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        for grant_id in [
            "grant-export-reservation-race-0",
            "grant-export-reservation-race-1",
        ] {
            assert_eq!(
                manager
                    .connection
                    .query_row(
                        "SELECT uses_consumed FROM authority_grants WHERE grant_id=?1",
                        [grant_id],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                0
            );
        }
    }

    #[test]
    fn post_copy_completion_failure_is_durable_unknown_without_provenance() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let artifact = manager
            .import_artifact(&import_request(), &mut Cursor::new(b"exported".as_slice()))
            .unwrap();
        let scope = manager
            .scope_owned_artifact_reads("T-artifact", &[artifact.artifact_id.clone()])
            .unwrap();
        let mut destination = manager
            .issue_owned_artifact_export_destination(
                &scope,
                "export-completion-failure",
                &artifact.artifact_id,
                "user-selected-file",
                1_024,
                deferred(Vec::new()),
            )
            .unwrap();
        EXPORT_COMPLETION_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(|| {
                Err(TaskManagerError::Io(std::io::Error::other(
                    "injected export completion failure",
                )))
            }));
        });
        assert!(matches!(
            manager.export_artifact(&scope, &artifact.artifact_id, &mut destination),
            Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_OUTCOME_UNKNOWN"
            ))
        ));
        assert_eq!(destination.writer.as_deref(), Some(b"exported".as_slice()));
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT state || ':' || outcome_certainty FROM operations WHERE operation_id='export-completion-failure'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "UNKNOWN:OUTCOME_UNKNOWN"
        );
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM provenance_events WHERE event_type='artifact.exported'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn copy_failure_after_factory_before_first_write_is_unknown() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let artifact = manager
            .import_artifact(
                &import_request(),
                &mut Cursor::new(b"not escaped".as_slice()),
            )
            .unwrap();
        let scope = manager
            .scope_owned_artifact_reads("T-artifact", &[artifact.artifact_id.clone()])
            .unwrap();
        let factory_opens = Arc::new(AtomicUsize::new(0));
        let observed_opens = Arc::clone(&factory_opens);
        let mut destination = manager
            .issue_owned_artifact_export_destination(
                &scope,
                "export-failed-no-effect",
                &artifact.artifact_id,
                "user-selected-file",
                1_024,
                move || {
                    observed_opens.fetch_add(1, Ordering::SeqCst);
                    Ok(Vec::new())
                },
            )
            .unwrap();
        EXPORT_COPY_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(|| {
                Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
            }));
        });
        assert!(matches!(
            manager.export_artifact(&scope, &artifact.artifact_id, &mut destination),
            Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_OUTCOME_UNKNOWN"
            ))
        ));
        assert_eq!(factory_opens.load(Ordering::SeqCst), 1);
        assert_eq!(destination.writer.as_deref(), Some([].as_slice()));
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT state || ':' || outcome_certainty FROM operations WHERE operation_id='export-failed-no-effect'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "UNKNOWN:OUTCOME_UNKNOWN"
        );
        assert!(matches!(
            manager.export_artifact(&scope, &artifact.artifact_id, &mut destination),
            Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_OUTCOME_UNKNOWN"
            ))
        ));
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM provenance_events WHERE event_type='artifact.exported'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn destination_factory_truncation_then_error_is_unknown() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let artifact = manager
            .import_artifact(&import_request(), &mut Cursor::new(b"private".as_slice()))
            .unwrap();
        let scope = manager
            .scope_owned_artifact_reads("T-artifact", &[artifact.artifact_id.clone()])
            .unwrap();
        let external = temp.path().join("external-destination.bin");
        std::fs::write(&external, b"existing destination bytes").unwrap();
        let factory_path = external.clone();
        let mut destination = manager
            .issue_owned_artifact_export_destination(
                &scope,
                "export-factory-effect-error",
                &artifact.artifact_id,
                "user-selected-file",
                1_024,
                move || -> std::io::Result<Vec<u8>> {
                    let _opened = File::create(factory_path)?;
                    Err(std::io::Error::other(
                        "destination open failed after truncation",
                    ))
                },
            )
            .unwrap();

        assert!(matches!(
            manager.export_artifact(&scope, &artifact.artifact_id, &mut destination),
            Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_OUTCOME_UNKNOWN"
            ))
        ));
        assert_eq!(std::fs::read(external).unwrap(), b"");
        assert!(destination.writer.is_none());
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT state || ':' || outcome_certainty FROM operations WHERE operation_id='export-factory-effect-error'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "UNKNOWN:OUTCOME_UNKNOWN"
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "covers unknown export persistence, recovery routing, trusted resolution, and response-loss replay"
    )]
    fn finalize_failure_is_unknown_and_routes_live_task_to_recovery() {
        let temp = TempDir::new().unwrap();
        let verifier = Arc::new(export_no_effect_verifier(
            "user-selected-file",
            "evidence:destination-unchanged",
            'a',
        ));
        let mut manager = manager_with_export_verifiers(&temp, vec![verifier.clone()]);
        let artifact = manager
            .import_artifact(
                &import_request(),
                &mut Cursor::new(b"finalize me".as_slice()),
            )
            .unwrap();
        let (binding_id, _) = install_one_shot_binding(
            &manager,
            "export-finalize-recovery",
            std::slice::from_ref(&artifact.artifact_id),
            &[
                ("artifact.read", "artifact", &artifact.artifact_id),
                ("data.egress", "destination", "user-selected-file"),
            ],
        );
        let session = manager
            .issue_provider_artifact_session("T-artifact", &binding_id)
            .unwrap();
        let scope = manager
            .scope_artifact_reads(&session, std::slice::from_ref(&artifact.artifact_id))
            .unwrap();
        let mut destination = manager
            .issue_bound_artifact_export_destination(
                &session,
                &scope,
                "export-finalize-recovery",
                &artifact.artifact_id,
                "user-selected-file",
                1_024,
                deferred(FinalizeFailureWriter::default()),
            )
            .unwrap();

        assert!(matches!(
            manager.export_artifact(&scope, &artifact.artifact_id, &mut destination),
            Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_OUTCOME_UNKNOWN"
            ))
        ));
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT state || ':' || outcome_certainty FROM operations WHERE operation_id='export-finalize-recovery'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "UNKNOWN:OUTCOME_UNKNOWN"
        );
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT state FROM tasks WHERE task_id='T-artifact'",
                    [],
                    |row| { row.get::<_, String>(0) }
                )
                .unwrap(),
            "RECOVERING"
        );
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM provenance_events WHERE event_type='artifact.exported'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );

        manager
            .connection
            .execute_batch(
                "CREATE TEMP TRIGGER fail_export_recovery_assessment
                 BEFORE UPDATE ON recovery_assessments
                 WHEN OLD.subject_kind<>'task'
                 BEGIN SELECT RAISE(ABORT,'injected assessment failure'); END;",
            )
            .unwrap();
        assert!(
            manager
                .reconcile_unknown_artifact_export_no_effect("export-finalize-recovery")
                .is_err()
        );
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT state || ':' || outcome_certainty FROM operations WHERE operation_id='export-finalize-recovery'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "UNKNOWN:OUTCOME_UNKNOWN"
        );
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM provenance_events
                     WHERE json_extract(event_json,'$.details.export_reconciliation.proof_hash')=?1",
                    [&verifier.proof_hash],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        manager
            .connection
            .execute_batch("DROP TRIGGER fail_export_recovery_assessment;")
            .unwrap();
        manager
            .reconcile_unknown_artifact_export_no_effect("export-finalize-recovery")
            .unwrap();
        // A delayed response-loss retry resolves through the durable challenge and assessment,
        // even if an unrelated Task revision has advanced in the meantime.
        manager
            .connection
            .execute(
                "UPDATE tasks SET revision=revision+1 WHERE task_id='T-artifact'",
                [],
            )
            .unwrap();
        manager
            .reconcile_unknown_artifact_export_no_effect("export-finalize-recovery")
            .unwrap();
        assert_eq!(verifier.calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT state || ':' || outcome_certainty FROM operations WHERE operation_id='export-finalize-recovery'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "FAILED:FAILED_NO_EFFECT"
        );
        let subject = manager
            .connection
            .query_row(
                "SELECT certainty || ':' || safe_action FROM recovery_assessments
                 WHERE task_id='T-artifact' AND subject_kind='external-operation'
                   AND subject_id='operation:export-finalize-recovery'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        assert_eq!(subject, "FAILED_NO_EFFECT:MARK_ATTEMPT_FAILED");
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one response-loss fixture proves the unknown row, absent inventory, deterministic repair, lifecycle handoff, and access fence"
    )]
    fn failed_live_recovery_handoff_propagates_and_fences_artifact_operations() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let artifact = manager
            .import_artifact(
                &import_request(),
                &mut Cursor::new(b"handoff fence".as_slice()),
            )
            .unwrap();
        let (binding_id, _) = install_one_shot_binding(
            &manager,
            "export-handoff-failure",
            std::slice::from_ref(&artifact.artifact_id),
            &[
                ("artifact.read", "artifact", &artifact.artifact_id),
                ("data.egress", "destination", "user-selected-file"),
            ],
        );
        let session = manager
            .issue_provider_artifact_session("T-artifact", &binding_id)
            .unwrap();
        let scope = manager
            .scope_artifact_reads(&session, std::slice::from_ref(&artifact.artifact_id))
            .unwrap();
        let mut destination = manager
            .issue_bound_artifact_export_destination(
                &session,
                &scope,
                "export-handoff-failure",
                &artifact.artifact_id,
                "user-selected-file",
                1_024,
                deferred(FinalizeFailureWriter::default()),
            )
            .unwrap();
        LIVE_RECOVERY_HANDOFF_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(|| {
                Err(TaskManagerError::InvalidRecord(
                    "injected live recovery handoff failure",
                ))
            }));
        });

        assert!(matches!(
            manager.export_artifact(&scope, &artifact.artifact_id, &mut destination),
            Err(TaskManagerError::InvalidRecord(
                "injected live recovery handoff failure"
            ))
        ));
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT state || ':' || outcome_certainty FROM operations WHERE operation_id='export-handoff-failure'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "UNKNOWN:OUTCOME_UNKNOWN"
        );
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM recovery_unknown_operations
                     WHERE operation_id='operation:export-handoff-failure'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert!(matches!(
            manager.export_artifact(&scope, &artifact.artifact_id, &mut destination),
            Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_OUTCOME_UNKNOWN"
            ))
        ));
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM recovery_unknown_operations
                     WHERE operation_id='operation:export-handoff-failure'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT state FROM tasks WHERE task_id='T-artifact'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "RECOVERING"
        );
        assert!(matches!(
            manager.scope_artifact_reads(&session, &[artifact.artifact_id.clone()]),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one recovery-boundary fixture proves retained provider/owner readers, writer admission, import, allocation, and publication remain mutation-free"
    )]
    fn recovering_task_denies_retained_provider_artifact_authority_without_export_unknown() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let artifact = manager
            .import_artifact(
                &import_request(),
                &mut Cursor::new(b"recovery fence".as_slice()),
            )
            .unwrap();
        let allocation_id = "alloc-recovery-provider-fence";
        let (binding_id, attempt_id) = install_one_shot_binding(
            &manager,
            "recovery-provider-fence",
            std::slice::from_ref(&artifact.artifact_id),
            &[
                ("artifact.read", "artifact", &artifact.artifact_id),
                ("artifact.write", "output-allocation", allocation_id),
            ],
        );
        let session = manager
            .issue_provider_artifact_session("T-artifact", &binding_id)
            .unwrap();
        let scope = manager
            .scope_artifact_reads(&session, std::slice::from_ref(&artifact.artifact_id))
            .unwrap();
        let owner_scope = manager
            .scope_owned_artifact_reads("T-artifact", std::slice::from_ref(&artifact.artifact_id))
            .unwrap();
        let integrity_before = manager
            .connection
            .query_row(
                "SELECT integrity_state,integrity_verified_at,integrity_verifier
                 FROM artifacts WHERE artifact_id=?1",
                [&artifact.artifact_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .unwrap();
        let mut request = allocation(allocation_id);
        request.binding_id = Some(binding_id.clone());
        request.attempt_id = Some(attempt_id.clone());
        manager
            .allocate_bound_artifact_output(&session, &request)
            .unwrap();
        let mut writer = manager
            .open_bound_artifact_output(&session, allocation_id)
            .unwrap();
        writer.write_all(b"recovery output").unwrap();
        writer.finish().unwrap();
        let unopened_allocation = allocation("alloc-recovery-unopened");
        manager
            .allocate_artifact_output(&unopened_allocation)
            .unwrap();
        manager
            .connection
            .execute(
                "UPDATE tasks SET state='RECOVERING' WHERE task_id='T-artifact'",
                [],
            )
            .unwrap();

        assert!(matches!(
            manager.open_artifact_reader(&scope, &artifact.artifact_id),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
        assert!(matches!(
            manager.open_artifact_reader(&owner_scope, &artifact.artifact_id),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT uses_consumed FROM authority_grants
                     WHERE grant_id='grant-recovery-provider-fence-0'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT integrity_state,integrity_verified_at,integrity_verifier
                     FROM artifacts WHERE artifact_id=?1",
                    [&artifact.artifact_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, Option<String>>(2)?,
                        ))
                    },
                )
                .unwrap(),
            integrity_before
        );
        assert!(matches!(
            manager.scope_artifact_reads(&session, &[artifact.artifact_id.clone()]),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
        assert!(matches!(
            manager.allocate_bound_artifact_output(&session, &request),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
        assert!(matches!(
            manager.open_artifact_output(&unopened_allocation.allocation_id),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
        assert_eq!(
            manager
                .get_artifact_output_allocation(&unopened_allocation.allocation_id)
                .unwrap()
                .unwrap()
                .state,
            ArtifactAllocationState::Allocated
        );
        assert!(matches!(
            manager.import_artifact(
                &import_request(),
                &mut Cursor::new(b"forbidden recovery import".as_slice()),
            ),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
        let publication = publication("pub-recovery-provider-fence", allocation_id);
        assert!(matches!(
            manager.publish_artifact_output(&publication),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
        assert_eq!(
            manager
                .get_artifact_output_allocation(allocation_id)
                .unwrap()
                .unwrap()
                .state,
            ArtifactAllocationState::Writing
        );
        manager
            .connection
            .execute(
                "UPDATE tasks SET state='RUNNING' WHERE task_id='T-artifact'",
                [],
            )
            .unwrap();
        let database = temp.path().join("task-manager.sqlite");
        READER_SETUP_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                Connection::open(database)?.execute(
                    "UPDATE tasks SET state='RECOVERING' WHERE task_id='T-artifact'",
                    [],
                )?;
                Ok(())
            }));
        });
        assert!(matches!(
            manager.open_artifact_reader(&scope, &artifact.artifact_id),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT uses_consumed FROM authority_grants
                     WHERE grant_id='grant-recovery-provider-fence-0'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        manager
            .connection
            .execute(
                "UPDATE tasks SET state='RUNNING' WHERE task_id='T-artifact'",
                [],
            )
            .unwrap();
        let mut reader = manager
            .open_artifact_reader(&scope, &artifact.artifact_id)
            .unwrap();
        let mut byte = [0_u8; 1];
        assert_eq!(reader.read(&mut byte).unwrap(), 1);
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT uses_consumed FROM authority_grants
                     WHERE grant_id='grant-recovery-provider-fence-0'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn import_rechecks_recovery_after_streaming_and_removes_uncommitted_blob() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let database = temp.path().join("task-manager.sqlite");
        IMPORT_COMMIT_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                Connection::open(database)?.execute(
                    "UPDATE tasks SET state='RECOVERING' WHERE task_id='T-artifact'",
                    [],
                )?;
                Ok(())
            }));
        });

        assert!(matches!(
            manager.import_artifact(
                &import_request(),
                &mut Cursor::new(b"raced import".as_slice()),
            ),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
        for query in [
            "SELECT COUNT(*) FROM artifact_blobs",
            "SELECT COUNT(*) FROM artifacts",
            "SELECT COUNT(*) FROM task_artifacts",
            "SELECT COUNT(*) FROM provenance_events WHERE event_type='artifact.imported'",
        ] {
            assert_eq!(
                manager
                    .connection
                    .query_row(query, [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
        assert_eq!(
            std::fs::read_dir(manager.artifact_store_root.join("staging"))
                .unwrap()
                .count(),
            0
        );
        assert_eq!(
            physical_blob_refs(&manager.artifact_store_dir)
                .unwrap()
                .len(),
            0
        );

        manager
            .connection
            .execute(
                "UPDATE tasks SET state='PLANNING' WHERE task_id='T-artifact'",
                [],
            )
            .unwrap();
        assert!(
            manager
                .import_artifact(
                    &import_request(),
                    &mut Cursor::new(b"raced import".as_slice()),
                )
                .is_ok()
        );
    }

    #[test]
    fn late_import_commit_error_retains_the_adopted_blob_and_metadata() {
        let temp = TempDir::new().unwrap();
        let database = temp.path().join("task-manager.sqlite");
        let mut manager = manager(&temp);
        IMPORT_COMMIT_RESULT_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(|| {
                Err(TaskManagerError::Io(std::io::Error::other(
                    "injected lost import commit response",
                )))
            }));
        });

        assert!(matches!(
            manager.import_artifact(
                &import_request(),
                &mut Cursor::new(b"durable despite response loss".as_slice()),
            ),
            Err(TaskManagerError::Io(_))
        ));
        let (artifact_id, storage_ref, content_hash) = manager
            .connection
            .query_row(
                "SELECT a.artifact_id,b.storage_ref,a.content_hash
                 FROM artifacts a JOIN artifact_blobs b ON b.content_hash=a.content_hash",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            hash_internal_file(&manager.artifact_store_dir, &storage_ref)
                .unwrap()
                .1,
            content_hash
        );
        drop(manager);

        let reopened = TaskManager::open_with_clock(&database, Box::new(FixedClock)).unwrap();
        assert_eq!(
            reopened
                .get_artifact(&artifact_id)
                .unwrap()
                .unwrap()
                .content_hash
                .as_ref()
                .unwrap()
                .tagged(),
            content_hash
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "covers expired, already-terminal, and terminal-Task allocation cleanup as one startup matrix"
    )]
    fn startup_terminalizes_unfinishable_allocations_and_cleans_all_staging_evidence() {
        let expired_temp = TempDir::new().unwrap();
        let mut expired_manager = manager(&expired_temp);
        for (allocation_id, already_expired) in [
            ("alloc-expired-writing", false),
            ("alloc-expired-row", true),
        ] {
            expired_manager
                .allocate_artifact_output(&allocation(allocation_id))
                .unwrap();
            let mut writer = expired_manager.open_artifact_output(allocation_id).unwrap();
            writer.write_all(b"sensitive residue").unwrap();
            if already_expired {
                writer.finish().unwrap();
            } else {
                drop(writer);
            }
            let staging_ref = expired_manager
                .connection
                .query_row(
                    "SELECT staging_ref FROM artifact_output_allocations WHERE allocation_id=?1",
                    [allocation_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap();
            let seal = seal_ref(&staging_ref);
            expired_manager
                .artifact_store_dir
                .write(format!("{seal}.pending"), b"pending residue")
                .unwrap();
            expired_manager
                .connection
                .execute(
                    "UPDATE artifact_output_allocations
                     SET state=CASE WHEN ?2 THEN 'EXPIRED' ELSE state END,
                         expires_at='2026-09-19T21:00:00Z'
                     WHERE allocation_id=?1",
                    params![allocation_id, already_expired],
                )
                .unwrap();
        }
        expired_manager.reconcile_artifacts_startup().unwrap();
        for allocation_id in ["alloc-expired-writing", "alloc-expired-row"] {
            let (state, staging_ref) = expired_manager
                .connection
                .query_row(
                    "SELECT state,staging_ref FROM artifact_output_allocations WHERE allocation_id=?1",
                    [allocation_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .unwrap();
            assert_eq!(state, "EXPIRED");
            let seal = seal_ref(&staging_ref);
            for residue in [staging_ref, seal.clone(), format!("{seal}.pending")] {
                assert!(!expired_manager.artifact_store_root.join(residue).exists());
            }
        }

        let terminal_temp = TempDir::new().unwrap();
        let mut terminal_manager = manager(&terminal_temp);
        terminal_manager
            .allocate_artifact_output(&allocation("alloc-terminal-finalizing"))
            .unwrap();
        write_output(
            &mut terminal_manager,
            "alloc-terminal-finalizing",
            b"terminal residue",
        );
        let request = publication("pub-terminal-finalizing", "alloc-terminal-finalizing");
        let request_json = canonical_json(&request).unwrap();
        terminal_manager
            .reserve_publication(&request, &request_json)
            .unwrap();
        terminal_manager
            .begin_reserved_publication(&request, &request_json)
            .unwrap();
        let staging_ref = terminal_manager
            .connection
            .query_row(
                "SELECT staging_ref FROM artifact_output_allocations WHERE allocation_id=?1",
                [&request.allocation_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        let seal = seal_ref(&staging_ref);
        terminal_manager
            .artifact_store_dir
            .write(format!("{seal}.pending"), b"pending residue")
            .unwrap();
        terminal_manager
            .connection
            .execute(
                "UPDATE tasks SET state='CANCELLED' WHERE task_id='T-artifact'",
                [],
            )
            .unwrap();

        terminal_manager.reconcile_artifacts_startup().unwrap();
        assert_eq!(
            terminal_manager
                .connection
                .query_row(
                    "SELECT state FROM artifact_output_allocations WHERE allocation_id=?1",
                    [&request.allocation_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "ABORTED"
        );
        assert_eq!(
            terminal_manager
                .connection
                .query_row(
                    "SELECT state || ':' || json_extract(result_json,'$.reason_code')
                     FROM artifact_publications WHERE publication_id=?1",
                    [&request.publication_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "ABORTED:ARTIFACT_ALLOCATION_STATE_CONFLICT"
        );
        for residue in [staging_ref, seal.clone(), format!("{seal}.pending")] {
            assert!(!terminal_manager.artifact_store_root.join(residue).exists());
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "covers reserve-before-link crash, startup receipt, residue cleanup, and reopen idempotency"
    )]
    fn startup_terminalizes_publication_reserved_before_allocation_link() {
        let temp = TempDir::new().unwrap();
        let database = temp.path().join("task-manager.sqlite");
        let request = publication("pub-reserved-crash", "alloc-reserved-crash");
        let staging_ref = {
            let mut manager = manager(&temp);
            manager
                .allocate_artifact_output(&allocation(&request.allocation_id))
                .unwrap();
            write_output(
                &mut manager,
                &request.allocation_id,
                b"reserved publication crash residue",
            );
            let request_json = canonical_json(&request).unwrap();
            manager
                .reserve_publication(&request, &request_json)
                .unwrap();
            let (staging_ref, linked_publication) = manager
                .connection
                .query_row(
                    "SELECT staging_ref,publication_id FROM artifact_output_allocations
                     WHERE allocation_id=?1",
                    [&request.allocation_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
                )
                .unwrap();
            assert_eq!(linked_publication, None);
            let seal = seal_ref(&staging_ref);
            let pending_ref = format!("{seal}.pending");
            let mut pending = manager
                .artifact_store_dir
                .open_with(
                    safe_internal_ref(&pending_ref).unwrap(),
                    CapOpenOptions::new().write(true).create_new(true),
                )
                .unwrap();
            secure_cap_file_permissions(&pending).unwrap();
            pending.write_all(b"pending residue").unwrap();
            pending.sync_all().unwrap();
            manager
                .connection
                .execute(
                    "UPDATE artifact_output_allocations
                     SET expires_at='2026-09-19T21:00:00Z'
                     WHERE allocation_id=?1",
                    [&request.allocation_id],
                )
                .unwrap();
            staging_ref
        };

        let reopened = TaskManager::open_with_clock(&database, Box::new(FixedClock)).unwrap();
        let (allocation_state, linked_publication) = reopened
            .connection
            .query_row(
                "SELECT state,publication_id FROM artifact_output_allocations
                 WHERE allocation_id=?1",
                [&request.allocation_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .unwrap();
        assert_eq!(allocation_state, "EXPIRED");
        assert_eq!(
            linked_publication.as_deref(),
            Some(request.publication_id.as_str())
        );
        let (publication_state, stored_result_json) = reopened
            .connection
            .query_row(
                "SELECT state,result_json FROM artifact_publications WHERE publication_id=?1",
                [&request.publication_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .unwrap();
        assert_eq!(publication_state, "FAILED");
        let result: ArtifactPublicationResult = serde_json::from_str(&stored_result_json).unwrap();
        assert_eq!(result.reason_code, "ARTIFACT_ALLOCATION_EXPIRED");
        assert!(!result.published);
        assert_eq!(result.message, None);
        assert_eq!(canonical_json(&result).unwrap(), stored_result_json);
        let seal = seal_ref(&staging_ref);
        for residue in [staging_ref.clone(), seal.clone(), format!("{seal}.pending")] {
            assert!(!reopened.artifact_store_root.join(residue).exists());
        }
        drop(reopened);

        let reopened = TaskManager::open_with_clock(&database, Box::new(FixedClock)).unwrap();
        let replayed_result_json = reopened
            .connection
            .query_row(
                "SELECT result_json FROM artifact_publications WHERE publication_id=?1",
                [&request.publication_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        assert_eq!(replayed_result_json, stored_result_json);
        assert_eq!(
            reopened
                .connection
                .query_row(
                    "SELECT state || ':' || publication_id
                     FROM artifact_output_allocations WHERE allocation_id=?1",
                    [&request.allocation_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "EXPIRED:pub-reserved-crash"
        );
    }

    #[test]
    fn allocation_rechecks_recovery_inside_admission_transaction() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let database = temp.path().join("task-manager.sqlite");
        let request = allocation("alloc-recovery-race");
        ALLOCATION_COMMIT_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                Connection::open(database)?.execute(
                    "UPDATE tasks SET state='RECOVERING' WHERE task_id='T-artifact'",
                    [],
                )?;
                Ok(())
            }));
        });

        assert!(matches!(
            manager.allocate_artifact_output(&request),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
        assert!(
            manager
                .get_artifact_output_allocation(&request.allocation_id)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM provenance_events WHERE event_type='artifact.created'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );

        manager
            .connection
            .execute(
                "UPDATE tasks SET state='PLANNING' WHERE task_id='T-artifact'",
                [],
            )
            .unwrap();
        assert_eq!(
            manager
                .allocate_artifact_output(&request)
                .unwrap()
                .allocation_id,
            request.allocation_id
        );
    }

    #[test]
    fn publication_rechecks_recovery_before_reservation_and_preserves_staged_output() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let request = allocation("alloc-publication-recovery-race");
        manager.allocate_artifact_output(&request).unwrap();
        write_output(&mut manager, &request.allocation_id, b"publication race");
        let publication = publication("pub-publication-recovery-race", &request.allocation_id);
        let database = temp.path().join("task-manager.sqlite");
        PUBLICATION_RESERVATION_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                Connection::open(database)?.execute(
                    "UPDATE tasks SET state='RECOVERING' WHERE task_id='T-artifact'",
                    [],
                )?;
                Ok(())
            }));
        });

        let denied = manager.publish_artifact_output(&publication).unwrap();
        assert!(!denied.published);
        assert_eq!(denied.reason_code, "ARTIFACT_AUTHORITY_DENIED");
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM artifact_publications WHERE publication_id=?1",
                    [&publication.publication_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            manager
                .get_artifact_output_allocation(&request.allocation_id)
                .unwrap()
                .unwrap()
                .state,
            ArtifactAllocationState::Writing
        );
        assert_no_created_artifact_metadata(&manager);

        manager
            .connection
            .execute(
                "UPDATE tasks SET state='PLANNING' WHERE task_id='T-artifact'",
                [],
            )
            .unwrap();
        let committed = manager.publish_artifact_output(&publication).unwrap();
        assert!(committed.published);
        manager
            .connection
            .execute(
                "UPDATE tasks SET state='RECOVERING' WHERE task_id='T-artifact'",
                [],
            )
            .unwrap();
        assert_eq!(
            manager.publish_artifact_output(&publication).unwrap(),
            committed
        );
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM artifacts WHERE artifact_id=?1",
                    [committed.artifact_id.as_deref().unwrap()],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn publication_rechecks_recovery_after_blob_placement_before_final_commit() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let request = allocation("alloc-publication-final-race");
        manager.allocate_artifact_output(&request).unwrap();
        write_output(
            &mut manager,
            &request.allocation_id,
            b"final publication race",
        );
        let staging_ref = load_allocation_row(&manager.connection, &request.allocation_id)
            .unwrap()
            .unwrap()
            .staging_ref
            .unwrap();
        let publication = publication("pub-publication-final-race", &request.allocation_id);
        let database = temp.path().join("task-manager.sqlite");
        PUBLICATION_COMMIT_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                Connection::open(database)?.execute(
                    "UPDATE tasks SET state='RECOVERING' WHERE task_id='T-artifact'",
                    [],
                )?;
                Ok(())
            }));
        });

        assert!(matches!(
            manager.publish_artifact_output(&publication),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
        assert_no_created_artifact_metadata(&manager);
        assert_eq!(
            manager
                .connection
                .query_row("SELECT COUNT(*) FROM artifact_blobs", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
        assert_eq!(
            physical_blob_refs(&manager.artifact_store_dir).unwrap(),
            Vec::<String>::new()
        );
        assert!(
            resolve_internal_ref(&manager.artifact_store_root, &staging_ref)
                .unwrap()
                .is_file()
        );
        assert!(
            resolve_internal_ref(&manager.artifact_store_root, &seal_ref(&staging_ref))
                .unwrap()
                .is_file()
        );
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT state || ':' || COALESCE(result_json,'') FROM artifact_publications WHERE publication_id=?1",
                    [&publication.publication_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "PENDING:"
        );
        assert_eq!(
            manager
                .get_artifact_output_allocation(&request.allocation_id)
                .unwrap()
                .unwrap()
                .state,
            ArtifactAllocationState::Finalizing
        );
        manager
            .connection
            .execute(
                "UPDATE tasks SET state='PLANNING' WHERE task_id='T-artifact'",
                [],
            )
            .unwrap();
        assert!(
            manager
                .publish_artifact_output(&publication)
                .unwrap()
                .published
        );
    }

    #[test]
    fn export_success_commit_rechecks_recovery_after_destination_finalize() {
        let temp = TempDir::new().unwrap();
        let database = temp.path().join("task-manager.sqlite");
        let mut manager = manager(&temp);
        let artifact = manager
            .import_artifact(
                &import_request(),
                &mut Cursor::new(b"export recovery race".as_slice()),
            )
            .unwrap();
        let scope = manager
            .scope_owned_artifact_reads("T-artifact", std::slice::from_ref(&artifact.artifact_id))
            .unwrap();
        let mut destination = manager
            .issue_owned_artifact_export_destination(
                &scope,
                "export-recovery-commit-race",
                &artifact.artifact_id,
                "user-selected-file",
                1_024,
                deferred(Vec::new()),
            )
            .unwrap();
        EXPORT_COMPLETION_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                Connection::open(database)?.execute(
                    "UPDATE tasks SET state='RECOVERING' WHERE task_id='T-artifact'",
                    [],
                )?;
                Ok(())
            }));
        });

        assert!(matches!(
            manager.export_artifact(&scope, &artifact.artifact_id, &mut destination),
            Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_OUTCOME_UNKNOWN"
            ))
        ));
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT state || ':' || outcome_certainty FROM operations WHERE operation_id='export-recovery-commit-race'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "UNKNOWN:OUTCOME_UNKNOWN"
        );
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM provenance_events WHERE event_id=?1",
                    [event_id("artifact-exported", "export-recovery-commit-race")],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn cached_export_proofs_are_rejected_by_challenge_independent_of_clock_skew() {
        for (suffix, observed_at) in [
            ("behind", "2020-01-01T00:00:00Z"),
            ("ahead", "2035-01-01T00:00:00Z"),
        ] {
            let temp = TempDir::new().unwrap();
            let mut stale = export_no_effect_verifier(
                "user-selected-file",
                &format!("evidence:cached-{suffix}"),
                if suffix == "behind" { 'e' } else { 'f' },
            );
            stale.observed_at = observed_at.to_owned();
            *stale.challenge_override.lock().unwrap() =
                Some("challenge:v1:cached-before-effect".to_owned());
            let verifier = Arc::new(stale);
            let mut manager = manager_with_export_verifiers(&temp, vec![verifier.clone()]);
            let artifact = manager
                .import_artifact(
                    &import_request(),
                    &mut Cursor::new(b"resolve me".as_slice()),
                )
                .unwrap();
            let scope = manager
                .scope_owned_artifact_reads("T-artifact", &[artifact.artifact_id.clone()])
                .unwrap();
            let operation_id = format!("export-owner-resolution-{suffix}");
            let mut destination = manager
                .issue_owned_artifact_export_destination(
                    &scope,
                    &operation_id,
                    &artifact.artifact_id,
                    "user-selected-file",
                    1_024,
                    deferred(FinalizeFailureWriter::default()),
                )
                .unwrap();
            assert!(
                manager
                    .export_artifact(&scope, &artifact.artifact_id, &mut destination)
                    .is_err()
            );
            assert!(matches!(
                manager.reconcile_unknown_artifact_export_no_effect(&operation_id),
                Err(TaskManagerError::InvalidRecord(
                    "Artifact export reconciliation proof does not match its immutable subject and challenge"
                ))
            ));
            assert_eq!(
                manager
                    .connection
                    .query_row(
                        "SELECT state || ':' || outcome_certainty FROM operations WHERE operation_id=?1",
                        [&operation_id],
                        |row| row.get::<_, String>(0),
                    )
                    .unwrap(),
                "UNKNOWN:OUTCOME_UNKNOWN"
            );
            let challenge = manager
                .connection
                .query_row(
                    "SELECT challenge FROM artifact_export_reconciliation_challenges WHERE operation_id=?1",
                    [&operation_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap();
            *verifier.challenge_override.lock().unwrap() = None;
            manager
                .reconcile_unknown_artifact_export_no_effect(&operation_id)
                .unwrap();
            assert_eq!(
                manager
                    .connection
                    .query_row(
                        "SELECT challenge FROM artifact_export_reconciliation_challenges WHERE operation_id=?1",
                        [&operation_id],
                        |row| row.get::<_, String>(0),
                    )
                    .unwrap(),
                challenge
            );
        }
    }

    #[test]
    fn export_reconciliation_rejects_cross_challenge_replay() {
        let temp = TempDir::new().unwrap();
        let verifier = Arc::new(export_no_effect_verifier(
            "user-selected-file",
            "evidence:challenge-bound",
            'b',
        ));
        let mut manager = manager_with_export_verifiers(&temp, vec![verifier.clone()]);
        let artifact = manager
            .import_artifact(
                &import_request(),
                &mut Cursor::new(b"challenge bytes".as_slice()),
            )
            .unwrap();
        for operation_id in ["export-challenge-first", "export-challenge-second"] {
            let scope = manager
                .scope_owned_artifact_reads("T-artifact", &[artifact.artifact_id.clone()])
                .unwrap();
            let mut destination = manager
                .issue_owned_artifact_export_destination(
                    &scope,
                    operation_id,
                    &artifact.artifact_id,
                    "user-selected-file",
                    1_024,
                    deferred(FinalizeFailureWriter::default()),
                )
                .unwrap();
            assert!(
                manager
                    .export_artifact(&scope, &artifact.artifact_id, &mut destination)
                    .is_err()
            );
            if operation_id.ends_with("first") {
                manager
                    .reconcile_unknown_artifact_export_no_effect(operation_id)
                    .unwrap();
                let first_challenge = manager
                    .connection
                    .query_row(
                        "SELECT challenge FROM artifact_export_reconciliation_challenges WHERE operation_id=?1",
                        [operation_id],
                        |row| row.get::<_, String>(0),
                    )
                    .unwrap();
                *verifier.challenge_override.lock().unwrap() = Some(first_challenge);
            } else {
                assert!(matches!(
                    manager.reconcile_unknown_artifact_export_no_effect(operation_id),
                    Err(TaskManagerError::InvalidRecord(
                        "Artifact export reconciliation proof does not match its immutable subject and challenge"
                    ))
                ));
            }
        }
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(DISTINCT challenge) FROM artifact_export_reconciliation_challenges",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            2
        );
    }

    #[test]
    fn reconciliation_checks_full_provenance_before_persisting_challenge() {
        let temp = TempDir::new().unwrap();
        let verifier = Arc::new(export_no_effect_verifier(
            "user-selected-file",
            "evidence:tampered-chain",
            'c',
        ));
        let mut manager = manager_with_export_verifiers(&temp, vec![verifier]);
        let artifact = manager
            .import_artifact(
                &import_request(),
                &mut Cursor::new(b"tamper fence".as_slice()),
            )
            .unwrap();
        let scope = manager
            .scope_owned_artifact_reads("T-artifact", &[artifact.artifact_id.clone()])
            .unwrap();
        let mut destination = manager
            .issue_owned_artifact_export_destination(
                &scope,
                "export-tampered-chain",
                &artifact.artifact_id,
                "user-selected-file",
                1_024,
                deferred(FinalizeFailureWriter::default()),
            )
            .unwrap();
        assert!(
            manager
                .export_artifact(&scope, &artifact.artifact_id, &mut destination)
                .is_err()
        );
        manager
            .connection
            .execute_batch(
                "DROP TRIGGER provenance_events_no_update;
                 UPDATE provenance_events SET event_json=json_set(event_json,'$.status','failure')
                 WHERE task_id='T-artifact' AND sequence=1;",
            )
            .unwrap();
        assert!(matches!(
            manager.reconcile_unknown_artifact_export_no_effect("export-tampered-chain"),
            Err(TaskManagerError::InvalidRecord(
                "Artifact export reconciliation requires an intact provenance chain"
            ))
        ));
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT (SELECT COUNT(*) FROM artifact_export_reconciliation_challenges) || ':' ||
                            (SELECT state || ':' || outcome_certainty FROM operations WHERE operation_id='export-tampered-chain')",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "0:UNKNOWN:OUTCOME_UNKNOWN"
        );
    }

    #[test]
    fn reconciled_no_effect_replay_requires_its_authenticated_provenance_and_assessment() {
        for tamper in ["event", "assessment"] {
            let temp = TempDir::new().unwrap();
            let verifier = Arc::new(export_no_effect_verifier(
                "user-selected-file",
                "evidence:authenticated-replay",
                'a',
            ));
            let mut manager = manager_with_export_verifiers(&temp, vec![verifier]);
            let artifact = manager
                .import_artifact(
                    &import_request(),
                    &mut Cursor::new(b"authenticated replay".as_slice()),
                )
                .unwrap();
            let scope = manager
                .scope_owned_artifact_reads(
                    "T-artifact",
                    std::slice::from_ref(&artifact.artifact_id),
                )
                .unwrap();
            let operation_id = format!("export-reconciled-tamper-{tamper}");
            let mut destination = manager
                .issue_owned_artifact_export_destination(
                    &scope,
                    &operation_id,
                    &artifact.artifact_id,
                    "user-selected-file",
                    1_024,
                    deferred(FinalizeFailureWriter::default()),
                )
                .unwrap();
            assert!(
                manager
                    .export_artifact(&scope, &artifact.artifact_id, &mut destination)
                    .is_err()
            );
            manager
                .reconcile_unknown_artifact_export_no_effect(&operation_id)
                .unwrap();
            if tamper == "event" {
                manager
                    .connection
                    .execute_batch(
                        "DROP TRIGGER provenance_events_no_delete;
                         DELETE FROM provenance_events
                         WHERE event_type='execution.completed'
                           AND json_extract(event_json,'$.details.export_reconciliation') IS NOT NULL;",
                    )
                    .unwrap();
            } else {
                manager
                    .connection
                    .execute(
                        "DELETE FROM recovery_assessments
                         WHERE subject_kind='external-operation' AND subject_id=?1",
                        [format!("operation:{operation_id}")],
                    )
                    .unwrap();
            }
            let mut replay = manager
                .issue_owned_artifact_export_destination(
                    &scope,
                    &operation_id,
                    &artifact.artifact_id,
                    "user-selected-file",
                    1_024,
                    deferred(Vec::new()),
                )
                .unwrap();
            assert!(matches!(
                manager.export_artifact(&scope, &artifact.artifact_id, &mut replay),
                Err(TaskManagerError::InvalidRecord(
                    "stored Artifact export reconciliation is invalid"
                ))
            ));
            assert!(replay.writer.is_none());
            let opened = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&opened);
            let mut fresh = manager
                .issue_owned_artifact_export_destination(
                    &scope,
                    &format!("export-after-reconciled-tamper-{tamper}"),
                    &artifact.artifact_id,
                    "user-selected-file",
                    1_024,
                    move || {
                        observed.fetch_add(1, Ordering::SeqCst);
                        Ok(Vec::new())
                    },
                )
                .unwrap();
            assert!(matches!(
                manager.export_artifact(&scope, &artifact.artifact_id, &mut fresh),
                Err(TaskManagerError::InvalidRecord(
                    "stored Artifact export reconciliation is invalid"
                ))
            ));
            assert_eq!(opened.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn public_reconciliation_replay_authenticates_denormalized_operation_context() {
        for (index, (column, forged)) in [
            (
                "semantic_program_hash",
                "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
            ("node_id", "forged-node"),
            ("binding_id", "forged-binding"),
            ("attempt_id", "forged-attempt"),
        ]
        .into_iter()
        .enumerate()
        {
            let temp = TempDir::new().unwrap();
            let verifier = Arc::new(export_no_effect_verifier(
                "user-selected-file",
                "evidence:context-bound-replay",
                char::from_digit(u32::try_from(index + 1).unwrap(), 16).unwrap(),
            ));
            let mut manager = manager_with_export_verifiers(&temp, vec![verifier.clone()]);
            let artifact = manager
                .import_artifact(
                    &import_request(),
                    &mut Cursor::new(b"context-bound replay".as_slice()),
                )
                .unwrap();
            let scope = manager
                .scope_owned_artifact_reads(
                    "T-artifact",
                    std::slice::from_ref(&artifact.artifact_id),
                )
                .unwrap();
            let operation_id = format!("export-context-tamper-{index}");
            let mut destination = manager
                .issue_owned_artifact_export_destination(
                    &scope,
                    &operation_id,
                    &artifact.artifact_id,
                    "user-selected-file",
                    1_024,
                    deferred(FinalizeFailureWriter::default()),
                )
                .unwrap();
            assert!(
                manager
                    .export_artifact(&scope, &artifact.artifact_id, &mut destination)
                    .is_err()
            );
            manager
                .reconcile_unknown_artifact_export_no_effect(&operation_id)
                .unwrap();
            manager
                .connection
                .execute_batch("PRAGMA foreign_keys=OFF;")
                .unwrap();
            manager
                .connection
                .execute(
                    &format!("UPDATE operations SET {column}=?2 WHERE operation_id=?1"),
                    params![operation_id, forged],
                )
                .unwrap();
            manager
                .connection
                .execute_batch("PRAGMA foreign_keys=ON;")
                .unwrap();

            assert!(matches!(
                manager.reconcile_unknown_artifact_export_no_effect(&operation_id),
                Err(TaskManagerError::InvalidRecord(
                    "ARTIFACT_EXPORT_OPERATION_ID_REUSE_CONFLICT"
                ))
            ));
            assert_eq!(verifier.calls.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn export_verifier_registry_is_fixed_and_rejects_ambiguous_destination_owners() {
        let temp = TempDir::new().unwrap();
        let first = Arc::new(export_no_effect_verifier(
            "user-selected-file",
            "evidence:first",
            '1',
        ));
        let second = Arc::new(export_no_effect_verifier(
            "user-selected-file",
            "evidence:second",
            '2',
        ));
        assert!(matches!(
            TaskManager::open_with_clock_and_export_verifiers(
                temp.path().join("task-manager.sqlite"),
                Box::new(FixedClock),
                vec![first, second],
            ),
            Err(TaskManagerError::InvalidRecord(
                "duplicate Artifact export reconciliation destination adapter"
            ))
        ));
    }

    #[test]
    fn owner_export_unknowns_have_inventory_without_changing_nonexecuting_lifecycle_states() {
        for (index, state) in [
            "CREATED",
            "PLANNING",
            "RUNNABLE",
            "WAITING_FOR_INPUT",
            "WAITING_FOR_AUTH",
        ]
        .into_iter()
        .enumerate()
        {
            let temp = TempDir::new().unwrap();
            let verifier = Arc::new(export_no_effect_verifier(
                "user-selected-file",
                &format!("evidence:state-{index}"),
                char::from_digit(u32::try_from(index + 1).unwrap(), 16).unwrap(),
            ));
            let mut manager = manager_with_export_verifiers(&temp, vec![verifier]);
            let artifact = manager
                .import_artifact(
                    &import_request(),
                    &mut Cursor::new(format!("state export {state}").into_bytes()),
                )
                .unwrap();
            let scope = manager
                .scope_owned_artifact_reads("T-artifact", &[artifact.artifact_id.clone()])
                .unwrap();
            manager
                .connection
                .execute(
                    "UPDATE tasks SET state=?1 WHERE task_id='T-artifact'",
                    [state],
                )
                .unwrap();
            let operation_id = format!("export-state-{index}");
            let mut destination = manager
                .issue_owned_artifact_export_destination(
                    &scope,
                    &operation_id,
                    &artifact.artifact_id,
                    "user-selected-file",
                    1_024,
                    deferred(FinalizeFailureWriter::default()),
                )
                .unwrap();
            assert!(
                manager
                    .export_artifact(&scope, &artifact.artifact_id, &mut destination)
                    .is_err()
            );
            assert_eq!(
                manager
                    .connection
                    .query_row(
                        "SELECT state FROM tasks WHERE task_id='T-artifact'",
                        [],
                        |row| row.get::<_, String>(0),
                    )
                    .unwrap(),
                state
            );
            assert_eq!(
                manager
                    .connection
                    .query_row(
                        "SELECT COUNT(*) FROM recovery_unknown_operations WHERE operation_id=?1",
                        [format!("operation:{operation_id}")],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                1
            );
            manager
                .reconcile_unknown_artifact_export_no_effect(&operation_id)
                .unwrap();
            assert_eq!(
                manager
                    .connection
                    .query_row(
                        "SELECT state FROM tasks WHERE task_id='T-artifact'",
                        [],
                        |row| row.get::<_, String>(0),
                    )
                    .unwrap(),
                state
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "covers terminal immutable recovery inventory, exact proof release, and cross-operation proof replay"
    )]
    fn terminal_owner_export_reconciliation_preserves_state_and_rejects_proof_replay() {
        let temp = TempDir::new().unwrap();
        let first_proof = Arc::new(export_no_effect_verifier(
            "terminal-file-one",
            "evidence:terminal-first",
            'd',
        ));
        let mut second_proof =
            export_no_effect_verifier("terminal-file-two", "evidence:terminal-first", 'e');
        second_proof.verifier_id = "adapter:independent-destination-status";
        let mut manager =
            manager_with_export_verifiers(&temp, vec![first_proof.clone(), Arc::new(second_proof)]);
        let artifact = manager
            .import_artifact(
                &import_request(),
                &mut Cursor::new(b"retained terminal bytes".as_slice()),
            )
            .unwrap();
        manager
            .connection
            .execute(
                "UPDATE tasks SET state='COMPLETED',completed_at='2026-09-19T22:00:00Z'
                 WHERE task_id='T-artifact'",
                [],
            )
            .unwrap();
        let scope = manager
            .scope_owned_artifact_reads("T-artifact", &[artifact.artifact_id.clone()])
            .unwrap();
        let mut first = manager
            .issue_owned_artifact_export_destination(
                &scope,
                "export-terminal-first",
                &artifact.artifact_id,
                "terminal-file-one",
                1_024,
                deferred(FinalizeFailureWriter::default()),
            )
            .unwrap();
        assert!(matches!(
            manager.export_artifact(&scope, &artifact.artifact_id, &mut first),
            Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_OUTCOME_UNKNOWN"
            ))
        ));
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT state || ':' || (recovery_json IS NULL) FROM tasks WHERE task_id='T-artifact'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "COMPLETED:1"
        );
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM recovery_unknown_operations
                     WHERE operation_id='operation:export-terminal-first'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert!(matches!(
            manager.scope_owned_artifact_reads("T-artifact", &[artifact.artifact_id.clone()]),
            Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_OUTCOME_UNKNOWN"
            ))
        ));

        manager
            .reconcile_unknown_artifact_export_no_effect("export-terminal-first")
            .unwrap();
        assert_eq!(first_proof.calls.load(Ordering::SeqCst), 1);
        manager
            .reconcile_unknown_artifact_export_no_effect("export-terminal-first")
            .unwrap();
        let second_scope = manager
            .scope_owned_artifact_reads("T-artifact", &[artifact.artifact_id.clone()])
            .unwrap();
        let mut reader = manager
            .open_artifact_reader(&second_scope, &artifact.artifact_id)
            .unwrap();
        let mut retained = Vec::new();
        reader.read_to_end(&mut retained).unwrap();
        assert_eq!(retained, b"retained terminal bytes");
        drop(reader);
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT state FROM tasks WHERE task_id='T-artifact'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "COMPLETED"
        );

        let mut second = manager
            .issue_owned_artifact_export_destination(
                &second_scope,
                "export-terminal-second",
                &artifact.artifact_id,
                "terminal-file-two",
                1_024,
                deferred(FinalizeFailureWriter::default()),
            )
            .unwrap();
        assert!(matches!(
            manager.export_artifact(&second_scope, &artifact.artifact_id, &mut second),
            Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_OUTCOME_UNKNOWN"
            ))
        ));
        assert!(matches!(
            manager.reconcile_unknown_artifact_export_no_effect("export-terminal-second"),
            Ok(()),
        ));
        assert!(matches!(
            manager.reconcile_unknown_artifact_export_no_effect("export-terminal-second"),
            Ok(()),
        ));
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT state || ':' || outcome_certainty FROM operations
                     WHERE operation_id='export-terminal-second'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "FAILED:FAILED_NO_EFFECT"
        );
        assert!(
            manager
                .scope_owned_artifact_reads("T-artifact", &[artifact.artifact_id])
                .is_ok()
        );
    }

    #[test]
    fn authority_is_rechecked_before_effectful_destination_finalize() {
        let temp = TempDir::new().unwrap();
        let database = temp.path().join("task-manager.sqlite");
        let mut manager = manager(&temp);
        let artifact = manager
            .import_artifact(
                &import_request(),
                &mut Cursor::new(b"final fence".as_slice()),
            )
            .unwrap();
        let scope = manager
            .scope_owned_artifact_reads("T-artifact", &[artifact.artifact_id.clone()])
            .unwrap();
        let finalized = Arc::new(AtomicUsize::new(0));
        let mut destination = manager
            .issue_owned_artifact_export_destination(
                &scope,
                "export-pre-finalize-fence",
                &artifact.artifact_id,
                "user-selected-file",
                1_024,
                deferred(FinalizeTrackingWriter {
                    finalized: Arc::clone(&finalized),
                }),
            )
            .unwrap();
        EXPORT_PRE_FINALIZE_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                Connection::open(database)?.execute(
                    "UPDATE tasks SET principal_id='user:revoked-before-finalize' WHERE task_id='T-artifact'",
                    [],
                )?;
                Ok(())
            }));
        });

        assert!(matches!(
            manager.export_artifact(&scope, &artifact.artifact_id, &mut destination),
            Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_OUTCOME_UNKNOWN"
            ))
        ));
        assert_eq!(finalized.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn empty_export_successful_flush_then_failed_final_fence_is_unknown() {
        let temp = TempDir::new().unwrap();
        let database = temp.path().join("task-manager.sqlite");
        let mut manager = manager(&temp);
        let artifact = manager
            .import_artifact(&import_request(), &mut Cursor::new([]))
            .unwrap();
        let scope = manager
            .scope_owned_artifact_reads("T-artifact", &[artifact.artifact_id.clone()])
            .unwrap();
        let mut destination = manager
            .issue_owned_artifact_export_destination(
                &scope,
                "export-empty-final-fence",
                &artifact.artifact_id,
                "user-selected-file",
                1_024,
                deferred(AuthorityRevokingWriter {
                    database,
                    flushed: false,
                }),
            )
            .unwrap();

        assert!(matches!(
            manager.export_artifact(&scope, &artifact.artifact_id, &mut destination),
            Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_OUTCOME_UNKNOWN"
            ))
        ));
        assert!(destination.writer.as_ref().unwrap().flushed);
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT state || ':' || outcome_certainty FROM operations WHERE operation_id='export-empty-final-fence'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "UNKNOWN:OUTCOME_UNKNOWN"
        );
    }

    #[test]
    fn crash_after_export_copy_reopens_as_unknown_and_cannot_retransfer() {
        let temp = TempDir::new().unwrap();
        let database = temp.path().join("task-manager.sqlite");
        let mut manager = manager(&temp);
        let artifact = manager
            .import_artifact(&import_request(), &mut Cursor::new(b"escaped".as_slice()))
            .unwrap();
        let (binding_id, _) = install_one_shot_binding(
            &manager,
            "export-crash",
            std::slice::from_ref(&artifact.artifact_id),
            &[
                ("artifact.read", "artifact", &artifact.artifact_id),
                ("data.egress", "destination", "user-selected-file"),
            ],
        );
        let session = manager
            .issue_provider_artifact_session("T-artifact", &binding_id)
            .unwrap();
        let scope = manager
            .scope_artifact_reads(&session, std::slice::from_ref(&artifact.artifact_id))
            .unwrap();
        let mut destination = manager
            .issue_bound_artifact_export_destination(
                &session,
                &scope,
                "export-crash-window",
                &artifact.artifact_id,
                "user-selected-file",
                1_024,
                deferred(Vec::new()),
            )
            .unwrap();
        EXPORT_COMPLETION_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(|| panic!("injected process crash")));
        });
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = manager.export_artifact(&scope, &artifact.artifact_id, &mut destination);
            }))
            .is_err()
        );
        assert_eq!(destination.writer.as_deref(), Some(b"escaped".as_slice()));
        assert!(matches!(
            manager.export_artifact(&scope, &artifact.artifact_id, &mut destination),
            Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_OUTCOME_UNKNOWN"
            ))
        ));
        assert_eq!(destination.writer.as_deref(), Some(b"escaped".as_slice()));
        manager
            .connection
            .execute_batch(
                "UPDATE step_executions
                 SET state='SUCCEEDED',outcome_certainty='COMPLETED',finished_at='2026-09-19T22:00:00Z'
                 WHERE attempt_id='attempt-export-crash';
                 UPDATE tasks SET state='COMPLETED',completed_at='2026-09-19T22:00:00Z'
                 WHERE task_id='T-artifact';",
            )
            .unwrap();
        drop(destination);
        drop(manager);

        let reopened = TaskManager::open_with_clock(database, Box::new(FixedClock)).unwrap();
        assert_eq!(
            reopened
                .connection
                .query_row(
                    "SELECT state || ':' || outcome_certainty FROM operations WHERE operation_id='export-crash-window'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "UNKNOWN:OUTCOME_UNKNOWN"
        );
        assert_eq!(
            reopened
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM provenance_events WHERE event_type='artifact.exported'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn publication_is_idempotent_and_same_bytes_keep_distinct_artifacts() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let source = manager
            .import_artifact(&import_request(), &mut Cursor::new(b"source".as_slice()))
            .unwrap();
        let stored_allocation = manager
            .allocate_artifact_output(&allocation("alloc-1"))
            .unwrap();
        assert_matches_schema("artifact-output-allocation.schema.json", &stored_allocation);
        write_output(&mut manager, "alloc-1", b"# report\n");
        let mut request = publication("pub-1", "alloc-1");
        request.lineage.input_artifact_ids = vec![source.artifact_id.clone()];
        request.lineage.derived_from_artifact_ids = vec![source.artifact_id.clone()];
        let first = manager.publish_artifact_output(&request).unwrap();
        assert_matches_schema("artifact-publication-request.schema.json", &request);
        assert_matches_schema("artifact-publication-result.schema.json", &first);
        let provenance_count = manager.provenance_count("T-artifact").unwrap();
        drop(manager);
        let mut manager = TaskManager::open_with_clock(
            temp.path().join("task-manager.sqlite"),
            Box::new(FixedClock),
        )
        .unwrap();
        assert_eq!(manager.publish_artifact_output(&request).unwrap(), first);
        assert_eq!(
            manager.provenance_count("T-artifact").unwrap(),
            provenance_count
        );

        let mut incompatible = request.clone();
        incompatible.labels.push("changed".to_owned());
        let conflict = manager.publish_artifact_output(&incompatible).unwrap();
        assert!(!conflict.published);
        assert_eq!(
            conflict.reason_code,
            "ARTIFACT_PUBLICATION_ID_REUSE_CONFLICT"
        );
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM artifact_lineage WHERE parent_artifact_id=?1 AND child_artifact_id=?2 AND relationship IN ('consumed-by','transformed-to')",
                    params![source.artifact_id, first.artifact_id.as_deref()],
                    |row| row.get::<_,i64>(0),
                )
                .unwrap(),
            2
        );

        manager
            .allocate_artifact_output(&allocation("alloc-2"))
            .unwrap();
        write_output(&mut manager, "alloc-2", b"# report\n");
        let second = manager
            .publish_artifact_output(&publication("pub-2", "alloc-2"))
            .unwrap();
        assert_ne!(first.artifact_id, second.artifact_id);
        assert_eq!(first.content_hash, second.content_hash);
        assert_eq!(second.blob_reused, Some(true));
    }

    #[test]
    fn allocation_writer_is_bounded_and_storage_refs_cannot_escape() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let mut small = allocation("alloc-small");
        small.max_size_bytes = Some(3);
        manager.allocate_artifact_output(&small).unwrap();
        let mut writer = manager.open_artifact_output("alloc-small").unwrap();
        assert_eq!(
            writer.write_all(b"four").unwrap_err().kind(),
            std::io::ErrorKind::FileTooLarge
        );
        assert!(manager.get_artifact("anything").unwrap().is_none());

        manager
            .allocate_artifact_output(&allocation("alloc-escape"))
            .unwrap();
        manager
            .connection
            .execute(
                "UPDATE artifact_output_allocations SET staging_ref='../escape' WHERE allocation_id='alloc-escape'",
                [],
            )
            .unwrap();
        assert!(matches!(
            manager.open_artifact_output("alloc-escape"),
            Err(TaskManagerError::InvalidRecord(
                "Artifact storage reference escaped store root"
            ))
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "covers independent publication preflight failures and durable receipts"
    )]
    fn publication_rejects_media_semantic_and_final_size_mismatches() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);

        manager
            .allocate_artifact_output(&allocation("alloc-media"))
            .unwrap();
        write_output(&mut manager, "alloc-media", b"bytes");
        let mut wrong_media = publication("pub-media", "alloc-media");
        wrong_media.media_type = "image/png".to_owned();
        assert_eq!(
            manager
                .publish_artifact_output(&wrong_media)
                .unwrap()
                .reason_code,
            "ARTIFACT_MEDIA_TYPE_MISMATCH"
        );

        manager
            .allocate_artifact_output(&allocation("alloc-semantic"))
            .unwrap();
        write_output(&mut manager, "alloc-semantic", b"bytes");
        let mut wrong_semantic = publication("pub-semantic", "alloc-semantic");
        wrong_semantic.semantic_type = Some("artifact.image@1".to_owned());
        assert_eq!(
            manager
                .publish_artifact_output(&wrong_semantic)
                .unwrap()
                .reason_code,
            "ARTIFACT_SEMANTIC_TYPE_MISMATCH"
        );

        let mut size_limited = allocation("alloc-final-size");
        size_limited.max_size_bytes = Some(3);
        manager.allocate_artifact_output(&size_limited).unwrap();
        // Simulate a compromised projection that bypassed the bounded writer;
        // trusted finalization must still enforce the durable allocation limit.
        let staging_ref = manager
            .connection
            .query_row(
                "SELECT staging_ref FROM artifact_output_allocations WHERE allocation_id='alloc-final-size'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        std::fs::write(
            resolve_internal_ref(&manager.artifact_store_root, &staging_ref).unwrap(),
            b"oversized",
        )
        .unwrap();
        write_manual_seal(&manager, "alloc-final-size", &staging_ref);
        manager
            .connection
            .execute(
                "UPDATE artifact_output_allocations SET state='WRITING' WHERE allocation_id='alloc-final-size'",
                [],
            )
            .unwrap();
        assert_eq!(
            manager
                .publish_artifact_output(&publication("pub-size", "alloc-final-size"))
                .unwrap()
                .reason_code,
            "ARTIFACT_SIZE_LIMIT"
        );
        assert_eq!(
            manager
                .connection
                .query_row("SELECT COUNT(*) FROM artifacts", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );

        manager
            .allocate_artifact_output(&allocation("alloc-lineage"))
            .unwrap();
        write_output(&mut manager, "alloc-lineage", b"bytes");
        let mut unauthorized = publication("pub-lineage", "alloc-lineage");
        unauthorized.lineage.derived_from_artifact_ids = vec!["artifact:foreign".to_owned()];
        assert_eq!(
            manager
                .publish_artifact_output(&unauthorized)
                .unwrap()
                .reason_code,
            "ARTIFACT_AUTHORITY_DENIED"
        );
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM artifact_publications WHERE publication_id='pub-lineage'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT state FROM artifact_publications WHERE publication_id='pub-lineage'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "FAILED"
        );
    }

    #[test]
    fn request_validation_enforces_semantic_grammar_value_bounds_and_supported_lineage() {
        for invalid in [
            "Artifact.report@1",
            "artifact/report@1",
            "artifact.report",
            "artifact.report@",
            "artifact.report@01",
            "artifact.report@1.0",
            "artifact.report@1@2",
            "1artifact@1",
        ] {
            let mut request = import_request();
            request.semantic_type = Some(invalid.to_owned());
            assert!(
                validate_import_request(&request).is_err(),
                "accepted {invalid}"
            );
        }
        let mut valid = import_request();
        valid.semantic_type = Some("artifact.report_v2@0".to_owned());
        validate_import_request(&valid).unwrap();
        valid.semantic_type = Some(String::new());
        validate_import_request(&valid).unwrap();
        let mut empty_allocation = allocation("alloc-empty-semantic-type");
        empty_allocation.expected_semantic_type = Some(String::new());
        validate_allocation_request_shape(&empty_allocation).unwrap();
        let mut empty_publication = publication(
            "publication-empty-semantic-type",
            "alloc-empty-semantic-type",
        );
        empty_publication.semantic_type = Some(String::new());
        validate_publication_request(&empty_publication).unwrap();

        let mut oversized_format = import_request();
        oversized_format.format = Some("x".repeat(161));
        assert!(validate_import_request(&oversized_format).is_err());
        let mut oversized_label = import_request();
        oversized_label.labels = vec!["x".repeat(257)];
        assert!(validate_import_request(&oversized_label).is_err());
        let mut malformed_expiry = import_request();
        malformed_expiry.expires_at = Some("2026-09-19 22:00:00".to_owned());
        assert!(validate_import_request(&malformed_expiry).is_err());

        let mut publication = publication("pub-validation", "alloc-validation");
        publication.lineage.input_artifact_ids = vec!["a".repeat(513)];
        assert!(validate_publication_request(&publication).is_err());
        publication.lineage.input_artifact_ids.clear();
        publication.lineage.representation_of_object_ids =
            vec!["object://workspace/example".to_owned()];
        assert!(validate_publication_request(&publication).is_err());
        publication.lineage.representation_of_object_ids = vec!["o".repeat(1_025)];
        assert!(validate_publication_request(&publication).is_err());
    }

    #[test]
    fn bound_lineage_is_limited_to_exact_attempt_inputs_and_origin_records_provider() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let authorized = manager
            .import_artifact(
                &import_request(),
                &mut Cursor::new(b"authorized".as_slice()),
            )
            .unwrap();
        let unrelated = manager
            .import_artifact(&import_request(), &mut Cursor::new(b"unrelated".as_slice()))
            .unwrap();
        let allocation_id = "alloc-exact-lineage";
        let (binding_id, attempt_id) = install_one_shot_binding(
            &manager,
            "exact-lineage",
            std::slice::from_ref(&authorized.artifact_id),
            &[("artifact.write", "output-allocation", allocation_id)],
        );
        let mut request = allocation(allocation_id);
        request.binding_id = Some(binding_id);
        request.attempt_id = Some(attempt_id);
        allocate_bound(&mut manager, &request);
        let mut writer = open_bound(&mut manager, allocation_id);
        writer.write_all(b"result").unwrap();
        writer.finish().unwrap();

        let mut publish = publication("pub-exact-lineage", allocation_id);
        publish.lineage.derived_from_artifact_ids = vec![unrelated.artifact_id];
        let denied = publish_bound(&mut manager, &publish).unwrap();
        assert!(!denied.published);
        assert_eq!(denied.reason_code, "ARTIFACT_AUTHORITY_DENIED");
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM artifact_publications WHERE publication_id='pub-exact-lineage'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(publish_bound(&mut manager, &publish).unwrap(), denied);

        publish.lineage.derived_from_artifact_ids = vec![authorized.artifact_id];
        let conflict = publish_bound(&mut manager, &publish).unwrap();
        assert!(!conflict.published);
        assert_eq!(
            conflict.reason_code,
            "ARTIFACT_PUBLICATION_ID_REUSE_CONFLICT"
        );

        let positive_temp = TempDir::new().unwrap();
        let mut positive = self::manager(&positive_temp);
        let source = positive
            .import_artifact(&import_request(), &mut Cursor::new(b"source".as_slice()))
            .unwrap();
        let positive_allocation = "alloc-exact-lineage-positive";
        let (binding_id, attempt_id) = install_one_shot_binding(
            &positive,
            "exact-lineage-positive",
            std::slice::from_ref(&source.artifact_id),
            &[("artifact.write", "output-allocation", positive_allocation)],
        );
        let mut allocation_request = allocation(positive_allocation);
        allocation_request.binding_id = Some(binding_id);
        allocation_request.attempt_id = Some(attempt_id);
        allocate_bound(&mut positive, &allocation_request);
        let mut writer = open_bound(&mut positive, positive_allocation);
        writer.write_all(b"positive").unwrap();
        writer.finish().unwrap();
        let mut positive_request = publication("pub-exact-lineage-positive", positive_allocation);
        positive_request.lineage.derived_from_artifact_ids = vec![source.artifact_id];
        let published = publish_bound(&mut positive, &positive_request).unwrap();
        assert!(published.published);
        let handle = positive
            .get_artifact(published.artifact_id.as_deref().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(
            handle.origin.provider_id.as_deref(),
            Some("provider:sequential")
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one cleanup fixture covers every terminal allocation state and preserves live staging evidence"
    )]
    fn allocated_staging_residue_is_removed_without_wedging_writer_retry() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        manager
            .allocate_artifact_output(&allocation("alloc-residue"))
            .unwrap();
        let staging_ref: String = manager
            .connection
            .query_row(
                "SELECT staging_ref FROM artifact_output_allocations WHERE allocation_id='alloc-residue'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let staging_path =
            resolve_internal_ref(&manager.artifact_store_root, &staging_ref).unwrap();
        std::fs::write(&staging_path, b"crash residue").unwrap();
        std::fs::write(
            resolve_internal_ref(&manager.artifact_store_root, &seal_ref(&staging_ref)).unwrap(),
            b"stale seal",
        )
        .unwrap();
        std::fs::write(
            resolve_internal_ref(
                &manager.artifact_store_root,
                &format!("{}.pending", seal_ref(&staging_ref)),
            )
            .unwrap(),
            b"stale pending seal",
        )
        .unwrap();

        let report = manager.reconcile_artifacts_startup().unwrap();
        assert!(!staging_path.exists());
        assert!(
            !resolve_internal_ref(&manager.artifact_store_root, &seal_ref(&staging_ref))
                .unwrap()
                .exists()
        );
        assert!(
            !resolve_internal_ref(
                &manager.artifact_store_root,
                &format!("{}.pending", seal_ref(&staging_ref)),
            )
            .unwrap()
            .exists()
        );
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| { finding.allocation_id.as_deref() == Some("alloc-residue") })
        );
        let mut writer = manager.open_artifact_output("alloc-residue").unwrap();
        writer.write_all(b"retry").unwrap();
        writer.finish().unwrap();

        for state in ["FAILED", "ABORTED", "PUBLISHED"] {
            let id = format!("alloc-residue-{state}");
            let mut request = allocation(&id);
            request.output_port = Some(format!("report-{state}"));
            manager.allocate_artifact_output(&request).unwrap();
            let staging_ref = manager
                .connection
                .query_row(
                    "SELECT staging_ref FROM artifact_output_allocations WHERE allocation_id=?1",
                    [&id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap();
            manager
                .artifact_store_dir
                .write(&staging_ref, b"terminal residue")
                .unwrap();
            manager
                .artifact_store_dir
                .write(seal_ref(&staging_ref), b"terminal seal")
                .unwrap();
            manager
                .artifact_store_dir
                .write(
                    format!("{}.pending", seal_ref(&staging_ref)),
                    b"terminal pending seal",
                )
                .unwrap();
            manager
                .connection
                .execute(
                    "UPDATE artifact_output_allocations SET state=?2 WHERE allocation_id=?1",
                    params![id, state],
                )
                .unwrap();
            manager.reconcile_artifacts_startup().unwrap();
            assert!(!manager.artifact_store_root.join(&staging_ref).exists());
            assert!(
                !manager
                    .artifact_store_root
                    .join(seal_ref(&staging_ref))
                    .exists()
            );
            assert!(
                !manager
                    .artifact_store_root
                    .join(format!("{}.pending", seal_ref(&staging_ref)))
                    .exists()
            );
        }

        let mut live = allocation("alloc-live-residue");
        live.output_port = Some("report-live".to_owned());
        manager.allocate_artifact_output(&live).unwrap();
        let live_ref = manager
            .connection
            .query_row(
                "SELECT staging_ref FROM artifact_output_allocations WHERE allocation_id='alloc-live-residue'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        manager
            .artifact_store_dir
            .write(&live_ref, b"live")
            .unwrap();
        manager
            .connection
            .execute(
                "UPDATE artifact_output_allocations SET state='WRITING' WHERE allocation_id='alloc-live-residue'",
                [],
            )
            .unwrap();
        manager.reconcile_artifacts_startup().unwrap();
        assert!(manager.artifact_store_root.join(live_ref).exists());
    }

    #[test]
    fn orphan_blob_and_staging_are_reported_but_never_promoted() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let staging_ref = "staging/manual-crash";
        let staging = manager.artifact_store_root.join(staging_ref);
        let (size, hash) =
            stream_into_new_file(&mut Cursor::new(b"orphan".as_slice()), &staging, 1_024).unwrap();
        manager
            .place_blob(staging_ref, &hash, size, false, "manual-crash")
            .unwrap();
        std::fs::write(
            manager.artifact_store_root.join("staging/raw-residue"),
            b"unknown",
        )
        .unwrap();
        let abandoned_import = manager
            .artifact_store_root
            .join("staging/import-response-loss");
        std::fs::write(&abandoned_import, b"uncommitted import").unwrap();
        manager
            .allocate_artifact_output(&allocation("alloc-staged"))
            .unwrap();
        let mut writer = manager.open_artifact_output("alloc-staged").unwrap();
        writer.write_all(b"partial").unwrap();
        writer.finish().unwrap();
        let report = manager.reconcile_artifacts_startup().unwrap();
        assert!(report.findings.iter().any(|finding| {
            finding.kind == ArtifactReconciliationKind::BlobOrphaned
                && finding.content_hash.as_deref() == Some(hash.as_str())
        }));
        assert!(!abandoned_import.exists());
        assert!(
            manager
                .artifact_store_root
                .join("staging/raw-residue")
                .exists()
        );
        assert!(report.findings.iter().any(|finding| {
            finding.kind == ArtifactReconciliationKind::StagingOrphaned
                && finding.allocation_id.as_deref() == Some("alloc-staged")
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.kind == ArtifactReconciliationKind::StagingOrphaned
                && finding.allocation_id.is_none()
        }));
        assert_eq!(
            manager
                .connection
                .query_row("SELECT COUNT(*) FROM artifacts", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[test]
    fn orphan_blob_path_must_encode_the_recomputed_content_hash() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let claimed = "0".repeat(64);
        let relative = format!("blobs/sha256/00/00/{claimed}");
        manager
            .artifact_store_dir
            .create_dir_all("blobs/sha256/00/00")
            .unwrap();
        manager
            .artifact_store_dir
            .write(&relative, b"bytes whose hash is not zero")
            .unwrap();

        let report = manager.reconcile_artifacts_startup().unwrap();
        assert!(report.findings.iter().any(|finding| {
            finding.kind == ArtifactReconciliationKind::BlobCorrupt
                && finding.content_hash.as_deref() == Some(&format!("sha256:{claimed}"))
        }));
        assert!(!manager.artifact_store_root.join(relative).exists());
        assert_eq!(
            manager
                .connection
                .query_row("SELECT COUNT(*) FROM artifact_blobs", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
        assert_eq!(
            std::fs::read_dir(manager.artifact_store_root.join("quarantine"))
                .unwrap()
                .count(),
            1
        );
    }

    #[test]
    fn crash_after_blob_placement_can_retry_without_automatic_promotion() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        manager
            .allocate_artifact_output(&allocation("alloc-crash"))
            .unwrap();
        write_output(&mut manager, "alloc-crash", b"candidate");
        let request = publication("pub-crash", "alloc-crash");
        let request_json = canonical_json(&request).unwrap();
        manager
            .reserve_publication(&request, &request_json)
            .unwrap();
        manager
            .begin_reserved_publication(&request, &request_json)
            .unwrap();
        let staging_ref = manager
            .connection
            .query_row(
                "SELECT staging_ref FROM artifact_output_allocations WHERE allocation_id='alloc-crash'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        let staging_path =
            resolve_internal_ref(&manager.artifact_store_root, &staging_ref).unwrap();
        let (size, hash) = hash_file(&staging_path).unwrap();
        manager
            .place_blob(&staging_ref, &hash, size, true, "pub-crash")
            .unwrap();

        let report = manager.reconcile_artifacts_startup().unwrap();
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.kind == ArtifactReconciliationKind::BlobOrphaned)
        );
        assert_eq!(
            manager
                .connection
                .query_row("SELECT COUNT(*) FROM artifacts", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        let result = manager.publish_artifact_output(&request).unwrap();
        assert!(result.published);
        assert_eq!(result.blob_reused, Some(true));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "covers explicit abort, changed-request conflict, and terminal-Task startup abort"
    )]
    fn pending_publication_can_be_authenticated_and_aborted_for_terminal_task() {
        let temp = TempDir::new().unwrap();
        let database = temp.path().join("task-manager.sqlite");
        let mut manager = manager(&temp);
        manager
            .allocate_artifact_output(&allocation("alloc-pending-abort"))
            .unwrap();
        write_output(&mut manager, "alloc-pending-abort", b"reserved");
        let request = publication("pub-pending-abort", "alloc-pending-abort");
        let request_json = canonical_json(&request).unwrap();
        manager
            .reserve_publication(&request, &request_json)
            .unwrap();
        assert!(
            crate::unresolved_execution_ids(&manager.connection, "T-artifact")
                .unwrap()
                .contains(&"publication:pub-pending-abort".to_owned())
        );

        let first = manager.abort_pending_publication(&request).unwrap();
        let replay = manager.abort_pending_publication(&request).unwrap();
        assert_eq!(first, replay);
        assert!(!first.published);
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT p.state || ':' || a.state FROM artifact_publications p JOIN artifact_output_allocations a USING(allocation_id) WHERE p.publication_id=?1",
                    [&request.publication_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "ABORTED:ABORTED"
        );
        assert!(
            !crate::unresolved_execution_ids(&manager.connection, "T-artifact")
                .unwrap()
                .contains(&"publication:pub-pending-abort".to_owned())
        );

        let mut changed = request.clone();
        changed.media_type = "application/json".to_owned();
        assert!(matches!(
            manager.abort_pending_publication(&changed),
            Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_PUBLICATION_ID_REUSE_CONFLICT"
            ))
        ));

        manager
            .allocate_artifact_output(&allocation("alloc-terminal-pending"))
            .unwrap();
        write_output(&mut manager, "alloc-terminal-pending", b"terminal reserved");
        let terminal_request = publication("pub-terminal-pending", "alloc-terminal-pending");
        manager
            .reserve_publication(
                &terminal_request,
                &canonical_json(&terminal_request).unwrap(),
            )
            .unwrap();
        manager
            .connection
            .execute(
                "UPDATE tasks SET state='COMPLETED' WHERE task_id='T-artifact'",
                [],
            )
            .unwrap();
        drop(manager);

        let reopened = TaskManager::open_with_clock(&database, Box::new(FixedClock)).unwrap();
        assert_eq!(
            reopened
                .connection
                .query_row(
                    "SELECT state FROM tasks WHERE task_id='T-artifact'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "COMPLETED"
        );
        assert_eq!(
            reopened
                .connection
                .query_row(
                    "SELECT p.state || ':' || a.state
                     FROM artifact_publications p
                     JOIN artifact_output_allocations a USING(allocation_id)
                     WHERE p.publication_id='pub-terminal-pending'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "ABORTED:ABORTED"
        );
        assert_eq!(
            reopened
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM recovery_unknown_operations
                     WHERE operation_id='publication:pub-terminal-pending'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn pending_path_replacement_cannot_substitute_verified_blob_bytes() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let allocation_id = "alloc-pending-replacement";
        manager
            .allocate_artifact_output(&allocation(allocation_id))
            .unwrap();
        write_output(&mut manager, allocation_id, b"verified candidate");
        let root = manager.artifact_store_root.clone();
        PENDING_PLACEMENT_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |_store, pending_ref| {
                let pending = root.join(safe_internal_ref(pending_ref)?);
                let displaced = pending.with_extension("verified-displaced");
                std::fs::rename(&pending, displaced)?;
                std::fs::write(&pending, b"substituted bytes")?;
                Ok(())
            }));
        });

        let failed = manager
            .publish_artifact_output(&publication("pub-pending-replacement", allocation_id))
            .unwrap();
        assert!(!failed.published);
        assert_eq!(failed.reason_code, "ARTIFACT_HASH_MISMATCH");
        assert_eq!(
            manager
                .connection
                .query_row("SELECT COUNT(*) FROM artifact_blobs", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            manager
                .connection
                .query_row("SELECT COUNT(*) FROM artifacts", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM task_artifacts WHERE role='output'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM provenance_events WHERE event_type='artifact.created'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM artifact_publications WHERE state='COMMITTED'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn corrupt_published_blob_fails_integrity_and_scoped_reads() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        manager
            .allocate_artifact_output(&allocation("alloc-corrupt"))
            .unwrap();
        write_output(&mut manager, "alloc-corrupt", b"trusted");
        let result = manager
            .publish_artifact_output(&publication("pub-corrupt", "alloc-corrupt"))
            .unwrap();
        let artifact_id = result.artifact_id.unwrap();
        let storage_ref = manager
            .connection
            .query_row(
                "SELECT b.storage_ref FROM artifacts a JOIN artifact_blobs b ON b.content_hash=a.content_hash WHERE a.artifact_id=?1",
                [&artifact_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        std::fs::write(
            resolve_internal_ref(&manager.artifact_store_root, &storage_ref).unwrap(),
            b"tampered",
        )
        .unwrap();
        let report = manager.reconcile_artifacts_startup().unwrap();
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.kind == ArtifactReconciliationKind::BlobCorrupt)
        );
        assert_eq!(
            manager
                .get_artifact(&artifact_id)
                .unwrap()
                .unwrap()
                .integrity
                .as_ref()
                .unwrap()
                .state
                .unwrap(),
            ArtifactIntegrityState::Failed
        );
        let scope = manager
            .scope_owned_artifact_reads("T-artifact", &[artifact_id.clone()])
            .unwrap();
        assert!(matches!(
            manager.open_artifact_reader(&scope, &artifact_id),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_INTEGRITY_FAILED"))
        ));

        std::fs::write(
            resolve_internal_ref(&manager.artifact_store_root, &storage_ref).unwrap(),
            b"trusted",
        )
        .unwrap();
        manager.reconcile_artifacts_startup().unwrap();
        assert_eq!(
            manager
                .get_artifact(&artifact_id)
                .unwrap()
                .unwrap()
                .integrity
                .as_ref()
                .unwrap()
                .state
                .unwrap(),
            ArtifactIntegrityState::Failed
        );
        assert!(matches!(
            manager.open_artifact_reader(&scope, &artifact_id),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_INTEGRITY_FAILED"))
        ));
    }

    #[test]
    fn mismatched_deduplicated_blob_marks_every_reference_failed() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let bytes = b"shared trusted bytes";
        let first = manager
            .import_artifact(&import_request(), &mut Cursor::new(bytes.as_slice()))
            .unwrap();
        let second = manager
            .import_artifact(&import_request(), &mut Cursor::new(bytes.as_slice()))
            .unwrap();
        let storage_ref: String = manager
            .connection
            .query_row(
                "SELECT storage_ref FROM artifact_blobs WHERE content_hash=?1",
                [first.content_hash.as_ref().unwrap().tagged()],
                |row| row.get(0),
            )
            .unwrap();
        std::fs::write(
            resolve_internal_ref(&manager.artifact_store_root, &storage_ref).unwrap(),
            b"substituted",
        )
        .unwrap();

        assert!(matches!(
            manager.import_artifact(&import_request(), &mut Cursor::new(bytes.as_slice())),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_HASH_MISMATCH"))
        ));
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT durability_state FROM artifact_blobs WHERE content_hash=?1",
                    [first.content_hash.as_ref().unwrap().tagged()],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "CORRUPT"
        );
        for artifact_id in [first.artifact_id, second.artifact_id] {
            assert_eq!(
                manager
                    .get_artifact(&artifact_id)
                    .unwrap()
                    .unwrap()
                    .integrity
                    .as_ref()
                    .unwrap()
                    .state
                    .unwrap(),
                ArtifactIntegrityState::Failed
            );
        }
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(*)
                     FROM provenance_events
                     WHERE event_type='artifact.integrity-failed'
                       AND json_extract(event_json,'$.details.content_hash')=?1",
                    [first.content_hash.as_ref().unwrap().tagged()],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            2
        );
    }

    #[test]
    fn missing_published_blob_is_detected_and_cannot_remain_verified() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        manager
            .allocate_artifact_output(&allocation("alloc-missing"))
            .unwrap();
        write_output(&mut manager, "alloc-missing", b"durable");
        let result = manager
            .publish_artifact_output(&publication("pub-missing", "alloc-missing"))
            .unwrap();
        let artifact_id = result.artifact_id.unwrap();
        let storage_ref = manager
            .connection
            .query_row(
                "SELECT b.storage_ref FROM artifacts a JOIN artifact_blobs b ON b.content_hash=a.content_hash WHERE a.artifact_id=?1",
                [&artifact_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        std::fs::remove_file(
            resolve_internal_ref(&manager.artifact_store_root, &storage_ref).unwrap(),
        )
        .unwrap();
        let scope = manager
            .scope_owned_artifact_reads("T-artifact", &[artifact_id.clone()])
            .unwrap();
        assert!(matches!(
            manager.open_artifact_reader(&scope, &artifact_id),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_INTEGRITY_FAILED"))
        ));
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT durability_state FROM artifact_blobs WHERE content_hash=(SELECT content_hash FROM artifacts WHERE artifact_id=?1)",
                    [&artifact_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "MISSING"
        );
        let report = manager.reconcile_artifacts_startup().unwrap();
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.kind == ArtifactReconciliationKind::BlobMissing)
        );
        assert_eq!(
            manager
                .get_artifact(&artifact_id)
                .unwrap()
                .unwrap()
                .integrity
                .as_ref()
                .unwrap()
                .state
                .unwrap(),
            ArtifactIntegrityState::Failed
        );
    }

    #[test]
    fn startup_verifies_provenance_before_artifact_reconciliation_mutates_integrity() {
        let temp = TempDir::new().unwrap();
        let database = temp.path().join("task-manager.sqlite");
        let mut manager = manager(&temp);
        let artifact = manager
            .import_artifact(&import_request(), &mut Cursor::new(b"original".as_slice()))
            .unwrap();
        let storage_ref: String = manager
            .connection
            .query_row(
                "SELECT storage_ref FROM artifact_blobs WHERE content_hash=?1",
                [artifact.content_hash.as_ref().unwrap().tagged()],
                |row| row.get(0),
            )
            .unwrap();
        let blob = resolve_internal_ref(&manager.artifact_store_root, &storage_ref).unwrap();
        drop(manager);
        std::fs::write(blob, b"corrupt").unwrap();
        let connection = Connection::open(&database).unwrap();
        connection
            .execute_batch("DROP TRIGGER provenance_events_no_update")
            .unwrap();
        connection
            .execute(
                "UPDATE provenance_events SET event_json='{}' WHERE task_id='T-artifact' AND sequence=1",
                [],
            )
            .unwrap();
        drop(connection);

        assert!(TaskManager::open_with_clock(&database, Box::new(FixedClock)).is_err());
        let connection = Connection::open(&database).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT integrity_state FROM artifacts WHERE artifact_id=?1",
                    [artifact.artifact_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "verified"
        );
    }

    #[test]
    fn read_scopes_do_not_grant_artifacts_from_another_task() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let artifact = manager
            .import_artifact(&import_request(), &mut Cursor::new(b"private".as_slice()))
            .unwrap();
        manager
            .create_task(&CreateTask {
                task_id: "T-other".to_owned(),
                principal: Actor {
                    kind: "user".to_owned(),
                    id: "user:test".to_owned(),
                },
                workspace_id: None,
                original_intent: "other".to_owned(),
                normalized_intent: None,
                active_step_ids: Vec::new(),
            })
            .unwrap();
        assert!(matches!(
            manager.scope_owned_artifact_reads("T-other", &[artifact.artifact_id]),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
    }

    #[test]
    fn read_scope_is_bound_to_its_issuing_manager_even_for_the_same_artifact_id() {
        let first_temp = TempDir::new().unwrap();
        let second_temp = TempDir::new().unwrap();
        let mut first = manager(&first_temp);
        let artifact = first
            .import_artifact(&import_request(), &mut Cursor::new(b"first".as_slice()))
            .unwrap();
        let foreign_scope = first
            .scope_owned_artifact_reads("T-artifact", &[artifact.artifact_id.clone()])
            .unwrap();

        let mut second = manager(&second_temp);
        let local = second
            .import_artifact(&import_request(), &mut Cursor::new(b"second".as_slice()))
            .unwrap();
        second
            .connection
            .execute_batch("PRAGMA foreign_keys=OFF")
            .unwrap();
        second
            .connection
            .execute(
                "UPDATE task_artifacts SET artifact_id=?1 WHERE artifact_id=?2",
                params![artifact.artifact_id, local.artifact_id],
            )
            .unwrap();
        second
            .connection
            .execute(
                "UPDATE artifacts SET artifact_id=?1,uri=?2 WHERE artifact_id=?3",
                params![
                    artifact.artifact_id,
                    ArtifactUri::new(&artifact.artifact_id).as_str(),
                    local.artifact_id
                ],
            )
            .unwrap();
        second
            .connection
            .execute_batch("PRAGMA foreign_keys=ON")
            .unwrap();
        let local_scope = second
            .scope_owned_artifact_reads("T-artifact", &[artifact.artifact_id.clone()])
            .unwrap();
        assert!(
            second
                .open_artifact_reader(&local_scope, &artifact.artifact_id)
                .is_ok()
        );
        assert!(matches!(
            second.open_artifact_reader(&foreign_scope, &artifact.artifact_id),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
    }

    #[test]
    fn cached_owner_read_scope_fails_after_principal_invalidation() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let artifact = manager
            .import_artifact(&import_request(), &mut Cursor::new(b"private".as_slice()))
            .unwrap();
        let principal_scope = manager
            .scope_owned_artifact_reads("T-artifact", &[artifact.artifact_id.clone()])
            .unwrap();
        manager
            .connection
            .execute(
                "UPDATE tasks SET principal_id='user:changed' WHERE task_id='T-artifact'",
                [],
            )
            .unwrap();
        assert!(matches!(
            manager.open_artifact_reader(&principal_scope, &artifact.artifact_id),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
    }

    #[test]
    fn public_read_scope_cannot_request_owner_authority_without_a_binding() {
        let temp = TempDir::new().unwrap();
        let manager = manager(&temp);
        assert!(
            manager
                .issue_provider_artifact_session("T-artifact", "binding:forged")
                .is_err()
        );
    }

    #[test]
    fn owner_can_read_and_export_retained_artifacts_after_terminal_states() {
        for state in ["COMPLETED", "FAILED", "CANCELLED", "ROLLED_BACK"] {
            let temp = TempDir::new().unwrap();
            let mut manager = manager(&temp);
            let bytes = format!("retained after {state}").into_bytes();
            let artifact = manager
                .import_artifact(&import_request(), &mut Cursor::new(bytes.as_slice()))
                .unwrap();
            manager
                .connection
                .execute(
                    "UPDATE tasks SET state=?1 WHERE task_id='T-artifact'",
                    [state],
                )
                .unwrap();

            let scope = manager
                .scope_owned_artifact_reads("T-artifact", &[artifact.artifact_id.clone()])
                .unwrap();
            let mut reader = manager
                .open_artifact_reader(&scope, &artifact.artifact_id)
                .unwrap();
            let mut read = Vec::new();
            reader.read_to_end(&mut read).unwrap();
            assert_eq!(read, bytes, "owner read failed in {state}");

            let mut exported = manager
                .issue_owned_artifact_export_destination(
                    &scope,
                    &format!("terminal-owner-export-{state}"),
                    &artifact.artifact_id,
                    "user-selected-file",
                    1_024,
                    deferred(Vec::new()),
                )
                .unwrap();
            manager
                .export_artifact(&scope, &artifact.artifact_id, &mut exported)
                .unwrap();
            assert_eq!(
                exported.writer.as_deref(),
                Some(bytes.as_slice()),
                "owner export failed in {state}"
            );
            assert_eq!(
                manager
                    .connection
                    .query_row(
                        "SELECT COUNT(*) FROM provenance_events WHERE task_id='T-artifact' AND event_type='artifact.exported'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                1
            );
            let (program_hash, node_id) = manager
                .connection
                .query_row(
                    "SELECT semantic_program_hash,node_id FROM operations WHERE operation_id=?1",
                    [format!("terminal-owner-export-{state}")],
                    |row| {
                        Ok((
                            row.get::<_, Option<String>>(0)?,
                            row.get::<_, Option<String>>(1)?,
                        ))
                    },
                )
                .unwrap();
            assert_eq!((program_hash, node_id), (None, None));

            assert!(matches!(
                manager.import_artifact(
                    &import_request(),
                    &mut Cursor::new(b"late import".as_slice())
                ),
                Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
            ));
            let mut late_allocation = allocation(&format!("alloc-after-{state}"));
            late_allocation.expires_at = "2026-09-20T00:00:00Z".to_owned();
            assert!(matches!(
                manager.allocate_artifact_output(&late_allocation),
                Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
            ));
        }
    }

    #[test]
    fn in_memory_store_cleanup_waits_for_issued_reader_release() {
        let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
        manager
            .create_task(&CreateTask {
                task_id: "T-memory-artifact".to_owned(),
                principal: Actor {
                    kind: "user".to_owned(),
                    id: "user:test".to_owned(),
                },
                workspace_id: None,
                original_intent: "exercise ephemeral cleanup".to_owned(),
                normalized_intent: None,
                active_step_ids: Vec::new(),
            })
            .unwrap();
        let mut request = import_request();
        request.task_id = "T-memory-artifact".to_owned();
        let artifact = manager
            .import_artifact(&request, &mut Cursor::new(b"ephemeral".as_slice()))
            .unwrap();
        let scope = manager
            .scope_owned_artifact_reads(
                "T-memory-artifact",
                std::slice::from_ref(&artifact.artifact_id),
            )
            .unwrap();
        let reader = manager
            .open_artifact_reader(&scope, &artifact.artifact_id)
            .unwrap();
        let root = manager.artifact_store_root.clone();
        drop(scope);
        drop(manager);
        assert!(root.exists());
        drop(reader);
        assert!(!root.exists());
    }

    #[test]
    fn sequential_one_shot_reads_ignore_an_expired_consumed_sibling_grant() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let first = manager
            .import_artifact(&import_request(), &mut Cursor::new(b"first".as_slice()))
            .unwrap();
        let second = manager
            .import_artifact(&import_request(), &mut Cursor::new(b"second".as_slice()))
            .unwrap();
        let (binding_id, _) = install_one_shot_binding(
            &manager,
            "two-reads",
            &[first.artifact_id.clone(), second.artifact_id.clone()],
            &[
                ("artifact.read", "artifact", &first.artifact_id),
                ("artifact.read", "artifact", &second.artifact_id),
            ],
        );
        let scope = scope_bound_reads(
            &manager,
            "T-artifact",
            &binding_id,
            &[first.artifact_id.clone(), second.artifact_id.clone()],
        )
        .unwrap();
        let mut first_reader = manager
            .open_artifact_reader(&scope, &first.artifact_id)
            .unwrap();
        manager
            .connection
            .execute(
                "UPDATE authority_grants SET expires_at='2026-09-19T21:00:00Z' WHERE grant_id='grant-two-reads-0'",
                [],
            )
            .unwrap();
        let mut byte = [0_u8; 1];
        assert_eq!(
            first_reader.read(&mut byte).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );

        let mut second_reader = manager
            .open_artifact_reader(&scope, &second.artifact_id)
            .unwrap();
        let mut bytes = Vec::new();
        second_reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"second");
        assert!(matches!(
            scope_bound_reads(
                &manager,
                "T-artifact",
                &binding_id,
                &[first.artifact_id.clone()]
            ),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
        let states = manager
            .connection
            .prepare(
                "SELECT state FROM authority_grants WHERE grant_id LIKE 'grant-two-reads-%' ORDER BY grant_id",
            )
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(states, ["CONSUMED", "CONSUMED"]);
    }

    #[test]
    fn fallible_reader_setup_completes_before_one_shot_grant_consumption() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let artifact = manager
            .import_artifact(
                &import_request(),
                &mut Cursor::new(b"reader setup".as_slice()),
            )
            .unwrap();
        let (binding_id, _) = install_one_shot_binding(
            &manager,
            "reader-setup",
            std::slice::from_ref(&artifact.artifact_id),
            &[("artifact.read", "artifact", &artifact.artifact_id)],
        );
        let scope = scope_bound_reads(
            &manager,
            "T-artifact",
            &binding_id,
            std::slice::from_ref(&artifact.artifact_id),
        )
        .unwrap();
        READER_SETUP_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(|| {
                Err(TaskManagerError::InvalidRecord("test reader setup failure"))
            }));
        });
        assert!(matches!(
            manager.open_artifact_reader(&scope, &artifact.artifact_id),
            Err(TaskManagerError::InvalidRecord("test reader setup failure"))
        ));
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT uses_consumed FROM authority_grants WHERE grant_id='grant-reader-setup-0'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        let mut reader = manager
            .open_artifact_reader(&scope, &artifact.artifact_id)
            .unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"reader setup");
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT uses_consumed FROM authority_grants WHERE grant_id='grant-reader-setup-0'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn issued_reader_rechecks_shared_integrity_and_transient_hash_errors_do_not_poison() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let artifact = manager
            .import_artifact(
                &import_request(),
                &mut Cursor::new(b"shared reader".as_slice()),
            )
            .unwrap();
        let scope = manager
            .scope_owned_artifact_reads("T-artifact", &[artifact.artifact_id.clone()])
            .unwrap();

        READER_HASH_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(|| {
                Err(TaskManagerError::Io(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "injected transient read failure",
                )))
            }));
        });
        assert!(matches!(
            manager.open_artifact_reader(&scope, &artifact.artifact_id),
            Err(TaskManagerError::Io(error)) if error.kind() == std::io::ErrorKind::Interrupted
        ));
        assert_eq!(
            manager
                .get_artifact(&artifact.artifact_id)
                .unwrap()
                .unwrap()
                .integrity
                .as_ref()
                .unwrap()
                .state
                .unwrap(),
            ArtifactIntegrityState::Verified
        );

        let mut reader = manager
            .open_artifact_reader(&scope, &artifact.artifact_id)
            .unwrap();
        manager
            .mark_content_hash_failed(&artifact.content_hash.as_ref().unwrap().tagged(), "CORRUPT")
            .unwrap();
        let mut byte = [0_u8; 1];
        assert_eq!(
            reader.read(&mut byte).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            reader.seek(SeekFrom::Start(0)).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn finite_task_and_time_limited_grants_admit_exactly_one_reader() {
        for (index, scope_name) in ["TASK", "TIME_LIMITED"].into_iter().enumerate() {
            let temp = TempDir::new().unwrap();
            let mut manager = manager(&temp);
            let artifact = manager
                .import_artifact(&import_request(), &mut Cursor::new(scope_name.as_bytes()))
                .unwrap();
            let fixture = format!("bounded-{index}");
            let (binding_id, _) = install_one_shot_binding(
                &manager,
                &fixture,
                &[artifact.artifact_id.clone()],
                &[("artifact.read", "artifact", &artifact.artifact_id)],
            );
            let grant_id = format!("grant-{fixture}-0");
            manager
                .connection
                .execute(
                    "UPDATE authority_grants SET scope=?1 WHERE grant_id=?2",
                    params![scope_name, grant_id],
                )
                .unwrap();
            let read_scope = scope_bound_reads(
                &manager,
                "T-artifact",
                &binding_id,
                &[artifact.artifact_id.clone()],
            )
            .unwrap();

            let mut first = manager
                .open_artifact_reader(&read_scope, &artifact.artifact_id)
                .unwrap();
            assert!(matches!(
                manager.open_artifact_reader(&read_scope, &artifact.artifact_id),
                Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
            ));
            let (uses_consumed, state) = manager
                .connection
                .query_row(
                    "SELECT uses_consumed,state FROM authority_grants WHERE grant_id=?1",
                    [&grant_id],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                )
                .unwrap();
            assert_eq!(uses_consumed, 1, "wrong use count for {scope_name}");
            assert_eq!(state, "ACTIVE", "wrong state for {scope_name}");

            let mut bytes = Vec::new();
            first.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, scope_name.as_bytes());
        }
    }

    #[test]
    fn exhausted_finite_read_grant_does_not_block_an_independent_read_grant() {
        for (index, scope_name) in ["TASK", "TIME_LIMITED"].into_iter().enumerate() {
            let temp = TempDir::new().unwrap();
            let mut manager = manager(&temp);
            let first = manager
                .import_artifact(&import_request(), &mut Cursor::new(b"first".as_slice()))
                .unwrap();
            let second = manager
                .import_artifact(&import_request(), &mut Cursor::new(b"second".as_slice()))
                .unwrap();
            let fixture = format!("finite-two-reads-{index}");
            let (binding_id, _) = install_one_shot_binding(
                &manager,
                &fixture,
                &[first.artifact_id.clone(), second.artifact_id.clone()],
                &[
                    ("artifact.read", "artifact", &first.artifact_id),
                    ("artifact.read", "artifact", &second.artifact_id),
                ],
            );
            manager
                .connection
                .execute(
                    "UPDATE authority_grants SET scope=?1 WHERE grant_id LIKE ?2",
                    params![scope_name, format!("grant-{fixture}-%")],
                )
                .unwrap();
            let read_scope = scope_bound_reads(
                &manager,
                "T-artifact",
                &binding_id,
                &[first.artifact_id.clone(), second.artifact_id.clone()],
            )
            .unwrap();

            let mut first_reader = manager
                .open_artifact_reader(&read_scope, &first.artifact_id)
                .unwrap();
            assert!(matches!(
                manager.open_artifact_reader(&read_scope, &first.artifact_id),
                Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
            ));
            manager
                .connection
                .execute(
                    "UPDATE authority_grants SET expires_at='2026-09-19T21:00:00Z' WHERE grant_id=?1",
                    [format!("grant-{fixture}-0")],
                )
                .unwrap();
            assert_eq!(
                first_reader.read(&mut [0_u8; 1]).unwrap_err().kind(),
                std::io::ErrorKind::PermissionDenied,
                "issued {scope_name} handle lost its expiry fence"
            );

            let mut second_reader = manager
                .open_artifact_reader(&read_scope, &second.artifact_id)
                .unwrap();
            let mut bytes = Vec::new();
            second_reader.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"second", "independent {scope_name} read failed");
            let grants = manager
                .connection
                .prepare(
                    "SELECT uses_consumed,state FROM authority_grants WHERE grant_id LIKE ?1 ORDER BY grant_id",
                )
                .unwrap()
                .query_map([format!("grant-{fixture}-%")], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })
                .unwrap()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(grants, [(1, "ACTIVE".to_owned()), (1, "ACTIVE".to_owned())]);
        }
    }

    #[test]
    fn exhausted_finite_read_grant_does_not_block_an_independent_write_grant() {
        for (index, scope_name) in ["TASK", "TIME_LIMITED"].into_iter().enumerate() {
            let temp = TempDir::new().unwrap();
            let mut manager = manager(&temp);
            let input = manager
                .import_artifact(&import_request(), &mut Cursor::new(b"input".as_slice()))
                .unwrap();
            let fixture = format!("finite-read-write-{index}");
            let allocation_id = format!("alloc-{fixture}");
            let (binding_id, attempt_id) = install_one_shot_binding(
                &manager,
                &fixture,
                &[input.artifact_id.clone()],
                &[
                    ("artifact.read", "artifact", &input.artifact_id),
                    ("artifact.write", "output-allocation", &allocation_id),
                ],
            );
            manager
                .connection
                .execute(
                    "UPDATE authority_grants SET scope=?1 WHERE grant_id LIKE ?2",
                    params![scope_name, format!("grant-{fixture}-%")],
                )
                .unwrap();
            let mut allocation_request = allocation(&allocation_id);
            allocation_request.binding_id = Some(binding_id.clone());
            allocation_request.attempt_id = Some(attempt_id);
            allocate_bound(&mut manager, &allocation_request);
            let read_scope = scope_bound_reads(
                &manager,
                "T-artifact",
                &binding_id,
                &[input.artifact_id.clone()],
            )
            .unwrap();
            let _reader = manager
                .open_artifact_reader(&read_scope, &input.artifact_id)
                .unwrap();
            assert!(matches!(
                manager.open_artifact_reader(&read_scope, &input.artifact_id),
                Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
            ));

            let mut writer = open_bound(&mut manager, &allocation_id);
            writer.write_all(b"output").unwrap();
            writer.finish().unwrap();
            let publication_id = format!("publication-{fixture}");
            let result =
                publish_bound(&mut manager, &publication(&publication_id, &allocation_id)).unwrap();
            assert!(result.published, "independent {scope_name} write failed");
            let grants = manager
                .connection
                .prepare(
                    "SELECT uses_consumed,state FROM authority_grants WHERE grant_id LIKE ?1 ORDER BY grant_id",
                )
                .unwrap()
                .query_map([format!("grant-{fixture}-%")], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })
                .unwrap()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(grants, [(1, "ACTIVE".to_owned()), (1, "ACTIVE".to_owned())]);
        }
    }

    #[test]
    fn admitted_one_shot_and_exhausted_finite_writers_can_publish_and_replay() {
        for (index, scope) in ["ONE_SHOT", "TASK", "TIME_LIMITED"].into_iter().enumerate() {
            let temp = TempDir::new().unwrap();
            let mut manager = manager(&temp);
            let fixture = format!("publish-admitted-{index}");
            let (allocation_id, grant_id) = finish_bound_output(&mut manager, &fixture, scope);
            let before = manager
                .connection
                .query_row(
                    "SELECT uses_consumed,authority_grants.state,writer_grant_id,writer_grant_one_shot_consumed
                     FROM authority_grants JOIN artifact_output_allocations ON writer_grant_id=grant_id
                     WHERE allocation_id=?1",
                    [&allocation_id],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, bool>(3)?,
                        ))
                    },
                )
                .unwrap();
            assert_eq!(before.0, 1);
            assert_eq!(
                before.1,
                if scope == "ONE_SHOT" {
                    "CONSUMED"
                } else {
                    "ACTIVE"
                }
            );
            assert_eq!(before.2, grant_id);
            assert_eq!(before.3, scope == "ONE_SHOT");

            let publication_id = format!("pub-{fixture}");
            let request = publication(&publication_id, &allocation_id);
            let result = publish_bound(&mut manager, &request).unwrap();
            assert!(result.published, "{scope} admitted writer did not publish");
            assert_eq!(publish_bound(&mut manager, &request).unwrap(), result);
            assert_eq!(
                manager
                    .connection
                    .query_row(
                        "SELECT uses_consumed FROM authority_grants WHERE grant_id=?1",
                        [&grant_id],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                1,
                "publication or response-loss replay consumed {scope} again"
            );
        }
    }

    #[test]
    fn legacy_bound_inflight_allocations_without_writer_admission_fail_closed() {
        for legacy_state in ["WRITING", "FINALIZING"] {
            let temp = TempDir::new().unwrap();
            let mut manager = manager(&temp);
            let fixture = format!("legacy-{}", legacy_state.to_ascii_lowercase());
            let (allocation_id, _) = finish_bound_output(&mut manager, &fixture, "ONE_SHOT");
            let publication_id = format!("pub-{fixture}");
            let request = publication(&publication_id, &allocation_id);
            // Migration 0006 cannot reconstruct the exact grant admitted by a
            // pre-v6 in-flight writer, so upgraded legacy rows retain NULL here.
            if legacy_state == "FINALIZING" {
                manager
                    .connection
                    .execute(
                        "INSERT INTO artifact_publications(publication_id,allocation_id,task_id,request_json,state,requested_at) VALUES (?1,?2,'T-artifact',?3,'PENDING','2026-09-19T22:00:00Z')",
                        params![publication_id, allocation_id, canonical_json(&request).unwrap()],
                    )
                    .unwrap();
            }
            manager
                .connection
                .execute(
                    "UPDATE artifact_output_allocations
                     SET state=?2,publication_id=CASE WHEN ?2='FINALIZING' THEN ?3 ELSE NULL END,
                         writer_grant_id=NULL,writer_grant_one_shot_consumed=NULL
                     WHERE allocation_id=?1",
                    params![allocation_id, legacy_state, publication_id],
                )
                .unwrap();

            assert!(matches!(
                publish_bound(&mut manager, &request),
                Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
            ));
            assert_publication_not_committed(&manager, &allocation_id, &publication_id);
            assert_eq!(
                manager
                    .connection
                    .query_row(
                        "SELECT state FROM artifact_output_allocations WHERE allocation_id=?1",
                        [&allocation_id],
                        |row| row.get::<_, String>(0),
                    )
                    .unwrap(),
                legacy_state
            );
            let publication_rows = manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM artifact_publications WHERE publication_id=?1",
                    [&publication_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap();
            assert_eq!(publication_rows, i64::from(legacy_state == "FINALIZING"));
            if legacy_state == "FINALIZING" {
                assert_eq!(
                    manager
                        .connection
                        .query_row(
                            "SELECT state FROM artifact_publications WHERE publication_id=?1",
                            [&publication_id],
                            |row| row.get::<_, String>(0),
                        )
                        .unwrap(),
                    "PENDING"
                );
            }
        }
    }

    #[test]
    fn legacy_committed_bound_publication_without_writer_admission_replays() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let (allocation_id, grant_id) =
            finish_bound_output(&mut manager, "legacy-committed", "ONE_SHOT");
        let request = publication("pub-legacy-committed", &allocation_id);
        let committed = publish_bound(&mut manager, &request).unwrap();
        assert!(committed.published);
        manager
            .connection
            .execute(
                "UPDATE artifact_output_allocations
                 SET writer_grant_id=NULL,writer_grant_one_shot_consumed=NULL
                 WHERE allocation_id=?1",
                [&allocation_id],
            )
            .unwrap();

        assert_eq!(publish_bound(&mut manager, &request).unwrap(), committed);
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT uses_consumed FROM authority_grants WHERE grant_id=?1",
                    [&grant_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn legacy_allocated_bound_output_records_writer_admission_atomically() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let fixture = "legacy-allocated";
        let allocation_id = format!("alloc-{fixture}");
        let (binding_id, attempt_id) = install_one_shot_binding(
            &manager,
            fixture,
            &[],
            &[("artifact.write", "output-allocation", &allocation_id)],
        );
        let mut request = allocation(&allocation_id);
        request.binding_id = Some(binding_id);
        request.attempt_id = Some(attempt_id);
        allocate_bound(&mut manager, &request);
        // A pre-v6 ALLOCATED row has no prior writer admission to reconstruct;
        // opening it after migration records the admission normally.
        assert!(
            manager
                .connection
                .query_row(
                    "SELECT writer_grant_id IS NULL AND writer_grant_one_shot_consumed IS NULL
                     FROM artifact_output_allocations WHERE allocation_id=?1",
                    [&allocation_id],
                    |row| row.get::<_, bool>(0),
                )
                .unwrap()
        );

        let writer = open_bound(&mut manager, &allocation_id);
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT a.state,a.writer_grant_id,a.writer_grant_one_shot_consumed,g.uses_consumed,g.state
                     FROM artifact_output_allocations a JOIN authority_grants g ON g.grant_id=a.writer_grant_id
                     WHERE a.allocation_id=?1",
                    [&allocation_id],
                    |row| Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, bool>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                    )),
                )
                .unwrap(),
            (
                "WRITING".to_owned(),
                format!("grant-{fixture}-0"),
                true,
                1,
                "CONSUMED".to_owned(),
            )
        );
        drop(writer);
    }

    #[test]
    fn committed_bound_one_shot_replays_after_close_without_second_consumption() {
        let temp = TempDir::new().unwrap();
        let database = temp.path().join("task-manager.sqlite");
        let mut manager = manager(&temp);
        let (allocation_id, grant_id) =
            finish_bound_output(&mut manager, "reopen-committed", "ONE_SHOT");
        let request = publication("pub-reopen-committed", &allocation_id);
        let committed = publish_bound(&mut manager, &request).unwrap();
        assert!(committed.published);
        manager
            .connection
            .execute_batch(&format!(
                "UPDATE step_executions
                 SET state='SUCCEEDED',outcome_certainty='COMPLETED',output_artifacts_json='[\"{}\"]',finished_at='2026-09-19T22:00:00Z'
                 WHERE attempt_id='attempt-reopen-committed';
                 UPDATE tasks SET state='COMPLETED',completed_at='2026-09-19T22:00:00Z'
                 WHERE task_id='T-artifact';",
                committed.artifact_id.as_deref().unwrap()
            ))
            .unwrap();
        drop(manager);

        let mut reopened = TaskManager::open_with_clock(&database, Box::new(FixedClock)).unwrap();
        let session = reopened
            .issue_provider_artifact_session("T-artifact", "binding-reopen-committed")
            .unwrap();
        assert_eq!(
            reopened
                .publish_bound_artifact_output(&session, &request)
                .unwrap(),
            committed
        );
        assert_eq!(
            reopened
                .connection
                .query_row(
                    "SELECT uses_consumed FROM authority_grants WHERE grant_id=?1",
                    [&grant_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn revoked_or_expired_writer_grant_after_finish_cannot_publish() {
        for mutation in ["revoke", "expire"] {
            let temp = TempDir::new().unwrap();
            let mut manager = manager(&temp);
            let fixture = format!("post-finish-{mutation}");
            let (allocation_id, grant_id) = finish_bound_output(&mut manager, &fixture, "ONE_SHOT");
            match mutation {
                "revoke" => {
                    manager
                        .connection
                        .execute(
                            "UPDATE authority_grants SET state='REVOKED',revoked_at='2026-09-19T22:00:00Z' WHERE grant_id=?1",
                            [&grant_id],
                        )
                        .unwrap();
                }
                "expire" => {
                    manager
                        .connection
                        .execute(
                            "UPDATE authority_grants SET expires_at='2026-09-19T21:59:59Z' WHERE grant_id=?1",
                            [&grant_id],
                        )
                        .unwrap();
                }
                _ => unreachable!(),
            }
            let publication_id = format!("pub-{fixture}");
            let request = publication(&publication_id, &allocation_id);
            let result = publish_bound(&mut manager, &request).unwrap();
            assert!(!result.published);
            assert_eq!(result.reason_code, "ARTIFACT_AUTHORITY_DENIED");
            assert_publication_not_committed(&manager, &allocation_id, &publication_id);
            assert_eq!(publish_bound(&mut manager, &request).unwrap(), result);
            assert!(manager
                .connection
                .query_row(
                    "SELECT result_json IS NOT NULL FROM artifact_publications WHERE publication_id=?1 AND state='FAILED'",
                    [&publication_id],
                    |row| row.get::<_, bool>(0),
                )
                .unwrap());
        }
    }

    #[test]
    fn invalidated_writer_approval_after_finish_cannot_publish() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let fixture = "post-finish-approval";
        let allocation_id = format!("alloc-{fixture}");
        let (binding_id, attempt_id) = install_one_shot_binding(
            &manager,
            fixture,
            &[],
            &[("artifact.write", "output-allocation", &allocation_id)],
        );
        let program_hash = allocation("unused").semantic_program_hash;
        manager
            .connection
            .execute_batch(&format!(
                "INSERT INTO approval_requests(approval_id,authority_request_id,task_id,semantic_program_hash,node_id,action,status,request_json,created_at,expires_at) VALUES ('approval-{fixture}','request-{fixture}-0','T-artifact','{program_hash}','compose_report','artifact.write','APPROVED','{{}}','2026-09-19T00:00:00Z','2026-09-20T00:00:00Z');
                 UPDATE policy_decisions SET approval_request_id='approval-{fixture}' WHERE decision_id='decision-{fixture}-0';
                 UPDATE authority_grants SET approval_id='approval-{fixture}' WHERE grant_id='grant-{fixture}-0';
                 INSERT INTO approval_decisions(decision_id,approval_id,task_id,decision,decided_by_kind,decided_by_id,scope,approved_until,decision_json,decided_at) VALUES ('approval-decision-{fixture}','approval-{fixture}','T-artifact','APPROVE','user','user:approver','ONE_SHOT','2026-09-20T00:00:00Z','{{}}','2026-09-19T00:00:00Z');"
            ))
            .unwrap();
        let mut allocation_request = allocation(&allocation_id);
        allocation_request.binding_id = Some(binding_id);
        allocation_request.attempt_id = Some(attempt_id);
        allocate_bound(&mut manager, &allocation_request);
        let mut writer = open_bound(&mut manager, &allocation_id);
        writer.write_all(b"approval-bound").unwrap();
        writer.finish().unwrap();
        manager
            .connection
            .execute(
                "UPDATE approval_requests SET status='STALE' WHERE approval_id=?1",
                [format!("approval-{fixture}")],
            )
            .unwrap();

        let publication_id = format!("pub-{fixture}");
        let result =
            publish_bound(&mut manager, &publication(&publication_id, &allocation_id)).unwrap();
        assert!(!result.published);
        assert_eq!(result.reason_code, "ARTIFACT_AUTHORITY_DENIED");
        assert_publication_not_committed(&manager, &allocation_id, &publication_id);
    }

    #[test]
    fn writer_grant_admission_substitution_or_tamper_cannot_publish() {
        for tamper in ["grant", "kind"] {
            let temp = TempDir::new().unwrap();
            let mut manager = manager(&temp);
            let fixture = format!("admission-tamper-{tamper}");
            let allocation_id = format!("alloc-{fixture}");
            let unrelated_id = format!("alloc-{fixture}-unrelated");
            let (binding_id, attempt_id) = install_one_shot_binding(
                &manager,
                &fixture,
                &[],
                &[
                    ("artifact.write", "output-allocation", &allocation_id),
                    ("artifact.write", "output-allocation", &unrelated_id),
                ],
            );
            if tamper == "kind" {
                manager
                    .connection
                    .execute(
                        "UPDATE authority_grants SET scope='TASK' WHERE grant_id=?1",
                        [format!("grant-{fixture}-0")],
                    )
                    .unwrap();
            }
            let mut request = allocation(&allocation_id);
            request.binding_id = Some(binding_id);
            request.attempt_id = Some(attempt_id);
            allocate_bound(&mut manager, &request);
            let mut writer = open_bound(&mut manager, &allocation_id);
            writer.write_all(b"sealed admission").unwrap();
            writer.finish().unwrap();
            match tamper {
                "grant" => {
                    manager
                        .connection
                        .execute(
                            "UPDATE artifact_output_allocations SET writer_grant_id=?2 WHERE allocation_id=?1",
                            params![allocation_id, format!("grant-{fixture}-1")],
                        )
                        .unwrap();
                }
                "kind" => {
                    manager
                        .connection
                        .execute(
                            "UPDATE artifact_output_allocations SET writer_grant_one_shot_consumed=1 WHERE allocation_id=?1",
                            [&allocation_id],
                        )
                        .unwrap();
                }
                _ => unreachable!(),
            }
            let publication_id = format!("pub-{fixture}");
            let result =
                publish_bound(&mut manager, &publication(&publication_id, &allocation_id)).unwrap();
            assert!(!result.published);
            assert_eq!(result.reason_code, "ARTIFACT_AUTHORITY_DENIED");
            assert_publication_not_committed(&manager, &allocation_id, &publication_id);
        }
    }

    #[test]
    fn cancelled_bound_task_after_writer_finish_cannot_publish() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let (allocation_id, _) =
            finish_bound_output(&mut manager, "post-finish-cancel", "ONE_SHOT");
        manager
            .connection
            .execute(
                "UPDATE tasks SET state='CANCELLED' WHERE task_id='T-artifact'",
                [],
            )
            .unwrap();
        let publication_id = "pub-post-finish-cancel";
        let result =
            publish_bound(&mut manager, &publication(publication_id, &allocation_id)).unwrap();
        assert!(!result.published);
        assert_eq!(result.reason_code, "ARTIFACT_AUTHORITY_DENIED");
        assert_publication_not_committed(&manager, &allocation_id, publication_id);
    }

    #[test]
    fn revocation_after_blob_placement_is_caught_by_metadata_commit_fence() {
        let temp = TempDir::new().unwrap();
        let database = temp.path().join("task-manager.sqlite");
        let state = Arc::new(Mutex::new(BlobRevokingClockState {
            armed: false,
            database: database.clone(),
            blob: None,
            grant_id: None,
            revoked: false,
            error: None,
        }));
        let mut manager = TaskManager::open_with_clock(
            &database,
            Box::new(BlobRevokingClock {
                state: Arc::clone(&state),
            }),
        )
        .unwrap();
        manager
            .create_task(&CreateTask {
                task_id: "T-artifact".to_owned(),
                principal: Actor {
                    kind: "user".to_owned(),
                    id: "user:test".to_owned(),
                },
                workspace_id: None,
                original_intent: "exercise Artifact storage".to_owned(),
                normalized_intent: None,
                active_step_ids: Vec::new(),
            })
            .unwrap();
        let fixture = "placement-revocation";
        let (allocation_id, grant_id) = finish_bound_output(&mut manager, fixture, "ONE_SHOT");
        let mut hasher = Sha256::new();
        hasher.update(fixture.as_bytes());
        let hash = tagged_digest(hasher);
        let digest = hash.strip_prefix("sha256:").unwrap();
        let blob = manager.artifact_store_root.join(format!(
            "blobs/sha256/{}/{}/{}",
            &digest[..2],
            &digest[2..4],
            digest
        ));
        {
            let mut state = state.lock().unwrap();
            state.blob = Some(blob.clone());
            state.grant_id = Some(grant_id.clone());
            state.armed = true;
        }

        let publication_id = "pub-placement-revocation";
        let result =
            publish_bound(&mut manager, &publication(publication_id, &allocation_id)).unwrap();
        assert!(!result.published);
        assert_eq!(result.reason_code, "ARTIFACT_AUTHORITY_DENIED");
        let state = state.lock().unwrap();
        assert!(state.revoked, "test did not revoke after blob placement");
        assert_eq!(state.error, None);
        drop(state);
        assert!(
            blob.exists(),
            "placement race did not reach durable blob placement"
        );
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT state FROM authority_grants WHERE grant_id=?1",
                    [&grant_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "REVOKED"
        );
        assert_publication_not_committed(&manager, &allocation_id, publication_id);
    }

    #[test]
    fn malformed_exhausted_sibling_grants_fail_closed() {
        for (index, scope_name) in ["TASK", "TIME_LIMITED"].into_iter().enumerate() {
            let temp = TempDir::new().unwrap();
            let mut manager = manager(&temp);
            let first = manager
                .import_artifact(&import_request(), &mut Cursor::new(b"first".as_slice()))
                .unwrap();
            let second = manager
                .import_artifact(&import_request(), &mut Cursor::new(b"second".as_slice()))
                .unwrap();
            let fixture = format!("malformed-finite-{index}");
            let (binding_id, _) = install_one_shot_binding(
                &manager,
                &fixture,
                &[first.artifact_id.clone(), second.artifact_id.clone()],
                &[
                    ("artifact.read", "artifact", &first.artifact_id),
                    ("artifact.read", "artifact", &second.artifact_id),
                ],
            );
            let first_grant = format!("grant-{fixture}-0");
            manager
                .connection
                .execute(
                    "UPDATE authority_grants SET scope=?1 WHERE grant_id LIKE ?2",
                    params![scope_name, format!("grant-{fixture}-%")],
                )
                .unwrap();
            manager
                .connection
                .execute(
                    "UPDATE authority_grants SET uses_consumed=1,state='CONSUMED' WHERE grant_id=?1",
                    [&first_grant],
                )
                .unwrap();
            assert!(matches!(
                scope_bound_reads(
                    &manager,
                    "T-artifact",
                    &binding_id,
                    &[second.artifact_id.clone()]
                ),
                Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
            ));

            manager
                .connection
                .execute(
                    "UPDATE authority_grants SET state='ACTIVE',max_uses=NULL WHERE grant_id=?1",
                    [&first_grant],
                )
                .unwrap();
            assert!(matches!(
                scope_bound_reads(
                    &manager,
                    "T-artifact",
                    &binding_id,
                    &[second.artifact_id.clone()]
                ),
                Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
            ));

            manager
                .connection
                .execute(
                    "UPDATE authority_grants SET max_uses=1 WHERE grant_id=?1",
                    [&first_grant],
                )
                .unwrap();
            let scope = scope_bound_reads(
                &manager,
                "T-artifact",
                &binding_id,
                &[second.artifact_id.clone()],
            )
            .unwrap();
            manager
                .open_artifact_reader(&scope, &second.artifact_id)
                .unwrap();
        }
    }

    #[test]
    fn public_bound_output_entry_points_reject_unbound_control_plane_requests() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let request = allocation("alloc-unbound-public");
        let forged = forged_provider_session();
        assert!(matches!(
            manager.allocate_bound_artifact_output(&forged, &request),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
        manager.allocate_artifact_output(&request).unwrap();
        assert!(matches!(
            manager.open_bound_artifact_output(&forged, &request.allocation_id),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
        assert!(matches!(
            manager.publish_bound_artifact_output(
                &forged,
                &publication("publication-unbound-public", &request.allocation_id)
            ),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
    }

    #[test]
    fn bound_allocation_validates_schema_before_idempotent_replay() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let allocation_id = "alloc-schema-replay";
        let (binding_id, attempt_id) = install_one_shot_binding(
            &manager,
            "allocation-schema-replay",
            &[],
            &[("artifact.write", "output-allocation", allocation_id)],
        );
        let session = manager
            .issue_provider_artifact_session("T-artifact", &binding_id)
            .unwrap();
        let mut request = allocation(allocation_id);
        request.binding_id = Some(binding_id);
        request.attempt_id = Some(attempt_id);
        manager
            .allocate_bound_artifact_output(&session, &request)
            .unwrap();

        request.expires_at = "2026-09-19T21:59:59Z".to_owned();
        manager
            .connection
            .execute(
                "UPDATE artifact_output_allocations SET expires_at=?2 WHERE allocation_id=?1",
                params![request.allocation_id, request.expires_at],
            )
            .unwrap();
        assert_eq!(
            manager
                .allocate_bound_artifact_output(&session, &request)
                .unwrap()
                .allocation_id,
            allocation_id
        );

        request.schema_version = "9.9".to_owned();
        assert!(matches!(
            manager.allocate_bound_artifact_output(&session, &request),
            Err(TaskManagerError::InvalidRecord(
                "invalid Artifact output allocation"
            ))
        ));
    }

    #[test]
    fn concurrent_bounded_grant_admission_is_atomic() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let artifact = manager
            .import_artifact(&import_request(), &mut Cursor::new(b"atomic".as_slice()))
            .unwrap();
        let (binding_id, _) = install_one_shot_binding(
            &manager,
            "atomic-bounded",
            &[artifact.artifact_id.clone()],
            &[("artifact.read", "artifact", &artifact.artifact_id)],
        );
        let grant_id = "grant-atomic-bounded-0";
        manager
            .connection
            .execute(
                "UPDATE authority_grants SET scope='TASK' WHERE grant_id=?1",
                [grant_id],
            )
            .unwrap();
        let execution = capture_execution_authority(
            &manager.connection,
            "T-artifact",
            &binding_id,
            "2026-09-19T22:00:00Z",
        )
        .unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let database_path = temp.path().join("task-manager.sqlite");
        let mut workers = Vec::new();
        for _ in 0..2 {
            let barrier = Arc::clone(&barrier);
            let database_path = database_path.clone();
            let execution = execution.clone();
            let artifact_id = artifact.artifact_id.clone();
            workers.push(std::thread::spawn(move || {
                let mut connection = Connection::open(database_path).unwrap();
                connection
                    .busy_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
                barrier.wait();
                let transaction = connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .unwrap();
                let admitted = admit_operation_grant(
                    &transaction,
                    "T-artifact",
                    &execution,
                    "artifact.read",
                    "artifact",
                    &artifact_id,
                    "2026-09-19T22:00:00Z",
                    grant_id,
                )
                .is_ok();
                if admitted {
                    transaction.commit().unwrap();
                }
                admitted
            }));
        }
        let admissions = workers
            .into_iter()
            .map(|worker| usize::from(worker.join().unwrap()))
            .sum::<usize>();
        assert_eq!(admissions, 1);
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT uses_consumed FROM authority_grants WHERE grant_id=?1",
                    [grant_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn one_shot_read_then_write_admits_the_exact_remaining_grant() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let input = manager
            .import_artifact(&import_request(), &mut Cursor::new(b"input".as_slice()))
            .unwrap();
        let allocation_id = "alloc-read-then-write";
        let (binding_id, attempt_id) = install_one_shot_binding(
            &manager,
            "read-write",
            &[input.artifact_id.clone()],
            &[
                ("artifact.read", "artifact", &input.artifact_id),
                ("artifact.write", "output-allocation", allocation_id),
            ],
        );
        let mut request = allocation(allocation_id);
        request.binding_id = Some(binding_id.clone());
        request.attempt_id = Some(attempt_id);
        manager.allocate_artifact_output(&request).unwrap();
        let scope = scope_bound_reads(
            &manager,
            "T-artifact",
            &binding_id,
            &[input.artifact_id.clone()],
        )
        .unwrap();
        let _reader = manager
            .open_artifact_reader(&scope, &input.artifact_id)
            .unwrap();
        manager
            .connection
            .execute(
                "UPDATE authority_grants SET expires_at='2026-09-19T21:00:00Z' WHERE grant_id='grant-read-write-0'",
                [],
            )
            .unwrap();

        let mut writer = manager.open_artifact_output(allocation_id).unwrap();
        writer.write_all(b"output").unwrap();
        writer.finish().unwrap();
        let states = manager
            .connection
            .prepare(
                "SELECT state FROM authority_grants WHERE grant_id LIKE 'grant-read-write-%' ORDER BY grant_id",
            )
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(states, ["CONSUMED", "CONSUMED"]);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one fixture exercises exact read/write grants, one-shot admission, approval time offsets, revocation, cancellation, and attempt supersession"
    )]
    fn bound_read_scope_fails_after_grant_revocation_or_attempt_supersession() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let artifact = manager
            .import_artifact(
                &import_request(),
                &mut Cursor::new(b"bound input".as_slice()),
            )
            .unwrap();
        let program_hash = allocation("unused").semantic_program_hash;
        let program_json = r#"{"nodes":[{"id":"compose_report","authority_requests":[{"action":"artifact.read","resource":"input"},{"action":"artifact.write","resource":"task.output"}]}]}"#;
        manager.connection.execute_batch(&format!(
            "INSERT INTO registry_snapshots(snapshot_id,manifest_json,created_at) VALUES ('registry-read','{{}}','2026-09-19T00:00:00Z');
             INSERT INTO semantic_program_revisions(task_id,program_revision,program_id,ir_version,semantic_hash,registry_snapshot_id,status,program_json,created_at) VALUES ('T-artifact',1,'program-read','0.1','{program_hash}','registry-read','active','{program_json}','2026-09-19T00:00:00Z');
             UPDATE tasks SET state='RUNNING',active_program_revision=1,active_step_ids_json='[\"compose_report\"]' WHERE task_id='T-artifact';
             INSERT INTO execution_bindings(binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,ir_version,node_id,capability,provider_id,provider_version,attempt,policy_decision_refs_json,grant_refs_json,execution_profile_ref,placement_json,binding_json,created_at) VALUES ('binding-read','attempt-read','T-artifact','{program_hash}','registry-read','0.1','compose_report','document.compose','provider:reader','1',1,'[\"decision-read\",\"decision-write\"]','[\"grant-read\",\"grant-write\"]','profile:test','{{}}','{{}}','2026-09-19T00:00:00Z');
             INSERT INTO step_executions(attempt_id,task_id,semantic_program_hash,registry_snapshot_id,node_id,binding_id,attempt_number,revision,state,input_artifacts_json,output_artifacts_json,created_at,updated_at) VALUES ('attempt-read','T-artifact','{program_hash}','registry-read','compose_report','binding-read',1,1,'RUNNING','[\"{}\"]','[]','2026-09-19T00:00:00Z','2026-09-19T00:00:00Z');
             INSERT INTO policy_snapshots(snapshot_id,scope_kind,scope_id,policy_language,policy_set_hash,engine_id,engine_version,snapshot_json,created_at) VALUES ('policy-read','task','T-artifact','cedar','sha256:policy','test','1','{{}}','2026-09-19T00:00:00Z');
             INSERT INTO authority_requests(request_id,task_id,semantic_program_hash,registry_snapshot_id,node_id,capability,principal_kind,principal_id,execution_binding_id,attempt_id,action,resolved_resource_kind,resolved_resource_id,semantic_selector,request_json,requested_at) VALUES ('request-read','T-artifact','{program_hash}','registry-read','compose_report','document.compose','provider','provider:reader','binding-read','attempt-read','artifact.read','artifact','{}','input','{{}}','2026-09-19T00:00:00Z');
             INSERT INTO policy_decisions(decision_id,authority_request_id,task_id,semantic_program_hash,node_id,principal_kind,principal_id,action,resolved_resource_kind,resolved_resource_id,decision,policy_snapshot_id,reason_codes_json,decision_json,decided_at) VALUES ('decision-read','request-read','T-artifact','{program_hash}','compose_report','provider','provider:reader','artifact.read','artifact','{}','ALLOW','policy-read','[]','{{}}','2026-09-19T00:00:00Z');
             INSERT INTO authority_grants(grant_id,task_id,semantic_program_hash,node_id,capability,principal_kind,principal_id,execution_binding_id,attempt_id,policy_decision_id,policy_snapshot_id,grants_json,scope,max_uses,uses_consumed,state,issued_at,expires_at) VALUES ('grant-read','T-artifact','{program_hash}','compose_report','document.compose','provider','provider:reader','binding-read','attempt-read','decision-read','policy-read','[{{\"action\":\"artifact.read\",\"resource_kind\":\"artifact\",\"resource_id\":\"{}\",\"semantic_selector\":\"input\"}}]','ONE_SHOT',1,0,'ACTIVE','2026-09-19T00:00:00Z','2026-09-20T00:00:00Z');
             INSERT INTO authority_requests(request_id,task_id,semantic_program_hash,registry_snapshot_id,node_id,capability,principal_kind,principal_id,execution_binding_id,attempt_id,action,resolved_resource_kind,resolved_resource_id,semantic_selector,request_json,requested_at) VALUES ('request-write','T-artifact','{program_hash}','registry-read','compose_report','document.compose','provider','provider:reader','binding-read','attempt-read','artifact.write','output-allocation','alloc-bound-revocation','task.output','{{}}','2026-09-19T00:00:00Z');
             INSERT INTO policy_decisions(decision_id,authority_request_id,task_id,semantic_program_hash,node_id,principal_kind,principal_id,action,resolved_resource_kind,resolved_resource_id,decision,policy_snapshot_id,reason_codes_json,decision_json,decided_at) VALUES ('decision-write','request-write','T-artifact','{program_hash}','compose_report','provider','provider:reader','artifact.write','output-allocation','alloc-bound-revocation','ALLOW','policy-read','[]','{{}}','2026-09-19T00:00:00Z');
             INSERT INTO authority_grants(grant_id,task_id,semantic_program_hash,node_id,capability,principal_kind,principal_id,execution_binding_id,attempt_id,policy_decision_id,policy_snapshot_id,grants_json,scope,state,issued_at,expires_at) VALUES ('grant-write','T-artifact','{program_hash}','compose_report','document.compose','provider','provider:reader','binding-read','attempt-read','decision-write','policy-read','[{{\"action\":\"artifact.write\",\"resource_kind\":\"output-allocation\",\"resource_id\":\"alloc-bound-revocation\",\"semantic_selector\":\"task.output\"}}]','TASK','ACTIVE','2026-09-19T00:00:00Z','2026-09-20T00:00:00Z');",
            artifact.artifact_id,
            artifact.artifact_id,
            artifact.artifact_id,
            artifact.artifact_id,
        )).unwrap();
        let revoked_scope = scope_bound_reads(
            &manager,
            "T-artifact",
            "binding-read",
            &[artifact.artifact_id.clone()],
        )
        .unwrap();
        let mut bound_allocation = allocation("alloc-bound-revocation");
        bound_allocation.binding_id = Some("binding-read".to_owned());
        bound_allocation.attempt_id = Some("attempt-read".to_owned());
        manager
            .connection
            .execute_batch(
                "UPDATE authority_requests SET resolved_resource_id='alloc-unrelated' WHERE request_id='request-write';
                 UPDATE policy_decisions SET resolved_resource_id='alloc-unrelated' WHERE decision_id='decision-write';
                 UPDATE authority_grants SET grants_json='[{\"action\":\"artifact.write\",\"resource_kind\":\"output-allocation\",\"resource_id\":\"alloc-unrelated\",\"semantic_selector\":\"task.output\"}]' WHERE grant_id='grant-write';",
            )
            .unwrap();
        assert!(matches!(
            manager.allocate_artifact_output(&bound_allocation),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
        manager
            .connection
            .execute_batch(
                "UPDATE authority_requests SET resolved_resource_id='alloc-bound-revocation' WHERE request_id='request-write';
                 UPDATE policy_decisions SET resolved_resource_id='alloc-bound-revocation' WHERE decision_id='decision-write';
                 UPDATE authority_grants SET grants_json='[{\"action\":\"artifact.write\",\"resource_kind\":\"output-allocation\",\"resource_id\":\"alloc-bound-revocation\",\"semantic_selector\":\"task.output\"}]' WHERE grant_id='grant-write';",
            )
            .unwrap();
        manager.allocate_artifact_output(&bound_allocation).unwrap();
        let mut bound_writer = manager
            .open_artifact_output("alloc-bound-revocation")
            .unwrap();
        bound_writer.write_all(b"before revocation").unwrap();
        let mut bound_reader = manager
            .open_artifact_reader(&revoked_scope, &artifact.artifact_id)
            .unwrap();
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT state FROM authority_grants WHERE grant_id='grant-read'",
                    [],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            "CONSUMED"
        );
        let mut first_byte = [0_u8; 1];
        assert_eq!(bound_reader.read(&mut first_byte).unwrap(), 1);
        assert_eq!(bound_reader.seek(SeekFrom::Start(0)).unwrap(), 0);
        assert_eq!(bound_reader.read(&mut first_byte).unwrap(), 1);
        manager
            .connection
            .execute(
                "UPDATE authority_grants SET state='REVOKED' WHERE grant_id IN ('grant-read','grant-write')",
                [],
            )
            .unwrap();
        assert!(matches!(
            manager.open_artifact_reader(&revoked_scope, &artifact.artifact_id),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
        assert_eq!(
            bound_reader.read(&mut first_byte).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            bound_reader.seek(SeekFrom::Start(0)).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            bound_writer
                .write_all(b"after revocation")
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );

        manager
            .connection
            .execute(
                "UPDATE authority_grants SET state='ACTIVE',uses_consumed=0 WHERE grant_id IN ('grant-read','grant-write')",
                [],
            )
            .unwrap();
        manager
            .connection
            .execute_batch(&format!(
                "INSERT INTO approval_requests(approval_id,authority_request_id,task_id,semantic_program_hash,node_id,action,status,request_json,created_at,expires_at) VALUES ('approval-read','request-read','T-artifact','{program_hash}','compose_report','artifact.read','APPROVED','{{}}','2026-09-19T00:00:00Z','2026-09-20T00:00:00Z');
                 UPDATE policy_decisions SET approval_request_id='approval-read' WHERE decision_id='decision-read';
                 UPDATE authority_grants SET approval_id='approval-read',expires_at='2026-09-19T22:15:00Z' WHERE grant_id='grant-read';
                 INSERT INTO approval_decisions(decision_id,approval_id,task_id,decision,decided_by_kind,decided_by_id,scope,approved_until,decision_json,decided_at) VALUES ('approval-decision-read','approval-read','T-artifact','APPROVE','user','user:approver','ONE_SHOT','2026-09-20T01:00:00+04:00','{{}}','2026-09-19T00:00:00Z');"
            ))
            .unwrap();
        assert!(matches!(
            scope_bound_reads(
                &manager,
                "T-artifact",
                "binding-read",
                &[artifact.artifact_id.clone()]
            ),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
        manager
            .connection
            .execute(
                "UPDATE approval_decisions SET approved_until='2026-09-19T18:30:00-04:00' WHERE decision_id='approval-decision-read'",
                [],
            )
            .unwrap();
        let cancellation_scope = scope_bound_reads(
            &manager,
            "T-artifact",
            "binding-read",
            &[artifact.artifact_id.clone()],
        )
        .unwrap();
        let mut cancellation_reader = manager
            .open_artifact_reader(&cancellation_scope, &artifact.artifact_id)
            .unwrap();
        manager
            .connection
            .execute(
                "UPDATE tasks SET state='CANCELLED' WHERE task_id='T-artifact'",
                [],
            )
            .unwrap();
        assert_eq!(
            cancellation_reader
                .read(&mut first_byte)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            cancellation_reader
                .seek(SeekFrom::Start(0))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        manager
            .connection
            .execute_batch(
                "UPDATE tasks SET state='RUNNING' WHERE task_id='T-artifact';
                 UPDATE authority_grants SET state='ACTIVE',uses_consumed=0 WHERE grant_id='grant-read';",
            )
            .unwrap();
        let superseded_scope = scope_bound_reads(
            &manager,
            "T-artifact",
            "binding-read",
            &[artifact.artifact_id.clone()],
        )
        .unwrap();
        manager.connection.execute_batch(&format!(
            "INSERT INTO execution_bindings(binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,ir_version,node_id,capability,provider_id,provider_version,attempt,policy_decision_refs_json,grant_refs_json,execution_profile_ref,placement_json,binding_json,created_at) VALUES ('binding-later','attempt-later','T-artifact','{program_hash}','registry-read','0.1','compose_report','document.compose','provider:reader','1',2,'[]','[]','profile:test','{{}}','{{}}','2026-09-19T00:01:00Z');
             INSERT INTO step_executions(attempt_id,task_id,semantic_program_hash,registry_snapshot_id,node_id,binding_id,attempt_number,revision,state,input_artifacts_json,output_artifacts_json,created_at,updated_at) VALUES ('attempt-later','T-artifact','{program_hash}','registry-read','compose_report','binding-later',2,1,'RUNNING','[\"{}\"]','[]','2026-09-19T00:01:00Z','2026-09-19T00:01:00Z');",
            artifact.artifact_id,
        )).unwrap();
        assert!(matches!(
            manager.open_artifact_reader(&superseded_scope, &artifact.artifact_id),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
    }

    #[test]
    fn reader_returns_the_verified_open_handle_across_path_replacement() {
        let temp = TempDir::new().unwrap();
        let state = Arc::new(Mutex::new(SwapClockState {
            armed_calls: None,
            blob: None,
            replacement: b"replacement".to_vec(),
            error: None,
        }));
        let mut manager = TaskManager::open_with_clock(
            temp.path().join("task-manager.sqlite"),
            Box::new(SwapClock {
                state: Arc::clone(&state),
            }),
        )
        .unwrap();
        manager
            .create_task(&CreateTask {
                task_id: "T-artifact".to_owned(),
                principal: Actor {
                    kind: "user".to_owned(),
                    id: "user:test".to_owned(),
                },
                workspace_id: None,
                original_intent: "reader swap".to_owned(),
                normalized_intent: None,
                active_step_ids: Vec::new(),
            })
            .unwrap();
        let original = b"verified bytes";
        let artifact = manager
            .import_artifact(&import_request(), &mut Cursor::new(original.as_slice()))
            .unwrap();
        let scope = manager
            .scope_owned_artifact_reads("T-artifact", &[artifact.artifact_id.clone()])
            .unwrap();
        let storage_ref = manager
            .connection
            .query_row(
                "SELECT b.storage_ref FROM artifacts a JOIN artifact_blobs b ON b.content_hash=a.content_hash WHERE a.artifact_id=?1",
                [&artifact.artifact_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        {
            let mut state = state.lock().unwrap();
            state.blob = Some(manager.artifact_store_root.join(storage_ref));
            // Point-of-use validation calls the clock first; the second call occurs
            // after hashing the already-open handle and before it is returned.
            state.armed_calls = Some(2);
        }
        let mut reader = manager
            .open_artifact_reader(&scope, &artifact.artifact_id)
            .unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, original);
        assert!(state.lock().unwrap().error.is_none());
    }

    #[test]
    fn cancelled_allocation_is_rejected_before_open_and_fences_an_open_writer() {
        let temp = TempDir::new().unwrap();
        let other_temp = TempDir::new().unwrap();
        let mut first = manager(&temp);
        let mut other = manager(&other_temp);
        first
            .allocate_artifact_output(&allocation("alloc-cancel-fence"))
            .unwrap();
        let mut writer = first.open_artifact_output("alloc-cancel-fence").unwrap();
        writer.write_all(b"before").unwrap();
        first
            .connection
            .execute(
                "UPDATE tasks SET state='CANCELLED' WHERE task_id='T-artifact'",
                [],
            )
            .unwrap();
        assert_eq!(
            writer.write_all(b"after").unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );

        other
            .allocate_artifact_output(&allocation("alloc-cancel-before-open"))
            .unwrap();
        other
            .connection
            .execute(
                "UPDATE tasks SET state='CANCELLED' WHERE task_id='T-artifact'",
                [],
            )
            .unwrap();
        assert!(matches!(
            other.open_artifact_output("alloc-cancel-before-open"),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
        let mut request = allocation("alloc-after-cancel");
        request.expires_at = "2026-09-20T00:00:00Z".to_owned();
        assert!(matches!(
            other.allocate_artifact_output(&request),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
    }

    #[test]
    fn every_new_content_directory_is_synced_before_publication_metadata() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let bytes = b"directory durability fault";
        let digest = match hash_reader(&mut Cursor::new(bytes.as_slice())).unwrap().1 {
            hash if hash.starts_with("sha256:") => hash[7..].to_owned(),
            _ => unreachable!(),
        };
        let first = format!("blobs/sha256/{}", &digest[..2]);
        DURABILITY_TEST_CONTROL.with(|control| {
            *control.borrow_mut() = Some((Vec::new(), Some("sync-parent:blobs/sha256".to_owned())));
        });
        let result = manager.import_artifact(&import_request(), &mut Cursor::new(bytes.as_slice()));
        let operations =
            DURABILITY_TEST_CONTROL.with(|control| control.borrow_mut().take().unwrap().0);
        assert!(result.is_err());
        assert!(operations.windows(3).any(|window| {
            window
                == [
                    format!("create:{first}"),
                    format!("sync:{first}"),
                    "sync-parent:blobs/sha256".to_owned(),
                ]
        }));
        assert_eq!(
            manager
                .connection
                .query_row("SELECT COUNT(*) FROM artifacts", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );

        DURABILITY_TEST_CONTROL.with(|control| {
            *control.borrow_mut() = Some((Vec::new(), None));
        });
        manager
            .import_artifact(&import_request(), &mut Cursor::new(bytes.as_slice()))
            .unwrap();
        let retry = DURABILITY_TEST_CONTROL.with(|control| control.borrow_mut().take().unwrap().0);
        assert!(retry.windows(3).any(|window| {
            window
                == [
                    format!("create:{first}"),
                    format!("sync:{first}"),
                    "sync-parent:blobs/sha256".to_owned(),
                ]
        }));
        assert_eq!(
            manager
                .connection
                .query_row("SELECT COUNT(*) FROM artifacts", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn sealed_staging_finish_replays_after_directory_sync_failure_and_response_loss() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let allocation_id = "alloc-finish-replay";
        let (binding_id, attempt_id) = install_one_shot_binding(
            &manager,
            "finish-replay",
            &[],
            &[("artifact.write", "output-allocation", allocation_id)],
        );
        let mut request = allocation(allocation_id);
        request.binding_id = Some(binding_id.clone());
        request.attempt_id = Some(attempt_id);
        allocate_bound(&mut manager, &request);
        let mut writer = open_bound(&mut manager, allocation_id);
        writer.write_all(b"one shot output").unwrap();
        DURABILITY_TEST_CONTROL.with(|control| {
            *control.borrow_mut() = Some((Vec::new(), Some("sync-staging-seal".to_owned())));
        });
        assert!(matches!(writer.finish(), Err(TaskManagerError::Io(_))));
        DURABILITY_TEST_CONTROL.with(|control| {
            control.borrow_mut().take();
        });
        assert_eq!(
            manager
                .get_artifact_output_allocation(allocation_id)
                .unwrap()
                .unwrap()
                .state,
            ArtifactAllocationState::Writing
        );
        let staging_ref = load_allocation_row(&manager.connection, allocation_id)
            .unwrap()
            .unwrap()
            .staging_ref
            .unwrap();
        let seal_reference = seal_ref(&staging_ref);
        assert!(!manager.artifact_store_root.join(&seal_reference).exists());
        assert!(
            manager
                .artifact_store_root
                .join(format!("{seal_reference}.pending"))
                .exists()
        );
        let session = manager
            .issue_provider_artifact_session("T-artifact", &binding_id)
            .unwrap();
        assert_eq!(
            manager
                .retry_bound_artifact_output_finish(&session, allocation_id)
                .unwrap(),
            15
        );
        assert!(manager.artifact_store_root.join(&seal_reference).exists());
        assert!(
            !manager
                .artifact_store_root
                .join(format!("{seal_reference}.pending"))
                .exists()
        );
        // Response-loss retries authenticate the same seal and do not consume another grant use.
        assert_eq!(
            manager
                .retry_bound_artifact_output_finish(&session, allocation_id)
                .unwrap(),
            15
        );
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT uses_consumed FROM authority_grants WHERE grant_id='grant-finish-replay-0'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn complete_final_seal_retries_directory_sync_before_acknowledging_success() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let allocation_id = "alloc-final-sync-replay";
        let (binding_id, attempt_id) = install_one_shot_binding(
            &manager,
            "final-sync-replay",
            &[],
            &[("artifact.write", "output-allocation", allocation_id)],
        );
        let mut request = allocation(allocation_id);
        request.binding_id = Some(binding_id.clone());
        request.attempt_id = Some(attempt_id);
        allocate_bound(&mut manager, &request);
        let mut writer = open_bound(&mut manager, allocation_id);
        writer.write_all(b"directory sync retry").unwrap();
        DURABILITY_TEST_CONTROL.with(|control| {
            *control.borrow_mut() = Some((Vec::new(), Some("sync-staging-seal-final".to_owned())));
        });
        assert!(matches!(writer.finish(), Err(TaskManagerError::Io(_))));
        let staging_ref = load_allocation_row(&manager.connection, allocation_id)
            .unwrap()
            .unwrap()
            .staging_ref
            .unwrap();
        let seal_reference = seal_ref(&staging_ref);
        assert!(manager.artifact_store_root.join(&seal_reference).exists());
        assert!(
            !manager
                .artifact_store_root
                .join(format!("{seal_reference}.pending"))
                .exists()
        );
        let session = manager
            .issue_provider_artifact_session("T-artifact", &binding_id)
            .unwrap();
        assert!(matches!(
            manager.retry_bound_artifact_output_finish(&session, allocation_id),
            Err(TaskManagerError::Io(_))
        ));
        let failed_operations =
            DURABILITY_TEST_CONTROL.with(|control| control.borrow_mut().take().unwrap().0);
        assert_eq!(
            failed_operations
                .iter()
                .filter(|operation| operation.as_str() == "sync-staging-seal-final")
                .count(),
            2
        );

        DURABILITY_TEST_CONTROL.with(|control| {
            *control.borrow_mut() = Some((Vec::new(), None));
        });
        assert_eq!(
            manager
                .retry_bound_artifact_output_finish(&session, allocation_id)
                .unwrap(),
            20
        );
        assert_eq!(
            manager
                .retry_bound_artifact_output_finish(&session, allocation_id)
                .unwrap(),
            20
        );
        let successful_operations =
            DURABILITY_TEST_CONTROL.with(|control| control.borrow_mut().take().unwrap().0);
        assert_eq!(
            successful_operations
                .iter()
                .filter(|operation| operation.as_str() == "sync-staging-seal-final")
                .count(),
            2
        );
    }

    #[test]
    fn retry_finish_sync_failure_fences_the_retained_writer_from_complete_seal() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let allocation_id = "alloc-retry-sync-writer-fence";
        let (binding_id, attempt_id) = install_one_shot_binding(
            &manager,
            "retry-sync-writer-fence",
            &[],
            &[("artifact.write", "output-allocation", allocation_id)],
        );
        let mut request = allocation(allocation_id);
        request.binding_id = Some(binding_id.clone());
        request.attempt_id = Some(attempt_id);
        allocate_bound(&mut manager, &request);
        let mut retained = open_bound(&mut manager, allocation_id);
        retained.write_all(b"sealed before sync failure").unwrap();
        retained.flush().unwrap();
        let session = manager
            .issue_provider_artifact_session("T-artifact", &binding_id)
            .unwrap();

        DURABILITY_TEST_CONTROL.with(|control| {
            *control.borrow_mut() = Some((Vec::new(), Some("sync-staging-seal-final".to_owned())));
        });
        assert!(matches!(
            manager.retry_bound_artifact_output_finish(&session, allocation_id),
            Err(TaskManagerError::Io(_))
        ));
        let staging_ref = load_allocation_row(&manager.connection, allocation_id)
            .unwrap()
            .unwrap()
            .staging_ref
            .unwrap();
        assert!(
            manager
                .artifact_store_root
                .join(seal_ref(&staging_ref))
                .exists()
        );
        assert!(retained.write_all(b"must not append").is_err());
        assert!(retained.flush().is_err());
        assert!(retained.finish().is_err());

        DURABILITY_TEST_CONTROL.with(|control| {
            *control.borrow_mut() = Some((Vec::new(), None));
        });
        assert_eq!(
            manager
                .retry_bound_artifact_output_finish(&session, allocation_id)
                .unwrap(),
            26
        );
        DURABILITY_TEST_CONTROL.with(|control| {
            control.borrow_mut().take();
        });
    }

    #[test]
    fn retry_finish_uses_fresh_post_hash_time_for_expiry_fence() {
        let temp = TempDir::new().unwrap();
        let now = Arc::new(Mutex::new("2026-09-19T22:00:00Z".to_owned()));
        let mut manager = manager_with_mutable_clock(&temp, &now);
        let allocation_id = "alloc-retry-fresh-time";
        let (binding_id, attempt_id) = install_one_shot_binding(
            &manager,
            "retry-fresh-time",
            &[],
            &[("artifact.write", "output-allocation", allocation_id)],
        );
        let mut request = allocation(allocation_id);
        request.binding_id = Some(binding_id.clone());
        request.attempt_id = Some(attempt_id);
        allocate_bound(&mut manager, &request);
        let mut writer = open_bound(&mut manager, allocation_id);
        writer.write_all(b"expires while hashing").unwrap();
        writer.flush().unwrap();
        let session = manager
            .issue_provider_artifact_session("T-artifact", &binding_id)
            .unwrap();
        let advanced = Arc::clone(&now);
        WRITER_FINISH_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                *advanced.lock().unwrap() = "2026-09-20T00:00:00Z".to_owned();
                Ok(())
            }));
        });
        assert!(matches!(
            manager.retry_bound_artifact_output_finish(&session, allocation_id),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
        let staging_ref = load_allocation_row(&manager.connection, allocation_id)
            .unwrap()
            .unwrap()
            .staging_ref
            .unwrap();
        assert!(
            !manager
                .artifact_store_root
                .join(seal_ref(&staging_ref))
                .exists()
        );
    }

    #[test]
    fn complete_pending_seal_rejects_changed_staging_and_survives_retry_and_reopen() {
        let temp = TempDir::new().unwrap();
        let database = temp.path().join("task-manager.sqlite");
        let mut manager = manager(&temp);
        let allocation_id = "alloc-pending-authoritative";
        let (binding_id, attempt_id) = install_one_shot_binding(
            &manager,
            "pending-authoritative",
            &[],
            &[("artifact.write", "output-allocation", allocation_id)],
        );
        let mut request = allocation(allocation_id);
        request.binding_id = Some(binding_id.clone());
        request.attempt_id = Some(attempt_id);
        allocate_bound(&mut manager, &request);
        let mut writer = open_bound(&mut manager, allocation_id);
        writer.write_all(b"original staging").unwrap();
        DURABILITY_TEST_CONTROL.with(|control| {
            *control.borrow_mut() = Some((Vec::new(), Some("sync-staging-seal".to_owned())));
        });
        assert!(matches!(writer.finish(), Err(TaskManagerError::Io(_))));
        DURABILITY_TEST_CONTROL.with(|control| {
            control.borrow_mut().take();
        });
        let staging_ref = load_allocation_row(&manager.connection, allocation_id)
            .unwrap()
            .unwrap()
            .staging_ref
            .unwrap();
        let pending_path = manager
            .artifact_store_root
            .join(format!("{}.pending", seal_ref(&staging_ref)));
        let pending_before = std::fs::read(&pending_path).unwrap();
        std::fs::write(
            manager.artifact_store_root.join(&staging_ref),
            b"changed staging!",
        )
        .unwrap();
        let session = manager
            .issue_provider_artifact_session("T-artifact", &binding_id)
            .unwrap();
        assert!(matches!(
            manager.retry_bound_artifact_output_finish(&session, allocation_id),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_HASH_MISMATCH"))
        ));
        assert_eq!(std::fs::read(&pending_path).unwrap(), pending_before);
        drop(manager);
        assert!(matches!(
            TaskManager::open_with_clock(&database, Box::new(FixedClock)),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_HASH_MISMATCH"))
        ));
        assert_eq!(std::fs::read(pending_path).unwrap(), pending_before);
    }

    #[test]
    fn startup_reconstructs_interrupted_seal_but_rejects_complete_mismatch() {
        for (suffix, seal_bytes, should_open) in [
            ("partial", b"{\"version\":".as_slice(), true),
            (
                "mismatch",
                br#"{"version":1,"allocation_id":"alloc-seal-mismatch","size_bytes":999,"content_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
                false,
            ),
        ] {
            let temp = TempDir::new().unwrap();
            let database = temp.path().join("task-manager.sqlite");
            let mut manager = manager(&temp);
            let allocation_id = format!("alloc-seal-{suffix}");
            manager
                .allocate_artifact_output(&allocation(&allocation_id))
                .unwrap();
            let mut writer = manager.open_artifact_output(&allocation_id).unwrap();
            writer.write_all(b"recoverable staging bytes").unwrap();
            drop(writer);
            let staging_ref = load_allocation_row(&manager.connection, &allocation_id)
                .unwrap()
                .unwrap()
                .staging_ref
                .unwrap();
            manager
                .artifact_store_dir
                .write(seal_ref(&staging_ref), seal_bytes)
                .unwrap();
            secure_cap_file_permissions(
                &manager
                    .artifact_store_dir
                    .open(seal_ref(&staging_ref))
                    .unwrap(),
            )
            .unwrap();
            drop(manager);

            let reopened = TaskManager::open_with_clock(&database, Box::new(FixedClock));
            if !should_open {
                assert!(matches!(
                    reopened,
                    Err(TaskManagerError::InvalidRecord("ARTIFACT_HASH_MISMATCH"))
                ));
                continue;
            }
            let reopened = reopened.unwrap();
            let sealed = reopened
                .sealed_staging(&load_allocation_row(&reopened.connection, &allocation_id).unwrap().unwrap(), &publication("unused", &allocation_id))
                .unwrap();
            assert_eq!(sealed.size_bytes, 25);
        }
    }

    #[test]
    fn startup_rejects_complete_schema_invalid_seals_without_rewriting_them() {
        for (suffix, seal_bytes) in [
            (
                "unknown-field",
                br#"{"version":1,"allocation_id":"alloc-schema-unknown-field","size_bytes":25,"content_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","unexpected":true}"#.as_slice(),
            ),
            (
                "wrong-type",
                br#"{"version":1,"allocation_id":"alloc-schema-wrong-type","size_bytes":"25","content_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
            ),
            ("malformed-syntax", br#"{"version":1,}"#),
        ] {
            let temp = TempDir::new().unwrap();
            let database = temp.path().join("task-manager.sqlite");
            let mut manager = manager(&temp);
            let allocation_id = format!("alloc-schema-{suffix}");
            manager
                .allocate_artifact_output(&allocation(&allocation_id))
                .unwrap();
            let mut writer = manager.open_artifact_output(&allocation_id).unwrap();
            writer.write_all(b"recoverable staging bytes").unwrap();
            drop(writer);
            let staging_ref = load_allocation_row(&manager.connection, &allocation_id)
                .unwrap()
                .unwrap()
                .staging_ref
                .unwrap();
            let seal_path = manager.artifact_store_root.join(seal_ref(&staging_ref));
            std::fs::write(&seal_path, seal_bytes).unwrap();
            secure_cap_file_permissions(
                &manager
                    .artifact_store_dir
                    .open(seal_ref(&staging_ref))
                    .unwrap(),
            )
            .unwrap();
            drop(manager);

            assert!(matches!(
                TaskManager::open_with_clock(&database, Box::new(FixedClock)),
                Err(TaskManagerError::InvalidRecord("ARTIFACT_HASH_MISMATCH"))
            ));
            assert_eq!(std::fs::read(seal_path).unwrap(), seal_bytes);
        }
    }

    #[test]
    fn startup_reconstructs_only_eof_truncated_final_or_pending_seals() {
        for target in ["final", "pending"] {
            let temp = TempDir::new().unwrap();
            let database = temp.path().join("task-manager.sqlite");
            let mut manager = manager(&temp);
            let allocation_id = format!("alloc-eof-{target}");
            manager
                .allocate_artifact_output(&allocation(&allocation_id))
                .unwrap();
            let mut writer = manager.open_artifact_output(&allocation_id).unwrap();
            writer.write_all(b"recoverable staging bytes").unwrap();
            drop(writer);
            let staging_ref = load_allocation_row(&manager.connection, &allocation_id)
                .unwrap()
                .unwrap()
                .staging_ref
                .unwrap();
            let seal_reference = seal_ref(&staging_ref);
            let evidence_reference = if target == "final" {
                seal_reference.clone()
            } else {
                format!("{seal_reference}.pending")
            };
            manager
                .artifact_store_dir
                .write(&evidence_reference, b"{\"version\":")
                .unwrap();
            secure_cap_file_permissions(
                &manager
                    .artifact_store_dir
                    .open(&evidence_reference)
                    .unwrap(),
            )
            .unwrap();
            drop(manager);

            let reopened = TaskManager::open_with_clock(&database, Box::new(FixedClock)).unwrap();
            let sealed =
                read_staging_seal_evidence(&reopened.artifact_store_dir, &seal_reference).unwrap();
            assert!(matches!(sealed, StagingSealEvidence::Complete(_)));
            assert!(
                !reopened
                    .artifact_store_root
                    .join(format!("{seal_reference}.pending"))
                    .exists()
            );
        }
    }

    #[test]
    fn complete_pending_seal_wins_over_eof_truncated_final() {
        let temp = TempDir::new().unwrap();
        let database = temp.path().join("task-manager.sqlite");
        let mut manager = manager(&temp);
        let allocation_id = "alloc-pending-wins";
        manager
            .allocate_artifact_output(&allocation(allocation_id))
            .unwrap();
        let mut writer = manager.open_artifact_output(allocation_id).unwrap();
        writer.write_all(b"pending wins bytes").unwrap();
        drop(writer);
        let staging_ref = load_allocation_row(&manager.connection, allocation_id)
            .unwrap()
            .unwrap()
            .staging_ref
            .unwrap();
        let (size_bytes, content_hash) =
            hash_internal_file(&manager.artifact_store_dir, &staging_ref).unwrap();
        let seal_reference = seal_ref(&staging_ref);
        manager
            .artifact_store_dir
            .write(&seal_reference, b"{\"version\":")
            .unwrap();
        let pending_reference = format!("{seal_reference}.pending");
        let pending = serde_json::to_vec(&SealedStaging {
            version: SEALED_STAGING_VERSION,
            allocation_id: allocation_id.to_owned(),
            size_bytes,
            content_hash,
        })
        .unwrap();
        manager
            .artifact_store_dir
            .write(&pending_reference, &pending)
            .unwrap();
        for reference in [&seal_reference, &pending_reference] {
            secure_cap_file_permissions(&manager.artifact_store_dir.open(reference).unwrap())
                .unwrap();
        }
        drop(manager);

        let reopened = TaskManager::open_with_clock(&database, Box::new(FixedClock)).unwrap();
        assert_eq!(
            std::fs::read(reopened.artifact_store_root.join(&seal_reference)).unwrap(),
            pending
        );
        assert!(
            !reopened
                .artifact_store_root
                .join(pending_reference)
                .exists()
        );
    }

    #[test]
    fn writer_finish_rechecks_recovery_after_hash_before_seal() {
        let temp = TempDir::new().unwrap();
        let database = temp.path().join("task-manager.sqlite");
        let mut manager = manager(&temp);
        let allocation_id = "alloc-finish-fence";
        let (binding_id, attempt_id) = install_one_shot_binding(
            &manager,
            "finish-fence",
            &[],
            &[("artifact.write", "output-allocation", allocation_id)],
        );
        let mut request = allocation(allocation_id);
        request.binding_id = Some(binding_id.clone());
        request.attempt_id = Some(attempt_id);
        allocate_bound(&mut manager, &request);
        let mut writer = open_bound(&mut manager, allocation_id);
        writer.write_all(b"long hash candidate").unwrap();
        WRITER_FINISH_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                Connection::open(database)?.execute(
                    "UPDATE tasks SET state='RECOVERING' WHERE task_id='T-artifact'",
                    [],
                )?;
                Ok(())
            }));
        });
        assert!(matches!(
            writer.finish(),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
        let staging_ref = load_allocation_row(&manager.connection, allocation_id)
            .unwrap()
            .unwrap()
            .staging_ref
            .unwrap();
        assert!(
            !manager
                .artifact_store_root
                .join(seal_ref(&staging_ref))
                .exists()
        );
        manager
            .connection
            .execute(
                "UPDATE tasks SET state='RUNNING' WHERE task_id='T-artifact'",
                [],
            )
            .unwrap();
        let session = manager
            .issue_provider_artifact_session("T-artifact", &binding_id)
            .unwrap();
        assert_eq!(
            manager
                .retry_bound_artifact_output_finish(&session, allocation_id)
                .unwrap(),
            19
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_store_root_is_created_atomically_private() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = TempDir::new().unwrap();
        let root = temp.path().join("atomic-private-root");
        create_store_root(&root).unwrap();
        assert_eq!(
            std::fs::metadata(root).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_store_root_is_created_with_a_private_acl_at_creation() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("atomic-private-root");
        create_store_root(&root).unwrap();
        let opened = open_store_root_bound(&root).unwrap();
        let file = opened.into_std_file();
        let information = winx::winapi_util::file::information(&file).unwrap();
        validate_windows_store_security(
            &root,
            Some((information.volume_serial_number(), information.file_index())),
        )
        .unwrap();
    }

    #[test]
    fn initial_and_nested_directory_durability_orders_child_before_parent() {
        let temp = TempDir::new().unwrap();
        DURABILITY_TEST_CONTROL.with(|control| {
            *control.borrow_mut() = Some((Vec::new(), None));
        });
        let manager = manager(&temp);
        let initial =
            DURABILITY_TEST_CONTROL.with(|control| control.borrow_mut().take().unwrap().0);
        for required in [
            ["create-root", "sync-root", "sync-root-parent"],
            ["create:blobs", "sync:blobs", "sync-parent:."],
            [
                "create:blobs/sha256",
                "sync:blobs/sha256",
                "sync-parent:blobs",
            ],
            ["create:staging", "sync:staging", "sync-parent:."],
            ["create:quarantine", "sync:quarantine", "sync-parent:."],
            [
                "create:blobs/pending",
                "sync:blobs/pending",
                "sync-parent:blobs",
            ],
        ] {
            assert!(initial.windows(3).any(|window| window == required));
        }

        DURABILITY_TEST_CONTROL.with(|control| {
            *control.borrow_mut() = Some((Vec::new(), None));
        });
        create_durable_ancestors(&manager.artifact_store_dir, "nested/one/two").unwrap();
        let nested = DURABILITY_TEST_CONTROL.with(|control| control.borrow_mut().take().unwrap().0);
        assert_eq!(
            nested,
            [
                "create:nested",
                "sync:nested",
                "sync-parent:.",
                "create:nested/one",
                "sync:nested/one",
                "sync-parent:nested",
                "create:nested/one/two",
                "sync:nested/one/two",
                "sync-parent:nested/one",
            ]
        );
    }

    #[test]
    fn live_writer_publication_failure_is_durable_and_fences_the_writer() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        manager
            .allocate_artifact_output(&allocation("alloc-live"))
            .unwrap();
        let mut writer = manager.open_artifact_output("alloc-live").unwrap();
        writer.write_all(b"partial").unwrap();
        let request = publication("pub-live", "alloc-live");
        let early = manager.publish_artifact_output(&request).unwrap();
        assert!(!early.published);
        assert_eq!(early.reason_code, "ARTIFACT_ALLOCATION_STATE_CONFLICT");
        assert_eq!(manager.publish_artifact_output(&request).unwrap(), early);
        assert!(writer.write_all(b"-finished").is_err());
        assert!(writer.finish().is_err());
        let mut conflicting = request;
        conflicting.labels.push("changed".to_owned());
        assert_eq!(
            manager
                .publish_artifact_output(&conflicting)
                .unwrap()
                .reason_code,
            "ARTIFACT_PUBLICATION_ID_REUSE_CONFLICT"
        );
        assert_publication_not_committed(&manager, "alloc-live", "pub-live");
    }

    #[test]
    fn terminal_preflight_failure_fences_an_unopened_allocation() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        manager
            .allocate_artifact_output(&allocation("alloc-unopened-terminal"))
            .unwrap();
        let request = publication("pub-unopened-terminal", "alloc-unopened-terminal");
        let failure = manager.publish_artifact_output(&request).unwrap();
        assert!(!failure.published);
        assert_eq!(failure.reason_code, "ARTIFACT_ALLOCATION_STATE_CONFLICT");
        assert_eq!(manager.publish_artifact_output(&request).unwrap(), failure);
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT state FROM artifact_output_allocations WHERE allocation_id='alloc-unopened-terminal'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "FAILED"
        );
        assert!(matches!(
            manager.open_artifact_output("alloc-unopened-terminal"),
            Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_ALLOCATION_STATE_CONFLICT"
            ))
        ));
        assert_publication_not_committed(
            &manager,
            "alloc-unopened-terminal",
            "pub-unopened-terminal",
        );
    }

    #[test]
    fn writer_limit_is_clamped_to_global_import_limit() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let mut request = allocation("alloc-global-limit");
        request.max_size_bytes = Some(IMPORT_LIMIT + 1);
        manager.allocate_artifact_output(&request).unwrap();
        let writer = manager.open_artifact_output("alloc-global-limit").unwrap();
        assert_eq!(writer.maximum, IMPORT_LIMIT);
    }

    #[cfg(unix)]
    #[test]
    fn directory_capability_rejects_staging_and_blob_symlink_escapes() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        manager
            .allocate_artifact_output(&allocation("alloc-link-escape"))
            .unwrap();
        symlink(
            outside.path(),
            manager.artifact_store_root.join("staging").join("escape"),
        )
        .unwrap();
        manager
            .connection
            .execute(
                "UPDATE artifact_output_allocations SET staging_ref='staging/escape/output' WHERE allocation_id='alloc-link-escape'",
                [],
            )
            .unwrap();
        assert!(manager.open_artifact_output("alloc-link-escape").is_err());
        assert!(!outside.path().join("output").exists());

        let artifact = manager
            .import_artifact(&import_request(), &mut Cursor::new(b"inside".as_slice()))
            .unwrap();
        let scope = manager
            .scope_owned_artifact_reads("T-artifact", &[artifact.artifact_id.clone()])
            .unwrap();
        std::fs::write(outside.path().join("external-blob"), b"inside").unwrap();
        symlink(
            outside.path(),
            manager.artifact_store_root.join("blobs").join("escape"),
        )
        .unwrap();
        manager
            .connection
            .execute(
                "UPDATE artifact_blobs SET storage_ref='blobs/escape/external-blob' WHERE content_hash=?1",
                [artifact.content_hash.as_ref().unwrap().tagged()],
            )
            .unwrap();
        assert!(
            manager
                .open_artifact_reader(&scope, &artifact.artifact_id)
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn artifact_store_root_cannot_be_preplaced_as_a_symlink() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let database = temp.path().join("preplaced.sqlite");
        symlink(
            outside.path(),
            temp.path().join("preplaced.sqlite.artifacts"),
        )
        .unwrap();
        assert!(matches!(
            TaskManager::open_with_clock(database, Box::new(FixedClock)),
            Err(TaskManagerError::InvalidRecord(
                "Artifact store root must be a real directory"
            ))
        ));
        assert!(std::fs::read_dir(outside.path()).unwrap().next().is_none());
    }

    #[cfg(windows)]
    #[test]
    fn windows_security_commands_ignore_current_directory_and_path() {
        const CHILD: &str = "AIOS_WINDOWS_SECURITY_POISON_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let temp = TempDir::new().unwrap();
            TaskManager::open_with_clock(
                temp.path().join("task-manager.sqlite"),
                Box::new(FixedClock),
            )
            .unwrap();
            return;
        }

        let poison = TempDir::new().unwrap();
        for name in ["whoami.exe", "icacls.exe", "powershell.exe", "pwsh.exe"] {
            std::fs::copy(r"C:\Windows\System32\cmd.exe", poison.path().join(name)).unwrap();
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "artifact_store::tests::windows_security_commands_ignore_current_directory_and_path",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("PATH", poison.path())
            .current_dir(poison.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "poisoned child failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(windows)]
    #[test]
    fn untrusted_existing_store_acl_fails_closed() {
        let temp = TempDir::new().unwrap();
        let database = temp.path().join("task-manager.sqlite");
        let manager = TaskManager::open_with_clock(&database, Box::new(FixedClock)).unwrap();
        let root = manager.artifact_store_root.clone();
        drop(manager);
        let root_text = root.to_str().unwrap();
        let output = std::process::Command::new(r"C:\Windows\System32\icacls.exe")
            .args([root_text, "/grant", "*S-1-1-0:(OI)(CI)R"])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(matches!(
            TaskManager::open_with_clock(&database, Box::new(FixedClock)),
            Err(TaskManagerError::InvalidRecord(
                "Artifact store ownership or ACL is untrusted"
            ))
        ));
    }

    #[cfg(windows)]
    #[test]
    fn descendant_acl_is_authenticated_from_its_pinned_open_handle() {
        let temp = TempDir::new().unwrap();
        let database = temp.path().join("task-manager.sqlite");
        let manager = TaskManager::open_with_clock(&database, Box::new(FixedClock)).unwrap();
        let staging = manager.artifact_store_root.join("staging");
        drop(manager);
        let output = std::process::Command::new(r"C:\Windows\System32\icacls.exe")
            .args([staging.to_str().unwrap(), "/grant", "*S-1-1-0:(OI)(CI)R"])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(matches!(
            TaskManager::open_with_clock(&database, Box::new(FixedClock)),
            Err(TaskManagerError::InvalidRecord(
                "Artifact store ownership or ACL is untrusted"
            ))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn privileged_manager_rejects_attacker_owned_private_store_tree() {
        if manager_effective_uid().unwrap() != 0 {
            return;
        }
        let chown = ["/usr/bin/chown", "/bin/chown"]
            .into_iter()
            .find(|candidate| Path::new(candidate).is_file())
            .unwrap();
        let temp = TempDir::new().unwrap();
        let database = temp.path().join("task-manager.sqlite");
        let manager = TaskManager::open_with_clock(&database, Box::new(FixedClock)).unwrap();
        let root = manager.artifact_store_root.clone();
        drop(manager);
        assert!(
            std::process::Command::new(chown)
                .args(["-R", "1"])
                .arg(&root)
                .status()
                .unwrap()
                .success()
        );
        let result = TaskManager::open_with_clock(&database, Box::new(FixedClock));
        let _ = std::process::Command::new(chown)
            .args(["-R", "0"])
            .arg(&root)
            .status();
        assert!(matches!(
            result,
            Err(TaskManagerError::InvalidRecord(
                "Artifact store ownership or permissions are untrusted"
            ))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn untrusted_existing_store_mode_fails_closed() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = TempDir::new().unwrap();
        let database = temp.path().join("task-manager.sqlite");
        let manager = TaskManager::open_with_clock(&database, Box::new(FixedClock)).unwrap();
        let root = manager.artifact_store_root.clone();
        drop(manager);
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            TaskManager::open_with_clock(&database, Box::new(FixedClock)),
            Err(TaskManagerError::InvalidRecord(message))
                if message == "Artifact store ownership or permissions are untrusted"
                    || message == "opened Artifact store ownership or permissions are untrusted"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn opened_store_handle_rejects_parent_entry_swap() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = TempDir::new().unwrap();
        let database = temp.path().join("task-manager.sqlite");
        let manager = TaskManager::open_with_clock(&database, Box::new(FixedClock)).unwrap();
        let root = manager.artifact_store_root.clone();
        drop(manager);
        let displaced = root.with_extension("artifacts-displaced");
        let hook_displaced = displaced.clone();
        ROOT_OPEN_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |opened_root| {
                std::fs::rename(opened_root, &hook_displaced)?;
                std::fs::create_dir(opened_root)?;
                std::fs::set_permissions(opened_root, std::fs::Permissions::from_mode(0o700))?;
                Ok(())
            }));
        });

        assert!(matches!(
            TaskManager::open_with_clock(&database, Box::new(FixedClock)),
            Err(TaskManagerError::InvalidRecord(
                "Artifact store root changed while it was being opened"
            ))
        ));
        std::fs::remove_dir(&root).unwrap();
        std::fs::rename(displaced, root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn effective_uid_comes_from_the_process_identity_api() {
        use std::os::unix::fs::MetadataExt as _;

        let temp = TempDir::new().unwrap();
        assert_eq!(
            manager_effective_uid().unwrap(),
            temp.path().metadata().unwrap().uid()
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_opened_store_acl_rejects_evidence_for_a_different_handle_identity() {
        let temp = TempDir::new().unwrap();
        let opened = temp.path().join("opened-root");
        let decoy = temp.path().join("trusted-decoy");
        std::fs::create_dir(&opened).unwrap();
        std::fs::create_dir(&decoy).unwrap();
        secure_store_root(&opened, true).unwrap();
        secure_store_root(&decoy, true).unwrap();
        let opened_file = Dir::open_ambient_dir(&opened, ambient_authority())
            .unwrap()
            .into_std_file();

        assert!(matches!(
            validate_opened_store_root(&decoy, &opened_file),
            Err(TaskManagerError::InvalidRecord(
                "Artifact store root changed while security was inspected"
            ))
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one collision fixture covers runtime and startup quarantine, shared metadata fanout, provenance, and an already-issued reader fence"
    )]
    fn partial_final_blob_is_never_overwritten_and_pending_blob_is_reconciled() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let bytes = b"complete-content";
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let hash = tagged_digest(hasher);
        let digest = hash.strip_prefix("sha256:").unwrap();
        let final_ref = format!("blobs/sha256/{}/{}/{}", &digest[..2], &digest[2..4], digest);
        manager
            .artifact_store_dir
            .create_dir_all(format!("blobs/sha256/{}/{}", &digest[..2], &digest[2..4]))
            .unwrap();
        manager
            .artifact_store_dir
            .write(&final_ref, b"partial")
            .unwrap();
        assert!(matches!(
            manager.import_artifact(&import_request(), &mut Cursor::new(bytes.as_slice())),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_HASH_MISMATCH"))
        ));
        assert!(!manager.artifact_store_root.join(&final_ref).exists());
        assert_eq!(
            manager
                .artifact_store_dir
                .read_dir("quarantine")
                .unwrap()
                .count(),
            2
        );

        let pending_ref = format!("blobs/pending/{digest}-interrupted");
        manager
            .artifact_store_dir
            .write(&final_ref, b"corrupt-final")
            .unwrap();
        manager
            .artifact_store_dir
            .write(&pending_ref, bytes)
            .unwrap();
        let report = manager.reconcile_artifacts_startup().unwrap();
        assert!(!report.findings.iter().any(|finding| {
            finding.kind == ArtifactReconciliationKind::BlobCorrupt
                && finding.content_hash.as_deref() == Some(hash.as_str())
        }));
        assert_eq!(manager.artifact_store_dir.read(&final_ref).unwrap(), bytes);
        assert!(!manager.artifact_store_root.join(pending_ref).exists());
        assert!(manager.reconcile_artifacts_startup().is_ok());

        let pending_ref = format!("blobs/pending/{digest}-retry");
        manager
            .artifact_store_dir
            .write(&pending_ref, bytes)
            .unwrap();
        DURABILITY_TEST_CONTROL.with(|control| {
            *control.borrow_mut() = Some((Vec::new(), None));
        });
        manager.reconcile_artifacts_startup().unwrap();
        let operations =
            DURABILITY_TEST_CONTROL.with(|control| control.borrow_mut().take().unwrap().0);
        assert!(operations.windows(3).any(|window| {
            window
                == [
                    "sync-recovered-blob-parent",
                    "unlink-recovered-blob-pending",
                    "sync-recovered-blob-pending",
                ]
        }));
        assert_eq!(
            std::fs::read(manager.artifact_store_root.join(&final_ref)).unwrap(),
            bytes
        );
        assert!(!manager.artifact_store_root.join(pending_ref).exists());

        let artifact = manager
            .import_artifact(&import_request(), &mut Cursor::new(bytes.as_slice()))
            .unwrap();
        let shared_artifact = manager
            .import_artifact(&import_request(), &mut Cursor::new(bytes.as_slice()))
            .unwrap();
        let scope = manager
            .scope_owned_artifact_reads("T-artifact", &[artifact.artifact_id.clone()])
            .unwrap();
        let mut issued_reader = manager
            .open_artifact_reader(&scope, &artifact.artifact_id)
            .unwrap();
        std::fs::write(manager.artifact_store_root.join(&final_ref), b"corrupt").unwrap();
        assert!(matches!(
            manager.import_artifact(&import_request(), &mut Cursor::new(bytes.as_slice())),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_HASH_MISMATCH"))
        ));
        assert_eq!(
            manager
                .get_artifact(&artifact.artifact_id)
                .unwrap()
                .unwrap()
                .integrity
                .as_ref()
                .unwrap()
                .state
                .unwrap(),
            ArtifactIntegrityState::Failed
        );
        assert_eq!(
            manager
                .get_artifact(&shared_artifact.artifact_id)
                .unwrap()
                .unwrap()
                .integrity
                .as_ref()
                .unwrap()
                .state
                .unwrap(),
            ArtifactIntegrityState::Failed
        );
        let mut byte = [0_u8; 1];
        assert_eq!(
            issued_reader.read(&mut byte).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM provenance_events WHERE event_type='artifact.integrity-failed' AND task_id='T-artifact' AND json_extract(event_json,'$.input_artifacts[0]') IN (?1,?2)",
                    params![artifact.artifact_id, shared_artifact.artifact_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            2
        );
        assert!(!manager.artifact_store_root.join(&final_ref).exists());
        assert!(manager.reconcile_artifacts_startup().is_ok());
    }

    #[test]
    fn recovery_pending_path_replacement_cannot_promote_substituted_bytes() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let bytes = b"verified-recovery-candidate";
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let hash = tagged_digest(hasher);
        let digest = hash.strip_prefix("sha256:").unwrap();
        let pending_ref = format!("blobs/pending/{digest}-interrupted-race");
        let displaced_ref = format!("{pending_ref}.verified-displaced");
        let final_ref = format!("blobs/sha256/{}/{}/{}", &digest[..2], &digest[2..4], digest);
        manager
            .artifact_store_dir
            .write(&pending_ref, bytes)
            .unwrap();

        let root = manager.artifact_store_root.clone();
        let expected_pending_ref = pending_ref.clone();
        RECOVERY_PENDING_PLACEMENT_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |_store, observed_pending_ref| {
                assert_eq!(observed_pending_ref, expected_pending_ref);
                let pending = root.join(safe_internal_ref(observed_pending_ref)?);
                let displaced = root.join(safe_internal_ref(&format!(
                    "{observed_pending_ref}.verified-displaced"
                ))?);
                std::fs::rename(&pending, displaced)?;
                std::fs::write(&pending, b"substituted-recovery-bytes")?;
                Ok(())
            }));
        });

        assert!(matches!(
            manager.reconcile_artifacts_startup(),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_HASH_MISMATCH"))
        ));
        assert!(!manager.artifact_store_root.join(&final_ref).exists());
        assert_eq!(
            std::fs::read(manager.artifact_store_root.join(&pending_ref)).unwrap(),
            b"substituted-recovery-bytes"
        );
        assert_eq!(
            std::fs::read(manager.artifact_store_root.join(&displaced_ref)).unwrap(),
            bytes
        );
        assert_eq!(
            manager
                .connection
                .query_row("SELECT COUNT(*) FROM artifact_blobs", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_no_created_artifact_metadata(&manager);

        // A later recovery promotes the still-valid candidate and removes the
        // invalid residue instead of wedging every future startup pass.
        let report = manager.reconcile_artifacts_startup().unwrap();
        assert!(report.findings.iter().any(|finding| {
            finding.kind == ArtifactReconciliationKind::BlobOrphaned
                && finding.content_hash.as_deref() == Some(hash.as_str())
        }));
        assert_eq!(
            std::fs::read(manager.artifact_store_root.join(&final_ref)).unwrap(),
            bytes
        );
        assert!(report.findings.iter().any(|finding| {
            finding.kind == ArtifactReconciliationKind::BlobCorrupt
                && finding.content_hash.as_deref() == Some(hash.as_str())
        }));
        assert!(!manager.artifact_store_root.join(&pending_ref).exists());
        assert!(!manager.artifact_store_root.join(&displaced_ref).exists());
        assert_no_created_artifact_metadata(&manager);
    }

    #[test]
    fn cancelled_task_cannot_import_or_publish() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        manager
            .allocate_artifact_output(&allocation("alloc-cancelled"))
            .unwrap();
        write_output(&mut manager, "alloc-cancelled", b"candidate");
        manager
            .connection
            .execute(
                "UPDATE tasks SET state='CANCELLED' WHERE task_id='T-artifact'",
                [],
            )
            .unwrap();
        assert!(matches!(
            manager.import_artifact(&import_request(), &mut Cursor::new(b"input".as_slice())),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
        let result = manager
            .publish_artifact_output(&publication("pub-cancelled", "alloc-cancelled"))
            .unwrap();
        assert!(!result.published);
        assert_eq!(result.reason_code, "ARTIFACT_AUTHORITY_DENIED");
    }

    #[test]
    fn failed_publication_replay_authenticates_complete_canonical_receipt_and_chain() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let allocation = allocation("alloc-failed-replay");
        manager.allocate_artifact_output(&allocation).unwrap();
        let request = publication("pub-failed-replay", &allocation.allocation_id);
        let request_json = canonical_json(&request).unwrap();
        manager
            .reserve_publication(&request, &request_json)
            .unwrap();
        let original = manager.abort_pending_publication(&request).unwrap();
        assert_eq!(
            manager.abort_pending_publication(&request).unwrap(),
            original
        );
        let original_json = canonical_json(&original).unwrap();

        for (field, value) in [
            ("reason_code", json!("ARTIFACT_PUBLICATION_APPLIED")),
            ("message", json!("untrusted detail")),
            ("semantic_type", json!("artifact.report@1")),
            ("blob_reused", json!(false)),
            ("resulted_at", json!("2026-09-19T22:00:01Z")),
        ] {
            let mut receipt: serde_json::Value = serde_json::from_str(&original_json).unwrap();
            receipt
                .as_object_mut()
                .unwrap()
                .insert(field.to_owned(), value);
            manager
                .connection
                .execute(
                    "UPDATE artifact_publications SET result_json=?2 WHERE publication_id=?1",
                    params![request.publication_id, canonical_json(&receipt).unwrap(),],
                )
                .unwrap();
            assert!(matches!(
                manager.abort_pending_publication(&request),
                Err(TaskManagerError::InvalidRecord(
                    "stored Artifact publication failure receipt is invalid"
                ))
            ));
        }
        manager
            .connection
            .execute(
                "UPDATE artifact_publications SET result_json=?2,committed_at='2026-09-19T22:00:01Z'
                 WHERE publication_id=?1",
                params![request.publication_id, original_json],
            )
            .unwrap();
        assert!(manager.abort_pending_publication(&request).is_err());
        manager
            .connection
            .execute(
                "UPDATE artifact_publications SET committed_at=?2 WHERE publication_id=?1",
                params![request.publication_id, original.resulted_at],
            )
            .unwrap();
        manager
            .connection
            .execute_batch(
                "DROP TRIGGER provenance_events_no_update;
                 UPDATE provenance_events SET event_hash='sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                 WHERE task_id='T-artifact' AND sequence=1;",
            )
            .unwrap();
        assert!(manager.abort_pending_publication(&request).is_err());
    }

    #[test]
    fn machine_contract_dtos_reject_unknown_json_fields() {
        let allocation = serde_json::to_value(allocation("alloc-closed-dto")).unwrap();
        let publication =
            serde_json::to_value(publication("pub-closed-dto", "alloc-closed-dto")).unwrap();
        let lineage = serde_json::to_value(ArtifactLineage::default()).unwrap();
        let result = serde_json::to_value(publication_failure(
            &self::publication("pub-result-closed", "alloc-result-closed"),
            "ARTIFACT_ALLOCATION_STATE_CONFLICT",
            "2026-09-19T22:00:00Z".to_owned(),
        ))
        .unwrap();
        let mut allocation = allocation;
        allocation
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_owned(), json!(true));
        assert!(serde_json::from_value::<OutputAllocationRequest>(allocation).is_err());
        let mut publication = publication;
        publication
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_owned(), json!(true));
        assert!(serde_json::from_value::<ArtifactPublicationRequest>(publication).is_err());
        let mut lineage = lineage;
        lineage
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_owned(), json!(true));
        assert!(serde_json::from_value::<ArtifactLineage>(lineage).is_err());
        let mut result = result;
        result
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_owned(), json!(true));
        assert!(serde_json::from_value::<ArtifactPublicationResult>(result).is_err());

        let handle = json!({
            "artifact_id":"artifact:closed",
            "uri":"artifact://artifact:closed",
            "semantic_type":"text.plain@1",
            "media_type":"text/plain",
            "format":"txt",
            "size_bytes":1,
            "content_hash":{"algorithm":"sha256","value":"a"},
            "origin":{"kind":"user","task_id":"T-artifact"},
            "sensitivity":"local",
            "retention":{"class":"task","expires_at":null},
            "integrity":{"state":"verified","verified_at":null,"verifier":null},
            "labels":[],
            "created_at":null
        });
        for path in ["", "/content_hash", "/origin", "/retention", "/integrity"] {
            let mut forged = handle.clone();
            forged
                .pointer_mut(path)
                .and_then(serde_json::Value::as_object_mut)
                .unwrap()
                .insert("unexpected".to_owned(), json!(true));
            assert!(serde_json::from_value::<ArtifactHandle>(forged).is_err());
        }
    }

    #[test]
    fn writer_reopen_fences_the_prior_generation_and_appends_at_authenticated_eof() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let allocation_id = "alloc-writer-generation";
        manager
            .allocate_artifact_output(&allocation(allocation_id))
            .unwrap();

        let mut first = manager.open_artifact_output(allocation_id).unwrap();
        first.write_all(b"AAA").unwrap();
        let mut resumed = manager.open_artifact_output(allocation_id).unwrap();
        assert_eq!(resumed.bytes_written(), 3);
        assert!(first.write_all(b"stale").is_err());
        assert!(first.finish().is_err());

        resumed.write_all(b"BBB").unwrap();
        assert_eq!(resumed.finish().unwrap(), 6);
        let staging_ref = load_allocation_row(&manager.connection, allocation_id)
            .unwrap()
            .unwrap()
            .staging_ref
            .unwrap();
        assert_eq!(
            std::fs::read(manager.artifact_store_root.join(&staging_ref)).unwrap(),
            b"AAABBB"
        );
        assert!(matches!(
            manager.open_artifact_output(allocation_id),
            Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_ALLOCATION_STATE_CONFLICT"
            ))
        ));
    }

    #[test]
    fn superseded_attempt_cannot_publish_after_a_new_latest_binding_exists() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let program_hash = allocation("unused").semantic_program_hash;
        manager
            .connection
            .execute_batch(&format!(
                "INSERT INTO registry_snapshots(snapshot_id,manifest_json,created_at) VALUES ('registry-artifact','{{}}','2026-09-19T00:00:00Z');
                 INSERT INTO semantic_program_revisions(task_id,program_revision,program_id,ir_version,semantic_hash,registry_snapshot_id,status,program_json,created_at) VALUES ('T-artifact',1,'program-artifact','0.1','{program_hash}','registry-artifact','active','{{}}','2026-09-19T00:00:00Z');
                 UPDATE tasks SET state='RUNNING',active_program_revision=1,active_step_ids_json='[\"compose_report\"]' WHERE task_id='T-artifact';
                 INSERT INTO execution_bindings(binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,ir_version,node_id,capability,provider_id,provider_version,attempt,policy_decision_refs_json,grant_refs_json,execution_profile_ref,placement_json,binding_json,created_at) VALUES ('binding-old','attempt-old','T-artifact','{program_hash}','registry-artifact','0.1','compose_report','document.compose','provider:test','1',1,'[\"decision-stale\",\"decision-stale-unopened\"]','[\"grant-stale\",\"grant-stale-unopened\"]','profile:test','{{}}','{{}}','2026-09-19T00:00:00Z');
                 INSERT INTO step_executions(attempt_id,task_id,semantic_program_hash,registry_snapshot_id,node_id,binding_id,attempt_number,revision,state,created_at,updated_at) VALUES ('attempt-old','T-artifact','{program_hash}','registry-artifact','compose_report','binding-old',1,1,'RUNNING','2026-09-19T00:00:00Z','2026-09-19T00:00:00Z');
                 INSERT INTO policy_snapshots(snapshot_id,scope_kind,scope_id,policy_language,policy_set_hash,engine_id,engine_version,snapshot_json,created_at) VALUES ('policy-artifact','task','T-artifact','cedar','sha256:policy','test','1','{{}}','2026-09-19T00:00:00Z');
                 INSERT INTO authority_requests(request_id,task_id,semantic_program_hash,registry_snapshot_id,node_id,capability,principal_kind,principal_id,execution_binding_id,attempt_id,action,resolved_resource_kind,resolved_resource_id,semantic_selector,request_json,requested_at) VALUES ('request-stale','T-artifact','{program_hash}','registry-artifact','compose_report','document.compose','provider','provider:test','binding-old','attempt-old','artifact.write','output-allocation','alloc-stale','task.output','{{}}','2026-09-19T00:00:00Z');
                 INSERT INTO authority_requests(request_id,task_id,semantic_program_hash,registry_snapshot_id,node_id,capability,principal_kind,principal_id,execution_binding_id,attempt_id,action,resolved_resource_kind,resolved_resource_id,semantic_selector,request_json,requested_at) VALUES ('request-stale-unopened','T-artifact','{program_hash}','registry-artifact','compose_report','document.compose','provider','provider:test','binding-old','attempt-old','artifact.write','output-allocation','alloc-stale-unopened','task.output','{{}}','2026-09-19T00:00:00Z');
                 INSERT INTO policy_decisions(decision_id,authority_request_id,task_id,semantic_program_hash,node_id,principal_kind,principal_id,action,resolved_resource_kind,resolved_resource_id,decision,policy_snapshot_id,reason_codes_json,decision_json,decided_at) VALUES ('decision-stale','request-stale','T-artifact','{program_hash}','compose_report','provider','provider:test','artifact.write','output-allocation','alloc-stale','ALLOW','policy-artifact','[]','{{}}','2026-09-19T00:00:00Z');
                 INSERT INTO policy_decisions(decision_id,authority_request_id,task_id,semantic_program_hash,node_id,principal_kind,principal_id,action,resolved_resource_kind,resolved_resource_id,decision,policy_snapshot_id,reason_codes_json,decision_json,decided_at) VALUES ('decision-stale-unopened','request-stale-unopened','T-artifact','{program_hash}','compose_report','provider','provider:test','artifact.write','output-allocation','alloc-stale-unopened','ALLOW','policy-artifact','[]','{{}}','2026-09-19T00:00:00Z');
                 INSERT INTO authority_grants(grant_id,task_id,semantic_program_hash,node_id,capability,principal_kind,principal_id,execution_binding_id,attempt_id,policy_decision_id,policy_snapshot_id,grants_json,scope,state,issued_at,expires_at) VALUES ('grant-stale','T-artifact','{program_hash}','compose_report','document.compose','provider','provider:test','binding-old','attempt-old','decision-stale','policy-artifact','[{{\"action\":\"artifact.write\",\"resource_kind\":\"output-allocation\",\"resource_id\":\"alloc-stale\",\"semantic_selector\":\"task.output\"}}]','TASK','ACTIVE','2026-09-19T00:00:00Z','2026-09-20T00:00:00Z');
                 INSERT INTO authority_grants(grant_id,task_id,semantic_program_hash,node_id,capability,principal_kind,principal_id,execution_binding_id,attempt_id,policy_decision_id,policy_snapshot_id,grants_json,scope,state,issued_at,expires_at) VALUES ('grant-stale-unopened','T-artifact','{program_hash}','compose_report','document.compose','provider','provider:test','binding-old','attempt-old','decision-stale-unopened','policy-artifact','[{{\"action\":\"artifact.write\",\"resource_kind\":\"output-allocation\",\"resource_id\":\"alloc-stale-unopened\",\"semantic_selector\":\"task.output\"}}]','TASK','ACTIVE','2026-09-19T00:00:00Z','2026-09-20T00:00:00Z');"
            ))
            .unwrap();
        let mut request = allocation("alloc-stale");
        request.binding_id = Some("binding-old".to_owned());
        request.attempt_id = Some("attempt-old".to_owned());
        allocate_bound(&mut manager, &request);
        let mut unopened = request.clone();
        unopened.allocation_id = "alloc-stale-unopened".to_owned();
        manager.allocate_artifact_output(&unopened).unwrap();
        let mut writer = open_bound(&mut manager, "alloc-stale");
        writer.write_all(b"stale").unwrap();
        writer.finish().unwrap();
        manager
            .connection
            .execute_batch(&format!(
                "INSERT INTO execution_bindings(binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,ir_version,node_id,capability,provider_id,provider_version,attempt,policy_decision_refs_json,grant_refs_json,execution_profile_ref,placement_json,binding_json,created_at) VALUES ('binding-new','attempt-new','T-artifact','{program_hash}','registry-artifact','0.1','compose_report','document.compose','provider:test','1',2,'[]','[]','profile:test','{{}}','{{}}','2026-09-19T00:01:00Z');
                 INSERT INTO step_executions(attempt_id,task_id,semantic_program_hash,registry_snapshot_id,node_id,binding_id,attempt_number,revision,state,created_at,updated_at) VALUES ('attempt-new','T-artifact','{program_hash}','registry-artifact','compose_report','binding-new',2,1,'RUNNING','2026-09-19T00:01:00Z','2026-09-19T00:01:00Z');"
            ))
            .unwrap();
        assert!(matches!(
            manager.open_artifact_output("alloc-stale-unopened"),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
        let mut stale_new = request.clone();
        stale_new.allocation_id = "alloc-stale-after".to_owned();
        assert!(matches!(
            manager.allocate_artifact_output(&stale_new),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
        let result = publish_bound(&mut manager, &publication("pub-stale", "alloc-stale")).unwrap();
        assert!(!result.published);
        assert_eq!(result.reason_code, "ARTIFACT_AUTHORITY_DENIED");
        assert_eq!(
            manager
                .connection
                .query_row("SELECT COUNT(*) FROM artifacts", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_publication_not_committed(&manager, "alloc-stale", "pub-stale");
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "authenticates the complete committed publication receipt and durable blob replay path"
    )]
    fn committed_replay_authenticates_receipt_rows_and_blob_bytes() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        manager
            .allocate_artifact_output(&allocation("alloc-replay"))
            .unwrap();
        write_output(&mut manager, "alloc-replay", b"replay");
        let request = publication("pub-replay", "alloc-replay");
        let original = manager.publish_artifact_output(&request).unwrap();
        assert!(original.published);
        manager
            .connection
            .execute(
                "UPDATE artifact_publications SET result_json=json_set(result_json,'$.blob_reused',NULL) WHERE publication_id='pub-replay'",
                [],
            )
            .unwrap();
        let missing_reuse = manager.publish_artifact_output(&request).unwrap();
        assert!(!missing_reuse.published);
        assert_eq!(missing_reuse.reason_code, "ARTIFACT_INTEGRITY_FAILED");
        manager
            .connection
            .execute(
                "UPDATE artifact_publications SET result_json=?2 WHERE publication_id=?1",
                params![
                    request.publication_id,
                    serde_json::to_string(&original).unwrap()
                ],
            )
            .unwrap();
        let mut forged_reuse = original.clone();
        forged_reuse.blob_reused = original.blob_reused.map(|value| !value);
        let mut forged_message = original.clone();
        forged_message.message = Some("forged success detail".to_owned());
        for forged in [forged_reuse, forged_message] {
            manager
                .connection
                .execute(
                    "UPDATE artifact_publications SET result_json=?2 WHERE publication_id=?1",
                    params![
                        request.publication_id,
                        serde_json::to_string(&forged).unwrap()
                    ],
                )
                .unwrap();
            let rejected = manager.publish_artifact_output(&request).unwrap();
            assert!(!rejected.published);
            assert_eq!(rejected.reason_code, "ARTIFACT_INTEGRITY_FAILED");
        }
        manager
            .connection
            .execute(
                "UPDATE artifact_publications SET result_json=?2 WHERE publication_id=?1",
                params![
                    request.publication_id,
                    serde_json::to_string(&original).unwrap()
                ],
            )
            .unwrap();
        PUBLICATION_REPLAY_HASH_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(|| {
                Err(TaskManagerError::Io(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "injected transient replay read failure",
                )))
            }));
        });
        assert!(matches!(
            manager.publish_artifact_output(&request),
            Err(TaskManagerError::Io(error)) if error.kind() == std::io::ErrorKind::Interrupted
        ));
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT a.integrity_state || ':' || b.durability_state
                     FROM artifacts a JOIN artifact_blobs b ON b.content_hash=a.content_hash
                     WHERE a.artifact_id=?1",
                    [original.artifact_id.as_deref().unwrap()],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "verified:DURABLE"
        );
        assert_eq!(manager.publish_artifact_output(&request).unwrap(), original);
        manager
            .connection
            .execute(
                "UPDATE artifact_publications SET result_json=json_set(result_json,'$.size_bytes',999) WHERE publication_id='pub-replay'",
                [],
            )
            .unwrap();
        let replay = manager.publish_artifact_output(&request).unwrap();
        assert!(!replay.published);
        assert_eq!(replay.reason_code, "ARTIFACT_INTEGRITY_FAILED");
        manager
            .connection
            .execute(
                "UPDATE artifact_publications SET result_json=?2 WHERE publication_id=?1",
                params![
                    request.publication_id,
                    serde_json::to_string(&original).unwrap()
                ],
            )
            .unwrap();
        let storage_ref = manager
            .connection
            .query_row(
                "SELECT storage_ref FROM artifact_blobs WHERE content_hash=?1",
                [original.content_hash.as_deref().unwrap()],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        manager
            .artifact_store_dir
            .remove_file(&storage_ref)
            .unwrap();
        let missing = manager.publish_artifact_output(&request).unwrap();
        assert!(!missing.published);
        assert_eq!(missing.reason_code, "ARTIFACT_INTEGRITY_FAILED");
    }

    #[test]
    fn hardlink_database_alias_reuses_bound_artifact_root() {
        let temp = TempDir::new().unwrap();
        let database = temp.path().join("task-manager.sqlite");
        let alias = temp.path().join("database-alias.sqlite");
        let manager = TaskManager::open_with_clock(&database, Box::new(FixedClock)).unwrap();
        let root = manager.artifact_store_root.clone();
        drop(manager);
        std::fs::hard_link(&database, &alias).unwrap();
        let reopened = TaskManager::open_with_clock(&alias, Box::new(FixedClock)).unwrap();
        assert_eq!(reopened.artifact_store_root, root);
        let bound_root = reopened
            .connection
            .query_row(
                "SELECT canonical_root FROM artifact_store_binding WHERE singleton_id=1",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        assert_eq!(PathBuf::from(bound_root), root);
        let attacker_root = TempDir::new().unwrap();
        reopened
            .connection
            .execute(
                "UPDATE artifact_store_binding SET canonical_root=?1 WHERE singleton_id=1",
                [attacker_root.path().to_string_lossy().as_ref()],
            )
            .unwrap();
        drop(reopened);
        let reopened = TaskManager::open_with_clock(&alias, Box::new(FixedClock));
        assert!(matches!(
            reopened,
            Err(TaskManagerError::InvalidRecord(message))
                if message == "Artifact store root identity does not match its database binding"
                    || message == "Artifact store ownership or ACL is untrusted"
                    || message == "opened Artifact store ownership or permissions are untrusted"
        ));
    }

    #[test]
    fn artifact_handle_accepts_the_published_optional_wire_shape() {
        let minimal = json!({
            "artifact_id":"artifact:minimal",
            "uri":"artifact://artifact:minimal",
            "media_type":"application/octet-stream",
            "origin":{"kind":"user"},
            "sensitivity":"private"
        });
        let handle: ArtifactHandle = serde_json::from_value(minimal).unwrap();
        assert_eq!(handle.size_bytes, None);
        assert_eq!(handle.content_hash, None);
        assert_eq!(handle.retention, None);
        assert_eq!(handle.integrity, None);
        assert_eq!(handle.created_at, None);

        let nullable: ArtifactHandle = serde_json::from_value(json!({
            "artifact_id":"artifact:nullable",
            "uri":"artifact://artifact:nullable",
            "semantic_type":null,
            "media_type":"application/octet-stream",
            "format":null,
            "size_bytes":null,
            "content_hash":null,
            "origin":{"kind":"user"},
            "sensitivity":"private",
            "created_at":null
        }))
        .unwrap();
        assert_eq!(nullable.size_bytes, None);
        assert_eq!(nullable.content_hash, None);
    }

    #[test]
    fn keyed_import_replays_after_lost_commit_response_without_reading_source() {
        struct PanicReader;
        impl Read for PanicReader {
            fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
                panic!("a committed keyed import replay must not read the source")
            }
        }

        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let mut request = import_request();
        request.import_id = Some("import:stable-response-loss".to_owned());
        IMPORT_COMMIT_RESULT_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(|| {
                Err(TaskManagerError::Io(std::io::Error::other(
                    "injected late import commit result",
                )))
            }));
        });
        assert!(
            manager
                .import_artifact(&request, &mut Cursor::new(b"stable import".as_slice()))
                .is_err()
        );
        let replayed = manager.import_artifact(&request, &mut PanicReader).unwrap();
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM artifacts WHERE artifact_id=?1",
                    [&replayed.artifact_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM provenance_events WHERE task_id='T-artifact'
                     AND event_type='artifact.imported'
                     AND json_extract(event_json,'$.details.import_id')=?1",
                    [request.import_id.as_deref().unwrap()],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn keyed_import_replays_after_later_read_and_export_integrity_verification() {
        struct PanicReader;
        impl Read for PanicReader {
            fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
                panic!("a keyed import replay must not read its source")
            }
        }

        let temp = TempDir::new().unwrap();
        let now = Arc::new(Mutex::new("2026-09-19T22:00:00Z".to_owned()));
        let mut manager = manager_with_mutable_clock(&temp, &now);
        let mut request = import_request();
        request.import_id = Some("import:later-integrity-verification".to_owned());
        let artifact = manager
            .import_artifact(&request, &mut Cursor::new(b"verified later".as_slice()))
            .unwrap();
        *now.lock().unwrap() = "2026-09-19T22:30:00Z".to_owned();
        let scope = manager
            .scope_owned_artifact_reads("T-artifact", &[artifact.artifact_id.clone()])
            .unwrap();
        let mut reader = manager
            .open_artifact_reader(&scope, &artifact.artifact_id)
            .unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        drop(reader);
        assert_eq!(bytes, b"verified later");
        let mut destination = manager
            .issue_owned_artifact_export_destination(
                &scope,
                "export-keyed-import-after-read",
                &artifact.artifact_id,
                "user-selected-file",
                1_024,
                deferred(Vec::new()),
            )
            .unwrap();
        manager
            .export_artifact(&scope, &artifact.artifact_id, &mut destination)
            .unwrap();

        let replayed = manager.import_artifact(&request, &mut PanicReader).unwrap();
        assert_eq!(replayed.artifact_id, artifact.artifact_id);
        assert_eq!(
            replayed.integrity.unwrap().verified_at.as_deref(),
            Some("2026-09-19T22:30:00Z")
        );
    }

    #[test]
    fn keyed_import_replay_authenticates_every_immutable_artifact_field() {
        struct PanicReader;
        impl Read for PanicReader {
            fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
                panic!("a keyed import replay must not read its source")
            }
        }

        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let mut request = import_request();
        request.import_id = Some("import:metadata-authentication".to_owned());
        request.semantic_type = Some("text.plain@1".to_owned());
        request.format = Some("txt".to_owned());
        request.labels = vec!["canonical".to_owned()];
        let artifact = manager
            .import_artifact(&request, &mut Cursor::new(b"immutable metadata".as_slice()))
            .unwrap();
        manager
            .connection
            .execute_batch(
                "DROP TRIGGER published_artifacts_no_content_update;
                 PRAGMA foreign_keys=OFF;",
            )
            .unwrap();

        let forged_hash = format!("sha256:{}", "a".repeat(64));
        let mutations = [
            "UPDATE artifacts SET uri='artifact://forged' WHERE artifact_id=?1".to_owned(),
            "UPDATE artifacts SET semantic_type='text.forged@1' WHERE artifact_id=?1".to_owned(),
            "UPDATE artifacts SET media_type='application/forged' WHERE artifact_id=?1".to_owned(),
            "UPDATE artifacts SET format='forged' WHERE artifact_id=?1".to_owned(),
            "UPDATE artifacts SET size_bytes=size_bytes+1 WHERE artifact_id=?1".to_owned(),
            format!("UPDATE artifacts SET content_hash='{forged_hash}' WHERE artifact_id=?1"),
            "UPDATE artifacts SET sensitivity='secret' WHERE artifact_id=?1".to_owned(),
            "UPDATE artifacts SET retention_class='persistent' WHERE artifact_id=?1".to_owned(),
            "UPDATE artifacts SET expires_at='2027-01-01T00:00:00Z' WHERE artifact_id=?1"
                .to_owned(),
            "UPDATE artifacts SET origin_kind='system' WHERE artifact_id=?1".to_owned(),
            "UPDATE artifacts SET origin_task_id='T-forged' WHERE artifact_id=?1".to_owned(),
            "UPDATE artifacts SET origin_program_hash='sha256:aaaa' WHERE artifact_id=?1"
                .to_owned(),
            "UPDATE artifacts SET origin_node_id='forged-node' WHERE artifact_id=?1".to_owned(),
            "UPDATE artifacts SET origin_binding_id='forged-binding' WHERE artifact_id=?1"
                .to_owned(),
            "UPDATE artifacts SET origin_provider_id='forged-provider' WHERE artifact_id=?1"
                .to_owned(),
            "UPDATE artifacts SET integrity_state='pending' WHERE artifact_id=?1".to_owned(),
            "UPDATE artifacts SET integrity_verifier='forged' WHERE artifact_id=?1".to_owned(),
            "UPDATE artifacts SET labels_json='[\"forged\"]' WHERE artifact_id=?1".to_owned(),
            "UPDATE artifacts SET created_at='2027-01-01T00:00:00Z' WHERE artifact_id=?1"
                .to_owned(),
        ];
        for mutation in mutations {
            manager
                .connection
                .execute_batch("SAVEPOINT metadata_tamper")
                .unwrap();
            manager
                .connection
                .execute(&mutation, [&artifact.artifact_id])
                .unwrap();
            assert!(matches!(
                manager.import_artifact(&request, &mut PanicReader),
                Err(TaskManagerError::InvalidRecord(_))
            ));
            manager
                .connection
                .execute_batch("ROLLBACK TO metadata_tamper; RELEASE metadata_tamper")
                .unwrap();
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one response-loss scenario covers the coupled writer and export admission protocol"
    )]
    fn late_writer_and_export_admission_commit_results_are_recovered_without_repeating_effects() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        manager
            .allocate_artifact_output(&allocation("alloc-late-writer-commit"))
            .unwrap();
        WRITER_ADMISSION_COMMIT_RESULT_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(|| {
                Err(TaskManagerError::Io(std::io::Error::other(
                    "injected late writer commit result",
                )))
            }));
        });
        let writer = manager
            .open_artifact_output("alloc-late-writer-commit")
            .unwrap();
        drop(writer);
        let mut replayed_writer = manager
            .open_artifact_output("alloc-late-writer-commit")
            .unwrap();
        replayed_writer.write_all(b"rehydrated").unwrap();
        assert_eq!(replayed_writer.finish().unwrap(), 10);

        let artifact = manager
            .import_artifact(
                &import_request(),
                &mut Cursor::new(b"export response loss".as_slice()),
            )
            .unwrap();
        let scope = manager
            .scope_owned_artifact_reads("T-artifact", &[artifact.artifact_id.clone()])
            .unwrap();
        let factory_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&factory_calls);
        let mut destination = manager
            .issue_owned_artifact_export_destination(
                &scope,
                "export-late-admission-commit",
                &artifact.artifact_id,
                "user-selected-file",
                1_024,
                move || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(Vec::<u8>::new())
                },
            )
            .unwrap();
        EXPORT_ADMISSION_COMMIT_RESULT_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(|| {
                Err(TaskManagerError::Io(std::io::Error::other(
                    "injected late export admission commit result",
                )))
            }));
        });
        assert!(matches!(
            manager.export_artifact(&scope, &artifact.artifact_id, &mut destination),
            Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_FAILED_NO_EFFECT"
            ))
        ));
        assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
        let pre_destination = manager
            .connection
            .query_row(
                "SELECT state,outcome_certainty,json_extract(external_receipt,'$.kind')
                 FROM operations WHERE operation_id='export-late-admission-commit'",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            pre_destination,
            (
                "STARTED".to_owned(),
                None,
                "pre-destination-admission".to_owned()
            )
        );
        assert!(matches!(
            manager.export_artifact(&scope, &artifact.artifact_id, &mut destination),
            Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_FAILED_NO_EFFECT"
            ))
        ));
        assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
        manager.reconcile_export_operations_startup().unwrap();
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT state || ':' || outcome_certainty FROM operations
                     WHERE operation_id='export-late-admission-commit'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "FAILED:FAILED_NO_EFFECT"
        );
    }

    #[test]
    fn terminal_cleanup_retries_staging_directory_sync_after_residue_is_absent() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        manager
            .allocate_artifact_output(&allocation("alloc-sync-retry"))
            .unwrap();
        write_output(&mut manager, "alloc-sync-retry", b"terminal cleanup");
        manager
            .connection
            .execute(
                "UPDATE tasks SET state='COMPLETED' WHERE task_id='T-artifact'",
                [],
            )
            .unwrap();
        for _ in 0..2 {
            DURABILITY_TEST_CONTROL.with(|control| {
                *control.borrow_mut() =
                    Some((Vec::new(), Some("sync-terminal-staging-cleanup".to_owned())));
            });
            assert!(manager.reconcile_artifacts_startup().is_err());
            let operations =
                DURABILITY_TEST_CONTROL.with(|control| control.borrow_mut().take().unwrap().0);
            assert!(operations.contains(&"sync-terminal-staging-cleanup".to_owned()));
        }
        assert!(manager.reconcile_artifacts_startup().is_ok());
    }

    #[test]
    fn committed_publication_replays_historical_event_without_blob_reused_only() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        manager
            .allocate_artifact_output(&allocation("alloc-historical-reuse"))
            .unwrap();
        write_output(&mut manager, "alloc-historical-reuse", b"historical reuse");
        let request = publication("pub-historical-reuse", "alloc-historical-reuse");
        let mut original = manager.publish_artifact_output(&request).unwrap();
        let (sequence, previous_hash, event_json) = manager
            .connection
            .query_row(
                "SELECT sequence,previous_event_hash,event_json FROM provenance_events
                 WHERE task_id='T-artifact' AND event_type='artifact.created'",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .unwrap();
        let mut event: serde_json::Value = serde_json::from_str(&event_json).unwrap();
        event
            .get_mut("details")
            .and_then(serde_json::Value::as_object_mut)
            .unwrap()
            .remove("blob_reused");
        let canonical = canonical_json(&event).unwrap();
        let hash = provenance_hash(
            "T-artifact",
            u64::try_from(sequence).unwrap(),
            previous_hash.as_deref(),
            &event,
        )
        .unwrap();
        manager
            .connection
            .execute_batch("DROP TRIGGER provenance_events_no_update;")
            .unwrap();
        manager
            .connection
            .execute(
                "UPDATE provenance_events SET event_json=?1,event_hash=?2
                 WHERE task_id='T-artifact' AND sequence=?3",
                params![canonical, hash, sequence],
            )
            .unwrap();
        original.provenance_event_hash = Some(hash.clone());
        manager
            .connection
            .execute(
                "UPDATE artifact_publications SET result_json=?2 WHERE publication_id=?1",
                params![request.publication_id, canonical_json(&original).unwrap()],
            )
            .unwrap();
        assert_eq!(manager.publish_artifact_output(&request).unwrap(), original);

        let mut malformed = event;
        malformed["details"]["blob_reused"] = json!("false");
        let malformed_json = canonical_json(&malformed).unwrap();
        let malformed_hash = provenance_hash(
            "T-artifact",
            u64::try_from(sequence).unwrap(),
            previous_hash.as_deref(),
            &malformed,
        )
        .unwrap();
        manager
            .connection
            .execute(
                "UPDATE provenance_events SET event_json=?1,event_hash=?2
                 WHERE task_id='T-artifact' AND sequence=?3",
                params![malformed_json, malformed_hash, sequence],
            )
            .unwrap();
        original.provenance_event_hash = Some(malformed_hash);
        manager
            .connection
            .execute(
                "UPDATE artifact_publications SET result_json=?2 WHERE publication_id=?1",
                params![request.publication_id, canonical_json(&original).unwrap()],
            )
            .unwrap();
        let rejected = manager.publish_artifact_output(&request).unwrap();
        assert!(!rejected.published);
        assert_eq!(rejected.reason_code, "ARTIFACT_INTEGRITY_FAILED");
    }

    #[test]
    fn staging_write_late_commit_result_never_hides_appended_bytes() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let allocation_id = "alloc-write-response-loss";
        let (binding_id, attempt_id) = install_one_shot_binding(
            &manager,
            "write-response-loss",
            &[],
            &[("artifact.write", "output-allocation", allocation_id)],
        );
        let mut request = allocation(allocation_id);
        request.binding_id = Some(binding_id);
        request.attempt_id = Some(attempt_id);
        allocate_bound(&mut manager, &request);
        let mut writer = open_bound(&mut manager, allocation_id);
        WRITER_WRITE_COMMIT_RESULT_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(|| {
                Err(TaskManagerError::Io(std::io::Error::other(
                    "injected late staging write commit result",
                )))
            }));
        });
        assert_eq!(writer.write(b"first").unwrap(), 5);
        assert_eq!(writer.bytes_written(), 5);
        drop(writer);

        let mut resumed = open_bound(&mut manager, allocation_id);
        assert_eq!(resumed.bytes_written(), 5);
        resumed.write_all(b"-second").unwrap();
        assert_eq!(resumed.finish().unwrap(), 12);
        let allocation = load_allocation_row(&manager.connection, allocation_id)
            .unwrap()
            .unwrap();
        let mut bytes = Vec::new();
        manager
            .artifact_store_dir
            .open(allocation.staging_ref.unwrap())
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, b"first-second");
    }

    #[test]
    fn artifact_handle_omission_only_fields_reject_explicit_null() {
        let minimal = json!({
            "artifact_id":"artifact:minimal",
            "uri":"artifact://artifact:minimal",
            "media_type":"application/octet-stream",
            "origin":{"kind":"user"},
            "sensitivity":"private"
        });
        assert!(serde_json::from_value::<ArtifactHandle>(minimal.clone()).is_ok());
        for pointer in ["retention", "integrity"] {
            let mut forged = minimal.clone();
            forged[pointer] = serde_json::Value::Null;
            assert!(serde_json::from_value::<ArtifactHandle>(forged).is_err());
        }
        for nested in [
            json!({"retention":{"class":null}}),
            json!({"integrity":{"state":null}}),
        ] {
            let mut forged = minimal.clone();
            forged
                .as_object_mut()
                .unwrap()
                .extend(nested.as_object().unwrap().clone());
            assert!(serde_json::from_value::<ArtifactHandle>(forged).is_err());
        }
    }

    #[test]
    fn invalid_pending_blob_cleanup_retries_directory_sync_after_unlink() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        for (name, bytes) in [
            ("malformed-name", b"private residue".as_slice()),
            (
                &format!("{}-mismatch", "a".repeat(64)),
                b"wrong bytes".as_slice(),
            ),
        ] {
            let path = manager.artifact_store_root.join("blobs/pending").join(name);
            std::fs::write(&path, bytes).unwrap();
            for _ in 0..2 {
                DURABILITY_TEST_CONTROL.with(|control| {
                    *control.borrow_mut() =
                        Some((Vec::new(), Some("sync-invalid-blob-pending".to_owned())));
                });
                assert!(manager.reconcile_artifacts_startup().is_err());
                assert!(!path.exists());
                let operations =
                    DURABILITY_TEST_CONTROL.with(|control| control.borrow_mut().take().unwrap().0);
                assert!(operations.contains(&"sync-invalid-blob-pending".to_owned()));
            }
            assert!(manager.reconcile_artifacts_startup().is_ok());
        }
    }

    #[test]
    fn keyed_import_replay_verifies_physical_blob_and_marks_shared_failure() {
        struct PanicReader;
        impl Read for PanicReader {
            fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
                panic!("invalid keyed replay must not consult the source")
            }
        }

        for (fixture, remove, expected_state) in
            [("missing", true, "MISSING"), ("corrupt", false, "CORRUPT")]
        {
            let temp = TempDir::new().unwrap();
            let mut manager = manager(&temp);
            let mut request = import_request();
            request.import_id = Some(format!("import:physical-{fixture}"));
            let artifact = manager
                .import_artifact(&request, &mut Cursor::new(b"physical replay".as_slice()))
                .unwrap();
            let storage_ref = manager
                .connection
                .query_row(
                    "SELECT storage_ref FROM artifact_blobs WHERE content_hash=?1",
                    [artifact.stored_content_hash().unwrap().tagged()],
                    |row| row.get::<_, String>(0),
                )
                .unwrap();
            let path = manager.artifact_store_root.join(&storage_ref);
            if remove {
                std::fs::remove_file(&path).unwrap();
            } else {
                std::fs::write(&path, b"corrupt").unwrap();
            }
            assert!(matches!(
                manager.import_artifact(&request, &mut PanicReader),
                Err(TaskManagerError::InvalidRecord("ARTIFACT_INTEGRITY_FAILED"))
            ));
            let states = manager
                .connection
                .query_row(
                    "SELECT a.integrity_state,b.durability_state
                     FROM artifacts a JOIN artifact_blobs b ON b.content_hash=a.content_hash
                     WHERE a.artifact_id=?1",
                    [&artifact.artifact_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .unwrap();
            assert_eq!(states, ("failed".to_owned(), expected_state.to_owned()));
        }
    }

    #[test]
    fn terminal_bound_publication_replays_while_unrelated_recovery_is_active() {
        for failed in [false, true] {
            let temp = TempDir::new().unwrap();
            let mut manager = manager(&temp);
            let fixture = if failed {
                "failed-replay"
            } else {
                "committed-replay"
            };
            let (allocation_id, _) = finish_bound_output(&mut manager, fixture, "ONE_SHOT");
            let mut request = publication(&format!("pub-{fixture}"), &allocation_id);
            if failed {
                request.media_type = "application/forbidden".to_owned();
            }
            let terminal = publish_bound(&mut manager, &request).unwrap();
            assert_eq!(terminal.published, !failed);
            manager
                .connection
                .execute(
                    "UPDATE tasks SET state='RECOVERING' WHERE task_id='T-artifact'",
                    [],
                )
                .unwrap();
            let session = session_for_allocation(&manager, &allocation_id);
            assert_eq!(
                manager
                    .publish_bound_artifact_output(&session, &request)
                    .unwrap(),
                terminal
            );
        }
    }

    #[test]
    fn reader_admission_response_loss_replays_once_without_second_grant_use() {
        let temp = TempDir::new().unwrap();
        let database = temp.path().join("task-manager.sqlite");
        let mut manager = manager(&temp);
        let artifact = manager
            .import_artifact(
                &import_request(),
                &mut Cursor::new(b"reader response loss".as_slice()),
            )
            .unwrap();
        let (binding_id, _) = install_one_shot_binding(
            &manager,
            "reader-response-loss",
            std::slice::from_ref(&artifact.artifact_id),
            &[("artifact.read", "artifact", &artifact.artifact_id)],
        );
        let session = session_for_binding(&manager, "T-artifact", &binding_id);
        let scope = manager
            .scope_artifact_reads(&session, std::slice::from_ref(&artifact.artifact_id))
            .unwrap();
        READER_ADMISSION_COMMIT_RESULT_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(|| {
                Err(TaskManagerError::Io(std::io::Error::other(
                    "injected late reader admission commit result",
                )))
            }));
        });
        assert!(matches!(
            manager.open_artifact_reader(&scope, &artifact.artifact_id),
            Err(TaskManagerError::Io(_))
        ));
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT uses_consumed FROM authority_grants WHERE grant_id='grant-reader-response-loss-0'",
                    [],
                    |row| row.get::<_,i64>(0),
                )
                .unwrap(),
            1
        );
        manager
            .connection
            .execute(
                "UPDATE tasks SET state='CREATED',active_program_revision=NULL,active_step_ids_json='[]' WHERE task_id='T-artifact'",
                [],
            )
            .unwrap();
        drop(scope);
        drop(session);
        drop(manager);

        let mut reopened = TaskManager::open_with_clock(&database, Box::new(FixedClock)).unwrap();
        reopened
            .connection
            .execute(
                "UPDATE tasks SET state='RUNNING',active_program_revision=1,active_step_ids_json='[\"compose_report\"]' WHERE task_id='T-artifact'",
                [],
            )
            .unwrap();
        let session = reopened
            .issue_provider_artifact_session("T-artifact", &binding_id)
            .unwrap();
        let scope = reopened
            .scope_artifact_reads(&session, std::slice::from_ref(&artifact.artifact_id))
            .unwrap();
        let mut reader = reopened
            .open_artifact_reader(&scope, &artifact.artifact_id)
            .unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"reader response loss");
        assert_eq!(
            reopened
                .connection
                .query_row(
                    "SELECT uses_consumed FROM authority_grants WHERE grant_id='grant-reader-response-loss-0'",
                    [],
                    |row| row.get::<_,i64>(0),
                )
                .unwrap(),
            1
        );
        assert!(matches!(
            reopened.scope_artifact_reads(&session, std::slice::from_ref(&artifact.artifact_id)),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
    }

    #[test]
    fn forged_pre_destination_phase_cannot_downgrade_a_genuine_unknown_export() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let artifact = manager
            .import_artifact(
                &import_request(),
                &mut Cursor::new(b"unknown export".as_slice()),
            )
            .unwrap();
        let scope = manager
            .scope_owned_artifact_reads("T-artifact", &[artifact.artifact_id.clone()])
            .unwrap();
        let mut destination = manager
            .issue_owned_artifact_export_destination(
                &scope,
                "export-forged-pre-destination",
                &artifact.artifact_id,
                "user-selected-file",
                1_024,
                || -> std::io::Result<Vec<u8>> {
                    Err(std::io::Error::other("effect-capable factory failed"))
                },
            )
            .unwrap();
        assert!(matches!(
            manager.export_artifact(&scope, &artifact.artifact_id, &mut destination),
            Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_EXPORT_OUTCOME_UNKNOWN"
            ))
        ));
        let armed_json = manager
            .connection
            .query_row(
                "SELECT external_receipt FROM operations
                 WHERE operation_id='export-forged-pre-destination'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        let armed: ArmedExportAdmission = serde_json::from_str(&armed_json).unwrap();
        let forged_pre = canonical_json(&PreDestinationExportAdmission {
            version: 1,
            kind: "pre-destination-admission".to_owned(),
            operation_id: armed.operation_id.clone(),
            intent_hash: armed.intent_hash.clone(),
            provenance_event_id: armed.admission_event_id.clone(),
            provenance_event_hash: armed.admission_event_hash.clone(),
        })
        .unwrap();
        manager
            .connection
            .execute(
                "UPDATE operations SET state='STARTED',outcome_certainty=NULL,finished_at=NULL,
                        external_receipt=?2 WHERE operation_id=?1",
                params![armed.operation_id, forged_pre],
            )
            .unwrap();
        assert!(matches!(
            manager.reconcile_export_operations_startup(),
            Err(TaskManagerError::InvalidRecord(
                "stored Artifact export effect phase is invalid"
            ))
        ));
        manager
            .connection
            .execute(
                "UPDATE operations SET external_receipt=NULL
                 WHERE operation_id='export-forged-pre-destination'",
                [],
            )
            .unwrap();
        assert!(manager.reconcile_export_operations_startup().is_err());
    }

    #[test]
    fn legacy_started_without_phase_receipt_upgrades_conservatively_to_unknown() {
        let temp = TempDir::new().unwrap();
        let database = temp.path().join("task-manager.sqlite");
        let mut manager = manager(&temp);
        let artifact = manager
            .import_artifact(
                &import_request(),
                &mut Cursor::new(b"legacy started export".as_slice()),
            )
            .unwrap();
        let intent_json = canonical_json(&ArtifactExportIntent {
            version: 1,
            task_id: "T-artifact".to_owned(),
            artifact_id: artifact.artifact_id.clone(),
            content_hash: artifact.stored_content_hash().unwrap().tagged().clone(),
            destination_class: "user-selected-file".to_owned(),
            max_size_bytes: 1_024,
            principal_kind: "user".to_owned(),
            principal_id: "user:test".to_owned(),
            semantic_program_hash: None,
            node_id: None,
            binding_id: None,
            attempt_id: None,
            grant_id: None,
        })
        .unwrap();
        manager
            .connection
            .execute(
                "INSERT INTO operations(
                    operation_id,task_id,transaction_class,effect_class,idempotency_key,
                    state,outcome_certainty,external_receipt,details_json,
                    prepared_at,started_at,finished_at
                 ) VALUES (?1,'T-artifact','irreversible_external','DATA_EGRESS',?1,
                           'STARTED',NULL,NULL,?2,?3,?3,NULL)",
                params![
                    "export-legacy-started-null",
                    intent_json,
                    "2026-09-19T21:00:00Z"
                ],
            )
            .unwrap();
        drop(manager);

        let reopened = TaskManager::open_with_clock(&database, Box::new(FixedClock)).unwrap();
        assert_eq!(
            reopened
                .connection
                .query_row(
                    "SELECT state || ':' || outcome_certainty || ':' ||
                            CASE WHEN external_receipt IS NULL THEN 'null' ELSE 'present' END
                     FROM operations WHERE operation_id='export-legacy-started-null'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "UNKNOWN:OUTCOME_UNKNOWN:null"
        );
        assert_eq!(
            reopened
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM recovery_unknown_operations
                     WHERE operation_id='operation:export-legacy-started-null'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn legacy_unknown_reopens_into_inventory_and_uses_trusted_reconciliation() {
        let temp = TempDir::new().unwrap();
        let database = temp.path().join("task-manager.sqlite");
        let verifier = Arc::new(export_no_effect_verifier(
            "user-selected-file",
            "evidence:legacy-unknown",
            '9',
        ));
        let mut manager = manager_with_export_verifiers(&temp, vec![verifier.clone()]);
        let artifact = manager
            .import_artifact(
                &import_request(),
                &mut Cursor::new(b"legacy unknown export".as_slice()),
            )
            .unwrap();
        let intent_json = canonical_json(&ArtifactExportIntent {
            version: 1,
            task_id: "T-artifact".to_owned(),
            artifact_id: artifact.artifact_id.clone(),
            content_hash: artifact.stored_content_hash().unwrap().tagged().clone(),
            destination_class: "user-selected-file".to_owned(),
            max_size_bytes: 1_024,
            principal_kind: "user".to_owned(),
            principal_id: "user:test".to_owned(),
            semantic_program_hash: None,
            node_id: None,
            binding_id: None,
            attempt_id: None,
            grant_id: None,
        })
        .unwrap();
        manager
            .connection
            .execute(
                "INSERT INTO operations(
                    operation_id,task_id,transaction_class,effect_class,idempotency_key,
                    state,outcome_certainty,external_receipt,details_json,
                    prepared_at,started_at,finished_at
                 ) VALUES (?1,'T-artifact','irreversible_external','DATA_EGRESS',?1,
                           'UNKNOWN','OUTCOME_UNKNOWN',NULL,?2,?3,?3,?4)",
                params![
                    "export-legacy-unknown",
                    intent_json,
                    "2026-09-19T21:00:00Z",
                    "2026-09-19T21:30:00Z"
                ],
            )
            .unwrap();
        drop(manager);

        let mut reopened = TaskManager::open_with_clock_and_export_verifiers(
            &database,
            Box::new(FixedClock),
            vec![verifier.clone()],
        )
        .unwrap();
        assert_eq!(
            reopened
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM recovery_unknown_operations
                     WHERE operation_id='operation:export-legacy-unknown'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        reopened
            .reconcile_unknown_artifact_export_no_effect("export-legacy-unknown")
            .unwrap();
        assert_eq!(verifier.calls.load(Ordering::SeqCst), 1);
        reopened
            .reconcile_unknown_artifact_export_no_effect("export-legacy-unknown")
            .unwrap();
        assert_eq!(verifier.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            reopened
                .connection
                .query_row(
                    "SELECT state || ':' || outcome_certainty FROM operations
                     WHERE operation_id='export-legacy-unknown'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "FAILED:FAILED_NO_EFFECT"
        );
    }

    #[test]
    fn delivered_one_shot_reader_marker_cannot_be_rolled_back_to_pending() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let artifact = manager
            .import_artifact(
                &import_request(),
                &mut Cursor::new(b"one delivered reader".as_slice()),
            )
            .unwrap();
        let (binding_id, _) = install_one_shot_binding(
            &manager,
            "reader-delivery-tamper",
            std::slice::from_ref(&artifact.artifact_id),
            &[("artifact.read", "artifact", &artifact.artifact_id)],
        );
        let session = session_for_binding(&manager, "T-artifact", &binding_id);
        let scope = manager
            .scope_artifact_reads(&session, std::slice::from_ref(&artifact.artifact_id))
            .unwrap();
        let mut reader = manager
            .open_artifact_reader(&scope, &artifact.artifact_id)
            .unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"one delivered reader");
        drop(reader);

        let (operation_id, delivered_json) = manager
            .connection
            .query_row(
                "SELECT operation_id,external_receipt FROM operations
                 WHERE effect_class='ARTIFACT_READ'",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .unwrap();
        let delivered: ArtifactReaderAdmissionReceipt =
            serde_json::from_str(&delivered_json).unwrap();
        assert_eq!(delivered.kind, "artifact-reader-admission-delivered");
        let forged_pending = canonical_json(&ArtifactReaderAdmissionReceipt {
            version: 1,
            kind: "artifact-reader-admission-pending-delivery".to_owned(),
            operation_id: operation_id.clone(),
            admission_event_id: delivered.admission_event_id,
            admission_event_hash: delivered.admission_event_hash,
            delivery_event_id: None,
            delivery_event_hash: None,
        })
        .unwrap();
        manager
            .connection
            .execute(
                "UPDATE operations SET external_receipt=?2 WHERE operation_id=?1",
                params![operation_id, forged_pending],
            )
            .unwrap();
        assert!(matches!(
            manager.open_artifact_reader(&scope, &artifact.artifact_id),
            Err(TaskManagerError::InvalidRecord(
                "stored Artifact reader admission is invalid"
            ))
        ));
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT uses_consumed FROM authority_grants
                     WHERE grant_id='grant-reader-delivery-tamper-0'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "table-like scenarios exercise recovery, revocation, and supersession at the same arming boundary"
    )]
    fn export_arming_rechecks_recovery_revocation_and_attempt_supersession() {
        for scenario in ["recovery", "revocation", "supersession"] {
            let temp = TempDir::new().unwrap();
            let database = temp.path().join("task-manager.sqlite");
            let mut manager = manager(&temp);
            let artifact = manager
                .import_artifact(
                    &import_request(),
                    &mut Cursor::new(format!("arming {scenario}").as_bytes()),
                )
                .unwrap();
            let (binding_id, _) = install_one_shot_binding(
                &manager,
                &format!("arm-{scenario}"),
                std::slice::from_ref(&artifact.artifact_id),
                &[
                    ("artifact.read", "artifact", &artifact.artifact_id),
                    ("data.egress", "destination", "user-selected-file"),
                ],
            );
            let session = session_for_binding(&manager, "T-artifact", &binding_id);
            let scope = manager
                .scope_artifact_reads(&session, std::slice::from_ref(&artifact.artifact_id))
                .unwrap();
            let factory_calls = Arc::new(AtomicUsize::new(0));
            let calls = Arc::clone(&factory_calls);
            let mut destination = manager
                .issue_bound_artifact_export_destination(
                    &session,
                    &scope,
                    &format!("export-arm-{scenario}"),
                    &artifact.artifact_id,
                    "user-selected-file",
                    1_024,
                    move || {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok(Vec::<u8>::new())
                    },
                )
                .unwrap();
            let program_hash = allocation("unused").semantic_program_hash;
            let registry_id = format!("registry-arm-{scenario}");
            let database_for_hook = database.clone();
            let scenario_for_hook = scenario.to_owned();
            EXPORT_BEFORE_ARM_TEST_HOOK.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    let connection = Connection::open(database_for_hook)?;
                    match scenario_for_hook.as_str() {
                        "recovery" => {
                            connection.execute(
                                "UPDATE tasks SET state='RECOVERING' WHERE task_id='T-artifact'",
                                [],
                            )?;
                        }
                        "revocation" => {
                            connection.execute(
                                "UPDATE authority_grants SET state='REVOKED'
                                 WHERE grant_id='grant-arm-revocation-1'",
                                [],
                            )?;
                        }
                        "supersession" => {
                            connection.execute_batch(&format!(
                                "INSERT INTO execution_bindings(binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,ir_version,node_id,capability,provider_id,provider_version,attempt,policy_decision_refs_json,grant_refs_json,execution_profile_ref,placement_json,binding_json,created_at)
                                 VALUES ('binding-arm-later','attempt-arm-later','T-artifact','{program_hash}','{registry_id}','0.1','compose_report','document.compose','provider:sequential','1',2,'[]','[]','profile:test','{{}}','{{}}','2026-09-19T00:01:00Z');
                                 INSERT INTO step_executions(attempt_id,task_id,semantic_program_hash,registry_snapshot_id,node_id,binding_id,attempt_number,revision,state,input_artifacts_json,output_artifacts_json,created_at,updated_at)
                                 VALUES ('attempt-arm-later','T-artifact','{program_hash}','{registry_id}','compose_report','binding-arm-later',2,1,'RUNNING','[]','[]','2026-09-19T00:01:00Z','2026-09-19T00:01:00Z');"
                            ))?;
                        }
                        _ => unreachable!(),
                    }
                    Ok(())
                }));
            });
            assert!(matches!(
                manager.export_artifact(&scope, &artifact.artifact_id, &mut destination),
                Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
            ));
            assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
            assert_eq!(
                manager
                    .connection
                    .query_row(
                        "SELECT json_extract(external_receipt,'$.kind') FROM operations
                         WHERE operation_id=?1",
                        [format!("export-arm-{scenario}")],
                        |row| row.get::<_, String>(0),
                    )
                    .unwrap(),
                "pre-destination-admission"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_store_rejects_reparse_descendants() {
        let temp = TempDir::new().unwrap();
        let database = temp.path().join("task-manager.sqlite");
        let manager = TaskManager::open_with_clock(&database, Box::new(FixedClock)).unwrap();
        let link = manager.artifact_store_root.join("junction-descendant");
        let target = TempDir::new().unwrap();
        drop(manager);
        let output = std::process::Command::new(r"C:\Windows\System32\cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&link)
            .arg(target.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(matches!(
            TaskManager::open_with_clock(&database, Box::new(FixedClock)),
            Err(TaskManagerError::InvalidRecord(_))
        ));
        std::fs::remove_dir(&link).unwrap();
    }
}
