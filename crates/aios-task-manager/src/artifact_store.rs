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

use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions as CapOpenOptions};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::{
    Actor, Clock, Result, SCHEMA_VERSION, StoreIdentity, StoreLock, TaskManager, TaskManagerError,
    append_event, assert_manager_lease, canonical_json,
};

const IMPORT_LIMIT: u64 = 8 * 1024 * 1024 * 1024;
const COPY_BUFFER_SIZE: usize = 64 * 1024;
const SEALED_STAGING_VERSION: u8 = 1;

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
pub struct ArtifactIntegrity {
    pub state: ArtifactIntegrityState,
    pub verified_at: Option<String>,
    pub verifier: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRetention {
    pub class: RetentionClass,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactHandle {
    pub artifact_id: String,
    pub uri: ArtifactUri,
    pub semantic_type: Option<String>,
    pub media_type: String,
    pub format: Option<String>,
    pub size_bytes: u64,
    pub content_hash: ContentHash,
    pub origin: ArtifactOrigin,
    pub sensitivity: Sensitivity,
    pub retention: ArtifactRetention,
    pub integrity: ArtifactIntegrity,
    pub labels: Vec<String>,
    pub created_at: String,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
pub struct ArtifactLineage {
    #[serde(default)]
    pub input_artifact_ids: Vec<String>,
    #[serde(default)]
    pub derived_from_artifact_ids: Vec<String>,
    #[serde(default)]
    pub representation_of_object_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct GrantAdmission {
    grant_id: String,
    one_shot_consumed: bool,
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
    seal_ref: String,
    maximum: u64,
    written: u64,
}

#[derive(Debug, Serialize, Deserialize)]
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
        validate_writer_fence(
            &self.authority_connection,
            &self.allocation_id,
            &self.clock.now(),
            &self.lease_owner,
            self.lease_epoch,
            self.grant_admission.as_ref(),
        )?;
        let mut file = self.file.take().ok_or(TaskManagerError::InvalidRecord(
            "Artifact staging writer is already finalized",
        ))?;
        file.flush()?;
        file.sync_all()?;
        file.seek(SeekFrom::Start(0))?;
        let (size_bytes, content_hash) = hash_reader(&mut file)?;
        if size_bytes != self.written {
            return Err(TaskManagerError::InvalidRecord(
                "Artifact staging writer byte count changed before sealing",
            ));
        }
        drop(file);
        let sealed = SealedStaging {
            version: SEALED_STAGING_VERSION,
            allocation_id: self.allocation_id.clone(),
            size_bytes,
            content_hash,
        };
        let bytes = serde_json::to_vec(&sealed)?;
        let mut seal = self.store.open_with(
            safe_internal_ref(&self.seal_ref)?,
            CapOpenOptions::new().write(true).create_new(true),
        )?;
        seal.write_all(&bytes)?;
        seal.flush()?;
        seal.sync_all()?;
        sync_cap_directory(&self.store, "staging")?;
        Ok(self.written)
    }
}

impl Write for ArtifactStagingWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        validate_writer_fence(
            &self.authority_connection,
            &self.allocation_id,
            &self.clock.now(),
            &self.lease_owner,
            self.lease_epoch,
            self.grant_admission.as_ref(),
        )
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
        self.written = self
            .written
            .checked_add(u64::try_from(written).unwrap_or(u64::MAX))
            .ok_or_else(|| std::io::Error::other("staging byte count overflow"))?;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        validate_writer_fence(
            &self.authority_connection,
            &self.allocation_id,
            &self.clock.now(),
            &self.lease_owner,
            self.lease_epoch,
            self.grant_admission.as_ref(),
        )
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::PermissionDenied, error))?;
        self.file
            .as_mut()
            .ok_or_else(|| std::io::Error::other("staging writer is finalized"))?
            .flush()
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

pub(super) fn initialize_root(
    store_lock: Option<&StoreLock>,
    connection: &Connection,
) -> Result<(PathBuf, Dir)> {
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
    match std::fs::create_dir(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    reject_reparse_root(&root)?;
    let canonical_root = root.canonicalize()?;
    let directory = Dir::open_ambient_dir(&canonical_root, ambient_authority())?;
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
    let root_file = directory.try_clone()?.into_std_file();
    let root_identity = super::store_identity(&canonical_root, &root_file)?.persistent_key();
    if stored_root_identity
        .as_deref()
        .is_some_and(|stored| stored != root_identity)
    {
        return Err(TaskManagerError::InvalidRecord(
            "Artifact store root identity does not match its database binding",
        ));
    }
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
    Ok((canonical_root, directory))
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

impl TaskManager {
    /// Imports bytes after the trusted in-crate control plane has authenticated the caller and
    /// mediated the selected source.
    pub(crate) fn import_artifact<R: Read>(
        &mut self,
        request: &ImportArtifactRequest,
        reader: &mut R,
    ) -> Result<ArtifactHandle> {
        validate_import_request(request)?;
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
        let token = random_token(&self.connection)?;
        let staging_ref = format!("staging/import-{token}");
        let maximum = request
            .max_size_bytes
            .unwrap_or(IMPORT_LIMIT)
            .min(IMPORT_LIMIT);
        let (size, content_hash) =
            stream_into_new_internal_file(reader, &self.artifact_store_dir, &staging_ref, maximum)?;
        let (storage_ref, reused) = place_blob(
            &self.artifact_store_dir,
            &staging_ref,
            &content_hash,
            size,
            false,
            &token,
        )?;
        let created_at = self.clock.now();
        let artifact_id = artifact_id("import", &token);
        let uri = ArtifactUri::new(&artifact_id);
        let labels_json = serde_json::to_string(&request.labels)?;
        let lease_owner = self.lease_owner.clone();
        let lease_epoch = self.lease_epoch;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_manager_lease(&transaction, &lease_owner, lease_epoch)?;
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
            "details": {"content_hash":content_hash,"size_bytes":size,"blob_reused":reused}
        });
        append_event(&transaction, &request.task_id, &event)?;
        transaction.commit()?;
        self.get_artifact(&artifact_id)?
            .ok_or(TaskManagerError::InvalidRecord(
                "imported Artifact disappeared",
            ))
    }

    pub fn allocate_artifact_output(
        &mut self,
        request: &OutputAllocationRequest,
    ) -> Result<ArtifactOutputAllocation> {
        validate_allocation_request(request, &self.clock.now())?;
        let created_at = self.clock.now();
        let staging_ref = format!("staging/output-{}", random_token(&self.connection)?);
        let lease_owner = self.lease_owner.clone();
        let lease_epoch = self.lease_epoch;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_manager_lease(&transaction, &lease_owner, lease_epoch)?;
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

    #[allow(
        clippy::too_many_lines,
        reason = "keeps output admission, file issuance, and one-shot consumption in one transaction"
    )]
    pub fn open_artifact_output(&mut self, allocation_id: &str) -> Result<ArtifactStagingWriter> {
        validate_id(allocation_id, 256, "invalid Artifact allocation ID")?;
        let authority_connection = self.database_locator.open()?;
        authority_connection.busy_timeout(std::time::Duration::from_secs(5))?;
        if let Some(lock) = self.store_lock.as_ref() {
            super::verify_locked_store_identity(&authority_connection, lock)?;
        }
        let lease_owner = self.lease_owner.clone();
        let lease_epoch = self.lease_epoch;
        let now = self.clock.now();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_manager_lease(&transaction, &lease_owner, lease_epoch)?;
        let Some(allocation) = load_allocation_row(&transaction, allocation_id)? else {
            return Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_ALLOCATION_NOT_FOUND",
            ));
        };
        let Some(staging_ref) = allocation.staging_ref.clone() else {
            return Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_ALLOCATION_NOT_FOUND",
            ));
        };
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
        transaction.execute(
            "UPDATE artifact_output_allocations SET state='WRITING',updated_at=?2 WHERE allocation_id=?1 AND state='ALLOCATED'",
            params![allocation_id,now],
        )?;
        transaction.commit()?;
        Ok(ArtifactStagingWriter {
            file: Some(file),
            store: self.artifact_store_dir.try_clone()?,
            authority_connection,
            clock: Arc::clone(&self.clock),
            lease_owner: self.lease_owner.clone(),
            lease_epoch: self.lease_epoch,
            grant_admission,
            allocation_id: allocation_id.to_owned(),
            seal_ref: seal_ref(&staging_ref),
            maximum: allocation
                .max_size_bytes
                .unwrap_or(IMPORT_LIMIT)
                .min(IMPORT_LIMIT),
            written: 0,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "publication is one auditable two-resource protocol"
    )]
    pub fn publish_artifact_output(
        &mut self,
        request: &ArtifactPublicationRequest,
    ) -> Result<ArtifactPublicationResult> {
        validate_publication_request(request)?;
        let request_json = canonical_json(request)?;
        if let Some((stored_request, state, result_json, stored_hash)) = self
            .connection
            .query_row(
                "SELECT request_json,state,result_json,content_hash FROM artifact_publications WHERE publication_id=?1",
                [&request.publication_id],
                |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,Option<String>>(2)?,row.get::<_,Option<String>>(3)?)),
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
            if state != "PENDING" {
                return Ok(publication_conflict(request, self.clock.now()));
            }
        } else {
            if !lineage_authorized(&self.connection, request)? {
                return Ok(publication_failure(
                    request,
                    "ARTIFACT_AUTHORITY_DENIED",
                    self.clock.now(),
                ));
            }
            let allocation = load_allocation_row(&self.connection, &request.allocation_id)?
                .ok_or(TaskManagerError::InvalidRecord(
                    "ARTIFACT_ALLOCATION_NOT_FOUND",
                ))?;
            if let Err(error) = self.sealed_staging(&allocation, request) {
                if let Some(code) = artifact_reason(&error) {
                    return Ok(publication_failure(request, code, self.clock.now()));
                }
                return Err(error);
            }
            if let Err(error) = self.begin_publication(request, &request_json) {
                if let Some(code) = artifact_reason(&error) {
                    return Ok(publication_failure(request, code, self.clock.now()));
                }
                return Err(error);
            }
        }

        let allocation = load_allocation_row(&self.connection, &request.allocation_id)?.ok_or(
            TaskManagerError::InvalidRecord("ARTIFACT_ALLOCATION_NOT_FOUND"),
        )?;
        if let Err(error) = validate_publication_allocation(request, &allocation, &self.clock.now())
        {
            if let Some(code) = artifact_reason(&error) {
                return Ok(publication_failure(request, code, self.clock.now()));
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
        let sealed = self.sealed_staging(&allocation, request)?;
        let (size, content_hash) = hash_internal_file(&self.artifact_store_dir, staging_ref)?;
        if size != sealed.size_bytes || content_hash != sealed.content_hash {
            self.fail_pending_publication(request, "ARTIFACT_HASH_MISMATCH")?;
            return Ok(publication_failure(
                request,
                "ARTIFACT_HASH_MISMATCH",
                self.clock.now(),
            ));
        }
        let effective_maximum = allocation
            .max_size_bytes
            .unwrap_or(IMPORT_LIMIT)
            .min(IMPORT_LIMIT);
        if size > effective_maximum {
            self.fail_pending_publication(request, "ARTIFACT_SIZE_LIMIT")?;
            return Ok(publication_failure(
                request,
                "ARTIFACT_SIZE_LIMIT",
                self.clock.now(),
            ));
        }
        let (storage_ref, blob_reused) = place_blob(
            &self.artifact_store_dir,
            staging_ref,
            &content_hash,
            size,
            true,
            &request.publication_id,
        )?;
        let resulted_at = self.clock.now();
        let artifact_id = artifact_id("publication", &request.publication_id);
        let artifact_uri = ArtifactUri::new(&artifact_id);
        let lease_owner = self.lease_owner.clone();
        let lease_epoch = self.lease_epoch;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_manager_lease(&transaction, &lease_owner, lease_epoch)?;
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
            self.fail_pending_publication(request, "ARTIFACT_AUTHORITY_DENIED")?;
            return Ok(publication_failure(
                request,
                "ARTIFACT_AUTHORITY_DENIED",
                self.clock.now(),
            ));
        }
        if let Err(error) = validate_publication_execution_scope(&transaction, request, &allocation)
        {
            drop(transaction);
            let Some(code) = artifact_reason(&error) else {
                return Err(error);
            };
            self.fail_pending_publication(request, code)?;
            return Ok(publication_failure(request, code, self.clock.now()));
        }
        for source in request
            .lineage
            .input_artifact_ids
            .iter()
            .chain(&request.lineage.derived_from_artifact_ids)
        {
            let authorized = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM task_artifacts WHERE task_id=?1 AND artifact_id=?2 AND role IN ('input','intermediate','output'))",
                params![request.task_id,source],
                |row| row.get::<_,bool>(0),
            )?;
            if !authorized {
                return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
            }
        }
        upsert_durable_blob(
            &transaction,
            &content_hash,
            size,
            &storage_ref,
            &resulted_at,
        )?;
        transaction.execute(
            "INSERT INTO artifacts (artifact_id,uri,semantic_type,media_type,format,size_bytes,content_hash,sensitivity,retention_class,origin_kind,origin_task_id,origin_program_hash,origin_node_id,origin_binding_id,integrity_state,integrity_verified_at,integrity_verifier,labels_json,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,'task',?10,?11,?12,?13,'verified',?14,'artifact-store:sha256',?15,?14)",
            params![artifact_id,artifact_uri.as_str(),request.semantic_type,request.media_type,request.format,to_i64(size)?,content_hash,allocation.sensitivity,allocation.retention,request.task_id,allocation.semantic_program_hash,allocation.node_id,allocation.binding_id,resulted_at,serde_json::to_string(&request.labels)?],
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
            "input_artifacts":request.lineage.input_artifact_ids,
            "output_artifacts":[artifact_id],
            "status":"success",
            "details":{"allocation_id":request.allocation_id,"publication_id":request.publication_id,"content_hash":content_hash,"size_bytes":size}
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
        task_id: &str,
        binding_id: Option<&str>,
        artifact_ids: &[String],
    ) -> Result<ArtifactReadScope> {
        validate_id(task_id, 256, "invalid Artifact read Task")?;
        if artifact_ids.is_empty() || artifact_ids.len() > 256 || !all_unique(artifact_ids) {
            return Err(TaskManagerError::InvalidRecord(
                "invalid Artifact read scope",
            ));
        }
        let Some(binding_id) = binding_id else {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        };
        let now = self.clock.now();
        let authority = capture_read_authority(&self.connection, task_id, Some(binding_id), &now)?;
        let execution = authority
            .execution
            .as_ref()
            .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?;
        let mut grant_ids = BTreeMap::new();
        for artifact_id in artifact_ids {
            if !artifact_read_authorized(&self.connection, task_id, &authority, artifact_id)?
                || exact_operation_grant(
                    &self.connection,
                    task_id,
                    execution,
                    "artifact.read",
                    "artifact",
                    artifact_id,
                    &now,
                    None,
                )?
                .map(|grant| grant_ids.insert(artifact_id.clone(), grant.grant_id))
                .is_none()
            {
                return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
            }
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

    #[allow(
        clippy::too_many_lines,
        reason = "keeps integrity verification and exact authority admission before reader issuance"
    )]
    pub fn open_artifact_reader(
        &mut self,
        scope: &ArtifactReadScope,
        artifact_id: &str,
    ) -> Result<ArtifactReader> {
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
        let expected_grant_id = match &scope.authority.execution {
            Some(execution) => Some((
                execution,
                scope
                    .grant_ids
                    .get(artifact_id)
                    .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?,
            )),
            None => None,
        };
        let handle = self
            .get_artifact(artifact_id)?
            .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_NOT_FOUND"))?;
        let storage_ref = self.connection.query_row(
            "SELECT b.storage_ref FROM artifacts a JOIN artifact_blobs b ON b.content_hash=a.content_hash WHERE a.artifact_id=?1",
            [artifact_id],
            |row| row.get::<_,String>(0),
        )?;
        let mut file = self
            .artifact_store_dir
            .open(safe_internal_ref(&storage_ref)?)?
            .into_std();
        let length_before = file.metadata()?.len();
        let verified = hash_reader(&mut file);
        let length_after = file.metadata()?.len();
        let expected_hash = handle.content_hash.tagged();
        match verified {
            Ok((size, hash))
                if length_before == length_after
                    && size == length_after
                    && size == handle.size_bytes
                    && hash == expected_hash =>
            {
                let admitted_at = self.clock.now();
                let lease_owner = self.lease_owner.clone();
                let lease_epoch = self.lease_epoch;
                let transaction = self
                    .connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)?;
                assert_manager_lease(&transaction, &lease_owner, lease_epoch)?;
                let grant_admission = if let Some((execution, grant_id)) = expected_grant_id {
                    let current = load_execution_authority(
                        &transaction,
                        &scope.task_id,
                        &execution.binding_id,
                        &admitted_at,
                    )?;
                    if current != *execution
                        || !artifact_read_authorized(
                            &transaction,
                            &scope.task_id,
                            &scope.authority,
                            artifact_id,
                        )?
                    {
                        return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
                    }
                    Some(admit_operation_grant(
                        &transaction,
                        &scope.task_id,
                        execution,
                        "artifact.read",
                        "artifact",
                        artifact_id,
                        &admitted_at,
                        grant_id,
                    )?)
                } else {
                    if capture_read_authority(&transaction, &scope.task_id, None, &admitted_at)?
                        != scope.authority
                        || !artifact_read_authorized(
                            &transaction,
                            &scope.task_id,
                            &scope.authority,
                            artifact_id,
                        )?
                    {
                        return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
                    }
                    None
                };
                transaction.execute("UPDATE artifacts SET integrity_state='verified',integrity_verified_at=?2,integrity_verifier='artifact-store:sha256' WHERE artifact_id=?1",params![artifact_id,admitted_at])?;
                transaction.execute("UPDATE artifact_blobs SET durability_state='DURABLE',verified_at=?2 WHERE content_hash=?1",params![expected_hash,admitted_at])?;
                transaction.commit()?;
                file.seek(SeekFrom::Start(0))?;
                let authority_connection = self.database_locator.open()?;
                authority_connection.busy_timeout(std::time::Duration::from_secs(5))?;
                let database_identity = self.store_lock.as_ref().map(|lock| lock.identity.clone());
                if let Some(identity) = database_identity.as_ref() {
                    verify_database_identity(&authority_connection, identity)?;
                }
                Ok(ArtifactReader {
                    file,
                    handle: self.get_artifact(artifact_id)?.ok_or(
                        TaskManagerError::InvalidRecord("verified Artifact disappeared"),
                    )?,
                    authority_connection,
                    clock: Arc::clone(&self.clock),
                    lease_owner,
                    lease_epoch,
                    database_identity,
                    task_id: scope.task_id.clone(),
                    authority: scope.authority.clone(),
                    artifact_id: artifact_id.to_owned(),
                    grant_admission,
                })
            }
            _ => {
                self.mark_integrity_failed(artifact_id, &scope.task_id, &expected_hash)?;
                Err(TaskManagerError::InvalidRecord("ARTIFACT_INTEGRITY_FAILED"))
            }
        }
    }

    pub fn export_artifact<W: Write>(
        &mut self,
        scope: &ArtifactReadScope,
        artifact_id: &str,
        destination: &mut W,
        max_size_bytes: u64,
    ) -> Result<u64> {
        let mut reader = self.open_artifact_reader(scope, artifact_id)?;
        if reader.handle.size_bytes > max_size_bytes {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_SIZE_LIMIT"));
        }
        copy_bounded(&mut reader, destination, max_size_bytes)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "keeps blob, integrity, and staging reconciliation in one fenced startup audit"
    )]
    pub fn reconcile_artifacts_startup(&mut self) -> Result<ArtifactReconciliationReport> {
        let reconciled_at = self.clock.now();
        let mut findings = Vec::new();
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
        reconcile_pending_blob_placements(&self.artifact_store_dir)?;
        for relative in physical_blob_refs(&self.artifact_store_dir)? {
            if known_refs.contains(&relative) {
                continue;
            }
            let (size, hash) = hash_internal_file(&self.artifact_store_dir, &relative)?;
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
                "SELECT allocation_id,staging_ref FROM artifact_output_allocations WHERE staging_ref IS NOT NULL ORDER BY allocation_id",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        let staged_by_ref = staged
            .into_iter()
            .map(|(allocation_id, staging_ref)| (staging_ref, allocation_id))
            .collect::<std::collections::BTreeMap<_, _>>();
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
                findings.push(ArtifactReconciliationFinding {
                    kind: ArtifactReconciliationKind::StagingOrphaned,
                    allocation_id: staged_by_ref.get(&staging_ref).cloned(),
                    content_hash: None,
                    artifact_ids: Vec::new(),
                });
            }
        }
        Ok(ArtifactReconciliationReport {
            reconciled_at,
            findings,
        })
    }

    fn begin_publication(
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
        let allocation = load_allocation_row(&transaction, &request.allocation_id)?.ok_or(
            TaskManagerError::InvalidRecord("ARTIFACT_ALLOCATION_NOT_FOUND"),
        )?;
        validate_publication_allocation(request, &allocation, &now)?;
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
        transaction.execute("UPDATE artifact_output_allocations SET state='FINALIZING',publication_id=?2,updated_at=?3 WHERE allocation_id=?1 AND state=?4",params![request.allocation_id,request.publication_id,now,request.expected_allocation_state.as_str()])?;
        transaction.commit()?;
        Ok(())
    }

    fn fail_pending_publication(
        &mut self,
        request: &ArtifactPublicationRequest,
        _reason_code: &str,
    ) -> Result<()> {
        let now = self.clock.now();
        let lease_owner = self.lease_owner.clone();
        let lease_epoch = self.lease_epoch;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_manager_lease(&transaction, &lease_owner, lease_epoch)?;
        transaction.execute(
            "UPDATE artifact_publications SET state='FAILED',committed_at=?2 WHERE publication_id=?1 AND state='PENDING'",
            params![request.publication_id, now],
        )?;
        transaction.execute(
            "UPDATE artifact_output_allocations SET state='FAILED',updated_at=?2 WHERE allocation_id=?1 AND state='FINALIZING'",
            params![request.allocation_id, now],
        )?;
        transaction.commit()?;
        Ok(())
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
        match hash_internal_file(&self.artifact_store_dir, &row.23) {
            Ok((actual_size, actual_hash)) if actual_size == size && actual_hash == row.1 => {
                Ok(result)
            }
            _ => {
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
        self.mark_blob_failed(
            content_hash,
            "CORRUPT",
            &[artifact_id.to_owned()],
            &self.clock.now(),
        )?;
        let authorized = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM task_artifacts WHERE task_id=?1 AND artifact_id=?2)",
            params![task_id, artifact_id],
            |row| row.get::<_, bool>(0),
        )?;
        if !authorized {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        Ok(())
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
    staging_ref: Option<String>,
    expires_at: String,
}

fn load_allocation_row(
    connection: &Connection,
    allocation_id: &str,
) -> Result<Option<AllocationRow>> {
    let row=connection.query_row("SELECT task_id,semantic_program_hash,node_id,binding_id,attempt_id,expected_semantic_type,allowed_media_types_json,max_size_bytes,sensitivity,retention,state,staging_ref,expires_at FROM artifact_output_allocations WHERE allocation_id=?1",[allocation_id],|row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,Option<String>>(3)?,row.get::<_,Option<String>>(4)?,row.get::<_,Option<String>>(5)?,row.get::<_,Option<String>>(6)?,row.get::<_,Option<i64>>(7)?,row.get::<_,String>(8)?,row.get::<_,String>(9)?,row.get::<_,String>(10)?,row.get::<_,Option<String>>(11)?,row.get::<_,String>(12)?))).optional()?;
    row.map(|row| {
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
            staging_ref: row.11,
            expires_at: row.12,
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

fn validate_writer_fence(
    connection: &Connection,
    allocation_id: &str,
    now: &str,
    lease_owner: &str,
    lease_epoch: i64,
    grant_admission: Option<&GrantAdmission>,
) -> Result<()> {
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
    if allocation.state != "WRITING" || parse_time(&allocation.expires_at)? <= parse_time(now)? {
        return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
    }
    if let Some(binding_id) = allocation.binding_id.as_deref() {
        let admission =
            grant_admission.ok_or(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))?;
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
        Ok(())
    } else {
        validate_allocation_execution_scope(connection, allocation_id, &allocation, now)
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
                AND s.state IN ('READY','STARTING','RUNNING','SUCCEEDED')
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
        let consumed_one_shot = grant.25 == "CONSUMED"
            && grant.11 == "ONE_SHOT"
            && grant.26 == Some(1)
            && grant.27 == 1;
        let binding_lifecycle_valid = (grant.25 == "ACTIVE"
            && grant.26.is_none_or(|maximum| grant.27 < maximum)
            && parse_time(&grant.0)? > checked_at)
            || consumed_one_shot;
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
                if status == "APPROVED" || consumed_one_shot && status == "EXPIRED" =>
            {
                if !consumed_one_shot
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
                    || !consumed_one_shot
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
                row.scope == "ONE_SHOT"
                    && row.state == "CONSUMED"
                    && row.max_uses == Some(1)
                    && row.uses_consumed == 1
            }
            Some(_) => row.state == "ACTIVE",
            None => {
                row.state == "ACTIVE"
                    && row
                        .max_uses
                        .is_none_or(|maximum| row.uses_consumed < maximum)
            }
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
    transaction: &rusqlite::Transaction<'_>,
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

fn lineage_authorized(
    connection: &Connection,
    request: &ArtifactPublicationRequest,
) -> Result<bool> {
    for source in request
        .lineage
        .input_artifact_ids
        .iter()
        .chain(&request.lineage.derived_from_artifact_ids)
    {
        if !connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM task_artifacts WHERE task_id=?1 AND artifact_id=?2 AND role IN ('input','intermediate','output'))",
            params![request.task_id, source],
            |row| row.get::<_, bool>(0),
        )? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn validate_import_request(request: &ImportArtifactRequest) -> Result<()> {
    if request.schema_version != SCHEMA_VERSION
        || request.media_type.is_empty()
        || request.media_type.len() > 160
        || request.max_size_bytes == Some(0)
        || !all_unique(&request.labels)
        || request.labels.len() > 64
    {
        return Err(TaskManagerError::InvalidRecord(
            "invalid Artifact import request",
        ));
    }
    validate_id(&request.task_id, 256, "invalid Artifact import Task")?;
    validate_optional_semantic_type(request.semantic_type.as_deref())?;
    Ok(())
}

fn validate_allocation_request(request: &OutputAllocationRequest, now: &str) -> Result<()> {
    if request.schema_version != SCHEMA_VERSION
        || request.allowed_media_types.len() > 32
        || !all_unique(&request.allowed_media_types)
        || request
            .allowed_media_types
            .iter()
            .any(|value| value.is_empty() || value.len() > 160)
        || request.binding_id.is_some() != request.attempt_id.is_some()
        || parse_time(&request.expires_at)? <= parse_time(now)?
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

fn validate_publication_request(request: &ArtifactPublicationRequest) -> Result<()> {
    let lineage_unique = all_unique(&request.lineage.input_artifact_ids)
        && all_unique(&request.lineage.derived_from_artifact_ids)
        && all_unique(&request.lineage.representation_of_object_ids);
    if request.schema_version != SCHEMA_VERSION
        || request.media_type.is_empty()
        || request.media_type.len() > 160
        || request.labels.len() > 64
        || !all_unique(&request.labels)
        || request.lineage.input_artifact_ids.len() > 256
        || request.lineage.derived_from_artifact_ids.len() > 256
        || request.lineage.representation_of_object_ids.len() > 64
        || !lineage_unique
        || request
            .lineage
            .representation_of_object_ids
            .iter()
            .any(|value| !value.starts_with("object://"))
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
            size_bytes: u64::try_from(size)
                .map_err(|_| TaskManagerError::InvalidRecord("negative Artifact size"))?,
            content_hash: ContentHash::from_tagged(&content_hash)?,
            origin: ArtifactOrigin {
                kind: ArtifactOriginKind::parse(&origin_kind)?,
                task_id: row.get(11)?,
                semantic_program_hash: row.get(12)?,
                step_id: row.get(13)?,
                execution_binding_id: row.get(14)?,
                provider_id: row.get(15)?,
            },
            sensitivity: Sensitivity::parse(&sensitivity)?,
            retention: ArtifactRetention {
                class: RetentionClass::parse(&retention)?,
                expires_at: row.get(9)?,
            },
            integrity: ArtifactIntegrity {
                state: ArtifactIntegrityState::parse(&integrity)?,
                verified_at: row.get(17)?,
                verifier: row.get(18)?,
            },
            labels: labels
                .map(|value| serde_json::from_str(&value))
                .transpose()?
                .unwrap_or_default(),
            created_at: row.get(20)?,
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

fn place_blob(
    store: &Dir,
    staging_ref: &str,
    content_hash: &str,
    size: u64,
    preserve_staging: bool,
    placement_identity: &str,
) -> Result<(String, bool)> {
    validate_hash(content_hash)?;
    let digest = content_hash.strip_prefix("sha256:").unwrap_or_default();
    let storage_ref = format!(
        "blobs/sha256/{}/{}/{}",
        &digest[0..2],
        &digest[2..4],
        digest
    );
    let parent_ref = format!("blobs/sha256/{}/{}", &digest[0..2], &digest[2..4]);
    create_durable_ancestors(store, &parent_ref)?;
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
    drop(pending);
    sync_cap_directory(store, "blobs/pending")?;
    let reused = match store.hard_link(
        safe_internal_ref(&pending_ref)?,
        store,
        safe_internal_ref(&storage_ref)?,
    ) {
        Ok(()) => false,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let (existing_size, existing_hash) = hash_internal_file(store, &storage_ref)?;
            if existing_size != size || existing_hash != content_hash {
                return Err(TaskManagerError::InvalidRecord("ARTIFACT_HASH_MISMATCH"));
            }
            true
        }
        Err(error) => return Err(error.into()),
    };
    store.remove_file(safe_internal_ref(&pending_ref)?)?;
    sync_cap_directory(store, &parent_ref)?;
    sync_cap_directory(store, "blobs/pending")?;
    if !preserve_staging {
        store.remove_file(safe_internal_ref(staging_ref)?)?;
        sync_cap_directory(store, "staging")?;
    }
    Ok((storage_ref, reused))
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
    let result = stream_into_file(reader, &mut file, maximum);
    if result.is_err() {
        drop(file);
        let _ = store.remove_file(&relative);
    }
    result
}

fn stream_into_new_file<R: Read>(
    reader: &mut R,
    path: &Path,
    maximum: u64,
) -> Result<(u64, String)> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
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

fn copy_bounded<R: Read, W: Write>(reader: &mut R, writer: &mut W, maximum: u64) -> Result<u64> {
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
        writer.write_all(&buffer[..count])?;
    }
    writer.flush()?;
    Ok(size)
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

fn reconcile_pending_blob_placements(store: &Dir) -> Result<()> {
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
        let Some(digest) = name.split('-').next() else {
            continue;
        };
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            continue;
        }
        let pending_ref = format!("blobs/pending/{name}");
        let expected = format!("sha256:{digest}");
        let (_, actual) = hash_internal_file(store, &pending_ref)?;
        if actual != expected {
            continue;
        }
        let parent_ref = format!("blobs/sha256/{}/{}", &digest[0..2], &digest[2..4]);
        let final_ref = format!("{parent_ref}/{digest}");
        create_durable_ancestors(store, &parent_ref)?;
        match store.hard_link(
            safe_internal_ref(&pending_ref)?,
            store,
            safe_internal_ref(&final_ref)?,
        ) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let (_, final_hash) = hash_internal_file(store, &final_ref)?;
                if final_hash != expected {
                    return Err(TaskManagerError::InvalidRecord("ARTIFACT_HASH_MISMATCH"));
                }
            }
            Err(error) => return Err(error.into()),
        }
        store.remove_file(safe_internal_ref(&pending_ref)?)?;
        sync_cap_directory(store, &parent_ref)?;
    }
    sync_cap_directory(store, "blobs/pending")?;
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

fn seal_ref(staging_ref: &str) -> String {
    format!("{staging_ref}.sealed")
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

fn validate_id(value: &str, maximum: usize, message: &'static str) -> Result<()> {
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
    if value.is_some_and(|value| value.is_empty() || value.len() > 256 || !value.contains('@')) {
        Err(TaskManagerError::InvalidRecord(
            "invalid Artifact semantic type",
        ))
    } else {
        Ok(())
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

#[allow(
    clippy::unnecessary_wraps,
    reason = "directory synchronization is fallible on supported durable filesystems and a portability no-op elsewhere"
)]
fn sync_store_root(store: &Dir) -> Result<()> {
    #[cfg(unix)]
    store.try_clone()?.into_std_file().sync_all()?;
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

    fn import_request() -> ImportArtifactRequest {
        ImportArtifactRequest {
            schema_version: "0.1".to_owned(),
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
        let mut export_one = Vec::new();
        let mut export_two = Vec::new();
        assert_eq!(
            manager
                .export_artifact(&scope, &first.artifact_id, &mut export_one, 1_024)
                .unwrap(),
            8
        );
        manager
            .export_artifact(&scope, &first.artifact_id, &mut export_two, 1_024)
            .unwrap();
        assert_eq!(export_one, export_two);
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
            0
        );
    }

    #[test]
    fn orphan_blob_and_staging_are_reported_but_never_promoted() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let staging_ref = "staging/manual-crash";
        let staging = manager.artifact_store_root.join(staging_ref);
        let (size, hash) =
            stream_into_new_file(&mut Cursor::new(b"orphan".as_slice()), &staging, 1_024).unwrap();
        place_blob(
            &manager.artifact_store_dir,
            staging_ref,
            &hash,
            size,
            false,
            "manual-crash",
        )
        .unwrap();
        std::fs::write(
            manager.artifact_store_root.join("staging/raw-residue"),
            b"unknown",
        )
        .unwrap();
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
    fn crash_after_blob_placement_can_retry_without_automatic_promotion() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        manager
            .allocate_artifact_output(&allocation("alloc-crash"))
            .unwrap();
        write_output(&mut manager, "alloc-crash", b"candidate");
        let request = publication("pub-crash", "alloc-crash");
        let request_json = canonical_json(&request).unwrap();
        manager.begin_publication(&request, &request_json).unwrap();
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
        place_blob(
            &manager.artifact_store_dir,
            &staging_ref,
            &hash,
            size,
            true,
            "pub-crash",
        )
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
                .state,
            ArtifactIntegrityState::Failed
        );
        let scope = manager
            .scope_owned_artifact_reads("T-artifact", &[artifact_id.clone()])
            .unwrap();
        assert!(matches!(
            manager.open_artifact_reader(&scope, &artifact_id),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_INTEGRITY_FAILED"))
        ));
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
                .state,
            ArtifactIntegrityState::Failed
        );
    }

    #[test]
    fn read_scopes_do_not_grant_artifacts_from_another_task() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        let artifact = manager
            .import_artifact(&import_request(), &mut Cursor::new(b"private".as_slice()))
            .unwrap();
        assert!(matches!(
            manager.scope_artifact_reads("T-artifact", None, &[artifact.artifact_id.clone()]),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
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
        assert!(matches!(
            manager.scope_artifact_reads("T-artifact", None, &["artifact:forged".to_owned()]),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
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

            let mut exported = Vec::new();
            manager
                .export_artifact(&scope, &artifact.artifact_id, &mut exported, 1_024)
                .unwrap();
            assert_eq!(exported, bytes, "owner export failed in {state}");

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
        let scope = manager
            .scope_artifact_reads(
                "T-artifact",
                Some(&binding_id),
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
            manager.scope_artifact_reads(
                "T-artifact",
                Some(&binding_id),
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
            let read_scope = manager
                .scope_artifact_reads(
                    "T-artifact",
                    Some(&binding_id),
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
        let scope = manager
            .scope_artifact_reads(
                "T-artifact",
                Some(&binding_id),
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
        let revoked_scope = manager
            .scope_artifact_reads(
                "T-artifact",
                Some("binding-read"),
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
            manager.scope_artifact_reads(
                "T-artifact",
                Some("binding-read"),
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
        let cancellation_scope = manager
            .scope_artifact_reads(
                "T-artifact",
                Some("binding-read"),
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
        let superseded_scope = manager
            .scope_artifact_reads(
                "T-artifact",
                Some("binding-read"),
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
    fn live_writer_cannot_publish_and_can_continue_until_durable_finish() {
        let temp = TempDir::new().unwrap();
        let mut manager = manager(&temp);
        manager
            .allocate_artifact_output(&allocation("alloc-live"))
            .unwrap();
        let mut writer = manager.open_artifact_output("alloc-live").unwrap();
        writer.write_all(b"partial").unwrap();
        let early = manager
            .publish_artifact_output(&publication("pub-live", "alloc-live"))
            .unwrap();
        assert!(!early.published);
        assert_eq!(early.reason_code, "ARTIFACT_ALLOCATION_STATE_CONFLICT");
        writer.write_all(b"-finished").unwrap();
        assert_eq!(writer.finish().unwrap(), 16);
        let published = manager
            .publish_artifact_output(&publication("pub-live", "alloc-live"))
            .unwrap();
        assert!(published.published);
        let scope = manager
            .scope_owned_artifact_reads("T-artifact", &[published.artifact_id.clone().unwrap()])
            .unwrap();
        let mut reader = manager
            .open_artifact_reader(&scope, published.artifact_id.as_deref().unwrap())
            .unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"partial-finished");
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
                [artifact.content_hash.tagged()],
            )
            .unwrap();
        assert!(matches!(
            manager.open_artifact_reader(&scope, &artifact.artifact_id),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_INTEGRITY_FAILED"))
        ));
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

    #[test]
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
        assert_eq!(
            std::fs::read(manager.artifact_store_root.join(&final_ref)).unwrap(),
            b"partial"
        );

        manager.artifact_store_dir.remove_file(&final_ref).unwrap();
        let pending_ref = format!("blobs/pending/{digest}-interrupted");
        manager
            .artifact_store_dir
            .write(&pending_ref, bytes)
            .unwrap();
        let report = manager.reconcile_artifacts_startup().unwrap();
        assert!(report.findings.iter().any(|finding| {
            finding.kind == ArtifactReconciliationKind::BlobOrphaned
                && finding.content_hash.as_deref() == Some(hash.as_str())
        }));
        assert_eq!(
            std::fs::read(manager.artifact_store_root.join(final_ref)).unwrap(),
            bytes
        );
        assert!(!manager.artifact_store_root.join(pending_ref).exists());
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
        manager.allocate_artifact_output(&request).unwrap();
        let mut unopened = request.clone();
        unopened.allocation_id = "alloc-stale-unopened".to_owned();
        manager.allocate_artifact_output(&unopened).unwrap();
        write_output(&mut manager, "alloc-stale", b"stale");
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
        let result = manager
            .publish_artifact_output(&publication("pub-stale", "alloc-stale"))
            .unwrap();
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
    }

    #[test]
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
        assert!(matches!(
            TaskManager::open_with_clock(&alias, Box::new(FixedClock)),
            Err(TaskManagerError::InvalidRecord(
                "Artifact store root identity does not match its database binding"
            ))
        ));
    }
}
