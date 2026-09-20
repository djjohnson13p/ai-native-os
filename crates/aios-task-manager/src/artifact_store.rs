//! Local immutable Artifact storage owned by the authoritative Task Manager.

#![allow(
    clippy::missing_errors_doc,
    reason = "the crate-level public DTO/API documentation is tracked with the daemon integration"
)]

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::{
    Actor, Result, SCHEMA_VERSION, StoreLock, TaskManager, TaskManagerError, append_event,
    assert_manager_lease, canonical_json,
};

const IMPORT_LIMIT: u64 = 8 * 1024 * 1024 * 1024;
const COPY_BUFFER_SIZE: usize = 64 * 1024;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportArtifactRequest {
    pub schema_version: String,
    pub task_id: String,
    pub actor: Actor,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactReadScope {
    scope_id: String,
    task_id: String,
    binding_id: Option<String>,
    artifact_ids: BTreeSet<String>,
}

impl ArtifactReadScope {
    pub fn scope_id(&self) -> &str {
        &self.scope_id
    }

    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    pub fn binding_id(&self) -> Option<&str> {
        self.binding_id.as_deref()
    }
}

pub struct ArtifactReader {
    file: File,
    handle: ArtifactHandle,
}

impl ArtifactReader {
    pub fn handle(&self) -> &ArtifactHandle {
        &self.handle
    }
}

impl Read for ArtifactReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buffer)
    }
}

impl Seek for ArtifactReader {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        self.file.seek(position)
    }
}

pub struct ArtifactStagingWriter {
    file: Option<File>,
    allocation_id: String,
    maximum: u64,
    written: u64,
}

impl ArtifactStagingWriter {
    pub fn allocation_id(&self) -> &str {
        &self.allocation_id
    }

    pub fn bytes_written(&self) -> u64 {
        self.written
    }

    pub fn finish(mut self) -> Result<u64> {
        let mut file = self.file.take().ok_or(TaskManagerError::InvalidRecord(
            "Artifact staging writer is already finalized",
        ))?;
        file.flush()?;
        file.sync_all()?;
        Ok(self.written)
    }
}

impl Write for ArtifactStagingWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
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
) -> Result<PathBuf> {
    let root = if let Some(lock) = store_lock {
        let file_name = lock
            .identity
            .canonical_path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(TaskManagerError::InvalidRecord(
                "Task store path has no portable file name",
            ))?;
        lock.identity
            .canonical_path
            .with_file_name(format!("{file_name}.artifacts"))
    } else {
        let token = random_token(connection)?;
        std::env::temp_dir().join(format!("aios-task-manager-{token}"))
    };
    std::fs::create_dir_all(root.join("blobs").join("sha256"))?;
    std::fs::create_dir_all(root.join("staging"))?;
    std::fs::create_dir_all(root.join("quarantine"))?;
    Ok(root.canonicalize()?)
}

impl TaskManager {
    pub fn import_artifact<R: Read>(
        &mut self,
        request: &ImportArtifactRequest,
        reader: &mut R,
    ) -> Result<ArtifactHandle> {
        validate_import_request(request)?;
        let principal = self
            .connection
            .query_row(
                "SELECT principal_kind,principal_id FROM tasks WHERE task_id=?1",
                [&request.task_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
            .ok_or(TaskManagerError::InvalidRecord(
                "Artifact import Task does not exist",
            ))?;
        if request.actor.kind == "user"
            && (principal.0 != request.actor.kind || principal.1 != request.actor.id)
        {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        let token = random_token(&self.connection)?;
        let staging_ref = format!("staging/import-{token}");
        let staging_path = resolve_internal_ref(&self.artifact_store_root, &staging_ref)?;
        let maximum = request
            .max_size_bytes
            .unwrap_or(IMPORT_LIMIT)
            .min(IMPORT_LIMIT);
        let (size, content_hash) = stream_into_new_file(reader, &staging_path, maximum)?;
        let (storage_ref, reused) = place_blob(
            &self.artifact_store_root,
            &staging_path,
            &content_hash,
            size,
            false,
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
            "actor": request.actor,
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
        let task_exists = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM tasks WHERE task_id=?1)",
            [&request.task_id],
            |row| row.get::<_, bool>(0),
        )?;
        if !task_exists {
            return Err(TaskManagerError::InvalidRecord(
                "Artifact allocation Task does not exist",
            ));
        }
        if let (Some(binding_id), Some(attempt_id)) =
            (request.binding_id.as_deref(), request.attempt_id.as_deref())
        {
            let exact = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM execution_bindings b JOIN step_executions s ON s.binding_id=b.binding_id AND s.attempt_id=b.attempt_id AND s.task_id=b.task_id AND s.semantic_program_hash=b.semantic_program_hash AND s.node_id=b.node_id WHERE b.binding_id=?1 AND b.attempt_id=?2 AND b.task_id=?3 AND b.semantic_program_hash=?4 AND b.node_id=?5)",
                params![binding_id,attempt_id,request.task_id,request.semantic_program_hash,request.node_id],
                |row| row.get::<_, bool>(0),
            )?;
            if !exact {
                return Err(TaskManagerError::InvalidRecord(
                    "Artifact allocation does not match its immutable attempt/binding",
                ));
            }
        }
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

    pub fn open_artifact_output(&mut self, allocation_id: &str) -> Result<ArtifactStagingWriter> {
        validate_id(allocation_id, 256, "invalid Artifact allocation ID")?;
        let lease_owner = self.lease_owner.clone();
        let lease_epoch = self.lease_epoch;
        let now = self.clock.now();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_manager_lease(&transaction, &lease_owner, lease_epoch)?;
        let row = transaction
            .query_row(
                "SELECT state,staging_ref,max_size_bytes,expires_at FROM artifact_output_allocations WHERE allocation_id=?1",
                [allocation_id],
                |row| Ok((row.get::<_,String>(0)?,row.get::<_,Option<String>>(1)?,row.get::<_,Option<i64>>(2)?,row.get::<_,String>(3)?)),
            )
            .optional()?;
        let Some((state, Some(staging_ref), maximum, expires_at)) = row else {
            return Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_ALLOCATION_NOT_FOUND",
            ));
        };
        if state != "ALLOCATED" {
            return Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_ALLOCATION_STATE_CONFLICT",
            ));
        }
        if parse_time(&expires_at)? <= parse_time(&now)? {
            transaction.execute(
                "UPDATE artifact_output_allocations SET state='EXPIRED',updated_at=?2 WHERE allocation_id=?1",
                params![allocation_id,now],
            )?;
            transaction.commit()?;
            return Err(TaskManagerError::InvalidRecord(
                "ARTIFACT_ALLOCATION_EXPIRED",
            ));
        }
        let path = resolve_internal_ref(&self.artifact_store_root, &staging_ref)?;
        let file = OpenOptions::new().write(true).create_new(true).open(path)?;
        transaction.execute(
            "UPDATE artifact_output_allocations SET state='WRITING',updated_at=?2 WHERE allocation_id=?1 AND state='ALLOCATED'",
            params![allocation_id,now],
        )?;
        transaction.commit()?;
        Ok(ArtifactStagingWriter {
            file: Some(file),
            allocation_id: allocation_id.to_owned(),
            maximum: maximum.map_or(IMPORT_LIMIT, |value| u64::try_from(value).unwrap_or(0)),
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
                let result: ArtifactPublicationResult = serde_json::from_str(
                    result_json.as_deref().ok_or(TaskManagerError::InvalidRecord(
                        "committed Artifact publication has no result",
                    ))?,
                )?;
                if let Some(current_hash) = self.staged_content_hash(&request.allocation_id)? {
                    if stored_hash.as_deref() != Some(current_hash.as_str()) {
                        return Ok(publication_conflict(request, self.clock.now()));
                    }
                }
                return Ok(result);
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
        let staging_path = resolve_internal_ref(&self.artifact_store_root, staging_ref)?;
        let (size, content_hash) = hash_file(&staging_path)?;
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
            &self.artifact_store_root,
            &staging_path,
            &content_hash,
            size,
            true,
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
        let _ = std::fs::remove_file(staging_path);
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
        for artifact_id in artifact_ids {
            let authorized = if let Some(binding_id) = binding_id {
                self.connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM step_executions s WHERE s.task_id=?1 AND s.binding_id=?2 AND EXISTS(SELECT 1 FROM json_each(s.input_artifacts_json) WHERE value=?3) AND EXISTS(SELECT 1 FROM task_artifacts t WHERE t.task_id=s.task_id AND t.artifact_id=?3))",
                    params![task_id,binding_id,artifact_id],
                    |row| row.get::<_,bool>(0),
                )?
            } else {
                self.connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM task_artifacts WHERE task_id=?1 AND artifact_id=?2)",
                    params![task_id,artifact_id],
                    |row| row.get::<_,bool>(0),
                )?
            };
            if !authorized {
                return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
            }
        }
        Ok(ArtifactReadScope {
            scope_id: format!("artifact-read-scope:{}", random_token(&self.connection)?),
            task_id: task_id.to_owned(),
            binding_id: binding_id.map(ToOwned::to_owned),
            artifact_ids: artifact_ids.iter().cloned().collect(),
        })
    }

    pub fn open_artifact_reader(
        &mut self,
        scope: &ArtifactReadScope,
        artifact_id: &str,
    ) -> Result<ArtifactReader> {
        if !scope.artifact_ids.contains(artifact_id) {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"));
        }
        let handle = self
            .get_artifact(artifact_id)?
            .ok_or(TaskManagerError::InvalidRecord("ARTIFACT_NOT_FOUND"))?;
        let storage_ref = self.connection.query_row(
            "SELECT b.storage_ref FROM artifacts a JOIN artifact_blobs b ON b.content_hash=a.content_hash WHERE a.artifact_id=?1",
            [artifact_id],
            |row| row.get::<_,String>(0),
        )?;
        let path = resolve_internal_ref(&self.artifact_store_root, &storage_ref)?;
        let verified = hash_file(&path);
        let expected_hash = handle.content_hash.tagged();
        match verified {
            Ok((size, hash)) if size == handle.size_bytes && hash == expected_hash => {
                let now = self.clock.now();
                let lease_owner = self.lease_owner.clone();
                let lease_epoch = self.lease_epoch;
                let transaction = self
                    .connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)?;
                assert_manager_lease(&transaction, &lease_owner, lease_epoch)?;
                transaction.execute("UPDATE artifacts SET integrity_state='verified',integrity_verified_at=?2,integrity_verifier='artifact-store:sha256' WHERE artifact_id=?1",params![artifact_id,now])?;
                transaction.execute("UPDATE artifact_blobs SET durability_state='DURABLE',verified_at=?2 WHERE content_hash=?1",params![expected_hash,now])?;
                transaction.commit()?;
            }
            _ => {
                self.mark_integrity_failed(artifact_id, &scope.task_id, &expected_hash)?;
                return Err(TaskManagerError::InvalidRecord("ARTIFACT_INTEGRITY_FAILED"));
            }
        }
        Ok(ArtifactReader {
            file: File::open(path)?,
            handle: self
                .get_artifact(artifact_id)?
                .ok_or(TaskManagerError::InvalidRecord(
                    "verified Artifact disappeared",
                ))?,
        })
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
            let path = resolve_internal_ref(&self.artifact_store_root, &storage_ref)?;
            let status = match hash_file(&path) {
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
        for path in physical_blob_paths(&self.artifact_store_root)? {
            let relative = internal_relative_ref(&self.artifact_store_root, &path)?;
            if known_refs.contains(&relative) {
                continue;
            }
            let (size, hash) = hash_file(&path)?;
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
        for entry in std::fs::read_dir(self.artifact_store_root.join("staging"))? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let staging_ref = internal_relative_ref(&self.artifact_store_root, &entry.path())?;
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

    fn staged_content_hash(&self, allocation_id: &str) -> Result<Option<String>> {
        let staging_ref = self
            .connection
            .query_row(
                "SELECT staging_ref FROM artifact_output_allocations WHERE allocation_id=?1",
                [allocation_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        let Some(staging_ref) = staging_ref else {
            return Ok(None);
        };
        let path = resolve_internal_ref(&self.artifact_store_root, &staging_ref)?;
        if !path.is_file() {
            return Ok(None);
        }
        hash_file(&path).map(|(_, hash)| Some(hash))
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

#[derive(Debug)]
struct AllocationRow {
    task_id: String,
    semantic_program_hash: String,
    node_id: String,
    binding_id: Option<String>,
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
    let row=connection.query_row("SELECT task_id,semantic_program_hash,node_id,binding_id,expected_semantic_type,allowed_media_types_json,max_size_bytes,sensitivity,retention,state,staging_ref,expires_at FROM artifact_output_allocations WHERE allocation_id=?1",[allocation_id],|row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,Option<String>>(3)?,row.get::<_,Option<String>>(4)?,row.get::<_,Option<String>>(5)?,row.get::<_,Option<i64>>(6)?,row.get::<_,String>(7)?,row.get::<_,String>(8)?,row.get::<_,String>(9)?,row.get::<_,Option<String>>(10)?,row.get::<_,String>(11)?))).optional()?;
    row.map(|row| {
        Ok(AllocationRow {
            task_id: row.0,
            semantic_program_hash: row.1,
            node_id: row.2,
            binding_id: row.3,
            expected_semantic_type: row.4,
            allowed_media_types: row
                .5
                .map(|value| serde_json::from_str(&value))
                .transpose()?
                .unwrap_or_default(),
            max_size_bytes: row
                .6
                .map(|value| {
                    u64::try_from(value).map_err(|_| {
                        TaskManagerError::InvalidRecord("negative Artifact size limit")
                    })
                })
                .transpose()?,
            sensitivity: row.7,
            retention: row.8,
            state: row.9,
            staging_ref: row.10,
            expires_at: row.11,
        })
    })
    .transpose()
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
        || !matches!(
            request.actor.kind.as_str(),
            "user" | "system-service" | "legacy-app"
        )
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
    root: &Path,
    staging: &Path,
    content_hash: &str,
    size: u64,
    preserve_staging: bool,
) -> Result<(String, bool)> {
    validate_hash(content_hash)?;
    let digest = content_hash.strip_prefix("sha256:").unwrap_or_default();
    let storage_ref = format!(
        "blobs/sha256/{}/{}/{}",
        &digest[0..2],
        &digest[2..4],
        digest
    );
    let destination = resolve_internal_ref(root, &storage_ref)?;
    let parent = destination.parent().ok_or(TaskManagerError::InvalidRecord(
        "Artifact blob has no parent",
    ))?;
    std::fs::create_dir_all(parent)?;
    let reused = if destination.exists() {
        let (existing_size, existing_hash) = hash_file(&destination)?;
        if existing_size != size || existing_hash != content_hash {
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_HASH_MISMATCH"));
        }
        if !preserve_staging {
            std::fs::remove_file(staging)?;
        }
        true
    } else {
        if preserve_staging {
            let mut source = File::open(staging)?;
            let mut blob = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&destination)?;
            std::io::copy(&mut source, &mut blob)?;
            blob.flush()?;
            blob.sync_all()?;
        } else {
            std::fs::rename(staging, &destination)?;
        }
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&destination)?
            .sync_all()?;
        sync_directory(parent)?;
        false
    };
    Ok((storage_ref, reused))
}

fn stream_into_new_file<R: Read>(
    reader: &mut R,
    path: &Path,
    maximum: u64,
) -> Result<(u64, String)> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
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
            drop(file);
            let _ = std::fs::remove_file(path);
            return Err(TaskManagerError::InvalidRecord("ARTIFACT_SIZE_LIMIT"));
        }
        file.write_all(&buffer[..count])?;
        hasher.update(&buffer[..count]);
    }
    file.flush()?;
    file.sync_all()?;
    Ok((size, tagged_digest(hasher)))
}

fn hash_file(path: &Path) -> Result<(u64, String)> {
    let mut file = File::open(path)?;
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

fn physical_blob_paths(root: &Path) -> Result<Vec<PathBuf>> {
    let base = root.join("blobs").join("sha256");
    let mut paths = Vec::new();
    for first in std::fs::read_dir(base)? {
        let first = first?;
        if !first.file_type()?.is_dir() {
            continue;
        }
        for second in std::fs::read_dir(first.path())? {
            let second = second?;
            if !second.file_type()?.is_dir() {
                continue;
            }
            for blob in std::fs::read_dir(second.path())? {
                let blob = blob?;
                if blob.file_type()?.is_file() {
                    paths.push(blob.path());
                }
            }
        }
    }
    paths.sort();
    Ok(paths)
}

fn internal_relative_ref(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| TaskManagerError::InvalidRecord("Artifact path escaped store root"))?;
    let parts = relative
        .components()
        .map(|component| match component {
            Component::Normal(value) => {
                value
                    .to_str()
                    .map(ToOwned::to_owned)
                    .ok_or(TaskManagerError::InvalidRecord(
                        "Artifact path is not UTF-8",
                    ))
            }
            _ => Err(TaskManagerError::InvalidRecord(
                "Artifact path is not a safe relative reference",
            )),
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(parts.join("/"))
}

fn resolve_internal_ref(root: &Path, reference: &str) -> Result<PathBuf> {
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
    Ok(root.join(relative))
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

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "keeps the platform-specific durability helper signature uniform"
)]
fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read as _, Write as _};

    use tempfile::TempDir;

    use super::*;
    use crate::{Actor, Clock, CreateTask};

    struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> String {
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
            actor: Actor {
                kind: "user".to_owned(),
                id: "user:test".to_owned(),
            },
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
            .scope_artifact_reads("T-artifact", None, &[first.artifact_id.clone()])
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
        let staging = manager.artifact_store_root.join("staging/manual-crash");
        let (size, hash) =
            stream_into_new_file(&mut Cursor::new(b"orphan".as_slice()), &staging, 1_024).unwrap();
        place_blob(&manager.artifact_store_root, &staging, &hash, size, false).unwrap();
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
            &manager.artifact_store_root,
            &staging_path,
            &hash,
            size,
            true,
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
            .scope_artifact_reads("T-artifact", None, &[artifact_id.clone()])
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
            manager.scope_artifact_reads("T-other", None, &[artifact.artifact_id]),
            Err(TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED"))
        ));
    }
}
