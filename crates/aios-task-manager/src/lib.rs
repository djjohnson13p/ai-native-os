//! Durable local Task state, CAS transitions, and transition provenance.

#![allow(
    missing_docs,
    reason = "public DTO fields mirror the v0.1 machine contracts"
)]
#![cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "privileged mutation entry points stay crate-private until the daemon integration owns them"
    )
)]

mod artifact_store;
mod authority_candidate;
mod authority_policy;
mod trusted_time;

pub use aios_provenance::{
    CheckpointExpectation as ProvenanceCheckpointExpectation,
    JournalRecord as ProvenanceJournalRecord, ProjectionPortableExport as ProvenancePortableExport,
    RecordPage as ProvenanceRecordPage, StreamHead as ProvenanceStreamHead,
    VerificationResult as ProvenanceVerificationResult,
};
pub use artifact_store::{
    ArtifactAllocationState, ArtifactExpectedState, ArtifactExportDestination,
    ArtifactExportOutcomeVerifier, ArtifactExportReconciliationSubject, ArtifactExportWriter,
    ArtifactHandle, ArtifactIntegrity, ArtifactIntegrityState, ArtifactLineage, ArtifactOrigin,
    ArtifactOriginKind, ArtifactOutputAllocation, ArtifactPublicationRequest,
    ArtifactPublicationResult, ArtifactReadScope, ArtifactReader, ArtifactReconciliationFinding,
    ArtifactReconciliationKind, ArtifactReconciliationReport, ArtifactRetention,
    ArtifactStagingWriter, ArtifactUri, ContentHash, ImportArtifactRequest,
    OutputAllocationRequest, ProviderArtifactSession, RetentionClass, Sensitivity,
    VerifiedArtifactExportNoEffect,
};
pub use trusted_time::{SecurityClockSample, TimeSource};

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use aios_registry::{StoreIdentity, StoreLock, StoreOwner, store_identity};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const SCHEMA_VERSION: &str = "0.1";
const MIGRATION: &str = include_str!("../../../specs/persistence-v0.1.sql");

#[derive(Debug)]
pub enum TaskManagerError {
    Storage(rusqlite::Error),
    Io(std::io::Error),
    Serialization(serde_json::Error),
    Canonicalization(String),
    Provenance(aios_provenance::Error),
    Registry(aios_registry::RegistryStoreError),
    Provider(aios_registry::ProviderStoreError),
    InvalidRecord(&'static str),
}

impl fmt::Display for TaskManagerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(formatter, "task storage failure: {error}"),
            Self::Io(error) => write!(formatter, "task store I/O failure: {error}"),
            Self::Serialization(error) => write!(formatter, "task serialization failure: {error}"),
            Self::Canonicalization(error) => {
                write!(formatter, "provenance canonicalization failure: {error}")
            }
            Self::Provenance(error) => write!(formatter, "{error}"),
            Self::Registry(error) => write!(formatter, "{error}"),
            Self::Provider(error) => write!(formatter, "{error}"),
            Self::InvalidRecord(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for TaskManagerError {}

impl From<rusqlite::Error> for TaskManagerError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage(error)
    }
}

impl From<std::io::Error> for TaskManagerError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for TaskManagerError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialization(error)
    }
}

impl From<aios_provenance::Error> for TaskManagerError {
    fn from(error: aios_provenance::Error) -> Self {
        Self::Provenance(error)
    }
}

impl From<aios_registry::RegistryStoreError> for TaskManagerError {
    fn from(error: aios_registry::RegistryStoreError) -> Self {
        Self::Registry(error)
    }
}

impl From<aios_registry::ProviderStoreError> for TaskManagerError {
    fn from(error: aios_registry::ProviderStoreError) -> Self {
        Self::Provider(error)
    }
}

pub type Result<T> = std::result::Result<T, TaskManagerError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaskState {
    Created,
    Planning,
    WaitingForInput,
    WaitingForAuth,
    Runnable,
    Running,
    Verifying,
    Paused,
    Recovering,
    RollingBack,
    Completed,
    Failed,
    Cancelled,
    RolledBack,
}

impl TaskState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Created => "CREATED",
            Self::Planning => "PLANNING",
            Self::WaitingForInput => "WAITING_FOR_INPUT",
            Self::WaitingForAuth => "WAITING_FOR_AUTH",
            Self::Runnable => "RUNNABLE",
            Self::Running => "RUNNING",
            Self::Verifying => "VERIFYING",
            Self::Paused => "PAUSED",
            Self::Recovering => "RECOVERING",
            Self::RollingBack => "ROLLING_BACK",
            Self::Completed => "COMPLETED",
            Self::Failed => "FAILED",
            Self::Cancelled => "CANCELLED",
            Self::RolledBack => "ROLLED_BACK",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "CREATED" => Ok(Self::Created),
            "PLANNING" => Ok(Self::Planning),
            "WAITING_FOR_INPUT" => Ok(Self::WaitingForInput),
            "WAITING_FOR_AUTH" => Ok(Self::WaitingForAuth),
            "RUNNABLE" => Ok(Self::Runnable),
            "RUNNING" => Ok(Self::Running),
            "VERIFYING" => Ok(Self::Verifying),
            "PAUSED" => Ok(Self::Paused),
            "RECOVERING" => Ok(Self::Recovering),
            "ROLLING_BACK" => Ok(Self::RollingBack),
            "COMPLETED" => Ok(Self::Completed),
            "FAILED" => Ok(Self::Failed),
            "CANCELLED" => Ok(Self::Cancelled),
            "ROLLED_BACK" => Ok(Self::RolledBack),
            _ => Err(TaskManagerError::InvalidRecord(
                "stored Task state is invalid",
            )),
        }
    }

    fn terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::RolledBack
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Actor {
    pub kind: String,
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionReason {
    pub code: String,
    pub message: Option<String>,
    #[serde(default)]
    pub related_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WaitingKind {
    Input,
    Approval,
    Resource,
    Provider,
    Validation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WaitingOn {
    pub kind: WaitingKind,
    pub id: String,
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivePlan {
    pub plan_id: String,
    pub revision: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryMutation {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unknown_operation_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unknown_operations_ref: Option<String>,
    pub last_known_daemon_instance: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent fields intentionally mirror task-record.schema.json"
)]
pub struct FailureRecord {
    pub code: String,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_binding_id: Option<String>,
    pub retryable: bool,
    pub safe_to_replan: bool,
    pub unknown_side_effects: bool,
    pub rollback_available: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance_event_ids: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskMutation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_plan: Option<ActivePlan>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_step_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub waiting_on: Option<Vec<WaitingOn>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<FailureRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery: Option<RecoveryMutation>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionRequest {
    pub schema_version: String,
    pub transition_id: String,
    pub task_id: String,
    pub expected_revision: u64,
    pub expected_state: TaskState,
    pub to_state: TaskState,
    pub requested_by: Actor,
    pub reason: TransitionReason,
    #[serde(default)]
    pub mutation: TaskMutation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransitionResult {
    pub schema_version: String,
    pub transition_id: String,
    pub task_id: String,
    pub applied: bool,
    pub reason_code: String,
    pub message: Option<String>,
    pub previous_state: Option<TaskState>,
    pub current_state: Option<TaskState>,
    pub previous_revision: Option<u64>,
    pub current_revision: Option<u64>,
    pub observed_state: Option<TaskState>,
    pub observed_revision: Option<u64>,
    pub provenance_event_id: Option<String>,
    pub provenance_event_hash: Option<String>,
    pub resulted_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CreateTask {
    pub task_id: String,
    pub principal: Actor,
    pub workspace_id: Option<String>,
    pub original_intent: String,
    pub normalized_intent: Option<Value>,
    #[serde(default)]
    pub active_step_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskRecord {
    pub schema_version: String,
    pub task_id: String,
    pub revision: u64,
    pub state: TaskState,
    pub state_reason: Option<Value>,
    pub principal: Actor,
    pub workspace_id: Option<String>,
    pub original_intent: String,
    pub normalized_intent: Option<Value>,
    pub input_artifacts: Vec<String>,
    pub output_artifacts: Vec<String>,
    pub active_plan: Option<ActivePlan>,
    pub active_program: Option<Value>,
    pub active_step_ids: Vec<String>,
    pub active_execution_binding_ids: Vec<String>,
    pub waiting_on: Vec<WaitingOn>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Value>,
    pub failure: Option<FailureRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery: Option<Value>,
    pub created_at: String,
    pub updated_at: String,
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StepState {
    Pending,
    Blocked,
    Ready,
    Starting,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    Skipped,
    Unknown,
}

impl StepState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Blocked => "BLOCKED",
            Self::Ready => "READY",
            Self::Starting => "STARTING",
            Self::Running => "RUNNING",
            Self::Succeeded => "SUCCEEDED",
            Self::Failed => "FAILED",
            Self::Cancelled => "CANCELLED",
            Self::Skipped => "SKIPPED",
            Self::Unknown => "UNKNOWN",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        serde_json::from_value(Value::String(value.to_owned())).map_err(Into::into)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OutcomeCertainty {
    NotStarted,
    StartedNoEffect,
    Completed,
    FailedNoEffect,
    FailedPartialEffect,
    OutcomeUnknown,
}

impl OutcomeCertainty {
    fn as_str(self) -> &'static str {
        match self {
            Self::NotStarted => "NOT_STARTED",
            Self::StartedNoEffect => "STARTED_NO_EFFECT",
            Self::Completed => "COMPLETED",
            Self::FailedNoEffect => "FAILED_NO_EFFECT",
            Self::FailedPartialEffect => "FAILED_PARTIAL_EFFECT",
            Self::OutcomeUnknown => "OUTCOME_UNKNOWN",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        serde_json::from_value(Value::String(value.to_owned())).map_err(Into::into)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepFailure {
    pub code: String,
    pub summary: String,
    pub retryable: bool,
    pub safe_to_rebind: bool,
    pub unknown_side_effects: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateStepExecution {
    pub attempt_id: String,
    pub task_id: String,
    pub semantic_program_hash: String,
    pub registry_snapshot_id: Option<String>,
    pub node_id: String,
    pub binding_id: Option<String>,
    pub provider_id: Option<String>,
    pub provider_version: Option<String>,
    pub attempt_number: u16,
    pub state: StepState,
    pub operation_id: Option<String>,
    pub idempotency_key: Option<String>,
    pub outcome_certainty: Option<OutcomeCertainty>,
    #[serde(default)]
    pub input_artifacts: Vec<String>,
    #[serde(default)]
    pub output_artifacts: Vec<String>,
    pub failure: Option<StepFailure>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepExecutionRecord {
    pub schema_version: String,
    pub attempt_id: String,
    pub task_id: String,
    pub semantic_program_hash: String,
    pub registry_snapshot_id: Option<String>,
    pub node_id: String,
    pub binding_id: Option<String>,
    pub provider_id: Option<String>,
    pub provider_version: Option<String>,
    pub attempt_number: u16,
    pub revision: u64,
    pub state: StepState,
    pub operation_id: Option<String>,
    pub idempotency_key: Option<String>,
    pub outcome_certainty: Option<OutcomeCertainty>,
    pub input_artifacts: Vec<String>,
    pub output_artifacts: Vec<String>,
    pub failure: Option<StepFailure>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

pub struct TaskManager {
    connection: Connection,
    clock: Arc<dyn Clock>,
    lease_owner: String,
    lease_epoch: i64,
    artifact_scope_issuer: String,
    database_locator: DatabaseLocator,
    artifact_store_root: PathBuf,
    artifact_store_dir: cap_std::fs::Dir,
    store_lock: Option<Arc<StoreLock>>,
    store_owner: StoreOwner,
    artifact_store_cleanup: Option<Arc<artifact_store::EphemeralStoreCleanup>>,
    artifact_export_verifiers:
        BTreeMap<String, Arc<dyn artifact_store::ArtifactExportOutcomeVerifier>>,
    /// Reader admissions returned by this live process but not yet durably marked delivered.
    /// Persisted pending admissions can be rehydrated after process loss without allowing two
    /// simultaneous handles in one manager lifetime.
    delivered_reader_admissions: Arc<Mutex<BTreeSet<String>>>,
}

pub trait Clock: Send + Sync {
    fn now(&self) -> String;

    /// Security sample used for expiry decisions; unavailable samples fail closed.
    fn security_sample(&self) -> Option<trusted_time::SecurityClockSample> {
        None
    }
}

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> String {
        OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
    }

    fn security_sample(&self) -> Option<trusted_time::SecurityClockSample> {
        static START: OnceLock<std::time::Instant> = OnceLock::new();
        let elapsed = START.get_or_init(std::time::Instant::now).elapsed();
        Some(trusted_time::SecurityClockSample {
            wall: OffsetDateTime::now_utc().format(&Rfc3339).ok()?,
            monotonic_nanos: u64::try_from(elapsed.as_nanos()).ok()?,
            source: trusted_time::TimeSource::SystemClock,
        })
    }
}

#[derive(Clone)]
enum DatabaseLocator {
    File(PathBuf),
    SharedMemory(String),
}

impl DatabaseLocator {
    fn open(&self) -> rusqlite::Result<Connection> {
        match self {
            Self::File(path) => Connection::open(path),
            Self::SharedMemory(uri) => Connection::open_with_flags(
                uri,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                    | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
                    | rusqlite::OpenFlags::SQLITE_OPEN_URI,
            ),
        }
    }
}

fn acquire_store_lock(path: &Path) -> Result<StoreLock> {
    StoreLock::acquire(path).map_err(Into::into)
}

fn verify_locked_store_identity(connection: &Connection, lock: &StoreLock) -> Result<()> {
    lock.verify_connection(connection).map_err(Into::into)
}

fn open_locked_store<F>(
    path: &Path,
    clock: Box<dyn Clock>,
    export_verifiers: Vec<Arc<dyn artifact_store::ArtifactExportOutcomeVerifier>>,
    after_lock: F,
) -> Result<TaskManager>
where
    F: FnOnce(&Path),
{
    let lock = Arc::new(acquire_store_lock(path)?);
    after_lock(path);
    let connection = Connection::open(path)?;
    verify_locked_store_identity(&connection, &lock)?;
    TaskManager::initialize(
        connection,
        clock,
        Some(lock),
        DatabaseLocator::File(path.to_path_buf()),
        export_verifiers,
    )
}

/// Explicit trusted offline upgrade for the historical Windows creation-time Artifact-store
/// binding. Ordinary open deliberately refuses that spoofable identity format.
#[cfg(windows)]
pub(crate) fn rebind_legacy_windows_artifact_store(path: &Path) -> Result<()> {
    let lock = acquire_store_lock(path)?;
    let mut connection = Connection::open(path)?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    verify_locked_store_identity(&connection, &lock)?;
    preflight_migration_state(&connection)?;
    artifact_store::rebind_legacy_windows_root(&lock, &mut connection)
}

fn assert_manager_lease(transaction: &Transaction<'_>, owner: &str, epoch: i64) -> Result<()> {
    let current = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM task_manager_lease WHERE singleton_id = 1 AND owner_id = ?1 AND fence_epoch = ?2)",
        params![owner, epoch],
        |row| row.get::<_, bool>(0),
    )?;
    if !current {
        return Err(TaskManagerError::InvalidRecord(
            "Task Manager write rejected by stale ownership fence",
        ));
    }
    Ok(())
}

impl TaskManager {
    /// Opens a semantic registry writer under this manager's live store lock
    /// and durable lease. The required optional schema is installed first.
    ///
    /// # Errors
    /// Returns an error if migration, store identity, or the lease fails.
    pub fn registry_store_writer(&mut self) -> Result<aios_registry::RegistryStore<'_>> {
        self.initialize_registry_store()?;
        Ok(aios_registry::RegistryStore::initialize_writer(
            &mut self.connection,
            &self.store_owner,
        )?)
    }

    /// Opens a provider writer under this manager's live store lock and lease.
    /// The required optional schemas are installed first.
    ///
    /// # Errors
    /// Returns an error if migration, store identity, or the lease fails.
    pub fn provider_store_writer(&mut self) -> Result<aios_registry::ProviderStore<'_>> {
        self.initialize_provider_store()?;
        Ok(aios_registry::ProviderStore::initialize_writer(
            &mut self.connection,
            &self.store_owner,
        )?)
    }

    /// Installs or upgrades the optional semantic registry schema while this
    /// manager owns the identity-bound store lock and current durable lease.
    ///
    /// # Errors
    /// Returns an error if migration preflight, store identity, or the lease fails.
    pub fn initialize_registry_store(&mut self) -> Result<()> {
        self.migrate_registry_schema(false)
    }

    /// Installs or upgrades both registry schemas under the same store fence.
    ///
    /// # Errors
    /// Returns an error if migration preflight, store identity, or the lease fails.
    pub fn initialize_provider_store(&mut self) -> Result<()> {
        self.migrate_registry_schema(true)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "keeps the fenced optional-schema migration atomic"
    )]
    fn migrate_registry_schema(&mut self, provider: bool) -> Result<()> {
        if let Some(lock) = &self.store_lock {
            verify_locked_store_identity(&self.connection, lock)?;
        }
        preflight_migration_state(&self.connection)?;
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        assert_manager_lease(&transaction, &self.lease_owner, self.lease_epoch)?;
        // CREATE IF NOT EXISTS must never bless unversioned lookalike tables.
        for (migration, objects, legacy_guards, additive_guards) in [
            (
                "0012_semantic_registry_store",
                "'semantic_type_contracts','semantic_capability_contracts',
                 'registry_snapshot_admissions','registry_snapshot_entries','registry_activations'",
                SEMANTIC_LEGACY_GUARDS,
                SEMANTIC_ADDITIVE_GUARDS,
            ),
            (
                "0013_provider_registry",
                "'provider_manifest_payloads','provider_health_observations',
                 'ix_provider_conformance_latest','execution_binding_admission_markers',
                 'provider_state_epochs','execution_binding_enablement_markers'",
                PROVIDER_LEGACY_GUARDS,
                PROVIDER_ADDITIVE_GUARDS,
            ),
            (
                "0014_semantic_repair_fence",
                "'semantic_repair_fences','semantic_snapshot_reattestations'",
                &[],
                SEMANTIC_FENCE_GUARDS,
            ),
        ] {
            let stamped: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE migration_id=?1)",
                [migration],
                |row| row.get(0),
            )?;
            if !stamped {
                let present: bool = transaction.query_row(
                    &format!(
                        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name IN ({objects}))"
                    ),
                    [],
                    |row| row.get(0),
                )?;
                if present {
                    return Err(TaskManagerError::InvalidRecord(
                        "unstamped registry schema objects require operator quarantine",
                    ));
                }
                for guard in legacy_guards.iter().chain(additive_guards) {
                    let present: bool = transaction.query_row(
                        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='trigger' AND name=?1)",
                        [guard],
                        |row| row.get(0),
                    )?;
                    if present {
                        return Err(TaskManagerError::InvalidRecord(
                            "unstamped registry schema objects require operator quarantine",
                        ));
                    }
                }
            }
        }
        transaction.execute_batch(include_str!(
            "../../../specs/persistence-v0.1-0012-semantic-registry.sql"
        ))?;
        transaction.execute(
            "INSERT OR IGNORE INTO schema_migrations(migration_id,checksum,applied_at) VALUES ('0012_semantic_registry_store','semantic-registry-store-v0.1',strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
            [],
        )?;
        transaction.execute_batch(include_str!(
            "../../../specs/persistence-v0.1-0014-semantic-repair-fence.sql"
        ))?;
        transaction.execute(
            "INSERT OR IGNORE INTO schema_migrations(migration_id,checksum,applied_at) VALUES ('0014_semantic_repair_fence','semantic-repair-fence-v0.1',strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
            [],
        )?;
        if provider {
            let provider_stamped: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM schema_migrations
                 WHERE migration_id='0013_provider_registry')",
                [],
                |row| row.get(0),
            )?;
            if !provider_stamped {
                // Baseline registrations predate the enabled-interval ledger.
                // Their current 'registered' state has no provable transition
                // identity, even when this is the first 0013 installation.
                transaction.execute(
                    "UPDATE provider_registrations SET state='disabled',updated_at=?1
                     WHERE state='registered'",
                    [self.clock.now()],
                )?;
            }
            transaction.execute_batch(include_str!(
                "../../../specs/persistence-v0.1-0013-provider-registry.sql"
            ))?;
            transaction.execute(
                "INSERT OR IGNORE INTO schema_migrations(migration_id,checksum,applied_at) VALUES ('0013_provider_registry','provider-registry-v0.1',strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
                [],
            )?;
        }
        preflight_migration_state(&transaction)?;
        assert_manager_lease(&transaction, &self.lease_owner, self.lease_epoch)?;
        transaction.commit()?;
        Ok(())
    }

    /// Opens or creates the authoritative local `SQLite` store.
    ///
    /// # Errors
    /// Returns an error when `SQLite` cannot open or initialize the schema.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        open_locked_store(path, Box::new(SystemClock), Vec::new(), |_| {})
    }

    /// Opens an isolated in-memory store with the production clock.
    ///
    /// # Errors
    /// Returns an error when `SQLite` cannot initialize the schema.
    pub fn open_in_memory() -> Result<Self> {
        Self::open_shared_memory(Box::new(SystemClock))
    }

    /// Opens a store with an injected trusted clock.
    ///
    /// # Errors
    /// Returns an error when `SQLite` cannot open or initialize the schema.
    pub fn open_with_clock(path: impl AsRef<Path>, clock: Box<dyn Clock>) -> Result<Self> {
        let path = path.as_ref();
        open_locked_store(path, clock, Vec::new(), |_| {})
    }

    /// Opens a store with an immutable set of trusted destination-status adapters.
    ///
    /// The adapters are fixed for the manager lifetime. Provider-facing methods cannot add,
    /// replace, or select them when resolving an unknown export.
    ///
    /// # Errors
    /// Returns an error when the store cannot open, an adapter identity is invalid, or two
    /// adapters claim the same destination class.
    pub fn open_with_export_verifiers(
        path: impl AsRef<Path>,
        verifiers: Vec<Arc<dyn ArtifactExportOutcomeVerifier>>,
    ) -> Result<Self> {
        let path = path.as_ref();
        open_locked_store(path, Box::new(SystemClock), verifiers, |_| {})
    }

    /// Opens a store with an injected trusted clock and immutable export verifiers.
    ///
    /// # Errors
    /// Returns an error when the store or verifier registry is invalid.
    pub fn open_with_clock_and_export_verifiers(
        path: impl AsRef<Path>,
        clock: Box<dyn Clock>,
        verifiers: Vec<Arc<dyn ArtifactExportOutcomeVerifier>>,
    ) -> Result<Self> {
        let path = path.as_ref();
        open_locked_store(path, clock, verifiers, |_| {})
    }

    /// Opens an in-memory store with an injected trusted clock.
    ///
    /// # Errors
    /// Returns an error when `SQLite` cannot initialize the schema.
    pub fn open_in_memory_with_clock(clock: Box<dyn Clock>) -> Result<Self> {
        Self::open_shared_memory(clock)
    }

    fn open_shared_memory(clock: Box<dyn Clock>) -> Result<Self> {
        static NEXT_MEMORY_STORE: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(1);
        let sequence = NEXT_MEMORY_STORE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let uri = format!("file:aios-task-manager-{sequence}?mode=memory&cache=shared");
        let locator = DatabaseLocator::SharedMemory(uri.clone());
        Self::initialize(locator.open()?, clock, None, locator, Vec::new())
    }

    fn initialize(
        mut connection: Connection,
        clock: Box<dyn Clock>,
        store_lock: Option<Arc<StoreLock>>,
        database_locator: DatabaseLocator,
        export_verifiers: Vec<Arc<dyn ArtifactExportOutcomeVerifier>>,
    ) -> Result<Self> {
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        aios_registry::register_strict_json_sqlite(&connection)?;
        preflight_migration_state_allowing_guard_upgrade(&connection)?;
        let clock: Arc<dyn Clock> = Arc::from(clock);
        let acquired_at = clock.now();
        let store_owner = StoreOwner::claim(&connection, store_lock.clone(), &acquired_at)?;
        let lease_owner = store_owner.owner().to_owned();
        let lease_epoch = store_owner.epoch();
        upgrade_stamped_registry_guards_fenced(
            &mut connection,
            &lease_owner,
            lease_epoch,
            &acquired_at,
        )?;
        preflight_migration_state(&connection)?;
        connection.execute_batch(MIGRATION)?;
        migrate_task_manager_schema(&connection, &lease_owner, lease_epoch)?;
        // Assess before any recovery path can make a protected expiry decision.
        // An uncertain sample is durable but does not prevent ordinary inspection/recovery.
        trusted_time::assess(&connection, &clock)?;
        let (artifact_store_root, artifact_store_dir, artifact_store_cleanup) =
            artifact_store::initialize_root(store_lock.as_deref(), &mut connection)?;
        let artifact_scope_issuer =
            connection.query_row("SELECT lower(hex(randomblob(32)))", [], |row| row.get(0))?;
        let mut artifact_export_verifiers = BTreeMap::new();
        for verifier in export_verifiers {
            artifact_store::validate_id(
                verifier.verifier_id(),
                256,
                "invalid Artifact export reconciliation verifier",
            )?;
            artifact_store::validate_id(
                verifier.destination_class(),
                256,
                "invalid Artifact export reconciliation destination class",
            )?;
            if artifact_export_verifiers
                .insert(verifier.destination_class().to_owned(), verifier)
                .is_some()
            {
                return Err(TaskManagerError::InvalidRecord(
                    "duplicate Artifact export reconciliation destination adapter",
                ));
            }
        }
        let mut manager = Self {
            connection,
            clock,
            lease_owner,
            lease_epoch,
            artifact_scope_issuer,
            database_locator,
            artifact_store_root,
            artifact_store_dir,
            store_lock,
            store_owner,
            artifact_store_cleanup,
            artifact_export_verifiers,
            delivered_reader_admissions: Arc::new(Mutex::new(BTreeSet::new())),
        };
        manager.verify_all_provenance_chains()?;
        manager.migrate_legacy_keyed_import_receipts()?;
        manager.reconcile_export_operations_startup()?;
        manager.reconcile_artifacts_startup()?;
        manager.recover_startup()?;
        // Runtime registry writers are admitted only after the complete
        // Task Manager startup and recovery sequence has succeeded on this
        // exact connection and lease.
        manager.connection.execute_batch(
            "CREATE TEMP TABLE aios_task_manager_startup_ready (
                nonce TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                fence_epoch INTEGER NOT NULL
            );",
        )?;
        let ready = manager.connection.execute(
            "INSERT INTO temp.aios_task_manager_startup_ready(nonce,owner_id,fence_epoch)
             SELECT c.nonce,l.owner_id,l.fence_epoch
             FROM temp.aios_store_owner_capability c CROSS JOIN task_manager_lease l
             WHERE l.singleton_id=1 AND l.owner_id=?1 AND l.fence_epoch=?2",
            params![&manager.lease_owner, manager.lease_epoch],
        )?;
        if ready != 1 {
            return Err(TaskManagerError::InvalidRecord(
                "Task Manager startup lost the current ownership lease",
            ));
        }
        Ok(manager)
    }

    /// Creates a revision-1 Task and genesis event atomically.
    ///
    /// # Errors
    /// Returns an error for an invalid record or failed `SQLite` commit.
    #[allow(
        clippy::too_many_lines,
        reason = "keeps Task creation, private commitments, and genesis provenance in one transaction"
    )]
    pub(crate) fn create_task(&mut self, request: &CreateTask) -> Result<TaskRecord> {
        let unique_steps = request
            .active_step_ids
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == request.active_step_ids.len();
        if request.task_id.is_empty()
            || request.task_id.chars().count() > 256
            || request.original_intent.is_empty()
            || request.original_intent.chars().count() > 65_536
            || request.principal.id.is_empty()
            || request.principal.id.chars().count() > 256
            || !matches!(request.principal.kind.as_str(), "user" | "system-service")
            || request
                .workspace_id
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.chars().count() > 256)
            || request
                .normalized_intent
                .as_ref()
                .is_some_and(|value| !value.is_object())
            || request.active_step_ids.len() > 512
            || !unique_steps
            || request
                .active_step_ids
                .iter()
                .any(|value| value.is_empty() || value.chars().count() > 128)
        {
            return Err(TaskManagerError::InvalidRecord(
                "invalid Task creation record",
            ));
        }
        let created_at = self.clock.now();
        let lease_owner = self.lease_owner.clone();
        let lease_epoch = self.lease_epoch;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_manager_lease(&transaction, &lease_owner, lease_epoch)?;
        let intent_nonce =
            transaction.query_row("SELECT randomblob(32)", [], |row| row.get::<_, Vec<u8>>(0))?;
        let original_intent_ref = task_field_commitment(
            &intent_nonce,
            "original_intent",
            request.original_intent.as_bytes(),
        );
        let normalized_intent_ref = request
            .normalized_intent
            .as_ref()
            .map(|value| {
                canonical_json(value).map(|canonical| {
                    task_field_commitment(&intent_nonce, "normalized_intent", canonical.as_bytes())
                })
            })
            .transpose()?;
        transaction.execute(
            "INSERT INTO tasks (task_id, revision, state, principal_kind, principal_id, workspace_id, original_intent, normalized_intent_json, intent_commitment_nonce, active_step_ids_json, waiting_on_json, created_at, updated_at) VALUES (?1, 1, 'CREATED', ?2, ?3, ?4, ?5, ?6, ?7, ?8, '[]', ?9, ?9)",
            params![
                request.task_id,
                request.principal.kind,
                request.principal.id,
                request.workspace_id,
                request.original_intent,
                encode_optional(request.normalized_intent.as_ref())?,
                intent_nonce,
                serde_json::to_string(&request.active_step_ids)?,
                created_at,
            ],
        )?;
        let event = json!({
            "schema_version": SCHEMA_VERSION,
            "event_id": task_created_event_id(&request.task_id),
            "task_id": request.task_id,
            "event_type": "task.created",
            "timestamp": created_at,
            "actor": request.principal,
            "status": "success",
            "details": {
                "revision": 1,
                "creation": {
                    "principal": request.principal,
                    "workspace_id": request.workspace_id,
                    "original_intent_ref": original_intent_ref,
                    "normalized_intent_ref": normalized_intent_ref,
                    "constraints": null,
                    "created_at": created_at
                },
                "active_plan": null,
                "active_step_ids": request.active_step_ids,
                "waiting_on": [],
                "failure": null,
                "recovery": null
            }
        });
        let appended = append_event(&transaction, &request.task_id, &event)?;
        transaction.execute(
            "UPDATE tasks SET state_reason_json = ?2 WHERE task_id = ?1",
            params![
                request.task_id,
                json!({"code":"TASK_CREATED","provenance_event_id":appended.event_id}).to_string()
            ],
        )?;
        transaction.commit()?;
        self.get_task(&request.task_id)?
            .ok_or(TaskManagerError::InvalidRecord("created Task disappeared"))
    }

    /// Loads a durable Task materialized view.
    ///
    /// # Errors
    /// Returns an error for storage, decoding, or invalid durable state.
    #[allow(
        clippy::too_many_lines,
        reason = "assembles the complete schema-shaped Task materialized view"
    )]
    pub fn get_task(&self, task_id: &str) -> Result<Option<TaskRecord>> {
        let row = self.connection.query_row(
            "SELECT revision, state, state_reason_json, principal_kind, principal_id, workspace_id, original_intent, normalized_intent_json, active_plan_revision, active_program_revision, active_step_ids_json, waiting_on_json, constraints_json, failure_json, recovery_json, created_at, updated_at, completed_at FROM tasks WHERE task_id = ?1",
            [task_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?, row.get::<_, String>(4)?, row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?, row.get::<_, Option<String>>(7)?, row.get::<_, Option<i64>>(8)?,
                    row.get::<_, Option<i64>>(9)?, row.get::<_, String>(10)?, row.get::<_, String>(11)?,
                    row.get::<_, Option<String>>(12)?, row.get::<_, Option<String>>(13)?, row.get::<_, Option<String>>(14)?,
                    row.get::<_, String>(15)?, row.get::<_, String>(16)?, row.get::<_, Option<String>>(17)?,
                ))
            },
        ).optional()?;
        let Some((
            revision,
            state,
            state_reason,
            principal_kind,
            principal_id,
            workspace_id,
            original_intent,
            normalized_intent,
            active_plan_revision,
            active_program_revision,
            active_steps,
            waiting_on,
            constraints,
            failure,
            recovery,
            created_at,
            updated_at,
            completed_at,
        )) = row
        else {
            return Ok(None);
        };
        let active_plan = if let Some(revision) = active_plan_revision {
            self.connection.query_row(
                "SELECT plan_id, plan_revision FROM plan_revisions WHERE task_id = ?1 AND plan_revision = ?2",
                params![task_id, revision],
                |row| Ok(ActivePlan { plan_id: row.get(0)?, revision: u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0) }),
            ).optional()?
        } else {
            None
        };
        let active_program = if let Some(revision) = active_program_revision {
            self.connection.query_row(
                "SELECT p.ir_version, p.program_id, p.semantic_hash, p.registry_snapshot_id, p.validation_result_id, v.validated_at, v.validator_id, v.validator_version FROM semantic_program_revisions p LEFT JOIN validation_results v ON v.validation_result_id = p.validation_result_id WHERE p.task_id = ?1 AND p.program_revision = ?2 AND p.status = 'active'",
                params![task_id, revision],
                |row| Ok(json!({
                    "ir_version": row.get::<_, String>(0)?,
                    "program_id": row.get::<_, String>(1)?,
                    "semantic_hash": row.get::<_, String>(2)?,
                    "registry_snapshot_id": row.get::<_, String>(3)?,
                    "validation_result_id": row.get::<_, Option<String>>(4)?,
                    "validated_at": row.get::<_, Option<String>>(5)?,
                    "validator_id": row.get::<_, Option<String>>(6)?,
                    "validator_version": row.get::<_, Option<String>>(7)?,
                })),
            ).optional()?
        } else {
            None
        };
        let input_artifacts = query_strings(
            &self.connection,
            "SELECT artifact_id FROM task_artifacts WHERE task_id = ?1 AND role = 'input' ORDER BY artifact_id",
            task_id,
        )?;
        let output_artifacts = query_strings(
            &self.connection,
            "SELECT artifact_id FROM task_artifacts WHERE task_id = ?1 AND role = 'output' ORDER BY artifact_id",
            task_id,
        )?;
        let decoded_active_steps: Vec<String> = serde_json::from_str(&active_steps)?;
        let active_execution_binding_ids = current_active_binding_ids(
            &self.connection,
            task_id,
            active_program_revision,
            &decoded_active_steps,
        )?;
        Ok(Some(TaskRecord {
            schema_version: SCHEMA_VERSION.to_owned(),
            task_id: task_id.to_owned(),
            revision: u64::try_from(revision)
                .map_err(|_| TaskManagerError::InvalidRecord("stored revision is invalid"))?,
            state: TaskState::parse(&state)?,
            state_reason: decode_optional(state_reason)?,
            principal: Actor {
                kind: principal_kind,
                id: principal_id,
            },
            workspace_id,
            original_intent,
            normalized_intent: decode_optional(normalized_intent)?,
            input_artifacts,
            output_artifacts,
            active_plan,
            active_program,
            active_step_ids: decoded_active_steps,
            active_execution_binding_ids,
            waiting_on: serde_json::from_str(&waiting_on)?,
            constraints: decode_optional(constraints)?,
            failure: decode_optional(failure)?,
            recovery: decode_optional(recovery)?,
            created_at,
            updated_at,
            completed_at,
        }))
    }

    /// Loads one immutable attempt identity and its current durable step state.
    ///
    /// # Errors
    /// Returns an error for storage, decoding, or invalid durable state.
    pub fn get_step_execution(&self, attempt_id: &str) -> Result<Option<StepExecutionRecord>> {
        let row = self.connection.query_row(
            "SELECT task_id, semantic_program_hash, registry_snapshot_id, node_id, binding_id, provider_id, provider_version, attempt_number, revision, state, operation_id, idempotency_key, outcome_certainty, input_artifacts_json, output_artifacts_json, failure_json, started_at, finished_at, created_at, updated_at FROM step_executions WHERE attempt_id = ?1",
            [attempt_id],
            |row| Ok((
                row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?, row.get::<_, Option<String>>(4)?, row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?, row.get::<_, i64>(7)?, row.get::<_, i64>(8)?,
                row.get::<_, String>(9)?, row.get::<_, Option<String>>(10)?, row.get::<_, Option<String>>(11)?,
                row.get::<_, Option<String>>(12)?, row.get::<_, Option<String>>(13)?, row.get::<_, Option<String>>(14)?,
                row.get::<_, Option<String>>(15)?, row.get::<_, Option<String>>(16)?, row.get::<_, Option<String>>(17)?,
                row.get::<_, String>(18)?, row.get::<_, String>(19)?,
            )),
        ).optional()?;
        let Some((
            task_id,
            semantic_program_hash,
            registry_snapshot_id,
            node_id,
            binding_id,
            provider_id,
            provider_version,
            attempt_number,
            revision,
            state,
            operation_id,
            idempotency_key,
            outcome_certainty,
            input_artifacts,
            output_artifacts,
            failure,
            started_at,
            finished_at,
            created_at,
            updated_at,
        )) = row
        else {
            return Ok(None);
        };
        let attempt_number = u16::try_from(attempt_number)
            .map_err(|_| TaskManagerError::InvalidRecord("stored attempt number is invalid"))?;
        if attempt_number > 100 {
            return Err(TaskManagerError::InvalidRecord(
                "stored attempt number exceeds the v0.1 limit",
            ));
        }
        if started_at
            .as_ref()
            .is_some_and(|value| OffsetDateTime::parse(value, &Rfc3339).is_err())
            || finished_at
                .as_ref()
                .is_some_and(|value| OffsetDateTime::parse(value, &Rfc3339).is_err())
        {
            return Err(TaskManagerError::InvalidRecord(
                "stored step timestamp is not RFC 3339",
            ));
        }
        Ok(Some(StepExecutionRecord {
            schema_version: SCHEMA_VERSION.to_owned(),
            attempt_id: attempt_id.to_owned(),
            task_id,
            semantic_program_hash,
            registry_snapshot_id,
            node_id,
            binding_id,
            provider_id,
            provider_version,
            attempt_number,
            revision: u64::try_from(revision)
                .map_err(|_| TaskManagerError::InvalidRecord("stored step revision is invalid"))?,
            state: StepState::parse(&state)?,
            operation_id,
            idempotency_key,
            outcome_certainty: outcome_certainty
                .as_deref()
                .map(OutcomeCertainty::parse)
                .transpose()?,
            input_artifacts: decode_optional(input_artifacts)?.unwrap_or_default(),
            output_artifacts: decode_optional(output_artifacts)?.unwrap_or_default(),
            failure: decode_optional(failure)?,
            started_at,
            finished_at,
            created_at,
            updated_at,
        }))
    }

    /// Persists a new append-only provider-attempt identity at revision 1.
    ///
    /// # Errors
    /// Returns an error for invalid input, duplicate attempt identity, missing
    /// Task/binding references, or failed storage.
    #[allow(
        clippy::too_many_lines,
        reason = "keeps schema validation and immutable attempt creation in one fenced transaction"
    )]
    pub(crate) fn create_step_execution(
        &mut self,
        request: &CreateStepExecution,
    ) -> Result<StepExecutionRecord> {
        let unique_inputs = all_unique(&request.input_artifacts);
        let unique_outputs = all_unique(&request.output_artifacts);
        let valid_failure = request.failure.as_ref().is_none_or(|failure| {
            reason_code_valid(&failure.code)
                && !failure.summary.is_empty()
                && failure.summary.chars().count() <= 4096
        });
        let valid_timestamps = request
            .started_at
            .iter()
            .chain(request.finished_at.iter())
            .all(|timestamp| OffsetDateTime::parse(timestamp, &Rfc3339).is_ok());
        if request.attempt_id.is_empty()
            || request.attempt_id.chars().count() > 256
            || request.task_id.is_empty()
            || request.task_id.chars().count() > 256
            || request.node_id.is_empty()
            || request.node_id.chars().count() > 128
            || request.attempt_number == 0
            || request.attempt_number > 100
            || !is_sha256(&request.semantic_program_hash)
            || matches!(request.state, StepState::Starting | StepState::Running)
            || request
                .registry_snapshot_id
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.chars().count() > 256)
            || request
                .binding_id
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.chars().count() > 256)
            || request
                .provider_id
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.chars().count() > 256)
            || request
                .provider_version
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.chars().count() > 128)
            || request
                .operation_id
                .as_ref()
                .is_some_and(|value| value.chars().count() > 512)
            || request
                .idempotency_key
                .as_ref()
                .is_some_and(|value| value.chars().count() > 512)
            || request.input_artifacts.len() > 256
            || request.output_artifacts.len() > 256
            || !unique_inputs
            || !unique_outputs
            || request
                .input_artifacts
                .iter()
                .chain(&request.output_artifacts)
                .any(|value| value.chars().count() > 512)
            || !valid_failure
            || !valid_timestamps
        {
            return Err(TaskManagerError::InvalidRecord(
                "step execution does not satisfy the v0.1 contract",
            ));
        }
        let now = self.clock.now();
        let lease_owner = self.lease_owner.clone();
        let lease_epoch = self.lease_epoch;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_manager_lease(&transaction, &lease_owner, lease_epoch)?;
        let duplicate_tuple = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM step_executions WHERE task_id = ?1 AND semantic_program_hash = ?2 AND node_id = ?3 AND attempt_number = ?4)",
            params![request.task_id, request.semantic_program_hash, request.node_id, i64::from(request.attempt_number)],
            |row| row.get::<_, bool>(0),
        )?;
        if duplicate_tuple {
            return Err(TaskManagerError::InvalidRecord(
                "step attempt tuple already exists",
            ));
        }
        if let Some(binding_id) = &request.binding_id {
            let exact_binding = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM execution_bindings WHERE binding_id = ?1 AND attempt_id = ?2 AND task_id = ?3 AND semantic_program_hash = ?4 AND registry_snapshot_id = ?5 AND node_id = ?6 AND provider_id = ?7 AND provider_version = ?8 AND attempt = ?9)",
                params![binding_id, request.attempt_id, request.task_id, request.semantic_program_hash, request.registry_snapshot_id, request.node_id, request.provider_id, request.provider_version, i64::from(request.attempt_number)],
                |row| row.get::<_, bool>(0),
            )?;
            if !exact_binding {
                return Err(TaskManagerError::InvalidRecord(
                    "step execution binding tuple does not match its immutable receipt",
                ));
            }
        }
        transaction.execute(
            "INSERT INTO step_executions (attempt_id, task_id, semantic_program_hash, registry_snapshot_id, node_id, binding_id, provider_id, provider_version, attempt_number, revision, state, operation_id, idempotency_key, outcome_certainty, failure_json, input_artifacts_json, output_artifacts_json, started_at, finished_at, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?19)",
            params![request.attempt_id, request.task_id, request.semantic_program_hash, request.registry_snapshot_id, request.node_id, request.binding_id, request.provider_id, request.provider_version, i64::from(request.attempt_number), request.state.as_str(), request.operation_id, request.idempotency_key, request.outcome_certainty.map(OutcomeCertainty::as_str), encode_optional(request.failure.as_ref())?, serde_json::to_string(&request.input_artifacts)?, serde_json::to_string(&request.output_artifacts)?, request.started_at, request.finished_at, now],
        )?;
        transaction.commit()?;
        self.get_step_execution(&request.attempt_id)?
            .ok_or(TaskManagerError::InvalidRecord(
                "created step execution disappeared",
            ))
    }

    /// Applies one idempotent CAS transition.
    ///
    /// # Errors
    /// Returns an error for storage/serialization failures. State-machine
    /// rejections are represented by a successful `TransitionResult` value.
    pub(crate) fn transition(&mut self, request: &TransitionRequest) -> Result<TransitionResult> {
        self.transition_impl(request, false, false)
    }

    /// Moves uncertain pre-restart execution states into `RECOVERING` by using
    /// the ordinary CAS/idempotency/provenance transition boundary.
    ///
    /// # Errors
    /// Returns an error when durable state cannot be read or a recovery
    /// transition cannot be committed.
    #[allow(
        clippy::too_many_lines,
        reason = "keeps nonterminal recovery transitions and immutable terminal recovery reporting in one startup scan"
    )]
    pub(crate) fn recover_startup(&mut self) -> Result<Vec<TransitionResult>> {
        self.verify_nonterminal_heads()?;
        let candidates = {
            let mut statement = self.connection.prepare(
                "SELECT task_id, revision, state FROM tasks WHERE state IN ('RUNNABLE', 'RUNNING', 'VERIFYING', 'PAUSED', 'WAITING_FOR_INPUT', 'WAITING_FOR_AUTH') ORDER BY task_id",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        let mut results = Vec::with_capacity(candidates.len());
        let mut newly_recovered = std::collections::BTreeSet::new();
        for (task_id, revision, state) in candidates {
            let revision = u64::try_from(revision)
                .map_err(|_| TaskManagerError::InvalidRecord("stored revision is invalid"))?;
            let state = TaskState::parse(&state)?;
            let unknown_operation_ids = unresolved_execution_ids(&self.connection, &task_id)?;
            // A nonterminal materialized state alone is not evidence of an
            // uncertain operation. Never create an empty recovery epoch that
            // cannot be reconciled; durable consequential subjects drive entry.
            if unknown_operation_ids.is_empty() {
                continue;
            }
            if matches!(
                state,
                TaskState::Runnable | TaskState::WaitingForInput | TaskState::WaitingForAuth
            ) {
                return Err(TaskManagerError::InvalidRecord(
                    "legacy non-executing Task retains unresolved execution and requires quarantine",
                ));
            }
            let recovery_ref = recovery_operations_ref(&task_id, revision, &unknown_operation_ids)?;
            let assessed_at = self.clock.now();
            self.persist_recovery_inventory(
                &recovery_ref,
                &task_id,
                revision,
                &unknown_operation_ids,
                &assessed_at,
            )?;
            let result = self.transition_impl(
                &TransitionRequest {
                    schema_version: SCHEMA_VERSION.to_owned(),
                    transition_id: startup_recovery_transition_id(&task_id, revision),
                    task_id,
                    expected_revision: revision,
                    expected_state: state,
                    to_state: TaskState::Recovering,
                    requested_by: Actor {
                        kind: "system-service".to_owned(),
                        id: "service:recovery".to_owned(),
                    },
                    reason: TransitionReason {
                        code: "TASK_RECOVERY_REQUIRED".to_owned(),
                        message: Some("startup found an uncertain in-flight Task".to_owned()),
                        related_ids: vec![recovery_ref.clone()],
                    },
                    mutation: TaskMutation {
                        recovery: Some(RecoveryMutation {
                            unknown_operation_ids: Vec::new(),
                            unknown_operations_ref: Some(recovery_ref),
                            last_known_daemon_instance: None,
                        }),
                        ..TaskMutation::default()
                    },
                },
                false,
                true,
            )?;
            if !result.applied {
                return Err(TaskManagerError::InvalidRecord(
                    "startup recovery transition was not applied",
                ));
            }
            newly_recovered.insert(result.task_id.clone());
            results.push(result);
        }
        // Terminal state is immutable, but new consequential evidence may be
        // discovered during startup Artifact/export reconciliation. Persist a
        // deterministic recovery inventory for reporting and subject-level
        // reconciliation without fabricating a terminal -> RECOVERING edge.
        let terminal_tasks = {
            let mut statement = self.connection.prepare(
                "SELECT task_id,revision FROM tasks
                 WHERE state IN ('COMPLETED','FAILED','CANCELLED','ROLLED_BACK')
                 ORDER BY task_id",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        for (task_id, revision) in terminal_tasks {
            let revision = u64::try_from(revision)
                .map_err(|_| TaskManagerError::InvalidRecord("stored revision is invalid"))?;
            let inventory = unresolved_execution_ids(&self.connection, &task_id)?;
            if inventory.is_empty() {
                continue;
            }
            let recovery_ref = recovery_operations_ref(&task_id, revision, &inventory)?;
            self.persist_recovery_inventory(
                &recovery_ref,
                &task_id,
                revision,
                &inventory,
                &self.clock.now(),
            )?;
        }
        // Artifact reconciliation runs before this scan and can discover a
        // consequential subject after a Task has already entered RECOVERING.
        // Persist a fresh immutable monotonic inventory for the current recovery
        // episode. The Task's recovery-entry transition remains the lifecycle
        // authority; active_recovery_inventory resolves later supersets.
        let recovering_tasks = {
            let mut statement = self.connection.prepare(
                "SELECT task_id,revision,json_extract(recovery_json,'$.unknown_operations_ref')
                 FROM tasks WHERE state='RECOVERING' ORDER BY task_id",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        for (task_id, revision, _active_recovery_ref) in recovering_tasks {
            if newly_recovered.contains(&task_id) {
                continue;
            }
            let revision = u64::try_from(revision)
                .map_err(|_| TaskManagerError::InvalidRecord("stored revision is invalid"))?;
            let current = unresolved_execution_ids(&self.connection, &task_id)?;
            if current.is_empty() {
                continue;
            }
            let Some(active) = active_recovery_inventory(&self.connection, &task_id)? else {
                return Err(TaskManagerError::InvalidRecord(
                    "active recovery inventory does not exist",
                ));
            };
            let mut inventory = active.operation_ids.clone();
            inventory.extend(current);
            inventory.sort();
            inventory.dedup();
            if inventory == active.operation_ids {
                continue;
            }
            let recovery_ref = recovery_operations_ref(&task_id, revision, &inventory)?;
            self.persist_recovery_inventory_in_existing_episode(
                &recovery_ref,
                &task_id,
                revision,
                &inventory,
                &self.clock.now(),
                &active.recovery_ref,
            )?;
        }
        Ok(results)
    }

    /// Persists immutable recovery reporting for newly discovered consequential evidence on a
    /// terminal Task without changing its lifecycle state.
    pub(crate) fn persist_terminal_recovery_inventory_for_task(
        &mut self,
        task_id: &str,
    ) -> Result<String> {
        let state = self.connection.query_row(
            "SELECT state FROM tasks WHERE task_id=?1",
            [task_id],
            |row| row.get::<_, String>(0),
        )?;
        if !matches!(
            state.as_str(),
            "COMPLETED" | "FAILED" | "CANCELLED" | "ROLLED_BACK"
        ) {
            return Err(TaskManagerError::InvalidRecord(
                "terminal recovery inventory requires a terminal Task",
            ));
        }
        self.persist_recovery_inventory_for_task(task_id)
    }

    pub(crate) fn persist_recovery_inventory_for_task(&mut self, task_id: &str) -> Result<String> {
        let (revision, state, _active_recovery_ref) = self
            .connection
            .query_row(
                "SELECT revision,state,json_extract(recovery_json,'$.unknown_operations_ref')
                 FROM tasks WHERE task_id=?1",
                [task_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .optional()?
            .ok_or(TaskManagerError::InvalidRecord(
                "terminal recovery Task does not exist",
            ))?;
        let revision = u64::try_from(revision)
            .map_err(|_| TaskManagerError::InvalidRecord("stored revision is invalid"))?;
        let current = unresolved_execution_ids(&self.connection, task_id)?;
        if current.is_empty() {
            return Err(TaskManagerError::InvalidRecord(
                "recovery inventory requires consequential evidence",
            ));
        }
        let mut inventory = current;
        let mut episode_ref = None;
        if state == "RECOVERING" {
            let active = active_recovery_inventory(&self.connection, task_id)?.ok_or(
                TaskManagerError::InvalidRecord("active recovery inventory does not exist"),
            )?;
            inventory.extend(active.operation_ids.iter().cloned());
            inventory.sort();
            inventory.dedup();
            if inventory == active.operation_ids {
                return Ok(active.recovery_ref);
            }
            episode_ref = Some(active.recovery_ref);
        }
        let recovery_ref = recovery_operations_ref(task_id, revision, &inventory)?;
        if let Some(episode_ref) = episode_ref {
            self.persist_recovery_inventory_in_existing_episode(
                &recovery_ref,
                task_id,
                revision,
                &inventory,
                &self.clock.now(),
                &episode_ref,
            )?;
        } else {
            self.persist_recovery_inventory(
                &recovery_ref,
                task_id,
                revision,
                &inventory,
                &self.clock.now(),
            )?;
        }
        Ok(recovery_ref)
    }

    /// Performs a trusted, evidence-derived live reconciliation handoff.
    ///
    /// # Errors
    /// Returns an error unless the Task is currently executing and the
    /// internally-authenticated recovery transition commits.
    pub(crate) fn reconcile_live_execution(&mut self, task_id: &str) -> Result<TransitionResult> {
        let stored = self
            .connection
            .query_row(
                "SELECT revision, state FROM tasks WHERE task_id = ?1",
                [task_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let Some((revision, state)) = stored else {
            return Err(TaskManagerError::InvalidRecord(
                "recovery Task does not exist",
            ));
        };
        let revision = u64::try_from(revision)
            .map_err(|_| TaskManagerError::InvalidRecord("stored revision is invalid"))?;
        let state = TaskState::parse(&state)?;
        if !matches!(
            state,
            TaskState::Running | TaskState::Verifying | TaskState::Paused
        ) {
            return Err(TaskManagerError::InvalidRecord(
                "live recovery is reserved for executing Tasks",
            ));
        }
        let inventory = unresolved_execution_ids(&self.connection, task_id)?;
        let recovery_ref = recovery_operations_ref(task_id, revision, &inventory)?;
        let assessed_at = self.clock.now();
        self.persist_recovery_inventory(
            &recovery_ref,
            task_id,
            revision,
            &inventory,
            &assessed_at,
        )?;
        let result = self.transition_impl(
            &TransitionRequest {
                schema_version: SCHEMA_VERSION.to_owned(),
                transition_id: live_recovery_transition_id(task_id, revision),
                task_id: task_id.to_owned(),
                expected_revision: revision,
                expected_state: state,
                to_state: TaskState::Recovering,
                requested_by: Actor {
                    kind: "system-service".to_owned(),
                    id: "service:recovery".to_owned(),
                },
                reason: TransitionReason {
                    code: "TASK_RECOVERY_REQUIRED".to_owned(),
                    message: Some(
                        "trusted live reconciliation found uncertain execution".to_owned(),
                    ),
                    related_ids: vec![recovery_ref.clone()],
                },
                mutation: TaskMutation {
                    recovery: Some(RecoveryMutation {
                        unknown_operation_ids: Vec::new(),
                        unknown_operations_ref: Some(recovery_ref),
                        last_known_daemon_instance: None,
                    }),
                    ..TaskMutation::default()
                },
            },
            false,
            true,
        )?;
        if !result.applied {
            return Err(TaskManagerError::InvalidRecord(
                "live recovery transition was not applied",
            ));
        }
        Ok(result)
    }

    /// Resolves a bounded startup-recovery reference to its exact durable
    /// unknown-operation inventory.
    ///
    /// # Errors
    /// Returns an error when the stored assessment cannot be read or decoded.
    pub fn recovery_unknown_operation_ids(
        &self,
        recovery_ref: &str,
    ) -> Result<Option<Vec<String>>> {
        Ok(exact_recovery_inventory(&self.connection, recovery_ref)?
            .map(|inventory| inventory.operation_ids))
    }

    pub(crate) fn active_recovery_inventory_ref(&self, task_id: &str) -> Result<Option<String>> {
        Ok(active_recovery_inventory(&self.connection, task_id)?
            .map(|inventory| inventory.recovery_ref))
    }

    /// Records a trusted recovery observation for one historically inventoried
    /// subject after its durable record establishes a safe outcome.
    #[allow(
        clippy::too_many_lines,
        reason = "keeps trusted resolution evidence, idempotent provenance, and assessment commit atomic"
    )]
    pub(crate) fn reconcile_recovery_subject(
        &mut self,
        recovery_ref: &str,
        inventory_id: &str,
    ) -> Result<()> {
        let lease_owner = self.lease_owner.clone();
        let lease_epoch = self.lease_epoch;
        let observed_at = self.clock.now();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_manager_lease(&transaction, &lease_owner, lease_epoch)?;
        let requested = exact_recovery_inventory(&transaction, recovery_ref)?.ok_or(
            TaskManagerError::InvalidRecord("recovery inventory does not exist"),
        )?;
        let recovery_ref = active_recovery_inventory(&transaction, &requested.task_id)?
            .filter(|active| {
                active.recovery_epoch_id == requested.recovery_epoch_id
                    && requested
                        .operation_ids
                        .iter()
                        .all(|id| active.operation_ids.contains(id))
            })
            .map_or_else(|| recovery_ref.to_owned(), |active| active.recovery_ref);
        reconcile_recovery_subject_in_transaction(
            &transaction,
            &recovery_ref,
            inventory_id,
            &observed_at,
        )?;
        transaction.commit()?;
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "keeps recovery assessment identity, inventory, and idempotency checks atomic"
    )]
    fn persist_recovery_inventory(
        &mut self,
        recovery_ref: &str,
        task_id: &str,
        basis_revision: u64,
        operation_ids: &[String],
        created_at: &str,
    ) -> Result<()> {
        if recovery_operations_ref(task_id, basis_revision, operation_ids)? != recovery_ref {
            return Err(TaskManagerError::InvalidRecord(
                "recovery reference does not authenticate its basis and inventory",
            ));
        }
        let lease_owner = self.lease_owner.clone();
        let lease_epoch = self.lease_epoch;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_manager_lease(&transaction, &lease_owner, lease_epoch)?;
        Self::persist_recovery_inventory_in_transaction(
            &transaction,
            recovery_ref,
            task_id,
            basis_revision,
            operation_ids,
            created_at,
            None,
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn persist_recovery_inventory_in_existing_episode(
        &mut self,
        recovery_ref: &str,
        task_id: &str,
        basis_revision: u64,
        operation_ids: &[String],
        created_at: &str,
        episode_root_ref: &str,
    ) -> Result<()> {
        let epoch_id = self.connection.query_row(
            "SELECT recovery_epoch_id FROM recovery_assessments
             WHERE assessment_id=?1 AND task_id=?2 AND subject_kind='task'",
            params![episode_root_ref, task_id],
            |row| row.get::<_, String>(0),
        )?;
        let lease_owner = self.lease_owner.clone();
        let lease_epoch = self.lease_epoch;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_manager_lease(&transaction, &lease_owner, lease_epoch)?;
        Self::persist_recovery_inventory_in_transaction(
            &transaction,
            recovery_ref,
            task_id,
            basis_revision,
            operation_ids,
            created_at,
            Some(&epoch_id),
        )?;
        transaction.commit()?;
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "keeps the recovery assessment and exact subject inventory in its caller's atomic transaction"
    )]
    fn persist_recovery_inventory_in_transaction(
        transaction: &Transaction<'_>,
        recovery_ref: &str,
        task_id: &str,
        basis_revision: u64,
        operation_ids: &[String],
        created_at: &str,
        episode_epoch_id: Option<&str>,
    ) -> Result<()> {
        if recovery_operations_ref(task_id, basis_revision, operation_ids)? != recovery_ref {
            return Err(TaskManagerError::InvalidRecord(
                "recovery reference does not authenticate its basis and inventory",
            ));
        }
        let default_epoch_id = format!("epoch:{recovery_ref}");
        let epoch_id = episode_epoch_id.unwrap_or(&default_epoch_id);
        // An empty inventory is absence of evidence, not affirmative proof that
        // execution never started. The aggregate therefore remains conservative;
        // per-subject assessments below may record NOT_STARTED only from an
        // explicit durable certainty/status fact.
        let certainty = "OUTCOME_UNKNOWN";
        let safe_action = "REQUIRE_EXTERNAL_RECONCILIATION";
        let reason_codes = vec![
            "RECOVERY_OUTCOME_UNKNOWN",
            "RECOVERY_EXTERNAL_RECONCILIATION_REQUIRED",
        ];
        let external_reconciliation_required = true;
        let reason_codes_json = serde_json::to_string(&reason_codes)?;
        transaction.execute(
            "INSERT OR IGNORE INTO recovery_epochs (recovery_epoch_id, started_at) VALUES (?1, ?2)",
            params![epoch_id, created_at],
        )?;
        let mut materialized_inventory = std::collections::BTreeSet::new();
        for subject in load_recovery_subjects(transaction, task_id)? {
            if let Some(inventory_id) = recovery_subject_inventory_id(subject.kind, &subject.id) {
                materialized_inventory.insert(inventory_id);
            }
            persist_recovery_subject_assessment(
                transaction,
                recovery_ref,
                epoch_id,
                task_id,
                basis_revision,
                &subject,
                created_at,
            )?;
        }
        let mut carried_resolutions = Vec::new();
        if episode_epoch_id.is_some() {
            for inventory_id in operation_ids {
                if !materialized_inventory.contains(inventory_id)
                    && carry_forward_resolved_recovery_subject(
                        transaction,
                        recovery_ref,
                        epoch_id,
                        task_id,
                        basis_revision,
                        inventory_id,
                        created_at,
                    )?
                {
                    carried_resolutions.push(inventory_id.clone());
                    materialized_inventory.insert(inventory_id.clone());
                }
            }
            if materialized_inventory.len() != operation_ids.len() {
                return Err(TaskManagerError::InvalidRecord(
                    "recovery inventory lacks authenticated subject evidence",
                ));
            }
        }
        let existing = transaction
            .query_row(
                "SELECT recovery_epoch_id, task_id, subject_kind, subject_id, certainty, safe_action, reason_codes_json, assessment_json, created_at, basis_revision FROM recovery_assessments WHERE assessment_id = ?1",
                [recovery_ref],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, i64>(9)?,
                    ))
                },
            )
            .optional()?;
        let canonical_created_at = existing.as_ref().map_or(created_at, |row| row.8.as_str());
        let assessment = canonical_json(&json!({
            "schema_version": SCHEMA_VERSION,
            "assessment_id": recovery_ref,
            "recovery_epoch_id": epoch_id,
            "task_id": task_id,
            "subject": {"kind": "task", "id": task_id},
            "certainty": certainty,
            "evidence": [{
                "kind": "task-record",
                "ref": format!("task:{task_id}:revision:{basis_revision}"),
                "observation": if operation_ids.is_empty() {
                    "no affirmative per-subject certainty evidence exists; external reconciliation is required".to_owned()
                } else {
                    format!("{} unresolved execution record(s) require reconciliation", operation_ids.len())
                }
            }],
            "safe_action": safe_action,
            "new_binding_required": false,
            "external_reconciliation_required": external_reconciliation_required,
            "reason_codes": reason_codes,
            "created_at": canonical_created_at
        }))?;
        if let Some(existing) = existing {
            if existing.0 != epoch_id
                || existing.1 != task_id
                || existing.2 != "task"
                || existing.3 != task_id
                || existing.4 != certainty
                || existing.5 != safe_action
                || existing.6 != reason_codes_json
                || existing.7 != assessment
                || existing.9
                    != i64::try_from(basis_revision).map_err(|_| {
                        TaskManagerError::InvalidRecord(
                            "recovery basis revision exceeds SQLite range",
                        )
                    })?
            {
                return Err(TaskManagerError::InvalidRecord(
                    "recovery reference resolves to a different assessment",
                ));
            }
        } else {
            transaction.execute(
                "INSERT INTO recovery_assessments (assessment_id, recovery_epoch_id, task_id, basis_revision, subject_kind, subject_id, certainty, safe_action, reason_codes_json, assessment_json, created_at) VALUES (?1, ?2, ?3, ?4, 'task', ?3, ?5, ?6, ?7, ?8, ?9)",
                params![recovery_ref, epoch_id, task_id, i64::try_from(basis_revision).map_err(|_| TaskManagerError::InvalidRecord("recovery basis revision exceeds SQLite range"))?, certainty, safe_action, reason_codes_json, assessment, canonical_created_at],
            )?;
            for (ordinal, operation_id) in operation_ids.iter().enumerate() {
                transaction.execute(
                    "INSERT INTO recovery_unknown_operations (assessment_id, ordinal, operation_id) VALUES (?1, ?2, ?3)",
                    params![recovery_ref, i64::try_from(ordinal).map_err(|_| TaskManagerError::InvalidRecord("recovery inventory exceeds SQLite range"))?, operation_id],
                )?;
            }
        }
        let stored = transaction.query_row(
            "SELECT assessment_json FROM recovery_assessments WHERE assessment_id = ?1",
            [recovery_ref],
            |row| row.get::<_, String>(0),
        )?;
        if stored != assessment {
            return Err(TaskManagerError::InvalidRecord(
                "recovery reference resolves to a different operation inventory",
            ));
        }
        let stored_operations = query_strings(
            transaction,
            "SELECT operation_id FROM recovery_unknown_operations WHERE assessment_id = ?1 ORDER BY ordinal",
            recovery_ref,
        )?;
        if stored_operations != operation_ids {
            return Err(TaskManagerError::InvalidRecord(
                "recovery reference resolves to a different operation inventory",
            ));
        }
        for inventory_id in carried_resolutions {
            reconcile_recovery_subject_in_transaction(
                transaction,
                recovery_ref,
                &inventory_id,
                created_at,
            )?;
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "keeps full provenance replay and materialized security-view comparison auditable"
    )]
    fn verify_nonterminal_heads(&self) -> Result<()> {
        let tasks = {
            let mut statement = self.connection.prepare(
                "SELECT task_id, revision, state FROM tasks WHERE state NOT IN ('COMPLETED', 'FAILED', 'CANCELLED', 'ROLLED_BACK') ORDER BY task_id",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        for (task_id, revision, state) in tasks {
            self.verify_task_head(&task_id, revision, &state)?;
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "keeps full provenance replay and materialized security-view comparison auditable"
    )]
    fn verify_task_head(&self, task_id: &str, revision: i64, state: &str) -> Result<()> {
        if !self.verify_provenance(task_id)? {
            return Err(TaskManagerError::InvalidRecord(
                "Task provenance chain is missing or invalid",
            ));
        }
        let mut statement = self.connection.prepare(
                "SELECT event_json FROM provenance_events WHERE task_id = ?1 AND event_type IN ('task.created', 'task.transitioned') ORDER BY sequence",
            )?;
        let rows = statement.query_map([&task_id], |row| row.get::<_, String>(0))?;
        let mut material_revision = 0_i64;
        let mut material_state: Option<TaskState> = None;
        let mut material_creation: Option<Value> = None;
        let mut material_active_plan: Option<ActivePlan> = None;
        let mut material_active_program: Option<Value> = None;
        let mut material_active_program_digest: Option<String> = None;
        let mut material_steps = Vec::<String>::new();
        let mut material_waiting = json!([]);
        let mut material_waiting_commitments = json!([]);
        let mut material_failure: Option<Value> = None;
        let mut material_failure_commitment: Option<Value> = None;
        let mut material_recovery: Option<Value> = None;
        let mut material_state_reason: Option<Value> = None;
        let mut material_reason_message_ref: Option<Value> = None;
        let mut material_updated_at: Option<String> = None;
        for row in rows {
            let event = aios_provenance::parse_unique_json(&row?)?;
            if event.get("event_type").and_then(Value::as_str) == Some("task.created") {
                let creation = event.pointer("/details/creation").cloned().ok_or(
                    TaskManagerError::InvalidRecord("Task provenance creation payload is missing"),
                )?;
                if material_revision != 0
                    || event.pointer("/details/revision").and_then(Value::as_i64) != Some(1)
                    || event.get("actor") != creation.get("principal")
                    || event.get("timestamp") != creation.get("created_at")
                {
                    return Err(TaskManagerError::InvalidRecord(
                        "Task provenance has an invalid creation event",
                    ));
                }
                material_revision = 1;
                material_state = Some(TaskState::Created);
                material_creation = Some(creation);
                material_updated_at = event
                    .get("timestamp")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned);
                material_steps = serde_json::from_value(
                    event
                        .pointer("/details/active_step_ids")
                        .cloned()
                        .unwrap_or_else(|| json!([])),
                )?;
                material_state_reason = Some(json!({
                    "code": "TASK_CREATED",
                    "provenance_event_id": event_string(&event, "event_id")
                }));
                continue;
            }
            let previous_revision = event
                .pointer("/task_transition/previous_revision")
                .and_then(Value::as_i64);
            let new_revision = event
                .pointer("/task_transition/new_revision")
                .and_then(Value::as_i64);
            let previous_state = event
                .pointer("/task_transition/previous_state")
                .and_then(Value::as_str)
                .map(TaskState::parse)
                .transpose()?;
            let new_state = event
                .pointer("/task_transition/new_state")
                .and_then(Value::as_str)
                .map(TaskState::parse)
                .transpose()?;
            if previous_revision != Some(material_revision)
                || new_revision != material_revision.checked_add(1)
                || previous_state != material_state
                || !previous_state
                    .zip(new_state)
                    .is_some_and(|(from, to)| allowed_transition(from, to))
            {
                return Err(TaskManagerError::InvalidRecord(
                    "Task provenance state history is discontinuous",
                ));
            }
            material_revision += 1;
            material_state = new_state;
            material_updated_at = event
                .get("timestamp")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            let mutation =
                event
                    .get("committed_mutation")
                    .ok_or(TaskManagerError::InvalidRecord(
                        "Task transition provenance has no committed mutation",
                    ))?;
            if let Some(value) = mutation.get("active_plan").filter(|value| !value.is_null()) {
                material_active_plan = Some(serde_json::from_value(value.clone())?);
            }
            if let Some(value) = mutation
                .get("active_step_ids")
                .filter(|value| !value.is_null())
            {
                material_steps = serde_json::from_value(value.clone())?;
            }
            if let Some(value) = mutation.get("waiting_on").filter(|value| !value.is_null()) {
                material_waiting = value.clone();
                material_waiting_commitments = event
                    .pointer("/details/mutation_text_commitments/waiting_on")
                    .cloned()
                    .ok_or(TaskManagerError::InvalidRecord(
                        "waiting message commitments are missing",
                    ))?;
            }
            if let Some(value) = mutation.get("failure").filter(|value| !value.is_null()) {
                material_failure = Some(value.clone());
                material_failure_commitment = event
                    .pointer("/details/mutation_text_commitments/failure_summary")
                    .cloned();
                if material_failure_commitment.is_none() {
                    return Err(TaskManagerError::InvalidRecord(
                        "failure summary commitment is missing",
                    ));
                }
            }
            if let Some(value) = mutation.get("recovery").filter(|value| !value.is_null()) {
                material_recovery = Some(value.clone());
            }
            material_state_reason = Some(json!({
                "code": event.pointer("/task_transition/reason_code"),
                "provenance_event_id": event_string(&event, "event_id")
            }));
            material_reason_message_ref = event.pointer("/details/reason_message_ref").cloned();
            if let Some(value) = event
                .pointer("/details/active_program")
                .filter(|value| !value.is_null())
            {
                let mut identity = value.clone();
                material_active_program_digest = identity
                    .get("program_content_digest")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned);
                let Some(identity) = identity.as_object_mut() else {
                    return Err(TaskManagerError::InvalidRecord(
                        "Task provenance active program is malformed",
                    ));
                };
                identity.remove("program_content_digest");
                material_active_program = Some(Value::Object(identity.clone()));
            }
        }
        if material_revision != revision || material_state.map(TaskState::as_str) != Some(state) {
            return Err(TaskManagerError::InvalidRecord(
                "Task state does not match provenance head",
            ));
        }
        let task = self
            .get_task(task_id)?
            .ok_or(TaskManagerError::InvalidRecord(
                "provenance-backed Task disappeared during startup verification",
            ))?;
        let intent_nonce = self.connection.query_row(
            "SELECT intent_commitment_nonce FROM tasks WHERE task_id = ?1",
            [&task_id],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        if intent_nonce.len() != 32 {
            return Err(TaskManagerError::InvalidRecord(
                "Task intent commitment nonce is invalid",
            ));
        }
        let expected_creation = json!({
            "principal": task.principal,
            "workspace_id": task.workspace_id,
            "original_intent_ref": task_field_commitment(&intent_nonce, "original_intent", task.original_intent.as_bytes()),
            "normalized_intent_ref": task.normalized_intent.as_ref().map(|value| canonical_json(value).map(|canonical| task_field_commitment(&intent_nonce, "normalized_intent", canonical.as_bytes()))).transpose()?,
            "constraints": task.constraints,
            "created_at": task.created_at,
        });
        let active_program_digest = self
                .connection
                .query_row(
                    "SELECT p.program_json FROM tasks t JOIN semantic_program_revisions p ON p.task_id = t.task_id AND p.program_revision = t.active_program_revision AND p.status = 'active' WHERE t.task_id = ?1",
                    [&task_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .map(|program_json| program_content_digest(&program_json))
                .transpose()?;
        let expected_waiting = provenance_waiting_on(&task.waiting_on);
        let expected_waiting_commitments =
            provenance_waiting_commitments(&task.waiting_on, &intent_nonce);
        let expected_failure = task.failure.as_ref().map(provenance_failure);
        let expected_failure_commitment = task
            .failure
            .as_ref()
            .map(|failure| provenance_failure_commitment(failure, &intent_nonce));
        let task_reason_without_message = task.state_reason.as_ref().map(|reason| {
            json!({
                "code": reason.get("code"),
                "provenance_event_id": reason.get("provenance_event_id"),
            })
        });
        let expected_reason_message_ref = task.state_reason.as_ref().and_then(|reason| {
            reason.get("message").map(|message| {
                message.as_str().map_or(Value::Null, |message| {
                    task_field_commitment(&intent_nonce, "reason_message", message.as_bytes())
                })
            })
        });
        let replayed_completed_at = if material_state == Some(TaskState::Completed) {
            material_updated_at.clone()
        } else {
            None
        };
        if material_creation.as_ref() != Some(&expected_creation)
            || task.updated_at != material_updated_at.unwrap_or_default()
            || task.completed_at != replayed_completed_at
            || task.active_plan != material_active_plan
            || task.active_program != material_active_program
            || active_program_digest != material_active_program_digest
            || task.active_step_ids != material_steps
            || expected_waiting != material_waiting
            || expected_waiting_commitments != material_waiting_commitments
            || expected_failure != material_failure
            || expected_failure_commitment != material_failure_commitment
            || task.recovery != material_recovery
            || task_reason_without_message != material_state_reason
            || expected_reason_message_ref != material_reason_message_ref
        {
            return Err(TaskManagerError::InvalidRecord(
                "Task security state does not match committed provenance",
            ));
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "keeps the single SQLite transaction boundary contiguous for audit"
    )]
    fn transition_impl(
        &mut self,
        request: &TransitionRequest,
        fail_provenance: bool,
        internal_recovery: bool,
    ) -> Result<TransitionResult> {
        validate_transition_request(request, internal_recovery)?;
        let mut resulted_at = if request.to_state == TaskState::Running {
            trusted_time::assess(&self.connection, &self.clock)?.require_trusted_time()?
        } else {
            self.clock.now()
        };
        let request_json = canonical_json(request)?;
        let lease_owner = self.lease_owner.clone();
        let lease_epoch = self.lease_epoch;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut locked_time = if request.to_state == TaskState::Running {
            let fresh = trusted_time::capture_locked(&transaction, &self.clock)?;
            resulted_at = match fresh.require_trusted_time() {
                Ok(now) => now,
                Err(error) => {
                    drop(transaction);
                    fresh.commit(&self.connection)?;
                    return Err(error);
                }
            };
            Some(fresh)
        } else {
            None
        };
        assert_manager_lease(&transaction, &lease_owner, lease_epoch)?;
        if let Some(stored_request) = transaction
            .query_row(
                "SELECT request_json FROM task_transitions WHERE transition_id = ?1",
                [&request.transition_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            if stored_request == request_json {
                return authenticated_transition_result(&transaction, &request.transition_id);
            }
            let observed = load_observed(&transaction, &request.task_id)?;
            return Ok(rejected(
                request,
                "TASK_TRANSITION_ID_REUSE_CONFLICT",
                observed,
                &resulted_at,
            ));
        }

        let Some((revision, state, waiting_json, steps_json, failure_json, active_program)) =
            load_transition_state(&transaction, &request.task_id)?
        else {
            let result = rejected(request, "TASK_NOT_FOUND", None, &resulted_at);
            persist_rejection(&transaction, request, &request_json, &result, &resulted_at)?;
            if let Some(fresh) = &locked_time {
                fresh.commit_in(&transaction)?.require_trusted_time()?;
            }
            transaction.commit()?;
            return Ok(result);
        };
        let observed_state = TaskState::parse(&state)?;
        let observed_revision = u64::try_from(revision)
            .map_err(|_| TaskManagerError::InvalidRecord("stored revision is invalid"))?;
        let observed = Some((observed_state, observed_revision));
        let rejection = if request.expected_revision != observed_revision {
            Some("TASK_REVISION_CONFLICT")
        } else if request.expected_state != observed_state {
            Some("TASK_STATE_CONFLICT")
        } else if observed_state.terminal()
            && !(observed_state == TaskState::Failed && request.to_state == TaskState::RollingBack)
        {
            Some("TASK_TERMINAL_STATE")
        } else if !allowed_transition(observed_state, request.to_state) {
            Some("TASK_ILLEGAL_TRANSITION")
        } else {
            guard_failure(
                &transaction,
                request,
                &waiting_json,
                &steps_json,
                active_program,
                &resulted_at,
                internal_recovery,
            )?
        };
        if let Some(code) = rejection {
            let result = rejected(request, code, observed, &resulted_at);
            persist_rejection(&transaction, request, &request_json, &result, &resulted_at)?;
            if let Some(fresh) = &locked_time {
                fresh.commit_in(&transaction)?.require_trusted_time()?;
            }
            transaction.commit()?;
            return Ok(result);
        }

        let new_revision = observed_revision
            .checked_add(1)
            .ok_or(TaskManagerError::InvalidRecord("Task revision overflow"))?;
        let active_steps: Vec<String> = serde_json::from_str(&steps_json)?;
        if request.to_state == TaskState::Running
            && !admit_active_steps(&transaction, &request.task_id, &active_steps, &resulted_at)?
        {
            let result = rejected(
                request,
                "TASK_TRANSITION_GUARD_FAILED",
                observed,
                &resulted_at,
            );
            transaction.rollback()?;
            if let Some(fresh) = locked_time.take() {
                fresh.commit(&self.connection)?;
            }
            let rejection_transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            assert_manager_lease(&rejection_transaction, &lease_owner, lease_epoch)?;
            persist_rejection(
                &rejection_transaction,
                request,
                &request_json,
                &result,
                &resulted_at,
            )?;
            rejection_transaction.commit()?;
            return Ok(result);
        }
        let waiting = match &request.mutation.waiting_on {
            Some(waiting) => serde_json::to_string(waiting)?,
            None => waiting_json,
        };
        let steps = match &request.mutation.active_step_ids {
            Some(steps) => serde_json::to_string(steps)?,
            None => steps_json,
        };
        let failure = request
            .mutation
            .failure
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?
            .or(failure_json);
        let recovery = request
            .mutation
            .recovery
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let active_program_row = active_program
            .map(|program_revision| {
                transaction.query_row(
                    "SELECT p.program_id, p.ir_version, p.semantic_hash, p.registry_snapshot_id, p.validation_result_id, v.validated_at, v.validator_id, v.validator_version, p.program_json FROM semantic_program_revisions p LEFT JOIN validation_results v ON v.validation_result_id = p.validation_result_id WHERE p.task_id = ?1 AND p.program_revision = ?2 AND p.status = 'active'",
                    params![request.task_id, program_revision],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, Option<String>>(2)?,
                            row.get::<_, Option<String>>(3)?,
                            row.get::<_, Option<String>>(4)?,
                            row.get::<_, Option<String>>(5)?,
                            row.get::<_, Option<String>>(6)?,
                            row.get::<_, Option<String>>(7)?,
                            row.get::<_, String>(8)?,
                        ))
                    },
                )
            })
            .transpose()?;
        let active_program_event = active_program_row
            .map(
                |(
                    program_id,
                    ir_version,
                    semantic_hash,
                    registry_snapshot_id,
                    validation_result_id,
                    validated_at,
                    validator_id,
                    validator_version,
                    program_json,
                )|
                 -> Result<Value> {
                    Ok(json!({
                        "program_id": program_id,
                        "ir_version": ir_version,
                        "semantic_hash": semantic_hash,
                        "registry_snapshot_id": registry_snapshot_id,
                        "validation_result_id": validation_result_id,
                        "validated_at": validated_at,
                        "validator_id": validator_id,
                        "validator_version": validator_version,
                        "program_content_digest": program_content_digest(&program_json)?,
                    }))
                },
            )
            .transpose()?;
        let intent_nonce = transaction.query_row(
            "SELECT intent_commitment_nonce FROM tasks WHERE task_id=?1",
            [&request.task_id],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        if intent_nonce.len() != 32 {
            return Err(TaskManagerError::InvalidRecord(
                "Task provenance commitment nonce is invalid",
            ));
        }
        let provenance_waiting = request
            .mutation
            .waiting_on
            .as_ref()
            .map(|values| provenance_waiting_on(values));
        let waiting_commitments = request
            .mutation
            .waiting_on
            .as_ref()
            .map(|values| provenance_waiting_commitments(values, &intent_nonce));
        let provenance_failure = request.mutation.failure.as_ref().map(provenance_failure);
        let failure_commitment = request
            .mutation
            .failure
            .as_ref()
            .map(|failure| provenance_failure_commitment(failure, &intent_nonce));
        let reason_message_ref = request.reason.message.as_ref().map(|message| {
            task_field_commitment(&intent_nonce, "reason_message", message.as_bytes())
        });
        let event_id = transition_event_id(&request.transition_id);
        let event = json!({
            "schema_version": SCHEMA_VERSION,
            "event_id": event_id,
            "task_id": request.task_id,
            "event_type": "task.transitioned",
            "timestamp": resulted_at,
            "actor": request.requested_by,
            "status": "success",
            "semantic_program_hash": active_program_event.as_ref().and_then(|value| value.get("semantic_hash")),
            "ir_version": active_program_event.as_ref().and_then(|value| value.get("ir_version")),
            "registry_snapshot_id": active_program_event.as_ref().and_then(|value| value.get("registry_snapshot_id")),
            "validation_result_id": active_program_event.as_ref().and_then(|value| value.get("validation_result_id")),
            "task_transition": {
                "transition_id": request.transition_id,
                "previous_state": observed_state,
                "new_state": request.to_state,
                "previous_revision": observed_revision,
                "new_revision": new_revision,
                "reason_code": request.reason.code,
            },
            "committed_mutation": {
                "active_plan": request.mutation.active_plan,
                "active_step_ids": request.mutation.active_step_ids,
                "waiting_on": provenance_waiting,
                "failure": provenance_failure,
                "recovery": request.mutation.recovery,
            },
            "details": {
                "related_ids": request.reason.related_ids,
                "reason_message_ref": reason_message_ref,
                "active_program": active_program_event,
                "mutation_text_commitments": {
                    "waiting_on": waiting_commitments,
                    "failure_summary": failure_commitment,
                }
            }
        });
        if fail_provenance {
            return Ok(rejected(
                request,
                "TASK_PROVENANCE_APPEND_FAILED",
                observed,
                &resulted_at,
            ));
        }
        let appended = append_event(&transaction, &request.task_id, &event)?;
        let completed_at = request.to_state == TaskState::Completed;
        let updated = transaction.execute(
            "UPDATE tasks SET revision = ?2, state = ?3, state_reason_json = ?4, active_step_ids_json = ?5, waiting_on_json = ?6, failure_json = ?7, recovery_json = COALESCE(?8, recovery_json), updated_at = ?9, completed_at = CASE WHEN ?10 THEN ?9 ELSE completed_at END WHERE task_id = ?1 AND revision = ?11 AND state = ?12",
            params![request.task_id, i64::try_from(new_revision).map_err(|_| TaskManagerError::InvalidRecord("Task revision exceeds SQLite range"))?, request.to_state.as_str(), json!({"code":request.reason.code,"message":request.reason.message,"provenance_event_id":appended.event_id}).to_string(), steps, waiting, failure, recovery, resulted_at, completed_at, revision, state],
        )?;
        if updated != 1 {
            return Ok(rejected(
                request,
                "TASK_REVISION_CONFLICT",
                observed,
                &resulted_at,
            ));
        }
        if let Some(plan) = &request.mutation.active_plan {
            let changed = transaction.execute(
                "UPDATE tasks SET active_plan_revision = ?2 WHERE task_id = ?1 AND EXISTS (SELECT 1 FROM plan_revisions WHERE task_id = ?1 AND plan_revision = ?2 AND plan_id = ?3)",
                params![request.task_id, i64::try_from(plan.revision).map_err(|_| TaskManagerError::InvalidRecord("active plan revision exceeds SQLite range"))?, plan.plan_id],
            )?;
            if changed != 1 {
                return Err(TaskManagerError::InvalidRecord(
                    "active plan mutation does not reference a persisted plan",
                ));
            }
        }
        let result = TransitionResult {
            schema_version: SCHEMA_VERSION.to_owned(),
            transition_id: request.transition_id.clone(),
            task_id: request.task_id.clone(),
            applied: true,
            reason_code: "TASK_TRANSITION_APPLIED".to_owned(),
            message: None,
            previous_state: Some(observed_state),
            current_state: Some(request.to_state),
            previous_revision: Some(observed_revision),
            current_revision: Some(new_revision),
            observed_state: Some(request.to_state),
            observed_revision: Some(new_revision),
            provenance_event_id: Some(appended.event_id),
            provenance_event_hash: Some(appended.event_hash),
            resulted_at: resulted_at.clone(),
        };
        transaction.execute(
            "INSERT INTO task_transitions (transition_id, task_id, expected_revision, expected_state, to_state, result_revision, result_state, outcome, reason_code, request_json, result_json, provenance_event_id, requested_at, committed_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?5, 'COMMITTED', ?7, ?8, ?9, ?10, ?11, ?11)",
            params![request.transition_id, request.task_id, i64::try_from(request.expected_revision).unwrap_or(i64::MAX), request.expected_state.as_str(), request.to_state.as_str(), i64::try_from(new_revision).unwrap_or(i64::MAX), result.reason_code, request_json, serde_json::to_string(&result)?, result.provenance_event_id, resulted_at],
        )?;
        if let Some(fresh) = &locked_time {
            fresh.commit_in(&transaction)?.require_trusted_time()?;
        }
        transaction.commit()?;
        Ok(result)
    }

    /// Counts committed provenance events for a Task.
    ///
    /// # Errors
    /// Returns an error when the `SQLite` query or integer conversion fails.
    pub fn provenance_count(&self, task_id: &str) -> Result<u64> {
        let count = self.connection.query_row(
            "SELECT COUNT(*) FROM provenance_events WHERE task_id = ?1",
            [task_id],
            |row| row.get::<_, i64>(0),
        )?;
        u64::try_from(count)
            .map_err(|_| TaskManagerError::InvalidRecord("negative provenance count"))
    }

    /// Verifies the Task's sequence and domain-separated provenance hash chain.
    ///
    /// # Errors
    /// Returns an error when event JSON cannot be read or canonicalized.
    pub fn verify_provenance(&self, task_id: &str) -> Result<bool> {
        verify_provenance_through(&self.connection, task_id, None)
    }

    /// Returns structured, reason-coded verification diagnostics for a Task stream.
    ///
    /// # Errors
    /// Returns an error when the stream identity is invalid or storage cannot be read.
    pub fn verify_provenance_detailed(
        &self,
        task_id: &str,
        checkpoint: Option<&ProvenanceCheckpointExpectation>,
    ) -> Result<ProvenanceVerificationResult> {
        let stream_id = aios_provenance::stream_id(task_id)?;
        let mut result = aios_provenance::verify_stream(
            &self.connection,
            &stream_id,
            None,
            checkpoint,
            &self.clock.now(),
        )?;
        let mismatched_streams = self.connection.query_row(
            "SELECT COUNT(*) FROM provenance_events WHERE task_id=?1 AND (stream_id IS NULL OR stream_id<>?2)",
            params![task_id, stream_id],
            |row| row.get::<_, i64>(0),
        )?;
        if result.valid && mismatched_streams != 0 {
            result.valid = false;
            result
                .diagnostics
                .push(aios_provenance::VerificationDiagnostic {
                    severity: aios_provenance::Severity::Error,
                    code: "PROVENANCE_STREAM_ID_MISMATCH".to_owned(),
                    message: "Task provenance rows do not share the expected stream".to_owned(),
                    sequence: None,
                    event_id: None,
                    related: Vec::new(),
                });
        }
        Ok(result)
    }

    /// Returns the current provenance head, if the Task has a journal stream.
    ///
    /// # Errors
    /// Returns an error when the stream identity is invalid or storage cannot be read.
    pub fn provenance_head(&self, task_id: &str) -> Result<Option<ProvenanceStreamHead>> {
        let stream_id = aios_provenance::stream_id(task_id)?;
        Ok(aios_provenance::get_head(&self.connection, &stream_id)?)
    }

    /// Lists one bounded page of provenance journal records.
    ///
    /// # Errors
    /// Returns an error for invalid bounds, malformed stored records, or storage failure.
    pub fn list_provenance(
        &self,
        task_id: &str,
        after_sequence: Option<u64>,
        limit: u32,
    ) -> Result<ProvenanceRecordPage> {
        let stream_id = aios_provenance::stream_id(task_id)?;
        Ok(aios_provenance::list_events(
            &self.connection,
            &stream_id,
            after_sequence,
            limit,
        )?)
    }

    /// Exports a privacy-redacted projection after checking its Task record and journal.
    ///
    /// # Errors
    /// Returns an error when the stream is invalid, unsafe to export, or cannot be read.
    pub fn export_provenance(&self, task_id: &str) -> Result<ProvenancePortableExport> {
        let stream_id = aios_provenance::stream_id(task_id)?;
        let mut validation_error = None;
        let export = aios_provenance::export_jsonl_with_validation(
            &self.connection,
            &stream_id,
            &self.clock.now(),
            |connection| {
                let (revision, state): (i64, String) = connection
                    .query_row(
                        "SELECT revision, state FROM tasks WHERE task_id = ?1",
                        [task_id],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .map_err(|error| {
                        validation_error = Some(TaskManagerError::Storage(error));
                        aios_provenance::Error::InvalidRecord(
                            "Task security state cannot be read".to_owned(),
                        )
                    })?;
                self.verify_task_head(task_id, revision, &state)
                    .map_err(|error| {
                        validation_error = Some(error);
                        aios_provenance::Error::InvalidRecord(
                            "Task security state does not match committed provenance".to_owned(),
                        )
                    })
            },
        );
        if let Some(error) = validation_error {
            return Err(error);
        }
        Ok(export?)
    }

    fn verify_all_provenance_chains(&self) -> Result<()> {
        let task_ids = {
            let mut statement = self
                .connection
                .prepare("SELECT task_id FROM tasks ORDER BY task_id")?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        for task_id in task_ids {
            if !verify_provenance_through(&self.connection, &task_id, None)? {
                return Err(TaskManagerError::InvalidRecord(
                    "Task provenance chain is missing or invalid before startup reconciliation",
                ));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn transition_with_provenance_failure(
        &mut self,
        request: &TransitionRequest,
    ) -> Result<TransitionResult> {
        self.transition_impl(request, true, false)
    }
}

struct AppendedEvent {
    event_id: String,
    event_hash: String,
}

#[allow(
    clippy::too_many_lines,
    reason = "keeps the authenticated resolution event, operation certainty, and subject assessment in one transaction"
)]
pub(crate) fn reconcile_recovery_subject_in_transaction(
    transaction: &Transaction<'_>,
    recovery_ref: &str,
    inventory_id: &str,
    observed_at: &str,
) -> Result<()> {
    let (task_id, epoch_id) = transaction
        .query_row(
            "SELECT task_id, recovery_epoch_id FROM recovery_assessments WHERE assessment_id=?1 AND subject_kind='task'",
            [recovery_ref],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .ok_or(TaskManagerError::InvalidRecord(
            "recovery reference does not exist",
        ))?;
    let inventoried = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM recovery_unknown_operations WHERE assessment_id=?1 AND operation_id=?2)",
        params![recovery_ref, inventory_id],
        |row| row.get::<_, bool>(0),
    )?;
    let resolution = resolved_recovery_subject(transaction, &task_id, inventory_id)?;
    let Some(resolution) = resolution.filter(|_| inventoried) else {
        return Err(TaskManagerError::InvalidRecord(
            "recovery subject lacks a safe durable outcome",
        ));
    };
    let rows = {
        let mut statement = transaction.prepare(
            "SELECT assessment_id, subject_kind, subject_id, basis_revision, created_at FROM recovery_assessments WHERE task_id=?1 AND recovery_epoch_id=?2 AND subject_kind<>'task'",
        )?;
        let rows = statement.query_map(params![task_id, epoch_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()?
    };
    let Some((assessment_id, subject_kind, subject_id, basis_revision, created_at)) =
        rows.into_iter().find(|(assessment_id, kind, id, _, _)| {
            recovery_subject_inventory_id(kind, id).as_deref() == Some(inventory_id)
                && recovery_subject_assessment_id(recovery_ref, kind, id) == *assessment_id
        })
    else {
        return Err(TaskManagerError::InvalidRecord(
            "recovery subject assessment is missing",
        ));
    };
    let event_id = recovery_resolution_event_id(recovery_ref, inventory_id);
    let existing_event = transaction
        .query_row(
            "SELECT event_json, timestamp FROM provenance_events WHERE task_id=?1 AND event_id=?2",
            params![task_id, event_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let event_timestamp = existing_event
        .as_ref()
        .map_or(observed_at, |(_, timestamp)| timestamp.as_str())
        .to_owned();
    let event = json!({
        "schema_version": SCHEMA_VERSION,
        "event_id": event_id,
        "task_id": task_id,
        "event_type": "execution.completed",
        "timestamp": event_timestamp,
        "actor": {"kind":"system-service","id":"service:recovery"},
        "status": resolution.event_status,
        "details": {
            "recovery_ref":recovery_ref,
            "inventory_id":inventory_id,
            "certainty":resolution.certainty,
            "safe_action":resolution.safe_action,
            "reason_code":resolution.reason_code
        }
    });
    let resolution_event_id = if let Some((stored, _)) = existing_event {
        let stored = aios_provenance::parse_unique_json(&stored)?;
        if stored != event || !verify_provenance_through(transaction, &task_id, None)? {
            return Err(TaskManagerError::InvalidRecord(
                "recovery resolution event identity conflicts with durable provenance",
            ));
        }
        event_id
    } else {
        append_event(transaction, &task_id, &event)?.event_id
    };
    if let Some(operation_id) = inventory_id.strip_prefix("operation:") {
        let terminal_state = match resolution.certainty.as_str() {
            "NOT_STARTED" => Some("CANCELLED"),
            "STARTED_NO_EFFECT" | "FAILED_NO_EFFECT" => Some("FAILED"),
            "COMPLETED" => Some("SUCCEEDED"),
            _ => None,
        };
        if let Some(terminal_state) = terminal_state {
            transaction.execute(
                "UPDATE operations SET state=?3,outcome_certainty=?4,finished_at=COALESCE(finished_at,?5) WHERE task_id=?1 AND operation_id=?2",
                params![task_id, operation_id, terminal_state, resolution.certainty, event_timestamp],
            )?;
        }
    }
    if let Some(attempt_id) = inventory_id.strip_prefix("attempt:") {
        let terminal_state = match resolution.certainty.as_str() {
            "COMPLETED" => Some("SUCCEEDED"),
            "NOT_STARTED" | "STARTED_NO_EFFECT" | "FAILED_NO_EFFECT" => Some("FAILED"),
            _ => None,
        };
        if let Some(terminal_state) = terminal_state {
            let changed = transaction.execute(
                "UPDATE step_executions
                 SET state=?3,outcome_certainty=?4,finished_at=COALESCE(finished_at,?5),updated_at=?5
                 WHERE task_id=?1 AND attempt_id=?2
                   AND (outcome_certainty IS NULL OR outcome_certainty='OUTCOME_UNKNOWN' OR outcome_certainty=?4)",
                params![task_id, attempt_id, terminal_state, resolution.certainty, event_timestamp],
            )?;
            if changed != 1 {
                return Err(TaskManagerError::InvalidRecord(
                    "attempt recovery evidence conflicts with durable step certainty",
                ));
            }
        }
    }
    let new_binding_required = resolution.safe_action == "CREATE_NEW_ATTEMPT";
    let assessment = canonical_json(&json!({
        "schema_version": SCHEMA_VERSION,
        "assessment_id": assessment_id,
        "recovery_epoch_id": epoch_id,
        "task_id": task_id,
        "subject": {"kind":subject_kind,"id":subject_id},
        "certainty":resolution.certainty,
        "evidence":[{"kind":"provenance","ref":resolution_event_id,"observation":"trusted durable recovery observation"}],
        "safe_action":resolution.safe_action,
        "new_binding_required":new_binding_required,
        "external_reconciliation_required":false,
        "reason_codes":[resolution.reason_code],
        "created_at":created_at
    }))?;
    let reason_codes_json = serde_json::to_string(&[resolution.reason_code])?;
    transaction.execute(
        "UPDATE recovery_assessments SET certainty=?2, safe_action=?3, reason_codes_json=?4, assessment_json=?5 WHERE assessment_id=?1 AND basis_revision=?6",
        params![assessment_id, resolution.certainty, resolution.safe_action, reason_codes_json, assessment, basis_revision],
    )?;
    Ok(())
}

fn verify_provenance_through(
    connection: &Connection,
    task_id: &str,
    through_sequence: Option<i64>,
) -> Result<bool> {
    let through_sequence = through_sequence
        .map(u64::try_from)
        .transpose()
        .map_err(|_| TaskManagerError::InvalidRecord("invalid provenance verification sequence"))?;
    let stream_id = aios_provenance::stream_id(task_id)?;
    let mismatched_streams = connection.query_row(
        "SELECT COUNT(*) FROM provenance_events WHERE task_id=?1 AND (stream_id IS NULL OR stream_id<>?2) AND (?3 IS NULL OR sequence<=?3)",
        params![task_id, stream_id, through_sequence.map(|value| i64::try_from(value).unwrap_or(i64::MAX))],
        |row| row.get::<_, i64>(0),
    )?;
    if mismatched_streams != 0 {
        return Ok(false);
    }
    Ok(aios_provenance::verify_stream(
        connection,
        &stream_id,
        through_sequence,
        None,
        "1970-01-01T00:00:00Z",
    )?
    .valid)
}

fn event_string<'a>(event: &'a Value, key: &str) -> Option<&'a str> {
    event.get(key).and_then(Value::as_str)
}

fn append_event(
    transaction: &Transaction<'_>,
    task_id: &str,
    event: &Value,
) -> Result<AppendedEvent> {
    let record = aios_provenance::append_in_tx(
        transaction,
        task_id,
        event,
        &aios_provenance::ExpectedHead::Any,
    )?;
    let event_id = event_string(&record.event, "event_id")
        .expect("validated provenance event has an ID")
        .to_owned();
    Ok(AppendedEvent {
        event_id,
        event_hash: record.event_hash,
    })
}

fn provenance_hash(
    task_id: &str,
    sequence: u64,
    previous: Option<&str>,
    event: &Value,
) -> Result<String> {
    Ok(aios_provenance::hash_record(
        &provenance_stream_id(task_id),
        sequence,
        previous,
        event,
    )?)
}

fn canonical_json<T: Serialize>(value: &T) -> Result<String> {
    let value = serde_json::to_value(value)?;
    let bytes = serde_json_canonicalizer::to_vec(&value)
        .map_err(|error| TaskManagerError::Canonicalization(error.to_string()))?;
    String::from_utf8(bytes)
        .map_err(|_| TaskManagerError::InvalidRecord("canonical JSON is not UTF-8"))
}

fn program_content_digest(program_json: &str) -> Result<String> {
    let value: Value = serde_json::from_str(program_json)?;
    let canonical = serde_json_canonicalizer::to_vec(&value)
        .map_err(|error| TaskManagerError::Canonicalization(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(b"AIOS-TASK-ACTIVE-PROGRAM-CONTENT\0v1\0");
    hasher.update(canonical);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        write!(&mut hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(format!("sha256:{hex}"))
}

fn task_field_commitment(secret_nonce: &[u8], field: &str, bytes: &[u8]) -> Value {
    let mut hasher = Sha256::new();
    hasher.update(b"AIOS-TASK-CREATION-FIELD-COMMITMENT\0v1\0");
    hasher.update(
        u64::try_from(secret_nonce.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hasher.update(secret_nonce);
    hasher.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(field.as_bytes());
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        write!(&mut hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    json!({"kind":"task-field-commitment","version":"v1","algorithm":"sha256-keyed-prefix","field":field,"commitment":format!("sha256:{hex}")})
}

fn provenance_waiting_on(values: &[WaitingOn]) -> Value {
    Value::Array(
        values
            .iter()
            .map(|value| {
                json!({
                    "kind": value.kind,
                    "id": value.id,
                })
            })
            .collect(),
    )
}

fn provenance_waiting_commitments(values: &[WaitingOn], secret_nonce: &[u8]) -> Value {
    Value::Array(
        values
            .iter()
            .map(|value| {
                json!({
                    "kind": value.kind,
                    "id": value.id,
                    "message_ref": value.message.as_ref().map(|message| {
                        task_field_commitment(secret_nonce, "waiting_message", message.as_bytes())
                    })
                })
            })
            .collect(),
    )
}

fn provenance_failure(failure: &FailureRecord) -> Value {
    json!({
        "code": failure.code,
        "step_id": failure.step_id,
        "provider_id": failure.provider_id,
        "execution_binding_id": failure.execution_binding_id,
        "provenance_event_ids": failure.provenance_event_ids,
        "retryable": failure.retryable,
        "safe_to_replan": failure.safe_to_replan,
        "unknown_side_effects": failure.unknown_side_effects,
        "rollback_available": failure.rollback_available,
    })
}

fn provenance_failure_commitment(failure: &FailureRecord, secret_nonce: &[u8]) -> Value {
    task_field_commitment(secret_nonce, "failure_summary", failure.summary.as_bytes())
}

fn reason_code_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            if index == 0 {
                byte.is_ascii_uppercase()
            } else {
                byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'
            }
        })
}

#[allow(
    clippy::too_many_lines,
    reason = "mirrors the closed v0.1 transition-request schema at the storage boundary"
)]
fn validate_transition_request(request: &TransitionRequest, internal_recovery: bool) -> Result<()> {
    let valid_actor = matches!(
        request.requested_by.kind.as_str(),
        "user" | "agent" | "provider" | "system-service" | "policy-engine" | "peer-node"
    );
    let valid_reason = reason_code_valid(&request.reason.code);
    let unique_steps = request
        .mutation
        .active_step_ids
        .as_ref()
        .is_none_or(|values| {
            values
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == values.len()
        });
    let unique_related = request
        .reason
        .related_ids
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        == request.reason.related_ids.len();
    let valid_plan = request.mutation.active_plan.as_ref().is_none_or(|plan| {
        !plan.plan_id.is_empty()
            && plan.plan_id.chars().count() <= 256
            && plan.revision > 0
            && i64::try_from(plan.revision).is_ok()
    });
    let valid_steps = request
        .mutation
        .active_step_ids
        .as_ref()
        .is_none_or(|values| {
            values
                .iter()
                .all(|value| !value.is_empty() && value.chars().count() <= 128)
        });
    let valid_waiting = request.mutation.waiting_on.as_ref().is_none_or(|values| {
        values.iter().all(|value| {
            !value.id.is_empty()
                && value.id.chars().count() <= 256
                && value
                    .message
                    .as_ref()
                    .is_none_or(|message| message.chars().count() <= 2048)
        })
    });
    let valid_failure = request.mutation.failure.as_ref().is_none_or(|failure| {
        reason_code_valid(&failure.code)
            && !failure.summary.is_empty()
            && failure.summary.chars().count() <= 4096
            && failure
                .step_id
                .as_ref()
                .is_none_or(|value| value.chars().count() <= 128)
            && failure
                .provider_id
                .as_ref()
                .is_none_or(|value| value.chars().count() <= 256)
            && failure
                .execution_binding_id
                .as_ref()
                .is_none_or(|value| value.chars().count() <= 256)
            && failure.provenance_event_ids.len() <= 64
            && all_unique(&failure.provenance_event_ids)
            && failure
                .provenance_event_ids
                .iter()
                .all(|value| value.chars().count() <= 256)
    });
    let valid_recovery = request.mutation.recovery.as_ref().is_none_or(|recovery| {
        recovery.unknown_operation_ids.len() <= 128
            && recovery
                .unknown_operation_ids
                .iter()
                .all(|value| value.chars().count() <= 256)
            && recovery
                .unknown_operation_ids
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == recovery.unknown_operation_ids.len()
            && recovery
                .last_known_daemon_instance
                .as_ref()
                .is_none_or(|value| value.chars().count() <= 256)
            && recovery
                .unknown_operations_ref
                .as_ref()
                .is_none_or(|value| !value.is_empty() && value.chars().count() <= 256)
    });
    if request.schema_version != SCHEMA_VERSION
        || request.transition_id.is_empty()
        || request.transition_id.chars().count() > 256
        || (request.transition_id.starts_with("__aios_internal:") && !internal_recovery)
        || (internal_recovery && !request.transition_id.starts_with("__aios_internal:"))
        || request.task_id.is_empty()
        || request.task_id.chars().count() > 256
        || request.expected_revision == 0
        || i64::try_from(request.expected_revision).is_err()
        || !valid_actor
        || request.requested_by.id.is_empty()
        || request.requested_by.id.chars().count() > 256
        || request.reason.code.is_empty()
        || request.reason.code.chars().count() > 128
        || !valid_reason
        || request
            .reason
            .message
            .as_ref()
            .is_some_and(|value| value.chars().count() > 2048)
        || request.reason.related_ids.len() > 32
        || !unique_related
        || request
            .reason
            .related_ids
            .iter()
            .any(|value| value.chars().count() > 512)
        || request
            .mutation
            .active_step_ids
            .as_ref()
            .is_some_and(|values| values.len() > 512)
        || !unique_steps
        || request
            .mutation
            .waiting_on
            .as_ref()
            .is_some_and(|values| values.len() > 64)
        || !valid_plan
        || !valid_steps
        || !valid_waiting
        || !valid_failure
        || !valid_recovery
    {
        return Err(TaskManagerError::InvalidRecord(
            "transition request does not satisfy the v0.1 contract",
        ));
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn recovery_operations_ref(
    task_id: &str,
    revision: u64,
    operation_ids: &[String],
) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"AIOS-RECOVERY-OPERATIONS\0v0.1\0");
    hasher.update(task_id.as_bytes());
    hasher.update(revision.to_be_bytes());
    for operation_id in operation_ids {
        let length = u64::try_from(operation_id.len()).map_err(|_| {
            TaskManagerError::InvalidRecord("recovery operation ID length exceeds hash framing")
        })?;
        hasher.update(length.to_be_bytes());
        hasher.update(operation_id.as_bytes());
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        write!(&mut hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(format!("recovery-operations:sha256:{hex}"))
}

#[derive(Debug, Clone)]
struct RecoveryInventory {
    recovery_ref: String,
    recovery_epoch_id: String,
    task_id: String,
    operation_ids: Vec<String>,
}

fn exact_recovery_inventory(
    connection: &Connection,
    recovery_ref: &str,
) -> Result<Option<RecoveryInventory>> {
    let basis = connection
        .query_row(
            "SELECT recovery_epoch_id,task_id,basis_revision FROM recovery_assessments
             WHERE assessment_id=?1 AND subject_kind='task'",
            [recovery_ref],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((recovery_epoch_id, task_id, basis_revision)) = basis else {
        return Ok(None);
    };
    let basis_revision = u64::try_from(basis_revision)
        .map_err(|_| TaskManagerError::InvalidRecord("recovery basis revision is invalid"))?;
    let operation_ids = query_strings(
        connection,
        "SELECT operation_id FROM recovery_unknown_operations
         WHERE assessment_id=?1 ORDER BY ordinal",
        recovery_ref,
    )?;
    if recovery_operations_ref(&task_id, basis_revision, &operation_ids)? != recovery_ref {
        return Err(TaskManagerError::InvalidRecord(
            "recovery inventory digest does not match its durable contents",
        ));
    }
    Ok(Some(RecoveryInventory {
        recovery_ref: recovery_ref.to_owned(),
        recovery_epoch_id,
        task_id,
        operation_ids,
    }))
}

fn active_recovery_inventory(
    connection: &Connection,
    task_id: &str,
) -> Result<Option<RecoveryInventory>> {
    let root_ref = connection
        .query_row(
            "SELECT json_extract(recovery_json,'$.unknown_operations_ref')
             FROM tasks WHERE task_id=?1 AND state='RECOVERING'",
            [task_id],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten();
    let Some(root_ref) = root_ref else {
        return Ok(None);
    };
    let mut selected = exact_recovery_inventory(connection, &root_ref)?.ok_or(
        TaskManagerError::InvalidRecord("active recovery inventory does not exist"),
    )?;
    let root_set = selected
        .operation_ids
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let candidates = {
        let mut statement = connection.prepare(
            "SELECT assessment_id FROM recovery_assessments
             WHERE task_id=?1 AND subject_kind='task' AND recovery_epoch_id=?2
             ORDER BY assessment_id",
        )?;
        let rows = statement.query_map(params![task_id, selected.recovery_epoch_id], |row| {
            row.get::<_, String>(0)
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()?
    };
    let mut selected_set = root_set.clone();
    for candidate_ref in candidates {
        let candidate = exact_recovery_inventory(connection, &candidate_ref)?.ok_or(
            TaskManagerError::InvalidRecord("active recovery inventory does not exist"),
        )?;
        let candidate_set = candidate
            .operation_ids
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        if !root_set.is_subset(&candidate_set) {
            continue;
        }
        if selected_set.is_subset(&candidate_set) {
            selected = candidate;
            selected_set = candidate_set;
        } else if !candidate_set.is_subset(&selected_set) {
            return Err(TaskManagerError::InvalidRecord(
                "active recovery inventories are not monotonic",
            ));
        }
    }
    Ok(Some(selected))
}

fn startup_recovery_transition_id(task_id: &str, revision: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"AIOS-STARTUP-RECOVERY-TRANSITION\0v0.1\0");
    hasher.update(task_id.as_bytes());
    hasher.update(revision.to_be_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        write!(&mut hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    format!("__aios_internal:startup-recovery:sha256:{hex}")
}

fn live_recovery_transition_id(task_id: &str, revision: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"AIOS-LIVE-RECOVERY-TRANSITION\0v0.1\0");
    hasher.update(task_id.as_bytes());
    hasher.update(revision.to_be_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        write!(&mut hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    format!("__aios_internal:live-recovery:sha256:{hex}")
}

fn hashed_event_id(prefix: &str, domain: &[u8], identity: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(identity.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        write!(&mut hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    format!("{prefix}{hex}")
}

fn transition_event_id(transition_id: &str) -> String {
    hashed_event_id(
        "event:transition:v1:sha256:",
        b"AIOS-TASK-TRANSITION-EVENT-ID\0v1\0",
        transition_id,
    )
}

fn attempt_admitted_event_id(attempt_id: &str, binding_id: &str) -> String {
    let framed = format!(
        "{}:{attempt_id}{}:{binding_id}",
        attempt_id.len(),
        binding_id.len()
    );
    hashed_event_id(
        "event:attempt-admitted:v1:sha256:",
        b"AIOS-ATTEMPT-ADMITTED-EVENT-ID\0v1\0",
        &framed,
    )
}

fn recovery_resolution_event_id(recovery_ref: &str, inventory_id: &str) -> String {
    let identity = format!(
        "{}:{recovery_ref}{}:{inventory_id}",
        recovery_ref.len(),
        inventory_id.len()
    );
    hashed_event_id(
        "event:recovery-resolution:v1:sha256:",
        b"AIOS-RECOVERY-RESOLUTION-EVENT-ID\0v1\0",
        &identity,
    )
}

fn task_created_event_id(task_id: &str) -> String {
    hashed_event_id(
        "event:task-created:v1:sha256:",
        b"AIOS-TASK-CREATED-EVENT-ID\0v1\0",
        task_id,
    )
}

fn provenance_stream_id(task_id: &str) -> String {
    aios_provenance::stream_id(task_id).expect("validated Task ID forms a provenance stream")
}

const SEMANTIC_ADDITIVE_GUARDS: &[&str] = &[
    "one_way_registry_snapshot_admissions_update",
    "immutable_registry_snapshot_admissions_reinsert",
    "immutable_admitted_registry_snapshots_reinsert",
    "immutable_admitted_registry_snapshots_target_update",
    "immutable_semantic_type_contracts_reinsert",
    "immutable_semantic_capability_contracts_reinsert",
    "immutable_registry_snapshot_entries_reinsert",
    "immutable_admitted_registry_snapshot_entries_insert",
    "registry_activation_no_duplicate_insert",
    "registry_activation_revision_monotonic",
    "registry_activation_no_delete",
];

const SEMANTIC_LEGACY_GUARDS: &[&str] = &[
    "immutable_admitted_registry_snapshots_update",
    "immutable_admitted_registry_snapshots_delete",
    "immutable_semantic_type_contracts_update",
    "immutable_semantic_type_contracts_delete",
    "immutable_semantic_capability_contracts_update",
    "immutable_semantic_capability_contracts_delete",
    "immutable_registry_snapshot_entries_update",
    "immutable_registry_snapshot_entries_delete",
    "immutable_registry_snapshot_admissions_delete",
];

const SEMANTIC_FENCE_GUARDS: &[&str] = &[
    "semantic_repair_fence_no_update",
    "semantic_repair_fence_no_delete",
    "semantic_repair_fence_no_duplicate_insert",
    "semantic_repair_fence_sequence",
    "semantic_terminal_admission_no_update",
    "semantic_terminal_admission_no_delete",
    "semantic_terminal_admission_no_duplicate_insert",
    "semantic_terminal_admission_insert",
    "semantic_terminal_admission_transition",
    "semantic_legacy_unprovable_no_update",
    "semantic_legacy_unprovable_no_delete",
    "semantic_legacy_unprovable_no_duplicate_insert",
    "semantic_invalidated_activation_no_update",
    "semantic_invalidated_activation_no_delete",
    "semantic_invalidated_activation_no_duplicate_insert",
    "semantic_activation_scope_history_no_update",
    "semantic_activation_scope_history_no_delete",
    "semantic_activation_scope_history_no_duplicate_insert",
    "semantic_activation_scope_history_insert",
    "semantic_activation_scope_history_key_update",
    "semantic_legacy_activation_quarantine_no_update",
    "semantic_legacy_activation_quarantine_no_delete",
    "semantic_legacy_activation_quarantine_no_duplicate_insert",
    "semantic_snapshot_reattestation_no_update",
    "semantic_snapshot_reattestation_no_delete",
    "semantic_snapshot_reattestation_no_duplicate_insert",
    "semantic_snapshot_reattestation_current_only",
    "semantic_repair_activation_insert",
    "semantic_repair_activation_update",
    "semantic_repair_registration_insert",
    "semantic_repair_registration_enable",
    "semantic_repair_binding_insert",
];

const PROVIDER_ADDITIVE_GUARDS: &[&str] = &[
    "provider_registration_no_duplicate_insert",
    "provider_registration_revoked_epoch_insert",
    "provider_registration_revoked_epoch_update",
    "provider_manifest_payload_no_duplicate_insert",
    "provider_evidence_no_duplicate_insert",
    "execution_binding_no_duplicate_insert",
    "execution_binding_provider_identity_at_insert",
    "execution_binding_evidence_present_at_insert",
    "execution_binding_admission_marker_insert",
    "execution_binding_marker_no_duplicate_insert",
    "execution_binding_marker_no_update",
    "execution_binding_marker_no_delete",
    "provider_registration_trust_receipt_insert",
    "provider_registration_trust_immutable_update",
    "provider_registration_no_initial_enablement",
    "provider_registration_state_transition_clock",
    "provider_registration_updated_at_requires_transition",
    "provider_state_epoch_no_update",
    "provider_state_epoch_no_delete",
    "provider_state_epoch_no_duplicate_insert",
    "provider_state_epoch_event_insert_guard",
    "provider_state_epoch_initial",
    "provider_state_epoch_transition",
    "provider_trust_admission_no_update",
    "provider_trust_admission_no_delete",
    "provider_trust_admission_no_duplicate_insert",
    "provider_trust_admission_receipt_insert",
    "execution_binding_evidence_pin_required",
    "execution_binding_evidence_not_future",
    "execution_binding_evidence_unexpired_at_insert",
    "execution_binding_enablement_marker_no_update",
    "execution_binding_enablement_marker_no_delete",
    "execution_binding_enablement_marker_no_duplicate_insert",
    "execution_binding_enablement_marker_insert",
    "execution_binding_evidence_latest_at_insert",
    "execution_binding_provider_enablement_not_future",
    "execution_binding_trust_marker_no_update",
    "execution_binding_trust_marker_no_delete",
    "execution_binding_trust_marker_no_duplicate_insert",
    "execution_binding_trust_marker_insert",
    "execution_binding_trust_not_future",
    "execution_binding_legacy_trust_quarantine_no_update",
    "execution_binding_legacy_trust_quarantine_no_delete",
    "execution_binding_legacy_trust_quarantine_no_duplicate_insert",
];

// Loss of any of these guards can rewrite the provider state ledger or erase
// a terminal transition. A stamped store cannot reconstruct that history.
const PROVIDER_HISTORY_GUARDS: &[&str] = &[
    "provider_registration_identity_immutable",
    "provider_registration_no_delete",
    "provider_registration_no_duplicate_insert",
    "provider_registration_revocation_terminal",
    "provider_registration_revoked_epoch_insert",
    "provider_registration_revoked_epoch_update",
    "provider_registration_no_initial_enablement",
    "provider_registration_state_transition_clock",
    "provider_registration_updated_at_requires_transition",
    "provider_state_epoch_no_update",
    "provider_state_epoch_no_delete",
    "provider_state_epoch_no_duplicate_insert",
    "provider_state_epoch_event_insert_guard",
    "provider_state_epoch_initial",
    "provider_state_epoch_transition",
];

// These guards authenticate evidence and review decisions used by *future*
// bindings. Restoring a lost guard cannot distinguish an original row from
// one replaced or rewritten while the guard was absent. Quarantining only
// historical bindings would leave that forged authority reusable.
const PROVIDER_AUTHORITY_HISTORY_GUARDS: &[&str] = &[
    "provider_evidence_no_duplicate_insert",
    "provider_registration_trust_receipt_insert",
    "provider_registration_trust_immutable_update",
    "provider_trust_admission_no_update",
    "provider_trust_admission_no_delete",
    "provider_trust_admission_no_duplicate_insert",
    "provider_trust_admission_receipt_insert",
];

const PROVIDER_LEGACY_GUARDS: &[&str] = &[
    "provider_manifest_payload_immutable_update",
    "provider_manifest_payload_immutable_delete",
    "provider_registration_identity_immutable",
    "provider_registration_no_delete",
    "provider_registration_revocation_terminal",
    "provider_evidence_immutable_update",
    "provider_evidence_immutable_delete",
];

const PRIOR_PROVIDER_TRUST_GUARDS: &[&str] = &[
    "execution_binding_trust_marker_insert",
    "execution_binding_trust_not_future",
];

const PRIOR_PROVIDER_C5A_GUARDS: &[&str] = &[
    "provider_registration_state_transition_clock",
    "provider_state_epoch_event_insert_guard",
    "provider_state_epoch_transition",
    "execution_binding_evidence_not_future",
    "execution_binding_evidence_unexpired_at_insert",
    "execution_binding_evidence_latest_at_insert",
    "execution_binding_trust_marker_insert",
    "execution_binding_trust_not_future",
    "execution_binding_provider_enablement_not_future",
];

const PRIOR_PROVIDER_2B1_EVIDENCE_GUARDS: &[&str] = &[
    "execution_binding_evidence_present_at_insert",
    "execution_binding_evidence_not_future",
    "execution_binding_evidence_unexpired_at_insert",
    "execution_binding_evidence_latest_at_insert",
];

fn missing_additive_guard(connection: &Connection, guards: &[&str]) -> Result<bool> {
    for guard in guards {
        let present: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='trigger' AND name=?1)",
            [guard],
            |row| row.get(0),
        )?;
        if !present {
            return Ok(true);
        }
    }
    Ok(false)
}

fn provider_history_provable(connection: &Connection) -> Result<bool> {
    if !additive_guard_definitions_current(connection, PROVIDER_HISTORY_GUARDS, true, true, true)? {
        return Ok(false);
    }
    let canonical = Connection::open_in_memory()?;
    canonical.execute_batch(include_str!("../../../specs/persistence-v0.1.sql"))?;
    canonical.execute_batch(include_str!(
        "../../../specs/persistence-v0.1-0012-semantic-registry.sql"
    ))?;
    canonical.execute_batch(include_str!(
        "../../../specs/persistence-v0.1-0013-provider-registry.sql"
    ))?;
    let actual: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='provider_state_epochs'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let expected: String = canonical.query_row(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='provider_state_epochs'",
        [],
        |row| row.get(0),
    )?;
    Ok(actual.is_some_and(|sql| normalize_schema_sql(&sql) == normalize_schema_sql(&expected)))
}

fn provider_authority_history_provable(connection: &Connection) -> Result<bool> {
    let other_guards: Vec<&str> = PROVIDER_AUTHORITY_HISTORY_GUARDS
        .iter()
        .copied()
        .filter(|guard| *guard != "provider_trust_admission_receipt_insert")
        .collect();
    if !additive_guard_definitions_current(connection, &other_guards, true, true, true)? {
        return Ok(false);
    }
    if additive_guard_definitions_current(
        connection,
        &["provider_trust_admission_receipt_insert"],
        true,
        true,
        true,
    )? {
        return Ok(true);
    }
    if !legacy_b0b_trust_admission_guard_present(connection)? {
        return Ok(false);
    }
    // The old guard did not authenticate receipt identity or chronology.
    // An existing immutable decision could have been forged while it ran.
    connection
        .query_row(
            "SELECT NOT EXISTS(SELECT 1 FROM provider_trust_admissions)",
            [],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

fn legacy_b0b_trust_admission_guard_present(connection: &Connection) -> Result<bool> {
    let actual: Option<String> = connection.query_row(
        "SELECT sql FROM sqlite_master WHERE type='trigger' AND name='provider_trust_admission_receipt_insert'",
        [],
        |row| row.get(0),
    ).optional()?;
    let Some(actual) = actual else {
        return Ok(false);
    };
    let canonical = Connection::open_in_memory()?;
    canonical.execute_batch("CREATE TABLE provider_trust_admissions(registration_id TEXT)")?;
    canonical.execute_batch(include_str!(
        "legacy_b0b7302_provider_trust_admission_guard.sql"
    ))?;
    let expected: String = canonical.query_row(
        "SELECT sql FROM sqlite_master WHERE type='trigger' AND name='provider_trust_admission_receipt_insert'",
        [],
        |row| row.get(0),
    )?;
    Ok(normalize_schema_sql(&actual) == normalize_schema_sql(&expected))
}

#[allow(
    clippy::too_many_lines,
    reason = "keeps fenced semantic and provider guard repairs in one atomic transaction"
)]
fn upgrade_stamped_registry_guards_fenced(
    connection: &mut Connection,
    owner: &str,
    epoch: i64,
    upgraded_at: &str,
) -> Result<()> {
    let has_migrations: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations')",
        [],
        |row| row.get(0),
    )?;
    if !has_migrations {
        return Ok(());
    }
    let semantic_stamped: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE migration_id='0012_semantic_registry_store')",
        [],
        |row| row.get(0),
    )?;
    let provider_stamped: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE migration_id='0013_provider_registry')",
        [],
        |row| row.get(0),
    )?;
    if provider_stamped && !provider_history_provable(connection)? {
        return Err(TaskManagerError::InvalidRecord(
            "provider state history requires operator quarantine",
        ));
    }
    if provider_stamped && !provider_authority_history_provable(connection)? {
        return Err(TaskManagerError::InvalidRecord(
            "provider evidence or trust history requires operator quarantine",
        ));
    }
    let fence_stamped: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE migration_id='0014_semantic_repair_fence')",
        [],
        |row| row.get(0),
    )?;
    let upgrade_semantic =
        semantic_stamped && missing_additive_guard(connection, SEMANTIC_ADDITIVE_GUARDS)?;
    let legacy_terminal_history_unprovable = semantic_stamped
        && !fence_stamped
        && missing_additive_guard(
            connection,
            &[
                "one_way_registry_snapshot_admissions_update",
                "immutable_registry_snapshot_admissions_reinsert",
            ],
        )?;
    let legacy_activation_history_unprovable = semantic_stamped
        && !fence_stamped
        && missing_additive_guard(
            connection,
            &[
                "registry_activation_no_duplicate_insert",
                "registry_activation_revision_monotonic",
                "registry_activation_no_delete",
            ],
        )?;
    let upgrade_provider = provider_stamped
        && (missing_additive_guard(connection, PROVIDER_ADDITIVE_GUARDS)?
            || !provider_additive_tables_current(connection, true, true)?
            || legacy_b0b_trust_admission_guard_present(connection)?
            || legacy_provider_trust_guard_present(connection)?
            || legacy_c5a_provider_guard_present(connection)?
            || legacy_2b1_evidence_guard_present(connection)?);
    if !upgrade_semantic && !upgrade_provider && (fence_stamped || !semantic_stamped) {
        return Ok(());
    }
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    assert_manager_lease(&transaction, owner, epoch)?;
    if semantic_stamped && !fence_stamped {
        // Only a canonical earlier 0012 store may acquire the new stamp.
        // A partial 0014 installation is an anti-downgrade failure, not a
        // generation-zero bootstrap.
        if !semantic_fence_objects_current(&transaction, false)? {
            return Err(TaskManagerError::InvalidRecord(
                "unstamped semantic repair fence requires operator quarantine",
            ));
        }
        transaction.execute_batch(include_str!(
            "../../../specs/persistence-v0.1-0014-semantic-repair-fence.sql"
        ))?;
        transaction.execute(
            "INSERT INTO schema_migrations(migration_id,checksum,applied_at)
             VALUES ('0014_semantic_repair_fence','semantic-repair-fence-v0.1',?1)",
            [upgraded_at],
        )?;
        if legacy_terminal_history_unprovable {
            // No Stage-1 fact can distinguish a previously terminal row
            // forged back to ADMITTED before the first fence existed.
            transaction.execute(
                "INSERT INTO semantic_legacy_unprovable_admissions(snapshot_id)
                 SELECT snapshot_id FROM registry_snapshot_admissions",
                [],
            )?;
        }
        if legacy_activation_history_unprovable {
            transaction.execute(
                "INSERT INTO semantic_legacy_activation_quarantine(singleton_id,reason)
                 VALUES (1,'UNPROVABLE_PRE_0014_HISTORY')",
                [],
            )?;
        }
    }
    if upgrade_semantic {
        // Historical admission transitions are unprovable. Rotate the
        // append-only fence; old receipts no longer authorize work, while
        // terminal QUARANTINED/REVOKED projections remain terminal.
        let current: i64 = transaction.query_row(
            "SELECT MAX(generation) FROM semantic_repair_fences",
            [],
            |row| row.get(0),
        )?;
        if current >= i64::MAX - 1 {
            return Err(TaskManagerError::InvalidRecord(
                "semantic repair fence generation requires operator quarantine",
            ));
        }
        transaction.execute(
            "INSERT INTO semantic_repair_fences(generation,reason,created_at)
             VALUES (?1,'GUARD_REPAIR',?2)",
            params![current + 1, upgraded_at],
        )?;
        transaction.execute(
            "INSERT INTO semantic_invalidated_activation_scopes(scope_kind,scope_id)
             SELECT h.scope_kind,h.scope_id FROM semantic_activation_scope_history h
             WHERE NOT EXISTS (SELECT 1 FROM semantic_invalidated_activation_scopes q
                               WHERE q.scope_kind=h.scope_kind AND q.scope_id=h.scope_id)",
            [],
        )?;
        transaction.execute_batch(include_str!(
            "../../../specs/persistence-v0.1-0012-semantic-registry.sql"
        ))?;
    }
    if upgrade_provider {
        if legacy_b0b_trust_admission_guard_present(&transaction)? {
            transaction.execute_batch("DROP TRIGGER provider_trust_admission_receipt_insert")?;
        }
        let has_epoch_table: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master
             WHERE type='table' AND name='provider_state_epochs')",
            [],
            |row| row.get(0),
        )?;
        if has_epoch_table {
            let exhausted: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM provider_state_epochs
                 WHERE typeof(revision)<>'integer' OR revision>=?1)",
                [i64::MAX - 1],
                |row| row.get(0),
            )?;
            if exhausted {
                return Err(TaskManagerError::InvalidRecord(
                    "provider state epoch revision requires operator quarantine",
                ));
            }
        }
        let had_enablement_guards = !missing_additive_guard(
            &transaction,
            &[
                "provider_registration_no_initial_enablement",
                "provider_registration_state_transition_clock",
                "provider_registration_updated_at_requires_transition",
                "provider_state_epoch_no_update",
                "provider_state_epoch_no_delete",
                "provider_state_epoch_no_duplicate_insert",
                "provider_state_epoch_event_insert_guard",
                "provider_state_epoch_initial",
                "provider_state_epoch_transition",
                "execution_binding_enablement_marker_no_update",
                "execution_binding_enablement_marker_no_delete",
                "execution_binding_enablement_marker_no_duplicate_insert",
                "execution_binding_enablement_marker_insert",
            ],
        )? && transaction.query_row(
            "SELECT (SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN
                ('provider_state_epochs','execution_binding_enablement_markers'))=2",
            [],
            |row| row.get::<_, bool>(0),
        )?;
        for name in PRIOR_PROVIDER_TRUST_GUARDS {
            let actual: Option<String> = transaction
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                    [name],
                    |row| row.get(0),
                )
                .optional()?;
            if actual
                .as_deref()
                .map(|sql| legacy_provider_trust_guard_matches(name, sql))
                .transpose()?
                .unwrap_or(false)
            {
                transaction.execute_batch(match *name {
                    "execution_binding_trust_marker_insert" => {
                        "DROP TRIGGER execution_binding_trust_marker_insert"
                    }
                    _ => "DROP TRIGGER execution_binding_trust_not_future",
                })?;
            }
        }
        for name in PRIOR_PROVIDER_C5A_GUARDS {
            let actual: Option<String> = transaction
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                    [name],
                    |row| row.get(0),
                )
                .optional()?;
            if actual
                .as_deref()
                .map(|sql| legacy_c5a_provider_guard_matches(name, sql))
                .transpose()?
                .unwrap_or(false)
            {
                transaction.execute_batch(&format!("DROP TRIGGER {name}"))?;
            }
        }
        for name in PRIOR_PROVIDER_2B1_EVIDENCE_GUARDS {
            let actual: Option<String> = transaction
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                    [name],
                    |row| row.get(0),
                )
                .optional()?;
            if actual
                .as_deref()
                .map(|sql| legacy_2b1_evidence_guard_matches(name, sql))
                .transpose()?
                .unwrap_or(false)
            {
                transaction.execute_batch(&format!("DROP TRIGGER {name}"))?;
            }
        }
        if !had_enablement_guards {
            // Older stamped stores cannot prove when an active registration
            // became enabled. End that interval while still under the lease,
            // before installing the new clock guard: legacy updated_at may
            // itself be untrusted or later than the current clock. A partial
            // upgrade may already have installed that exact guard.
            transaction.execute_batch(
                "DROP TRIGGER IF EXISTS provider_registration_state_transition_clock;
                 DROP TRIGGER IF EXISTS provider_state_epoch_transition",
            )?;
            transaction.execute(
                "UPDATE provider_registrations SET state='disabled',updated_at=?1
                 WHERE state='registered'",
                [upgraded_at],
            )?;
        }
        if has_epoch_table {
            // A missing duplicate-insert or initial-epoch guard once allowed
            // INSERT OR REPLACE to obscure the registration row. The ledger's
            // terminal revocation still wins over the replacement's state.
            transaction.execute_batch(
                "DROP TRIGGER IF EXISTS provider_registration_state_transition_clock;
                 DROP TRIGGER IF EXISTS provider_state_epoch_transition",
            )?;
            transaction.execute(
                "UPDATE provider_registrations SET state='revoked',updated_at=
                     CASE WHEN (SELECT e.state FROM provider_state_epochs e
                                WHERE e.registration_id=provider_registrations.registration_id
                                ORDER BY e.revision DESC LIMIT 1)='revoked'
                          THEN (SELECT e.transitioned_at FROM provider_state_epochs e
                                WHERE e.registration_id=provider_registrations.registration_id
                                ORDER BY e.revision DESC LIMIT 1)
                          ELSE ?1 END
                 WHERE state<>'revoked' AND EXISTS (
                     SELECT 1 FROM provider_state_epochs e
                     WHERE e.registration_id=provider_registrations.registration_id
                       AND e.state='revoked')",
                [upgraded_at],
            )?;
        }
        transaction.execute_batch(include_str!(
            "../../../specs/persistence-v0.1-0013-provider-registry.sql"
        ))?;
        if has_epoch_table {
            transaction.execute(
                "INSERT INTO provider_state_epochs(registration_id,revision,state,transitioned_at)
                 SELECT r.registration_id,
                        (SELECT MAX(e.revision)+1 FROM provider_state_epochs e
                         WHERE e.registration_id=r.registration_id),
                        'revoked',r.updated_at
                 FROM provider_registrations r
                 WHERE r.state='revoked'
                   AND EXISTS (SELECT 1 FROM provider_state_epochs e
                               WHERE e.registration_id=r.registration_id AND e.state='revoked')
                   AND (SELECT e.state FROM provider_state_epochs e
                        WHERE e.registration_id=r.registration_id
                        ORDER BY e.revision DESC LIMIT 1)<>'revoked'",
                [],
            )?;
        }
        if !had_enablement_guards {
            // A partially installed ledger may have missed the forced
            // disable transition. Reconcile only that terminal interval;
            // subsequent enables must mint a fresh revision normally.
            transaction.execute(
                "INSERT INTO provider_state_epochs(registration_id,revision,state,transitioned_at)
                 SELECT r.registration_id,
                        (SELECT MAX(e.revision)+1 FROM provider_state_epochs e
                         WHERE e.registration_id=r.registration_id),
                        'disabled',r.updated_at
                 FROM provider_registrations r
                 WHERE r.state='disabled'
                   AND EXISTS (SELECT 1 FROM provider_state_epochs e
                               WHERE e.registration_id=r.registration_id)
                   AND (SELECT e.state FROM provider_state_epochs e
                        WHERE e.registration_id=r.registration_id
                        ORDER BY e.revision DESC LIMIT 1) <> 'disabled'",
                [],
            )?;
        }
        // Any repaired provider guard means historical binding admission was
        // not fully proven. Preserve immutable markers for audit and deny
        // their execution, including a store missing only one binding guard.
        transaction.execute(
            "INSERT INTO execution_binding_legacy_trust_quarantine(binding_id)
                 SELECT m.binding_id FROM execution_binding_trust_markers m
                 WHERE NOT EXISTS (
                     SELECT 1 FROM execution_binding_legacy_trust_quarantine q
                     WHERE q.binding_id=m.binding_id
                 )",
            [],
        )?;
    }
    if upgrade_semantic && provider_stamped && !upgrade_provider {
        // Semantic guard loss also invalidates any prior provider bindings.
        transaction.execute(
            "INSERT INTO execution_binding_legacy_trust_quarantine(binding_id)
             SELECT m.binding_id FROM execution_binding_trust_markers m
             WHERE NOT EXISTS (
                 SELECT 1 FROM execution_binding_legacy_trust_quarantine q
                 WHERE q.binding_id=m.binding_id
             )",
            [],
        )?;
    }
    preflight_migration_state(&transaction)?;
    assert_manager_lease(&transaction, owner, epoch)?;
    transaction.commit()?;
    Ok(())
}

fn additive_guard_definitions_current(
    connection: &Connection,
    guards: &[&str],
    stamped: bool,
    require_all: bool,
    provider: bool,
) -> Result<bool> {
    let mut found = Vec::with_capacity(guards.len());
    for guard in guards {
        found.push(
            connection
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                    [guard],
                    |row| row.get::<_, String>(0),
                )
                .optional()?,
        );
    }
    if !stamped {
        return Ok(found.iter().all(Option::is_none));
    }
    if require_all && found.iter().any(Option::is_none) {
        return Ok(false);
    }
    let canonical = Connection::open_in_memory()?;
    canonical.execute_batch(include_str!("../../../specs/persistence-v0.1.sql"))?;
    canonical.execute_batch(include_str!(
        "../../../specs/persistence-v0.1-0012-semantic-registry.sql"
    ))?;
    if provider {
        canonical.execute_batch(include_str!(
            "../../../specs/persistence-v0.1-0013-provider-registry.sql"
        ))?;
    }
    for (guard, actual) in guards.iter().zip(found) {
        let Some(actual) = actual else { continue };
        let expected: String = canonical.query_row(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
            [guard],
            |row| row.get(0),
        )?;
        // SQLite preserves the SQL text but old stores may cross a platform's
        // line-ending convention. Whitespace changes do not alter this DDL.
        if normalize_schema_sql(&actual) != normalize_schema_sql(&expected)
            && !(provider && !require_all && legacy_provider_trust_guard_matches(guard, &actual)?)
            && !(provider && !require_all && legacy_c5a_provider_guard_matches(guard, &actual)?)
            && !(provider && !require_all && legacy_2b1_evidence_guard_matches(guard, &actual)?)
            && !(provider
                && !require_all
                && *guard == "provider_trust_admission_receipt_insert"
                && legacy_b0b_trust_admission_guard_present(connection)?)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn normalize_schema_sql(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn legacy_provider_trust_guard_definition(name: &str) -> Result<String> {
    let canonical = Connection::open_in_memory()?;
    canonical.execute_batch(include_str!("../../../specs/persistence-v0.1.sql"))?;
    canonical.execute_batch(include_str!(
        "../../../specs/persistence-v0.1-0012-semantic-registry.sql"
    ))?;
    canonical.execute_batch(include_str!(
        "../../../specs/persistence-v0.1-0013-provider-registry.sql"
    ))?;
    canonical.execute_batch(
        "DROP TRIGGER execution_binding_trust_marker_insert;
         DROP TRIGGER execution_binding_trust_not_future;",
    )?;
    canonical.execute_batch(include_str!("legacy_5eb3b71_provider_trust_guards.sql"))?;
    canonical
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
            [name],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

fn legacy_provider_trust_guard_matches(name: &str, actual: &str) -> Result<bool> {
    if !PRIOR_PROVIDER_TRUST_GUARDS.contains(&name) {
        return Ok(false);
    }
    Ok(normalize_schema_sql(actual)
        == normalize_schema_sql(&legacy_provider_trust_guard_definition(name)?))
}

fn legacy_provider_trust_guard_present(connection: &Connection) -> Result<bool> {
    for name in PRIOR_PROVIDER_TRUST_GUARDS {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                [name],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(actual) = actual {
            if legacy_provider_trust_guard_matches(name, &actual)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn legacy_c5a_provider_guard_definition(name: &str) -> Result<String> {
    let canonical = Connection::open_in_memory()?;
    canonical.execute_batch(include_str!("../../../specs/persistence-v0.1.sql"))?;
    canonical.execute_batch(include_str!(
        "../../../specs/persistence-v0.1-0012-semantic-registry.sql"
    ))?;
    canonical.execute_batch(include_str!("legacy_c5a_provider_registry.sql"))?;
    canonical
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
            [name],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

fn legacy_c5a_provider_guard_matches(name: &str, actual: &str) -> Result<bool> {
    if !PRIOR_PROVIDER_C5A_GUARDS.contains(&name) {
        return Ok(false);
    }
    Ok(normalize_schema_sql(actual)
        == normalize_schema_sql(&legacy_c5a_provider_guard_definition(name)?))
}

fn legacy_c5a_provider_guard_present(connection: &Connection) -> Result<bool> {
    for name in PRIOR_PROVIDER_C5A_GUARDS {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                [name],
                |row| row.get(0),
            )
            .optional()?;
        if actual
            .as_deref()
            .map(|sql| legacy_c5a_provider_guard_matches(name, sql))
            .transpose()?
            .unwrap_or(false)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn legacy_2b1_evidence_guard_definition(name: &str) -> Result<String> {
    let canonical = Connection::open_in_memory()?;
    canonical.execute_batch(include_str!("../../../specs/persistence-v0.1.sql"))?;
    canonical.execute_batch(include_str!(
        "../../../specs/persistence-v0.1-0012-semantic-registry.sql"
    ))?;
    canonical.execute_batch(include_str!(
        "../../../specs/persistence-v0.1-0013-provider-registry.sql"
    ))?;
    for guard in PRIOR_PROVIDER_2B1_EVIDENCE_GUARDS {
        canonical.execute_batch(&format!("DROP TRIGGER {guard}"))?;
    }
    canonical.execute_batch(include_str!("legacy_2b1f8e2_provider_evidence_guards.sql"))?;
    canonical
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
            [name],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

fn legacy_2b1_evidence_guard_matches(name: &str, actual: &str) -> Result<bool> {
    if !PRIOR_PROVIDER_2B1_EVIDENCE_GUARDS.contains(&name) {
        return Ok(false);
    }
    Ok(normalize_schema_sql(actual)
        == normalize_schema_sql(&legacy_2b1_evidence_guard_definition(name)?))
}

fn legacy_2b1_evidence_guard_present(connection: &Connection) -> Result<bool> {
    for name in PRIOR_PROVIDER_2B1_EVIDENCE_GUARDS {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                [name],
                |row| row.get(0),
            )
            .optional()?;
        if actual
            .as_deref()
            .map(|sql| legacy_2b1_evidence_guard_matches(name, sql))
            .transpose()?
            .unwrap_or(false)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn provider_additive_tables_current(
    connection: &Connection,
    stamped: bool,
    require_all: bool,
) -> Result<bool> {
    let canonical = Connection::open_in_memory()?;
    canonical.execute_batch(include_str!("../../../specs/persistence-v0.1.sql"))?;
    canonical.execute_batch(include_str!(
        "../../../specs/persistence-v0.1-0012-semantic-registry.sql"
    ))?;
    canonical.execute_batch(include_str!(
        "../../../specs/persistence-v0.1-0013-provider-registry.sql"
    ))?;
    for name in [
        "provider_manifest_payloads",
        "provider_health_observations",
        "execution_binding_admission_markers",
        "provider_trust_admissions",
        "execution_binding_trust_markers",
        "execution_binding_legacy_trust_quarantine",
        "provider_state_epochs",
        "execution_binding_enablement_markers",
    ] {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
                [name],
                |row| row.get(0),
            )
            .optional()?;
        if !stamped {
            if actual.is_some() {
                return Ok(false);
            }
            continue;
        }
        let Some(actual) = actual else {
            if require_all {
                return Ok(false);
            }
            continue;
        };
        let expected: String = canonical.query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
            [name],
            |row| row.get(0),
        )?;
        if normalize_schema_sql(&actual) != normalize_schema_sql(&expected) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn semantic_fence_objects_current(connection: &Connection, stamped: bool) -> Result<bool> {
    let canonical = Connection::open_in_memory()?;
    canonical.execute_batch(include_str!("../../../specs/persistence-v0.1.sql"))?;
    canonical.execute_batch(include_str!(
        "../../../specs/persistence-v0.1-0012-semantic-registry.sql"
    ))?;
    canonical.execute_batch(include_str!(
        "../../../specs/persistence-v0.1-0014-semantic-repair-fence.sql"
    ))?;
    for (kind, name) in [
        ("table", "semantic_repair_fences"),
        ("table", "semantic_snapshot_reattestations"),
        ("table", "semantic_terminal_admissions"),
        ("table", "semantic_legacy_unprovable_admissions"),
        ("table", "semantic_invalidated_activation_scopes"),
        ("table", "semantic_activation_scope_history"),
        ("table", "semantic_legacy_activation_quarantine"),
        ("view", "semantic_current_usable_snapshots"),
    ]
    .into_iter()
    .chain(SEMANTIC_FENCE_GUARDS.iter().map(|name| ("trigger", *name)))
    {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type=?1 AND name=?2",
                params![kind, name],
                |row| row.get(0),
            )
            .optional()?;
        if !stamped {
            if actual.is_some() {
                return Ok(false);
            }
            continue;
        }
        let Some(actual) = actual else {
            return Ok(false);
        };
        let expected: String = canonical.query_row(
            "SELECT sql FROM sqlite_master WHERE type=?1 AND name=?2",
            params![kind, name],
            |row| row.get(0),
        )?;
        if normalize_schema_sql(&actual) != normalize_schema_sql(&expected) {
            return Ok(false);
        }
    }
    if stamped {
        let invalid: bool = connection.query_row(
            "SELECT NOT EXISTS(SELECT 1 FROM semantic_repair_fences WHERE generation=0 AND reason='BOOTSTRAP')
                 OR EXISTS(SELECT 1 FROM semantic_repair_fences f WHERE typeof(f.generation)<>'integer'
                           OR (f.generation>0 AND f.reason<>'GUARD_REPAIR')
                           OR (f.generation>0 AND NOT EXISTS (
                               SELECT 1 FROM semantic_repair_fences p WHERE p.generation=f.generation-1)))
                 OR EXISTS(SELECT 1 FROM semantic_snapshot_reattestations r
                           WHERE r.verification_profile<>'strict-semantic-v0.1'
                              OR r.decision_id='' OR r.decision_source='')
                 OR EXISTS(SELECT 1 FROM registry_snapshot_admissions a
                           WHERE a.state IN ('QUARANTINED','REVOKED')
                             AND NOT EXISTS(SELECT 1 FROM semantic_terminal_admissions t
                                            WHERE t.snapshot_id=a.snapshot_id))
                 OR EXISTS(SELECT 1 FROM registry_activations a
                           WHERE NOT EXISTS(SELECT 1 FROM semantic_activation_scope_history h
                                            WHERE h.scope_kind=a.scope_kind AND h.scope_id=a.scope_id))",
            [],
            |row| row.get(0),
        )?;
        if invalid {
            return Ok(false);
        }
    }
    Ok(true)
}

fn preflight_migration_state_allowing_guard_upgrade(connection: &Connection) -> Result<()> {
    preflight_migration_state_with_mode(connection, false)?;
    let has_migrations: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master
         WHERE type='table' AND name='schema_migrations')",
        [],
        |row| row.get(0),
    )?;
    if !has_migrations {
        return Ok(());
    }
    let provider_stamped: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM schema_migrations
         WHERE migration_id='0013_provider_registry')",
        [],
        |row| row.get(0),
    )?;
    if provider_stamped && !provider_authority_history_provable(connection)? {
        return Err(TaskManagerError::InvalidRecord(
            "provider evidence or trust history requires operator quarantine",
        ));
    }
    Ok(())
}

fn preflight_migration_state(connection: &Connection) -> Result<()> {
    preflight_migration_state_with_mode(connection, true)
}

fn authority_fence_objects_current(connection: &Connection, stamped: bool) -> Result<bool> {
    const OBJECTS: [&str; 4] = [
        "authority_issuance_receipts",
        "authority_issuance_receipt_exact_insert",
        "authority_issuance_receipt_no_update",
        "authority_issuance_receipt_no_delete",
    ];
    let canonical = if stamped {
        let canonical = Connection::open_in_memory()?;
        canonical.execute_batch(MIGRATION)?;
        canonical.execute_batch(include_str!(
            "../../../specs/persistence-v0.1-0015-authority-issuance-fence.sql"
        ))?;
        Some(canonical)
    } else {
        None
    };
    for name in OBJECTS {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE name=?1 AND type IN ('table','trigger')",
                [name],
                |row| row.get(0),
            )
            .optional()?;
        let expected = canonical
            .as_ref()
            .map(|canonical| {
                canonical.query_row(
                    "SELECT sql FROM sqlite_master WHERE name=?1 AND type IN ('table','trigger')",
                    [name],
                    |row| row.get::<_, String>(0),
                )
            })
            .transpose()?;
        if actual.map(|sql| normalize_schema_sql(&sql))
            != expected.map(|sql| normalize_schema_sql(&sql))
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn authority_candidate_objects_current(connection: &Connection, stamped: bool) -> Result<bool> {
    const OBJECTS: [&str; 23] = [
        "authority_candidate_reservations",
        "authority_candidate_resources",
        "ux_authority_candidate_output_identity",
        "authority_candidate_status",
        "authority_candidate_reservation_no_duplicate_insert",
        "authority_candidate_resource_no_duplicate_insert",
        "authority_candidate_status_no_duplicate_insert",
        "authority_candidate_reservation_exact_insert",
        "authority_candidate_binding_insert_guard",
        "authority_candidate_step_insert_guard",
        "authority_candidate_step_identity_update_guard",
        "authority_candidate_step_no_delete",
        "authority_candidate_allocation_insert_guard",
        "authority_candidate_allocation_identity_update_guard",
        "authority_candidate_allocation_no_delete",
        "authority_candidate_resource_exact_insert",
        "authority_candidate_status_exact_insert",
        "authority_candidate_status_cas_update",
        "authority_candidate_reservation_no_update",
        "authority_candidate_reservation_no_delete",
        "authority_candidate_resource_no_update",
        "authority_candidate_resource_no_delete",
        "authority_candidate_status_no_delete",
    ];
    let canonical = if stamped {
        let canonical = Connection::open_in_memory()?;
        canonical.execute_batch(MIGRATION)?;
        canonical.execute_batch(include_str!(
            "../../../specs/persistence-v0.1-0016-authority-candidate-reservations.sql"
        ))?;
        Some(canonical)
    } else {
        None
    };
    for name in OBJECTS {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE name=?1 AND type IN ('table','index','trigger')",
                [name], |row| row.get(0),
            ).optional()?;
        let expected = canonical.as_ref().map(|canonical| {
            canonical.query_row(
                "SELECT sql FROM sqlite_master WHERE name=?1 AND type IN ('table','index','trigger')",
                [name], |row| row.get::<_,String>(0),
            )
        }).transpose()?;
        if actual.map(|sql| normalize_schema_sql(&sql))
            != expected.map(|sql| normalize_schema_sql(&sql))
        {
            return Ok(false);
        }
    }
    Ok(true)
}

#[allow(
    clippy::too_many_lines,
    reason = "keeps the read-only migration and required-core-schema preflight contiguous"
)]
fn preflight_migration_state_with_mode(
    connection: &Connection,
    require_additive_guards: bool,
) -> Result<()> {
    let table_count = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    let has_migrations = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations')",
        [],
        |row| row.get::<_, bool>(0),
    )?;
    if !has_migrations {
        let lease_only = table_count == 1
            && connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'task_manager_lease')",
                [],
                |row| row.get::<_, bool>(0),
            )?;
        if table_count != 0 && !lease_only {
            return Err(TaskManagerError::InvalidRecord(
                "unversioned persistence tables require operator quarantine",
            ));
        }
        return Ok(());
    }
    let unknown_migrations = connection.query_row(
        "SELECT COUNT(*) FROM schema_migrations WHERE migration_id NOT IN ('0001_v0_1_trusted_control_plane', '0002_task_manager_contract_reconciliation', '0003_task_manager_recovery_fencing_privacy', '0004_task_manager_review_hardening', '0005_artifact_store_root_binding', '0006_artifact_writer_admission', '0007_artifact_owner_export_context', '0008_artifact_export_reconciliation_challenge', '0009_artifact_writer_session_fencing', '0010_keyed_import_causal_receipts', '0011_provenance_service_boundary', '0012_semantic_registry_store', '0013_provider_registry', '0014_semantic_repair_fence', '0015_authority_issuance_fence', '0016_authority_candidate_reservations', '0017_authority_policy_evaluation', '0018_trusted_time')",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    if unknown_migrations != 0 {
        return Err(TaskManagerError::InvalidRecord(
            "database contains migrations newer than this binary",
        ));
    }
    verify_migration_checksum(
        connection,
        "0001_v0_1_trusted_control_plane",
        "UNGENERATED-DRAFT-CHECKSUM",
    )?;
    verify_migration_checksum(
        connection,
        "0002_task_manager_contract_reconciliation",
        "task-manager-v0.1",
    )?;
    verify_migration_checksum(
        connection,
        "0003_task_manager_recovery_fencing_privacy",
        "task-manager-recovery-fencing-privacy-v0.1",
    )?;
    verify_migration_checksum(
        connection,
        "0004_task_manager_review_hardening",
        "task-manager-review-hardening-v0.1",
    )?;
    verify_migration_checksum(
        connection,
        "0005_artifact_store_root_binding",
        "artifact-store-root-binding-v0.1",
    )?;
    verify_migration_checksum(
        connection,
        "0006_artifact_writer_admission",
        "artifact-writer-admission-v0.1",
    )?;
    verify_migration_checksum(
        connection,
        "0007_artifact_owner_export_context",
        "artifact-owner-export-context-v0.1",
    )?;
    verify_migration_checksum(
        connection,
        "0008_artifact_export_reconciliation_challenge",
        "artifact-export-reconciliation-challenge-v0.1",
    )?;
    verify_migration_checksum(
        connection,
        "0009_artifact_writer_session_fencing",
        "artifact-writer-session-fencing-v0.1",
    )?;
    verify_migration_checksum(
        connection,
        "0010_keyed_import_causal_receipts",
        "keyed-import-causal-receipts-v0.1",
    )?;
    verify_migration_checksum(
        connection,
        "0011_provenance_service_boundary",
        "provenance-service-boundary-v0.1",
    )?;
    verify_migration_checksum(
        connection,
        "0012_semantic_registry_store",
        "semantic-registry-store-v0.1",
    )?;
    verify_migration_checksum(
        connection,
        "0013_provider_registry",
        "provider-registry-v0.1",
    )?;
    verify_migration_checksum(
        connection,
        "0014_semantic_repair_fence",
        "semantic-repair-fence-v0.1",
    )?;
    verify_migration_checksum(
        connection,
        "0015_authority_issuance_fence",
        "authority-issuance-fence-v0.1",
    )?;
    verify_migration_checksum(
        connection,
        "0016_authority_candidate_reservations",
        "authority-candidate-reservations-v0.1",
    )?;
    verify_migration_checksum(
        connection,
        "0017_authority_policy_evaluation",
        "authority-policy-evaluation-v0.1",
    )?;
    verify_migration_checksum(connection, "0018_trusted_time", "trusted-time-v0.1")?;
    let has_v1 = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE migration_id = '0001_v0_1_trusted_control_plane')",
        [],
        |row| row.get::<_, bool>(0),
    )?;
    if table_count != 0 && !has_v1 {
        return Err(TaskManagerError::InvalidRecord(
            "persistence tables without a baseline migration stamp require operator quarantine",
        ));
    }
    if has_v1 {
        let integrity =
            connection.query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))?;
        if integrity != "ok" {
            return Err(TaskManagerError::InvalidRecord(
                "stamped persistence store failed SQLite integrity verification",
            ));
        }
        require_migration_tables(connection, &["tasks", "task_transitions"])?;
        let has_v2 = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE migration_id='0002_task_manager_contract_reconciliation')",
            [],
            |row| row.get::<_, bool>(0),
        )?;
        if has_v2 {
            require_migration_tables(
                connection,
                &[
                    "plan_revisions",
                    "registry_snapshots",
                    "validation_results",
                    "semantic_program_revisions",
                    "provider_registrations",
                    "provider_conformance_evidence",
                    "artifact_blobs",
                    "artifacts",
                    "artifact_output_allocations",
                    "artifact_publications",
                    "task_artifacts",
                    "artifact_lineage",
                    "policy_snapshots",
                    "authority_requests",
                    "policy_decisions",
                    "approval_requests",
                    "approval_decisions",
                    "authority_grants",
                    "credential_handles",
                    "credential_use_records",
                    "execution_bindings",
                    "step_executions",
                    "provider_invocations",
                    "operations",
                    "provenance_events",
                    "provenance_checkpoints",
                    "skills",
                ],
            )?;
        }
        let has_authority_fence: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE migration_id='0015_authority_issuance_fence')",
            [],
            |row| row.get(0),
        )?;
        if !authority_fence_objects_current(connection, has_authority_fence)? {
            return Err(TaskManagerError::InvalidRecord(
                "authority issuance fence requires operator quarantine",
            ));
        }
        let has_candidate_reservations: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE migration_id='0016_authority_candidate_reservations')",
            [], |row| row.get(0),
        )?;
        if !authority_candidate_objects_current(connection, has_candidate_reservations)? {
            return Err(TaskManagerError::InvalidRecord(
                "authority candidate reservation schema requires operator quarantine",
            ));
        }
        let has_policy_evaluation: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE migration_id='0017_authority_policy_evaluation')",
            [], |row| row.get(0),
        )?;
        if !authority_policy::policy_objects_current(connection, has_policy_evaluation)? {
            return Err(TaskManagerError::InvalidRecord(
                "authority policy evaluation schema requires operator quarantine",
            ));
        }
        let has_trusted_time: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE migration_id='0018_trusted_time')",
            [],
            |row| row.get(0),
        )?;
        if !trusted_time::objects_current(connection, has_trusted_time)? {
            return Err(TaskManagerError::InvalidRecord(
                "trusted time schema requires operator quarantine",
            ));
        }
        let has_v3 = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE migration_id='0003_task_manager_recovery_fencing_privacy')",
            [],
            |row| row.get::<_, bool>(0),
        )?;
        if has_v3 {
            require_migration_tables(
                connection,
                &[
                    "tasks",
                    "task_transitions",
                    "task_manager_lease",
                    "recovery_epochs",
                    "recovery_assessments",
                    "recovery_unknown_operations",
                ],
            )?;
        }
        let has_v5 = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE migration_id='0005_artifact_store_root_binding')",
            [],
            |row| row.get::<_, bool>(0),
        )?;
        if has_v5 {
            require_migration_tables(connection, &["artifact_store_binding"])?;
        }
        let has_v6 = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE migration_id='0006_artifact_writer_admission')",
            [],
            |row| row.get::<_, bool>(0),
        )?;
        if has_v6
            && (!table_has_column(connection, "artifact_output_allocations", "writer_grant_id")?
                || !table_has_column(
                    connection,
                    "artifact_output_allocations",
                    "writer_grant_one_shot_consumed",
                )?)
        {
            return Err(TaskManagerError::InvalidRecord(
                "artifact writer admission migration is incomplete",
            ));
        }
        let has_v7 = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE migration_id='0007_artifact_owner_export_context')",
            [],
            |row| row.get::<_, bool>(0),
        )?;
        if has_v7
            && (table_column_not_null(connection, "operations", "semantic_program_hash")?
                || table_column_not_null(connection, "operations", "node_id")?)
        {
            return Err(TaskManagerError::InvalidRecord(
                "Artifact owner export context migration is incomplete",
            ));
        }
        let has_v8 = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE migration_id='0008_artifact_export_reconciliation_challenge')",
            [],
            |row| row.get::<_, bool>(0),
        )?;
        if has_v8 {
            require_migration_tables(connection, &["artifact_export_reconciliation_challenges"])?;
        }
        let has_v9 = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE migration_id='0009_artifact_writer_session_fencing')",
            [],
            |row| row.get::<_, bool>(0),
        )?;
        if has_v9
            && (!table_has_column(
                connection,
                "artifact_output_allocations",
                "writer_session_id",
            )? || !table_has_column(
                connection,
                "artifact_output_allocations",
                "writer_generation",
            )?)
        {
            return Err(TaskManagerError::InvalidRecord(
                "artifact writer session fencing migration is incomplete",
            ));
        }
        let has_v11 = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE migration_id='0011_provenance_service_boundary')",
            [],
            |row| row.get::<_, bool>(0),
        )?;
        if has_v11
            && (!table_has_column(connection, "provenance_events", "schema_version")?
                || !table_has_column(connection, "provenance_events", "hash_profile")?
                || !provenance_event_id_is_primary_key(connection)?
                || !table_column_not_null(connection, "provenance_events", "task_id")?
                || !provenance_foreign_keys_are_current(connection)?
                || !provenance_append_only_triggers_are_current(connection)?)
        {
            return Err(TaskManagerError::InvalidRecord(
                "provenance service-boundary migration is incomplete",
            ));
        }
        let has_semantic_registry_store = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE migration_id='0012_semantic_registry_store')",
            [],
            |row| row.get::<_, bool>(0),
        )?;
        if has_semantic_registry_store {
            require_migration_tables(
                connection,
                &[
                    "semantic_type_contracts",
                    "semantic_capability_contracts",
                    "registry_snapshot_admissions",
                    "registry_snapshot_entries",
                    "registry_activations",
                ],
            )?;
            if !additive_guard_definitions_current(
                connection,
                SEMANTIC_LEGACY_GUARDS,
                true,
                true,
                false,
            )? {
                return Err(TaskManagerError::InvalidRecord(
                    "semantic registry migration is incomplete",
                ));
            }
        }
        if !additive_guard_definitions_current(
            connection,
            SEMANTIC_ADDITIVE_GUARDS,
            has_semantic_registry_store,
            require_additive_guards,
            false,
        )? {
            return Err(TaskManagerError::InvalidRecord(
                "semantic registry migration is incomplete",
            ));
        }
        let has_semantic_fence: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations
             WHERE migration_id='0014_semantic_repair_fence')",
            [],
            |row| row.get(0),
        )?;
        if (has_semantic_fence && !has_semantic_registry_store)
            || !semantic_fence_objects_current(connection, has_semantic_fence)?
        {
            return Err(TaskManagerError::InvalidRecord(
                "semantic repair fence migration is incomplete",
            ));
        }
        let has_provider_registry = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE migration_id='0013_provider_registry')",
            [],
            |row| row.get::<_, bool>(0),
        )?;
        if has_provider_registry {
            if !has_semantic_registry_store {
                return Err(TaskManagerError::InvalidRecord(
                    "provider registry requires semantic registry migration",
                ));
            }
            if !additive_guard_definitions_current(
                connection,
                &[
                    "execution_bindings_no_update",
                    "execution_bindings_no_delete",
                ],
                true,
                true,
                false,
            )? {
                return Err(TaskManagerError::InvalidRecord(
                    "provider registry migration is incomplete",
                ));
            }
            require_migration_tables(
                connection,
                &["provider_health_observations", "provider_manifest_payloads"],
            )?;
            if !additive_guard_definitions_current(
                connection,
                PROVIDER_LEGACY_GUARDS,
                true,
                true,
                true,
            )? {
                return Err(TaskManagerError::InvalidRecord(
                    "provider registry migration is incomplete",
                ));
            }
            let index_present: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='index' AND name='ix_provider_conformance_latest')",
                [],
                |row| row.get(0),
            )?;
            if !index_present {
                return Err(TaskManagerError::InvalidRecord(
                    "provider registry migration is incomplete",
                ));
            }
        }
        if !additive_guard_definitions_current(
            connection,
            PROVIDER_ADDITIVE_GUARDS,
            has_provider_registry,
            require_additive_guards,
            true,
        )? {
            return Err(TaskManagerError::InvalidRecord(
                "provider registry migration is incomplete",
            ));
        }
        if !provider_additive_tables_current(
            connection,
            has_provider_registry,
            require_additive_guards,
        )? {
            return Err(TaskManagerError::InvalidRecord(
                "provider registry migration is incomplete",
            ));
        }
        if has_v11
            && connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM provenance_events WHERE event_id IS NULL)",
                [],
                |row| row.get::<_, bool>(0),
            )?
        {
            return Err(TaskManagerError::InvalidRecord(
                "provenance event has no identity",
            ));
        }
        if has_v11
            && connection.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM provenance_events AS event
                    LEFT JOIN tasks AS task ON task.task_id = event.task_id
                    WHERE event.task_id IS NULL OR task.task_id IS NULL
                )",
                [],
                |row| row.get::<_, bool>(0),
            )?
        {
            return Err(TaskManagerError::InvalidRecord(
                "provenance event has no owning Task",
            ));
        }
    }
    let has_steps = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'step_executions')",
        [],
        |row| row.get::<_, bool>(0),
    )?;
    if has_steps {
        let out_of_range = connection.query_row(
            "SELECT COUNT(*) FROM step_executions WHERE attempt_number NOT BETWEEN 1 AND 100",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        if out_of_range != 0 {
            return Err(TaskManagerError::InvalidRecord(
                "out-of-range step attempt numbers require operator quarantine",
            ));
        }
        let duplicates = connection.query_row(
            "SELECT COUNT(*) FROM (SELECT task_id, semantic_program_hash, node_id, attempt_number FROM step_executions GROUP BY task_id, semantic_program_hash, node_id, attempt_number HAVING COUNT(*) > 1)",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        if duplicates != 0 {
            return Err(TaskManagerError::InvalidRecord(
                "duplicate step attempt tuples require operator quarantine",
            ));
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "keeps the contract reconciliation migration within one explicit rollback boundary"
)]
fn migrate_task_manager_schema(
    connection: &Connection,
    lease_owner: &str,
    lease_epoch: i64,
) -> Result<()> {
    verify_migration_checksum(
        connection,
        "0001_v0_1_trusted_control_plane",
        "UNGENERATED-DRAFT-CHECKSUM",
    )?;
    verify_migration_checksum(
        connection,
        "0002_task_manager_contract_reconciliation",
        "task-manager-v0.1",
    )?;
    verify_migration_checksum(
        connection,
        "0003_task_manager_recovery_fencing_privacy",
        "task-manager-recovery-fencing-privacy-v0.1",
    )?;
    verify_migration_checksum(
        connection,
        "0004_task_manager_review_hardening",
        "task-manager-review-hardening-v0.1",
    )?;
    verify_migration_checksum(
        connection,
        "0005_artifact_store_root_binding",
        "artifact-store-root-binding-v0.1",
    )?;
    verify_migration_checksum(
        connection,
        "0006_artifact_writer_admission",
        "artifact-writer-admission-v0.1",
    )?;
    verify_migration_checksum(
        connection,
        "0007_artifact_owner_export_context",
        "artifact-owner-export-context-v0.1",
    )?;
    verify_migration_checksum(
        connection,
        "0008_artifact_export_reconciliation_challenge",
        "artifact-export-reconciliation-challenge-v0.1",
    )?;
    verify_migration_checksum(
        connection,
        "0009_artifact_writer_session_fencing",
        "artifact-writer-session-fencing-v0.1",
    )?;
    verify_migration_checksum(
        connection,
        "0010_keyed_import_causal_receipts",
        "keyed-import-causal-receipts-v0.1",
    )?;
    verify_migration_checksum(
        connection,
        "0011_provenance_service_boundary",
        "provenance-service-boundary-v0.1",
    )?;
    verify_migration_checksum(
        connection,
        "0012_semantic_registry_store",
        "semantic-registry-store-v0.1",
    )?;
    verify_migration_checksum(
        connection,
        "0013_provider_registry",
        "provider-registry-v0.1",
    )?;
    verify_migration_checksum(
        connection,
        "0015_authority_issuance_fence",
        "authority-issuance-fence-v0.1",
    )?;
    verify_migration_checksum(
        connection,
        "0016_authority_candidate_reservations",
        "authority-candidate-reservations-v0.1",
    )?;
    verify_migration_checksum(
        connection,
        "0017_authority_policy_evaluation",
        "authority-policy-evaluation-v0.1",
    )?;
    verify_migration_checksum(connection, "0018_trusted_time", "trusted-time-v0.1")?;
    let transition_has_foreign_key = {
        let mut statement = connection.prepare("PRAGMA foreign_key_list(task_transitions)")?;
        statement.query([])?.next()?.is_some()
    };
    let has_owner_export_context = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE migration_id='0007_artifact_owner_export_context')",
        [],
        |row| row.get::<_, bool>(0),
    )?;
    let operations_require_rebuild = !has_owner_export_context
        && (table_column_not_null(connection, "operations", "semantic_program_hash")?
            || table_column_not_null(connection, "operations", "node_id")?);
    let challenge_table_exists = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='artifact_export_reconciliation_challenges')",
        [],
        |row| row.get::<_, bool>(0),
    )?;
    let provenance_requires_rebuild =
        !table_has_column(connection, "provenance_events", "schema_version")?
            || !table_has_column(connection, "provenance_events", "hash_profile")?
            || !provenance_event_id_is_primary_key(connection)?
            || !table_column_not_null(connection, "provenance_events", "task_id")?
            || !provenance_foreign_keys_are_current(connection)?;
    let foreign_key_rebuild =
        transition_has_foreign_key || operations_require_rebuild || provenance_requires_rebuild;
    let foreign_keys_enabled =
        connection.query_row("PRAGMA foreign_keys", [], |row| row.get::<_, bool>(0))?;
    if foreign_key_rebuild {
        connection.execute_batch("PRAGMA foreign_keys = OFF")?;
    }
    connection.execute_batch("BEGIN IMMEDIATE")?;
    let migration = (|| -> Result<()> {
        let fenced = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM task_manager_lease WHERE singleton_id = 1 AND owner_id = ?1 AND fence_epoch = ?2)",
            params![lease_owner, lease_epoch],
            |row| row.get::<_, bool>(0),
        )?;
        if !fenced {
            return Err(TaskManagerError::InvalidRecord(
                "Task Manager migration rejected by stale ownership fence",
            ));
        }
        if transition_has_foreign_key {
            connection.execute_batch(
                "DROP INDEX IF EXISTS ix_task_transitions_task;
                 ALTER TABLE task_transitions RENAME TO task_transitions_legacy;
                 CREATE TABLE task_transitions (
                     transition_id TEXT PRIMARY KEY,
                     task_id TEXT NOT NULL,
                     expected_revision INTEGER NOT NULL CHECK (expected_revision >= 1),
                     expected_state TEXT NOT NULL,
                     to_state TEXT NOT NULL,
                     result_revision INTEGER,
                     result_state TEXT,
                     outcome TEXT NOT NULL CHECK (outcome IN ('PENDING', 'COMMITTED', 'REJECTED')),
                     reason_code TEXT NOT NULL,
                     request_json TEXT NOT NULL,
                     result_json TEXT,
                     provenance_event_id TEXT,
                     requested_at TEXT NOT NULL,
                     committed_at TEXT
                 );
                 INSERT INTO task_transitions SELECT * FROM task_transitions_legacy;
                 DROP TABLE task_transitions_legacy;
                 CREATE INDEX ix_task_transitions_task ON task_transitions(task_id, requested_at);",
            )?;
        }
        if provenance_requires_rebuild {
            connection.execute_batch(
                "DROP INDEX IF EXISTS ix_provenance_task_sequence;
                 DROP TRIGGER IF EXISTS provenance_events_no_update;
                 DROP TRIGGER IF EXISTS provenance_events_no_delete;
                 ALTER TABLE provenance_events RENAME TO provenance_events_legacy;
                 CREATE TABLE provenance_events (
                     schema_version TEXT NOT NULL CHECK (schema_version = '0.1'),
                     hash_profile TEXT NOT NULL CHECK (hash_profile = 'aios-provenance-event-v0.1'),
                     event_id TEXT PRIMARY KEY,
                     task_id TEXT NOT NULL,
                     stream_id TEXT NOT NULL,
                     sequence INTEGER NOT NULL CHECK (sequence >= 1),
                     timestamp TEXT NOT NULL,
                     event_type TEXT NOT NULL,
                     semantic_program_hash TEXT,
                     ir_version TEXT,
                     registry_snapshot_id TEXT,
                     node_id TEXT,
                     execution_binding_id TEXT,
                     provider_id TEXT,
                     status TEXT,
                     previous_event_hash TEXT,
                     event_hash TEXT NOT NULL,
                     event_json TEXT NOT NULL,
                     FOREIGN KEY (task_id) REFERENCES tasks(task_id),
                     FOREIGN KEY (registry_snapshot_id) REFERENCES registry_snapshots(snapshot_id),
                     FOREIGN KEY (execution_binding_id) REFERENCES execution_bindings(binding_id),
                     UNIQUE (task_id, sequence),
                     UNIQUE (stream_id, sequence)
                 );
                 INSERT INTO provenance_events (
                     schema_version,hash_profile,event_id,task_id,stream_id,sequence,timestamp,
                     event_type,semantic_program_hash,ir_version,registry_snapshot_id,node_id,
                     execution_binding_id,provider_id,status,previous_event_hash,event_hash,event_json
                 )
                 SELECT '0.1','aios-provenance-event-v0.1',event_id,task_id,stream_id,sequence,
                     timestamp,event_type,semantic_program_hash,ir_version,registry_snapshot_id,
                     node_id,execution_binding_id,provider_id,status,previous_event_hash,event_hash,event_json
                 FROM provenance_events_legacy ORDER BY stream_id,sequence;
                 DROP TABLE provenance_events_legacy;
                 CREATE INDEX ix_provenance_task_sequence ON provenance_events(task_id,sequence);
                 CREATE TRIGGER provenance_events_no_update
                 BEFORE UPDATE ON provenance_events
                 BEGIN SELECT RAISE(ABORT, 'provenance_events are append-only'); END;
                 CREATE TRIGGER provenance_events_no_delete
                 BEFORE DELETE ON provenance_events
                 BEGIN SELECT RAISE(ABORT, 'provenance_events are append-only'); END;",
            )?;
            let stream_ids = {
                let mut statement = connection.prepare(
                    "SELECT DISTINCT stream_id FROM provenance_events ORDER BY stream_id",
                )?;
                let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
                rows.collect::<std::result::Result<Vec<_>, _>>()?
            };
            for stream_id in stream_ids {
                if !aios_provenance::verify_stream(
                    connection,
                    &stream_id,
                    None,
                    None,
                    "1970-01-01T00:00:00Z",
                )?
                .valid
                {
                    return Err(TaskManagerError::InvalidRecord(
                        "legacy provenance failed verification during migration",
                    ));
                }
            }
        }
        for (column, declaration) in [
            ("active_plan_revision", "INTEGER"),
            ("active_step_ids_json", "TEXT NOT NULL DEFAULT '[]'"),
            ("waiting_on_json", "TEXT NOT NULL DEFAULT '[]'"),
            ("intent_commitment_nonce", "BLOB"),
        ] {
            if !table_has_column(connection, "tasks", column)? {
                connection.execute_batch(&format!(
                    "ALTER TABLE tasks ADD COLUMN {column} {declaration};"
                ))?;
            }
        }
        connection.execute(
            "UPDATE tasks SET intent_commitment_nonce = randomblob(32) WHERE intent_commitment_nonce IS NULL",
            [],
        )?;
        if !table_has_column(connection, "recovery_assessments", "basis_revision")? {
            connection.execute_batch(
                "ALTER TABLE recovery_assessments ADD COLUMN basis_revision INTEGER;",
            )?;
        }
        connection.execute(
            "UPDATE recovery_assessments SET basis_revision = (SELECT revision FROM tasks WHERE tasks.task_id = recovery_assessments.task_id) WHERE basis_revision IS NULL",
            [],
        )?;
        let invalid_recovery_basis = connection.query_row(
            "SELECT COUNT(*) FROM recovery_assessments WHERE basis_revision IS NULL OR basis_revision < 1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        if invalid_recovery_basis != 0 {
            return Err(TaskManagerError::InvalidRecord(
                "invalid recovery assessment basis revisions require operator quarantine",
            ));
        }
        connection.execute_batch(
            "DROP TRIGGER IF EXISTS recovery_assessments_basis_insert;
             DROP TRIGGER IF EXISTS recovery_assessments_basis_update;
             CREATE TRIGGER recovery_assessments_basis_insert
             BEFORE INSERT ON recovery_assessments
             WHEN NEW.basis_revision IS NULL OR NEW.basis_revision < 1
             BEGIN SELECT RAISE(ABORT, 'recovery basis revision must be at least 1'); END;
             CREATE TRIGGER recovery_assessments_basis_update
             BEFORE UPDATE OF basis_revision ON recovery_assessments
             WHEN NEW.basis_revision IS NULL OR NEW.basis_revision < 1
             BEGIN SELECT RAISE(ABORT, 'recovery basis revision must be at least 1'); END;",
        )?;
        if !table_has_column(connection, "approval_decisions", "approved_until")? {
            connection
                .execute_batch("ALTER TABLE approval_decisions ADD COLUMN approved_until TEXT;")?;
        }
        if !table_has_column(connection, "artifact_output_allocations", "writer_grant_id")? {
            connection.execute_batch(
                "ALTER TABLE artifact_output_allocations ADD COLUMN writer_grant_id TEXT;",
            )?;
        }
        if !table_has_column(
            connection,
            "artifact_output_allocations",
            "writer_grant_one_shot_consumed",
        )? {
            connection.execute_batch(
                "ALTER TABLE artifact_output_allocations ADD COLUMN writer_grant_one_shot_consumed INTEGER CHECK (writer_grant_one_shot_consumed IS NULL OR writer_grant_one_shot_consumed IN (0, 1));",
            )?;
        }
        if !table_has_column(
            connection,
            "artifact_output_allocations",
            "writer_session_id",
        )? {
            connection.execute_batch(
                "ALTER TABLE artifact_output_allocations ADD COLUMN writer_session_id TEXT;",
            )?;
        }
        if !table_has_column(
            connection,
            "artifact_output_allocations",
            "writer_generation",
        )? {
            connection.execute_batch(
                "ALTER TABLE artifact_output_allocations ADD COLUMN writer_generation INTEGER NOT NULL DEFAULT 0 CHECK (writer_generation >= 0);",
            )?;
        }
        if operations_require_rebuild {
            if challenge_table_exists {
                connection.execute_batch(
                    "ALTER TABLE artifact_export_reconciliation_challenges
                     RENAME TO artifact_export_reconciliation_challenges_legacy;",
                )?;
            }
            connection.execute_batch(
                "DROP INDEX IF EXISTS ix_operations_task_state;
                 ALTER TABLE operations RENAME TO operations_legacy;
                 CREATE TABLE operations (
                     operation_id TEXT PRIMARY KEY,
                     task_id TEXT NOT NULL,
                     semantic_program_hash TEXT,
                     node_id TEXT,
                     binding_id TEXT,
                     attempt_id TEXT,
                     transaction_class TEXT,
                     effect_class TEXT NOT NULL,
                     idempotency_key TEXT,
                     state TEXT NOT NULL CHECK (state IN (
                         'PREPARED','STARTED','SUCCEEDED','FAILED','UNKNOWN','CANCELLED'
                     )),
                     outcome_certainty TEXT CHECK (outcome_certainty IS NULL OR outcome_certainty IN (
                         'NOT_STARTED','STARTED_NO_EFFECT','COMPLETED',
                         'FAILED_NO_EFFECT','FAILED_PARTIAL_EFFECT','OUTCOME_UNKNOWN'
                     )),
                     external_receipt TEXT,
                     details_json TEXT,
                     prepared_at TEXT NOT NULL,
                     started_at TEXT,
                     finished_at TEXT,
                     FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE,
                     FOREIGN KEY (binding_id) REFERENCES execution_bindings(binding_id),
                     FOREIGN KEY (attempt_id) REFERENCES step_executions(attempt_id)
                 );
                 INSERT INTO operations SELECT * FROM operations_legacy;
                 DROP TABLE operations_legacy;
                 CREATE INDEX ix_operations_task_state ON operations(task_id,state);",
            )?;
            if challenge_table_exists {
                connection.execute_batch(
                    "CREATE TABLE artifact_export_reconciliation_challenges (
                         operation_id TEXT PRIMARY KEY,
                         recovery_assessment_id TEXT NOT NULL,
                         subject_hash TEXT NOT NULL,
                         challenge TEXT NOT NULL UNIQUE,
                         issued_at TEXT NOT NULL,
                         FOREIGN KEY (operation_id) REFERENCES operations(operation_id) ON DELETE CASCADE,
                         FOREIGN KEY (recovery_assessment_id) REFERENCES recovery_assessments(assessment_id)
                     );
                     INSERT INTO artifact_export_reconciliation_challenges
                     SELECT operation_id,recovery_assessment_id,subject_hash,challenge,issued_at
                     FROM artifact_export_reconciliation_challenges_legacy;
                     DROP TABLE artifact_export_reconciliation_challenges_legacy;",
                )?;
            }
        }
        let duplicate_publications = connection.query_row(
            "SELECT COUNT(*) FROM (SELECT allocation_id FROM artifact_publications GROUP BY allocation_id HAVING COUNT(*) > 1)",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        if duplicate_publications != 0 {
            return Err(TaskManagerError::InvalidRecord(
                "duplicate artifact publications require operator quarantine",
            ));
        }
        reconcile_pending_transitions(connection)?;
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS ux_artifact_publications_allocation ON artifact_publications(allocation_id)",
            [],
        )?;
        connection.execute_batch(
            "DROP INDEX IF EXISTS ux_step_executions_attempt_tuple;
             CREATE UNIQUE INDEX ux_step_executions_attempt_tuple
             ON step_executions(task_id, semantic_program_hash, node_id, attempt_number);",
        )?;
        connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(migration_id, checksum, applied_at) VALUES ('0002_task_manager_contract_reconciliation', 'task-manager-v0.1', '2026-09-19T00:00:00Z')",
            [],
        )?;
        connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(migration_id, checksum, applied_at) VALUES ('0003_task_manager_recovery_fencing_privacy', 'task-manager-recovery-fencing-privacy-v0.1', '2026-09-20T00:00:00Z')",
            [],
        )?;
        connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(migration_id, checksum, applied_at) VALUES ('0004_task_manager_review_hardening', 'task-manager-review-hardening-v0.1', '2026-09-20T00:00:00Z')",
            [],
        )?;
        connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(migration_id, checksum, applied_at) VALUES ('0005_artifact_store_root_binding', 'artifact-store-root-binding-v0.1', '2026-09-20T00:00:00Z')",
            [],
        )?;
        connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(migration_id, checksum, applied_at) VALUES ('0006_artifact_writer_admission', 'artifact-writer-admission-v0.1', '2026-09-20T00:00:00Z')",
            [],
        )?;
        connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(migration_id, checksum, applied_at) VALUES ('0007_artifact_owner_export_context', 'artifact-owner-export-context-v0.1', '2026-09-20T00:00:00Z')",
            [],
        )?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS artifact_export_reconciliation_challenges (
                 operation_id TEXT PRIMARY KEY,
                 recovery_assessment_id TEXT NOT NULL,
                 subject_hash TEXT NOT NULL,
                 challenge TEXT NOT NULL UNIQUE,
                 issued_at TEXT NOT NULL,
                 FOREIGN KEY (operation_id) REFERENCES operations(operation_id) ON DELETE CASCADE,
                 FOREIGN KEY (recovery_assessment_id) REFERENCES recovery_assessments(assessment_id)
             );",
        )?;
        connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(migration_id, checksum, applied_at) VALUES ('0008_artifact_export_reconciliation_challenge', 'artifact-export-reconciliation-challenge-v0.1', '2026-09-20T00:00:00Z')",
            [],
        )?;
        connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(migration_id, checksum, applied_at) VALUES ('0009_artifact_writer_session_fencing', 'artifact-writer-session-fencing-v0.1', '2026-09-20T00:00:00Z')",
            [],
        )?;
        let foreign_key_failures = connection.query_row(
            "SELECT (SELECT COUNT(*) FROM pragma_foreign_key_check('provenance_events'))
                  + (SELECT COUNT(*) FROM pragma_foreign_key_check('artifact_export_reconciliation_challenges'))",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        if foreign_key_failures != 0 {
            return Err(TaskManagerError::InvalidRecord(
                "persistence migration produced invalid foreign-key references",
            ));
        }
        let missing_event_id = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM provenance_events WHERE event_id IS NULL)",
            [],
            |row| row.get::<_, bool>(0),
        )?;
        if missing_event_id {
            return Err(TaskManagerError::InvalidRecord(
                "persistence migration found a provenance event without identity",
            ));
        }
        if !provenance_append_only_triggers_are_current(connection)? {
            return Err(TaskManagerError::InvalidRecord(
                "persistence migration found invalid provenance append-only triggers",
            ));
        }
        connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(migration_id, checksum, applied_at) VALUES ('0011_provenance_service_boundary', 'provenance-service-boundary-v0.1', '2026-09-21T00:00:00Z')",
            [],
        )?;
        connection.execute_batch(include_str!(
            "../../../specs/persistence-v0.1-0015-authority-issuance-fence.sql"
        ))?;
        connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(migration_id, checksum, applied_at) VALUES ('0015_authority_issuance_fence', 'authority-issuance-fence-v0.1', '2026-09-23T00:00:00Z')",
            [],
        )?;
        connection.execute_batch(include_str!(
            "../../../specs/persistence-v0.1-0016-authority-candidate-reservations.sql"
        ))?;
        connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(migration_id, checksum, applied_at) VALUES ('0016_authority_candidate_reservations', 'authority-candidate-reservations-v0.1', '2026-09-23T00:00:00Z')",
            [],
        )?;
        connection.execute_batch(include_str!(
            "../../../specs/persistence-v0.1-0017-authority-policy-evaluation.sql"
        ))?;
        connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(migration_id, checksum, applied_at) VALUES ('0017_authority_policy_evaluation', 'authority-policy-evaluation-v0.1', '2026-09-23T00:00:00Z')",
            [],
        )?;
        connection.execute_batch(trusted_time::MIGRATION)?;
        connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(migration_id, checksum, applied_at) VALUES ('0018_trusted_time', 'trusted-time-v0.1', '2026-09-23T00:00:00Z')",
            [],
        )?;
        Ok(())
    })();
    let result = match migration {
        Ok(()) => connection.execute_batch("COMMIT"),
        Err(error) => {
            connection.execute_batch("ROLLBACK")?;
            return if foreign_key_rebuild && foreign_keys_enabled {
                connection.execute_batch("PRAGMA foreign_keys = ON")?;
                Err(error)
            } else {
                Err(error)
            };
        }
    };
    if foreign_key_rebuild && foreign_keys_enabled {
        connection.execute_batch("PRAGMA foreign_keys = ON")?;
    }
    result.map_err(Into::into)
}

fn verify_migration_checksum(
    connection: &Connection,
    migration_id: &str,
    expected: &str,
) -> Result<()> {
    let stored = connection
        .query_row(
            "SELECT checksum FROM schema_migrations WHERE migration_id = ?1",
            [migration_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if stored.as_deref().is_some_and(|value| value != expected) {
        return Err(TaskManagerError::InvalidRecord(
            "stored migration checksum does not match this binary",
        ));
    }
    Ok(())
}

fn reconcile_pending_transitions(connection: &Connection) -> Result<()> {
    let pending = {
        let mut statement = connection.prepare(
            "SELECT transition_id, task_id, requested_at FROM task_transitions WHERE outcome = 'PENDING' ORDER BY transition_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()?
    };
    for (transition_id, task_id, requested_at) in pending {
        let observed = connection
            .query_row(
                "SELECT state, revision FROM tasks WHERE task_id = ?1",
                [&task_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;
        let (reason_code, observed_state, observed_revision) =
            if let Some((state, revision)) = observed {
                (
                    "TASK_STORAGE_FAILURE",
                    Some(TaskState::parse(&state)?),
                    Some(u64::try_from(revision).map_err(|_| {
                        TaskManagerError::InvalidRecord("stored revision is invalid")
                    })?),
                )
            } else {
                ("TASK_NOT_FOUND", None, None)
            };
        let result = TransitionResult {
            schema_version: SCHEMA_VERSION.to_owned(),
            transition_id: transition_id.clone(),
            task_id,
            applied: false,
            reason_code: reason_code.to_owned(),
            message: Some("legacy pending transition was quarantined during migration".to_owned()),
            previous_state: None,
            current_state: None,
            previous_revision: None,
            current_revision: None,
            observed_state,
            observed_revision,
            provenance_event_id: None,
            provenance_event_hash: None,
            resulted_at: requested_at,
        };
        connection.execute(
            "UPDATE task_transitions SET outcome = 'REJECTED', reason_code = ?2, result_revision = ?3, result_state = ?4, result_json = ?5, committed_at = COALESCE(committed_at, requested_at) WHERE transition_id = ?1",
            params![transition_id, result.reason_code, result.observed_revision.and_then(|value| i64::try_from(value).ok()), result.observed_state.map(TaskState::as_str), serde_json::to_string(&result)?],
        )?;
    }
    let committed = {
        let mut statement = connection.prepare(
            "SELECT transition_id, task_id, result_revision, result_state, provenance_event_id FROM task_transitions WHERE outcome = 'COMMITTED' AND result_json IS NULL ORDER BY transition_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()?
    };
    for (transition_id, task_id, result_revision, result_state, event_id) in committed {
        reconstruct_committed_transition(
            connection,
            &transition_id,
            &task_id,
            result_revision,
            result_state.as_deref(),
            event_id.as_deref(),
        )?;
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "legacy committed receipt reconstruction keeps every provenance consistency check together"
)]
fn reconstruct_committed_transition(
    connection: &Connection,
    transition_id: &str,
    task_id: &str,
    stored_revision: Option<i64>,
    stored_state: Option<&str>,
    event_id: Option<&str>,
) -> Result<()> {
    let event_id = event_id.ok_or(TaskManagerError::InvalidRecord(
        "committed transition without result has no provenance identity",
    ))?;
    let event_row = connection
        .query_row(
            "SELECT sequence, previous_event_hash, event_hash, event_json, timestamp, task_id, event_type FROM provenance_events WHERE event_id = ?1",
            [event_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .optional()?
        .ok_or(TaskManagerError::InvalidRecord(
            "committed transition result cannot be reconstructed from provenance",
        ))?;
    let event = aios_provenance::parse_unique_json(&event_row.3)?;
    let request_json = connection.query_row(
        "SELECT request_json FROM task_transitions WHERE transition_id = ?1",
        [transition_id],
        |row| row.get::<_, String>(0),
    )?;
    let stored_request: TransitionRequest = serde_json::from_str(&request_json)?;
    let internal_recovery = stored_request
        .transition_id
        .starts_with("__aios_internal:startup-recovery:")
        || stored_request
            .transition_id
            .starts_with("__aios_internal:live-recovery:");
    validate_transition_request(&stored_request, internal_recovery)?;
    let previous_revision = event
        .pointer("/task_transition/previous_revision")
        .and_then(Value::as_u64);
    let new_revision = event
        .pointer("/task_transition/new_revision")
        .and_then(Value::as_u64);
    let previous_state = event
        .pointer("/task_transition/previous_state")
        .and_then(Value::as_str)
        .map(TaskState::parse)
        .transpose()?;
    let new_state = event
        .pointer("/task_transition/new_state")
        .and_then(Value::as_str)
        .map(TaskState::parse)
        .transpose()?;
    let row_revision = stored_revision.and_then(|value| u64::try_from(value).ok());
    let expected_actor = serde_json::to_value(&stored_request.requested_by)?;
    let expected_related_ids = serde_json::to_value(&stored_request.reason.related_ids)?;
    let intent_nonce = connection.query_row(
        "SELECT intent_commitment_nonce FROM tasks WHERE task_id=?1",
        [task_id],
        |row| row.get::<_, Vec<u8>>(0),
    )?;
    if intent_nonce.len() != 32 {
        return Err(TaskManagerError::InvalidRecord(
            "Task provenance commitment nonce is invalid",
        ));
    }
    let expected_reason_message_ref =
        stored_request.reason.message.as_ref().map(|message| {
            task_field_commitment(&intent_nonce, "reason_message", message.as_bytes())
        });
    let expected_waiting = stored_request
        .mutation
        .waiting_on
        .as_ref()
        .map(|values| provenance_waiting_on(values));
    let expected_waiting_commitments = stored_request
        .mutation
        .waiting_on
        .as_ref()
        .map(|values| provenance_waiting_commitments(values, &intent_nonce));
    let expected_failure = stored_request
        .mutation
        .failure
        .as_ref()
        .map(provenance_failure);
    let expected_failure_commitment = stored_request
        .mutation
        .failure
        .as_ref()
        .map(|failure| provenance_failure_commitment(failure, &intent_nonce));
    let computed_hash = provenance_hash(
        task_id,
        u64::try_from(event_row.0)
            .map_err(|_| TaskManagerError::InvalidRecord("invalid provenance sequence"))?,
        event_row.1.as_deref(),
        &event,
    )?;
    if event_row.2 != computed_hash
        || event_row.5 != task_id
        || event_row.6 != "task.transitioned"
        || event_string(&event, "event_id") != Some(event_id)
        || event_string(&event, "task_id") != Some(task_id)
        || event_string(&event, "timestamp") != Some(event_row.4.as_str())
        || event.get("actor") != Some(&expected_actor)
        || event
            .pointer("/task_transition/transition_id")
            .and_then(Value::as_str)
            != Some(transition_id)
        || stored_request.transition_id != transition_id
        || stored_request.task_id != task_id
        || Some(stored_request.expected_revision) != previous_revision
        || Some(stored_request.expected_state) != previous_state
        || Some(stored_request.to_state) != new_state
        || event
            .pointer("/task_transition/reason_code")
            .and_then(Value::as_str)
            != Some(stored_request.reason.code.as_str())
        || event.pointer("/details/reason_message_ref")
            != Some(&serde_json::to_value(&expected_reason_message_ref)?)
        || event.pointer("/details/related_ids") != Some(&expected_related_ids)
        || event.pointer("/details/mutation_text_commitments/waiting_on")
            != Some(&serde_json::to_value(&expected_waiting_commitments)?)
        || event.pointer("/details/mutation_text_commitments/failure_summary")
            != Some(&serde_json::to_value(&expected_failure_commitment)?)
        || event.get("committed_mutation")
            != Some(&json!({
                "active_plan": stored_request.mutation.active_plan,
                "active_step_ids": stored_request.mutation.active_step_ids,
                "waiting_on": expected_waiting,
                "failure": expected_failure,
                "recovery": stored_request.mutation.recovery,
            }))
        || new_revision != row_revision
        || new_state.map(TaskState::as_str) != stored_state
        || previous_revision.and_then(|value| value.checked_add(1)) != new_revision
    {
        return Err(TaskManagerError::InvalidRecord(
            "committed transition result conflicts with durable provenance",
        ));
    }
    if !verify_provenance_through(connection, task_id, Some(event_row.0))? {
        return Err(TaskManagerError::InvalidRecord(
            "committed transition provenance stream is incomplete",
        ));
    }
    let task_revision = connection
        .query_row(
            "SELECT revision FROM tasks WHERE task_id = ?1",
            [task_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or(TaskManagerError::InvalidRecord(
            "committed transition task is missing",
        ))?;
    let task_revision = u64::try_from(task_revision)
        .map_err(|_| TaskManagerError::InvalidRecord("stored revision is invalid"))?;
    if task_revision < new_revision.unwrap_or(u64::MAX) {
        return Err(TaskManagerError::InvalidRecord(
            "committed transition is ahead of its Task",
        ));
    }
    let result = TransitionResult {
        schema_version: SCHEMA_VERSION.to_owned(),
        transition_id: transition_id.to_owned(),
        task_id: task_id.to_owned(),
        applied: true,
        reason_code: "TASK_TRANSITION_APPLIED".to_owned(),
        message: None,
        previous_state,
        current_state: new_state,
        previous_revision,
        current_revision: new_revision,
        observed_state: new_state,
        observed_revision: new_revision,
        provenance_event_id: Some(event_id.to_owned()),
        provenance_event_hash: Some(event_row.2),
        resulted_at: event_row.4,
    };
    connection.execute(
        "UPDATE task_transitions SET request_json = ?2, result_json = ?3 WHERE transition_id = ?1 AND outcome = 'COMMITTED' AND result_json IS NULL",
        params![transition_id, canonical_json(&stored_request)?, serde_json::to_string(&result)?],
    )?;
    Ok(())
}

fn table_has_column(connection: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let names = statement.query_map([], |row| row.get::<_, String>(1))?;
    for name in names {
        if name? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn provenance_event_id_is_primary_key(connection: &Connection) -> Result<bool> {
    let mut statement = connection.prepare("PRAGMA table_info(provenance_events)")?;
    let columns = statement.query_map([], |row| {
        Ok((row.get::<_, String>(1)?, row.get::<_, i64>(5)?))
    })?;
    let primary_key_columns = columns
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|(_, position)| *position != 0)
        .collect::<Vec<_>>();
    Ok(matches!(primary_key_columns.as_slice(), [(name, 1)] if name == "event_id"))
}

fn provenance_task_fk_is_current(connection: &Connection) -> Result<bool> {
    let mut statement = connection.prepare("PRAGMA foreign_key_list(provenance_events)")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
        ))
    })?;
    let foreign_keys = rows.collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(foreign_keys
        .iter()
        .filter(|(_, _, table, from, ..)| table == "tasks" || from == "task_id")
        .count()
        == 1
        && foreign_keys
            .iter()
            .any(|(id, sequence, table, from, to, on_update, on_delete)| {
                *sequence == 0
                    && table == "tasks"
                    && from == "task_id"
                    && to == "task_id"
                    && on_update.eq_ignore_ascii_case("NO ACTION")
                    && on_delete.eq_ignore_ascii_case("NO ACTION")
                    && foreign_keys
                        .iter()
                        .filter(|(other_id, ..)| other_id == id)
                        .count()
                        == 1
            }))
}

fn provenance_foreign_keys_are_current(connection: &Connection) -> Result<bool> {
    if !provenance_task_fk_is_current(connection)? {
        return Ok(false);
    }
    let mut statement = connection.prepare("PRAGMA foreign_key_list(provenance_events)")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
        ))
    })?;
    let foreign_keys = rows.collect::<std::result::Result<Vec<_>, _>>()?;
    let expected = [
        ("tasks", "task_id", "task_id"),
        ("registry_snapshots", "registry_snapshot_id", "snapshot_id"),
        ("execution_bindings", "execution_binding_id", "binding_id"),
    ];
    Ok(foreign_keys.len() == expected.len()
        && expected.iter().all(|(target, source, key)| {
            foreign_keys
                .iter()
                .filter(|(_, sequence, table, from, to, on_update, on_delete)| {
                    *sequence == 0
                        && table == target
                        && from == source
                        && to == key
                        && on_update.eq_ignore_ascii_case("NO ACTION")
                        && on_delete.eq_ignore_ascii_case("NO ACTION")
                })
                .count()
                == 1
        }))
}

fn table_column_not_null(connection: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement.query_map([], |row| {
        Ok((row.get::<_, String>(1)?, row.get::<_, bool>(3)?))
    })?;
    for stored in columns {
        let (name, not_null) = stored?;
        if name == column {
            return Ok(not_null);
        }
    }
    Err(TaskManagerError::InvalidRecord(
        "required persistence column is missing",
    ))
}

fn require_migration_tables(connection: &Connection, tables: &[&str]) -> Result<()> {
    for table in tables {
        let present = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
            [table],
            |row| row.get::<_, bool>(0),
        )?;
        if !present {
            return Err(TaskManagerError::InvalidRecord(
                "stamped persistence store is missing a required core table",
            ));
        }
    }
    Ok(())
}

fn provenance_append_only_triggers_are_current(connection: &Connection) -> Result<bool> {
    for (name, operation) in [
        ("provenance_events_no_update", "UPDATE"),
        ("provenance_events_no_delete", "DELETE"),
    ] {
        let sql: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1 AND tbl_name='provenance_events'",
                [name],
                |row| row.get(0),
            )
            .optional()?;
        let Some(sql) = sql else {
            return Ok(false);
        };
        let normalized = sql.split_whitespace().collect::<Vec<_>>().join(" ");
        let expected = format!(
            "CREATE TRIGGER {name} BEFORE {operation} ON provenance_events BEGIN SELECT RAISE(ABORT, 'provenance_events are append-only'); END"
        );
        if normalized != expected
            && normalized
                != expected.replacen("CREATE TRIGGER ", "CREATE TRIGGER IF NOT EXISTS ", 1)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn encode_optional<T: Serialize>(value: Option<&T>) -> Result<Option<String>> {
    value
        .map(serde_json::to_string)
        .transpose()
        .map_err(Into::into)
}
fn decode_optional<T: for<'de> Deserialize<'de>>(value: Option<String>) -> Result<Option<T>> {
    value
        .map(|value| serde_json::from_str(&value))
        .transpose()
        .map_err(Into::into)
}

fn query_strings(connection: &Connection, query: &str, task_id: &str) -> Result<Vec<String>> {
    let mut statement = connection.prepare(query)?;
    let rows = statement.query_map([task_id], |row| row.get(0))?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

struct StoredCredentialUse {
    request_id: String,
    result_id: Option<String>,
    credential_id: String,
    status: Option<String>,
    completed_at: Option<String>,
    result_json: Option<String>,
    requested_at: String,
}

struct StoredProviderInvocation {
    invocation_id: String,
    attempt_id: String,
    binding_id: String,
    provider_id: String,
    provider_version: String,
    status: String,
    result_json: Option<String>,
    started_at: Option<String>,
    completed_at: Option<String>,
    binding_attempt_id: Option<String>,
    binding_task_id: Option<String>,
    node_id: Option<String>,
    binding_provider_id: Option<String>,
    binding_provider_version: Option<String>,
    binding_provider_build_hash: Option<String>,
}

fn stored_provider_invocations(
    connection: &Connection,
    task_id: &str,
) -> Result<Vec<StoredProviderInvocation>> {
    let mut statement = connection.prepare(
        "SELECT invocation.invocation_id, invocation.attempt_id, invocation.binding_id,
                invocation.provider_id, invocation.provider_version, invocation.status,
                invocation.result_json, invocation.started_at, invocation.completed_at,
                binding.attempt_id, binding.task_id, binding.node_id,
                binding.provider_id, binding.provider_version, binding.provider_build_hash
         FROM provider_invocations invocation
         LEFT JOIN execution_bindings binding ON binding.binding_id = invocation.binding_id
         WHERE invocation.task_id=?1 ORDER BY invocation.invocation_id",
    )?;
    let rows = statement.query_map([task_id], |row| {
        Ok(StoredProviderInvocation {
            invocation_id: row.get(0)?,
            attempt_id: row.get(1)?,
            binding_id: row.get(2)?,
            provider_id: row.get(3)?,
            provider_version: row.get(4)?,
            status: row.get(5)?,
            result_json: row.get(6)?,
            started_at: row.get(7)?,
            completed_at: row.get(8)?,
            binding_attempt_id: row.get(9)?,
            binding_task_id: row.get(10)?,
            node_id: row.get(11)?,
            binding_provider_id: row.get(12)?,
            binding_provider_version: row.get(13)?,
            binding_provider_build_hash: row.get(14)?,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn stored_credential_uses(
    connection: &Connection,
    task_id: &str,
) -> Result<Vec<StoredCredentialUse>> {
    let mut statement = connection.prepare(
        "SELECT request_id, result_id, credential_id, status, completed_at, result_json, requested_at
         FROM credential_use_records WHERE task_id = ?1 ORDER BY request_id",
    )?;
    let rows = statement.query_map([task_id], |row| {
        Ok(StoredCredentialUse {
            request_id: row.get(0)?,
            result_id: row.get(1)?,
            credential_id: row.get(2)?,
            status: row.get(3)?,
            completed_at: row.get(4)?,
            result_json: row.get(5)?,
            requested_at: row.get(6)?,
        })
    })?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn authenticated_credential_use_resolution(
    task_id: &str,
    record: &StoredCredentialUse,
) -> Option<RecoveryResolution> {
    let (Some(result_id), Some(status), Some(completed_at), Some(result_json)) = (
        record.result_id.as_deref(),
        record.status.as_deref(),
        record.completed_at.as_deref(),
        record.result_json.as_deref(),
    ) else {
        return None;
    };
    credential_use_resolution(
        task_id,
        &record.request_id,
        result_id,
        &record.credential_id,
        status,
        completed_at,
        result_json,
    )
    .ok()
    .flatten()
}

fn unresolved_credential_use_ids(connection: &Connection, task_id: &str) -> Result<Vec<String>> {
    Ok(stored_credential_uses(connection, task_id)?
        .into_iter()
        .filter(|record| authenticated_credential_use_resolution(task_id, record).is_none())
        .map(|record| format!("credential-use:{}", record.request_id))
        .collect())
}

fn unresolved_provider_invocation_ids(
    connection: &Connection,
    task_id: &str,
) -> Result<Vec<String>> {
    Ok(stored_provider_invocations(connection, task_id)?
        .into_iter()
        .filter(|record| {
            authenticated_provider_invocation_resolution(task_id, record)
                .ok()
                .flatten()
                .is_none()
        })
        .map(|record| format!("provider-invocation:{}", record.invocation_id))
        .collect())
}

fn committed_publication_structurally_valid(
    connection: &Connection,
    task_id: &str,
    publication_id: &str,
) -> Result<bool> {
    artifact_store::committed_publication_receipt_authenticates(connection, task_id, publication_id)
}

fn unresolved_committed_publication_ids(
    connection: &Connection,
    task_id: &str,
) -> Result<Vec<String>> {
    let ids = query_strings(
        connection,
        "SELECT publication_id FROM artifact_publications
         WHERE task_id=?1 AND state='COMMITTED' ORDER BY publication_id",
        task_id,
    )?;
    ids.into_iter()
        .filter_map(
            |id| match committed_publication_structurally_valid(connection, task_id, &id) {
                Ok(true) => None,
                Ok(false) => Some(Ok(id)),
                Err(error) => Some(Err(error)),
            },
        )
        .collect()
}

fn unresolved_execution_ids(connection: &Connection, task_id: &str) -> Result<Vec<String>> {
    let mut ids = query_strings(
        connection,
        "SELECT recovery_id FROM (
             SELECT 'operation:' || operation_id AS recovery_id FROM operations
              WHERE task_id = ?1 AND (outcome_certainty IN ('FAILED_PARTIAL_EFFECT', 'OUTCOME_UNKNOWN') OR (state IN ('PREPARED', 'STARTED', 'UNKNOWN') AND outcome_certainty IS NULL))
             UNION ALL
             SELECT 'attempt:' || attempt_id FROM step_executions
              WHERE task_id = ?1 AND (outcome_certainty IN ('FAILED_PARTIAL_EFFECT', 'OUTCOME_UNKNOWN') OR (state IN ('STARTING', 'RUNNING', 'UNKNOWN') AND outcome_certainty IS NULL))
             UNION ALL
             SELECT 'publication:' || publication_id FROM artifact_publications
              WHERE task_id = ?1 AND state = 'PENDING'
             UNION ALL
             SELECT 'grant:' || grant_id FROM authority_grants
              WHERE task_id = ?1 AND state = 'ACTIVE'
        ) ORDER BY recovery_id",
        task_id,
    )?;
    ids.extend(
        unresolved_committed_publication_ids(connection, task_id)?
            .into_iter()
            .map(|id| format!("publication:{id}")),
    );
    ids.extend(unresolved_provider_invocation_ids(connection, task_id)?);
    ids.extend(unresolved_credential_use_ids(connection, task_id)?);
    ids.sort();
    Ok(ids)
}

fn unresolved_execution_count(transaction: &Transaction<'_>, task_id: &str) -> Result<i64> {
    let unresolved_without_receipts = transaction
        .query_row(
            "SELECT
               (SELECT COUNT(*) FROM operations WHERE task_id = ?1 AND (outcome_certainty IN ('FAILED_PARTIAL_EFFECT', 'OUTCOME_UNKNOWN') OR (state IN ('PREPARED', 'STARTED', 'UNKNOWN') AND outcome_certainty IS NULL))) +
               (SELECT COUNT(*) FROM step_executions WHERE task_id = ?1 AND (outcome_certainty IN ('FAILED_PARTIAL_EFFECT', 'OUTCOME_UNKNOWN') OR (state IN ('STARTING', 'RUNNING', 'UNKNOWN') AND outcome_certainty IS NULL))) +
               (SELECT COUNT(*) FROM artifact_publications WHERE task_id = ?1 AND state = 'PENDING')",
            [task_id],
            |row| row.get::<_, i64>(0),
        )?;
    let unresolved_credentials = i64::try_from(
        unresolved_credential_use_ids(transaction, task_id)?.len(),
    )
    .map_err(|_| TaskManagerError::InvalidRecord("credential-use count exceeds supported range"))?;
    let unresolved_invocations = i64::try_from(
        unresolved_provider_invocation_ids(transaction, task_id)?.len(),
    )
    .map_err(|_| {
        TaskManagerError::InvalidRecord("provider-invocation count exceeds supported range")
    })?;
    let unresolved_publications = i64::try_from(
        unresolved_committed_publication_ids(transaction, task_id)?.len(),
    )
    .map_err(|_| TaskManagerError::InvalidRecord("publication count exceeds supported range"))?;
    Ok(unresolved_without_receipts
        + unresolved_credentials
        + unresolved_invocations
        + unresolved_publications)
}

struct RecoverySubject {
    kind: &'static str,
    id: String,
    evidence_kind: &'static str,
    certainty: String,
    safe_action: &'static str,
    reason_code: &'static str,
    observation: String,
}

fn recovery_disposition(certainty: &str) -> (&'static str, &'static str) {
    match certainty {
        "NOT_STARTED" => ("CREATE_NEW_ATTEMPT", "RECOVERY_NOT_STARTED"),
        "STARTED_NO_EFFECT" => ("CREATE_NEW_ATTEMPT", "RECOVERY_STARTED_NO_EFFECT"),
        "COMPLETED" => ("RECONCILE_STATE", "RECOVERY_COMPLETED"),
        "FAILED_NO_EFFECT" => ("MARK_ATTEMPT_FAILED", "RECOVERY_FAILED_NO_EFFECT"),
        "FAILED_PARTIAL_EFFECT" => (
            "REQUIRE_EXTERNAL_RECONCILIATION",
            "RECOVERY_FAILED_PARTIAL_EFFECT",
        ),
        _ => (
            "REQUIRE_EXTERNAL_RECONCILIATION",
            "RECOVERY_OUTCOME_UNKNOWN",
        ),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "keeps each consequential recovery subject and its evidence mapping auditable"
)]
fn load_recovery_subjects(
    transaction: &Transaction<'_>,
    task_id: &str,
) -> Result<Vec<RecoverySubject>> {
    let mut subjects = Vec::new();
    {
        let mut statement = transaction.prepare(
            "SELECT attempt_id, outcome_certainty, state, started_at FROM step_executions
             WHERE task_id = ?1 AND (outcome_certainty IN ('FAILED_PARTIAL_EFFECT','OUTCOME_UNKNOWN')
                OR (state IN ('STARTING','RUNNING','UNKNOWN') AND outcome_certainty IS NULL)) ORDER BY attempt_id",
        )?;
        let rows = statement.query_map([task_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })?;
        for row in rows {
            let (id, durable_certainty, state, started_at) = row?;
            let certainty = durable_certainty.unwrap_or_else(|| "OUTCOME_UNKNOWN".to_owned());
            let (safe_action, reason_code) = recovery_disposition(&certainty);
            subjects.push(RecoverySubject {
                kind: "attempt",
                id,
                evidence_kind: "attempt-record",
                certainty,
                safe_action,
                reason_code,
                observation: format!("durable step state={state}; started_at={started_at:?}"),
            });
        }
    }
    {
        let mut statement = transaction.prepare(
            "SELECT operation_id, outcome_certainty, state FROM operations
             WHERE task_id = ?1 AND (state IN ('PREPARED','STARTED','UNKNOWN')
                OR outcome_certainty IN ('FAILED_PARTIAL_EFFECT','OUTCOME_UNKNOWN')) ORDER BY operation_id",
        )?;
        let rows = statement.query_map([task_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            let (id, durable_certainty, state) = row?;
            let certainty = durable_certainty.unwrap_or_else(|| {
                if state == "PREPARED" {
                    "NOT_STARTED".to_owned()
                } else {
                    "OUTCOME_UNKNOWN".to_owned()
                }
            });
            let (safe_action, reason_code) = recovery_disposition(&certainty);
            subjects.push(RecoverySubject {
                kind: "external-operation",
                id: format!("operation:{id}"),
                evidence_kind: "external-status",
                certainty,
                safe_action,
                reason_code,
                observation: format!("durable operation state={state}"),
            });
        }
    }
    {
        for record in stored_provider_invocations(transaction, task_id)? {
            if authenticated_provider_invocation_resolution(task_id, &record)?.is_some() {
                continue;
            }
            let certainty = "OUTCOME_UNKNOWN".to_owned();
            let (safe_action, reason_code) = recovery_disposition(&certainty);
            subjects.push(RecoverySubject {
                kind: "external-operation",
                id: format!("provider-invocation:{}", record.invocation_id),
                evidence_kind: "provider-runtime",
                certainty,
                safe_action,
                reason_code,
                observation: format!(
                    "durable provider invocation status={}; started_at={:?}",
                    record.status, record.started_at
                ),
            });
        }
    }
    {
        for record in stored_credential_uses(transaction, task_id)? {
            if authenticated_credential_use_resolution(task_id, &record).is_some() {
                continue;
            }
            subjects.push(RecoverySubject {
                kind: "external-operation",
                id: format!("credential-use:{}", record.request_id),
                evidence_kind: "credential-record",
                certainty: "OUTCOME_UNKNOWN".to_owned(),
                safe_action: "REQUIRE_EXTERNAL_RECONCILIATION",
                reason_code: "RECOVERY_OUTCOME_UNKNOWN",
                observation: format!(
                    "durable credential use status={:?}; requested_at={}; completed_at={:?}",
                    record.status, record.requested_at, record.completed_at
                ),
            });
        }
    }
    for (query, prefix, kind, evidence_kind, safe_action, reason_code, observation) in [
        (
            "SELECT publication_id FROM artifact_publications WHERE task_id = ?1 AND state = 'PENDING' ORDER BY publication_id",
            "publication:",
            "artifact-publication",
            "artifact-publication",
            "CLEAN_STAGING",
            "RECOVERY_ARTIFACT_STAGING_ONLY",
            "durable publication remains PENDING",
        ),
        (
            "SELECT grant_id FROM authority_grants WHERE task_id = ?1 AND state = 'ACTIVE' ORDER BY grant_id",
            "grant:",
            "authority-grant",
            "grant-record",
            "REVOKE_GRANTS",
            "RECOVERY_EXTERNAL_RECONCILIATION_REQUIRED",
            "durable authority grant remains ACTIVE",
        ),
    ] {
        for id in query_strings(transaction, query, task_id)? {
            subjects.push(RecoverySubject {
                kind,
                id: format!("{prefix}{id}"),
                evidence_kind,
                certainty: "OUTCOME_UNKNOWN".to_owned(),
                safe_action,
                reason_code,
                observation: observation.to_owned(),
            });
        }
    }
    for id in unresolved_committed_publication_ids(transaction, task_id)? {
        subjects.push(RecoverySubject {
            kind: "artifact-publication",
            id: format!("publication:{id}"),
            evidence_kind: "blob-integrity",
            certainty: "FAILED_PARTIAL_EFFECT".to_owned(),
            safe_action: "FAIL_TASK",
            reason_code: "RECOVERY_ARTIFACT_INTEGRITY_FAILED",
            observation: "committed Artifact publication lacks complete authenticated structural or blob proof"
                .to_owned(),
        });
    }
    subjects.sort_by(|left, right| (left.kind, &left.id).cmp(&(right.kind, &right.id)));
    Ok(subjects)
}

fn recovery_subject_assessment_id(recovery_ref: &str, kind: &str, id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"AIOS-RECOVERY-SUBJECT-ASSESSMENT\0v0.1\0");
    for value in [recovery_ref, kind, id] {
        hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        write!(&mut hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    format!("recovery-subject:sha256:{hex}")
}

fn recovery_subject_inventory_id(kind: &str, id: &str) -> Option<String> {
    match kind {
        "attempt" => Some(format!("attempt:{id}")),
        "external-operation" | "artifact-publication" | "authority-grant" => Some(id.to_owned()),
        _ => None,
    }
}

fn persist_recovery_subject_assessment(
    transaction: &Transaction<'_>,
    recovery_ref: &str,
    epoch_id: &str,
    task_id: &str,
    basis_revision: u64,
    subject: &RecoverySubject,
    created_at: &str,
) -> Result<()> {
    let assessment_id = recovery_subject_assessment_id(recovery_ref, subject.kind, &subject.id);
    let existing_created_at = transaction
        .query_row(
            "SELECT created_at FROM recovery_assessments WHERE assessment_id = ?1",
            [&assessment_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let canonical_created_at = existing_created_at.as_deref().unwrap_or(created_at);
    let reason_codes = vec![subject.reason_code];
    let assessment = canonical_json(&json!({
        "schema_version": SCHEMA_VERSION,
        "assessment_id": assessment_id,
        "recovery_epoch_id": epoch_id,
        "task_id": task_id,
        "subject": {"kind": subject.kind, "id": subject.id},
        "certainty": subject.certainty,
        "evidence": [{
            "kind": subject.evidence_kind,
            "ref": subject.id,
            "observation": subject.observation
        }],
        "safe_action": subject.safe_action,
        "new_binding_required": subject.safe_action == "CREATE_NEW_ATTEMPT",
        "external_reconciliation_required": subject.safe_action == "REQUIRE_EXTERNAL_RECONCILIATION",
        "reason_codes": reason_codes,
        "created_at": canonical_created_at
    }))?;
    let changed = transaction.execute(
        "INSERT OR IGNORE INTO recovery_assessments
         (assessment_id, recovery_epoch_id, task_id, basis_revision, subject_kind, subject_id,
          certainty, safe_action, reason_codes_json, assessment_json, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            assessment_id,
            epoch_id,
            task_id,
            i64::try_from(basis_revision).map_err(|_| TaskManagerError::InvalidRecord(
                "recovery basis revision exceeds SQLite range"
            ))?,
            subject.kind,
            subject.id,
            subject.certainty,
            subject.safe_action,
            serde_json::to_string(&reason_codes)?,
            assessment,
            canonical_created_at
        ],
    )?;
    if changed == 0 {
        let stored = transaction.query_row(
            "SELECT assessment_json FROM recovery_assessments WHERE assessment_id = ?1",
            [&assessment_id],
            |row| row.get::<_, String>(0),
        )?;
        if stored != assessment {
            return Err(TaskManagerError::InvalidRecord(
                "recovery subject assessment identity was reused with different evidence",
            ));
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "copies one authenticated subject into a new immutable recovery inventory"
)]
fn carry_forward_resolved_recovery_subject(
    transaction: &Transaction<'_>,
    recovery_ref: &str,
    epoch_id: &str,
    task_id: &str,
    basis_revision: u64,
    inventory_id: &str,
    created_at: &str,
) -> Result<bool> {
    let rows = {
        let mut statement = transaction.prepare(
            "SELECT subject_kind,subject_id
             FROM recovery_assessments
             WHERE task_id=?1 AND recovery_epoch_id=?2 AND subject_kind<>'task'
             ORDER BY assessment_id",
        )?;
        let rows = statement.query_map(params![task_id, epoch_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()?
    };
    for (kind, id) in rows {
        if recovery_subject_inventory_id(&kind, &id).as_deref() != Some(inventory_id) {
            continue;
        }
        let Some(resolution) = resolved_recovery_subject(transaction, task_id, inventory_id)?
        else {
            continue;
        };
        let kind = match kind.as_str() {
            "attempt" => "attempt",
            "external-operation" => "external-operation",
            "artifact-publication" => "artifact-publication",
            "authority-grant" => "authority-grant",
            _ => continue,
        };
        persist_recovery_subject_assessment(
            transaction,
            recovery_ref,
            epoch_id,
            task_id,
            basis_revision,
            &RecoverySubject {
                kind,
                id,
                evidence_kind: "recovery-subject",
                certainty: resolution.certainty,
                safe_action: resolution.safe_action,
                reason_code: resolution.reason_code,
                observation:
                    "authenticated terminal evidence became durable before inventory refresh"
                        .to_owned(),
            },
            created_at,
        )?;
        return Ok(true);
    }
    Ok(false)
}

fn all_unique(values: &[String]) -> bool {
    values
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        == values.len()
}

fn current_active_binding_ids(
    connection: &Connection,
    task_id: &str,
    active_program_revision: Option<i64>,
    active_steps: &[String],
) -> Result<Vec<String>> {
    let Some(program_revision) = active_program_revision else {
        return Ok(Vec::new());
    };
    let mut bindings = Vec::new();
    for node_id in active_steps {
        let binding = connection
            .query_row(
                "SELECT b.binding_id FROM execution_bindings b JOIN step_executions s ON s.binding_id = b.binding_id AND s.attempt_id = b.attempt_id AND s.task_id = b.task_id AND s.semantic_program_hash = b.semantic_program_hash AND s.registry_snapshot_id = b.registry_snapshot_id AND s.node_id = b.node_id JOIN semantic_program_revisions p ON p.task_id = b.task_id AND p.semantic_hash = b.semantic_program_hash AND p.registry_snapshot_id = b.registry_snapshot_id WHERE b.task_id = ?1 AND p.program_revision = ?2 AND b.node_id = ?3 AND s.state IN ('READY', 'STARTING', 'RUNNING') AND s.attempt_number = (SELECT MAX(s2.attempt_number) FROM step_executions s2 WHERE s2.task_id = s.task_id AND s2.node_id = s.node_id AND s2.semantic_program_hash = s.semantic_program_hash AND s2.registry_snapshot_id = s.registry_snapshot_id) LIMIT 1",
                params![task_id, program_revision, node_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(binding) = binding {
            bindings.push(binding);
        }
    }
    bindings.sort();
    bindings.dedup();
    Ok(bindings)
}

type TransitionState = (i64, String, String, String, Option<String>, Option<i64>);
fn load_transition_state(
    transaction: &Transaction<'_>,
    task_id: &str,
) -> Result<Option<TransitionState>> {
    transaction.query_row("SELECT revision, state, waiting_on_json, active_step_ids_json, failure_json, active_program_revision FROM tasks WHERE task_id = ?1", [task_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?))).optional().map_err(Into::into)
}

fn load_observed(transaction: &Transaction<'_>, task_id: &str) -> Result<Option<(TaskState, u64)>> {
    let row = transaction
        .query_row(
            "SELECT state, revision FROM tasks WHERE task_id = ?1",
            [task_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    row.map(|(state, revision)| {
        Ok((
            TaskState::parse(&state)?,
            u64::try_from(revision)
                .map_err(|_| TaskManagerError::InvalidRecord("stored revision is invalid"))?,
        ))
    })
    .transpose()
}

#[allow(
    clippy::too_many_lines,
    reason = "authenticates every replayed receipt field against its transition row and provenance"
)]
fn authenticated_transition_result(
    transaction: &Transaction<'_>,
    transition_id: &str,
) -> Result<TransitionResult> {
    let row = transaction.query_row(
        "SELECT task_id,expected_revision,expected_state,to_state,result_revision,result_state,outcome,reason_code,result_json,provenance_event_id,requested_at,committed_at FROM task_transitions WHERE transition_id=?1",
        [transition_id],
        |row| Ok((
            row.get::<_, String>(0)?, row.get::<_, i64>(1)?, row.get::<_, String>(2)?,
            row.get::<_, String>(3)?, row.get::<_, Option<i64>>(4)?, row.get::<_, Option<String>>(5)?,
            row.get::<_, String>(6)?, row.get::<_, String>(7)?, row.get::<_, Option<String>>(8)?,
            row.get::<_, Option<String>>(9)?, row.get::<_, String>(10)?, row.get::<_, Option<String>>(11)?,
        )),
    )?;
    let result_json = row.8.ok_or(TaskManagerError::InvalidRecord(
        "stored transition has no result",
    ))?;
    let result: TransitionResult = serde_json::from_str(&result_json)?;
    let expected_revision = u64::try_from(row.1)
        .map_err(|_| TaskManagerError::InvalidRecord("stored transition revision is invalid"))?;
    let expected_state = TaskState::parse(&row.2)?;
    let to_state = TaskState::parse(&row.3)?;
    let result_revision = row.4.and_then(|value| u64::try_from(value).ok());
    let result_state = row.5.as_deref().map(TaskState::parse).transpose()?;
    let resulted_at = row.11.as_deref().unwrap_or(&row.10);
    if result.schema_version != SCHEMA_VERSION
        || result.transition_id != transition_id
        || result.task_id != row.0
        || result.reason_code != row.7
        || result.resulted_at != resulted_at
        || result.observed_revision != result_revision
        || result.observed_state != result_state
    {
        return Err(TaskManagerError::InvalidRecord(
            "stored transition result conflicts with its durable row",
        ));
    }
    match row.6.as_str() {
        "COMMITTED" => {
            let Some(event_id) = row.9.as_deref() else {
                return Err(TaskManagerError::InvalidRecord(
                    "committed transition result has no provenance identity",
                ));
            };
            // Reuse the full request-to-event authentication performed for
            // legacy receipt reconstruction. This binds actor, reason, and
            // every privacy-safe mutation field before replaying a receipt.
            reconstruct_committed_transition(
                transaction,
                transition_id,
                &row.0,
                row.4,
                row.5.as_deref(),
                Some(event_id),
            )?;
            let event_row = transaction
                .query_row(
                    "SELECT sequence,previous_event_hash,event_hash,event_json,timestamp FROM provenance_events WHERE event_id=?1 AND task_id=?2 AND event_type='task.transitioned'",
                    params![event_id, row.0],
                    |event| Ok((event.get::<_, i64>(0)?,event.get::<_, Option<String>>(1)?,event.get::<_, String>(2)?,event.get::<_, String>(3)?,event.get::<_, String>(4)?)),
                )
                .optional()?
                .ok_or(TaskManagerError::InvalidRecord(
                    "committed transition result provenance is missing",
                ))?;
            let sequence = u64::try_from(event_row.0)
                .map_err(|_| TaskManagerError::InvalidRecord("invalid provenance sequence"))?;
            let event = aios_provenance::parse_unique_json(&event_row.3)?;
            if !result.applied
                || result.reason_code != "TASK_TRANSITION_APPLIED"
                || result.previous_revision != Some(expected_revision)
                || result.previous_state != Some(expected_state)
                || result.current_revision != result_revision
                || result.current_state != Some(to_state)
                || result.provenance_event_id.as_deref() != Some(event_id)
                || result.provenance_event_hash.as_deref() != Some(event_row.2.as_str())
                || result.resulted_at != event_row.4
                || event
                    .pointer("/task_transition/transition_id")
                    .and_then(Value::as_str)
                    != Some(transition_id)
                || event
                    .pointer("/task_transition/previous_revision")
                    .and_then(Value::as_u64)
                    != Some(expected_revision)
                || event
                    .pointer("/task_transition/new_revision")
                    .and_then(Value::as_u64)
                    != result_revision
                || event
                    .pointer("/task_transition/previous_state")
                    .and_then(Value::as_str)
                    != Some(expected_state.as_str())
                || event
                    .pointer("/task_transition/new_state")
                    .and_then(Value::as_str)
                    != Some(to_state.as_str())
                || provenance_hash(&row.0, sequence, event_row.1.as_deref(), &event)? != event_row.2
                || !verify_provenance_through(transaction, &row.0, Some(event_row.0))?
            {
                return Err(TaskManagerError::InvalidRecord(
                    "stored transition result conflicts with committed provenance",
                ));
            }
        }
        "REJECTED" => {
            if result.applied
                || result.previous_state.is_some()
                || result.current_state.is_some()
                || result.previous_revision.is_some()
                || result.current_revision.is_some()
                || result.provenance_event_id.is_some()
                || result.provenance_event_hash.is_some()
                || row.9.is_some()
            {
                return Err(TaskManagerError::InvalidRecord(
                    "stored rejection result conflicts with its durable row",
                ));
            }
        }
        _ => {
            return Err(TaskManagerError::InvalidRecord(
                "stored transition has no replayable terminal outcome",
            ));
        }
    }
    Ok(result)
}

fn rejected(
    request: &TransitionRequest,
    code: &str,
    observed: Option<(TaskState, u64)>,
    resulted_at: &str,
) -> TransitionResult {
    TransitionResult {
        schema_version: SCHEMA_VERSION.to_owned(),
        transition_id: request.transition_id.clone(),
        task_id: request.task_id.clone(),
        applied: false,
        reason_code: code.to_owned(),
        message: None,
        previous_state: None,
        current_state: None,
        previous_revision: None,
        current_revision: None,
        observed_state: observed.map(|value| value.0),
        observed_revision: observed.map(|value| value.1),
        provenance_event_id: None,
        provenance_event_hash: None,
        resulted_at: resulted_at.to_owned(),
    }
}

fn persist_rejection(
    transaction: &Transaction<'_>,
    request: &TransitionRequest,
    request_json: &str,
    result: &TransitionResult,
    resulted_at: &str,
) -> Result<()> {
    transaction.execute("INSERT INTO task_transitions (transition_id, task_id, expected_revision, expected_state, to_state, result_revision, result_state, outcome, reason_code, request_json, result_json, requested_at, committed_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'REJECTED', ?8, ?9, ?10, ?11, ?11)", params![request.transition_id, request.task_id, i64::try_from(request.expected_revision).unwrap_or(i64::MAX), request.expected_state.as_str(), request.to_state.as_str(), result.observed_revision.and_then(|value| i64::try_from(value).ok()), result.observed_state.map(TaskState::as_str), result.reason_code, request_json, serde_json::to_string(result)?, resulted_at])?;
    Ok(())
}

fn allowed_transition(from: TaskState, to: TaskState) -> bool {
    use TaskState::{
        Cancelled, Completed, Created, Failed, Paused, Planning, Recovering, RolledBack,
        RollingBack, Runnable, Running, Verifying, WaitingForAuth, WaitingForInput,
    };
    match from {
        Created => matches!(to, Planning | Cancelled | Failed),
        Planning => matches!(
            to,
            WaitingForInput | WaitingForAuth | Runnable | Failed | Cancelled | Paused
        ),
        WaitingForInput => matches!(to, Planning | Cancelled | Paused | Failed),
        WaitingForAuth => matches!(to, Planning | Runnable | Cancelled | Paused | Failed),
        Runnable => matches!(to, Running | Planning | Paused | Cancelled | Failed),
        Running => matches!(
            to,
            Runnable
                | Planning
                | WaitingForInput
                | WaitingForAuth
                | Verifying
                | Paused
                | Recovering
                | Failed
                | Cancelled
                | RollingBack
        ),
        Verifying => matches!(
            to,
            Completed | Running | Planning | Paused | Recovering | Failed | Cancelled | RollingBack
        ),
        Paused => matches!(to, Planning | Runnable | Recovering | Cancelled | Failed),
        Recovering => matches!(
            to,
            Planning
                | Runnable
                | Running
                | WaitingForInput
                | WaitingForAuth
                | Paused
                | Failed
                | RollingBack
        ),
        RollingBack => matches!(to, RolledBack | Failed),
        Failed => to == RollingBack,
        Completed | Cancelled | RolledBack => false,
    }
}

fn count_active_steps(
    transaction: &Transaction<'_>,
    task_id: &str,
    active_steps: &[String],
    state: &str,
) -> Result<i64> {
    let mut count = 0_i64;
    for node_id in active_steps {
        let (latest_count, matching_state) = transaction.query_row(
            "SELECT COUNT(*), COALESCE(SUM(CASE WHEN s.state = ?3 THEN 1 ELSE 0 END), 0) FROM step_executions s JOIN tasks t ON t.task_id = s.task_id JOIN semantic_program_revisions p ON p.task_id = t.task_id AND p.program_revision = t.active_program_revision AND p.semantic_hash = s.semantic_program_hash AND p.registry_snapshot_id = s.registry_snapshot_id WHERE s.task_id = ?1 AND s.node_id = ?2 AND s.attempt_number = (SELECT MAX(s2.attempt_number) FROM step_executions s2 WHERE s2.task_id = s.task_id AND s2.node_id = s.node_id AND s2.semantic_program_hash = s.semantic_program_hash AND s2.registry_snapshot_id = s.registry_snapshot_id)",
            params![task_id, node_id, state],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )?;
        if latest_count == 1 && matching_state == 1 {
            count += 1;
        }
    }
    Ok(count)
}

fn latest_active_attempt_count(
    transaction: &Transaction<'_>,
    task_id: &str,
    node_id: &str,
) -> Result<i64> {
    transaction
        .query_row(
            "SELECT COUNT(*) FROM step_executions s JOIN tasks t ON t.task_id = s.task_id JOIN semantic_program_revisions p ON p.task_id = t.task_id AND p.program_revision = t.active_program_revision AND p.semantic_hash = s.semantic_program_hash AND p.registry_snapshot_id = s.registry_snapshot_id WHERE s.task_id = ?1 AND s.node_id = ?2 AND s.attempt_number = (SELECT MAX(s2.attempt_number) FROM step_executions s2 WHERE s2.task_id = s.task_id AND s2.node_id = s.node_id AND s2.semantic_program_hash = s.semantic_program_hash AND s2.registry_snapshot_id = s.registry_snapshot_id)",
            params![task_id, node_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(Into::into)
}

fn count_bound_active_steps(
    transaction: &Transaction<'_>,
    task_id: &str,
    active_steps: &[String],
    states: &[&str],
    checked_at: &str,
) -> Result<i64> {
    let mut count = 0_i64;
    for node_id in active_steps {
        if latest_active_attempt_count(transaction, task_id, node_id)? != 1 {
            continue;
        }
        let candidate = transaction
            .query_row(
                "SELECT s.state, b.binding_id, s.attempt_id, s.semantic_program_hash, b.grant_refs_json FROM step_executions s JOIN tasks t ON t.task_id = s.task_id JOIN semantic_program_revisions p ON p.task_id = t.task_id AND p.program_revision = t.active_program_revision AND p.semantic_hash = s.semantic_program_hash AND p.registry_snapshot_id = s.registry_snapshot_id JOIN execution_bindings b ON b.binding_id = s.binding_id AND b.attempt_id = s.attempt_id AND b.task_id = s.task_id AND b.semantic_program_hash = s.semantic_program_hash AND b.registry_snapshot_id = s.registry_snapshot_id AND b.node_id = s.node_id WHERE s.task_id = ?1 AND s.node_id = ?2 AND s.attempt_number = (SELECT MAX(s2.attempt_number) FROM step_executions s2 WHERE s2.task_id = s.task_id AND s2.node_id = s.node_id AND s2.semantic_program_hash = s.semantic_program_hash AND s2.registry_snapshot_id = s.registry_snapshot_id) LIMIT 1",
                params![task_id, node_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?)),
            )
            .optional()?;
        if let Some((state, binding_id, attempt_id, semantic_hash, grant_refs)) = candidate {
            let check = BindingGrantCheck {
                task_id,
                semantic_hash: &semantic_hash,
                node_id,
                binding_id: &binding_id,
                attempt_id: &attempt_id,
                grant_refs_json: &grant_refs,
                checked_at,
            };
            if states.contains(&state.as_str())
                && binding_grants_valid(transaction, &check)?
                && output_allocations_ready(transaction, &check)?
            {
                count += 1;
            }
        }
    }
    Ok(count)
}

fn admit_active_steps(
    transaction: &Transaction<'_>,
    task_id: &str,
    active_steps: &[String],
    admitted_at: &str,
) -> Result<bool> {
    if active_steps.is_empty() {
        return Ok(false);
    }
    let mut admitted = 0_usize;
    for node_id in active_steps {
        let ready_latest = transaction.query_row(
            "SELECT COUNT(*) FROM step_executions s JOIN tasks t ON t.task_id=s.task_id JOIN semantic_program_revisions p ON p.task_id=t.task_id AND p.program_revision=t.active_program_revision AND p.semantic_hash=s.semantic_program_hash AND p.registry_snapshot_id=s.registry_snapshot_id WHERE s.task_id=?1 AND s.node_id=?2 AND s.state='READY' AND s.attempt_number=(SELECT MAX(s2.attempt_number) FROM step_executions s2 WHERE s2.task_id=s.task_id AND s2.node_id=s.node_id AND s2.semantic_program_hash=s.semantic_program_hash AND s2.registry_snapshot_id=s.registry_snapshot_id)",
            params![task_id, node_id],
            |row| row.get::<_, i64>(0),
        )?;
        if ready_latest == 0 {
            continue;
        }
        if ready_latest != 1 || latest_active_attempt_count(transaction, task_id, node_id)? != 1 {
            return Ok(false);
        }
        let candidate = transaction
            .query_row(
                "SELECT s.attempt_id, b.binding_id, s.semantic_program_hash, b.grant_refs_json, b.registry_snapshot_id, b.provider_id, b.provider_version FROM step_executions s JOIN tasks t ON t.task_id = s.task_id JOIN semantic_program_revisions p ON p.task_id = t.task_id AND p.program_revision = t.active_program_revision AND p.semantic_hash = s.semantic_program_hash AND p.registry_snapshot_id = s.registry_snapshot_id JOIN execution_bindings b ON b.binding_id = s.binding_id AND b.attempt_id = s.attempt_id AND b.task_id = s.task_id AND b.semantic_program_hash = s.semantic_program_hash AND b.registry_snapshot_id = s.registry_snapshot_id AND b.node_id = s.node_id WHERE s.task_id = ?1 AND s.node_id = ?2 AND s.state = 'READY' AND s.attempt_number = (SELECT MAX(s2.attempt_number) FROM step_executions s2 WHERE s2.task_id = s.task_id AND s2.node_id = s.node_id AND s2.semantic_program_hash = s.semantic_program_hash AND s2.registry_snapshot_id = s.registry_snapshot_id) LIMIT 1",
                params![task_id, node_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?, row.get::<_, String>(5)?, row.get::<_, String>(6)?)),
            )
            .optional()?;
        let Some((
            attempt_id,
            binding_id,
            semantic_hash,
            grant_refs,
            registry_snapshot_id,
            provider_id,
            provider_version,
        )) = candidate
        else {
            return Ok(false);
        };
        let check = BindingGrantCheck {
            task_id,
            semantic_hash: &semantic_hash,
            node_id,
            binding_id: &binding_id,
            attempt_id: &attempt_id,
            grant_refs_json: &grant_refs,
            checked_at: admitted_at,
        };
        if !active_program_validation_valid(transaction, task_id, &semantic_hash)?
            || !binding_grants_valid(transaction, &check)?
            || !output_allocations_ready(transaction, &check)?
        {
            return Ok(false);
        }
        let changed = transaction.execute(
            "UPDATE step_executions SET revision = revision + 1, state = 'RUNNING', started_at = COALESCE(started_at, ?2), updated_at = ?2 WHERE attempt_id = ?1 AND state = 'READY'",
            params![attempt_id, admitted_at],
        )?;
        if changed != 1 {
            return Ok(false);
        }
        let event = json!({
            "schema_version": SCHEMA_VERSION,
            "event_id": attempt_admitted_event_id(&attempt_id, &binding_id),
            "task_id": task_id,
            "event_type": "execution.started",
            "timestamp": admitted_at,
            "actor": {"kind":"provider","id":provider_id},
            "status": "success",
            "semantic_program_hash": semantic_hash,
            "registry_snapshot_id": registry_snapshot_id,
            "step_id": node_id,
            "execution_binding_id": binding_id,
            "provider_id": provider_id,
            "provider_version": provider_version,
            "details": {
                "attempt_id": attempt_id,
                "binding_id": binding_id,
                "node_id": node_id,
            }
        });
        append_event(transaction, task_id, &event)?;
        admitted += 1;
    }
    Ok(admitted > 0)
}

struct BindingGrantCheck<'a> {
    task_id: &'a str,
    semantic_hash: &'a str,
    node_id: &'a str,
    binding_id: &'a str,
    attempt_id: &'a str,
    grant_refs_json: &'a str,
    checked_at: &'a str,
}

struct BindingEvidence {
    capability: String,
    principal_id: String,
    program_json: String,
    registry_snapshot_id: String,
    contract_hash: Option<String>,
    snapshot_manifest_json: String,
    ir_version: String,
    provider_version: String,
    provider_manifest_hash: Option<String>,
    provider_build_hash: Option<String>,
    provider_registration_id: Option<String>,
    attempt: i64,
    policy_decision_refs_json: String,
    grant_refs_json: String,
    execution_profile_ref: String,
    placement_json: String,
    binding_json: String,
    created_at: String,
    conformance_evidence_id: String,
    conformance_suite_id: Option<String>,
    conformance_suite_hash: Option<String>,
    conformance_status: String,
    conformance_json: String,
    conformance_tested_at: Option<String>,
}

struct SnapshotContract {
    version: String,
    content_hash: String,
}

fn validation_result_validator() -> Result<&'static jsonschema::Validator> {
    static VALIDATOR: OnceLock<std::result::Result<jsonschema::Validator, String>> =
        OnceLock::new();
    match VALIDATOR.get_or_init(|| {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../specs/ir-validation-result.schema.json"
        ))
        .map_err(|error| error.to_string())?;
        jsonschema::options()
            .should_validate_formats(true)
            .build(&schema)
            .map_err(|error| error.to_string())
    }) {
        Ok(validator) => Ok(validator),
        Err(_) => Err(TaskManagerError::InvalidRecord(
            "IR validation result schema cannot be compiled",
        )),
    }
}

fn provider_conformance_result_validator() -> Result<&'static jsonschema::Validator> {
    static VALIDATOR: OnceLock<std::result::Result<jsonschema::Validator, String>> =
        OnceLock::new();
    match VALIDATOR.get_or_init(|| {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../specs/provider-conformance-result.schema.json"
        ))
        .map_err(|error| error.to_string())?;
        jsonschema::options()
            .should_validate_formats(true)
            .build(&schema)
            .map_err(|error| error.to_string())
    }) {
        Ok(validator) => Ok(validator),
        Err(_) => Err(TaskManagerError::InvalidRecord(
            "provider conformance result schema cannot be compiled",
        )),
    }
}

fn active_program_validation_valid(
    transaction: &Transaction<'_>,
    task_id: &str,
    semantic_hash: &str,
) -> Result<bool> {
    let evidence = transaction
        .query_row(
            "SELECT p.program_json,p.program_id,p.ir_version,p.semantic_hash,p.registry_snapshot_id,
                    v.task_id,v.program_id,v.ir_version,v.valid,v.semantic_hash,v.registry_snapshot_id,
                    v.validator_id,v.validator_version,v.validator_build_hash,v.result_json,v.validated_at
             FROM tasks t
             JOIN semantic_program_revisions p ON p.task_id=t.task_id
                AND p.program_revision=t.active_program_revision AND p.status='active'
             JOIN validation_results v ON v.validation_result_id=p.validation_result_id
             WHERE t.task_id=?1 AND p.semantic_hash=?2",
            params![task_id, semantic_hash],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, bool>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, Option<String>>(13)?,
                    row.get::<_, String>(14)?,
                    row.get::<_, String>(15)?,
                ))
            },
        )
        .optional()?;
    let Some((
        program_json,
        program_id,
        ir_version,
        stored_hash,
        snapshot_id,
        validation_task_id,
        validation_program_id,
        validation_ir_version,
        validation_valid,
        validation_hash,
        validation_snapshot_id,
        validator_id,
        validator_version,
        validator_build_hash,
        result_json,
        validated_at,
    )) = evidence
    else {
        return Ok(false);
    };
    let Ok(result) = serde_json::from_str::<Value>(&result_json) else {
        return Ok(false);
    };
    let recomputed_hash = aios_ir::recompute_semantic_hash(program_json.as_bytes()).ok();
    let timestamp_valid = OffsetDateTime::parse(&validated_at, &Rfc3339).is_ok();
    Ok(timestamp_valid
        && validation_result_validator()?.is_valid(&result)
        && validation_task_id.as_deref() == Some(task_id)
        && validation_program_id.as_deref() == Some(program_id.as_str())
        && validation_ir_version.as_deref() == Some(ir_version.as_str())
        && validation_valid
        && validation_hash.as_deref() == Some(stored_hash.as_str())
        && validation_snapshot_id.as_deref() == Some(snapshot_id.as_str())
        && recomputed_hash.as_deref() == Some(stored_hash.as_str())
        && result.get("valid").and_then(Value::as_bool) == Some(true)
        && result.get("program_id").and_then(Value::as_str) == Some(program_id.as_str())
        && result.get("ir_version").and_then(Value::as_str) == Some(ir_version.as_str())
        && result.get("semantic_hash").and_then(Value::as_str) == Some(stored_hash.as_str())
        && result.get("semantic_hash_profile").and_then(Value::as_str) == Some("aios-ir-v0.1")
        && result.get("registry_snapshot_id").and_then(Value::as_str) == Some(snapshot_id.as_str())
        && result.pointer("/validator/id").and_then(Value::as_str) == Some(validator_id.as_str())
        && result.pointer("/validator/version").and_then(Value::as_str)
            == Some(validator_version.as_str())
        && match validator_build_hash.as_deref() {
            Some(expected) => {
                result
                    .pointer("/validator/build_hash")
                    .and_then(Value::as_str)
                    == Some(expected)
            }
            None => result
                .pointer("/validator/build_hash")
                .is_none_or(Value::is_null),
        }
        && result.get("validated_at").and_then(Value::as_str) == Some(validated_at.as_str()))
}

fn canonical_version_component(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
}

fn capability_selector(value: &str) -> Option<(&str, &str)> {
    let (id, major) = value.rsplit_once('@')?;
    let mut id_bytes = id.bytes();
    if !(5..=160).contains(&value.len())
        || !(3..=160).contains(&id.len())
        || !id_bytes.next()?.is_ascii_lowercase()
        || !id_bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
        })
        || !canonical_version_component(major)
    {
        return None;
    }
    Some((id, major))
}

fn full_version_major(value: &str) -> Option<&str> {
    let components = value.split('.').collect::<Vec<_>>();
    if value.len() > 64
        || !(2..=3).contains(&components.len())
        || !components
            .iter()
            .all(|component| canonical_version_component(component))
    {
        return None;
    }
    components.first().copied()
}

fn contract_content_hash(value: &str) -> bool {
    let Some((algorithm, digest)) = value.split_once(':') else {
        return false;
    };
    !algorithm.is_empty()
        && algorithm.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
        && !digest.is_empty()
        && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn snapshot_contract(value: &Value, capability: &str) -> Option<SnapshotContract> {
    let (requested_id, requested_major) = capability_selector(capability)?;
    let contracts = value.get("capability_contracts")?.as_array()?;
    let mut matched = None;
    for contract in contracts {
        let contract = contract.as_object()?;
        let id = contract.get("id")?.as_str()?;
        let version = contract.get("version")?.as_str()?;
        let content_hash = contract.get("content_hash")?.as_str()?;
        if !(3..=160).contains(&id.len()) || !contract_content_hash(content_hash) {
            return None;
        }
        if id == requested_id
            && full_version_major(version)? == requested_major
            && matched
                .replace(SnapshotContract {
                    version: version.to_owned(),
                    content_hash: content_hash.to_owned(),
                })
                .is_some()
        {
            return None;
        }
    }
    matched
}

fn snapshot_contract_hash(value: &Value, capability: &str) -> Option<String> {
    snapshot_contract(value, capability).map(|contract| contract.content_hash)
}

#[allow(
    clippy::too_many_lines,
    reason = "keeps Stage-1 shared evidence projection beside the retained baseline validation path"
)]
fn conformance_evidence_valid(
    binding: &BindingEvidence,
    contract: &SnapshotContract,
    checked_at: &str,
    admitted_suite_version: Option<&str>,
) -> Result<bool> {
    if let Some(suite_version) = admitted_suite_version {
        let (Some(build_hash), Some(suite_id), Some(suite_hash), Some(tested_at)) = (
            binding.provider_build_hash.as_deref(),
            binding.conformance_suite_id.as_deref(),
            binding.conformance_suite_hash.as_deref(),
            binding.conformance_tested_at.as_deref(),
        ) else {
            return Ok(false);
        };
        let expected = aios_registry::EvidenceMatch {
            evidence_id: &binding.conformance_evidence_id,
            provider_id: &binding.principal_id,
            provider_version: &binding.provider_version,
            build_hash,
            capability: &binding.capability,
            contract_version: &contract.version,
            contract_hash: &contract.content_hash,
            suite_id,
            suite_hash,
            suite_version,
            status: &binding.conformance_status,
            tested_at,
            evaluated_at: &binding.created_at,
        };
        let created = OffsetDateTime::parse(&binding.created_at, &Rfc3339).ok();
        let checked = OffsetDateTime::parse(checked_at, &Rfc3339).ok();
        return Ok(created
            .zip(checked)
            .is_some_and(|(created, checked)| created <= checked)
            && aios_registry::evidence_matches_binding(
                binding.conformance_json.as_bytes(),
                &expected,
            )
            && aios_registry::evidence_matches_binding(
                binding.conformance_json.as_bytes(),
                &aios_registry::EvidenceMatch {
                    evaluated_at: checked_at,
                    ..expected
                },
            ));
    }
    let Ok(evidence) = aios_registry::parse_strict_value(
        binding.conformance_json.as_bytes(),
        aios_registry::StrictJsonLimits::default(),
    ) else {
        return Ok(false);
    };
    if !provider_conformance_result_validator()?.is_valid(&evidence) {
        return Ok(false);
    }
    let Ok(checked_at_time) = OffsetDateTime::parse(checked_at, &Rfc3339) else {
        return Ok(false);
    };
    let tested_at = binding
        .conformance_tested_at
        .as_deref()
        .and_then(|tested_at| OffsetDateTime::parse(tested_at, &Rfc3339).ok());
    let created_at = OffsetDateTime::parse(&binding.created_at, &Rfc3339).ok();
    let executed_at_valid = tested_at.is_some_and(|tested_at| {
        tested_at <= checked_at_time
            && admitted_suite_version.is_none_or(|_| {
                created_at.is_some_and(|created| tested_at <= created && created <= checked_at_time)
            })
    });
    let not_expired = match evidence.get("expires_at") {
        None | Some(Value::Null) => true,
        Some(Value::String(expires_at)) => {
            let Ok(expires_at) = OffsetDateTime::parse(expires_at, &Rfc3339) else {
                return Ok(false);
            };
            expires_at > checked_at_time
                && admitted_suite_version
                    .is_none_or(|_| tested_at.is_some_and(|tested| expires_at > tested))
        }
        Some(_) => false,
    };
    let admitted_pass_valid = admitted_suite_version.is_none_or(|suite_version| {
        let total = evidence.get("tests_total").and_then(Value::as_u64);
        total.is_some_and(|total| total > 0)
            && evidence.get("tests_passed").and_then(Value::as_u64) == total
            && evidence.get("tests_failed").and_then(Value::as_u64) == Some(0)
            && evidence
                .pointer("/conformance_suite/version")
                .and_then(Value::as_str)
                == Some(suite_version)
    });
    Ok(executed_at_valid
        && not_expired
        && admitted_pass_valid
        && evidence.get("result_id").and_then(Value::as_str)
            == Some(binding.conformance_evidence_id.as_str())
        && evidence.get("provider_id").and_then(Value::as_str)
            == Some(binding.principal_id.as_str())
        && evidence.get("provider_version").and_then(Value::as_str)
            == Some(binding.provider_version.as_str())
        && evidence
            .pointer("/provider_build_identity/value")
            .and_then(Value::as_str)
            == binding.provider_build_hash.as_deref()
        && evidence
            .get("semantic_capability_ref")
            .and_then(Value::as_str)
            == Some(binding.capability.as_str())
        && evidence
            .get("semantic_contract_version")
            .and_then(Value::as_str)
            == Some(contract.version.as_str())
        && evidence
            .get("semantic_contract_hash")
            .and_then(Value::as_str)
            == Some(contract.content_hash.as_str())
        && evidence
            .pointer("/conformance_suite/id")
            .and_then(Value::as_str)
            == binding.conformance_suite_id.as_deref()
        && evidence
            .pointer("/conformance_suite/hash")
            .and_then(Value::as_str)
            == binding.conformance_suite_hash.as_deref()
        && evidence.get("result").and_then(Value::as_str)
            == Some(binding.conformance_status.as_str())
        && evidence.get("executed_at").and_then(Value::as_str)
            == binding.conformance_tested_at.as_deref())
}

fn latest_conformance_evidence_id(
    transaction: &Transaction<'_>,
    check: &BindingGrantCheck<'_>,
    has_provider_store: bool,
) -> Result<Option<String>> {
    let seed: Option<(String, String, Option<String>, String)> = transaction.query_row(
        "SELECT b.provider_registration_id,b.capability,b.capability_contract_hash,r.registration_json
         FROM execution_bindings b JOIN provider_registrations r ON r.registration_id=b.provider_registration_id
         WHERE b.binding_id=?1 AND b.attempt_id=?2 AND b.task_id=?3
           AND b.semantic_program_hash=?4 AND b.node_id=?5",
        params![check.binding_id, check.attempt_id, check.task_id, check.semantic_hash, check.node_id],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
    ).optional()?;
    let Some((registration_id, capability, contract_hash, receipt_json)) = seed else {
        return Ok(None);
    };
    let Ok(checked_at) = OffsetDateTime::parse(check.checked_at, &Rfc3339) else {
        return Ok(None);
    };
    let claimed_suite = if has_provider_store {
        let Ok(receipt) = aios_registry::parse_strict_value(
            receipt_json.as_bytes(),
            aios_registry::StrictJsonLimits::default(),
        ) else {
            return Ok(None);
        };
        let Some(claims) = receipt.get("capabilities").and_then(Value::as_array) else {
            return Ok(None);
        };
        let matching = claims
            .iter()
            .filter_map(|claim| {
                let id = claim.get("capability")?.as_str()?;
                let version =
                    aios_registry::FullVersion::parse(claim.get("version")?.as_str()?).ok()?;
                if capability != format!("{id}@{}", version.major)
                    || claim.get("contract_hash")?.as_str() != contract_hash.as_deref()
                {
                    return None;
                }
                Some((
                    claim.get("conformance_suite")?.as_str()?.to_owned(),
                    claim.get("conformance_suite_hash")?.as_str()?.to_owned(),
                ))
            })
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Ok(None);
        }
        Some(matching[0].clone())
    } else {
        None
    };
    let mut statement = transaction.prepare(
        "SELECT evidence_id,tested_at,suite_id,suite_hash FROM provider_conformance_evidence
         WHERE registration_id=?1 AND capability=?2 AND contract_hash=?3",
    )?;
    let mut rows = statement.query(params![registration_id, capability, contract_hash])?;
    let mut latest: Option<OffsetDateTime> = None;
    let mut latest_id: Option<String> = None;
    let mut tied = false;
    while let Some(row) = rows.next()? {
        let id: String = row.get(0)?;
        let Some(suite_id) = row.get::<_, Option<String>>(2)? else {
            // Baseline evidence may predate required suite identities. It is
            // retained for audit but cannot participate in Stage-1 selection.
            continue;
        };
        let suite_hash: Option<String> = row.get(3)?;
        if claimed_suite.as_ref().is_some_and(|(id, hash)| {
            id != &suite_id || Some(hash.as_str()) != suite_hash.as_deref()
        }) {
            continue;
        }
        let Some(raw_time) = row.get::<_, Option<String>>(1)? else {
            return Ok(None);
        };
        let Ok(time) = OffsetDateTime::parse(&raw_time, &Rfc3339) else {
            return Ok(None);
        };
        if time > checked_at {
            continue;
        }
        match latest {
            Some(previous) if time < previous => {}
            Some(previous) if time == previous => tied = true,
            _ => {
                latest = Some(time);
                latest_id = Some(id);
                tied = false;
            }
        }
    }
    Ok((!tied).then_some(latest_id).flatten())
}

fn embedded_provider_schema(
    source: &'static str,
    cache: &'static OnceLock<std::result::Result<jsonschema::Validator, String>>,
) -> Result<&'static jsonschema::Validator> {
    cache
        .get_or_init(|| {
            let schema: Value = serde_json::from_str(source).map_err(|error| error.to_string())?;
            jsonschema::options()
                .should_validate_formats(true)
                .build(&schema)
                .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|_| TaskManagerError::InvalidRecord("embedded provider schema is invalid"))
}

fn provider_manifest_validator() -> Result<&'static jsonschema::Validator> {
    static CACHE: OnceLock<std::result::Result<jsonschema::Validator, String>> = OnceLock::new();
    embedded_provider_schema(
        include_str!("../../../specs/capability-manifest.schema.json"),
        &CACHE,
    )
}

fn provider_registration_validator() -> Result<&'static jsonschema::Validator> {
    static CACHE: OnceLock<std::result::Result<jsonschema::Validator, String>> = OnceLock::new();
    embedded_provider_schema(
        include_str!("../../../specs/provider-registration.schema.json"),
        &CACHE,
    )
}

fn provider_identity_digest(domain: &[u8], content: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(content);
    let mut result = String::from("sha256:");
    for byte in digest.finalize() {
        write!(&mut result, "{byte:02x}").expect("String writes do not fail");
    }
    result
}

type ProviderAdmissionRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
);

#[allow(
    clippy::too_many_lines,
    reason = "verifies persisted provider identity, immutable receipt, and both semantic snapshots"
)]
fn verified_provider_receipt_and_compatibility(
    transaction: &Transaction<'_>,
    binding: &BindingEvidence,
    checked_at: &str,
) -> Result<bool> {
    let Some(registration_id) = binding.provider_registration_id.as_deref() else {
        return Ok(false);
    };
    let record: Option<ProviderAdmissionRow> = transaction
        .query_row(
            "SELECT r.provider_id,r.provider_version,r.manifest_hash,r.package_content_hash,
                r.registry_snapshot_id,r.registration_json,r.registered_at,
                r.trust_status,m.manifest_json
         FROM provider_registrations r JOIN provider_manifest_payloads m
           ON m.registration_id=r.registration_id WHERE r.registration_id=?1",
            [registration_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            },
        )
        .optional()?;
    let Some((
        provider_id,
        version,
        manifest_hash,
        build_hash,
        snapshot_id,
        receipt_json,
        registered_at,
        trust_status,
        manifest_json,
    )) = record
    else {
        return Ok(false);
    };
    if provider_id != binding.principal_id
        || version != binding.provider_version
        || Some(manifest_hash.as_str()) != binding.provider_manifest_hash.as_deref()
        || Some(build_hash.as_str()) != binding.provider_build_hash.as_deref()
        || OffsetDateTime::parse(&registered_at, &Rfc3339).is_err()
    {
        return Ok(false);
    }
    let limits = aios_registry::StrictJsonLimits {
        max_bytes: 1024 * 1024,
        max_depth: 32,
    };
    let Ok(manifest_value) = aios_registry::parse_strict_value(manifest_json.as_bytes(), limits)
    else {
        return Ok(false);
    };
    if canonical_json(&manifest_value)? != manifest_json
        || !provider_manifest_validator()?.is_valid(&manifest_value)
    {
        return Ok(false);
    }
    let Ok(manifest) =
        serde_json::from_value::<aios_contracts::CapabilityManifest>(manifest_value.clone())
    else {
        return Ok(false);
    };
    let expected_manifest_hash =
        provider_identity_digest(b"AIOS-PROVIDER-MANIFEST\0v0.1\0", manifest_json.as_bytes());
    let expected_registration_id = provider_identity_digest(
        b"AIOS-PROVIDER-REGISTRATION\0v0.1\0",
        format!("{provider_id}\0{version}\0{manifest_hash}\0{build_hash}").as_bytes(),
    );
    if manifest.id != provider_id
        || manifest.version != version
        || expected_manifest_hash != manifest_hash
        || expected_registration_id != registration_id
    {
        return Ok(false);
    }
    let admitted_registration = aios_registry::ProviderRegistration {
        registration_id: registration_id.to_owned(),
        provider_id: provider_id.clone(),
        provider_version: version.clone(),
        manifest_hash: manifest_hash.clone(),
        build_hash: build_hash.clone(),
        snapshot_id: snapshot_id.clone(),
    };
    if aios_registry::verify_provider_registration_receipt(
        &admitted_registration,
        &manifest,
        &trust_status,
        &registered_at,
        &receipt_json,
    )
    .is_err()
    {
        return Ok(false);
    }
    let Ok((effective_trust, _)) = aios_registry::verified_provider_trust_source_at(
        transaction,
        &admitted_registration,
        &manifest,
        checked_at,
    ) else {
        return Ok(false);
    };
    if !matches!(
        effective_trust,
        aios_registry::ProviderTrustStatus::LocallyTrusted
            | aios_registry::ProviderTrustStatus::ProjectReviewed
            | aios_registry::ProviderTrustStatus::OrganizationApproved
    ) {
        return Ok(false);
    }
    let Ok(receipt) = aios_registry::parse_strict_value(receipt_json.as_bytes(), limits) else {
        return Ok(false);
    };
    if canonical_json(&receipt)? != receipt_json
        || !provider_registration_validator()?.is_valid(&receipt)
        || receipt.get("registration_id").and_then(Value::as_str) != Some(registration_id)
        || receipt.pointer("/provider/id").and_then(Value::as_str) != Some(provider_id.as_str())
        || receipt.pointer("/provider/version").and_then(Value::as_str) != Some(version.as_str())
        || receipt
            .pointer("/provider/manifest_hash")
            .and_then(Value::as_str)
            != Some(manifest_hash.as_str())
        || receipt
            .pointer("/package/content_hash")
            .and_then(Value::as_str)
            != Some(build_hash.as_str())
        || receipt.get("registry_snapshot_id").and_then(Value::as_str) != Some(snapshot_id.as_str())
        || receipt.get("registered_at").and_then(Value::as_str) != Some(registered_at.as_str())
        || receipt.pointer("/trust/status").and_then(Value::as_str) != Some(trust_status.as_str())
    {
        return Ok(false);
    }
    let Some(receipt_claims) = receipt.get("capabilities").and_then(Value::as_array) else {
        return Ok(false);
    };
    if receipt_claims.len() != manifest.provides.len() {
        return Ok(false);
    }
    let mut binding_claim_matches = 0;
    for (claim, recorded) in manifest.provides.iter().zip(receipt_claims) {
        if recorded.get("capability").and_then(Value::as_str)
            != Some(claim.contract.capability.as_str())
            || recorded.get("version").and_then(Value::as_str)
                != Some(claim.contract.version.as_str())
            || recorded.get("contract_hash").and_then(Value::as_str)
                != claim.contract.contract_hash.as_deref()
            || recorded.get("conformance_suite").and_then(Value::as_str)
                != Some(claim.conformance.suite.as_str())
            || recorded
                .get("conformance_suite_hash")
                .and_then(Value::as_str)
                != claim.conformance.suite_hash.as_deref()
            || recorded.get("conformance_status").and_then(Value::as_str) != Some("declared")
            || recorded.get("eligible").and_then(Value::as_bool) != Some(false)
        {
            return Ok(false);
        }
        let Ok(version) = aios_registry::FullVersion::parse(&claim.contract.version) else {
            return Ok(false);
        };
        if binding.capability == format!("{}@{}", claim.contract.capability, version.major)
            && claim.contract.contract_hash.as_deref() == binding.contract_hash.as_deref()
            && Some(claim.conformance.suite.as_str()) == binding.conformance_suite_id.as_deref()
            && claim.conformance.suite_hash.as_deref() == binding.conformance_suite_hash.as_deref()
        {
            binding_claim_matches += 1;
        }
    }
    if binding_claim_matches != 1 {
        return Ok(false);
    }
    let origin_state: Option<String> = transaction
        .query_row(
            "SELECT state FROM semantic_current_usable_snapshots WHERE snapshot_id=?1",
            [&snapshot_id],
            |row| row.get(0),
        )
        .optional()?;
    if !matches!(origin_state.as_deref(), Some("ADMITTED" | "DEPRECATED")) {
        return Ok(false);
    }
    let Some(origin_registry) = load_admitted_semantic_registry(transaction, &snapshot_id)? else {
        return Ok(false);
    };
    let Some(selected_registry) =
        load_admitted_semantic_registry(transaction, &binding.registry_snapshot_id)?
    else {
        return Ok(false);
    };
    let options = aios_registry::ProviderConformanceOptions::default();
    let origin_report =
        aios_registry::validate_provider_manifest(&origin_registry, &manifest, options);
    let mut selected_manifest = manifest.clone();
    selected_manifest.provides.retain(|claim| {
        aios_registry::FullVersion::parse(&claim.contract.version)
            .ok()
            .is_some_and(|version| {
                binding.capability == format!("{}@{}", claim.contract.capability, version.major)
                    && claim.contract.contract_hash.as_deref() == binding.contract_hash.as_deref()
                    && Some(claim.conformance.suite.as_str())
                        == binding.conformance_suite_id.as_deref()
                    && claim.conformance.suite_hash.as_deref()
                        == binding.conformance_suite_hash.as_deref()
            })
    });
    let selected_report =
        aios_registry::validate_provider_manifest(&selected_registry, &selected_manifest, options);
    Ok(origin_report.valid
        && !origin_report.bootstrap_contract_hash_bypass_used
        && selected_report.valid
        && !selected_report.bootstrap_contract_hash_bypass_used)
}

/// A binding must retain the exact trust source that existed when its
/// immutable receipt was inserted. Later provider review requires a new
/// attempt; it cannot retroactively authorize an older binding.
fn verified_provider_admission(
    transaction: &Transaction<'_>,
    binding_id: &str,
    binding: &BindingEvidence,
    checked_at: &str,
    receipt: &aios_registry::BindingReceiptProjection,
) -> Result<bool> {
    let quarantined: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM execution_binding_legacy_trust_quarantine WHERE binding_id=?1)",
        [binding_id],
        |row| row.get(0),
    )?;
    if quarantined {
        return Ok(false);
    }
    if !verified_provider_receipt_and_compatibility(transaction, binding, checked_at)? {
        return Ok(false);
    }
    let Some(registration_id) = binding.provider_registration_id.as_deref() else {
        return Ok(false);
    };
    let Ok(checked_time) = OffsetDateTime::parse(checked_at, &Rfc3339) else {
        return Ok(false);
    };
    let mut statement = transaction.prepare(
        "SELECT admission_id,admitted_at FROM provider_trust_admissions
         WHERE registration_id=?1 ORDER BY revision DESC",
    )?;
    let mut rows = statement.query([registration_id])?;
    let mut expected_source = registration_id.to_owned();
    while let Some(row) = rows.next()? {
        let admitted_at: String = row.get(1)?;
        let Ok(admitted_time) = OffsetDateTime::parse(&admitted_at, &Rfc3339) else {
            return Ok(false);
        };
        if admitted_time <= checked_time {
            expected_source = row.get(0)?;
            break;
        }
    }
    let admitted_source: Option<String> = transaction
        .query_row(
            "SELECT trust_source_id FROM execution_binding_trust_markers WHERE binding_id=?1",
            [binding_id],
            |row| row.get(0),
        )
        .optional()?;
    Ok(admitted_source.as_deref() == Some(expected_source.as_str())
        && receipt.trust_pin() == Some(expected_source.as_str()))
}

fn load_admitted_semantic_registry(
    transaction: &Transaction<'_>,
    snapshot_id: &str,
) -> Result<Option<aios_registry::SemanticRegistry>> {
    let snapshot_json: Option<String> = transaction
        .query_row(
            "SELECT manifest_json FROM registry_snapshots WHERE snapshot_id=?1",
            [snapshot_id],
            |row| row.get(0),
        )
        .optional()?;
    let Some(snapshot_json) = snapshot_json else {
        return Ok(None);
    };
    let Ok(snapshot) = aios_registry::parse_strict_json::<aios_contracts::RegistrySnapshot>(
        snapshot_json.as_bytes(),
        aios_registry::StrictJsonLimits::default(),
    ) else {
        return Ok(None);
    };
    let mut types = Vec::new();
    let mut capabilities = Vec::new();
    for (class, sink_type) in [("type", true), ("capability", false)] {
        let mut statement = transaction.prepare(
            "SELECT t.contract_json,c.contract_json FROM registry_snapshot_entries e
             LEFT JOIN semantic_type_contracts t ON e.contract_class='type' AND t.content_hash=e.content_hash
             LEFT JOIN semantic_capability_contracts c ON e.contract_class='capability' AND c.content_hash=e.content_hash
             WHERE e.snapshot_id=?1 AND e.contract_class=?2",
        )?;
        let mut rows = statement.query(params![snapshot_id, class])?;
        while let Some(row) = rows.next()? {
            if sink_type {
                let Some(json) = row.get::<_, Option<String>>(0)? else {
                    return Ok(None);
                };
                let Ok(contract) = aios_registry::parse_strict_json::<aios_contracts::TypeContract>(
                    json.as_bytes(),
                    aios_registry::StrictJsonLimits::default(),
                ) else {
                    return Ok(None);
                };
                types.push(contract);
            } else {
                let Some(json) = row.get::<_, Option<String>>(1)? else {
                    return Ok(None);
                };
                let Ok(contract) = aios_registry::parse_strict_json::<
                    aios_contracts::CapabilityContract,
                >(
                    json.as_bytes(), aios_registry::StrictJsonLimits::default()
                ) else {
                    return Ok(None);
                };
                capabilities.push(contract);
            }
        }
    }
    let Ok(registry) = aios_registry::SemanticRegistry::from_records(
        snapshot,
        types,
        capabilities,
        aios_registry::RegistryBuildOptions::default(),
    ) else {
        return Ok(None);
    };
    Ok((registry.snapshot_id() == snapshot_id).then_some(registry))
}

fn admitted_suite_version(
    transaction: &Transaction<'_>,
    binding: &BindingEvidence,
) -> Result<Option<String>> {
    let Some(registry) =
        load_admitted_semantic_registry(transaction, &binding.registry_snapshot_id)?
    else {
        return Ok(None);
    };
    let Some((capability, major)) = binding.capability.rsplit_once('@') else {
        return Ok(None);
    };
    let Ok(major) = major.parse::<u64>() else {
        return Ok(None);
    };
    let Some(contract) = registry.capability_contract(capability, major) else {
        return Ok(None);
    };
    Ok(contract.conformance.suite_version.clone())
}

fn binding_receipt_projection(
    binding: &BindingEvidence,
    check: &BindingGrantCheck<'_>,
    require_pin: bool,
) -> Option<aios_registry::BindingReceiptProjection> {
    let receipt =
        aios_registry::BindingReceiptProjection::parse(binding.binding_json.as_bytes()).ok()?;
    let columns = aios_registry::BindingReceiptColumns {
        binding_id: check.binding_id,
        attempt_id: check.attempt_id,
        task_id: check.task_id,
        semantic_program_hash: check.semantic_hash,
        registry_snapshot_id: &binding.registry_snapshot_id,
        ir_version: &binding.ir_version,
        node_id: check.node_id,
        capability: &binding.capability,
        capability_contract_hash: binding.contract_hash.as_deref(),
        provider_id: &binding.principal_id,
        provider_version: &binding.provider_version,
        provider_manifest_hash: binding.provider_manifest_hash.as_deref(),
        provider_build_hash: binding.provider_build_hash.as_deref(),
        attempt: binding.attempt,
        policy_decision_refs_json: &binding.policy_decision_refs_json,
        grant_refs_json: &binding.grant_refs_json,
        execution_profile_ref: &binding.execution_profile_ref,
        placement_json: &binding.placement_json,
        created_at: &binding.created_at,
    };
    ((!require_pin || receipt.conforms_to_stamped_schema())
        && receipt.matches_columns(&columns)
        && receipt.evidence_pin_matches(&binding.conformance_evidence_id, require_pin)
        && (!require_pin || receipt.trust_pin().is_some()))
    .then_some(receipt)
}

fn program_node<'a>(program: &'a Value, node_id: &str) -> Option<&'a Value> {
    let mut matches = program
        .get("nodes")?
        .as_array()?
        .iter()
        .filter(|node| node.get("id").and_then(Value::as_str) == Some(node_id));
    let node = matches.next()?;
    matches.next().is_none().then_some(node)
}

fn program_output_ports(
    program: &Value,
    node_id: &str,
) -> Option<std::collections::BTreeMap<String, String>> {
    program_node(program, node_id)?
        .get("outputs")?
        .as_object()?
        .iter()
        .map(|(port, semantic_type)| {
            semantic_type
                .as_str()
                .map(|semantic_type| (port.clone(), semantic_type.to_owned()))
        })
        .collect()
}

fn output_allocations_ready(
    transaction: &Transaction<'_>,
    check: &BindingGrantCheck<'_>,
) -> Result<bool> {
    let program_json = transaction.query_row(
        "SELECT p.program_json FROM tasks t JOIN semantic_program_revisions p ON p.task_id = t.task_id AND p.program_revision = t.active_program_revision WHERE t.task_id = ?1 AND p.semantic_hash = ?2",
        params![check.task_id, check.semantic_hash],
        |row| row.get::<_, String>(0),
    )?;
    let program: Value = serde_json::from_str(&program_json)?;
    let Some(expected_ports) = program_output_ports(&program, check.node_id) else {
        return Ok(false);
    };
    let checked_at = OffsetDateTime::parse(check.checked_at, &Rfc3339)
        .map_err(|_| TaskManagerError::InvalidRecord("trusted allocation time is not RFC 3339"))?;
    let mut actual = std::collections::BTreeMap::new();
    let mut statement = transaction.prepare(
        "SELECT output_port, expected_semantic_type, expires_at FROM artifact_output_allocations WHERE task_id = ?1 AND semantic_program_hash = ?2 AND node_id = ?3 AND binding_id = ?4 AND attempt_id = ?5 AND state = 'ALLOCATED'",
    )?;
    let rows = statement.query_map(
        params![
            check.task_id,
            check.semantic_hash,
            check.node_id,
            check.binding_id,
            check.attempt_id
        ],
        |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, String>(2)?,
            ))
        },
    )?;
    for row in rows {
        let (Some(port), Some(semantic_type), expires_at) = row? else {
            return Ok(false);
        };
        let Ok(expires_at) = OffsetDateTime::parse(&expires_at, &Rfc3339) else {
            return Ok(false);
        };
        if expires_at <= checked_at || actual.insert(port, semantic_type).is_some() {
            return Ok(false);
        }
    }
    Ok(actual == expected_ports)
}

#[allow(
    clippy::too_many_lines,
    reason = "keeps the exact semantic-request, policy-decision, and runtime-grant intersection auditable"
)]
fn binding_grants_valid(
    transaction: &Transaction<'_>,
    check: &BindingGrantCheck<'_>,
) -> Result<bool> {
    let grant_ids: Vec<String> = serde_json::from_str(check.grant_refs_json)?;
    if grant_ids.len() > 64 || !all_unique(&grant_ids) {
        return Ok(false);
    }
    let has_registry_store: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE migration_id='0012_semantic_registry_store')",
        [], |row| row.get(0),
    )?;
    let has_provider_store: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE migration_id='0013_provider_registry')",
        [], |row| row.get(0),
    )?;
    let Some(latest_evidence_id) =
        latest_conformance_evidence_id(transaction, check, has_provider_store)?
    else {
        return Ok(false);
    };
    let mut binding_query = String::from(
        "SELECT b.capability, b.provider_id, p.program_json, p.registry_snapshot_id,
                    b.capability_contract_hash, s.manifest_json, b.ir_version,
                    b.provider_version, b.provider_manifest_hash, b.provider_build_hash,
                    b.provider_registration_id, b.attempt, b.policy_decision_refs_json,
                    b.grant_refs_json, b.execution_profile_ref, b.placement_json,
                    b.binding_json, b.created_at, c.evidence_id, c.suite_id,
                    c.suite_hash, c.status, c.evidence_json, c.tested_at
             FROM execution_bindings b
             JOIN tasks t ON t.task_id = b.task_id
             JOIN semantic_program_revisions p ON p.task_id = t.task_id AND p.program_revision = t.active_program_revision AND p.status = 'active'
             JOIN registry_snapshots s ON s.snapshot_id = p.registry_snapshot_id
             JOIN provider_registrations r ON r.registration_id = b.provider_registration_id
                AND r.provider_id = b.provider_id AND r.provider_version = b.provider_version
                AND r.state = 'registered'
                AND r.manifest_hash = b.provider_manifest_hash
                AND r.package_content_hash = b.provider_build_hash
             JOIN provider_conformance_evidence c ON c.evidence_id = ?6
                AND c.registration_id = r.registration_id AND c.capability = b.capability
                AND c.contract_hash = b.capability_contract_hash AND c.status = 'pass'
             WHERE b.binding_id = ?1 AND b.attempt_id = ?2 AND b.task_id = ?3
                AND b.semantic_program_hash = ?4 AND b.node_id = ?5
                AND b.registry_snapshot_id = p.registry_snapshot_id AND b.semantic_program_hash = p.semantic_hash",
    );
    if has_registry_store {
        binding_query.push_str(
            " AND EXISTS(SELECT 1 FROM semantic_current_usable_snapshots a
               WHERE a.snapshot_id=p.registry_snapshot_id AND a.state='ADMITTED')",
        );
    }
    if has_provider_store {
        binding_query.push_str(
            " AND EXISTS(SELECT 1 FROM execution_binding_admission_markers marker
               WHERE marker.binding_id=b.binding_id AND marker.conformance_evidence_id=c.evidence_id)
               AND EXISTS(SELECT 1 FROM execution_binding_enablement_markers marker
                   JOIN provider_state_epochs epoch
                     ON epoch.registration_id=marker.registration_id
                    AND epoch.revision=marker.revision
                   WHERE marker.binding_id=b.binding_id
                     AND marker.registration_id=r.registration_id
                     AND epoch.state='registered'
                     AND epoch.transitioned_at=r.updated_at
                     AND epoch.revision=(SELECT MAX(revision) FROM provider_state_epochs
                                         WHERE registration_id=r.registration_id))",
        );
    } else {
        // Older stores have no append-only trust decisions to verify, so the
        // immutable registration row remains the complete trust authority.
        binding_query.push_str(
            " AND r.registry_snapshot_id=b.registry_snapshot_id
               AND r.trust_status IN ('locally-trusted','project-reviewed','organization-approved')",
        );
    }
    let binding = transaction
        .query_row(
            &binding_query,
            params![
                check.binding_id,
                check.attempt_id,
                check.task_id,
                check.semantic_hash,
                check.node_id,
                latest_evidence_id
            ],
            |row| {
                Ok(BindingEvidence {
                    capability: row.get(0)?,
                    principal_id: row.get(1)?,
                    program_json: row.get(2)?,
                    registry_snapshot_id: row.get(3)?,
                    contract_hash: row.get(4)?,
                    snapshot_manifest_json: row.get(5)?,
                    ir_version: row.get(6)?,
                    provider_version: row.get(7)?,
                    provider_manifest_hash: row.get(8)?,
                    provider_build_hash: row.get(9)?,
                    provider_registration_id: row.get(10)?,
                    attempt: row.get(11)?,
                    policy_decision_refs_json: row.get(12)?,
                    grant_refs_json: row.get(13)?,
                    execution_profile_ref: row.get(14)?,
                    placement_json: row.get(15)?,
                    binding_json: row.get(16)?,
                    created_at: row.get(17)?,
                    conformance_evidence_id: row.get(18)?,
                    conformance_suite_id: row.get(19)?,
                    conformance_suite_hash: row.get(20)?,
                    conformance_status: row.get(21)?,
                    conformance_json: row.get(22)?,
                    conformance_tested_at: row.get(23)?,
                })
            },
        )
        .optional()?;
    let Some(binding) = binding else {
        return Ok(false);
    };
    if binding.provider_registration_id.is_none()
        || binding.grant_refs_json != check.grant_refs_json
    {
        return Ok(false);
    }
    let Some(receipt) = binding_receipt_projection(&binding, check, has_provider_store) else {
        return Ok(false);
    };
    if has_provider_store
        && !verified_provider_admission(
            transaction,
            check.binding_id,
            &binding,
            check.checked_at,
            &receipt,
        )?
    {
        return Ok(false);
    }
    let snapshot: Value = serde_json::from_str(&binding.snapshot_manifest_json)?;
    let Some(contract) = snapshot_contract(&snapshot, &binding.capability) else {
        return Ok(false);
    };
    let suite_version = if has_provider_store {
        let Some(version) = admitted_suite_version(transaction, &binding)? else {
            return Ok(false);
        };
        Some(version)
    } else {
        None
    };
    if Some(contract.content_hash.as_str()) != binding.contract_hash.as_deref()
        || !conformance_evidence_valid(
            &binding,
            &contract,
            check.checked_at,
            suite_version.as_deref(),
        )?
    {
        return Ok(false);
    }
    let capability = binding.capability;
    let principal_id = binding.principal_id;
    let registry_snapshot_id = binding.registry_snapshot_id;
    let policy_refs: Vec<String> = serde_json::from_str(&binding.policy_decision_refs_json)?;
    if policy_refs.len() > 64 || !all_unique(&policy_refs) {
        return Ok(false);
    }
    let program: Value = serde_json::from_str(&binding.program_json)?;
    let Some(node) = program_node(&program, check.node_id) else {
        return Ok(false);
    };
    if node
        .pointer("/operation/capability")
        .and_then(Value::as_str)
        != Some(capability.as_str())
    {
        return Ok(false);
    }
    let Some(authority_requests) = node.get("authority_requests").and_then(Value::as_array) else {
        return Ok(false);
    };
    let mut required_semantics = std::collections::BTreeSet::new();
    for authority in authority_requests {
        let (Some(action), Some(resource)) = (
            authority.get("action").and_then(Value::as_str),
            authority.get("resource").and_then(Value::as_str),
        ) else {
            return Ok(false);
        };
        if !required_semantics.insert((action.to_owned(), resource.to_owned())) {
            return Ok(false);
        }
    }
    let durable_requests = {
        let mut statement = transaction.prepare(
            "SELECT request_id, capability, principal_kind, principal_id, action, resolved_resource_kind, resolved_resource_id, semantic_selector FROM authority_requests WHERE task_id = ?1 AND semantic_program_hash = ?2 AND registry_snapshot_id = ?3 AND node_id = ?4 AND execution_binding_id = ?5 AND attempt_id = ?6 ORDER BY request_id",
        )?;
        let rows = statement.query_map(
            params![
                check.task_id,
                check.semantic_hash,
                registry_snapshot_id,
                check.node_id,
                check.binding_id,
                check.attempt_id
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                ))
            },
        )?;
        rows.collect::<std::result::Result<Vec<_>, _>>()?
    };
    if durable_requests.len() != required_semantics.len() {
        return Ok(false);
    }
    let mut durable_by_id = std::collections::BTreeMap::new();
    let mut durable_semantics = std::collections::BTreeSet::new();
    for request in durable_requests {
        if request.1 != capability
            || request.2 != "provider"
            || request.3 != principal_id
            || request.5.is_empty()
            || request.6.is_empty()
            || request.7.is_none()
        {
            return Ok(false);
        }
        let Some(selector) = request.7.as_ref() else {
            return Ok(false);
        };
        if !durable_semantics.insert((request.4.clone(), selector.clone()))
            || durable_by_id.insert(request.0.clone(), request).is_some()
        {
            return Ok(false);
        }
    }
    if durable_semantics != required_semantics || grant_ids.len() != durable_by_id.len() {
        return Ok(false);
    }
    let mut covered_requests = std::collections::BTreeSet::new();
    let mut covered_decisions = std::collections::BTreeSet::new();
    for grant_id in grant_ids {
        let grant = transaction
            .query_row(
                "SELECT g.expires_at, g.capability, g.principal_kind, g.principal_id, g.policy_snapshot_id, g.grants_json, r.request_id, d.task_id, d.semantic_program_hash, d.node_id, d.principal_kind, d.principal_id, d.action, d.resolved_resource_kind, d.resolved_resource_id, d.decision, d.policy_snapshot_id, g.approval_id, d.approval_request_id, g.scope, d.decision_id, g.delegable, g.max_delegation_depth FROM authority_grants g JOIN authority_issuance_receipts i ON i.grant_id=g.grant_id AND i.token_id=g.token_id AND i.task_id=g.task_id AND i.execution_binding_id=g.execution_binding_id AND i.attempt_id=g.attempt_id AND i.policy_decision_id=g.policy_decision_id AND i.issued_at=g.issued_at AND i.issuance_profile='coordinator-issued-v0.1' JOIN policy_decisions d ON d.decision_id = g.policy_decision_id JOIN authority_requests r ON r.request_id = d.authority_request_id WHERE g.grant_id = ?1 AND g.task_id = ?2 AND g.semantic_program_hash = ?3 AND g.node_id = ?4 AND g.execution_binding_id = ?5 AND g.attempt_id = ?6 AND g.state = 'ACTIVE' AND g.scope IN ('ONE_SHOT', 'TASK', 'TIME_LIMITED') AND (g.max_uses IS NULL OR g.uses_consumed < g.max_uses)",
                params![grant_id, check.task_id, check.semantic_hash, check.node_id, check.binding_id, check.attempt_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?, row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?, row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?, row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?, row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?, row.get::<_, String>(9)?,
                        row.get::<_, String>(10)?, row.get::<_, String>(11)?,
                        row.get::<_, String>(12)?, row.get::<_, String>(13)?,
                        row.get::<_, String>(14)?, row.get::<_, String>(15)?,
                        row.get::<_, String>(16)?, row.get::<_, Option<String>>(17)?,
                        row.get::<_, Option<String>>(18)?,
                        row.get::<_, String>(19)?,
                        row.get::<_, String>(20)?, row.get::<_, bool>(21)?,
                        row.get::<_, i64>(22)?,
                    ))
                },
            )
            .optional()?;
        let Some(grant) = grant else {
            return Ok(false);
        };
        let Some(request) = durable_by_id.get(&grant.6) else {
            return Ok(false);
        };
        if grant.1 != capability
            || grant.2 != "provider"
            || grant.3 != principal_id
            || grant.4 != grant.16
            || grant.7 != check.task_id
            || grant.8 != check.semantic_hash
            || grant.9 != check.node_id
            || grant.10 != request.2
            || grant.11 != request.3
            || grant.12 != request.4
            || grant.13 != request.5
            || grant.14 != request.6
            || grant.15 != "ALLOW"
            || grant.21
            || grant.22 != 0
        {
            return Ok(false);
        }
        let grant_items: Value = serde_json::from_str(&grant.5)?;
        let Some([grant_item]) = grant_items.as_array().map(Vec::as_slice) else {
            return Ok(false);
        };
        if grant_item.get("action").and_then(Value::as_str) != Some(request.4.as_str())
            || grant_item.get("resource_kind").and_then(Value::as_str) != Some(request.5.as_str())
            || grant_item.get("resource_id").and_then(Value::as_str) != Some(request.6.as_str())
            || grant_item.get("semantic_selector").and_then(Value::as_str) != request.7.as_deref()
        {
            return Ok(false);
        }
        let Ok(expires_at) = OffsetDateTime::parse(&grant.0, &Rfc3339) else {
            return Ok(false);
        };
        let Ok(checked_at) = OffsetDateTime::parse(check.checked_at, &Rfc3339) else {
            return Ok(false);
        };
        if expires_at <= checked_at {
            return Ok(false);
        }
        let grant_scope = &grant.19;
        match (&grant.17, &grant.18) {
            (None, None) => {}
            (Some(approval_id), Some(decision_approval_id))
                if approval_id == decision_approval_id =>
            {
                let approval = transaction
                    .query_row(
                        "SELECT a.expires_at, COUNT(ad.decision_id), MIN(ad.scope), MIN(ad.approved_until)
                     FROM approval_requests a
                     JOIN authority_requests ar ON ar.request_id = a.authority_request_id
                     LEFT JOIN approval_decisions ad ON ad.approval_id = a.approval_id
                        AND ad.task_id = a.task_id AND ad.decision = 'APPROVE'
                     WHERE a.approval_id = ?1 AND a.authority_request_id = ?2
                        AND a.task_id = ?3 AND a.semantic_program_hash = ?4
                        AND a.node_id = ?5 AND a.action = ?6 AND a.status = 'APPROVED'
                        AND ar.resolved_resource_kind = ?7 AND ar.resolved_resource_id = ?8
                     GROUP BY a.expires_at",
                        params![
                            approval_id,
                            request.0,
                            check.task_id,
                            check.semantic_hash,
                            check.node_id,
                            request.4,
                            request.5,
                            request.6
                        ],
                        |row| {
                            Ok((
                                row.get::<_, Option<String>>(0)?,
                                row.get::<_, i64>(1)?,
                                row.get::<_, Option<String>>(2)?,
                                row.get::<_, Option<String>>(3)?,
                            ))
                        },
                    )
                    .optional()?;
                let Some((approval_expires_at, decisions, decision_scope, approved_until)) =
                    approval
                else {
                    return Ok(false);
                };
                if decisions != 1
                    || decision_scope.as_deref() != Some(grant_scope.as_str())
                    || approval_expires_at.as_ref().is_some_and(|value| {
                        OffsetDateTime::parse(value, &Rfc3339)
                            .map_or(true, |expires| expires <= checked_at)
                    })
                {
                    return Ok(false);
                }
                if grant_scope == "TIME_LIMITED" && approved_until.is_none() {
                    return Ok(false);
                }
                if let Some(approved_until) = approved_until {
                    let Ok(approved_until) = OffsetDateTime::parse(&approved_until, &Rfc3339)
                    else {
                        return Ok(false);
                    };
                    if approved_until <= checked_at || expires_at > approved_until {
                        return Ok(false);
                    }
                }
            }
            _ => return Ok(false),
        }
        if !covered_requests.insert(grant.6) {
            return Ok(false);
        }
        if !covered_decisions.insert(grant.20.clone()) {
            return Ok(false);
        }
    }
    Ok(covered_requests == durable_by_id.keys().cloned().collect()
        && covered_decisions == policy_refs.into_iter().collect())
}

#[derive(Default)]
struct ActiveStepCompletionFacts {
    artifact_ids: std::collections::BTreeSet<String>,
    publication_tuples: std::collections::BTreeSet<(String, String, String)>,
}

#[allow(
    clippy::too_many_lines,
    reason = "audits the full program-port, attempt, publication, artifact, and blob integrity join"
)]
fn active_step_completion_facts(
    transaction: &Transaction<'_>,
    task_id: &str,
    active_steps: &[String],
) -> Result<Option<ActiveStepCompletionFacts>> {
    let program = transaction
        .query_row(
            "SELECT p.program_json,p.semantic_hash FROM tasks t JOIN semantic_program_revisions p ON p.task_id = t.task_id AND p.program_revision = t.active_program_revision WHERE t.task_id = ?1 AND p.status = 'active'",
            [task_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let Some((program_json, program_hash)) = program else {
        return Ok(None);
    };
    if !active_program_validation_valid(transaction, task_id, &program_hash)? {
        return Ok(None);
    }
    let program: Value = serde_json::from_str(&program_json)?;
    let Some(nodes) = program.get("nodes").and_then(Value::as_array) else {
        return Ok(None);
    };
    let mut expected_nodes = std::collections::BTreeSet::new();
    let mut expected_ports = Vec::new();
    for node in nodes {
        let Some(node_id) = node.get("id").and_then(Value::as_str) else {
            return Ok(None);
        };
        if !expected_nodes.insert(node_id.to_owned()) {
            return Ok(None);
        }
        let Some(outputs) = program_output_ports(&program, node_id) else {
            return Ok(None);
        };
        expected_ports.extend(
            outputs
                .into_iter()
                .map(|(port, semantic_type)| (node_id.to_owned(), port, semantic_type)),
        );
    }
    let active_nodes = active_steps
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    if expected_nodes.is_empty()
        || expected_ports.is_empty()
        || active_nodes.len() != active_steps.len()
        || active_nodes != expected_nodes
    {
        return Ok(None);
    }
    let mut completion_facts = ActiveStepCompletionFacts::default();
    for (node_id, output_port, semantic_type) in expected_ports {
        if latest_active_attempt_count(transaction, task_id, &node_id)? != 1 {
            return Ok(None);
        }
        let attempt = transaction
            .query_row(
                "SELECT s.attempt_id, s.binding_id, s.semantic_program_hash, s.state, s.outcome_certainty FROM step_executions s JOIN tasks t ON t.task_id = s.task_id JOIN semantic_program_revisions p ON p.task_id = t.task_id AND p.program_revision = t.active_program_revision AND p.semantic_hash = s.semantic_program_hash AND p.registry_snapshot_id = s.registry_snapshot_id JOIN execution_bindings b ON b.binding_id = s.binding_id AND b.attempt_id = s.attempt_id AND b.task_id = s.task_id AND b.semantic_program_hash = s.semantic_program_hash AND b.registry_snapshot_id = s.registry_snapshot_id AND b.node_id = s.node_id WHERE s.task_id = ?1 AND s.node_id = ?2 AND s.attempt_number = (SELECT MAX(s2.attempt_number) FROM step_executions s2 WHERE s2.task_id = s.task_id AND s2.node_id = s.node_id AND s2.semantic_program_hash = s.semantic_program_hash AND s2.registry_snapshot_id = s.registry_snapshot_id)",
                params![task_id, node_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((attempt_id, binding_id, semantic_hash, state, certainty)) = attempt else {
            return Ok(None);
        };
        if state != "SUCCEEDED" || certainty.as_deref() != Some("COMPLETED") {
            return Ok(None);
        }
        let artifacts = {
            let mut statement = transaction.prepare(
                "SELECT a.allocation_id, p.publication_id, a.published_artifact_id,
                        f.media_type, f.size_bytes,
                        f.sensitivity, f.retention_class, a.allowed_media_types_json,
                        a.max_size_bytes, a.sensitivity, a.retention
                 FROM artifact_output_allocations a
                 JOIN artifact_publications p ON p.publication_id = a.publication_id
                    AND p.allocation_id = a.allocation_id AND p.task_id = a.task_id
                    AND p.artifact_id = a.published_artifact_id AND p.state = 'COMMITTED'
                 JOIN artifacts f ON f.artifact_id = a.published_artifact_id
                    AND f.content_hash = p.content_hash AND f.integrity_state = 'verified'
                    AND f.integrity_verified_at IS NOT NULL
                    AND f.semantic_type = a.expected_semantic_type
                 JOIN artifact_blobs bl ON bl.content_hash = f.content_hash
                    AND bl.durability_state = 'DURABLE' AND bl.verified_at IS NOT NULL
                    AND f.size_bytes = bl.size_bytes
                 JOIN task_artifacts t ON t.task_id = a.task_id
                    AND t.artifact_id = a.published_artifact_id AND t.role = 'output'
                    AND t.node_id = a.node_id
                 WHERE a.task_id = ?1 AND a.semantic_program_hash = ?2
                    AND a.node_id = ?3 AND a.binding_id = ?4 AND a.attempt_id = ?5
                    AND a.output_port = ?6 AND a.state = 'PUBLISHED'
                    AND a.expected_semantic_type = ?7
                    AND a.published_artifact_id IS NOT NULL",
            )?;
            let rows = statement.query_map(
                params![
                    task_id,
                    semantic_hash,
                    node_id,
                    binding_id,
                    attempt_id,
                    output_port,
                    semantic_type
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, Option<String>>(7)?,
                        row.get::<_, Option<i64>>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, String>(10)?,
                    ))
                },
            )?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        if artifacts.len() != 1 {
            return Ok(None);
        }
        let (
            allocation_id,
            publication_id,
            artifact_id,
            media_type,
            size_bytes,
            artifact_sensitivity,
            artifact_retention,
            allowed_media_types_json,
            max_size_bytes,
            allocation_sensitivity,
            allocation_retention,
        ) = &artifacts[0];
        let media_allowed = if let Some(allowed_media_types_json) = allowed_media_types_json {
            let Ok(allowed) = serde_json::from_str::<Vec<String>>(allowed_media_types_json) else {
                return Ok(None);
            };
            allowed.len() <= 32 && all_unique(&allowed) && allowed.contains(media_type)
        } else {
            true
        };
        if !media_allowed
            || max_size_bytes.is_some_and(|maximum| *size_bytes > maximum)
            || artifact_sensitivity != allocation_sensitivity
            || artifact_retention.as_deref() != Some(allocation_retention.as_str())
            || !completion_facts.artifact_ids.insert(artifact_id.clone())
            || !completion_facts.publication_tuples.insert((
                publication_id.clone(),
                allocation_id.clone(),
                artifact_id.clone(),
            ))
        {
            return Ok(None);
        }
    }
    Ok(Some(completion_facts))
}

fn has_current_verification(
    transaction: &Transaction<'_>,
    task_id: &str,
    required_outputs: &std::collections::BTreeSet<String>,
) -> Result<bool> {
    let active_identity = transaction
        .query_row(
            "SELECT p.semantic_hash, p.registry_snapshot_id, p.validation_result_id FROM tasks t JOIN semantic_program_revisions p ON p.task_id = t.task_id AND p.program_revision = t.active_program_revision WHERE t.task_id = ?1 AND p.status = 'active'",
            [task_id],
            |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, Option<String>>(1)?, row.get::<_, Option<String>>(2)?)),
        )
        .optional()?;
    let Some((Some(semantic_hash), Some(registry_snapshot_id), Some(validation_result_id))) =
        active_identity
    else {
        return Ok(false);
    };
    if required_outputs.is_empty() {
        return Ok(false);
    }
    let mut statement = transaction.prepare(
        "SELECT sequence, previous_event_hash, event_hash, event_json, timestamp, event_id, status FROM provenance_events WHERE task_id = ?1 AND event_type = 'verification.completed' AND status = 'success' ORDER BY sequence DESC",
    )?;
    let rows = statement.query_map([task_id], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
        ))
    })?;
    for row in rows {
        let (sequence, previous_hash, stored_hash, event_json, timestamp, event_id, status) = row?;
        let Ok(sequence) = u64::try_from(sequence) else {
            return Ok(false);
        };
        let event = aios_provenance::parse_unique_json(&event_json)?;
        if status != "success"
            || event_string(&event, "event_id") != Some(event_id.as_str())
            || event_string(&event, "task_id") != Some(task_id)
            || event_string(&event, "event_type") != Some("verification.completed")
            || event_string(&event, "timestamp") != Some(timestamp.as_str())
            || event_string(&event, "status") != Some("success")
            || provenance_hash(task_id, sequence, previous_hash.as_deref(), &event)? != stored_hash
            || !verify_provenance_through(
                transaction,
                task_id,
                Some(i64::try_from(sequence).map_err(|_| {
                    TaskManagerError::InvalidRecord("verification sequence exceeds SQLite range")
                })?),
            )?
            || !verify_provenance_through(transaction, task_id, None)?
        {
            return Ok(false);
        }
        if event.get("semantic_program_hash").and_then(Value::as_str)
            != Some(semantic_hash.as_str())
            || event.get("registry_snapshot_id").and_then(Value::as_str)
                != Some(registry_snapshot_id.as_str())
            || event.get("validation_result_id").and_then(Value::as_str)
                != Some(validation_result_id.as_str())
        {
            continue;
        }
        let covered = event
            .get("input_artifacts")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .chain(
                event
                    .get("output_artifacts")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten(),
            )
            .filter_map(Value::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        if required_outputs
            .iter()
            .all(|item| covered.contains(item.as_str()))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn execution_is_contained(transaction: &Transaction<'_>, task_id: &str) -> Result<bool> {
    let live_attempts = transaction.query_row(
        "SELECT COUNT(*) FROM step_executions WHERE task_id = ?1 AND (state IN ('STARTING', 'RUNNING', 'UNKNOWN') OR outcome_certainty IN ('FAILED_PARTIAL_EFFECT', 'OUTCOME_UNKNOWN'))",
        [task_id],
        |row| row.get::<_, i64>(0),
    )?;
    let live_grants = transaction.query_row(
        "SELECT COUNT(*) FROM authority_grants WHERE task_id = ?1 AND state = 'ACTIVE'",
        [task_id],
        |row| row.get::<_, i64>(0),
    )?;
    let live_effects = transaction.query_row(
        "SELECT COUNT(*) FROM operations WHERE task_id = ?1 AND (state IN ('PREPARED', 'STARTED', 'UNKNOWN') OR outcome_certainty IN ('FAILED_PARTIAL_EFFECT', 'OUTCOME_UNKNOWN'))",
        [task_id],
        |row| row.get::<_, i64>(0),
    )?;
    let live_invocations = unresolved_provider_invocation_ids(transaction, task_id)?.len();
    let live_credential_uses = unresolved_credential_use_ids(transaction, task_id)?.len();
    Ok(live_attempts == 0
        && live_grants == 0
        && live_effects == 0
        && live_invocations == 0
        && live_credential_uses == 0)
}

fn active_execution_is_contained(transaction: &Transaction<'_>, task_id: &str) -> Result<bool> {
    let active_attempts = transaction.query_row(
        "SELECT COUNT(*) FROM step_executions WHERE task_id = ?1 AND state IN ('STARTING', 'RUNNING', 'UNKNOWN')",
        [task_id],
        |row| row.get::<_, i64>(0),
    )?;
    let active_grants = transaction.query_row(
        "SELECT COUNT(*) FROM authority_grants WHERE task_id = ?1 AND state = 'ACTIVE'",
        [task_id],
        |row| row.get::<_, i64>(0),
    )?;
    let active_operations = transaction.query_row(
        "SELECT COUNT(*) FROM operations WHERE task_id = ?1 AND state IN ('PREPARED', 'STARTED', 'UNKNOWN')",
        [task_id],
        |row| row.get::<_, i64>(0),
    )?;
    let active_invocations = transaction.query_row(
        "SELECT COUNT(*) FROM provider_invocations WHERE task_id = ?1 AND status IN ('PENDING', 'STARTING', 'RUNNING', 'OUTCOME_UNKNOWN', 'TIMED_OUT', 'AUTHORITY_REVOKED')",
        [task_id],
        |row| row.get::<_, i64>(0),
    )?;
    let active_credentials = transaction.query_row(
        "SELECT COUNT(*) FROM credential_use_records WHERE task_id = ?1 AND completed_at IS NULL",
        [task_id],
        |row| row.get::<_, i64>(0),
    )?;
    Ok(active_attempts == 0
        && active_grants == 0
        && active_operations == 0
        && active_invocations == 0
        && active_credentials == 0)
}

struct RecoveryResolution {
    certainty: String,
    safe_action: &'static str,
    reason_code: &'static str,
    event_status: &'static str,
}

fn recovery_resolution(certainty: String) -> Option<RecoveryResolution> {
    if matches!(
        certainty.as_str(),
        "OUTCOME_UNKNOWN" | "FAILED_PARTIAL_EFFECT"
    ) {
        return None;
    }
    let (safe_action, reason_code) = recovery_disposition(&certainty);
    let event_status = match certainty.as_str() {
        "COMPLETED" => "success",
        "NOT_STARTED" => "cancelled",
        _ => "failure",
    };
    Some(RecoveryResolution {
        certainty,
        safe_action,
        reason_code,
        event_status,
    })
}

fn credential_use_resolution(
    task_id: &str,
    request_id: &str,
    result_id: &str,
    credential_id: &str,
    row_status: &str,
    completed_at: &str,
    result_json: &str,
) -> Result<Option<RecoveryResolution>> {
    let result: Value = serde_json::from_str(result_json)?;
    if !credential_use_result_validator()?.is_valid(&result)
        || canonical_json(&result)? != result_json
        || result.get("result_id").and_then(Value::as_str) != Some(result_id)
        || result.get("request_id").and_then(Value::as_str) != Some(request_id)
        || result.get("task_id").and_then(Value::as_str) != Some(task_id)
        || result.get("credential_handle_id").and_then(Value::as_str) != Some(credential_id)
        || !credential_id.starts_with("credential://")
        || result.get("status").and_then(Value::as_str) != Some(row_status)
        || result.get("completed_at").and_then(Value::as_str) != Some(completed_at)
        || OffsetDateTime::parse(completed_at, &Rfc3339).is_err()
    {
        return Ok(None);
    }
    Ok(match row_status {
        "ALLOWED_AND_USED" => recovery_resolution("COMPLETED".to_owned()),
        "AUTHORITY_DENIED"
        | "HANDLE_NOT_FOUND"
        | "HANDLE_INACTIVE"
        | "EXPIRED"
        | "SCOPE_MISMATCH"
        | "SERVICE_MISMATCH"
        | "EXPORT_NOT_ALLOWED"
        | "PROVIDER_BINDING_MISMATCH"
        | "DELEGATION_FAILED"
        | "SECURE_STORE_UNAVAILABLE"
        | "EXTERNAL_AUTH_FAILED"
        | "RATE_OR_USE_LIMIT"
        | "CANCELLED" => Some(RecoveryResolution {
            certainty: "FAILED_NO_EFFECT".to_owned(),
            safe_action: "NO_ACTION",
            reason_code: "RECOVERY_FAILED_NO_EFFECT",
            event_status: "denied",
        }),
        _ => None,
    })
}

fn credential_use_result_validator() -> Result<&'static jsonschema::Validator> {
    static VALIDATOR: OnceLock<std::result::Result<jsonschema::Validator, String>> =
        OnceLock::new();
    match VALIDATOR.get_or_init(|| {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../specs/credential-use-result.schema.json"
        ))
        .map_err(|error| error.to_string())?;
        jsonschema::options()
            .should_validate_formats(true)
            .build(&schema)
            .map_err(|error| error.to_string())
    }) {
        Ok(validator) => Ok(validator),
        Err(_) => Err(TaskManagerError::InvalidRecord(
            "credential-use result schema cannot be compiled",
        )),
    }
}

fn provider_invocation_result_validator() -> Result<&'static jsonschema::Validator> {
    static VALIDATOR: OnceLock<std::result::Result<jsonschema::Validator, String>> =
        OnceLock::new();
    match VALIDATOR.get_or_init(|| {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../specs/provider-invocation-result.schema.json"
        ))
        .map_err(|error| error.to_string())?;
        jsonschema::options()
            .should_validate_formats(true)
            .build(&schema)
            .map_err(|error| error.to_string())
    }) {
        Ok(validator) => Ok(validator),
        Err(_) => Err(TaskManagerError::InvalidRecord(
            "provider-invocation result schema cannot be compiled",
        )),
    }
}

fn provider_invocation_resolution(
    connection: &Connection,
    task_id: &str,
    invocation_id: &str,
) -> Result<Option<RecoveryResolution>> {
    let records = stored_provider_invocations(connection, task_id)?;
    let Some(record) = records
        .iter()
        .find(|record| record.invocation_id == invocation_id)
    else {
        return Ok(None);
    };
    authenticated_provider_invocation_resolution(task_id, record)
}

fn authenticated_provider_invocation_resolution(
    task_id: &str,
    record: &StoredProviderInvocation,
) -> Result<Option<RecoveryResolution>> {
    let (
        Some(result_json),
        Some(started_at),
        Some(completed_at),
        Some(binding_attempt_id),
        Some(binding_task_id),
        Some(node_id),
        Some(binding_provider_id),
        Some(binding_provider_version),
    ) = (
        record.result_json.as_deref(),
        record.started_at.as_deref(),
        record.completed_at.as_deref(),
        record.binding_attempt_id.as_deref(),
        record.binding_task_id.as_deref(),
        record.node_id.as_deref(),
        record.binding_provider_id.as_deref(),
        record.binding_provider_version.as_deref(),
    )
    else {
        return Ok(None);
    };
    let Ok(result) = serde_json::from_str::<Value>(result_json) else {
        return Ok(None);
    };
    let expected_build_hash = record
        .binding_provider_build_hash
        .as_ref()
        .map_or(Value::Null, |hash| Value::String(hash.clone()));
    if !provider_invocation_result_validator()?.is_valid(&result)
        || canonical_json(&result)? != result_json
        || binding_attempt_id != record.attempt_id
        || binding_task_id != task_id
        || binding_provider_id != record.provider_id
        || binding_provider_version != record.provider_version
        || result.get("invocation_id").and_then(Value::as_str)
            != Some(record.invocation_id.as_str())
        || result.get("task_id").and_then(Value::as_str) != Some(task_id)
        || result.get("execution_binding_id").and_then(Value::as_str)
            != Some(record.binding_id.as_str())
        || result.get("node_id").and_then(Value::as_str) != Some(node_id)
        || result.pointer("/provider/id").and_then(Value::as_str)
            != Some(record.provider_id.as_str())
        || result.pointer("/provider/version").and_then(Value::as_str)
            != Some(record.provider_version.as_str())
        || result.pointer("/provider/package_or_build_hash") != Some(&expected_build_hash)
        || result.get("status").and_then(Value::as_str) != Some(record.status.as_str())
        || result.get("started_at").and_then(Value::as_str) != Some(started_at)
        || result.get("completed_at").and_then(Value::as_str) != Some(completed_at)
    {
        return Ok(None);
    }
    Ok(match record.status.as_str() {
        "SUCCEEDED" => recovery_resolution("COMPLETED".to_owned()),
        "START_FAILED" => recovery_resolution("NOT_STARTED".to_owned()),
        // Every other status, including a declared semantic failure, lacks
        // explicit v0.1 effect certainty and therefore remains unresolved.
        _ => None,
    })
}

fn resolved_publication_recovery_subject(
    transaction: &Transaction<'_>,
    task_id: &str,
    publication_id: &str,
) -> Result<Option<RecoveryResolution>> {
    let publication = transaction
        .query_row(
            "SELECT state,allocation_id,artifact_id FROM artifact_publications WHERE task_id=?1 AND publication_id=?2",
            params![task_id, publication_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )
        .optional()?;
    Ok(match publication {
        Some((state, _, _))
            if state == "ABORTED"
                && artifact_store::aborted_publication_receipt_authenticates(
                    transaction,
                    task_id,
                    publication_id,
                )? =>
        {
            Some(RecoveryResolution {
                certainty: "FAILED_NO_EFFECT".to_owned(),
                safe_action: "CLEAN_STAGING",
                reason_code: "RECOVERY_FAILED_NO_EFFECT",
                event_status: "cancelled",
            })
        }
        Some((state, _, _))
            if state == "FAILED"
                && artifact_store::failed_expired_publication_receipt_authenticates(
                    transaction,
                    task_id,
                    publication_id,
                )? =>
        {
            Some(RecoveryResolution {
                certainty: "FAILED_NO_EFFECT".to_owned(),
                safe_action: "CLEAN_STAGING",
                reason_code: "RECOVERY_FAILED_NO_EFFECT",
                event_status: "failure",
            })
        }
        Some((state, allocation_id, Some(artifact_id))) if state == "COMMITTED" => {
            let active_steps = transaction
                .query_row(
                    "SELECT active_step_ids_json FROM tasks WHERE task_id=?1",
                    [task_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .and_then(|steps| serde_json::from_str::<Vec<String>>(&steps).ok());
            let Some(active_steps) = active_steps else {
                return Ok(None);
            };
            active_step_completion_facts(transaction, task_id, &active_steps)?
                .filter(|facts| {
                    facts.publication_tuples.contains(&(
                        publication_id.to_owned(),
                        allocation_id,
                        artifact_id,
                    ))
                })
                .and_then(|_| recovery_resolution("COMPLETED".to_owned()))
        }
        _ => None,
    })
}

fn resolved_recovery_subject(
    transaction: &Transaction<'_>,
    task_id: &str,
    inventory_id: &str,
) -> Result<Option<RecoveryResolution>> {
    if let Some(attempt_id) = inventory_id.strip_prefix("attempt:") {
        let step = transaction
            .query_row(
                "SELECT invocation_id,binding_id,node_id,outcome_certainty
                 FROM step_executions WHERE task_id=?1 AND attempt_id=?2",
                params![task_id, attempt_id],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((Some(invocation_id), Some(binding_id), node_id, stored_certainty)) = step else {
            return Ok(None);
        };
        let records = stored_provider_invocations(transaction, task_id)?;
        let Some(record) = records.iter().find(|record| {
            record.invocation_id == invocation_id
                && record.attempt_id == attempt_id
                && record.binding_id == binding_id
                && record.node_id.as_deref() == Some(node_id.as_str())
        }) else {
            return Ok(None);
        };
        let Some(resolution) = authenticated_provider_invocation_resolution(task_id, record)?
        else {
            return Ok(None);
        };
        return Ok(match stored_certainty.as_deref() {
            None | Some("OUTCOME_UNKNOWN") => Some(resolution),
            Some(certainty) if certainty == resolution.certainty => Some(resolution),
            _ => None,
        });
    }
    if let Some(publication_id) = inventory_id.strip_prefix("publication:") {
        return resolved_publication_recovery_subject(transaction, task_id, publication_id);
    }
    if let Some(grant_id) = inventory_id.strip_prefix("grant:") {
        let state = transaction
            .query_row(
                "SELECT state FROM authority_grants WHERE task_id=?1 AND grant_id=?2",
                params![task_id, grant_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        return Ok(match state.as_deref() {
            Some("CONSUMED") => recovery_resolution("COMPLETED".to_owned()),
            Some("REVOKED" | "EXPIRED") => Some(RecoveryResolution {
                certainty: "FAILED_NO_EFFECT".to_owned(),
                safe_action: "NO_ACTION",
                reason_code: "RECOVERY_FAILED_NO_EFFECT",
                event_status: "denied",
            }),
            _ => None,
        });
    }
    if let Some(request_id) = inventory_id.strip_prefix("credential-use:") {
        let record = transaction
            .query_row(
                "SELECT request_id, result_id, credential_id, status, completed_at, result_json, requested_at FROM credential_use_records WHERE task_id=?1 AND request_id=?2",
                params![task_id, request_id],
                |row| Ok(StoredCredentialUse {
                    request_id: row.get(0)?, result_id: row.get(1)?, credential_id: row.get(2)?,
                    status: row.get(3)?, completed_at: row.get(4)?, result_json: row.get(5)?,
                    requested_at: row.get(6)?,
                }),
            )
            .optional()?;
        return Ok(record
            .as_ref()
            .and_then(|record| authenticated_credential_use_resolution(task_id, record)));
    }
    if let Some(invocation_id) = inventory_id.strip_prefix("provider-invocation:") {
        return provider_invocation_resolution(transaction, task_id, invocation_id);
    }
    let Some(operation_id) = inventory_id.strip_prefix("operation:") else {
        return Ok(None);
    };
    let operation = transaction
        .query_row(
            "SELECT state, outcome_certainty FROM operations WHERE task_id=?1 AND operation_id=?2",
            params![task_id, operation_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
        )
        .optional()?;
    Ok(operation.and_then(|(state, certainty)| {
        certainty
            .or_else(|| (state == "PREPARED").then(|| "NOT_STARTED".to_owned()))
            .and_then(recovery_resolution)
    }))
}

fn authenticated_recovery_resolution(
    transaction: &Transaction<'_>,
    task_id: &str,
    recovery_ref: &str,
    inventory_id: &str,
    assessment: &Value,
) -> Result<bool> {
    let Some(event_id) = assessment
        .pointer("/evidence/0/ref")
        .and_then(Value::as_str)
    else {
        return Ok(false);
    };
    let event_json = transaction
        .query_row(
            "SELECT event_json FROM provenance_events WHERE task_id=?1 AND event_id=?2 AND event_type='execution.completed'",
            params![task_id, event_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let Some(event_json) = event_json else {
        return Ok(false);
    };
    let event = aios_provenance::parse_unique_json(&event_json)?;
    Ok(event
        .pointer("/details/recovery_ref")
        .and_then(Value::as_str)
        == Some(recovery_ref)
        && event
            .pointer("/details/inventory_id")
            .and_then(Value::as_str)
            == Some(inventory_id)
        && event.pointer("/details/certainty").and_then(Value::as_str)
            == assessment.get("certainty").and_then(Value::as_str)
        && event
            .pointer("/details/safe_action")
            .and_then(Value::as_str)
            == assessment.get("safe_action").and_then(Value::as_str)
        && event
            .pointer("/details/reason_code")
            .and_then(Value::as_str)
            == assessment
                .pointer("/reason_codes/0")
                .and_then(Value::as_str)
        && assessment
            .pointer("/evidence/0/kind")
            .and_then(Value::as_str)
            == Some("provenance")
        && verify_provenance_through(transaction, task_id, None)?)
}

#[allow(
    clippy::too_many_lines,
    reason = "keeps aggregate, inventory, and per-subject recovery authentication contiguous for audit"
)]
fn recovery_allows_exit(transaction: &Transaction<'_>, task_id: &str) -> Result<bool> {
    let Some(active_inventory) = active_recovery_inventory(transaction, task_id)? else {
        return Ok(false);
    };
    let recovery_ref = active_inventory.recovery_ref;
    let aggregate = transaction
        .query_row(
            "SELECT recovery_epoch_id, basis_revision, certainty, safe_action, assessment_json
         FROM recovery_assessments
         WHERE assessment_id = ?1 AND task_id = ?2 AND subject_kind = 'task' AND subject_id = ?2",
            params![&recovery_ref, task_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((epoch_id, basis_revision, certainty, safe_action, assessment_json)) = aggregate
    else {
        return Ok(false);
    };
    let basis_revision = u64::try_from(basis_revision)
        .map_err(|_| TaskManagerError::InvalidRecord("recovery basis revision is invalid"))?;
    let inventory = query_strings(
        transaction,
        "SELECT operation_id FROM recovery_unknown_operations WHERE assessment_id = ?1 ORDER BY ordinal",
        &recovery_ref,
    )?;
    if recovery_operations_ref(task_id, basis_revision, &inventory)? != recovery_ref {
        return Ok(false);
    }
    let current_unresolved = unresolved_execution_ids(transaction, task_id)?;
    let inventory_set = inventory
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    if current_unresolved
        .iter()
        .any(|subject| !inventory_set.contains(subject))
    {
        return Ok(false);
    }
    let aggregate_json: Value = serde_json::from_str(&assessment_json)?;
    if aggregate_json.get("assessment_id").and_then(Value::as_str) != Some(recovery_ref.as_str())
        || aggregate_json
            .pointer("/subject/kind")
            .and_then(Value::as_str)
            != Some("task")
        || aggregate_json
            .pointer("/subject/id")
            .and_then(Value::as_str)
            != Some(task_id)
        || aggregate_json.get("certainty").and_then(Value::as_str) != Some(certainty.as_str())
        || aggregate_json.get("safe_action").and_then(Value::as_str) != Some(safe_action.as_str())
        || aggregate_json
            .get("external_reconciliation_required")
            .and_then(Value::as_bool)
            .is_none()
    {
        return Ok(false);
    }
    let subject_rows = {
        let mut statement = transaction.prepare(
            "SELECT assessment_id, subject_kind, subject_id, certainty, safe_action, assessment_json FROM recovery_assessments
             WHERE task_id = ?1 AND recovery_epoch_id = ?2 AND subject_kind <> 'task'
             ORDER BY assessment_id",
        )?;
        let rows = statement.query_map(params![task_id, epoch_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()?
    };
    let mut covered_inventory = std::collections::BTreeSet::new();
    let mut authenticated_resolved_inventory = std::collections::BTreeSet::new();
    for (
        assessment_id,
        subject_kind,
        subject_id,
        subject_certainty,
        subject_action,
        subject_json,
    ) in subject_rows
    {
        if recovery_subject_assessment_id(&recovery_ref, &subject_kind, &subject_id)
            != assessment_id
        {
            continue;
        }
        let subject: Value = serde_json::from_str(&subject_json)?;
        let Some(inventory_id) = recovery_subject_inventory_id(&subject_kind, &subject_id) else {
            return Ok(false);
        };
        if !covered_inventory.insert(inventory_id.clone())
            || subject.get("assessment_id").and_then(Value::as_str) != Some(assessment_id.as_str())
            || subject.pointer("/subject/kind").and_then(Value::as_str)
                != Some(subject_kind.as_str())
            || subject.pointer("/subject/id").and_then(Value::as_str) != Some(subject_id.as_str())
            || subject.get("certainty").and_then(Value::as_str) != Some(subject_certainty.as_str())
            || subject.get("safe_action").and_then(Value::as_str) != Some(subject_action.as_str())
            || subject
                .get("external_reconciliation_required")
                .and_then(Value::as_bool)
                != Some(subject_action == "REQUIRE_EXTERNAL_RECONCILIATION")
        {
            return Ok(false);
        }
        if !matches!(
            subject_certainty.as_str(),
            "OUTCOME_UNKNOWN" | "FAILED_PARTIAL_EFFECT"
        ) && subject_action != "REQUIRE_EXTERNAL_RECONCILIATION"
            && authenticated_recovery_resolution(
                transaction,
                task_id,
                &recovery_ref,
                &inventory_id,
                &subject,
            )?
        {
            authenticated_resolved_inventory.insert(inventory_id.clone());
        }
    }
    if covered_inventory != inventory_set {
        return Ok(false);
    }
    let stored_aggregate_safe = !matches!(
        certainty.as_str(),
        "OUTCOME_UNKNOWN" | "FAILED_PARTIAL_EFFECT"
    ) && safe_action != "REQUIRE_EXTERNAL_RECONCILIATION"
        && !aggregate_json
            .get("external_reconciliation_required")
            .and_then(Value::as_bool)
            .unwrap_or(true);
    if stored_aggregate_safe {
        return Ok(
            current_unresolved.is_empty() && authenticated_resolved_inventory == inventory_set
        );
    }
    if inventory.is_empty()
        || current_unresolved
            .iter()
            .any(|subject| !authenticated_resolved_inventory.contains(subject))
    {
        return Ok(false);
    }
    Ok(authenticated_resolved_inventory == inventory_set)
}

fn plan_program_coherent(
    transaction: &Transaction<'_>,
    task_id: &str,
    active_program: Option<i64>,
    proposed_plan: Option<&ActivePlan>,
) -> Result<bool> {
    let Some(program_revision) = active_program else {
        return Ok(false);
    };
    if let Some(plan) = proposed_plan {
        let plan_revision = i64::try_from(plan.revision).map_err(|_| {
            TaskManagerError::InvalidRecord("active plan revision exceeds SQLite range")
        })?;
        return transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM semantic_program_revisions p JOIN plan_revisions r ON r.task_id = p.task_id AND r.plan_revision = p.created_from_plan_revision WHERE p.task_id = ?1 AND p.program_revision = ?2 AND r.plan_revision = ?3 AND r.plan_id = ?4 AND p.superseded_at IS NULL AND r.superseded_at IS NULL)",
                params![task_id, program_revision, plan_revision, plan.plan_id],
                |row| row.get::<_, bool>(0),
            )
            .map_err(Into::into);
    }
    transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM tasks t JOIN semantic_program_revisions p ON p.task_id = t.task_id AND p.program_revision = t.active_program_revision JOIN plan_revisions r ON r.task_id = t.task_id AND r.plan_revision = t.active_plan_revision AND p.created_from_plan_revision = r.plan_revision WHERE t.task_id = ?1 AND p.program_revision = ?2 AND p.superseded_at IS NULL AND r.superseded_at IS NULL)",
            params![task_id, program_revision],
            |row| row.get::<_, bool>(0),
        )
        .map_err(Into::into)
}

#[allow(
    clippy::too_many_lines,
    reason = "keeps the deterministic target-state guard matrix in one auditable function"
)]
fn guard_failure(
    transaction: &Transaction<'_>,
    request: &TransitionRequest,
    stored_waiting: &str,
    stored_steps: &str,
    active_program: Option<i64>,
    checked_at: &str,
    internal_recovery: bool,
) -> Result<Option<&'static str>> {
    let waiting: Vec<WaitingOn> = request
        .mutation
        .waiting_on
        .clone()
        .map_or_else(|| serde_json::from_str(stored_waiting), Ok)?;
    let durable_waiting: Vec<WaitingOn> = serde_json::from_str(stored_waiting)?;
    // Admission guards evaluate the materialized execution plan. A caller may
    // propose a replacement list, but it cannot use that uncommitted proposal
    // as evidence that runnable/running/completion prerequisites already hold.
    let active_steps: Vec<String> = serde_json::from_str(stored_steps)?;
    let approval_scope_steps = if request.to_state == TaskState::WaitingForAuth {
        request
            .mutation
            .active_step_ids
            .as_ref()
            .unwrap_or(&active_steps)
    } else {
        &active_steps
    };
    let active_program_hash = active_program
        .map(|program_revision| {
            transaction
                .query_row(
                    "SELECT semantic_hash FROM semantic_program_revisions WHERE task_id=?1 AND program_revision=?2 AND status='active'",
                    params![request.task_id, program_revision],
                    |row| row.get::<_, String>(0),
                )
                .optional()
        })
        .transpose()?
        .flatten();
    let valid_program = if let Some(active_program_hash) = active_program_hash {
        active_program_validation_valid(transaction, &request.task_id, &active_program_hash)?
    } else {
        false
    };
    let ready_steps = count_active_steps(transaction, &request.task_id, &active_steps, "READY")?;
    let bound_ready_steps = count_bound_active_steps(
        transaction,
        &request.task_id,
        &active_steps,
        &["READY"],
        checked_at,
    )?;
    let checked_instant = OffsetDateTime::parse(checked_at, &Rfc3339)
        .map_err(|_| TaskManagerError::InvalidRecord("trusted guard time is not RFC 3339"))?;
    let scoped_pending_approvals = {
        let mut statement = transaction.prepare(
            "SELECT a.approval_id, a.node_id, a.expires_at FROM approval_requests a JOIN authority_requests r ON r.request_id = a.authority_request_id AND r.task_id = a.task_id AND r.semantic_program_hash = a.semantic_program_hash AND r.node_id = a.node_id JOIN tasks t ON t.task_id = a.task_id JOIN semantic_program_revisions p ON p.task_id = t.task_id AND p.program_revision = t.active_program_revision AND p.semantic_hash = a.semantic_program_hash AND p.registry_snapshot_id = r.registry_snapshot_id WHERE a.task_id = ?1 AND a.status = 'PENDING'",
        )?;
        let rows = statement.query_map([&request.task_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|(_, node_id, expires_at)| {
                approval_scope_steps.contains(node_id)
                    && expires_at.as_ref().is_none_or(|expires_at| {
                        OffsetDateTime::parse(expires_at, &Rfc3339)
                            .is_ok_and(|expires_at| expires_at > checked_instant)
                    })
            })
            .map(|(approval_id, _, _)| approval_id)
            .collect::<std::collections::BTreeSet<_>>()
    };
    let pending_approvals = scoped_pending_approvals.len();
    let unknown_operations = unresolved_execution_count(transaction, &request.task_id)?;
    let durable_nonapproval_blocker = durable_waiting
        .iter()
        .any(|item| item.kind != WaitingKind::Approval);
    let effective_waiting = waiting.iter().any(|item| {
        item.kind != WaitingKind::Approval || scoped_pending_approvals.contains(&item.id)
    });
    let durable_effective_waiting = durable_waiting.iter().any(|item| {
        item.kind != WaitingKind::Approval || scoped_pending_approvals.contains(&item.id)
    });
    let mut matching_pending_approval = false;
    for blocker in waiting
        .iter()
        .filter(|item| item.kind == WaitingKind::Approval)
    {
        matching_pending_approval |= scoped_pending_approvals.contains(&blocker.id);
    }
    if request.mutation.active_step_ids.is_some()
        && matches!(
            request.to_state,
            TaskState::Runnable | TaskState::Running | TaskState::Verifying | TaskState::Completed
        )
    {
        return Ok(Some("TASK_TRANSITION_GUARD_FAILED"));
    }
    if request.to_state == TaskState::Recovering && !internal_recovery {
        return Ok(Some("TASK_TRANSITION_GUARD_FAILED"));
    }
    if request.expected_state == TaskState::Recovering
        && matches!(
            request.to_state,
            TaskState::Planning
                | TaskState::Runnable
                | TaskState::Running
                | TaskState::WaitingForInput
                | TaskState::WaitingForAuth
                | TaskState::Verifying
                | TaskState::Paused
                | TaskState::Completed
        )
        && !recovery_allows_exit(transaction, &request.task_id)?
    {
        return Ok(Some("TASK_TRANSITION_GUARD_FAILED"));
    }
    let execution_target = matches!(
        request.to_state,
        TaskState::Runnable | TaskState::Running | TaskState::Verifying | TaskState::Completed
    );
    if matches!(
        request.to_state,
        TaskState::Runnable | TaskState::Running | TaskState::Verifying
    ) && unknown_operations > 0
    {
        return Ok(Some("TASK_UNKNOWN_EXTERNAL_OUTCOME"));
    }
    let changed_plan_for_active_program =
        request.mutation.active_plan.is_some() && active_program.is_some();
    if (changed_plan_for_active_program || execution_target)
        && !plan_program_coherent(
            transaction,
            &request.task_id,
            active_program,
            request.mutation.active_plan.as_ref(),
        )?
    {
        return Ok(Some("TASK_PROGRAM_NOT_RUNNABLE"));
    }
    let code = match request.to_state {
        TaskState::Runnable
            if request.expected_state == TaskState::Running
                && !execution_is_contained(transaction, &request.task_id)? =>
        {
            Some("TASK_TRANSITION_GUARD_FAILED")
        }
        TaskState::WaitingForInput
            if !waiting
                .iter()
                .any(|item| matches!(item.kind, WaitingKind::Input | WaitingKind::Validation)) =>
        {
            Some("TASK_TRANSITION_GUARD_FAILED")
        }
        TaskState::WaitingForAuth if pending_approvals == 0 || !matching_pending_approval => {
            Some("TASK_TRANSITION_GUARD_FAILED")
        }
        TaskState::Runnable
            if !valid_program
                || active_steps.is_empty()
                || ready_steps == 0
                || effective_waiting
                || pending_approvals > 0
                || durable_nonapproval_blocker =>
        {
            Some("TASK_PROGRAM_NOT_RUNNABLE")
        }
        TaskState::Running
            if !valid_program
                || effective_waiting
                || pending_approvals > 0
                || durable_nonapproval_blocker
                || active_steps.is_empty()
                || bound_ready_steps == 0 =>
        {
            Some("TASK_TRANSITION_GUARD_FAILED")
        }
        TaskState::Verifying => {
            active_step_completion_facts(transaction, &request.task_id, &active_steps)?
                .is_none()
                .then_some("TASK_TRANSITION_GUARD_FAILED")
        }
        TaskState::Completed => {
            let published_outputs =
                active_step_completion_facts(transaction, &request.task_id, &active_steps)?;
            let verified = match &published_outputs {
                Some(outputs) => {
                    has_current_verification(transaction, &request.task_id, &outputs.artifact_ids)?
                }
                None => false,
            };
            if unknown_operations > 0 {
                Some("TASK_UNKNOWN_EXTERNAL_OUTCOME")
            } else if !valid_program
                || published_outputs.is_none()
                || !verified
                || pending_approvals > 0
                || effective_waiting
                || durable_effective_waiting
            {
                Some("TASK_COMPLETION_GATE_FAILED")
            } else {
                None
            }
        }
        // Compensation authority and completion evidence are owned by later
        // Stage-1 services. Until those durable facts exist, rollback state
        // changes fail closed rather than trusting request-supplied flags.
        TaskState::RollingBack | TaskState::RolledBack => Some("TASK_TRANSITION_GUARD_FAILED"),
        TaskState::Failed if request.mutation.failure.is_none() => {
            Some("TASK_TRANSITION_GUARD_FAILED")
        }
        TaskState::Failed
            if unknown_operations > 0
                && !request
                    .mutation
                    .failure
                    .as_ref()
                    .is_some_and(|failure| failure.unknown_side_effects) =>
        {
            Some("TASK_UNKNOWN_EXTERNAL_OUTCOME")
        }
        TaskState::Failed
            if !(if request
                .mutation
                .failure
                .as_ref()
                .is_some_and(|failure| failure.unknown_side_effects)
            {
                active_execution_is_contained(transaction, &request.task_id)?
            } else {
                execution_is_contained(transaction, &request.task_id)?
            }) =>
        {
            Some("TASK_TRANSITION_GUARD_FAILED")
        }
        TaskState::Planning
        | TaskState::WaitingForInput
        | TaskState::WaitingForAuth
        | TaskState::Paused
        | TaskState::Cancelled
            if !execution_is_contained(transaction, &request.task_id)? =>
        {
            Some("TASK_TRANSITION_GUARD_FAILED")
        }
        _ => None,
    };
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const T0: &str = "2026-09-19T00:00:00Z";

    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> String {
            T0.to_owned()
        }
        fn security_sample(&self) -> Option<crate::SecurityClockSample> {
            Some(crate::trusted_time::synthetic_sample(self.now()))
        }
    }

    fn test_manager() -> TaskManager {
        TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap()
    }

    fn create(id: &str) -> CreateTask {
        CreateTask {
            task_id: id.to_owned(),
            principal: Actor {
                kind: "user".to_owned(),
                id: "user:fixture".to_owned(),
            },
            workspace_id: None,
            original_intent: "Persist this task.".to_owned(),
            normalized_intent: None,
            active_step_ids: Vec::new(),
        }
    }

    fn remove_fixture_fence_schema(connection: &Connection) {
        for name in SEMANTIC_FENCE_GUARDS {
            connection
                .execute_batch(&format!("DROP TRIGGER IF EXISTS {name}"))
                .unwrap();
        }
        connection
            .execute_batch(
                "DROP VIEW semantic_current_usable_snapshots;
             DROP TABLE semantic_snapshot_reattestations;
             DROP TABLE semantic_invalidated_activation_scopes;
             DROP TABLE semantic_activation_scope_history;
             DROP TABLE semantic_legacy_activation_quarantine;
             DROP TABLE semantic_legacy_unprovable_admissions;
             DROP TABLE semantic_terminal_admissions;
             DROP TABLE semantic_repair_fences;
             DELETE FROM schema_migrations WHERE migration_id='0014_semantic_repair_fence';",
            )
            .unwrap();
    }

    #[test]
    fn provenance_event_id_key_shape_rejects_unique_and_composite_substitutes() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch("CREATE TABLE provenance_events(event_id TEXT UNIQUE, task_id TEXT)")
            .unwrap();
        assert!(!provenance_event_id_is_primary_key(&connection).unwrap());
        connection
            .execute_batch(
                "DROP TABLE provenance_events;
                 CREATE TABLE provenance_events(
                     event_id TEXT, task_id TEXT, PRIMARY KEY(event_id, task_id)
                 );",
            )
            .unwrap();
        assert!(!provenance_event_id_is_primary_key(&connection).unwrap());
        connection
            .execute_batch(
                "DROP TABLE provenance_events;
                 CREATE TABLE provenance_events(event_id TEXT PRIMARY KEY, task_id TEXT) WITHOUT ROWID;",
            )
            .unwrap();
        assert!(provenance_event_id_is_primary_key(&connection).unwrap());
    }

    #[test]
    fn provenance_foreign_key_shape_rejects_misbound_and_cascading_evidence_keys() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE tasks(task_id TEXT PRIMARY KEY);
                 CREATE TABLE registry_snapshots(snapshot_id TEXT PRIMARY KEY);
                 CREATE TABLE execution_bindings(binding_id TEXT PRIMARY KEY);",
            )
            .unwrap();
        for (registry_target, binding_delete, expected) in [
            ("snapshot_id", "", true),
            ("wrong_snapshot_id", "", false),
            ("snapshot_id", "ON DELETE CASCADE", false),
        ] {
            connection
                .execute_batch(&format!(
                    "CREATE TABLE provenance_events(
                         task_id TEXT,
                         registry_snapshot_id TEXT,
                         execution_binding_id TEXT,
                         FOREIGN KEY(task_id) REFERENCES tasks(task_id),
                         FOREIGN KEY(registry_snapshot_id) REFERENCES registry_snapshots({registry_target}),
                         FOREIGN KEY(execution_binding_id) REFERENCES execution_bindings(binding_id) {binding_delete}
                     );"
                ))
                .unwrap();
            assert_eq!(
                provenance_foreign_keys_are_current(&connection).unwrap(),
                expected,
                "registry target {registry_target}, binding delete {binding_delete}"
            );
            connection
                .execute_batch("DROP TABLE provenance_events")
                .unwrap();
        }
    }

    #[test]
    fn stamped_provenance_rejects_null_event_id_despite_sqlite_primary_key() {
        let mut manager = test_manager();
        manager
            .create_task(&create("T-null-event-identity"))
            .unwrap();
        manager
            .connection
            .execute_batch(
                "DROP TRIGGER provenance_events_no_update;
                 UPDATE provenance_events SET event_id=NULL;
                 CREATE TRIGGER provenance_events_no_update
                 BEFORE UPDATE ON provenance_events
                 BEGIN SELECT RAISE(ABORT, 'provenance_events are append-only'); END;",
            )
            .unwrap();
        assert!(provenance_event_id_is_primary_key(&manager.connection).unwrap());
        assert!(matches!(
            preflight_migration_state(&manager.connection),
            Err(TaskManagerError::InvalidRecord(
                "provenance event has no identity"
            ))
        ));
    }

    #[test]
    fn stamped_semantic_registry_requires_terminal_state_guard() {
        let manager = test_manager();
        manager
            .connection
            .execute_batch(include_str!(
                "../../../specs/persistence-v0.1-0012-semantic-registry.sql"
            ))
            .unwrap();
        manager.connection.execute(
            "INSERT INTO schema_migrations(migration_id,checksum,applied_at) VALUES ('0012_semantic_registry_store','semantic-registry-store-v0.1','2026-09-19T00:00:00Z')",
            [],
        ).unwrap();
        assert!(preflight_migration_state(&manager.connection).is_ok());
        for trigger in SEMANTIC_ADDITIVE_GUARDS {
            manager
                .connection
                .execute_batch(&format!("DROP TRIGGER {trigger}"))
                .unwrap();
            assert!(matches!(
                preflight_migration_state(&manager.connection),
                Err(TaskManagerError::InvalidRecord(
                    "semantic registry migration is incomplete"
                ))
            ));
            manager
                .connection
                .execute_batch(include_str!(
                    "../../../specs/persistence-v0.1-0012-semantic-registry.sql"
                ))
                .unwrap();
        }
    }

    #[test]
    fn public_registry_initializers_cannot_migrate_without_live_manager_fence() {
        let directory = tempdir().unwrap();
        let path = directory
            .path()
            .join("registry-public-migration-fence.sqlite3");
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        let mut independent = Connection::open(&path).unwrap();
        assert!(aios_registry::RegistryStore::initialize(&mut independent).is_err());
        assert!(aios_registry::ProviderStore::initialize(&mut independent).is_err());
        let migrations: i64 = independent.query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE migration_id IN ('0012_semantic_registry_store','0013_provider_registry')",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(migrations, 0);
        drop(independent);

        manager
            .connection
            .execute(
                "UPDATE task_manager_lease SET fence_epoch=fence_epoch+1 WHERE singleton_id=1",
                [],
            )
            .unwrap();
        assert!(manager.initialize_provider_store().is_err());
        let migrations: i64 = manager.connection.query_row(
            "SELECT COUNT(*) FROM schema_migrations WHERE migration_id IN ('0012_semantic_registry_store','0013_provider_registry')",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(migrations, 0);
    }

    #[test]
    fn fenced_registry_migration_rejects_unstamped_lookalike_tables() {
        let mut manager = test_manager();
        manager
            .connection
            .execute_batch("CREATE TABLE semantic_type_contracts (forged TEXT)")
            .unwrap();
        assert!(manager.initialize_registry_store().is_err());
        let stamped: bool = manager
            .connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE migration_id='0012_semantic_registry_store')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!stamped);
    }

    #[test]
    fn fenced_registry_migration_rejects_unstamped_triggers_on_baseline_tables() {
        for (trigger, provider) in [
            (
                "CREATE TRIGGER immutable_admitted_registry_snapshots_update BEFORE UPDATE ON registry_snapshots BEGIN SELECT 1; END",
                false,
            ),
            (
                "CREATE TRIGGER provider_registration_no_delete BEFORE DELETE ON provider_registrations BEGIN SELECT 1; END",
                true,
            ),
        ] {
            let mut manager = test_manager();
            manager.connection.execute_batch(trigger).unwrap();
            assert!(
                if provider {
                    manager.initialize_provider_store()
                } else {
                    manager.initialize_registry_store()
                }
                .is_err()
            );
            let stamps: i64 = manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM schema_migrations WHERE migration_id IN ('0012_semantic_registry_store','0013_provider_registry')",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(stamps, 0);
        }
    }

    #[test]
    fn file_backed_reopen_upgrades_old_stamped_registry_guard() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("old-stamped-registry.sqlite3");
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        manager.initialize_registry_store().unwrap();
        let stamp: (String, String) = manager
            .connection
            .query_row(
                "SELECT checksum,applied_at FROM schema_migrations WHERE migration_id='0012_semantic_registry_store'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        manager
            .connection
            .execute_batch(
                "DROP TRIGGER one_way_registry_snapshot_admissions_update;
                 DROP TRIGGER immutable_registry_snapshot_admissions_reinsert;
                 DROP TRIGGER immutable_admitted_registry_snapshots_reinsert;
                 DROP TRIGGER immutable_admitted_registry_snapshots_target_update;
                 DROP TRIGGER immutable_semantic_type_contracts_reinsert;
                 DROP TRIGGER immutable_semantic_capability_contracts_reinsert;
                 DROP TRIGGER immutable_registry_snapshot_entries_reinsert;
                 DROP TRIGGER immutable_admitted_registry_snapshot_entries_insert;",
            )
            .unwrap();
        drop(manager);

        let reopened = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        assert!(preflight_migration_state(&reopened.connection).is_ok());
        assert!(!missing_additive_guard(&reopened.connection, SEMANTIC_ADDITIVE_GUARDS).unwrap());
        let after: (String, String) = reopened
            .connection
            .query_row(
                "SELECT checksum,applied_at FROM schema_migrations WHERE migration_id='0012_semantic_registry_store'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(stamp, after);
    }

    #[test]
    fn stamped_provider_registry_requires_semantic_registry_stamp() {
        let manager = test_manager();
        manager
            .connection
            .execute_batch(include_str!(
                "../../../specs/persistence-v0.1-0013-provider-registry.sql"
            ))
            .unwrap();
        manager.connection.execute(
            "INSERT INTO schema_migrations(migration_id,checksum,applied_at) VALUES ('0013_provider_registry','provider-registry-v0.1','2026-09-19T00:00:00Z')",
            [],
        ).unwrap();
        assert!(matches!(
            preflight_migration_state(&manager.connection),
            Err(TaskManagerError::InvalidRecord(
                "provider registry requires semantic registry migration"
            ))
        ));
    }

    #[test]
    fn stamped_provider_registry_requires_duplicate_insert_guards() {
        let mut manager = test_manager();
        manager.initialize_provider_store().unwrap();
        for trigger in PROVIDER_ADDITIVE_GUARDS {
            manager
                .connection
                .execute_batch(&format!("DROP TRIGGER {trigger}"))
                .unwrap();
            assert!(matches!(
                preflight_migration_state(&manager.connection),
                Err(TaskManagerError::InvalidRecord(
                    "provider registry migration is incomplete"
                ))
            ));
            manager
                .connection
                .execute_batch(include_str!(
                    "../../../specs/persistence-v0.1-0013-provider-registry.sql"
                ))
                .unwrap();
        }
    }

    #[test]
    fn stamped_provider_registry_rejects_same_name_malformed_legacy_tables_on_reopen() {
        for name in ["provider_manifest_payloads", "provider_health_observations"] {
            let directory = tempdir().unwrap();
            let path = directory.path().join("malformed-provider.sqlite3");
            let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
            manager.initialize_provider_store().unwrap();
            let manifest_guards = if name == "provider_manifest_payloads" {
                [
                    "provider_manifest_payload_immutable_update",
                    "provider_manifest_payload_immutable_delete",
                    "provider_manifest_payload_no_duplicate_insert",
                ]
                .iter()
                .map(|trigger| {
                    manager
                        .connection
                        .query_row(
                            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                            [trigger],
                            |row| row.get::<_, String>(0),
                        )
                        .unwrap()
                })
                .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            manager
                .connection
                .execute_batch(&format!("DROP TABLE {name}; CREATE TABLE {name}(x TEXT);"))
                .unwrap();
            for guard in manifest_guards {
                manager
                    .connection
                    .execute_batch(&format!("{guard};"))
                    .unwrap();
            }
            if name == "provider_manifest_payloads" {
                let restored: i64 = manager
                    .connection
                    .query_row(
                        "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger'
                     AND name IN ('provider_manifest_payload_immutable_update',
                                  'provider_manifest_payload_immutable_delete',
                                  'provider_manifest_payload_no_duplicate_insert')",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(restored, 3);
            }
            drop(manager);

            assert!(
                TaskManager::open_with_clock(&path, Box::new(FixedClock)).is_err(),
                "{name}"
            );
            let connection = Connection::open(&path).unwrap();
            let columns: String = connection
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
                    [name],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(columns, format!("CREATE TABLE {name}(x TEXT)"));
        }
    }

    #[test]
    fn file_backed_reopen_upgrades_old_stamped_provider_guards() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("old-stamped-provider.sqlite3");
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        manager.initialize_provider_store().unwrap();
        let stamp: (String, String) = manager
            .connection
            .query_row(
                "SELECT checksum,applied_at FROM schema_migrations WHERE migration_id='0013_provider_registry'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        manager
            .connection
            .execute_batch(
                "DROP TRIGGER provider_manifest_payload_no_duplicate_insert;
                 DROP TRIGGER execution_binding_no_duplicate_insert;
                 DROP TRIGGER execution_binding_evidence_present_at_insert;
                 DROP TRIGGER execution_binding_admission_marker_insert;
                 DROP TABLE execution_binding_admission_markers;",
            )
            .unwrap();
        drop(manager);

        let reopened = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        assert!(preflight_migration_state(&reopened.connection).is_ok());
        assert!(!missing_additive_guard(&reopened.connection, PROVIDER_ADDITIVE_GUARDS).unwrap());
        assert!(provider_additive_tables_current(&reopened.connection, true, true).unwrap());
        let after: (String, String) = reopened
            .connection
            .query_row(
                "SELECT checksum,applied_at FROM schema_migrations WHERE migration_id='0013_provider_registry'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(stamp, after);
    }

    #[test]
    fn old_trust_insert_guard_upgrades_only_without_prior_decisions() {
        for poisoned in [false, true] {
            let directory = tempdir().unwrap();
            let path = directory.path().join("prior-trust-insert.sqlite3");
            let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
            manager.initialize_provider_store().unwrap();
            manager
                .connection
                .execute_batch("DROP TRIGGER provider_trust_admission_receipt_insert")
                .unwrap();
            manager
                .connection
                .execute_batch(include_str!(
                    "legacy_b0b7302_provider_trust_admission_guard.sql"
                ))
                .unwrap();
            assert!(legacy_b0b_trust_admission_guard_present(&manager.connection).unwrap());
            if poisoned {
                manager
                    .connection
                    .pragma_update(None, "foreign_keys", "OFF")
                    .unwrap();
                manager.connection.execute(
                    "INSERT INTO provider_trust_admissions
                     (admission_id,registration_id,decision_id,revision,trust_status,
                      authority_ref,admitted_at,receipt_json)
                     VALUES ('forged','missing-registration','review',1,
                             'locally-trusted','reviewer',?1,
                             '{\"registration_id\":\"missing-registration\",\"decision_id\":\"review\",\"revision\":1,\"trust_status\":\"locally-trusted\",\"authority_ref\":\"reviewer\",\"admitted_at\":\"2026-09-19T00:00:00Z\"}')",
                    ["2026-09-19T00:00:00Z"],
                ).unwrap();
            }
            drop(manager);
            if poisoned {
                assert!(matches!(
                    TaskManager::open_with_clock(&path, Box::new(FixedClock)),
                    Err(TaskManagerError::InvalidRecord(
                        "provider evidence or trust history requires operator quarantine"
                    ))
                ));
                let connection = Connection::open(&path).unwrap();
                assert!(legacy_b0b_trust_admission_guard_present(&connection).unwrap());
            } else {
                let reopened = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
                assert!(preflight_migration_state(&reopened.connection).is_ok());
                assert!(!legacy_b0b_trust_admission_guard_present(&reopened.connection).unwrap());
            }
        }
    }

    #[test]
    fn lost_evidence_or_trust_history_refuses_fenced_reopen() {
        for guard in [
            "provider_evidence_no_duplicate_insert",
            "provider_trust_admission_no_update",
            "provider_trust_admission_receipt_insert",
        ] {
            let directory = tempdir().unwrap();
            let path = directory.path().join("unprovable-provider-history.sqlite3");
            let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
            manager.initialize_provider_store().unwrap();
            let old_epoch: i64 = manager
                .connection
                .query_row(
                    "SELECT fence_epoch FROM task_manager_lease WHERE singleton_id=1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            if guard == "provider_evidence_no_duplicate_insert" {
                manager
                    .connection
                    .execute_batch(
                        "INSERT INTO provider_registrations
                         (registration_id,provider_id,provider_version,package_content_hash,
                          state,trust_status,registration_json,registered_at)
                         VALUES ('forged-provider','provider:forged','1.0.0','build:forged',
                                 'disabled','locally-trusted',
                                 '{\"trust\":{\"status\":\"locally-trusted\"}}',
                                 '2026-09-19T00:00:00Z');
                         INSERT INTO provider_conformance_evidence
                         (evidence_id,registration_id,capability,contract_hash,suite_id,
                          suite_hash,status,evidence_json,tested_at)
                         VALUES ('forged-evidence','forged-provider','artifact.hash@1',
                                 'sha256:1111111111111111111111111111111111111111111111111111111111111111',
                                 'suite:forged',
                                 'sha256:2222222222222222222222222222222222222222222222222222',
                                 'fail','{\"result\":\"fail\"}','2026-09-19T00:00:00Z');",
                    )
                    .unwrap();
            }
            manager
                .connection
                .execute_batch(&format!("DROP TRIGGER {guard}"))
                .unwrap();
            if guard == "provider_evidence_no_duplicate_insert" {
                manager
                    .connection
                    .execute_batch(
                        "PRAGMA recursive_triggers=OFF;
                         INSERT OR REPLACE INTO provider_conformance_evidence
                         (evidence_id,registration_id,capability,contract_hash,suite_id,
                          suite_hash,status,evidence_json,tested_at)
                         VALUES ('forged-evidence','forged-provider','artifact.hash@1',
                                 'sha256:1111111111111111111111111111111111111111111111111111',
                                 'suite:forged',
                                 'sha256:2222222222222222222222222222222222222222222222222222',
                                 'pass','{\"result\":\"pass\"}','2026-09-19T00:00:00Z');",
                    )
                    .unwrap();
                assert_eq!(
                    manager
                        .connection
                        .query_row(
                            "SELECT status FROM provider_conformance_evidence
                             WHERE evidence_id='forged-evidence'",
                            [],
                            |row| row.get::<_, String>(0),
                        )
                        .unwrap(),
                    "pass"
                );
            }
            drop(manager);
            for _ in 0..2 {
                assert!(matches!(
                    TaskManager::open_with_clock(&path, Box::new(FixedClock)),
                    Err(TaskManagerError::InvalidRecord(
                        "provider evidence or trust history requires operator quarantine"
                    ))
                ));
            }
            let connection = Connection::open(&path).unwrap();
            assert_eq!(
                connection
                    .query_row(
                        "SELECT fence_epoch FROM task_manager_lease WHERE singleton_id=1",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                old_epoch,
                "{guard}"
            );
            assert!(
                missing_additive_guard(&connection, &[guard]).unwrap(),
                "{guard} was silently reinstalled"
            );
        }
    }

    #[test]
    fn file_backed_reopen_upgrades_complete_prior_evidence_guards() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("prior-evidence-guards.sqlite3");
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        manager.initialize_provider_store().unwrap();
        for guard in PRIOR_PROVIDER_2B1_EVIDENCE_GUARDS {
            manager
                .connection
                .execute_batch(&format!("DROP TRIGGER {guard}"))
                .unwrap();
        }
        manager
            .connection
            .execute_batch(include_str!("legacy_2b1f8e2_provider_evidence_guards.sql"))
            .unwrap();
        assert!(legacy_2b1_evidence_guard_present(&manager.connection).unwrap());
        assert!(matches!(
            preflight_migration_state(&manager.connection),
            Err(TaskManagerError::InvalidRecord(
                "provider registry migration is incomplete"
            ))
        ));
        drop(manager);
        let reopened = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        assert!(preflight_migration_state(&reopened.connection).is_ok());
        assert!(!legacy_2b1_evidence_guard_present(&reopened.connection).unwrap());
        assert!(
            additive_guard_definitions_current(
                &reopened.connection,
                PROVIDER_ADDITIVE_GUARDS,
                true,
                true,
                true
            )
            .unwrap()
        );
    }

    #[test]
    fn erased_revocation_history_requires_operator_quarantine() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("replaced-revoked-provider.sqlite3");
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        manager.initialize_provider_store().unwrap();
        manager
            .connection
            .execute_batch(
                "INSERT INTO provider_registrations
             (registration_id,provider_id,provider_version,package_content_hash,state,
              trust_status,registration_json,registered_at)
             VALUES ('terminal-provider','provider:terminal','1.0.0','build:terminal',
                     'disabled','locally-trusted',
                     '{\"trust\":{\"status\":\"locally-trusted\"}}','2026-09-19T00:00:00Z');
             UPDATE provider_registrations SET state='registered',
                 updated_at='2026-09-19T00:00:00Z'
             WHERE registration_id='terminal-provider';
             UPDATE provider_registrations SET state='revoked',
                 updated_at='2026-09-19T00:00:01Z'
             WHERE registration_id='terminal-provider';
             INSERT INTO provider_registrations
             (registration_id,provider_id,provider_version,package_content_hash,state,
              trust_status,registration_json,registered_at)
             VALUES ('unaffected-provider','provider:unaffected','1.0.0','build:unaffected',
                     'disabled','locally-trusted',
                     '{\"trust\":{\"status\":\"locally-trusted\"}}','2026-09-19T00:00:00Z');
             DROP TRIGGER provider_registration_no_duplicate_insert;
             DROP TRIGGER provider_state_epoch_initial;
             DROP TRIGGER provider_state_epoch_transition;
             DROP TRIGGER provider_state_epoch_no_duplicate_insert;
             DROP TRIGGER provider_state_epoch_event_insert_guard;
             DROP TRIGGER provider_state_epoch_no_delete;
             DROP TRIGGER provider_registration_revoked_epoch_insert;
             DROP TRIGGER provider_registration_revoked_epoch_update;
             INSERT OR REPLACE INTO provider_state_epochs
             (registration_id,revision,state,transitioned_at)
             VALUES ('terminal-provider',2,'disabled','2026-09-19T00:00:01Z');
             INSERT OR REPLACE INTO provider_registrations
             (registration_id,provider_id,provider_version,package_content_hash,state,
              trust_status,registration_json,registered_at)
             VALUES ('terminal-provider','provider:terminal','1.0.0','build:terminal',
                     'disabled','locally-trusted',
                     '{\"trust\":{\"status\":\"locally-trusted\"}}','2026-09-19T00:00:00Z');
             UPDATE provider_registrations SET state='registered',
                 updated_at='2026-09-19T00:00:02Z'
             WHERE registration_id='terminal-provider';",
            )
            .unwrap();
        assert_eq!(manager.connection.query_row(
            "SELECT state FROM provider_registrations WHERE registration_id='terminal-provider'",
            [], |row| row.get::<_, String>(0),
        ).unwrap(), "registered");
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM provider_state_epochs
             WHERE registration_id='terminal-provider' AND state='revoked'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        drop(manager);
        let reopen_error = match TaskManager::open_with_clock(&path, Box::new(FixedClock)) {
            Ok(_) => panic!("unprovable legacy provider history reopened"),
            Err(error) => error,
        };
        assert!(
            matches!(
                &reopen_error,
                TaskManagerError::InvalidRecord(
                    "provider state history requires operator quarantine"
                        | "provider registry migration is incomplete"
                )
            ),
            "{reopen_error}"
        );
        let after = Connection::open(&path).unwrap();
        assert_eq!(after.query_row(
            "SELECT state FROM provider_registrations WHERE registration_id='terminal-provider'",
            [], |row| row.get::<_, String>(0),
        ).unwrap(), "registered");
        assert_eq!(
            after
                .query_row(
                    "SELECT COUNT(*) FROM provider_state_epochs
             WHERE registration_id='terminal-provider' AND state='revoked'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn retained_revoked_epoch_blocks_replacement_and_state_update() {
        let mut manager = TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap();
        manager.initialize_provider_store().unwrap();
        manager
            .connection
            .execute_batch(
                "INSERT INTO provider_registrations
             (registration_id,provider_id,provider_version,package_content_hash,state,
              trust_status,registration_json,registered_at)
             VALUES ('terminal-provider','provider:terminal','1.0.0','build:terminal',
                     'disabled','locally-trusted',
                     '{\"trust\":{\"status\":\"locally-trusted\"}}','2026-09-19T00:00:00Z');
             UPDATE provider_registrations SET state='registered',
                 updated_at='2026-09-19T00:00:00Z'
             WHERE registration_id='terminal-provider';
             UPDATE provider_registrations SET state='revoked',
                 updated_at='2026-09-19T00:00:01Z'
             WHERE registration_id='terminal-provider';
             DROP TRIGGER provider_registration_no_duplicate_insert;",
            )
            .unwrap();
        let replacement = manager
            .connection
            .execute(
                "INSERT OR REPLACE INTO provider_registrations
             (registration_id,provider_id,provider_version,package_content_hash,state,
              trust_status,registration_json,registered_at)
             VALUES ('terminal-provider','provider:terminal','1.0.0','build:terminal',
                     'disabled','locally-trusted',
                     '{\"trust\":{\"status\":\"locally-trusted\"}}','2026-09-19T00:00:00Z')",
                [],
            )
            .unwrap_err()
            .to_string();
        assert!(
            replacement.contains("provider revocation epoch is terminal"),
            "{replacement}"
        );
        manager
            .connection
            .execute_batch("DROP TRIGGER provider_registration_revocation_terminal")
            .unwrap();
        let update = manager
            .connection
            .execute(
                "UPDATE provider_registrations SET state='disabled',
                updated_at='2026-09-19T00:00:02Z'
             WHERE registration_id='terminal-provider'",
                [],
            )
            .unwrap_err()
            .to_string();
        assert!(
            update.contains("provider revocation epoch is terminal"),
            "{update}"
        );
        let state: String = manager.connection.query_row(
            "SELECT state FROM provider_registrations WHERE registration_id='terminal-provider'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(state, "revoked");
        let terminal_epochs: i64 = manager
            .connection
            .query_row(
                "SELECT COUNT(*) FROM provider_state_epochs
             WHERE registration_id='terminal-provider' AND state='revoked'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(terminal_epochs, 1);
    }

    #[test]
    fn stamped_provider_history_defects_are_not_auto_repaired() {
        for defect in [
            "provider_registration_no_duplicate_insert",
            "provider_registration_revoked_epoch_insert",
            "provider_state_epoch_no_update",
            "provider_state_epoch_no_duplicate_insert",
            "provider_state_epoch_event_insert_guard",
            "provider_state_epoch_initial",
            "provider_state_epoch_transition",
            "provider_state_epochs",
            "malformed_provider_state_epochs",
            "malformed_provider_state_epoch_event_insert_guard",
        ] {
            let directory = tempdir().unwrap();
            let path = directory.path().join("unprovable-provider-history.sqlite3");
            let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
            manager.initialize_provider_store().unwrap();
            match defect {
                "provider_state_epochs" => manager
                    .connection
                    .execute_batch("DROP TABLE provider_state_epochs")
                    .unwrap(),
                "malformed_provider_state_epochs" => manager
                    .connection
                    .execute_batch("ALTER TABLE provider_state_epochs ADD COLUMN forged TEXT")
                    .unwrap(),
                "malformed_provider_state_epoch_event_insert_guard" => manager
                    .connection
                    .execute_batch(
                        "DROP TRIGGER provider_state_epoch_event_insert_guard;
                     CREATE TRIGGER provider_state_epoch_event_insert_guard
                     BEFORE INSERT ON provider_state_epochs BEGIN SELECT 1; END",
                    )
                    .unwrap(),
                name => manager
                    .connection
                    .execute_batch(&format!("DROP TRIGGER {name}"))
                    .unwrap(),
            }
            drop(manager);
            let reopen_error = match TaskManager::open_with_clock(&path, Box::new(FixedClock)) {
                Ok(_) => panic!("unprovable provider history reopened: {defect}"),
                Err(error) => error,
            };
            assert!(
                matches!(
                    &reopen_error,
                    TaskManagerError::InvalidRecord(
                        "provider state history requires operator quarantine"
                            | "provider registry migration is incomplete"
                    )
                ),
                "{defect}: {reopen_error}"
            );
            let retained = Connection::open(&path).unwrap();
            assert_eq!(
                retained
                    .query_row(
                        "SELECT COUNT(*) FROM schema_migrations
                 WHERE migration_id='0013_provider_registry'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                1,
                "{defect}"
            );
        }
    }

    #[test]
    fn missing_history_guard_or_ledger_quarantines_before_repair() {
        for missing in [
            "provider_state_epoch_transition",
            "execution_binding_enablement_marker_insert",
            "provider_state_epochs",
        ] {
            let directory = tempdir().unwrap();
            let path = directory.path().join("partial-enable-ledger.sqlite3");
            let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
            manager.initialize_provider_store().unwrap();
            manager
                .connection
                .execute_batch(
                    "INSERT INTO provider_registrations
                 (registration_id,provider_id,provider_version,package_content_hash,state,
                  trust_status,registration_json,registered_at)
                 VALUES ('epoch-provider','provider:epoch','1.0.0','build:epoch','disabled',
                         'locally-trusted','{\"trust\":{\"status\":\"locally-trusted\"}}',
                         '2026-09-19T00:00:00Z');
                 UPDATE provider_registrations SET state='registered',
                     updated_at='2026-09-19T00:00:00Z'
                 WHERE registration_id='epoch-provider';",
                )
                .unwrap();
            manager
                .connection
                .execute_batch(&format!(
                    "DROP {} {missing}",
                    if missing == "provider_state_epochs" {
                        "TABLE"
                    } else {
                        "TRIGGER"
                    }
                ))
                .unwrap();
            drop(manager);
            if missing != "execution_binding_enablement_marker_insert" {
                assert!(
                    matches!(
                        TaskManager::open_with_clock(&path, Box::new(FixedClock)),
                        Err(TaskManagerError::InvalidRecord(
                            "provider state history requires operator quarantine"
                        ))
                    ),
                    "{missing}"
                );
                continue;
            }

            let reopened = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
            assert_eq!(reopened.connection.query_row(
                "SELECT state FROM provider_registrations WHERE registration_id='epoch-provider'",
                [], |row| row.get::<_, String>(0),
            ).unwrap(), "disabled", "{missing}");
            assert_eq!(reopened.connection.query_row(
                "SELECT state FROM provider_state_epochs WHERE registration_id='epoch-provider'
                 ORDER BY revision DESC LIMIT 1", [], |row| row.get::<_, String>(0),
            ).unwrap(), "disabled", "{missing}");
            reopened
                .connection
                .execute(
                    "UPDATE provider_registrations SET state='registered',updated_at=?1
                 WHERE registration_id='epoch-provider'",
                    [T0],
                )
                .unwrap();
            let revision: i64 = reopened.connection.query_row(
                "SELECT MAX(revision) FROM provider_state_epochs WHERE registration_id='epoch-provider'",
                [], |row| row.get(0),
            ).unwrap();
            drop(reopened);
            let again = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
            assert_eq!(again.connection.query_row(
                "SELECT state FROM provider_registrations WHERE registration_id='epoch-provider'",
                [], |row| row.get::<_, String>(0),
            ).unwrap(), "registered", "{missing}");
            assert_eq!(again.connection.query_row(
                "SELECT MAX(revision) FROM provider_state_epochs WHERE registration_id='epoch-provider'",
                [], |row| row.get::<_, i64>(0),
            ).unwrap(), revision, "{missing}");
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "tests both exhausted reopen and the reserved terminal transition"
    )]
    fn exhausted_epoch_revision_blocks_transition_and_fenced_repair() {
        for revision in [i64::MAX - 1, i64::MAX] {
            let directory = tempdir().unwrap();
            let path = directory.path().join("exhausted-epoch.sqlite3");
            let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
            manager.initialize_provider_store().unwrap();
            manager
                .connection
                .execute_batch(
                    "INSERT INTO provider_registrations
                 (registration_id,provider_id,provider_version,package_content_hash,
                  state,trust_status,registration_json,registered_at)
                 VALUES ('exhausted-provider','provider:exhausted','1.0.0','build:exhausted',
                         'disabled','locally-trusted',
                         '{\"trust\":{\"status\":\"locally-trusted\"}}',
                         '2026-09-19T00:00:00Z');
                 DROP TRIGGER provider_state_epoch_event_insert_guard;",
                )
                .unwrap();
            manager.connection.execute(
                "INSERT INTO provider_state_epochs(registration_id,revision,state,transitioned_at)
                 VALUES ('exhausted-provider',?1,'disabled',?2)",
                params![revision,T0],
            ).unwrap();
            manager
                .connection
                .execute_batch(include_str!(
                    "../../../specs/persistence-v0.1-0013-provider-registry.sql"
                ))
                .unwrap();
            assert!(
                manager
                    .connection
                    .execute(
                        "UPDATE provider_registrations SET state='registered',updated_at=?1
                 WHERE registration_id='exhausted-provider'",
                        [T0],
                    )
                    .unwrap_err()
                    .to_string()
                    .contains("epoch revision exhausted")
            );
            assert_eq!(manager.connection.query_row(
                "SELECT state FROM provider_registrations WHERE registration_id='exhausted-provider'",
                [], |row| row.get::<_, String>(0),
            ).unwrap(),"disabled");
            manager
                .connection
                .execute_batch("DROP TRIGGER provider_state_epoch_transition")
                .unwrap();
            drop(manager);
            assert!(matches!(
                TaskManager::open_with_clock(&path, Box::new(FixedClock)),
                Err(TaskManagerError::InvalidRecord(
                    "provider state history requires operator quarantine"
                ))
            ));
            let retained = Connection::open(&path).unwrap();
            assert_eq!(retained.query_row(
                "SELECT state FROM provider_registrations WHERE registration_id='exhausted-provider'",
                [], |row| row.get::<_, String>(0),
            ).unwrap(),"disabled");
            assert_eq!(
                retained
                    .query_row(
                        "SELECT MAX(revision) FROM provider_state_epochs
                 WHERE registration_id='exhausted-provider'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                revision
            );
        }
        let mut manager = test_manager();
        manager.initialize_provider_store().unwrap();
        manager
            .connection
            .execute_batch(
                "INSERT INTO provider_registrations
             (registration_id,provider_id,provider_version,package_content_hash,
              state,trust_status,registration_json,registered_at)
             VALUES ('terminal-epoch','provider:terminal','1.0.0','build:terminal',
                     'disabled','locally-trusted',
                     '{\"trust\":{\"status\":\"locally-trusted\"}}','2026-09-19T00:00:00Z');
             UPDATE provider_registrations SET state='registered',
                 updated_at='2026-09-19T00:00:00Z'
             WHERE registration_id='terminal-epoch';
             DROP TRIGGER provider_state_epoch_event_insert_guard;",
            )
            .unwrap();
        manager
            .connection
            .execute(
                "INSERT INTO provider_state_epochs(registration_id,revision,state,transitioned_at)
             VALUES ('terminal-epoch',?1,'registered',?2)",
                params![i64::MAX - 2, T0],
            )
            .unwrap();
        manager
            .connection
            .execute_batch(include_str!(
                "../../../specs/persistence-v0.1-0013-provider-registry.sql"
            ))
            .unwrap();
        manager
            .connection
            .execute(
                "UPDATE provider_registrations SET state='disabled',updated_at=?1
             WHERE registration_id='terminal-epoch'",
                [T0],
            )
            .unwrap();
        assert_eq!(manager.connection.query_row(
            "SELECT MAX(revision) FROM provider_state_epochs WHERE registration_id='terminal-epoch'",
            [], |row| row.get::<_, i64>(0),
        ).unwrap(),i64::MAX-1);
        assert!(
            manager
                .connection
                .execute(
                    "UPDATE provider_registrations SET state='registered',updated_at=?1
             WHERE registration_id='terminal-epoch'",
                    [T0],
                )
                .unwrap_err()
                .to_string()
                .contains("epoch revision exhausted")
        );
    }

    #[test]
    fn first_provider_migration_disables_unproven_baseline_enablement() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("baseline-provider-epoch.sqlite3");
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        manager
            .connection
            .execute_batch(
                "INSERT INTO provider_registrations
             (registration_id,provider_id,provider_version,package_content_hash,state,
              trust_status,registration_json,registered_at,updated_at)
             VALUES ('baseline-provider','provider:baseline','1.0.0','build:baseline',
                     'registered','locally-trusted',
                     '{\"trust\":{\"status\":\"locally-trusted\"}}',
                     '2026-09-19T00:00:00Z','2026-09-20T00:00:00Z');",
            )
            .unwrap();
        manager.initialize_provider_store().unwrap();
        assert_eq!(manager.connection.query_row(
            "SELECT state FROM provider_registrations WHERE registration_id='baseline-provider'",
            [], |row| row.get::<_, String>(0),
        ).unwrap(), "disabled");
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT revision,state FROM provider_state_epochs
             WHERE registration_id='baseline-provider'",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                )
                .unwrap(),
            (0, "disabled".to_owned())
        );
        manager
            .connection
            .execute(
                "UPDATE provider_registrations SET state='registered',updated_at=?1
             WHERE registration_id='baseline-provider'",
                [T0],
            )
            .unwrap();
        drop(manager);
        let reopened = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        assert_eq!(reopened.connection.query_row(
            "SELECT state FROM provider_registrations WHERE registration_id='baseline-provider'",
            [], |row| row.get::<_, String>(0),
        ).unwrap(), "registered");
        assert_eq!(
            reopened
                .connection
                .query_row(
                    "SELECT revision,state FROM provider_state_epochs
             WHERE registration_id='baseline-provider' ORDER BY revision DESC LIMIT 1",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                )
                .unwrap(),
            (1, "registered".to_owned())
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "covers offset normalization and exact stamped-guard migration in one durable fixture"
    )]
    fn large_rfc3339_offsets_survive_provider_guard_upgrade() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("offset-provider-guards.sqlite3");
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        manager.initialize_provider_store().unwrap();
        manager.create_task(&create("T-offset-provider")).unwrap();
        manager.connection.execute_batch(
            "INSERT INTO registry_snapshots(snapshot_id,manifest_json,created_at)
             VALUES ('offset-snapshot','{}','2026-09-19T00:00:00Z');
             INSERT INTO registry_snapshot_admissions(snapshot_id,state)
             VALUES ('offset-snapshot','ADMITTED');
             DROP TRIGGER immutable_admitted_registry_snapshot_entries_insert;
             INSERT INTO registry_snapshot_entries
             (snapshot_id,contract_class,semantic_id,major,full_version,content_hash)
             VALUES ('offset-snapshot','capability','artifact.hash',1,'1.0',
                     'sha256:1111111111111111111111111111111111111111111111111111111111111111');
             CREATE TRIGGER immutable_admitted_registry_snapshot_entries_insert
             BEFORE INSERT ON registry_snapshot_entries
             WHEN EXISTS (
                 SELECT 1 FROM registry_snapshot_admissions WHERE snapshot_id IS NEW.snapshot_id
             )
             BEGIN SELECT RAISE(ABORT, 'admitted registry snapshot entry set is immutable'); END;
             INSERT INTO semantic_capability_contracts
             (content_hash,semantic_id,full_version,contract_json)
             VALUES ('sha256:1111111111111111111111111111111111111111111111111111111111111111',
                     'artifact.hash','1.0',
                     '{\"conformance\":{\"suite_version\":\"0.1\"}}');
             INSERT INTO provider_registrations
             (registration_id,provider_id,provider_version,manifest_hash,package_content_hash,
              registry_snapshot_id,state,trust_status,registration_json,registered_at)
             VALUES ('sha256:afa34cd537c467a13070d3ffaef13b06b7131d12ddd29b7625426730d5b4316b','provider.offset','1.0.0','sha256:e3d734314ad3098ce199002e9a9ce433d5b401c52f3ba3a4dbee3194a93c8d6c','sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
                     'offset-snapshot','disabled','locally-trusted',
                     '{\"trust\":{\"status\":\"locally-trusted\"}}',
                     '2026-09-19T15:00:00+15:00');
             INSERT INTO provider_manifest_payloads(registration_id,manifest_json)
             VALUES ('sha256:afa34cd537c467a13070d3ffaef13b06b7131d12ddd29b7625426730d5b4316b',
                     '{\"id\":\"provider.offset\",\"provides\":[{\"conformance\":{\"status\":\"declared\",\"suite\":\"offset-suite\",\"suite_hash\":\"sha256:2222222222222222222222222222222222222222222222222222222222222222\"},\"contract\":{\"capability\":\"artifact.hash\",\"contract_hash\":\"sha256:1111111111111111111111111111111111111111111111111111111111111111\",\"version\":\"1.0\"},\"effect_classes\":[\"PURE\"],\"execution\":{\"execution_class\":\"deterministic\",\"locality\":[\"local\"],\"minimum_isolation\":\"P2\"}}],\"publisher\":{\"id\":\"fixture\"},\"runtime\":{\"kind\":\"process\"},\"schema_version\":\"0.1\",\"version\":\"1.0.0\"}');
             UPDATE provider_registrations SET state='registered',
                 updated_at='2026-09-19T15:00:00+15:00'
             WHERE registration_id='sha256:afa34cd537c467a13070d3ffaef13b06b7131d12ddd29b7625426730d5b4316b';
             INSERT INTO provider_conformance_evidence
             (evidence_id,registration_id,capability,contract_hash,suite_id,suite_hash,
              status,evidence_json,tested_at)
             VALUES ('offset-evidence','sha256:afa34cd537c467a13070d3ffaef13b06b7131d12ddd29b7625426730d5b4316b','artifact.hash@1','sha256:1111111111111111111111111111111111111111111111111111111111111111',
                     'offset-suite','sha256:2222222222222222222222222222222222222222222222222222222222222222','pass',
                     '{\"schema_version\":\"0.1\",\"result_id\":\"offset-evidence\",\"provider_id\":\"provider.offset\",\"provider_version\":\"1.0.0\",\"provider_build_identity\":{\"kind\":\"build_hash\",\"value\":\"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\"},\"semantic_capability_ref\":\"artifact.hash@1\",\"semantic_contract_version\":\"1.0\",\"semantic_contract_hash\":\"sha256:1111111111111111111111111111111111111111111111111111111111111111\",\"conformance_suite\":{\"id\":\"offset-suite\",\"version\":\"0.1\",\"hash\":\"sha256:2222222222222222222222222222222222222222222222222222222222222222\"},\"harness\":{\"id\":\"harness:offset\",\"version\":\"0.1\"},\"result\":\"pass\",\"tests_total\":1,\"tests_passed\":1,\"tests_failed\":0,\"executed_at\":\"2026-09-19T00:00:00.100Z\",\"expires_at\":\"2026-09-19T00:00:02Z\"}',
                     '2026-09-19T00:00:00.100Z');
             INSERT INTO provider_trust_admissions
             (admission_id,registration_id,decision_id,revision,trust_status,authority_ref,
              admitted_at,receipt_json)
             VALUES ('sha256:4162116b26d1a831b57a060d6928c2ade7c7140e3ad8245a3e11aaeef1c20986','sha256:afa34cd537c467a13070d3ffaef13b06b7131d12ddd29b7625426730d5b4316b','offset-decision',1,'project-reviewed',
                     'review:offset','2026-09-19T15:00:00.200+15:00',
                     '{\"admitted_at\":\"2026-09-19T15:00:00.200+15:00\",\"authority_ref\":\"review:offset\",\"decision_id\":\"offset-decision\",\"registration_id\":\"sha256:afa34cd537c467a13070d3ffaef13b06b7131d12ddd29b7625426730d5b4316b\",\"revision\":1,\"schema_version\":\"0.1\",\"trust_status\":\"project-reviewed\"}');
             INSERT INTO execution_bindings
             (binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,
              ir_version,node_id,capability,capability_contract_hash,provider_registration_id,
              provider_id,provider_version,provider_manifest_hash,provider_build_hash,
              attempt,policy_decision_refs_json,grant_refs_json,execution_profile_ref,
              placement_json,binding_json,created_at)
             VALUES ('offset-binding','offset-attempt','T-offset-provider','sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
                     'offset-snapshot','0.1','offset-node','artifact.hash@1','sha256:1111111111111111111111111111111111111111111111111111111111111111',
                     'sha256:afa34cd537c467a13070d3ffaef13b06b7131d12ddd29b7625426730d5b4316b','provider.offset','1.0.0','sha256:e3d734314ad3098ce199002e9a9ce433d5b401c52f3ba3a4dbee3194a93c8d6c','sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
                     1,'[]','[]','offset-profile','{\"locality\":\"local\"}',
                     '{\"schema_version\":\"0.1\",\"binding_id\":\"offset-binding\",\"attempt_id\":\"offset-attempt\",\"task_id\":\"T-offset-provider\",\"semantic_program_hash\":\"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",\"registry_snapshot_id\":\"offset-snapshot\",\"ir_version\":\"0.1\",\"node_id\":\"offset-node\",\"capability\":\"artifact.hash@1\",\"capability_contract_hash\":\"sha256:1111111111111111111111111111111111111111111111111111111111111111\",\"conformance_evidence_id\":\"offset-evidence\",\"provider_trust_source_id\":\"sha256:4162116b26d1a831b57a060d6928c2ade7c7140e3ad8245a3e11aaeef1c20986\",\"provider\":{\"id\":\"provider.offset\",\"version\":\"1.0.0\",\"manifest_hash\":\"sha256:e3d734314ad3098ce199002e9a9ce433d5b401c52f3ba3a4dbee3194a93c8d6c\",\"package_or_build_hash\":\"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\"},\"attempt\":1,\"policy_decision_refs\":[],\"authority\":{\"grant_refs\":[]},\"execution_profile\":{\"profile_ref\":\"offset-profile\"},\"placement\":{\"locality\":\"local\"},\"inputs\":{},\"outputs\":{},\"created_at\":\"2026-09-19T01:00:00.300+01:00\"}',
                     '2026-09-19T01:00:00.300+01:00');",
        ).unwrap();
        let clone_receipt = |binding_id: &str, attempt_id: &str, attempt: i64| {
            manager
                .connection
                .query_row(
                    "SELECT json_set(binding_json,'$.binding_id',?1,
                    '$.attempt_id',?2,'$.attempt',?3)
                 FROM execution_bindings WHERE binding_id='offset-binding'",
                    params![binding_id, attempt_id, attempt],
                    |row| row.get::<_, String>(0),
                )
                .unwrap()
        };
        let insert_clone = |connection: &Connection,
                            binding_id: &str,
                            attempt_id: &str,
                            attempt: i64,
                            receipt: &str,
                            policy: &str,
                            grants: &str,
                            placement: &str| {
            let placement = if placement == "{}" {
                r#"{"locality":"local"}"#
            } else {
                placement
            };
            connection.execute(
                "INSERT INTO execution_bindings
                 (binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,
                  ir_version,node_id,capability,capability_contract_hash,provider_registration_id,
                  provider_id,provider_version,provider_manifest_hash,provider_build_hash,
                  attempt,policy_decision_refs_json,grant_refs_json,execution_profile_ref,
                  placement_json,binding_json,created_at)
                 SELECT ?1,?2,task_id,semantic_program_hash,registry_snapshot_id,
                        ir_version,node_id,capability,capability_contract_hash,
                        provider_registration_id,provider_id,provider_version,
                        provider_manifest_hash,provider_build_hash,?3,
                        ?5,?6,execution_profile_ref,
                        ?7,?4,created_at
                 FROM execution_bindings WHERE binding_id='offset-binding'",
                params![
                    binding_id, attempt_id, attempt, receipt, policy, grants, placement
                ],
            )
        };
        let receipt = clone_receipt("offset-invalid-unicode", "offset-unicode-attempt", 4);
        let malformed = receipt.replace("\"outputs\":{}", "\"outputs\":{\"bad\":\"\\ud800\"}");
        assert_ne!(malformed, receipt);
        assert!(
            insert_clone(
                &manager.connection,
                "offset-invalid-unicode",
                "offset-unicode-attempt",
                4,
                &malformed,
                "[]",
                "[]",
                "{}"
            )
            .is_err()
        );
        let raw = Connection::open(&path).unwrap();
        let raw_receipt = clone_receipt("offset-raw-writer", "offset-raw-attempt", 5);
        let error = insert_clone(
            &raw,
            "offset-raw-writer",
            "offset-raw-attempt",
            5,
            &raw_receipt,
            "[]",
            "[]",
            "{}",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("no such function: aios_binding_"), "{error}");
        let padding = " ".repeat(8 * 1024 * 1024);
        for (binding_id, attempt_id, attempt, policy, grants, placement) in [
            (
                "offset-large-policy",
                "offset-large-policy-attempt",
                6,
                format!("{padding}[]"),
                "[]".to_owned(),
                "{}".to_owned(),
            ),
            (
                "offset-large-grants",
                "offset-large-grants-attempt",
                7,
                "[]".to_owned(),
                format!("{padding}[]"),
                "{}".to_owned(),
            ),
            (
                "offset-large-placement",
                "offset-large-placement-attempt",
                8,
                "[]".to_owned(),
                "[]".to_owned(),
                format!("{padding}{{}}"),
            ),
        ] {
            let receipt = clone_receipt(binding_id, attempt_id, attempt);
            assert!(
                insert_clone(
                    &manager.connection,
                    binding_id,
                    attempt_id,
                    attempt,
                    &receipt,
                    &policy,
                    &grants,
                    &placement
                )
                .is_err(),
                "{binding_id}"
            );
        }
        let count_binding_and_markers = |id: &str| -> i64 {
            manager.connection.query_row(
                "SELECT (SELECT COUNT(*) FROM execution_bindings WHERE binding_id=?1)
                      + (SELECT COUNT(*) FROM execution_binding_admission_markers WHERE binding_id=?1)
                      + (SELECT COUNT(*) FROM execution_binding_trust_markers WHERE binding_id=?1)
                      + (SELECT COUNT(*) FROM execution_binding_enablement_markers WHERE binding_id=?1)",
                [id], |row| row.get(0),
            ).unwrap()
        };
        let binding_id = "offset-non-rfc3339";
        let attempt_id = "offset-non-rfc3339-attempt";
        let mut receipt: Value =
            serde_json::from_str(&clone_receipt(binding_id, attempt_id, 23)).unwrap();
        let missing_offset = "2026-09-19T00:00:01";
        receipt["created_at"] = json!(missing_offset);
        assert!(
            manager
                .connection
                .query_row(
                    "SELECT julianday(?1) IS NOT NULL",
                    [missing_offset],
                    |row| row.get::<_, bool>(0),
                )
                .unwrap()
        );
        let error = manager
            .connection
            .execute(
                "INSERT INTO execution_bindings
                 (binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,
                  ir_version,node_id,capability,capability_contract_hash,provider_registration_id,
                  provider_id,provider_version,provider_manifest_hash,provider_build_hash,
                  attempt,policy_decision_refs_json,grant_refs_json,execution_profile_ref,
                  placement_json,binding_json,created_at)
                 SELECT ?1,?2,task_id,semantic_program_hash,registry_snapshot_id,
                        ir_version,node_id,capability,capability_contract_hash,
                        provider_registration_id,provider_id,provider_version,
                        provider_manifest_hash,provider_build_hash,23,
                        policy_decision_refs_json,grant_refs_json,execution_profile_ref,
                        placement_json,?3,?4
                 FROM execution_bindings WHERE binding_id='offset-binding'",
                params![binding_id, attempt_id, receipt.to_string(), missing_offset],
            )
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("binding provider identity does not match registration")
                || error.contains("binding conformance evidence is not latest"),
            "{error}"
        );
        assert_eq!(count_binding_and_markers(binding_id), 0);
        let corrected = clone_receipt(binding_id, attempt_id, 23);
        insert_clone(
            &manager.connection,
            binding_id,
            attempt_id,
            23,
            &corrected,
            "[]",
            "[]",
            "{}",
        )
        .unwrap();
        assert_eq!(count_binding_and_markers(binding_id), 4);
        for id in [
            "offset-invalid-unicode",
            "offset-raw-writer",
            "offset-large-policy",
            "offset-large-grants",
            "offset-large-placement",
        ] {
            assert_eq!(
                count_binding_and_markers(id),
                0,
                "rejected {id} must leave no binding or markers"
            );
        }
        let overlong = json!((0..65).map(|i| format!("ref:{i}")).collect::<Vec<_>>());
        for (suffix, attempt, policy, grants) in [
            ("policy-number", 9, json!([0]), json!([])),
            ("grant-number", 10, json!([]), json!([0])),
            ("policy-duplicate", 11, json!(["same", "same"]), json!([])),
            ("grant-duplicate", 12, json!([]), json!(["same", "same"])),
            ("policy-overlong", 13, overlong.clone(), json!([])),
            ("grant-overlong", 14, json!([]), overlong.clone()),
        ] {
            let binding_id = format!("offset-{suffix}");
            let attempt_id = format!("offset-{suffix}-attempt");
            let mut receipt: Value =
                serde_json::from_str(&clone_receipt(&binding_id, &attempt_id, attempt)).unwrap();
            receipt["policy_decision_refs"] = policy.clone();
            receipt["authority"]["grant_refs"] = grants.clone();
            let error = insert_clone(
                &manager.connection,
                &binding_id,
                &attempt_id,
                attempt,
                &receipt.to_string(),
                &policy.to_string(),
                &grants.to_string(),
                "{}",
            )
            .unwrap_err()
            .to_string();
            assert!(
                error.contains("binding provider identity does not match registration"),
                "{suffix}: {error}"
            );
            assert_eq!(
                count_binding_and_markers(&binding_id),
                0,
                "rejected {suffix} must not consume its immutable identity"
            );
        }
        let corrected = clone_receipt("offset-policy-number", "offset-policy-number-attempt", 9);
        insert_clone(
            &manager.connection,
            "offset-policy-number",
            "offset-policy-number-attempt",
            9,
            &corrected,
            "[]",
            "[]",
            "{}",
        )
        .unwrap();
        assert_eq!(count_binding_and_markers("offset-policy-number"), 4);
        for (suffix, attempt, old, replacement, valid) in [
            (
                "nul-only",
                15,
                "\"schema_version\":\"0.1\"".to_owned(),
                "\"schema_version\\u0000suffix\":\"0.1\"".to_owned(),
                false,
            ),
            (
                "nul-before",
                16,
                "\"schema_version\":\"0.1\"".to_owned(),
                "\"schema_version\\u0000suffix\":\"0.1\",\"schema_version\":\"0.1\"".to_owned(),
                false,
            ),
            (
                "nul-after",
                17,
                "\"schema_version\":\"0.1\"".to_owned(),
                "\"schema_version\":\"0.1\",\"schema_version\\u0000suffix\":\"0.1\"".to_owned(),
                false,
            ),
            (
                "evidence-nul-only",
                18,
                "\"conformance_evidence_id\":\"offset-evidence\"".to_owned(),
                "\"conformance_evidence_id\\u0000suffix\":\"offset-evidence\"".to_owned(),
                false,
            ),
            (
                "trust-nul-only",
                19,
                "\"provider_trust_source_id\":\"sha256:4162116b26d1a831b57a060d6928c2ade7c7140e3ad8245a3e11aaeef1c20986\"".to_owned(),
                "\"provider_trust_source_id\\u0000suffix\":\"sha256:4162116b26d1a831b57a060d6928c2ade7c7140e3ad8245a3e11aaeef1c20986\"".to_owned(),
                false,
            ),
            (
                "overflow",
                20,
                "\"attempt\":20".to_owned(),
                "\"attempt\":18446744073709551615".to_owned(),
                false,
            ),
        ] {
            let binding_id = format!("offset-{suffix}");
            let attempt_id = format!("offset-{suffix}-attempt");
            let receipt = clone_receipt(&binding_id, &attempt_id, attempt);
            let forged = receipt.replacen(&old, &replacement, 1);
            assert_ne!(
                forged, receipt,
                "fixture mutation {suffix} must be effective"
            );
            let result = insert_clone(
                &manager.connection,
                &binding_id,
                &attempt_id,
                attempt,
                &forged,
                "[]",
                "[]",
                "{}",
            );
            if valid {
                result.unwrap();
                assert_eq!(count_binding_and_markers(&binding_id), 4, "{suffix}");
            } else {
                let error = result.unwrap_err().to_string();
                assert!(error.contains("binding "), "{suffix}: {error}");
                assert_eq!(count_binding_and_markers(&binding_id), 0, "{suffix}");
            }
        }
        for (suffix, attempt) in [("nul-only", 15), ("overflow", 20)] {
            let binding_id = format!("offset-{suffix}");
            let attempt_id = format!("offset-{suffix}-attempt");
            let receipt = clone_receipt(&binding_id, &attempt_id, attempt);
            insert_clone(
                &manager.connection,
                &binding_id,
                &attempt_id,
                attempt,
                &receipt,
                "[]",
                "[]",
                "{}",
            )
            .unwrap();
            assert_eq!(count_binding_and_markers(&binding_id), 4);
        }
        aios_registry::register_strict_json_sqlite(&raw).unwrap();
        raw.pragma_update(None, "foreign_keys", "OFF").unwrap();
        let ignored_sql = "INSERT OR IGNORE INTO execution_bindings
            (binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,
             ir_version,node_id,capability,capability_contract_hash,provider_registration_id,
             provider_id,provider_version,provider_manifest_hash,provider_build_hash,
             attempt,policy_decision_refs_json,grant_refs_json,execution_profile_ref,
             placement_json,binding_json,created_at)
            SELECT ?1,?2,task_id,semantic_program_hash,registry_snapshot_id,
                   ir_version,node_id,capability,capability_contract_hash,
                   provider_registration_id,provider_id,provider_version,
                   provider_manifest_hash,provider_build_hash,?3,
                   policy_decision_refs_json,grant_refs_json,execution_profile_ref,
                   placement_json,?4,created_at
            FROM execution_bindings WHERE binding_id='offset-binding'";
        for (suffix, valid_attempt, sql) in [
            ("ignored-check", 21, ignored_sql.to_owned()),
            (
                "replaced-check",
                22,
                ignored_sql.replacen("OR IGNORE", "OR REPLACE", 1),
            ),
        ] {
            let binding_id = format!("offset-{suffix}");
            let attempt_id = format!("offset-{suffix}-attempt");
            let invalid = clone_receipt(&binding_id, &attempt_id, 0);
            let error = raw
                .execute(&sql, params![&binding_id, &attempt_id, 0, &invalid])
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("binding provider identity does not match registration"),
                "{suffix}: {error}"
            );
            assert_eq!(count_binding_and_markers(&binding_id), 0, "{suffix}");
            let corrected = clone_receipt(&binding_id, &attempt_id, valid_attempt);
            insert_clone(
                &raw,
                &binding_id,
                &attempt_id,
                valid_attempt,
                &corrected,
                "[]",
                "[]",
                "{}",
            )
            .unwrap();
            assert_eq!(count_binding_and_markers(&binding_id), 4);
        }
        assert!(
            manager
                .connection
                .execute(
                    "INSERT INTO execution_bindings
             (binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,
              ir_version,node_id,capability,capability_contract_hash,provider_registration_id,
              provider_id,provider_version,provider_manifest_hash,provider_build_hash,
              attempt,policy_decision_refs_json,grant_refs_json,execution_profile_ref,
              placement_json,binding_json,created_at)
             SELECT 'offset-expired','offset-expired-attempt',task_id,semantic_program_hash,
              registry_snapshot_id,ir_version,node_id,capability,capability_contract_hash,
              provider_registration_id,provider_id,provider_version,provider_manifest_hash,
              provider_build_hash,2,policy_decision_refs_json,grant_refs_json,
              execution_profile_ref,placement_json,
              json_set(binding_json,'$.binding_id','offset-expired',
                       '$.attempt_id','offset-expired-attempt','$.attempt',2,
                       '$.created_at','2026-09-19T00:00:02Z'),
              '2026-09-19T00:00:02Z'
             FROM execution_bindings WHERE binding_id='offset-binding'",
                    [],
                )
                .unwrap_err()
                .to_string()
                .contains("expired at creation")
        );
        manager
            .connection
            .execute_batch("DROP TRIGGER execution_binding_evidence_unexpired_at_insert")
            .unwrap();
        // A partially upgraded store can contain one prior evidence guard
        // alongside current guards. Reopening must replace the mixed set and
        // quarantine the already admitted binding and its immutable markers.
        manager
            .connection
            .execute_batch("DROP TRIGGER execution_binding_evidence_present_at_insert")
            .unwrap();
        let prior_guards = include_str!("legacy_2b1f8e2_provider_evidence_guards.sql");
        let first_guard = prior_guards
            .split_once("END;")
            .expect("prior guard definition")
            .0;
        manager
            .connection
            .execute_batch(&format!("{first_guard}END;"))
            .unwrap();
        assert!(legacy_2b1_evidence_guard_present(&manager.connection).unwrap());
        let stamp: (String, String) = manager
            .connection
            .query_row(
                "SELECT checksum,applied_at FROM schema_migrations
             WHERE migration_id='0013_provider_registry'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        drop(manager);
        let reopened = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        assert!(!legacy_2b1_evidence_guard_present(&reopened.connection).unwrap());
        assert_eq!(reopened.connection.query_row(
            "SELECT state FROM provider_registrations WHERE registration_id='sha256:afa34cd537c467a13070d3ffaef13b06b7131d12ddd29b7625426730d5b4316b'",
            [], |row| row.get::<_, String>(0),
        ).unwrap(),"registered");
        assert_eq!(
            reopened
                .connection
                .query_row(
                    "SELECT checksum,applied_at FROM schema_migrations
             WHERE migration_id='0013_provider_registry'",
                    [],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .unwrap(),
            stamp
        );
        assert_eq!(
            reopened
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM execution_binding_legacy_trust_quarantine
             WHERE binding_id='offset-binding'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        reopened
            .connection
            .execute_batch(
                "UPDATE provider_registrations SET state='disabled',
                 updated_at='2026-09-19T00:00:00.400Z'
             WHERE registration_id='sha256:afa34cd537c467a13070d3ffaef13b06b7131d12ddd29b7625426730d5b4316b';
             UPDATE provider_registrations SET state='registered',
                 updated_at='2026-09-19T15:00:00.400+15:00'
             WHERE registration_id='sha256:afa34cd537c467a13070d3ffaef13b06b7131d12ddd29b7625426730d5b4316b';
             INSERT INTO execution_bindings
             (binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,
              ir_version,node_id,capability,capability_contract_hash,provider_registration_id,
              provider_id,provider_version,provider_manifest_hash,provider_build_hash,
              attempt,policy_decision_refs_json,grant_refs_json,execution_profile_ref,
              placement_json,binding_json,created_at)
             SELECT 'offset-fresh','offset-fresh-attempt',task_id,semantic_program_hash,
              registry_snapshot_id,ir_version,node_id,capability,capability_contract_hash,
              provider_registration_id,provider_id,provider_version,provider_manifest_hash,
              provider_build_hash,3,policy_decision_refs_json,grant_refs_json,
              execution_profile_ref,placement_json,
              json_set(binding_json,'$.binding_id','offset-fresh',
                       '$.attempt_id','offset-fresh-attempt','$.attempt',3,
                       '$.created_at','2026-09-19T00:00:00.500Z'),
              '2026-09-19T00:00:00.500Z'
             FROM execution_bindings WHERE binding_id='offset-binding';",
            )
            .unwrap();
        assert_eq!(
            reopened
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM execution_binding_enablement_markers m
             JOIN provider_state_epochs e ON e.registration_id=m.registration_id
                 AND e.revision=m.revision WHERE m.binding_id='offset-fresh'
                 AND e.revision=(SELECT MAX(revision) FROM provider_state_epochs
                                 WHERE registration_id='sha256:afa34cd537c467a13070d3ffaef13b06b7131d12ddd29b7625426730d5b4316b')",
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
        reason = "covers one forged admission and dependent binding across fenced reopen"
    )]
    fn semantic_guard_repair_fences_forged_admission_and_existing_binding() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("semantic-guard-repair.sqlite3");
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        manager.initialize_provider_store().unwrap();
        manager.create_task(&create("T-semantic-repair")).unwrap();
        manager.connection.execute_batch(
            "INSERT INTO registry_snapshots(snapshot_id,manifest_json,created_at)
             VALUES ('repair-snapshot','{}','2026-09-19T00:00:00Z');
             INSERT INTO registry_snapshot_admissions(snapshot_id,state)
             VALUES ('repair-snapshot','ADMITTED');
             DROP TRIGGER immutable_admitted_registry_snapshot_entries_insert;
             INSERT INTO registry_snapshot_entries
             (snapshot_id,contract_class,semantic_id,major,full_version,content_hash)
             VALUES ('repair-snapshot','capability','artifact.hash',1,'1.0',
                     'sha256:3333333333333333333333333333333333333333333333333333333333333333');
             CREATE TRIGGER immutable_admitted_registry_snapshot_entries_insert
             BEFORE INSERT ON registry_snapshot_entries
             WHEN EXISTS (
                 SELECT 1 FROM registry_snapshot_admissions WHERE snapshot_id IS NEW.snapshot_id
             )
             BEGIN SELECT RAISE(ABORT, 'admitted registry snapshot entry set is immutable'); END;
             INSERT INTO semantic_capability_contracts
             (content_hash,semantic_id,full_version,contract_json)
             VALUES ('sha256:3333333333333333333333333333333333333333333333333333333333333333',
                     'artifact.hash','1.0',
                     '{\"conformance\":{\"suite_version\":\"0.1\"}}');
             INSERT INTO provider_registrations
             (registration_id,provider_id,provider_version,manifest_hash,package_content_hash,
              registry_snapshot_id,state,trust_status,registration_json,registered_at)
             VALUES ('sha256:a09b3d1eec3f8d97709b8253a4f3e380e70b8cd23af341b4d0bf2e8b91bd7a74','provider.repair','1.0.0','sha256:6024c42cbfc4fce1192605eaf452bc37f61e2e03a44fdc8047f864ea4f925777','sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
                     'repair-snapshot','disabled','locally-trusted',
                     '{\"trust\":{\"status\":\"locally-trusted\"}}','2026-09-19T00:00:00Z');
              INSERT INTO provider_manifest_payloads(registration_id,manifest_json)
              VALUES ('sha256:a09b3d1eec3f8d97709b8253a4f3e380e70b8cd23af341b4d0bf2e8b91bd7a74','{\"id\":\"provider.repair\",\"provides\":[{\"conformance\":{\"status\":\"declared\",\"suite\":\"repair-suite\",\"suite_hash\":\"sha256:4444444444444444444444444444444444444444444444444444444444444444\"},\"contract\":{\"capability\":\"artifact.hash\",\"contract_hash\":\"sha256:3333333333333333333333333333333333333333333333333333333333333333\",\"version\":\"1.0\"},\"effect_classes\":[\"PURE\"],\"execution\":{\"execution_class\":\"deterministic\",\"locality\":[\"local\"],\"minimum_isolation\":\"P2\"}}],\"publisher\":{\"id\":\"fixture\"},\"runtime\":{\"kind\":\"process\"},\"schema_version\":\"0.1\",\"version\":\"1.0.0\"}');
             UPDATE provider_registrations SET state='registered',
                 updated_at='2026-09-19T00:00:00Z'
             WHERE registration_id='sha256:a09b3d1eec3f8d97709b8253a4f3e380e70b8cd23af341b4d0bf2e8b91bd7a74';
             INSERT INTO provider_conformance_evidence
             (evidence_id,registration_id,capability,contract_hash,suite_id,suite_hash,
              status,evidence_json,tested_at)
             VALUES ('repair-evidence','sha256:a09b3d1eec3f8d97709b8253a4f3e380e70b8cd23af341b4d0bf2e8b91bd7a74','artifact.hash@1','sha256:3333333333333333333333333333333333333333333333333333333333333333',
                     'repair-suite','sha256:4444444444444444444444444444444444444444444444444444444444444444','pass',
                     '{\"schema_version\":\"0.1\",\"result_id\":\"repair-evidence\",\"provider_id\":\"provider.repair\",\"provider_version\":\"1.0.0\",\"provider_build_identity\":{\"kind\":\"build_hash\",\"value\":\"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"},\"semantic_capability_ref\":\"artifact.hash@1\",\"semantic_contract_version\":\"1.0\",\"semantic_contract_hash\":\"sha256:3333333333333333333333333333333333333333333333333333333333333333\",\"conformance_suite\":{\"id\":\"repair-suite\",\"version\":\"0.1\",\"hash\":\"sha256:4444444444444444444444444444444444444444444444444444444444444444\"},\"harness\":{\"id\":\"harness:repair\",\"version\":\"0.1\"},\"result\":\"pass\",\"tests_total\":1,\"tests_passed\":1,\"tests_failed\":0,\"executed_at\":\"2026-09-19T00:00:00Z\",\"expires_at\":\"2026-09-20T00:00:00Z\"}',
                     '2026-09-19T00:00:00Z');
             INSERT INTO execution_bindings
             (binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,
              ir_version,node_id,capability,capability_contract_hash,provider_registration_id,
              provider_id,provider_version,provider_manifest_hash,provider_build_hash,
              attempt,policy_decision_refs_json,grant_refs_json,
              execution_profile_ref,placement_json,binding_json,created_at)
             VALUES ('repair-binding','repair-attempt','T-semantic-repair','sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
                     'repair-snapshot','0.1','repair-node','artifact.hash@1','sha256:3333333333333333333333333333333333333333333333333333333333333333',
                     'sha256:a09b3d1eec3f8d97709b8253a4f3e380e70b8cd23af341b4d0bf2e8b91bd7a74','provider.repair','1.0.0','sha256:6024c42cbfc4fce1192605eaf452bc37f61e2e03a44fdc8047f864ea4f925777','sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
                     1,'[]','[]','repair-profile','{\"locality\":\"local\"}',
                      '{\"schema_version\":\"0.1\",\"binding_id\":\"repair-binding\",\"attempt_id\":\"repair-attempt\",\"task_id\":\"T-semantic-repair\",\"semantic_program_hash\":\"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\",\"registry_snapshot_id\":\"repair-snapshot\",\"ir_version\":\"0.1\",\"node_id\":\"repair-node\",\"capability\":\"artifact.hash@1\",\"capability_contract_hash\":\"sha256:3333333333333333333333333333333333333333333333333333333333333333\",\"conformance_evidence_id\":\"repair-evidence\",\"provider_trust_source_id\":\"sha256:a09b3d1eec3f8d97709b8253a4f3e380e70b8cd23af341b4d0bf2e8b91bd7a74\",\"provider\":{\"id\":\"provider.repair\",\"version\":\"1.0.0\",\"manifest_hash\":\"sha256:6024c42cbfc4fce1192605eaf452bc37f61e2e03a44fdc8047f864ea4f925777\",\"package_or_build_hash\":\"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"},\"attempt\":1,\"policy_decision_refs\":[],\"authority\":{\"grant_refs\":[]},\"execution_profile\":{\"profile_ref\":\"repair-profile\"},\"placement\":{\"locality\":\"local\"},\"inputs\":{},\"outputs\":{},\"created_at\":\"2026-09-19T00:00:00Z\"}',
                     '2026-09-19T00:00:00Z');",
        ).unwrap();
        let stamp: (String, String) = manager
            .connection
            .query_row(
                "SELECT checksum,applied_at FROM schema_migrations
             WHERE migration_id='0012_semantic_registry_store'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(manager.connection.query_row(
            "SELECT COUNT(*) FROM execution_binding_trust_markers WHERE binding_id='repair-binding'",
            [], |row| row.get::<_, i64>(0),
        ).unwrap(),1);
        manager
            .connection
            .execute_batch(
                "DROP TRIGGER one_way_registry_snapshot_admissions_update;
             UPDATE registry_snapshot_admissions SET state='QUARANTINED'
             WHERE snapshot_id='repair-snapshot';
             UPDATE registry_snapshot_admissions SET state='ADMITTED'
             WHERE snapshot_id='repair-snapshot';",
            )
            .unwrap();
        drop(manager);
        let reopened = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        assert_eq!(reopened.connection.query_row(
            "SELECT state FROM registry_snapshot_admissions WHERE snapshot_id='repair-snapshot'",
            [], |row| row.get::<_, String>(0),
        ).unwrap(),"ADMITTED");
        assert_eq!(
            reopened
                .connection
                .query_row(
                    "SELECT MAX(generation) FROM semantic_repair_fences",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(reopened.connection.query_row(
            "SELECT COUNT(*) FROM semantic_current_usable_snapshots WHERE snapshot_id='repair-snapshot'",
            [], |row| row.get::<_, i64>(0),
        ).unwrap(),0);
        assert_eq!(
            reopened
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM execution_binding_legacy_trust_quarantine
             WHERE binding_id='repair-binding'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            reopened
                .connection
                .query_row(
                    "SELECT checksum,applied_at FROM schema_migrations
             WHERE migration_id='0012_semantic_registry_store'",
                    [],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .unwrap(),
            stamp
        );
        drop(reopened);
        let again = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        assert_eq!(again.connection.query_row(
            "SELECT state FROM registry_snapshot_admissions WHERE snapshot_id='repair-snapshot'",
            [], |row| row.get::<_, String>(0),
        ).unwrap(),"ADMITTED");
        assert_eq!(
            again
                .connection
                .query_row(
                    "SELECT MAX(generation) FROM semantic_repair_fences",
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
        reason = "checks clean legacy bootstrap and distinct partial-stamp fence defects together"
    )]
    fn intact_0012_bootstraps_zero_fence_and_partial_0014_fails_closed() {
        for mutation in [
            "clean-legacy",
            "unstamped-partial",
            "stamped-missing",
            "stamped-noop",
            "stamped-history-missing",
        ] {
            let directory = tempdir().unwrap();
            let path = directory.path().join("semantic-fence-migration.sqlite3");
            let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
            manager.initialize_registry_store().unwrap();
            let mut expected_default = None;
            if mutation == "clean-legacy" {
                use aios_contracts::{CapabilityContract, RegistrySnapshot, TypeContract};
                use aios_registry::{RegistryBuildOptions, SemanticRegistry};

                let registry = SemanticRegistry::from_records(
                    serde_json::from_str::<RegistrySnapshot>(include_str!(
                        "../../../examples/aios-ir/registry-snapshot.json"
                    ))
                    .unwrap(),
                    serde_json::from_str::<Vec<TypeContract>>(include_str!(
                        "../../../examples/aios-ir/type-contracts.json"
                    ))
                    .unwrap(),
                    serde_json::from_str::<Vec<CapabilityContract>>(include_str!(
                        "../../../examples/aios-ir/capability-contracts.json"
                    ))
                    .unwrap(),
                    RegistryBuildOptions::default(),
                )
                .unwrap();
                let mut store = manager.registry_store_writer().unwrap();
                store.admit_registry(&registry).unwrap();
                let first = store
                    .activate_default("device", "legacy", None, registry.snapshot_id())
                    .unwrap();
                let second = store
                    .activate_default(
                        "device",
                        "legacy",
                        Some(first.revision),
                        registry.snapshot_id(),
                    )
                    .unwrap();
                assert_eq!(second.revision, 2);
                expected_default = Some((registry.snapshot_id().to_owned(), second.revision));
            }
            match mutation {
                "clean-legacy" | "unstamped-partial" => {
                    remove_fixture_fence_schema(&manager.connection);
                    if mutation == "unstamped-partial" {
                        manager.connection.execute_batch(
                            "CREATE TABLE semantic_repair_fences(generation INTEGER PRIMARY KEY)",
                        ).unwrap();
                    }
                }
                "stamped-missing" => {
                    manager
                        .connection
                        .execute_batch("DROP TRIGGER semantic_terminal_admission_transition")
                        .unwrap();
                }
                "stamped-noop" => {
                    manager.connection.execute_batch(
                        "DROP TRIGGER semantic_terminal_admission_transition;
                         CREATE TRIGGER semantic_terminal_admission_transition
                         AFTER UPDATE OF state ON registry_snapshot_admissions BEGIN SELECT 1; END;",
                    ).unwrap();
                }
                "stamped-history-missing" => {
                    manager
                        .connection
                        .execute_batch("DROP TRIGGER semantic_activation_scope_history_no_delete")
                        .unwrap();
                }
                _ => unreachable!(),
            }
            drop(manager);
            if mutation == "clean-legacy" {
                let mut reopened =
                    TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
                let default = reopened
                    .registry_store_writer()
                    .unwrap()
                    .default_snapshot("device", "legacy")
                    .unwrap()
                    .unwrap();
                let (snapshot_id, revision) = expected_default.unwrap();
                assert_eq!(default.snapshot_id, snapshot_id);
                assert_eq!(default.revision, revision);
                assert_eq!(
                    reopened
                        .connection
                        .query_row(
                            "SELECT MAX(generation) FROM semantic_repair_fences",
                            [],
                            |row| row.get::<_, i64>(0),
                        )
                        .unwrap(),
                    0
                );
                assert_eq!(
                    reopened
                        .connection
                        .query_row(
                            "SELECT COUNT(*) FROM semantic_activation_scope_history
                     WHERE scope_kind='device' AND scope_id='legacy'",
                            [],
                            |row| row.get::<_, i64>(0),
                        )
                        .unwrap(),
                    1
                );
                assert_eq!(
                    reopened
                        .connection
                        .query_row(
                            "SELECT COUNT(*) FROM semantic_invalidated_activation_scopes",
                            [],
                            |row| row.get::<_, i64>(0),
                        )
                        .unwrap(),
                    0
                );
                assert_eq!(
                    reopened
                        .connection
                        .query_row(
                            "SELECT COUNT(*) FROM semantic_legacy_activation_quarantine",
                            [],
                            |row| row.get::<_, i64>(0),
                        )
                        .unwrap(),
                    0
                );
                assert_eq!(
                    reopened
                        .connection
                        .query_row(
                            "SELECT COUNT(*) FROM semantic_legacy_unprovable_admissions",
                            [],
                            |row| row.get::<_, i64>(0),
                        )
                        .unwrap(),
                    0
                );
            } else {
                assert!(
                    TaskManager::open_with_clock(&path, Box::new(FixedClock)).is_err(),
                    "{mutation}"
                );
                let raw = Connection::open(&path).unwrap();
                let stamped: i64 = raw.query_row(
                    "SELECT COUNT(*) FROM schema_migrations WHERE migration_id='0014_semantic_repair_fence'",
                    [], |row| row.get(0),
                ).unwrap();
                assert_eq!(
                    stamped,
                    i64::from(mutation != "unstamped-partial"),
                    "{mutation}"
                );
            }
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        clippy::drop_non_drop,
        reason = "exercises strict re-attestation, ownership, repeated repairs, terminal history and legacy ambiguity in one file-backed chronology"
    )]
    fn semantic_repair_requires_explicit_strict_reattestation_and_rotates_again() {
        use aios_contracts::{CapabilityContract, RegistrySnapshot, TypeContract};
        use aios_registry::{RegistryBuildOptions, SemanticRegistry};

        let directory = tempdir().unwrap();
        let path = directory.path().join("semantic-reattest.sqlite3");
        let registry = SemanticRegistry::from_records(
            serde_json::from_str::<RegistrySnapshot>(include_str!(
                "../../../examples/aios-ir/registry-snapshot.json"
            ))
            .unwrap(),
            serde_json::from_str::<Vec<TypeContract>>(include_str!(
                "../../../examples/aios-ir/type-contracts.json"
            ))
            .unwrap(),
            serde_json::from_str::<Vec<CapabilityContract>>(include_str!(
                "../../../examples/aios-ir/capability-contracts.json"
            ))
            .unwrap(),
            RegistryBuildOptions::default(),
        )
        .unwrap();
        let snapshot_id = registry.snapshot_id().to_owned();
        let mut fresh_snapshot = registry.snapshot().clone();
        let fresh_types = registry.type_contracts().cloned().collect::<Vec<_>>();
        let mut fresh_capabilities = registry.capability_contracts().cloned().collect::<Vec<_>>();
        let changed = fresh_capabilities
            .iter_mut()
            .find(|contract| contract.capability == "artifact.hash")
            .unwrap();
        changed.version = "1.1".to_owned();
        let changed_hash = aios_registry::capability_contract_hash(changed)
            .unwrap()
            .to_string();
        let changed_ref = fresh_snapshot
            .capability_contracts
            .iter_mut()
            .find(|entry| entry.id == "artifact.hash")
            .unwrap();
        changed_ref.version = "1.1".to_owned();
        changed_ref.content_hash = changed_hash;
        let as_hash = |entry: &aios_contracts::ContractRef| aios_registry::SnapshotHashEntry {
            id: entry.id.clone(),
            version: entry.version.clone(),
            content_hash: entry.content_hash.clone(),
        };
        fresh_snapshot.snapshot_id = aios_registry::registry_snapshot_id(
            &fresh_snapshot.schema_version,
            &fresh_snapshot
                .type_contracts
                .iter()
                .map(as_hash)
                .collect::<Vec<_>>(),
            &fresh_snapshot
                .capability_contracts
                .iter()
                .map(as_hash)
                .collect::<Vec<_>>(),
        )
        .unwrap()
        .to_string();
        let fresh_registry = SemanticRegistry::from_records(
            fresh_snapshot,
            fresh_types,
            fresh_capabilities,
            RegistryBuildOptions::default(),
        )
        .unwrap();
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        let mut store = manager.registry_store_writer().unwrap();
        store.admit_registry(&registry).unwrap();
        store
            .activate_default("device", "local", None, &snapshot_id)
            .unwrap();
        store
            .activate_default("device", "deleted", None, &snapshot_id)
            .unwrap();
        store
            .activate_default("device", "renamed", None, &snapshot_id)
            .unwrap();
        for revision in 1..7 {
            store
                .activate_default("device", "local", Some(revision), &snapshot_id)
                .unwrap();
        }
        drop(store);
        manager
            .connection
            .execute_batch(
                "DROP TRIGGER one_way_registry_snapshot_admissions_update;
             DROP TRIGGER registry_activation_revision_monotonic;
             DROP TRIGGER registry_activation_no_delete;
             UPDATE registry_activations SET revision=1
             WHERE scope_kind='device' AND scope_id='local';
             DELETE FROM registry_activations
             WHERE scope_kind='device' AND scope_id='deleted';
             UPDATE registry_activations SET scope_id='renamed-new',revision=2
             WHERE scope_kind='device' AND scope_id='renamed'",
            )
            .unwrap();
        drop(manager);

        let mut reopened = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        let mut store = reopened.registry_store_writer().unwrap();
        assert!(store.default_snapshot("device", "local").unwrap().is_none());
        assert!(
            store
                .reattest_snapshot(&snapshot_id, "", "local-authority")
                .is_err()
        );
        let side = Connection::open(&path).unwrap();
        side.execute_batch(
            "UPDATE task_manager_lease SET owner_id='stale-owner',fence_epoch=fence_epoch+1
             WHERE singleton_id=1",
        )
        .unwrap();
        assert!(
            store
                .reattest_snapshot(&snapshot_id, "decision:stale", "local-authority")
                .is_err()
        );
        assert_eq!(
            side.query_row(
                "SELECT COUNT(*) FROM semantic_snapshot_reattestations
             WHERE snapshot_id=?1 AND generation=1",
                [&snapshot_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            0
        );
        drop(store);
        drop(reopened);
        let mut reopened = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        let mut store = reopened.registry_store_writer().unwrap();
        store
            .reattest_snapshot(&snapshot_id, "decision:repair:1", "local-authority")
            .unwrap();
        let fresh_id = store.admit_registry(&fresh_registry).unwrap();
        store
            .activate_default("device", "fresh-import", None, &fresh_id)
            .unwrap();
        store
            .reattest_snapshot(&snapshot_id, "decision:repair:1", "local-authority")
            .unwrap();
        assert!(
            store
                .reattest_snapshot(&snapshot_id, "decision:changed", "local-authority")
                .is_err()
        );
        assert!(store.default_snapshot("device", "local").unwrap().is_none());
        assert!(
            store
                .activate_default("device", "local", Some(1), &snapshot_id)
                .is_err()
        );
        assert!(
            store
                .activate_default("device", "deleted", None, &snapshot_id)
                .is_err()
        );
        assert!(
            store
                .activate_default("device", "renamed", None, &snapshot_id)
                .is_err()
        );
        assert!(
            store
                .activate_default("device", "renamed-new", Some(2), &snapshot_id)
                .is_err()
        );
        store
            .activate_default("device", "fresh", None, &snapshot_id)
            .unwrap();
        assert!(store.default_snapshot("device", "fresh").unwrap().is_some());
        drop(store);
        reopened
            .connection
            .execute_batch("DROP TRIGGER immutable_registry_snapshot_entries_reinsert")
            .unwrap();
        drop(reopened);

        let mut again = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        assert_eq!(
            again
                .connection
                .query_row(
                    "SELECT MAX(generation) FROM semantic_repair_fences",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            2
        );
        let mut store = again.registry_store_writer().unwrap();
        assert!(store.default_snapshot("device", "fresh").unwrap().is_none());
        store
            .reattest_snapshot(&snapshot_id, "decision:repair:2", "local-authority")
            .unwrap();
        store
            .activate_default("device", "fresh-2", None, &snapshot_id)
            .unwrap();
        assert!(
            store
                .default_snapshot("device", "fresh-2")
                .unwrap()
                .is_some()
        );
        store
            .set_snapshot_state(&snapshot_id, aios_registry::SnapshotState::Quarantined)
            .unwrap();
        assert!(
            store
                .reattest_snapshot(&snapshot_id, "decision:repair:3", "local-authority")
                .is_err()
        );
        assert!(
            store
                .default_snapshot("device", "fresh-2")
                .unwrap()
                .is_none()
        );
        drop(store);
        assert_eq!(
            again
                .connection
                .query_row(
                    "SELECT terminal_state FROM semantic_terminal_admissions WHERE snapshot_id=?1",
                    [&snapshot_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "QUARANTINED"
        );
        again
            .connection
            .execute_batch("DROP TRIGGER one_way_registry_snapshot_admissions_update")
            .unwrap();
        again
            .connection
            .execute(
                "UPDATE registry_snapshot_admissions SET state='ADMITTED' WHERE snapshot_id=?1",
                [&snapshot_id],
            )
            .unwrap();
        drop(again);
        let mut terminal_reopen =
            TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        let mut store = terminal_reopen.registry_store_writer().unwrap();
        assert!(
            store
                .reattest_snapshot(&snapshot_id, "decision:forged", "local-authority")
                .is_err()
        );
        assert!(
            store
                .default_snapshot("device", "fresh-2")
                .unwrap()
                .is_none()
        );
        drop(store);

        // An old 0012 database with no 0014 terminal ledger cannot prove
        // whether a formerly terminal admission was forged back to ADMITTED.
        let legacy_path = directory.path().join("legacy-ambiguous.sqlite3");
        let mut legacy = TaskManager::open_with_clock(&legacy_path, Box::new(FixedClock)).unwrap();
        let mut writer = legacy.registry_store_writer().unwrap();
        writer.admit_registry(&registry).unwrap();
        writer
            .set_snapshot_state(&snapshot_id, aios_registry::SnapshotState::Quarantined)
            .unwrap();
        drop(writer);
        remove_fixture_fence_schema(&legacy.connection);
        legacy
            .connection
            .execute_batch("DROP TRIGGER one_way_registry_snapshot_admissions_update")
            .unwrap();
        legacy
            .connection
            .execute(
                "UPDATE registry_snapshot_admissions SET state='ADMITTED' WHERE snapshot_id=?1",
                [&snapshot_id],
            )
            .unwrap();
        drop(legacy);
        let mut legacy_reopen =
            TaskManager::open_with_clock(&legacy_path, Box::new(FixedClock)).unwrap();
        assert_eq!(legacy_reopen.connection.query_row(
            "SELECT COUNT(*) FROM semantic_legacy_unprovable_admissions WHERE snapshot_id=?1",
            [&snapshot_id], |row| row.get::<_, i64>(0),
        ).unwrap(),1);
        assert!(
            legacy_reopen
                .registry_store_writer()
                .unwrap()
                .reattest_snapshot(&snapshot_id, "decision:legacy", "local-authority")
                .is_err()
        );

        // If an activation identity disappeared before the first 0014
        // bootstrap, no local ledger can enumerate it. Even a strictly
        // re-attested snapshot cannot issue a new activation in that store.
        let lost_scope_path = directory.path().join("legacy-lost-activation.sqlite3");
        let mut lost =
            TaskManager::open_with_clock(&lost_scope_path, Box::new(FixedClock)).unwrap();
        let mut writer = lost.registry_store_writer().unwrap();
        writer.admit_registry(&registry).unwrap();
        writer
            .activate_default("device", "lost", None, &snapshot_id)
            .unwrap();
        drop(writer);
        remove_fixture_fence_schema(&lost.connection);
        lost.connection
            .execute_batch(
                "DROP TRIGGER registry_activation_no_delete;
             DELETE FROM registry_activations WHERE scope_kind='device' AND scope_id='lost'",
            )
            .unwrap();
        drop(lost);
        let mut recovered =
            TaskManager::open_with_clock(&lost_scope_path, Box::new(FixedClock)).unwrap();
        assert_eq!(
            recovered
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM semantic_legacy_activation_quarantine",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        let mut writer = recovered.registry_store_writer().unwrap();
        writer
            .reattest_snapshot(&snapshot_id, "decision:lost-scope", "local-authority")
            .unwrap();
        assert!(
            writer
                .activate_default("device", "lost", None, &snapshot_id)
                .is_err()
        );
        assert!(
            writer
                .activate_default("device", "new", None, &snapshot_id)
                .is_err()
        );
    }

    #[allow(
        clippy::too_many_lines,
        reason = "exercises the full file-backed historical schema upgrade and audit preservation"
    )]
    #[allow(
        clippy::fn_params_excessive_bools,
        reason = "each flag selects an independent historical fixture defect"
    )]
    fn assert_file_backed_reopen_quarantines_legacy_bindings(
        missing_prior_guards: bool,
        existing_quarantine_table: bool,
        future_legacy_clock: bool,
        partial_binding_guard_only: bool,
        partial_clock_guard: bool,
    ) {
        let directory = tempdir().unwrap();
        let path = directory.path().join("old-trust-guard.sqlite3");
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        manager.initialize_provider_store().unwrap();
        manager.create_task(&create("T-old-trust-guard")).unwrap();
        let stamp: (String, String) = manager.connection.query_row(
            "SELECT checksum,applied_at FROM schema_migrations WHERE migration_id='0013_provider_registry'",
            [], |row| Ok((row.get(0)?,row.get(1)?)),
        ).unwrap();
        manager
            .connection
            .execute_batch(
                "DROP TRIGGER execution_binding_trust_marker_insert;
             DROP TRIGGER execution_binding_trust_not_future;",
            )
            .unwrap();
        manager
            .connection
            .execute_batch(include_str!("legacy_5eb3b71_provider_trust_guards.sql"))
            .unwrap();
        manager
            .connection
            .execute_batch(
                "DROP TRIGGER provider_registration_state_transition_clock;
             DROP TRIGGER provider_registration_updated_at_requires_transition;
             DROP TRIGGER execution_binding_provider_enablement_not_future;
              DROP TRIGGER execution_binding_evidence_latest_at_insert;
              DROP TRIGGER execution_binding_evidence_present_at_insert;
              DROP TRIGGER execution_binding_provider_identity_at_insert;",
            )
            .unwrap();
        if !existing_quarantine_table {
            manager
                .connection
                .execute_batch(
                    "DROP TRIGGER execution_binding_legacy_trust_quarantine_no_update;
                     DROP TRIGGER execution_binding_legacy_trust_quarantine_no_delete;
                     DROP TRIGGER execution_binding_legacy_trust_quarantine_no_duplicate_insert;
                     DROP TABLE execution_binding_legacy_trust_quarantine;",
                )
                .unwrap();
        }
        manager.connection.execute_batch(
            "INSERT INTO registry_snapshots(snapshot_id,manifest_json,created_at)
             VALUES ('legacy-snapshot','{}','2026-09-19T00:00:00Z');
              INSERT INTO registry_snapshot_admissions(snapshot_id,state)
              VALUES ('legacy-snapshot','ADMITTED');
             INSERT INTO provider_registrations
             (registration_id,provider_id,provider_version,manifest_hash,package_content_hash,
              registry_snapshot_id,state,trust_status,registration_json,registered_at)
             VALUES ('legacy-provider','legacy-provider','1.0.0','legacy-manifest','legacy-build',
                     'legacy-snapshot','disabled','locally-trusted',
                     '{\"trust\":{\"status\":\"locally-trusted\"}}','2026-09-19T00:00:00Z');
             UPDATE provider_registrations
             SET state='registered',updated_at='2026-09-18T00:00:00Z'
             WHERE registration_id='legacy-provider';
             INSERT INTO provider_conformance_evidence
             (evidence_id,registration_id,capability,contract_hash,status,evidence_json,tested_at)
             VALUES ('legacy-evidence','legacy-provider','artifact.hash@1','legacy-contract',
                     'pass','{}','2026-09-19T00:00:00Z');
             INSERT INTO execution_bindings
             (binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,
              ir_version,node_id,capability,capability_contract_hash,provider_registration_id,
              provider_id,provider_version,provider_manifest_hash,provider_build_hash,
              attempt,policy_decision_refs_json,grant_refs_json,
              execution_profile_ref,placement_json,binding_json,created_at)
             VALUES ('legacy-binding','legacy-attempt','T-old-trust-guard','legacy-program',
                     'legacy-snapshot','0.1','legacy-node','artifact.hash@1','legacy-contract',
                     'legacy-provider','legacy-provider','1.0.0','legacy-manifest','legacy-build',
                     1,'[]','[]','legacy-profile','{}',
                     '{\"conformance_evidence_id\":\"legacy-evidence\",\"provider_trust_source_id\":\"legacy-provider\",\"provider\":{\"id\":\"legacy-provider\",\"version\":\"1.0.0\",\"manifest_hash\":\"legacy-manifest\",\"package_or_build_hash\":\"legacy-build\"}}',
                     '2026-09-19T00:00:00Z');",
        ).unwrap();
        assert!(preflight_migration_state(&manager.connection).is_err());
        let old_marker: String = manager.connection.query_row(
            "SELECT trust_source_id FROM execution_binding_trust_markers WHERE binding_id='legacy-binding'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(old_marker, "legacy-provider");
        if future_legacy_clock {
            manager
                .connection
                .execute(
                    "UPDATE provider_registrations SET updated_at='2026-09-20T00:00:00Z'
                 WHERE registration_id='legacy-provider'",
                    [],
                )
                .unwrap();
        }
        if missing_prior_guards {
            manager
                .connection
                .execute_batch(
                    "DROP TRIGGER execution_binding_trust_marker_insert;
                     DROP TRIGGER execution_binding_trust_not_future;",
                )
                .unwrap();
        }
        if partial_binding_guard_only || partial_clock_guard {
            manager
                .connection
                .execute_batch(
                    "DROP TRIGGER IF EXISTS execution_binding_trust_marker_insert;
                 DROP TRIGGER IF EXISTS execution_binding_trust_not_future;",
                )
                .unwrap();
            manager
                .connection
                .execute_batch(include_str!(
                    "../../../specs/persistence-v0.1-0013-provider-registry.sql"
                ))
                .unwrap();
            manager
                .connection
                .execute_batch(if partial_binding_guard_only {
                    "DROP TRIGGER execution_binding_provider_enablement_not_future;"
                } else {
                    "DROP TRIGGER provider_registration_updated_at_requires_transition;"
                })
                .unwrap();
        }
        drop(manager);

        if partial_binding_guard_only {
            let reopened = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
            assert!(preflight_migration_state(&reopened.connection).is_ok());
            assert_eq!(
                reopened
                    .connection
                    .query_row(
                        "SELECT COUNT(*) FROM execution_binding_legacy_trust_quarantine
                 WHERE binding_id='legacy-binding'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                1
            );
            assert_eq!(
                reopened
                    .connection
                    .query_row(
                        "SELECT state FROM provider_registrations
                 WHERE registration_id='legacy-provider'",
                        [],
                        |row| row.get::<_, String>(0),
                    )
                    .unwrap(),
                "registered"
            );
            return;
        }
        let reopen_error = match TaskManager::open_with_clock(&path, Box::new(FixedClock)) {
            Ok(_) => panic!("unprovable legacy provider history reopened"),
            Err(error) => error,
        };
        assert!(
            matches!(
                &reopen_error,
                TaskManagerError::InvalidRecord(
                    "provider state history requires operator quarantine"
                        | "provider registry migration is incomplete"
                )
            ),
            "{reopen_error}"
        );
        let retained = Connection::open(&path).unwrap();
        assert_eq!(
            retained
                .query_row(
                    "SELECT checksum,applied_at FROM schema_migrations
             WHERE migration_id='0013_provider_registry'",
                    [],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .unwrap(),
            stamp
        );
        let preserved_marker: String = retained
            .query_row(
                "SELECT trust_source_id FROM execution_binding_trust_markers
             WHERE binding_id='legacy-binding'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(preserved_marker, old_marker);
        assert_eq!(retained.query_row(
            "SELECT state FROM provider_registrations WHERE registration_id='legacy-provider'",
            [], |row| row.get::<_, String>(0),
        ).unwrap(), "registered");
    }

    #[test]
    fn file_backed_reopen_replaces_only_exact_5eb3b71_trust_guards() {
        assert_file_backed_reopen_quarantines_legacy_bindings(false, false, false, false, false);
    }

    #[test]
    fn file_backed_reopen_quarantines_old_markers_with_both_guards_missing() {
        assert_file_backed_reopen_quarantines_legacy_bindings(true, false, false, false, false);
    }

    #[test]
    fn file_backed_reopen_quarantines_old_markers_with_existing_table() {
        assert_file_backed_reopen_quarantines_legacy_bindings(false, true, false, false, false);
    }

    #[test]
    fn file_backed_reopen_quarantines_only_missing_binding_guard() {
        assert_file_backed_reopen_quarantines_legacy_bindings(false, true, false, true, false);
    }

    #[test]
    fn file_backed_reopen_disables_future_dated_legacy_enablement() {
        assert_file_backed_reopen_quarantines_legacy_bindings(false, true, true, false, false);
    }

    #[test]
    fn file_backed_reopen_disables_future_legacy_row_with_partial_clock_guard() {
        assert_file_backed_reopen_quarantines_legacy_bindings(false, true, true, false, true);
    }

    #[test]
    fn same_name_trust_guard_noop_rejects_reopen_before_lease_claim() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("forged-trust-guard.sqlite3");
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        manager.initialize_provider_store().unwrap();
        let old_epoch: i64 = manager
            .connection
            .query_row(
                "SELECT fence_epoch FROM task_manager_lease WHERE singleton_id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        manager
            .connection
            .execute_batch(
                "DROP TRIGGER execution_binding_trust_marker_insert;
             CREATE TRIGGER execution_binding_trust_marker_insert
             BEFORE INSERT ON execution_bindings BEGIN SELECT 1; END;",
            )
            .unwrap();
        let forged: String = manager.connection.query_row(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name='execution_binding_trust_marker_insert'",
            [], |row| row.get(0),
        ).unwrap();
        drop(manager);

        assert!(TaskManager::open_with_clock(&path, Box::new(FixedClock)).is_err());
        let connection = Connection::open(&path).unwrap();
        let epoch: i64 = connection
            .query_row(
                "SELECT fence_epoch FROM task_manager_lease WHERE singleton_id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let still_forged: String = connection.query_row(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name='execution_binding_trust_marker_insert'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(epoch, old_epoch);
        assert_eq!(still_forged, forged);
    }

    #[test]
    fn stamped_guard_names_do_not_authenticate_noop_definitions() {
        let mut manager = test_manager();
        manager.initialize_provider_store().unwrap();
        for (name, table) in [
            (
                "immutable_admitted_registry_snapshot_entries_insert",
                "registry_snapshot_entries",
            ),
            (
                "immutable_registry_snapshot_entries_update",
                "registry_snapshot_entries",
            ),
            (
                "provider_evidence_no_duplicate_insert",
                "provider_conformance_evidence",
            ),
            (
                "provider_evidence_immutable_update",
                "provider_conformance_evidence",
            ),
            (
                "execution_binding_marker_no_duplicate_insert",
                "execution_binding_admission_markers",
            ),
            ("execution_bindings_no_update", "execution_bindings"),
        ] {
            manager.connection.execute_batch(&format!(
                "DROP TRIGGER {name}; CREATE TRIGGER {name} BEFORE INSERT ON {table} BEGIN SELECT 1; END;"
            )).unwrap();
            assert!(
                preflight_migration_state_allowing_guard_upgrade(&manager.connection).is_err(),
                "{name}"
            );
            assert!(
                preflight_migration_state(&manager.connection).is_err(),
                "{name}"
            );
            manager
                .connection
                .execute_batch(&format!("DROP TRIGGER {name}"))
                .unwrap();
            if name == "execution_bindings_no_update" {
                manager
                    .connection
                    .execute_batch(include_str!("../../../specs/persistence-v0.1.sql"))
                    .unwrap();
            } else if name == "immutable_admitted_registry_snapshot_entries_insert"
                || name == "immutable_registry_snapshot_entries_update"
            {
                manager
                    .connection
                    .execute_batch(include_str!(
                        "../../../specs/persistence-v0.1-0012-semantic-registry.sql"
                    ))
                    .unwrap();
            } else {
                manager
                    .connection
                    .execute_batch(include_str!(
                        "../../../specs/persistence-v0.1-0013-provider-registry.sql"
                    ))
                    .unwrap();
            }
        }
        assert!(preflight_migration_state(&manager.connection).is_ok());
    }

    #[test]
    fn unstamped_binding_marker_objects_are_not_silently_adopted() {
        let manager = test_manager();
        manager
            .connection
            .execute_batch(
                "CREATE TABLE execution_binding_admission_markers (
                binding_id TEXT PRIMARY KEY, conformance_evidence_id TEXT NOT NULL
            );",
            )
            .unwrap();
        assert!(preflight_migration_state_allowing_guard_upgrade(&manager.connection).is_err());
        manager
            .connection
            .execute_batch("DROP TABLE execution_binding_admission_markers")
            .unwrap();
        manager
            .connection
            .execute_batch(
                "CREATE TRIGGER execution_binding_admission_marker_insert
             BEFORE INSERT ON execution_bindings BEGIN SELECT 1; END;",
            )
            .unwrap();
        assert!(preflight_migration_state_allowing_guard_upgrade(&manager.connection).is_err());
    }

    #[test]
    fn failed_open_does_not_upgrade_guards_before_claiming_lease() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("untrusted-old-guards.sqlite3");
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        manager.initialize_provider_store().unwrap();
        let old_epoch: i64 = manager
            .connection
            .query_row(
                "SELECT fence_epoch FROM task_manager_lease WHERE singleton_id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        manager
            .connection
            .execute_batch(
                "DROP TRIGGER immutable_admitted_registry_snapshot_entries_insert;
             DROP TRIGGER provider_evidence_no_duplicate_insert;
             CREATE TRIGGER provider_evidence_no_duplicate_insert
             BEFORE INSERT ON provider_conformance_evidence BEGIN SELECT 1; END;",
            )
            .unwrap();
        drop(manager);

        assert!(TaskManager::open_with_clock(&path, Box::new(FixedClock)).is_err());
        let connection = Connection::open(&path).unwrap();
        let new_epoch: i64 = connection
            .query_row(
                "SELECT fence_epoch FROM task_manager_lease WHERE singleton_id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(new_epoch, old_epoch);
        assert!(missing_additive_guard(&connection, SEMANTIC_ADDITIVE_GUARDS).unwrap());
        let sql: String = connection.query_row(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name='provider_evidence_no_duplicate_insert'",
            [], |row| row.get(0)
        ).unwrap();
        assert!(sql.contains("SELECT 1"));
    }

    #[test]
    fn fenced_guard_upgrade_installs_both_migrations_after_lease_claim() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("atomic-old-guards.sqlite3");
        let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        manager.initialize_provider_store().unwrap();
        let old_epoch: i64 = manager
            .connection
            .query_row(
                "SELECT fence_epoch FROM task_manager_lease WHERE singleton_id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        manager
            .connection
            .execute_batch(
                "DROP TRIGGER immutable_admitted_registry_snapshot_entries_insert;
             DROP TRIGGER execution_binding_evidence_present_at_insert;",
            )
            .unwrap();
        drop(manager);

        let reopened = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        drop(reopened);
        let connection = Connection::open(&path).unwrap();
        let new_epoch: i64 = connection
            .query_row(
                "SELECT fence_epoch FROM task_manager_lease WHERE singleton_id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(new_epoch, old_epoch + 1);
        assert!(!missing_additive_guard(&connection, SEMANTIC_ADDITIVE_GUARDS).unwrap());
        assert!(!missing_additive_guard(&connection, PROVIDER_ADDITIVE_GUARDS).unwrap());
    }

    #[test]
    fn stamped_provenance_rejects_same_name_noop_append_only_triggers() {
        for (name, operation) in [
            ("provenance_events_no_update", "UPDATE"),
            ("provenance_events_no_delete", "DELETE"),
        ] {
            let manager = test_manager();
            assert!(provenance_append_only_triggers_are_current(&manager.connection).unwrap());
            manager
                .connection
                .execute_batch(&format!(
                    "DROP TRIGGER {name}; CREATE TRIGGER {name} BEFORE {operation} ON provenance_events BEGIN SELECT 1; END;"
                ))
                .unwrap();
            assert!(!provenance_append_only_triggers_are_current(&manager.connection).unwrap());
            assert!(matches!(
                preflight_migration_state(&manager.connection),
                Err(TaskManagerError::InvalidRecord(
                    "provenance service-boundary migration is incomplete"
                ))
            ));
        }
    }

    #[test]
    fn unstamped_provenance_refuses_noop_triggers_before_v11_stamp() {
        for (name, operation) in [
            ("provenance_events_no_update", "UPDATE"),
            ("provenance_events_no_delete", "DELETE"),
        ] {
            let directory = tempdir().unwrap();
            let path = directory
                .path()
                .join(format!("unstamped-noop-{operation}.sqlite3"));
            let task_id = "T-unstamped-noop-trigger";
            let original_hash = {
                let mut manager =
                    TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
                manager.create_task(&create(task_id)).unwrap();
                manager
                    .provenance_head(task_id)
                    .unwrap()
                    .unwrap()
                    .event_hash
            };
            let connection = Connection::open(&path).unwrap();
            connection
                .execute_batch(&format!(
                    "DELETE FROM schema_migrations WHERE migration_id='0011_provenance_service_boundary';
                     DROP TRIGGER {name};
                     CREATE TRIGGER {name} BEFORE {operation} ON provenance_events BEGIN SELECT 1; END;"
                ))
                .unwrap();
            drop(connection);

            assert!(matches!(
                TaskManager::open_with_clock(&path, Box::new(FixedClock)),
                Err(TaskManagerError::InvalidRecord(
                    "persistence migration found invalid provenance append-only triggers"
                ))
            ));
            let connection = Connection::open(&path).unwrap();
            assert_eq!(
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM schema_migrations WHERE migration_id='0011_provenance_service_boundary'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                0
            );
            assert!(!provenance_append_only_triggers_are_current(&connection).unwrap());
            connection
                .execute_batch(&format!(
                    "DROP TRIGGER {name};
                     CREATE TRIGGER {name} BEFORE {operation} ON provenance_events
                     BEGIN SELECT RAISE(ABORT, 'provenance_events are append-only'); END;"
                ))
                .unwrap();
            drop(connection);
            let manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
            assert!(manager.verify_provenance(task_id).unwrap());
            assert_eq!(
                manager
                    .provenance_head(task_id)
                    .unwrap()
                    .unwrap()
                    .event_hash,
                original_hash
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "checks hash-valid duplicate identities and atomic rollback on both migration paths"
    )]
    fn stamped_provenance_requires_event_id_single_column_primary_key() {
        let directory = tempdir().unwrap();
        let path = directory
            .path()
            .join("duplicate-provenance-event-ids.sqlite3");
        let first_task = "T-duplicate-event-first";
        let second_task = "T-duplicate-event-second";
        {
            let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
            manager.create_task(&create(first_task)).unwrap();
            manager.create_task(&create(second_task)).unwrap();
        }

        let connection = Connection::open(&path).unwrap();
        let schema: String = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='provenance_events'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let without_primary_key = schema
            .replacen(
                "CREATE TABLE provenance_events",
                "CREATE TABLE provenance_events_without_pk",
                1,
            )
            .replacen(
                "event_id                 TEXT PRIMARY KEY",
                "event_id                 TEXT",
                1,
            );
        assert_ne!(without_primary_key, schema);
        assert!(without_primary_key.contains("event_id                 TEXT,"));
        connection
            .execute_batch(&format!(
                "PRAGMA foreign_keys=OFF;
                 DROP TRIGGER provenance_events_no_update;
                 DROP TRIGGER provenance_events_no_delete;
                 {without_primary_key};
                 INSERT INTO provenance_events_without_pk SELECT * FROM provenance_events;
                 DROP TABLE provenance_events;
                 ALTER TABLE provenance_events_without_pk RENAME TO provenance_events;"
            ))
            .unwrap();
        assert!(!provenance_event_id_is_primary_key(&connection).unwrap());
        assert!(provenance_task_fk_is_current(&connection).unwrap());

        let first_event_id: String = connection
            .query_row(
                "SELECT event_id FROM provenance_events WHERE task_id=?1",
                [first_task],
                |row| row.get(0),
            )
            .unwrap();
        let second_stream = provenance_stream_id(second_task);
        let second_json: String = connection
            .query_row(
                "SELECT event_json FROM provenance_events WHERE task_id=?1",
                [second_task],
                |row| row.get(0),
            )
            .unwrap();
        let mut second_event: Value = serde_json::from_str(&second_json).unwrap();
        second_event["event_id"] = serde_json::json!(first_event_id);
        let second_hash =
            aios_provenance::hash_record(&second_stream, 1, None, &second_event).unwrap();
        connection
            .execute(
                "UPDATE provenance_events SET event_id=?1,event_hash=?2,event_json=?3 WHERE task_id=?4",
                params![first_event_id, second_hash, second_event.to_string(), second_task],
            )
            .unwrap();
        for task_id in [first_task, second_task] {
            let result = aios_provenance::verify_stream(
                &connection,
                &provenance_stream_id(task_id),
                None,
                None,
                T0,
            )
            .unwrap();
            assert!(result.valid, "{task_id}: {result:?}");
        }
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM provenance_events WHERE event_id=?1",
                    [&first_event_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            2
        );
        assert!(matches!(
            preflight_migration_state(&connection),
            Err(TaskManagerError::InvalidRecord(
                "provenance service-boundary migration is incomplete"
            ))
        ));
        drop(connection);
        assert!(matches!(
            TaskManager::open_with_clock(&path, Box::new(FixedClock)),
            Err(TaskManagerError::InvalidRecord(
                "provenance service-boundary migration is incomplete"
            ))
        ));

        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "DELETE FROM schema_migrations WHERE migration_id='0011_provenance_service_boundary'",
                [],
            )
            .unwrap();
        drop(connection);
        assert!(TaskManager::open_with_clock(&path, Box::new(FixedClock)).is_err());
        let connection = Connection::open(&path).unwrap();
        assert!(!provenance_event_id_is_primary_key(&connection).unwrap());
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM provenance_events WHERE event_id=?1",
                    [&first_event_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            2
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM schema_migrations WHERE migration_id='0011_provenance_service_boundary'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn unstamped_provenance_rebuild_restores_event_id_primary_key() {
        let directory = tempdir().unwrap();
        let path = directory
            .path()
            .join("unstamped-provenance-without-pk.sqlite3");
        let task_id = "T-rebuild-provenance-key";
        let original_hash = {
            let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
            manager.create_task(&create(task_id)).unwrap();
            manager
                .provenance_head(task_id)
                .unwrap()
                .unwrap()
                .event_hash
        };
        let connection = Connection::open(&path).unwrap();
        let schema: String = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='provenance_events'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let without_primary_key = schema
            .replacen(
                "CREATE TABLE provenance_events",
                "CREATE TABLE provenance_events_without_pk",
                1,
            )
            .replacen(
                "event_id                 TEXT PRIMARY KEY",
                "event_id                 TEXT",
                1,
            );
        assert!(without_primary_key.contains("event_id                 TEXT,"));
        connection
            .execute_batch(&format!(
                "PRAGMA foreign_keys=OFF;
                 DROP TRIGGER provenance_events_no_update;
                 DROP TRIGGER provenance_events_no_delete;
                 {without_primary_key};
                 INSERT INTO provenance_events_without_pk SELECT * FROM provenance_events;
                 DROP TABLE provenance_events;
                 ALTER TABLE provenance_events_without_pk RENAME TO provenance_events;
                 DELETE FROM schema_migrations WHERE migration_id='0011_provenance_service_boundary';"
            ))
            .unwrap();
        assert!(!provenance_event_id_is_primary_key(&connection).unwrap());
        drop(connection);

        let manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        assert!(provenance_event_id_is_primary_key(&manager.connection).unwrap());
        assert!(manager.verify_provenance(task_id).unwrap());
        assert_eq!(
            manager
                .provenance_head(task_id)
                .unwrap()
                .unwrap()
                .event_hash,
            original_hash
        );
    }

    fn request(
        id: &str,
        task: &str,
        revision: u64,
        from: TaskState,
        to: TaskState,
    ) -> TransitionRequest {
        TransitionRequest {
            schema_version: SCHEMA_VERSION.to_owned(),
            transition_id: id.to_owned(),
            task_id: task.to_owned(),
            expected_revision: revision,
            expected_state: from,
            to_state: to,
            requested_by: Actor {
                kind: "system-service".to_owned(),
                id: "service:task-manager".to_owned(),
            },
            reason: TransitionReason {
                code: "STATE_CHANGE_REQUESTED".to_owned(),
                message: None,
                related_ids: Vec::new(),
            },
            mutation: TaskMutation::default(),
        }
    }

    #[test]
    fn legal_illegal_cas_and_terminal_transitions_fail_closed() {
        let mut manager = test_manager();
        manager.create_task(&create("T-1")).unwrap();
        let illegal = manager
            .transition(&request(
                "tr-illegal",
                "T-1",
                1,
                TaskState::Created,
                TaskState::Completed,
            ))
            .unwrap();
        assert_eq!(illegal.reason_code, "TASK_ILLEGAL_TRANSITION");
        assert_eq!(manager.provenance_count("T-1").unwrap(), 1);
        let applied = manager
            .transition(&request(
                "tr-plan",
                "T-1",
                1,
                TaskState::Created,
                TaskState::Planning,
            ))
            .unwrap();
        assert!(applied.applied);
        assert_eq!(applied.current_revision, Some(2));
        let before_stale = manager.get_task("T-1").unwrap().unwrap();
        let count_before_stale = manager.provenance_count("T-1").unwrap();
        let head_before_stale = manager.provenance_head("T-1").unwrap();
        let stale = manager
            .transition(&request(
                "tr-stale",
                "T-1",
                1,
                TaskState::Created,
                TaskState::Failed,
            ))
            .unwrap();
        assert_eq!(stale.reason_code, "TASK_REVISION_CONFLICT");
        assert!(!stale.applied);
        assert!(stale.provenance_event_id.is_none());
        assert!(stale.provenance_event_hash.is_none());
        let after_stale = manager.get_task("T-1").unwrap().unwrap();
        assert_eq!(after_stale.state, before_stale.state);
        assert_eq!(after_stale.revision, before_stale.revision);
        assert_eq!(manager.provenance_count("T-1").unwrap(), count_before_stale);
        assert_eq!(manager.provenance_head("T-1").unwrap(), head_before_stale);
        assert_eq!(
            manager.connection.query_row(
                "SELECT COUNT(*) FROM provenance_events WHERE json_extract(event_json,'$.task_transition.transition_id')='tr-stale'",
                [],
                |row| row.get::<_, i64>(0),
            ).unwrap(),
            0
        );
        let cancel = manager
            .transition(&request(
                "tr-cancel",
                "T-1",
                2,
                TaskState::Planning,
                TaskState::Cancelled,
            ))
            .unwrap();
        assert!(cancel.applied);
        let reopen = manager
            .transition(&request(
                "tr-reopen",
                "T-1",
                3,
                TaskState::Cancelled,
                TaskState::Planning,
            ))
            .unwrap();
        assert_eq!(reopen.reason_code, "TASK_TERMINAL_STATE");
    }

    #[test]
    fn response_loss_retry_and_transition_id_reuse_are_deterministic() {
        let mut manager = test_manager();
        manager.create_task(&create("T-2")).unwrap();
        let original = request("tr-once", "T-2", 1, TaskState::Created, TaskState::Planning);
        let first = manager.transition(&original).unwrap();
        let retry = manager.transition(&original).unwrap();
        assert_eq!(first, retry);
        assert_eq!(manager.provenance_count("T-2").unwrap(), 2);
        let mut reused = original.clone();
        reused.to_state = TaskState::Failed;
        assert_eq!(
            manager.transition(&reused).unwrap().reason_code,
            "TASK_TRANSITION_ID_REUSE_CONFLICT"
        );
    }

    #[test]
    fn not_found_results_are_idempotent_and_id_reuse_has_paired_null_observations() {
        let mut manager = test_manager();
        let missing = request(
            "tr-missing",
            "T-absent",
            1,
            TaskState::Created,
            TaskState::Planning,
        );
        let first = manager.transition(&missing).unwrap();
        assert_eq!(first.reason_code, "TASK_NOT_FOUND");
        assert_eq!(first.observed_state, None);
        assert_eq!(first, manager.transition(&missing).unwrap());
        let mut reused = missing;
        reused.to_state = TaskState::Failed;
        let conflict = manager.transition(&reused).unwrap();
        assert_eq!(conflict.reason_code, "TASK_TRANSITION_ID_REUSE_CONFLICT");
        assert_eq!(
            (conflict.observed_state, conflict.observed_revision),
            (None, None)
        );
    }

    #[test]
    fn crash_reopen_preserves_task_transition_and_hash_chain() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("task-manager.sqlite3");
        {
            let mut manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
            manager.create_task(&create("T-reopen")).unwrap();
            manager
                .transition(&request(
                    "tr-reopen-persisted",
                    "T-reopen",
                    1,
                    TaskState::Created,
                    TaskState::Planning,
                ))
                .unwrap();
        }
        let manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        let task = manager.get_task("T-reopen").unwrap().unwrap();
        assert_eq!((task.state, task.revision), (TaskState::Planning, 2));
        assert!(manager.verify_provenance("T-reopen").unwrap());
    }

    #[test]
    fn local_store_has_one_fenced_writer() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("revision-race.sqlite3");
        let mut first = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        first.create_task(&create("T-race")).unwrap();
        assert!(TaskManager::open_with_clock(&path, Box::new(FixedClock)).is_err());

        let winner = first
            .transition(&request(
                "tr-race-winner",
                "T-race",
                1,
                TaskState::Created,
                TaskState::Planning,
            ))
            .unwrap();
        assert!(winner.applied);
        assert_eq!(first.provenance_count("T-race").unwrap(), 2);
    }

    #[test]
    fn provenance_failure_rolls_back_task_and_event() {
        let mut manager = test_manager();
        manager.create_task(&create("T-rollback")).unwrap();
        let result = manager
            .transition_with_provenance_failure(&request(
                "tr-fail",
                "T-rollback",
                1,
                TaskState::Created,
                TaskState::Planning,
            ))
            .unwrap();
        assert_eq!(result.reason_code, "TASK_PROVENANCE_APPEND_FAILED");
        let task = manager.get_task("T-rollback").unwrap().unwrap();
        assert_eq!((task.state, task.revision), (TaskState::Created, 1));
        assert_eq!(manager.provenance_count("T-rollback").unwrap(), 1);
    }

    #[test]
    fn waiting_guards_accept_validation_identity_and_rollback_guard_is_structured() {
        let mut manager = test_manager();
        manager.create_task(&create("T-guards")).unwrap();
        manager
            .transition(&request(
                "tr-g1",
                "T-guards",
                1,
                TaskState::Created,
                TaskState::Planning,
            ))
            .unwrap();
        let missing = manager
            .transition(&request(
                "tr-g2",
                "T-guards",
                2,
                TaskState::Planning,
                TaskState::WaitingForInput,
            ))
            .unwrap();
        assert_eq!(missing.reason_code, "TASK_TRANSITION_GUARD_FAILED");
        let mut valid = request(
            "tr-g3",
            "T-guards",
            2,
            TaskState::Planning,
            TaskState::WaitingForInput,
        );
        valid.mutation.waiting_on = Some(vec![WaitingOn {
            kind: WaitingKind::Validation,
            id: "validation:1".to_owned(),
            message: None,
        }]);
        assert!(manager.transition(&valid).unwrap().applied);

        let mut failed = test_manager();
        failed.create_task(&create("T-failed")).unwrap();
        let mut fail = request(
            "tr-failed",
            "T-failed",
            1,
            TaskState::Created,
            TaskState::Failed,
        );
        fail.mutation.failure = Some(FailureRecord {
            code: "TEST_FAILURE".to_owned(),
            summary: "failed".to_owned(),
            step_id: None,
            provider_id: None,
            execution_binding_id: None,
            retryable: false,
            safe_to_replan: false,
            unknown_side_effects: false,
            rollback_available: false,
            provenance_event_ids: Vec::new(),
        });
        assert!(failed.transition(&fail).unwrap().applied);
        let rollback = failed
            .transition(&request(
                "tr-rollback-denied",
                "T-failed",
                2,
                TaskState::Failed,
                TaskState::RollingBack,
            ))
            .unwrap();
        assert_eq!(rollback.reason_code, "TASK_TRANSITION_GUARD_FAILED");
    }
}

#[cfg(test)]
pub(crate) fn admit_fixture_grant(connection: &Connection, grant_id: &str) -> Result<()> {
    // Unit tests exercise downstream admission with synthetic trusted issuance.
    // This helper is absent from production builds; production issuance belongs
    // to the future private Authority Coordinator writer.
    let token_id = format!("fixture-token:{grant_id}");
    connection.execute(
        "UPDATE authority_grants SET token_id=?2 WHERE grant_id=?1",
        params![grant_id, token_id],
    )?;
    connection.execute(
        "INSERT INTO authority_issuance_receipts(
            grant_id,token_id,task_id,execution_binding_id,attempt_id,
            policy_decision_id,issued_at,issuance_profile)
         SELECT grant_id,token_id,task_id,execution_binding_id,attempt_id,
                policy_decision_id,issued_at,'coordinator-issued-v0.1'
         FROM authority_grants WHERE grant_id=?1",
        [grant_id],
    )?;
    Ok(())
}

#[cfg(test)]
mod adversarial_tests;
