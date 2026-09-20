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

use std::fmt;
use std::fmt::Write as _;
use std::path::Path;

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const SCHEMA_VERSION: &str = "0.1";
const HASH_PROFILE: &str = "aios-provenance-event-v0.1";
const HASH_DOMAIN: &[u8] = b"AIOS-PROVENANCE-EVENT\0v0.1\0";
const MIGRATION: &str = include_str!("../../../specs/persistence-v0.1.sql");

#[derive(Debug)]
pub enum TaskManagerError {
    Storage(rusqlite::Error),
    Serialization(serde_json::Error),
    Canonicalization(String),
    InvalidRecord(&'static str),
}

impl fmt::Display for TaskManagerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(formatter, "task storage failure: {error}"),
            Self::Serialization(error) => write!(formatter, "task serialization failure: {error}"),
            Self::Canonicalization(error) => {
                write!(formatter, "provenance canonicalization failure: {error}")
            }
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

impl From<serde_json::Error> for TaskManagerError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialization(error)
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
pub struct Actor {
    pub kind: String,
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
pub struct WaitingOn {
    pub kind: WaitingKind,
    pub id: String,
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivePlan {
    pub plan_id: String,
    pub revision: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryMutation {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unknown_operation_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unknown_operations_ref: Option<String>,
    pub last_known_daemon_instance: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    pub constraints: Option<Value>,
    pub failure: Option<FailureRecord>,
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
    clock: Box<dyn Clock>,
}

pub trait Clock: Send + Sync {
    fn now(&self) -> String;
}

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> String {
        OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
    }
}

impl TaskManager {
    /// Opens or creates the authoritative local `SQLite` store.
    ///
    /// # Errors
    /// Returns an error when `SQLite` cannot open or initialize the schema.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let connection = Connection::open(path)?;
        Self::initialize(connection, Box::new(SystemClock))
    }

    /// Opens an isolated in-memory store with the production clock.
    ///
    /// # Errors
    /// Returns an error when `SQLite` cannot initialize the schema.
    pub fn open_in_memory() -> Result<Self> {
        Self::initialize(Connection::open_in_memory()?, Box::new(SystemClock))
    }

    /// Opens a store with an injected trusted clock.
    ///
    /// # Errors
    /// Returns an error when `SQLite` cannot open or initialize the schema.
    pub fn open_with_clock(path: impl AsRef<Path>, clock: Box<dyn Clock>) -> Result<Self> {
        Self::initialize(Connection::open(path)?, clock)
    }

    /// Opens an in-memory store with an injected trusted clock.
    ///
    /// # Errors
    /// Returns an error when `SQLite` cannot initialize the schema.
    pub fn open_in_memory_with_clock(clock: Box<dyn Clock>) -> Result<Self> {
        Self::initialize(Connection::open_in_memory()?, clock)
    }

    fn initialize(connection: Connection, clock: Box<dyn Clock>) -> Result<Self> {
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch(MIGRATION)?;
        migrate_task_manager_schema(&connection)?;
        let mut manager = Self { connection, clock };
        manager.recover_startup()?;
        Ok(manager)
    }

    /// Creates a revision-1 Task and genesis event atomically.
    ///
    /// # Errors
    /// Returns an error for an invalid record or failed `SQLite` commit.
    pub(crate) fn create_task(&mut self, request: &CreateTask) -> Result<TaskRecord> {
        let unique_steps = request
            .active_step_ids
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == request.active_step_ids.len();
        if request.task_id.is_empty()
            || request.task_id.len() > 256
            || request.original_intent.is_empty()
            || request.original_intent.chars().count() > 65_536
            || request.principal.id.is_empty()
            || request.principal.id.len() > 256
            || !matches!(request.principal.kind.as_str(), "user" | "system-service")
            || request
                .workspace_id
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 256)
            || request
                .normalized_intent
                .as_ref()
                .is_some_and(|value| !value.is_object())
            || request.active_step_ids.len() > 512
            || !unique_steps
            || request
                .active_step_ids
                .iter()
                .any(|value| value.is_empty() || value.len() > 128)
        {
            return Err(TaskManagerError::InvalidRecord(
                "invalid Task creation record",
            ));
        }
        let created_at = self.clock.now();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO tasks (task_id, revision, state, principal_kind, principal_id, workspace_id, original_intent, normalized_intent_json, active_step_ids_json, waiting_on_json, created_at, updated_at) VALUES (?1, 1, 'CREATED', ?2, ?3, ?4, ?5, ?6, ?7, '[]', ?8, ?8)",
            params![
                request.task_id,
                request.principal.kind,
                request.principal.id,
                request.workspace_id,
                request.original_intent,
                encode_optional(request.normalized_intent.as_ref())?,
                serde_json::to_string(&request.active_step_ids)?,
                created_at,
            ],
        )?;
        let event = json!({
            "schema_version": SCHEMA_VERSION,
            "event_id": format!("event:create:{}", request.task_id),
            "task_id": request.task_id,
            "event_type": "task.created",
            "timestamp": created_at,
            "actor": request.principal,
            "status": "success",
            "details": {"revision": 1}
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
            attempt_number: u16::try_from(attempt_number)
                .map_err(|_| TaskManagerError::InvalidRecord("stored attempt number is invalid"))?,
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
    pub(crate) fn create_step_execution(
        &mut self,
        request: &CreateStepExecution,
    ) -> Result<StepExecutionRecord> {
        let unique_inputs = all_unique(&request.input_artifacts);
        let unique_outputs = all_unique(&request.output_artifacts);
        let valid_failure = request.failure.as_ref().is_none_or(|failure| {
            !failure.code.is_empty()
                && failure.code.len() <= 128
                && !failure.summary.is_empty()
                && failure.summary.chars().count() <= 4096
        });
        if request.attempt_id.is_empty()
            || request.attempt_id.len() > 256
            || request.task_id.is_empty()
            || request.task_id.len() > 256
            || request.node_id.is_empty()
            || request.node_id.len() > 128
            || request.attempt_number == 0
            || request.attempt_number > 100
            || !is_sha256(&request.semantic_program_hash)
            || matches!(request.state, StepState::Starting | StepState::Running)
            || request
                .registry_snapshot_id
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 256)
            || request
                .binding_id
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 256)
            || request
                .provider_id
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 256)
            || request
                .provider_version
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > 128)
            || request
                .operation_id
                .as_ref()
                .is_some_and(|value| value.len() > 512)
            || request
                .idempotency_key
                .as_ref()
                .is_some_and(|value| value.len() > 512)
            || request.input_artifacts.len() > 256
            || request.output_artifacts.len() > 256
            || !unique_inputs
            || !unique_outputs
            || request
                .input_artifacts
                .iter()
                .chain(&request.output_artifacts)
                .any(|value| value.len() > 512)
            || !valid_failure
        {
            return Err(TaskManagerError::InvalidRecord(
                "step execution does not satisfy the v0.1 contract",
            ));
        }
        if let Some(binding_id) = &request.binding_id {
            let exact_binding = self.connection.query_row(
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
        let now = self.clock.now();
        self.connection.execute(
            "INSERT INTO step_executions (attempt_id, task_id, semantic_program_hash, registry_snapshot_id, node_id, binding_id, provider_id, provider_version, attempt_number, revision, state, operation_id, idempotency_key, outcome_certainty, failure_json, input_artifacts_json, output_artifacts_json, started_at, finished_at, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?19)",
            params![request.attempt_id, request.task_id, request.semantic_program_hash, request.registry_snapshot_id, request.node_id, request.binding_id, request.provider_id, request.provider_version, i64::from(request.attempt_number), request.state.as_str(), request.operation_id, request.idempotency_key, request.outcome_certainty.map(OutcomeCertainty::as_str), encode_optional(request.failure.as_ref())?, serde_json::to_string(&request.input_artifacts)?, serde_json::to_string(&request.output_artifacts)?, request.started_at, request.finished_at, now],
        )?;
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
    pub(crate) fn recover_startup(&mut self) -> Result<Vec<TransitionResult>> {
        self.verify_nonterminal_heads()?;
        let candidates = {
            let mut statement = self.connection.prepare(
                "SELECT task_id, revision, state FROM tasks WHERE state IN ('RUNNING', 'VERIFYING') ORDER BY task_id",
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
        for (task_id, revision, state) in candidates {
            let revision = u64::try_from(revision)
                .map_err(|_| TaskManagerError::InvalidRecord("stored revision is invalid"))?;
            let state = TaskState::parse(&state)?;
            let unknown_operation_ids = query_strings(
                &self.connection,
                "SELECT operation_id FROM operations WHERE task_id = ?1 AND outcome_certainty = 'OUTCOME_UNKNOWN' ORDER BY operation_id",
                &task_id,
            )?;
            let recovery_ref = recovery_operations_ref(&task_id, revision, &unknown_operation_ids);
            let assessed_at = self.clock.now();
            self.persist_recovery_inventory(
                &recovery_ref,
                &task_id,
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
            results.push(result);
        }
        Ok(results)
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
        let assessment = self
            .connection
            .query_row(
                "SELECT assessment_json FROM recovery_assessments WHERE assessment_id = ?1 AND subject_kind = 'task-unknown-operations'",
                [recovery_ref],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        assessment
            .map(|value| {
                let value: Value = serde_json::from_str(&value)?;
                serde_json::from_value(value.get("unknown_operation_ids").cloned().ok_or(
                    TaskManagerError::InvalidRecord("recovery inventory has no operation list"),
                )?)
                .map_err(Into::into)
            })
            .transpose()
    }

    fn persist_recovery_inventory(
        &mut self,
        recovery_ref: &str,
        task_id: &str,
        operation_ids: &[String],
        created_at: &str,
    ) -> Result<()> {
        let assessment = canonical_json(&json!({
            "schema_version": SCHEMA_VERSION,
            "recovery_ref": recovery_ref,
            "task_id": task_id,
            "unknown_operation_ids": operation_ids,
        }))?;
        let epoch_id = format!("epoch:{recovery_ref}");
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT OR IGNORE INTO recovery_epochs (recovery_epoch_id, started_at) VALUES (?1, ?2)",
            params![epoch_id, created_at],
        )?;
        transaction.execute(
            "INSERT OR IGNORE INTO recovery_assessments (assessment_id, recovery_epoch_id, task_id, subject_kind, subject_id, certainty, safe_action, reason_codes_json, assessment_json, created_at) VALUES (?1, ?2, ?3, 'task-unknown-operations', ?3, 'OUTCOME_UNKNOWN', 'ENTER_RECOVERING', '[\"TASK_RECOVERY_REQUIRED\"]', ?4, ?5)",
            params![recovery_ref, epoch_id, task_id, assessment, created_at],
        )?;
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
        transaction.commit()?;
        Ok(())
    }

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
            if !self.verify_provenance(&task_id)? {
                return Err(TaskManagerError::InvalidRecord(
                    "nonterminal Task provenance chain is missing or invalid",
                ));
            }
            let mut statement = self.connection.prepare(
                "SELECT event_json FROM provenance_events WHERE task_id = ?1 AND event_type IN ('task.created', 'task.transitioned') ORDER BY sequence",
            )?;
            let rows = statement.query_map([&task_id], |row| row.get::<_, String>(0))?;
            let mut material_revision = 0_i64;
            let mut material_state: Option<TaskState> = None;
            for row in rows {
                let event: Value = serde_json::from_str(&row?)?;
                if event.get("event_type").and_then(Value::as_str) == Some("task.created") {
                    if material_revision != 0
                        || event.pointer("/details/revision").and_then(Value::as_i64) != Some(1)
                    {
                        return Err(TaskManagerError::InvalidRecord(
                            "Task provenance has an invalid creation event",
                        ));
                    }
                    material_revision = 1;
                    material_state = Some(TaskState::Created);
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
            }
            if material_revision != revision
                || material_state.map(TaskState::as_str) != Some(state.as_str())
            {
                return Err(TaskManagerError::InvalidRecord(
                    "nonterminal Task state does not match provenance head",
                ));
            }
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
        let resulted_at = self.clock.now();
        let request_json = canonical_json(request)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((stored_request, stored_result)) = transaction
            .query_row(
                "SELECT request_json, result_json FROM task_transitions WHERE transition_id = ?1",
                [&request.transition_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .optional()?
        {
            if stored_request == request_json {
                let result = stored_result.ok_or(TaskManagerError::InvalidRecord(
                    "stored transition has no result",
                ))?;
                return Ok(serde_json::from_str(&result)?);
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
            let rejection_transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
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
        let event_id = format!("event:transition:{}", request.transition_id);
        let event = json!({
            "schema_version": SCHEMA_VERSION,
            "event_id": event_id,
            "task_id": request.task_id,
            "event_type": "task.transitioned",
            "timestamp": resulted_at,
            "actor": request.requested_by,
            "status": "success",
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
                "waiting_on": request.mutation.waiting_on,
                "failure": request.mutation.failure,
                "recovery": request.mutation.recovery,
            },
            "details": {"related_ids": request.reason.related_ids}
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
                params![request.task_id, i64::try_from(plan.revision).unwrap_or(i64::MAX), plan.plan_id],
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
        let mut statement = self.connection.prepare("SELECT event_id, stream_id, sequence, timestamp, event_type, semantic_program_hash, ir_version, registry_snapshot_id, node_id, execution_binding_id, provider_id, status, previous_event_hash, event_hash, event_json FROM provenance_events WHERE task_id = ?1 ORDER BY sequence")?;
        let rows = statement.query_map([task_id], |row| {
            Ok(ProvenanceRow {
                event_id: row.get(0)?,
                stream_id: row.get(1)?,
                sequence: row.get(2)?,
                timestamp: row.get(3)?,
                event_type: row.get(4)?,
                semantic_program_hash: row.get(5)?,
                ir_version: row.get(6)?,
                registry_snapshot_id: row.get(7)?,
                node_id: row.get(8)?,
                execution_binding_id: row.get(9)?,
                provider_id: row.get(10)?,
                status: row.get(11)?,
                previous_event_hash: row.get(12)?,
                event_hash: row.get(13)?,
                event_json: row.get(14)?,
            })
        })?;
        let mut expected_sequence = 1_i64;
        let mut previous: Option<String> = None;
        for row in rows {
            let row = row?;
            if row.sequence != expected_sequence || row.previous_event_hash != previous {
                return Ok(false);
            }
            let event: Value = serde_json::from_str(&row.event_json)?;
            if !valid_transition_shape(&event)
                || row.event_id != event_string(&event, "event_id").unwrap_or_default()
                || row.stream_id != format!("task:{task_id}")
                || event_string(&event, "task_id") != Some(task_id)
                || row.timestamp != event_string(&event, "timestamp").unwrap_or_default()
                || row.event_type != event_string(&event, "event_type").unwrap_or_default()
                || row.semantic_program_hash.as_deref()
                    != event_string(&event, "semantic_program_hash")
                || row.ir_version.as_deref() != event_string(&event, "ir_version")
                || row.registry_snapshot_id.as_deref()
                    != event_string(&event, "registry_snapshot_id")
                || row.node_id.as_deref() != event_string(&event, "step_id")
                || row.execution_binding_id.as_deref()
                    != event_string(&event, "execution_binding_id")
                || row.provider_id.as_deref() != event_string(&event, "provider_id")
                || row.status.as_deref() != event_string(&event, "status")
            {
                return Ok(false);
            }
            let computed = provenance_hash(
                task_id,
                u64::try_from(row.sequence).unwrap_or(0),
                row.previous_event_hash.as_deref(),
                &event,
            )?;
            if computed != row.event_hash {
                return Ok(false);
            }
            previous = Some(row.event_hash);
            expected_sequence += 1;
        }
        Ok(expected_sequence > 1)
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

struct ProvenanceRow {
    event_id: String,
    stream_id: String,
    sequence: i64,
    timestamp: String,
    event_type: String,
    semantic_program_hash: Option<String>,
    ir_version: Option<String>,
    registry_snapshot_id: Option<String>,
    node_id: Option<String>,
    execution_binding_id: Option<String>,
    provider_id: Option<String>,
    status: Option<String>,
    previous_event_hash: Option<String>,
    event_hash: String,
    event_json: String,
}

fn event_string<'a>(event: &'a Value, key: &str) -> Option<&'a str> {
    event.get(key).and_then(Value::as_str)
}

fn append_event(
    transaction: &Transaction<'_>,
    task_id: &str,
    event: &Value,
) -> Result<AppendedEvent> {
    if !valid_transition_shape(event) {
        return Err(TaskManagerError::InvalidRecord(
            "invalid typed Task transition provenance",
        ));
    }
    let (last_sequence, previous): (i64, Option<String>) = transaction.query_row(
        "SELECT COALESCE(MAX(sequence), 0), (SELECT event_hash FROM provenance_events WHERE task_id = ?1 ORDER BY sequence DESC LIMIT 1) FROM provenance_events WHERE task_id = ?1",
        [task_id], |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let sequence = u64::try_from(last_sequence)
        .map_err(|_| TaskManagerError::InvalidRecord("invalid provenance sequence"))?
        .checked_add(1)
        .ok_or(TaskManagerError::InvalidRecord(
            "provenance sequence overflow",
        ))?;
    let event_hash = provenance_hash(task_id, sequence, previous.as_deref(), event)?;
    let event_id = event
        .get("event_id")
        .and_then(Value::as_str)
        .ok_or(TaskManagerError::InvalidRecord(
            "provenance event has no ID",
        ))?
        .to_owned();
    transaction.execute(
        "INSERT INTO provenance_events (event_id, task_id, stream_id, sequence, timestamp, event_type, semantic_program_hash, ir_version, registry_snapshot_id, node_id, execution_binding_id, provider_id, status, previous_event_hash, event_hash, event_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        params![event_id, task_id, format!("task:{task_id}"), i64::try_from(sequence).map_err(|_| TaskManagerError::InvalidRecord("provenance sequence exceeds SQLite range"))?, event_string(event, "timestamp"), event_string(event, "event_type"), event_string(event, "semantic_program_hash"), event_string(event, "ir_version"), event_string(event, "registry_snapshot_id"), event_string(event, "step_id"), event_string(event, "execution_binding_id"), event_string(event, "provider_id"), event_string(event, "status"), previous, event_hash, serde_json::to_string(event)?],
    )?;
    Ok(AppendedEvent {
        event_id,
        event_hash,
    })
}

fn provenance_hash(
    task_id: &str,
    sequence: u64,
    previous: Option<&str>,
    event: &Value,
) -> Result<String> {
    let view = json!({"schema_version":SCHEMA_VERSION,"hash_profile":HASH_PROFILE,"stream_id":format!("task:{task_id}"),"sequence":sequence,"previous_event_hash":previous,"event":event});
    let canonical = serde_json_canonicalizer::to_vec(&view)
        .map_err(|error| TaskManagerError::Canonicalization(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(HASH_DOMAIN);
    hasher.update(canonical);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        write!(&mut hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(format!("sha256:{hex}"))
}

fn valid_transition_shape(event: &Value) -> bool {
    if event.get("event_type").and_then(Value::as_str) != Some("task.transitioned") {
        return event.get("task_transition").is_none();
    }
    let Some(transition) = event.get("task_transition") else {
        return false;
    };
    let Some(previous) = transition.get("previous_revision").and_then(Value::as_u64) else {
        return false;
    };
    transition.get("new_revision").and_then(Value::as_u64) == previous.checked_add(1)
}

fn canonical_json<T: Serialize>(value: &T) -> Result<String> {
    let value = serde_json::to_value(value)?;
    let bytes = serde_json_canonicalizer::to_vec(&value)
        .map_err(|error| TaskManagerError::Canonicalization(error.to_string()))?;
    String::from_utf8(bytes)
        .map_err(|_| TaskManagerError::InvalidRecord("canonical JSON is not UTF-8"))
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
    let valid_reason = request
        .reason
        .code
        .bytes()
        .enumerate()
        .all(|(index, byte)| {
            if index == 0 {
                byte.is_ascii_uppercase()
            } else {
                byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'
            }
        });
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
        !plan.plan_id.is_empty() && plan.plan_id.len() <= 256 && plan.revision > 0
    });
    let valid_steps = request
        .mutation
        .active_step_ids
        .as_ref()
        .is_none_or(|values| {
            values
                .iter()
                .all(|value| !value.is_empty() && value.len() <= 128)
        });
    let valid_waiting = request.mutation.waiting_on.as_ref().is_none_or(|values| {
        values.iter().all(|value| {
            !value.id.is_empty()
                && value.id.len() <= 256
                && value
                    .message
                    .as_ref()
                    .is_none_or(|message| message.chars().count() <= 2048)
        })
    });
    let valid_failure = request.mutation.failure.as_ref().is_none_or(|failure| {
        !failure.code.is_empty()
            && failure.code.len() <= 128
            && !failure.summary.is_empty()
            && failure.summary.chars().count() <= 4096
            && failure
                .step_id
                .as_ref()
                .is_none_or(|value| value.len() <= 128)
            && failure
                .provider_id
                .as_ref()
                .is_none_or(|value| value.len() <= 256)
            && failure
                .execution_binding_id
                .as_ref()
                .is_none_or(|value| value.len() <= 256)
            && failure.provenance_event_ids.len() <= 64
            && all_unique(&failure.provenance_event_ids)
            && failure
                .provenance_event_ids
                .iter()
                .all(|value| value.len() <= 256)
    });
    let valid_recovery = request.mutation.recovery.as_ref().is_none_or(|recovery| {
        recovery.unknown_operation_ids.len() <= 128
            && recovery
                .unknown_operation_ids
                .iter()
                .all(|value| value.len() <= 256)
            && recovery
                .unknown_operation_ids
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == recovery.unknown_operation_ids.len()
            && recovery
                .last_known_daemon_instance
                .as_ref()
                .is_none_or(|value| value.len() <= 256)
            && recovery
                .unknown_operations_ref
                .as_ref()
                .is_none_or(|value| !value.is_empty() && value.len() <= 256)
    });
    if request.schema_version != SCHEMA_VERSION
        || request.transition_id.is_empty()
        || request.transition_id.len() > 256
        || (request.transition_id.starts_with("__aios_internal:") && !internal_recovery)
        || (internal_recovery && !request.transition_id.starts_with("__aios_internal:"))
        || request.task_id.is_empty()
        || request.task_id.len() > 256
        || request.expected_revision == 0
        || !valid_actor
        || request.requested_by.id.is_empty()
        || request.requested_by.id.len() > 256
        || request.reason.code.is_empty()
        || request.reason.code.len() > 128
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
            .any(|value| value.len() > 512)
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

fn recovery_operations_ref(task_id: &str, revision: u64, operation_ids: &[String]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"AIOS-RECOVERY-OPERATIONS\0v0.1\0");
    hasher.update(task_id.as_bytes());
    hasher.update(revision.to_be_bytes());
    for operation_id in operation_ids {
        hasher.update(operation_id.len().to_be_bytes());
        hasher.update(operation_id.as_bytes());
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        write!(&mut hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    format!("recovery-operations:sha256:{hex}")
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

fn migrate_task_manager_schema(connection: &Connection) -> Result<()> {
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
    for (column, declaration) in [
        ("active_plan_revision", "INTEGER"),
        ("active_step_ids_json", "TEXT NOT NULL DEFAULT '[]'"),
        ("waiting_on_json", "TEXT NOT NULL DEFAULT '[]'"),
    ] {
        if !table_has_column(connection, "tasks", column)? {
            connection.execute_batch(&format!(
                "ALTER TABLE tasks ADD COLUMN {column} {declaration};"
            ))?;
        }
    }
    let transition_has_foreign_key = {
        let mut statement = connection.prepare("PRAGMA foreign_key_list(task_transitions)")?;
        statement.query([])?.next()?.is_some()
    };
    if transition_has_foreign_key {
        connection.execute_batch(
            "PRAGMA foreign_keys = OFF;
             BEGIN IMMEDIATE;
             DROP INDEX IF EXISTS ix_task_transitions_task;
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
             CREATE INDEX ix_task_transitions_task ON task_transitions(task_id, requested_at);
             COMMIT;
             PRAGMA foreign_keys = ON;",
        )?;
    }
    connection.execute(
        "INSERT OR IGNORE INTO schema_migrations(migration_id, checksum, applied_at) VALUES ('0002_task_manager_contract_reconciliation', 'task-manager-v0.1', '2026-09-19T00:00:00Z')",
        [],
    )?;
    reconcile_pending_transitions(connection)?;
    Ok(())
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
            "SELECT transition_id, task_id, requested_at FROM task_transitions WHERE outcome = 'PENDING' OR result_json IS NULL ORDER BY transition_id",
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
                "SELECT b.binding_id FROM execution_bindings b JOIN step_executions s ON s.binding_id = b.binding_id AND s.attempt_id = b.attempt_id AND s.task_id = b.task_id AND s.semantic_program_hash = b.semantic_program_hash AND s.node_id = b.node_id JOIN semantic_program_revisions p ON p.task_id = b.task_id AND p.semantic_hash = b.semantic_program_hash WHERE b.task_id = ?1 AND p.program_revision = ?2 AND b.node_id = ?3 AND s.state IN ('READY', 'STARTING', 'RUNNING') AND s.attempt_number = (SELECT MAX(s2.attempt_number) FROM step_executions s2 WHERE s2.task_id = s.task_id AND s2.node_id = s.node_id AND s2.semantic_program_hash = s.semantic_program_hash) LIMIT 1",
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
        count += transaction.query_row(
            "SELECT COUNT(*) FROM step_executions s JOIN tasks t ON t.task_id = s.task_id JOIN semantic_program_revisions p ON p.task_id = t.task_id AND p.program_revision = t.active_program_revision AND p.semantic_hash = s.semantic_program_hash WHERE s.task_id = ?1 AND s.node_id = ?2 AND s.state = ?3",
            params![task_id, node_id, state],
            |row| row.get::<_, i64>(0),
        )?;
    }
    Ok(count)
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
        let candidate = transaction
            .query_row(
                "SELECT s.state, b.binding_id, s.attempt_id, s.semantic_program_hash, b.grant_refs_json FROM step_executions s JOIN tasks t ON t.task_id = s.task_id JOIN semantic_program_revisions p ON p.task_id = t.task_id AND p.program_revision = t.active_program_revision AND p.semantic_hash = s.semantic_program_hash JOIN execution_bindings b ON b.binding_id = s.binding_id AND b.attempt_id = s.attempt_id AND b.task_id = s.task_id AND b.semantic_program_hash = s.semantic_program_hash AND b.node_id = s.node_id WHERE s.task_id = ?1 AND s.node_id = ?2 AND s.attempt_number = (SELECT MAX(s2.attempt_number) FROM step_executions s2 WHERE s2.task_id = s.task_id AND s2.node_id = s.node_id AND s2.semantic_program_hash = s.semantic_program_hash) LIMIT 1",
                params![task_id, node_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?)),
            )
            .optional()?;
        if let Some((state, binding_id, attempt_id, semantic_hash, grant_refs)) = candidate
            && states.contains(&state.as_str())
            && binding_grants_valid(
                transaction,
                &BindingGrantCheck {
                    task_id,
                    semantic_hash: &semantic_hash,
                    node_id,
                    binding_id: &binding_id,
                    attempt_id: &attempt_id,
                    grant_refs_json: &grant_refs,
                    checked_at,
                },
            )?
        {
            count += 1;
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
    for node_id in active_steps {
        let candidate = transaction
            .query_row(
                "SELECT s.attempt_id, b.binding_id, s.semantic_program_hash, b.grant_refs_json FROM step_executions s JOIN tasks t ON t.task_id = s.task_id JOIN semantic_program_revisions p ON p.task_id = t.task_id AND p.program_revision = t.active_program_revision AND p.semantic_hash = s.semantic_program_hash JOIN execution_bindings b ON b.binding_id = s.binding_id AND b.attempt_id = s.attempt_id AND b.task_id = s.task_id AND b.semantic_program_hash = s.semantic_program_hash AND b.node_id = s.node_id WHERE s.task_id = ?1 AND s.node_id = ?2 AND s.state = 'READY' AND s.attempt_number = (SELECT MAX(s2.attempt_number) FROM step_executions s2 WHERE s2.task_id = s.task_id AND s2.node_id = s.node_id AND s2.semantic_program_hash = s.semantic_program_hash) LIMIT 1",
                params![task_id, node_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?)),
            )
            .optional()?;
        let Some((attempt_id, binding_id, semantic_hash, grant_refs)) = candidate else {
            return Ok(false);
        };
        if !binding_grants_valid(
            transaction,
            &BindingGrantCheck {
                task_id,
                semantic_hash: &semantic_hash,
                node_id,
                binding_id: &binding_id,
                attempt_id: &attempt_id,
                grant_refs_json: &grant_refs,
                checked_at: admitted_at,
            },
        )? {
            return Ok(false);
        }
        let changed = transaction.execute(
            "UPDATE step_executions SET revision = revision + 1, state = 'RUNNING', started_at = COALESCE(started_at, ?2), updated_at = ?2 WHERE attempt_id = ?1 AND state = 'READY'",
            params![attempt_id, admitted_at],
        )?;
        if changed != 1 {
            return Ok(false);
        }
    }
    Ok(true)
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

fn binding_grants_valid(
    transaction: &Transaction<'_>,
    check: &BindingGrantCheck<'_>,
) -> Result<bool> {
    let grant_ids: Vec<String> = serde_json::from_str(check.grant_refs_json)?;
    if grant_ids.len() > 64 || !all_unique(&grant_ids) {
        return Ok(false);
    }
    for grant_id in grant_ids {
        let expires_at = transaction
            .query_row(
                "SELECT expires_at FROM authority_grants WHERE grant_id = ?1 AND task_id = ?2 AND semantic_program_hash = ?3 AND node_id = ?4 AND execution_binding_id = ?5 AND attempt_id = ?6 AND state = 'ACTIVE' AND scope IN ('ONE_SHOT', 'TASK', 'TIME_LIMITED') AND (max_uses IS NULL OR uses_consumed < max_uses)",
                params![grant_id, check.task_id, check.semantic_hash, check.node_id, check.binding_id, check.attempt_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(expires_at) = expires_at else {
            return Ok(false);
        };
        let Ok(expires_at) = OffsetDateTime::parse(&expires_at, &Rfc3339) else {
            return Ok(false);
        };
        let Ok(checked_at) = OffsetDateTime::parse(check.checked_at, &Rfc3339) else {
            return Ok(false);
        };
        if expires_at <= checked_at {
            return Ok(false);
        }
    }
    Ok(true)
}

fn active_step_completion_facts(
    transaction: &Transaction<'_>,
    task_id: &str,
    active_steps: &[String],
) -> Result<(usize, usize, usize)> {
    let mut bad_steps = 0_usize;
    let mut published_outputs = 0_usize;
    for node_id in active_steps {
        let attempt = transaction
            .query_row(
                "SELECT s.attempt_id, s.binding_id, s.semantic_program_hash, s.state, s.outcome_certainty, s.output_artifacts_json FROM step_executions s JOIN tasks t ON t.task_id = s.task_id JOIN semantic_program_revisions p ON p.task_id = t.task_id AND p.program_revision = t.active_program_revision AND p.semantic_hash = s.semantic_program_hash JOIN execution_bindings b ON b.binding_id = s.binding_id AND b.attempt_id = s.attempt_id AND b.task_id = s.task_id AND b.semantic_program_hash = s.semantic_program_hash AND b.node_id = s.node_id WHERE s.task_id = ?1 AND s.node_id = ?2 AND s.attempt_number = (SELECT MAX(s2.attempt_number) FROM step_executions s2 WHERE s2.task_id = s.task_id AND s2.node_id = s.node_id AND s2.semantic_program_hash = s.semantic_program_hash) LIMIT 1",
                params![task_id, node_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((attempt_id, binding_id, semantic_hash, state, certainty, output_json)) = attempt
        else {
            bad_steps += 1;
            continue;
        };
        // v0.1 has no durable optional-node contract yet, so SKIPPED cannot
        // prove a required node complete. Fail closed until program optionality
        // is represented and validated explicitly.
        if state != "SUCCEEDED" || certainty.as_deref() != Some("COMPLETED") {
            bad_steps += 1;
            continue;
        }
        let outputs: Vec<String> = decode_optional(output_json)?.unwrap_or_default();
        for artifact_id in outputs {
            let committed = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM artifact_output_allocations a JOIN artifact_publications p ON p.publication_id = a.publication_id AND p.allocation_id = a.allocation_id AND p.task_id = a.task_id AND p.artifact_id = a.published_artifact_id AND p.state = 'COMMITTED' JOIN task_artifacts t ON t.task_id = a.task_id AND t.artifact_id = a.published_artifact_id AND t.role = 'output' WHERE a.task_id = ?1 AND a.semantic_program_hash = ?2 AND a.node_id = ?3 AND a.binding_id = ?4 AND a.attempt_id = ?5 AND a.published_artifact_id = ?6 AND a.state = 'PUBLISHED')",
                params![task_id, semantic_hash, node_id, binding_id, attempt_id, artifact_id],
                |row| row.get::<_, bool>(0),
            )?;
            if committed {
                published_outputs += 1;
            } else {
                bad_steps += 1;
            }
        }
    }
    Ok((active_steps.len(), bad_steps, published_outputs))
}

fn active_candidate_output_count(
    transaction: &Transaction<'_>,
    task_id: &str,
    active_steps: &[String],
) -> Result<usize> {
    let mut count = 0_usize;
    for node_id in active_steps {
        let output_json = transaction
            .query_row(
                "SELECT s.output_artifacts_json FROM step_executions s JOIN tasks t ON t.task_id = s.task_id JOIN semantic_program_revisions p ON p.task_id = t.task_id AND p.program_revision = t.active_program_revision AND p.semantic_hash = s.semantic_program_hash JOIN execution_bindings b ON b.binding_id = s.binding_id AND b.attempt_id = s.attempt_id AND b.task_id = s.task_id AND b.semantic_program_hash = s.semantic_program_hash AND b.node_id = s.node_id WHERE s.task_id = ?1 AND s.node_id = ?2 AND s.state = 'SUCCEEDED' AND s.attempt_number = (SELECT MAX(s2.attempt_number) FROM step_executions s2 WHERE s2.task_id = s.task_id AND s2.node_id = s.node_id AND s2.semantic_program_hash = s.semantic_program_hash) LIMIT 1",
                params![task_id, node_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        if let Some(output_json) = output_json {
            count += serde_json::from_str::<Vec<String>>(&output_json)?.len();
        }
    }
    Ok(count)
}

fn has_current_verification(
    transaction: &Transaction<'_>,
    task_id: &str,
    active_steps: &[String],
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
    let mut required_outputs = std::collections::BTreeSet::new();
    for node_id in active_steps {
        let output_json = transaction
            .query_row(
                "SELECT s.output_artifacts_json FROM step_executions s JOIN execution_bindings b ON b.binding_id = s.binding_id AND b.attempt_id = s.attempt_id AND b.task_id = s.task_id AND b.semantic_program_hash = s.semantic_program_hash AND b.node_id = s.node_id WHERE s.task_id = ?1 AND s.node_id = ?2 AND s.semantic_program_hash = ?3 AND s.state = 'SUCCEEDED' AND s.attempt_number = (SELECT MAX(s2.attempt_number) FROM step_executions s2 WHERE s2.task_id = s.task_id AND s2.node_id = s.node_id AND s2.semantic_program_hash = s.semantic_program_hash) LIMIT 1",
                params![task_id, node_id, semantic_hash],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        let Some(output_json) = output_json else {
            return Ok(false);
        };
        required_outputs.extend(serde_json::from_str::<Vec<String>>(&output_json)?);
    }
    if required_outputs.is_empty() {
        return Ok(false);
    }
    let mut statement = transaction.prepare(
        "SELECT event_json FROM provenance_events WHERE task_id = ?1 AND event_type = 'verification.completed' AND status = 'success' ORDER BY sequence DESC",
    )?;
    let rows = statement.query_map([task_id], |row| row.get::<_, String>(0))?;
    for row in rows {
        let event: Value = serde_json::from_str(&row?)?;
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
        "SELECT COUNT(*) FROM step_executions WHERE task_id = ?1 AND (state IN ('PENDING', 'BLOCKED', 'READY', 'STARTING', 'RUNNING', 'UNKNOWN') OR outcome_certainty IN ('FAILED_PARTIAL_EFFECT', 'OUTCOME_UNKNOWN'))",
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
    Ok(live_attempts == 0 && live_grants == 0 && live_effects == 0)
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
    let valid_program = active_program.is_some()
        && transaction.query_row(
            "SELECT COUNT(*) FROM semantic_program_revisions p JOIN validation_results v ON v.validation_result_id = p.validation_result_id WHERE p.task_id = ?1 AND p.program_revision = ?2 AND p.status = 'active' AND v.valid = 1 AND v.semantic_hash = p.semantic_hash AND v.registry_snapshot_id = p.registry_snapshot_id",
            params![request.task_id, active_program],
            |row| row.get::<_, i64>(0),
        )? == 1;
    let ready_steps = count_active_steps(transaction, &request.task_id, &active_steps, "READY")?;
    let bound_ready_steps = count_bound_active_steps(
        transaction,
        &request.task_id,
        &active_steps,
        &["READY"],
        checked_at,
    )?;
    let pending_approvals: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM approval_requests WHERE task_id = ?1 AND status = 'PENDING'",
        [&request.task_id],
        |row| row.get(0),
    )?;
    let unknown_operations: i64 = transaction.query_row(
        "SELECT (SELECT COUNT(*) FROM operations WHERE task_id = ?1 AND outcome_certainty = 'OUTCOME_UNKNOWN') + (SELECT COUNT(*) FROM step_executions WHERE task_id = ?1 AND outcome_certainty = 'OUTCOME_UNKNOWN')",
        [&request.task_id],
        |row| row.get(0),
    )?;
    let durable_nonapproval_blocker = durable_waiting
        .iter()
        .any(|item| item.kind != WaitingKind::Approval);
    let mut matching_pending_approval = false;
    for blocker in waiting
        .iter()
        .filter(|item| item.kind == WaitingKind::Approval)
    {
        matching_pending_approval |= transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM approval_requests WHERE task_id = ?1 AND approval_id = ?2 AND status = 'PENDING')",
            params![request.task_id, blocker.id],
            |row| row.get::<_, bool>(0),
        )?;
    }
    if request.mutation.active_step_ids.is_some()
        && matches!(
            request.to_state,
            TaskState::Running | TaskState::Verifying | TaskState::Completed
        )
    {
        return Ok(Some("TASK_TRANSITION_GUARD_FAILED"));
    }
    if request.to_state == TaskState::Recovering && !internal_recovery {
        return Ok(Some("TASK_TRANSITION_GUARD_FAILED"));
    }
    if let Some(plan) = &request.mutation.active_plan
        && matches!(
            request.to_state,
            TaskState::Runnable | TaskState::Running | TaskState::Verifying | TaskState::Completed
        )
    {
        let coherent = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM plan_revisions r JOIN tasks t ON t.task_id = r.task_id JOIN semantic_program_revisions p ON p.task_id = t.task_id AND p.program_revision = t.active_program_revision WHERE r.task_id = ?1 AND r.plan_id = ?2 AND r.plan_revision = ?3 AND p.created_from_plan_revision = r.plan_revision)",
            params![request.task_id, plan.plan_id, i64::try_from(plan.revision).unwrap_or(i64::MAX)],
            |row| row.get::<_, bool>(0),
        )?;
        if !coherent {
            return Ok(Some("TASK_PROGRAM_NOT_RUNNABLE"));
        }
    }
    if matches!(
        request.to_state,
        TaskState::Runnable | TaskState::Running | TaskState::Verifying
    ) && unknown_operations > 0
    {
        return Ok(Some("TASK_UNKNOWN_EXTERNAL_OUTCOME"));
    }
    let code = match request.to_state {
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
                || ready_steps == 0
                || !waiting.is_empty()
                || pending_approvals > 0
                || durable_nonapproval_blocker =>
        {
            Some("TASK_PROGRAM_NOT_RUNNABLE")
        }
        TaskState::Running
            if !valid_program
                || !waiting.is_empty()
                || pending_approvals > 0
                || durable_nonapproval_blocker
                || active_steps.is_empty()
                || usize::try_from(bound_ready_steps).ok() != Some(active_steps.len()) =>
        {
            Some("TASK_TRANSITION_GUARD_FAILED")
        }
        TaskState::Verifying => {
            let candidate_outputs =
                active_candidate_output_count(transaction, &request.task_id, &active_steps)?;
            (candidate_outputs == 0).then_some("TASK_TRANSITION_GUARD_FAILED")
        }
        TaskState::Completed => {
            let (active_step_count, bad_active_steps, published_active_outputs) =
                active_step_completion_facts(transaction, &request.task_id, &active_steps)?;
            let verified = has_current_verification(transaction, &request.task_id, &active_steps)?;
            if unknown_operations > 0 {
                Some("TASK_UNKNOWN_EXTERNAL_OUTCOME")
            } else if !valid_program
                || active_step_count == 0
                || bad_active_steps > 0
                || published_active_outputs == 0
                || !verified
                || pending_approvals > 0
                || !waiting.is_empty()
                || !durable_waiting.is_empty()
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
        TaskState::Cancelled if !execution_is_contained(transaction, &request.task_id)? => {
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
    fn two_writers_with_one_expected_revision_have_one_winner() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("revision-race.sqlite3");
        let mut first = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        first.create_task(&create("T-race")).unwrap();
        let mut second = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();

        let winner = first
            .transition(&request(
                "tr-race-winner",
                "T-race",
                1,
                TaskState::Created,
                TaskState::Planning,
            ))
            .unwrap();
        let loser = second
            .transition(&request(
                "tr-race-loser",
                "T-race",
                1,
                TaskState::Created,
                TaskState::Failed,
            ))
            .unwrap();

        assert!(winner.applied);
        assert_eq!(loser.reason_code, "TASK_REVISION_CONFLICT");
        assert_eq!(second.provenance_count("T-race").unwrap(), 2);
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
mod adversarial_tests;
