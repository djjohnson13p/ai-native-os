//! Durable, local semantic snapshot admission and default selection.
//!
//! The caller supplies a connection to the trusted control-plane database. This
//! module never discovers contracts, executes providers, or changes Task evidence.

#![allow(
    clippy::missing_errors_doc,
    reason = "the store methods return one coded operational error type"
)]

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::path::Path;
use std::sync::Arc;

use aios_contracts::{CapabilityContract, RegistrySnapshot, TypeContract};
use fs2::FileExt;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::schema::{self, RecordKind};
use crate::{
    HashVerificationMode, RegistryBuildOptions, RegistryLoadOptions, SemanticRegistry,
    StrictJsonLimits,
};

const MIGRATION_ID: &str = "0012_semantic_registry_store";
// This is a draft migration stamp, not a digest of the SQL file. Keep it stable
// while adding the admission guard to existing Issue #2 databases.
const MIGRATION_CHECKSUM: &str = "semantic-registry-store-v0.1";
const STORE_OBJECTS: &[(&str, &str)] = &[
    ("table", "semantic_type_contracts"),
    ("table", "semantic_capability_contracts"),
    ("table", "registry_snapshot_admissions"),
    ("table", "registry_snapshot_entries"),
    ("table", "registry_activations"),
    ("trigger", "immutable_admitted_registry_snapshots_update"),
    ("trigger", "immutable_admitted_registry_snapshots_delete"),
    ("trigger", "immutable_semantic_type_contracts_update"),
    ("trigger", "immutable_semantic_type_contracts_delete"),
    ("trigger", "immutable_semantic_capability_contracts_update"),
    ("trigger", "immutable_semantic_capability_contracts_delete"),
    ("trigger", "immutable_registry_snapshot_entries_update"),
    ("trigger", "immutable_registry_snapshot_entries_delete"),
    ("trigger", "immutable_registry_snapshot_admissions_delete"),
];

#[allow(
    clippy::too_many_lines,
    reason = "authenticates migration stamps, full schema definitions and foreign-key integrity as one startup gate"
)]
fn preflight_store_migration(connection: &Connection) -> Result<()> {
    let known: &[(&str, &str)] = &[
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
        (MIGRATION_ID, MIGRATION_CHECKSUM),
        ("0013_provider_registry", "provider-registry-v0.1"),
        ("0014_semantic_repair_fence", "semantic-repair-fence-v0.1"),
        (
            "0015_authority_issuance_fence",
            "authority-issuance-fence-v0.1",
        ),
        (
            "0016_authority_candidate_reservations",
            "authority-candidate-reservations-v0.1",
        ),
        (
            "0017_authority_policy_evaluation",
            "authority-policy-evaluation-v0.1",
        ),
        ("0018_trusted_time", "trusted-time-v0.1"),
        ("0019_inflight_time", "inflight-time-v0.1"),
        (
            "0020_artifact_placement_receipts",
            "artifact-placement-receipts-v0.1",
        ),
        (
            "0021_authority_grant_deadlines",
            "authority-grant-deadlines-v0.1",
        ),
    ];
    let mut stamped = false;
    let mut baseline = false;
    let mut repair_fence_stamped = false;
    let mut statement =
        connection.prepare("SELECT migration_id,checksum FROM schema_migrations")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let id: String = row.get(0)?;
        let checksum: String = row.get(1)?;
        let Some((_, expected)) = known.iter().find(|(known_id, _)| *known_id == id) else {
            return Err(RegistryStoreError::Conflict(
                "unknown control-plane migration",
            ));
        };
        if checksum != *expected {
            return Err(RegistryStoreError::Conflict(
                "control-plane migration checksum mismatch",
            ));
        }
        baseline |= id == "0001_v0_1_trusted_control_plane";
        stamped |= id == MIGRATION_ID;
        repair_fence_stamped |= id == "0014_semantic_repair_fence";
    }
    if !baseline {
        return Err(RegistryStoreError::Conflict(
            "trusted control-plane baseline is required",
        ));
    }
    let canonical = Connection::open_in_memory()?;
    canonical.execute_batch(include_str!("../../../specs/persistence-v0.1.sql"))?;
    canonical.execute_batch(include_str!(
        "../../../specs/persistence-v0.1-0012-semantic-registry.sql"
    ))?;
    for (kind, name) in STORE_OBJECTS {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type=?1 AND name=?2",
                params![kind, name],
                |row| row.get(0),
            )
            .optional()?;
        if actual.is_some() != stamped {
            return Err(RegistryStoreError::Conflict(
                "semantic registry migration is incomplete or unstamped",
            ));
        }
        if let Some(actual) = actual {
            let expected: String = canonical.query_row(
                "SELECT sql FROM sqlite_master WHERE type=?1 AND name=?2",
                params![kind, name],
                |row| row.get(0),
            )?;
            if actual.split_whitespace().ne(expected.split_whitespace()) {
                return Err(RegistryStoreError::Conflict(
                    "semantic registry schema definition mismatch",
                ));
            }
        }
    }
    preflight_admission_guards(connection, &canonical, stamped)?;
    if !repair_fence_stamped {
        return Err(RegistryStoreError::Conflict(
            "Task Manager fenced semantic repair migration is required",
        ));
    }
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
        ("trigger", "semantic_repair_fence_no_update"),
        ("trigger", "semantic_repair_fence_no_delete"),
        ("trigger", "semantic_repair_fence_no_duplicate_insert"),
        ("trigger", "semantic_repair_fence_sequence"),
        ("trigger", "semantic_terminal_admission_no_update"),
        ("trigger", "semantic_terminal_admission_no_delete"),
        ("trigger", "semantic_terminal_admission_no_duplicate_insert"),
        ("trigger", "semantic_terminal_admission_insert"),
        ("trigger", "semantic_terminal_admission_transition"),
        ("trigger", "semantic_legacy_unprovable_no_update"),
        ("trigger", "semantic_legacy_unprovable_no_delete"),
        ("trigger", "semantic_legacy_unprovable_no_duplicate_insert"),
        ("trigger", "semantic_invalidated_activation_no_update"),
        ("trigger", "semantic_invalidated_activation_no_delete"),
        (
            "trigger",
            "semantic_invalidated_activation_no_duplicate_insert",
        ),
        ("trigger", "semantic_activation_scope_history_no_update"),
        ("trigger", "semantic_activation_scope_history_no_delete"),
        (
            "trigger",
            "semantic_activation_scope_history_no_duplicate_insert",
        ),
        ("trigger", "semantic_activation_scope_history_insert"),
        ("trigger", "semantic_activation_scope_history_key_update"),
        ("trigger", "semantic_legacy_activation_quarantine_no_update"),
        ("trigger", "semantic_legacy_activation_quarantine_no_delete"),
        (
            "trigger",
            "semantic_legacy_activation_quarantine_no_duplicate_insert",
        ),
        ("trigger", "semantic_snapshot_reattestation_no_update"),
        ("trigger", "semantic_snapshot_reattestation_no_delete"),
        (
            "trigger",
            "semantic_snapshot_reattestation_no_duplicate_insert",
        ),
        ("trigger", "semantic_snapshot_reattestation_current_only"),
        ("trigger", "semantic_repair_activation_insert"),
        ("trigger", "semantic_repair_activation_update"),
        ("trigger", "semantic_repair_registration_insert"),
        ("trigger", "semantic_repair_registration_enable"),
        ("trigger", "semantic_repair_binding_insert"),
    ] {
        let actual: String = connection.query_row(
            "SELECT sql FROM sqlite_master WHERE type=?1 AND name=?2",
            params![kind, name],
            |row| row.get(0),
        )?;
        let expected: String = canonical.query_row(
            "SELECT sql FROM sqlite_master WHERE type=?1 AND name=?2",
            params![kind, name],
            |row| row.get(0),
        )?;
        if actual.split_whitespace().ne(expected.split_whitespace()) {
            return Err(RegistryStoreError::Conflict(
                "semantic repair fence schema definition mismatch",
            ));
        }
    }
    let fence_invalid: bool = connection.query_row(
        "SELECT NOT EXISTS(SELECT 1 FROM semantic_repair_fences WHERE generation=0 AND reason='BOOTSTRAP')
          OR EXISTS(SELECT 1 FROM semantic_repair_fences f WHERE typeof(f.generation)<>'integer'
                    OR (f.generation>0 AND (f.reason<>'GUARD_REPAIR' OR NOT EXISTS (
                        SELECT 1 FROM semantic_repair_fences p WHERE p.generation=f.generation-1))))
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
    if fence_invalid {
        return Err(RegistryStoreError::Conflict(
            "semantic repair fence data mismatch",
        ));
    }
    let mut violations = connection.prepare("PRAGMA foreign_key_check")?;
    if violations.query([])?.next()?.is_some() {
        return Err(RegistryStoreError::Conflict(
            "control-plane foreign key integrity violation",
        ));
    }
    Ok(())
}

fn preflight_admission_guards(
    connection: &Connection,
    canonical: &Connection,
    stamped: bool,
) -> Result<()> {
    // Older stamped stores can be upgraded only by Task Manager while its
    // identity-bound lock and durable ownership lease are held.
    for (guard, _additive) in [
        ("immutable_admitted_registry_snapshots_update", false),
        ("immutable_admitted_registry_snapshots_delete", false),
        ("immutable_semantic_type_contracts_update", false),
        ("immutable_semantic_type_contracts_delete", false),
        ("immutable_semantic_capability_contracts_update", false),
        ("immutable_semantic_capability_contracts_delete", false),
        ("immutable_registry_snapshot_entries_update", false),
        ("immutable_registry_snapshot_entries_delete", false),
        ("immutable_registry_snapshot_admissions_delete", false),
        ("one_way_registry_snapshot_admissions_update", true),
        ("immutable_registry_snapshot_admissions_reinsert", true),
        ("immutable_admitted_registry_snapshots_reinsert", true),
        ("immutable_admitted_registry_snapshots_target_update", true),
        ("immutable_semantic_type_contracts_reinsert", true),
        ("immutable_semantic_capability_contracts_reinsert", true),
        ("immutable_registry_snapshot_entries_reinsert", true),
        ("immutable_admitted_registry_snapshot_entries_insert", true),
        ("registry_activation_no_duplicate_insert", true),
        ("registry_activation_revision_monotonic", true),
        ("registry_activation_no_delete", true),
    ] {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                [guard],
                |row| row.get(0),
            )
            .optional()?;
        if actual.is_some() && !stamped {
            return Err(RegistryStoreError::Conflict(
                "semantic registry migration is incomplete or unstamped",
            ));
        }
        if actual.is_none() && stamped {
            return Err(RegistryStoreError::Conflict(
                "semantic registry migration is incomplete or unstamped",
            ));
        }
        if let Some(actual) = actual {
            let expected: String = canonical.query_row(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                [guard],
                |row| row.get(0),
            )?;
            if actual.split_whitespace().ne(expected.split_whitespace()) {
                return Err(RegistryStoreError::Conflict(
                    "semantic registry admission guard definition mismatch",
                ));
            }
        }
    }
    if !stamped {
        return Err(RegistryStoreError::Conflict(
            "Task Manager fenced semantic registry migration is required",
        ));
    }
    Ok(())
}

fn decode_stored<T: serde::de::DeserializeOwned>(json: &str, kind: RecordKind) -> Result<T> {
    Ok(schema::decode_with_record_limit(
        json.as_bytes(),
        StrictJsonLimits::default(),
        kind,
        false,
        None,
    )?)
}

fn verify_snapshot_identity(snapshot: &RegistrySnapshot, expected_id: &str) -> Result<()> {
    let as_entry = |entry: &aios_contracts::ContractRef| crate::SnapshotHashEntry {
        id: entry.id.clone(),
        version: entry.version.clone(),
        content_hash: entry.content_hash.clone(),
    };
    let computed = crate::registry_snapshot_id(
        &snapshot.schema_version,
        &snapshot
            .type_contracts
            .iter()
            .map(as_entry)
            .collect::<Vec<_>>(),
        &snapshot
            .capability_contracts
            .iter()
            .map(as_entry)
            .collect::<Vec<_>>(),
    )?;
    if snapshot.snapshot_id != expected_id || computed.as_str() != expected_id {
        return Err(RegistryStoreError::Conflict(
            "stored snapshot identity does not match semantic entries",
        ));
    }
    Ok(())
}

#[derive(Debug)]
pub enum RegistryStoreError {
    Io(std::io::Error),
    Database(rusqlite::Error),
    Registry(crate::RegistryError),
    Serialization(serde_json::Error),
    Conflict(&'static str),
    NotFound,
    NotAdmitted,
    NotActivatable,
}

impl std::fmt::Display for RegistryStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "registry I/O error: {e}"),
            Self::Database(e) => write!(f, "registry database error: {e}"),
            Self::Registry(e) => write!(f, "{e}"),
            Self::Serialization(e) => write!(f, "registry serialization error: {e}"),
            Self::Conflict(message) => write!(f, "registry conflict: {message}"),
            Self::NotFound => f.write_str("registry snapshot not found"),
            Self::NotAdmitted => f.write_str("registry snapshot is not admitted"),
            Self::NotActivatable => f.write_str("registry snapshot cannot be activated"),
        }
    }
}

impl std::error::Error for RegistryStoreError {}

impl From<std::io::Error> for RegistryStoreError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<rusqlite::Error> for RegistryStoreError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Database(value)
    }
}
impl From<crate::RegistryError> for RegistryStoreError {
    fn from(value: crate::RegistryError) -> Self {
        Self::Registry(value)
    }
}
impl From<serde_json::Error> for RegistryStoreError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value)
    }
}

pub type Result<T> = std::result::Result<T, RegistryStoreError>;

/// Identity of the database file guarded by a live store lock.
#[derive(Debug, Clone)]
pub struct StoreIdentity {
    canonical_path: std::path::PathBuf,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    volume_serial_number: u64,
    #[cfg(windows)]
    file_index: u64,
}

impl PartialEq for StoreIdentity {
    fn eq(&self, other: &Self) -> bool {
        #[cfg(unix)]
        {
            self.device == other.device && self.inode == other.inode
        }
        #[cfg(windows)]
        {
            self.volume_serial_number == other.volume_serial_number
                && self.file_index == other.file_index
        }
        #[cfg(not(any(unix, windows)))]
        {
            self.canonical_path == other.canonical_path
        }
    }
}

impl Eq for StoreIdentity {}

impl StoreIdentity {
    pub fn persistent_key(&self) -> String {
        #[cfg(unix)]
        {
            format!("unix:{}:{}", self.device, self.inode)
        }
        #[cfg(windows)]
        {
            format!("windows:{}:{}", self.volume_serial_number, self.file_index)
        }
        #[cfg(not(any(unix, windows)))]
        {
            format!("path:{}", self.canonical_path.display())
        }
    }

    pub fn canonical_path(&self) -> &Path {
        &self.canonical_path
    }
}

pub fn store_identity(path: &Path, file: &File) -> Result<StoreIdentity> {
    #[cfg(not(windows))]
    let metadata = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(StoreIdentity {
            canonical_path: path.canonicalize()?,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(windows)]
    {
        let information = winx::winapi_util::file::information(file)?;
        Ok(StoreIdentity {
            canonical_path: path.canonicalize()?,
            volume_serial_number: information.volume_serial_number(),
            file_index: information.file_index(),
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = metadata;
        Ok(StoreIdentity {
            canonical_path: path.canonicalize()?,
        })
    }
}

/// Exclusive, identity-bound ownership of a file-backed control-plane store.
pub struct StoreLock {
    #[cfg_attr(not(windows), allow(dead_code))]
    database_file: File,
    _lock_file: File,
    identity: StoreIdentity,
}

impl StoreLock {
    pub fn acquire(path: &Path) -> Result<Self> {
        let database_file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)?;
        let identity = store_identity(path, &database_file)?;
        #[cfg(windows)]
        let lock_path = {
            // The alternate data stream is shared by every NTFS path alias.
            let mut value = path.as_os_str().to_os_string();
            value.push(":aios-task-manager-lock");
            std::path::PathBuf::from(value)
        };
        #[cfg(not(windows))]
        let lock_path = path.to_path_buf();
        let lock_file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path)?;
        lock_file.try_lock_exclusive()?;
        Ok(Self {
            database_file,
            _lock_file: lock_file,
            identity,
        })
    }

    pub fn verify_connection(&self, connection: &Connection) -> Result<()> {
        let main_filename = connection.query_row(
            "SELECT file FROM pragma_database_list WHERE name = 'main'",
            [],
            |row| row.get::<_, String>(0),
        )?;
        if main_filename.is_empty() {
            return Err(RegistryStoreError::Conflict(
                "SQLite main database has no durable file identity",
            ));
        }
        let main_path = std::path::PathBuf::from(main_filename);
        let main_file = OpenOptions::new().read(true).write(true).open(&main_path)?;
        if store_identity(&main_path, &main_file)? != self.identity {
            return Err(RegistryStoreError::Conflict(
                "SQLite main database identity does not match the locked store",
            ));
        }
        Ok(())
    }

    pub fn identity(&self) -> &StoreIdentity {
        &self.identity
    }

    pub fn database_file(&self) -> &File {
        &self.database_file
    }
}

/// Opaque runtime authority minted by a fresh, atomic Task Manager lease claim.
/// It cannot be reconstructed from owner and epoch values read from `SQLite`.
pub struct StoreOwner {
    lock: Option<Arc<StoreLock>>,
    owner: String,
    epoch: i64,
    nonce: String,
}

impl StoreOwner {
    pub fn claim(
        connection: &Connection,
        lock: Option<Arc<StoreLock>>,
        acquired_at: &str,
    ) -> Result<Self> {
        if let Some(lock) = &lock {
            lock.verify_connection(connection)?;
        } else {
            require_in_memory(connection)?;
        }
        connection.execute_batch("BEGIN IMMEDIATE")?;
        let claimed = (|| -> Result<Self> {
            connection.execute_batch(
                "CREATE TABLE IF NOT EXISTS task_manager_lease (
                    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                    owner_id TEXT NOT NULL,
                    fence_epoch INTEGER NOT NULL CHECK (fence_epoch >= 1),
                    acquired_at TEXT NOT NULL
                );
                CREATE TEMP TABLE IF NOT EXISTS aios_store_owner_capability (
                    nonce TEXT NOT NULL
                );",
            )?;
            if lock.is_none() {
                let already_owned: bool = connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM task_manager_lease WHERE singleton_id=1)",
                    [],
                    |row| row.get(0),
                )?;
                if already_owned {
                    return Err(RegistryStoreError::Conflict(
                        "in-memory Task Manager store already has an owner",
                    ));
                }
            }
            let owner: String =
                connection.query_row("SELECT lower(hex(randomblob(16)))", [], |row| row.get(0))?;
            let nonce: String =
                connection.query_row("SELECT lower(hex(randomblob(32)))", [], |row| row.get(0))?;
            connection.execute("DELETE FROM temp.aios_store_owner_capability", [])?;
            connection.execute(
                "INSERT INTO temp.aios_store_owner_capability(nonce) VALUES (?1)",
                [&nonce],
            )?;
            connection.execute(
                "INSERT INTO task_manager_lease(singleton_id,owner_id,fence_epoch,acquired_at)
                 VALUES (1,?1,1,?2)
                 ON CONFLICT(singleton_id) DO UPDATE SET owner_id=excluded.owner_id,
                   fence_epoch=task_manager_lease.fence_epoch+1,
                   acquired_at=excluded.acquired_at",
                params![owner, acquired_at],
            )?;
            let epoch: i64 = connection.query_row(
                "SELECT fence_epoch FROM task_manager_lease WHERE singleton_id=1 AND owner_id=?1",
                [&owner],
                |row| row.get(0),
            )?;
            Ok(Self {
                lock,
                owner,
                epoch,
                nonce,
            })
        })();
        match claimed {
            Ok(owner) => {
                connection.execute_batch("COMMIT")?;
                Ok(owner)
            }
            Err(error) => {
                connection.execute_batch("ROLLBACK")?;
                Err(error)
            }
        }
    }

    pub fn verify(&self, connection: &Connection) -> Result<()> {
        if let Some(lock) = &self.lock {
            lock.verify_connection(connection)?;
        } else {
            require_in_memory(connection)?;
        }
        let actual: Option<String> = connection
            .query_row(
                "SELECT nonce FROM temp.aios_store_owner_capability",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if actual.as_deref() != Some(&self.nonce) {
            return Err(RegistryStoreError::Conflict(
                "registry writer is not on its owner connection",
            ));
        }
        let current: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM task_manager_lease WHERE singleton_id=1 AND owner_id=?1 AND fence_epoch=?2)",
            params![&self.owner, self.epoch],
            |row| row.get(0),
        )?;
        if !current {
            return Err(RegistryStoreError::Conflict(
                "registry write rejected by stale Task Manager ownership fence",
            ));
        }
        Ok(())
    }

    pub(crate) fn verify_writer_ready(&self, connection: &Connection) -> Result<()> {
        self.verify(connection)?;
        let marker_exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_temp_master WHERE type='table' AND name='aios_task_manager_startup_ready')",
            [],
            |row| row.get(0),
        )?;
        if !marker_exists {
            return Err(RegistryStoreError::Conflict(
                "Task Manager startup recovery is not complete",
            ));
        }
        let ready: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM temp.aios_task_manager_startup_ready
             WHERE nonce=?1 AND owner_id=?2 AND fence_epoch=?3)",
            params![&self.nonce, &self.owner, self.epoch],
            |row| row.get(0),
        )?;
        if !ready {
            return Err(RegistryStoreError::Conflict(
                "Task Manager startup recovery is not complete",
            ));
        }
        Ok(())
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub fn epoch(&self) -> i64 {
        self.epoch
    }
}

pub(crate) struct WriteFence<'a> {
    mode: WriteFenceMode<'a>,
}

enum WriteFenceMode<'a> {
    Owner(&'a StoreOwner),
    InMemoryFixture,
    #[cfg(test)]
    TestFixture,
}

impl<'a> WriteFence<'a> {
    pub(crate) fn new(connection: &Connection, owner: &'a StoreOwner) -> Result<Self> {
        let fence = Self {
            mode: WriteFenceMode::Owner(owner),
        };
        fence.verify(connection)?;
        Ok(fence)
    }

    pub(crate) fn verify(&self, connection: &Connection) -> Result<()> {
        match self.mode {
            WriteFenceMode::Owner(owner) => owner.verify_writer_ready(connection),
            WriteFenceMode::InMemoryFixture => require_unleased_in_memory(connection),
            #[cfg(test)]
            WriteFenceMode::TestFixture => Ok(()),
        }
    }

    pub(crate) fn in_memory(connection: &Connection) -> Result<Self> {
        require_unleased_in_memory(connection)?;
        Ok(Self {
            mode: WriteFenceMode::InMemoryFixture,
        })
    }

    #[cfg(test)]
    pub(crate) fn fixture() -> Self {
        Self {
            mode: WriteFenceMode::TestFixture,
        }
    }
}

fn require_unleased_in_memory(connection: &Connection) -> Result<()> {
    require_in_memory(connection)?;
    let has_lease_table: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='task_manager_lease')",
            [],
            |row| row.get(0),
        )?;
    let has_lease: bool = if has_lease_table {
        connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM task_manager_lease WHERE singleton_id=1)",
            [],
            |row| row.get(0),
        )?
    } else {
        false
    };
    if has_lease {
        return Err(RegistryStoreError::Conflict(
            "in-memory Task Manager store requires current ownership fence",
        ));
    }
    Ok(())
}

fn require_in_memory(connection: &Connection) -> Result<()> {
    let main_filename: String = connection.query_row(
        "SELECT file FROM pragma_database_list WHERE name='main'",
        [],
        |row| row.get(0),
    )?;
    if !main_filename.is_empty() {
        return Err(RegistryStoreError::Conflict(
            "unlocked registry writer requires an in-memory database",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotState {
    Admitted,
    Deprecated,
    Quarantined,
    Revoked,
}

impl SnapshotState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "ADMITTED",
            Self::Deprecated => "DEPRECATED",
            Self::Quarantined => "QUARANTINED",
            Self::Revoked => "REVOKED",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Activation {
    pub scope_kind: String,
    pub scope_id: String,
    pub snapshot_id: String,
    pub revision: u64,
}

pub struct RegistryStore<'a> {
    connection: &'a mut Connection,
    write_fence: Option<WriteFence<'a>>,
}

impl<'a> RegistryStore<'a> {
    /// Opens a fully migrated semantic registry. Task Manager installs or upgrades
    /// the schema under its identity-bound store lock and durable ownership fence.
    pub fn initialize(connection: &'a mut Connection) -> Result<Self> {
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        preflight_store_migration(connection)?;
        Ok(Self {
            connection,
            write_fence: None,
        })
    }

    /// Opens a runtime mutation handle bound to Task Manager's locked `SQLite`
    /// connection and current durable owner/epoch.
    pub fn initialize_writer(
        connection: &'a mut Connection,
        owner: &'a StoreOwner,
    ) -> Result<Self> {
        let mut store = Self::initialize(connection)?;
        store.write_fence = Some(WriteFence::new(store.connection, owner)?);
        Ok(store)
    }

    /// Creates a writer only for an unleased in-memory fixture database.
    pub fn initialize_in_memory(connection: &'a mut Connection) -> Result<Self> {
        let mut store = Self::initialize(connection)?;
        store.write_fence = Some(WriteFence::in_memory(store.connection)?);
        Ok(store)
    }

    #[cfg(test)]
    pub(crate) fn initialize_unfenced_fixture(connection: &'a mut Connection) -> Result<Self> {
        let mut store = Self::initialize(connection)?;
        store.write_fence = Some(WriteFence::fixture());
        Ok(store)
    }

    /// Strictly validates an explicitly supplied local bundle before any write.
    pub fn admit_bundle(&mut self, directory: impl AsRef<Path>) -> Result<String> {
        let registry = SemanticRegistry::load_bundle(directory, RegistryLoadOptions::default())?;
        self.admit_registry(&registry)
    }

    /// Persists only a strictly verified, immutable semantic registry.
    #[allow(
        clippy::too_many_lines,
        reason = "keeps verified admission and fenced publication in one operation"
    )]
    pub fn admit_registry(&mut self, registry: &SemanticRegistry) -> Result<String> {
        let fence = self
            .write_fence
            .as_ref()
            .ok_or(RegistryStoreError::Conflict(
                "registry mutation requires Task Manager write authority",
            ))?;
        if !registry.is_strictly_verified() {
            return Err(RegistryStoreError::NotAdmitted);
        }
        let snapshot_id = registry.snapshot_id().to_owned();
        let manifest_json = serde_json::to_string(registry.snapshot())?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        fence.verify(&transaction)?;
        let already_admitted = defer_entry_fk_until_admission(&transaction, &snapshot_id)?;
        let prior: Option<String> = transaction
            .query_row(
                "SELECT manifest_json FROM registry_snapshots WHERE snapshot_id=?1",
                [&snapshot_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(prior) = prior {
            // Existing Task Manager fixtures may contain an ID with an unverified
            // placeholder manifest. Never promote or overwrite one by accident.
            let stored: RegistrySnapshot = decode_stored(&prior, RecordKind::Snapshot)?;
            verify_snapshot_identity(&stored, &snapshot_id)?;
        } else {
            transaction.execute(
                "INSERT INTO registry_snapshots(snapshot_id,generation,manifest_json,created_at,publisher_id,signature_ref) VALUES (?1,?2,?3,?4,?5,?6)",
                params![snapshot_id, registry.snapshot().generation, manifest_json,
                    registry.snapshot().created_at,
                    registry.snapshot().publisher.as_ref().and_then(|p| p.id.as_deref()),
                    registry.snapshot().publisher.as_ref().and_then(|p| p.signature.as_deref())],
            )?;
        }
        for contract in registry.type_contracts() {
            let major = crate::FullVersion::parse(&contract.version)?.major;
            let hash = registry
                .type_contract_hash(&contract.type_id, major)
                .ok_or(RegistryStoreError::Conflict("missing verified type hash"))?;
            insert_contract(
                &transaction,
                "semantic_type_contracts",
                hash.as_str(),
                &contract.type_id,
                &contract.version,
                &serde_json::to_string(contract)?,
            )?;
            insert_entry(
                &transaction,
                &snapshot_id,
                "type",
                &contract.type_id,
                major,
                &contract.version,
                hash.as_str(),
            )?;
        }
        for contract in registry.capability_contracts() {
            let major = crate::FullVersion::parse(&contract.version)?.major;
            let hash = registry
                .capability_contract_hash(&contract.capability, major)
                .ok_or(RegistryStoreError::Conflict(
                    "missing verified capability hash",
                ))?;
            insert_contract(
                &transaction,
                "semantic_capability_contracts",
                hash.as_str(),
                &contract.capability,
                &contract.version,
                &serde_json::to_string(contract)?,
            )?;
            insert_entry(
                &transaction,
                &snapshot_id,
                "capability",
                &contract.capability,
                major,
                &contract.version,
                hash.as_str(),
            )?;
        }
        let entry_count: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM registry_snapshot_entries WHERE snapshot_id=?1",
            [&snapshot_id],
            |row| row.get(0),
        )?;
        let expected_count = registry
            .snapshot()
            .type_contracts
            .len()
            .checked_add(registry.snapshot().capability_contracts.len())
            .ok_or(RegistryStoreError::Conflict(
                "snapshot entry count overflow",
            ))?;
        if usize::try_from(entry_count).ok() != Some(expected_count) {
            return Err(RegistryStoreError::Conflict(
                "snapshot has unexpected persisted entries",
            ));
        }
        publish_admission(&transaction, &snapshot_id, already_admitted)?;
        if !already_admitted {
            let generation: i64 = transaction.query_row(
                "SELECT MAX(generation) FROM semantic_repair_fences",
                [],
                |row| row.get(0),
            )?;
            if generation > 0 {
                transaction.execute(
                    "INSERT INTO semantic_snapshot_reattestations
                     (snapshot_id,generation,decision_id,decision_source,verification_profile,verified_at)
                     VALUES (?1,?2,?3,'stage1-local-writer','strict-semantic-v0.1',
                             strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
                    params![snapshot_id, generation, format!("admission:{snapshot_id}:{generation}")],
                )?;
            }
        }
        fence.verify(&transaction)?;
        transaction.commit()?;
        // Read back through the same strict builder; persisted records, rather
        // than caller memory, become the admissible historical source.
        self.open_snapshot(&snapshot_id)?;
        Ok(snapshot_id)
    }

    /// Rebuilds and re-verifies a historical snapshot without source files/network.
    pub fn open_snapshot(&self, snapshot_id: &str) -> Result<SemanticRegistry> {
        Self::open_snapshot_from_connection(self.connection, snapshot_id)
    }

    /// Records a new, prospective authority decision for a previously admitted
    /// immutable snapshot after the current semantic repair fence. This does
    /// not reconstruct historical admission transitions or revive terminal
    /// QUARANTINED/REVOKED snapshots.
    pub fn reattest_snapshot(
        &mut self,
        snapshot_id: &str,
        decision_id: &str,
        decision_source: &str,
    ) -> Result<()> {
        let fence = self
            .write_fence
            .as_ref()
            .ok_or(RegistryStoreError::Conflict(
                "registry mutation requires Task Manager write authority",
            ))?;
        let valid_ref = |value: &str, limit: usize| {
            !value.is_empty()
                && value.len() <= limit
                && value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'.' | b'_' | b'/' | b'-')
                })
        };
        if !valid_ref(decision_id, 512) || !valid_ref(decision_source, 256) {
            return Err(RegistryStoreError::Conflict(
                "invalid re-attestation decision reference",
            ));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        fence.verify(&transaction)?;
        Self::open_snapshot_from_connection(&transaction, snapshot_id)?;
        let state: String = transaction.query_row(
            "SELECT state FROM registry_snapshot_admissions WHERE snapshot_id=?1",
            [snapshot_id],
            |row| row.get(0),
        )?;
        if !matches!(state.as_str(), "ADMITTED" | "DEPRECATED") {
            return Err(RegistryStoreError::NotAdmitted);
        }
        let generation: i64 = transaction.query_row(
            "SELECT MAX(generation) FROM semantic_repair_fences",
            [],
            |row| row.get(0),
        )?;
        if generation == 0 {
            return Err(RegistryStoreError::Conflict(
                "semantic repair fence has not advanced",
            ));
        }
        let prior: Option<(String, String)> = transaction
            .query_row(
                "SELECT decision_id,decision_source FROM semantic_snapshot_reattestations
             WHERE snapshot_id=?1 AND generation=?2",
                params![snapshot_id, generation],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some(prior) = prior {
            if prior.0 != decision_id || prior.1 != decision_source {
                return Err(RegistryStoreError::Conflict(
                    "semantic re-attestation decision changed",
                ));
            }
        } else {
            transaction.execute(
                "INSERT INTO semantic_snapshot_reattestations
                 (snapshot_id,generation,decision_id,decision_source,verification_profile,verified_at)
                 VALUES (?1,?2,?3,?4,'strict-semantic-v0.1',strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
                params![snapshot_id,generation,decision_id,decision_source],
            )?;
        }
        fence.verify(&transaction)?;
        transaction.commit()?;
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "keeps stored manifest and contract re-verification together"
    )]
    fn open_snapshot_from_connection(
        connection: &Connection,
        snapshot_id: &str,
    ) -> Result<SemanticRegistry> {
        let manifest_json: Option<String> = connection.query_row(
            "SELECT s.manifest_json FROM registry_snapshots s JOIN registry_snapshot_admissions a USING(snapshot_id) WHERE s.snapshot_id=?1",
            [snapshot_id], |row| row.get(0),
        ).optional()?;
        let manifest_json = manifest_json.ok_or(RegistryStoreError::NotAdmitted)?;
        let snapshot: RegistrySnapshot = decode_stored(&manifest_json, RecordKind::Snapshot)?;
        verify_snapshot_identity(&snapshot, snapshot_id)?;
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
        let mut types = Vec::<TypeContract>::new();
        let mut capabilities = Vec::<CapabilityContract>::new();
        let mut statement = connection.prepare(
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
            let major = u64::try_from(row.get::<_, i64>(2)?)
                .map_err(|_| RegistryStoreError::Conflict("negative stored major"))?;
            let version: String = row.get(3)?;
            let hash: String = row.get(4)?;
            if !expected.remove(&(class.clone(), id.clone(), version.clone(), hash.clone())) {
                return Err(RegistryStoreError::Conflict(
                    "stored snapshot contains an unexpected entry",
                ));
            }
            match class.as_str() {
                "type" => {
                    let json: String = row
                        .get::<_, Option<String>>(5)?
                        .ok_or(RegistryStoreError::Conflict("missing type contract bytes"))?;
                    let contract: TypeContract = decode_stored(&json, RecordKind::Type)?;
                    if contract.type_id != id
                        || contract.version != version
                        || crate::FullVersion::parse(&version)?.major != major
                        || crate::type_contract_hash(&contract)?.as_str() != hash
                    {
                        return Err(RegistryStoreError::Conflict(
                            "stored type entry does not match contract",
                        ));
                    }
                    types.push(contract);
                }
                "capability" => {
                    let json: String =
                        row.get::<_, Option<String>>(6)?
                            .ok_or(RegistryStoreError::Conflict(
                                "missing capability contract bytes",
                            ))?;
                    let contract: CapabilityContract =
                        decode_stored(&json, RecordKind::Capability)?;
                    if contract.capability != id
                        || contract.version != version
                        || crate::FullVersion::parse(&version)?.major != major
                        || crate::capability_contract_hash(&contract)?.as_str() != hash
                    {
                        return Err(RegistryStoreError::Conflict(
                            "stored capability entry does not match contract",
                        ));
                    }
                    capabilities.push(contract);
                }
                _ => {
                    return Err(RegistryStoreError::Conflict(
                        "unknown stored contract class",
                    ));
                }
            }
        }
        if !expected.is_empty() {
            return Err(RegistryStoreError::Conflict(
                "stored snapshot is missing entries",
            ));
        }
        let registry = SemanticRegistry::from_records(
            snapshot,
            types,
            capabilities,
            RegistryBuildOptions {
                hash_verification: HashVerificationMode::Strict,
                ..RegistryBuildOptions::default()
            },
        )?;
        if registry.snapshot_id() != snapshot_id {
            return Err(RegistryStoreError::Conflict(
                "stored snapshot identity mismatch",
            ));
        }
        Ok(registry)
    }

    pub fn set_snapshot_state(&mut self, snapshot_id: &str, state: SnapshotState) -> Result<()> {
        // State changes never delete historical content or rewrite Task evidence.
        let fence = self
            .write_fence
            .as_ref()
            .ok_or(RegistryStoreError::Conflict(
                "registry mutation requires Task Manager write authority",
            ))?;
        // A corrupt admission must still be containable. Only states eligible
        // for ordinary use require a successful strict reopen before changing.
        if matches!(state, SnapshotState::Admitted | SnapshotState::Deprecated) {
            self.open_snapshot(snapshot_id)?;
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        fence.verify(&transaction)?;
        let current: String = transaction
            .query_row(
                "SELECT a.state FROM registry_snapshot_admissions a JOIN registry_snapshots s USING(snapshot_id) WHERE a.snapshot_id=?1",
                [snapshot_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(RegistryStoreError::NotAdmitted)?;
        let allowed = match current.as_str() {
            "ADMITTED" => true,
            "DEPRECATED" => matches!(
                state,
                SnapshotState::Deprecated | SnapshotState::Quarantined | SnapshotState::Revoked
            ),
            "QUARANTINED" => matches!(state, SnapshotState::Quarantined | SnapshotState::Revoked),
            "REVOKED" => state == SnapshotState::Revoked,
            _ => false,
        };
        if !allowed {
            return Err(RegistryStoreError::Conflict(
                "snapshot state transition would reverse restriction",
            ));
        }
        let affected = transaction.execute(
            "UPDATE registry_snapshot_admissions SET state=?2 WHERE snapshot_id=?1 AND state=?3",
            params![snapshot_id, state.as_str(), current],
        )?;
        if affected != 1 {
            return Err(RegistryStoreError::Conflict("snapshot state changed"));
        }
        fence.verify(&transaction)?;
        transaction.commit()?;
        Ok(())
    }

    /// Atomically changes one scoped default. `None` expects no prior default.
    pub fn activate_default(
        &mut self,
        scope_kind: &str,
        scope_id: &str,
        expected_revision: Option<u64>,
        snapshot_id: &str,
    ) -> Result<Activation> {
        let fence = self
            .write_fence
            .as_ref()
            .ok_or(RegistryStoreError::Conflict(
                "registry mutation requires Task Manager write authority",
            ))?;
        if !matches!(scope_kind, "device" | "user" | "organization") || scope_id.is_empty() {
            return Err(RegistryStoreError::Conflict("invalid activation scope"));
        }
        self.open_snapshot(snapshot_id)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        fence.verify(&transaction)?;
        let state: Option<String> = transaction
            .query_row(
                "SELECT state FROM semantic_current_usable_snapshots WHERE snapshot_id=?1",
                [snapshot_id],
                |row| row.get(0),
            )
            .optional()?;
        if state.as_deref() != Some("ADMITTED") {
            return Err(RegistryStoreError::NotActivatable);
        }
        let current: Option<i64> = transaction
            .query_row(
                "SELECT revision FROM registry_activations WHERE scope_kind=?1 AND scope_id=?2",
                params![scope_kind, scope_id],
                |row| row.get(0),
            )
            .optional()?;
        let current_revision = current
            .map(|value| {
                u64::try_from(value)
                    .map_err(|_| RegistryStoreError::Conflict("invalid activation revision"))
            })
            .transpose()?;
        if current_revision != expected_revision {
            return Err(RegistryStoreError::Conflict("activation revision changed"));
        }
        let next = current
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(RegistryStoreError::Conflict("activation revision overflow"))?;
        if let Some(current) = current {
            let updated = transaction.execute(
                "UPDATE registry_activations SET snapshot_id=?3,revision=?4
                 WHERE scope_kind=?1 AND scope_id=?2 AND revision=?5",
                params![scope_kind, scope_id, snapshot_id, next, current],
            )?;
            if updated != 1 {
                return Err(RegistryStoreError::Conflict("activation revision changed"));
            }
        } else {
            transaction.execute(
                "INSERT INTO registry_activations(scope_kind,scope_id,snapshot_id,revision) VALUES (?1,?2,?3,?4)",
                params![scope_kind, scope_id, snapshot_id, next],
            )?;
        }
        fence.verify(&transaction)?;
        transaction.commit()?;
        Ok(Activation {
            scope_kind: scope_kind.to_owned(),
            scope_id: scope_id.to_owned(),
            snapshot_id: snapshot_id.to_owned(),
            revision: u64::try_from(next)
                .map_err(|_| RegistryStoreError::Conflict("invalid activation revision"))?,
        })
    }

    /// Returns the persisted pointer and CAS revision even after revocation.
    pub fn activation_pointer(
        &self,
        scope_kind: &str,
        scope_id: &str,
    ) -> Result<Option<Activation>> {
        let activation = self.connection.query_row(
            "SELECT snapshot_id,revision FROM registry_activations WHERE scope_kind=?1 AND scope_id=?2",
            params![scope_kind, scope_id], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        ).optional()?;
        let Some((snapshot_id, revision)) = activation else {
            return Ok(None);
        };
        Ok(Some(Activation {
            scope_kind: scope_kind.to_owned(),
            scope_id: scope_id.to_owned(),
            snapshot_id,
            revision: u64::try_from(revision)
                .map_err(|_| RegistryStoreError::Conflict("invalid activation revision"))?,
        }))
    }

    /// Returns only an admitted, verified default for new validation work.
    pub fn default_snapshot(&self, scope_kind: &str, scope_id: &str) -> Result<Option<Activation>> {
        self.default_snapshot_with_interleave(scope_kind, scope_id, || {})
    }

    fn default_snapshot_with_interleave(
        &self,
        scope_kind: &str,
        scope_id: &str,
        after_pointer: impl FnOnce(),
    ) -> Result<Option<Activation>> {
        // The pointer, admission state, and strict reopen must observe one
        // SQLite snapshot. A writer can otherwise revoke or switch the default
        // between these reads and make the result inconsistent.
        let read = self.connection.unchecked_transaction()?;
        let Some(activation) = self.activation_pointer(scope_kind, scope_id)? else {
            return Ok(None);
        };
        after_pointer();
        let invalidated: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM semantic_legacy_activation_quarantine)
                OR EXISTS(SELECT 1 FROM semantic_invalidated_activation_scopes
                          WHERE scope_kind=?1 AND scope_id=?2)",
            params![scope_kind, scope_id],
            |row| row.get(0),
        )?;
        if invalidated {
            return Ok(None);
        }
        let snapshot_id = &activation.snapshot_id;
        let state: String = self
            .connection
            .query_row(
                "SELECT state FROM semantic_current_usable_snapshots WHERE snapshot_id=?1",
                [&snapshot_id],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or_default();
        if state != "ADMITTED" {
            return Ok(None);
        }
        self.open_snapshot(snapshot_id)?;
        read.commit()?;
        Ok(Some(activation))
    }
}

fn defer_entry_fk_until_admission(
    transaction: &rusqlite::Transaction<'_>,
    snapshot_id: &str,
) -> Result<bool> {
    let already_admitted: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM registry_snapshot_admissions WHERE snapshot_id=?1)",
        [snapshot_id],
        |row| row.get(0),
    )?;
    if !already_admitted {
        // Entries reference admissions in 0012. Defer that FK within this
        // transaction so the complete entry set can precede publication.
        transaction.execute_batch("PRAGMA defer_foreign_keys=ON")?;
    }
    Ok(already_admitted)
}

fn publish_admission(
    transaction: &rusqlite::Transaction<'_>,
    snapshot_id: &str,
    already_admitted: bool,
) -> Result<()> {
    if !already_admitted {
        transaction.execute(
            "INSERT INTO registry_snapshot_admissions(snapshot_id,state) VALUES (?1,'ADMITTED')",
            [snapshot_id],
        )?;
    }
    Ok(())
}

fn insert_contract(
    transaction: &rusqlite::Transaction<'_>,
    table: &str,
    hash: &str,
    id: &str,
    version: &str,
    json: &str,
) -> Result<()> {
    let sql = match table {
        "semantic_type_contracts" => {
            "INSERT INTO semantic_type_contracts(content_hash,semantic_id,full_version,contract_json) SELECT ?1,?2,?3,?4 WHERE NOT EXISTS (SELECT 1 FROM semantic_type_contracts WHERE content_hash=?1)"
        }
        "semantic_capability_contracts" => {
            "INSERT INTO semantic_capability_contracts(content_hash,semantic_id,full_version,contract_json) SELECT ?1,?2,?3,?4 WHERE NOT EXISTS (SELECT 1 FROM semantic_capability_contracts WHERE content_hash=?1)"
        }
        _ => return Err(RegistryStoreError::Conflict("unknown contract table")),
    };
    transaction.execute(sql, params![hash, id, version, json])?;
    let read_sql = match table {
        "semantic_type_contracts" => {
            "SELECT semantic_id,full_version,contract_json FROM semantic_type_contracts WHERE content_hash=?1"
        }
        _ => {
            "SELECT semantic_id,full_version,contract_json FROM semantic_capability_contracts WHERE content_hash=?1"
        }
    };
    let stored: (String, String, String) = transaction.query_row(read_sql, [hash], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
    })?;
    if stored.0 != id || stored.1 != version {
        return Err(RegistryStoreError::Conflict(
            "contract hash already maps to different identity",
        ));
    }
    if table == "semantic_type_contracts" {
        let contract: TypeContract = decode_stored(&stored.2, RecordKind::Type)?;
        if contract.type_id != id
            || contract.version != version
            || crate::type_contract_hash(&contract)?.as_str() != hash
        {
            return Err(RegistryStoreError::Conflict(
                "stored type contract differs semantically",
            ));
        }
    } else {
        let contract: CapabilityContract = decode_stored(&stored.2, RecordKind::Capability)?;
        if contract.capability != id
            || contract.version != version
            || crate::capability_contract_hash(&contract)?.as_str() != hash
        {
            return Err(RegistryStoreError::Conflict(
                "stored capability contract differs semantically",
            ));
        }
    }
    Ok(())
}

fn insert_entry(
    transaction: &rusqlite::Transaction<'_>,
    snapshot_id: &str,
    class: &str,
    id: &str,
    major: u64,
    version: &str,
    hash: &str,
) -> Result<()> {
    let major = i64::try_from(major)
        .map_err(|_| RegistryStoreError::Conflict("semantic major exceeds SQLite integer range"))?;
    transaction.execute(
        "INSERT INTO registry_snapshot_entries(snapshot_id,contract_class,semantic_id,major,full_version,content_hash) SELECT ?1,?2,?3,?4,?5,?6 WHERE NOT EXISTS (SELECT 1 FROM registry_snapshot_entries WHERE snapshot_id=?1 AND contract_class=?2 AND semantic_id=?3 AND major=?4)",
        params![snapshot_id,class,id,major,version,hash],
    )?;
    let stored: (String,String) = transaction.query_row(
        "SELECT full_version,content_hash FROM registry_snapshot_entries WHERE snapshot_id=?1 AND contract_class=?2 AND semantic_id=?3 AND major=?4",
        params![snapshot_id,class,id,major], |row| Ok((row.get(0)?,row.get(1)?)),
    )?;
    if stored != (version.to_owned(), hash.to_owned()) {
        return Err(RegistryStoreError::Conflict(
            "snapshot major entry already maps to different contract",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const SNAPSHOT: &str = include_str!("../../../examples/aios-ir/registry-snapshot.json");
    const TYPES: &str = include_str!("../../../examples/aios-ir/type-contracts.json");
    const CAPABILITIES: &str = include_str!("../../../examples/aios-ir/capability-contracts.json");

    fn baseline(connection: &Connection) {
        connection
            .execute_batch(include_str!("../../../specs/persistence-v0.1.sql"))
            .unwrap();
        connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(migration_id,checksum,applied_at) VALUES ('0001_v0_1_trusted_control_plane','UNGENERATED-DRAFT-CHECKSUM','2026-09-19T00:00:00Z')",
            [],
        ).unwrap();
        // Unit fixtures seed an already migrated in-memory/file database. The
        // production migration belongs to Task Manager's fenced transaction.
        connection
            .execute_batch(include_str!(
                "../../../specs/persistence-v0.1-0012-semantic-registry.sql"
            ))
            .unwrap();
        connection.execute(
            "INSERT INTO schema_migrations(migration_id,checksum,applied_at) VALUES (?1,?2,'2026-09-19T00:00:00Z')",
            params![MIGRATION_ID, MIGRATION_CHECKSUM],
        ).unwrap();
        connection
            .execute_batch(include_str!(
                "../../../specs/persistence-v0.1-0014-semantic-repair-fence.sql"
            ))
            .unwrap();
        connection.execute(
            "INSERT INTO schema_migrations(migration_id,checksum,applied_at) VALUES ('0014_semantic_repair_fence','semantic-repair-fence-v0.1','2026-09-19T00:00:00Z')",
            [],
        ).unwrap();
    }

    fn mark_startup_ready(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TEMP TABLE aios_task_manager_startup_ready (
                    nonce TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    fence_epoch INTEGER NOT NULL
                );
                INSERT INTO temp.aios_task_manager_startup_ready(nonce,owner_id,fence_epoch)
                  SELECT c.nonce,l.owner_id,l.fence_epoch
                  FROM temp.aios_store_owner_capability c CROSS JOIN task_manager_lease l
                  WHERE l.singleton_id=1;",
            )
            .unwrap();
    }

    fn fixture_registry() -> SemanticRegistry {
        SemanticRegistry::from_records(
            serde_json::from_str(SNAPSHOT).unwrap(),
            serde_json::from_str(TYPES).unwrap(),
            serde_json::from_str(CAPABILITIES).unwrap(),
            RegistryBuildOptions::default(),
        )
        .unwrap()
    }

    fn second_registry() -> SemanticRegistry {
        let mut snapshot: RegistrySnapshot = serde_json::from_str(SNAPSHOT).unwrap();
        let types: Vec<TypeContract> = serde_json::from_str(TYPES).unwrap();
        let mut capabilities: Vec<CapabilityContract> = serde_json::from_str(CAPABILITIES).unwrap();
        let capability = capabilities
            .iter_mut()
            .find(|c| c.capability == "artifact.hash")
            .unwrap();
        capability.version = "1.1".to_owned();
        let hash = crate::capability_contract_hash(capability)
            .unwrap()
            .to_string();
        let entry = snapshot
            .capability_contracts
            .iter_mut()
            .find(|c| c.id == "artifact.hash")
            .unwrap();
        entry.version = "1.1".to_owned();
        entry.content_hash = hash;
        let as_hash_entry = |entry: &aios_contracts::ContractRef| crate::SnapshotHashEntry {
            id: entry.id.clone(),
            version: entry.version.clone(),
            content_hash: entry.content_hash.clone(),
        };
        snapshot.snapshot_id = crate::registry_snapshot_id(
            &snapshot.schema_version,
            &snapshot
                .type_contracts
                .iter()
                .map(as_hash_entry)
                .collect::<Vec<_>>(),
            &snapshot
                .capability_contracts
                .iter()
                .map(as_hash_entry)
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

    #[test]
    fn retains_two_exact_snapshots_and_cas_default_without_rewriting_old_reference() {
        let mut connection = Connection::open_in_memory().unwrap();
        baseline(&connection);
        // Historical Task Manager tests insert synthetic rows; they are not admissions.
        connection.execute("INSERT INTO registry_snapshots(snapshot_id,manifest_json,created_at) VALUES ('legacy-fixture','{}','2026-09-19T00:00:00Z')", []).unwrap();
        let mut store = RegistryStore::initialize_unfenced_fixture(&mut connection).unwrap();
        assert!(matches!(
            store.open_snapshot("legacy-fixture"),
            Err(RegistryStoreError::NotAdmitted)
        ));
        let first = fixture_registry();
        let second = second_registry();
        let first_id = store.admit_registry(&first).unwrap();
        let second_id = store.admit_registry(&second).unwrap();
        assert_ne!(first_id, second_id);
        assert_eq!(
            store
                .activate_default("user", "u1", None, &first_id)
                .unwrap()
                .revision,
            1
        );
        store.connection.execute(
            "INSERT INTO validation_results(validation_result_id,valid,semantic_hash,registry_snapshot_id,validator_id,validator_version,result_json,validated_at) VALUES ('historical-validation',1,'sha256:1111111111111111111111111111111111111111111111111111111111111111',?1,'validator:test','0.1','{}','2026-09-19T00:00:00Z')",
            [&first_id],
        ).unwrap();
        assert!(matches!(
            store.activate_default("user", "u1", None, &second_id),
            Err(RegistryStoreError::Conflict(_))
        ));
        assert_eq!(
            store
                .activate_default("user", "u1", Some(1), &second_id)
                .unwrap()
                .revision,
            2
        );
        assert_eq!(
            store
                .default_snapshot("user", "u1")
                .unwrap()
                .unwrap()
                .snapshot_id,
            second_id
        );
        let retained: String = store.connection.query_row(
            "SELECT registry_snapshot_id FROM validation_results WHERE validation_result_id='historical-validation'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(retained, first_id);
        assert_eq!(
            retained,
            store.open_snapshot(&first_id).unwrap().snapshot_id()
        );
        store
            .set_snapshot_state(&second_id, SnapshotState::Revoked)
            .unwrap();
        assert!(store.default_snapshot("user", "u1").unwrap().is_none());
        let pointer = store.activation_pointer("user", "u1").unwrap().unwrap();
        assert_eq!(pointer.snapshot_id, second_id);
        assert_eq!(pointer.revision, 2);
        assert_eq!(
            store
                .activate_default("user", "u1", Some(pointer.revision), &first_id)
                .unwrap()
                .revision,
            3
        );
        store
            .set_snapshot_state(&first_id, SnapshotState::Revoked)
            .unwrap();
        assert!(store.open_snapshot(&first_id).is_ok());
        assert!(matches!(
            store.activate_default("user", "u1", Some(3), &first_id),
            Err(RegistryStoreError::NotActivatable)
        ));
        assert!(
            store
                .set_snapshot_state(&first_id, SnapshotState::Admitted)
                .is_err()
        );
    }

    #[test]
    fn direct_sql_cannot_reset_activation_revision_or_replace_pointer() {
        let mut connection = Connection::open_in_memory().unwrap();
        baseline(&connection);
        let mut store = RegistryStore::initialize_unfenced_fixture(&mut connection).unwrap();
        let first_id = store.admit_registry(&fixture_registry()).unwrap();
        let second_id = store.admit_registry(&second_registry()).unwrap();
        let first = store
            .activate_default("user", "u1", None, &first_id)
            .unwrap();
        assert_eq!(first.revision, 1);

        assert!(
            store
                .connection
                .execute(
                    "UPDATE registry_activations SET snapshot_id=?1,revision=1 WHERE scope_kind='user' AND scope_id='u1'",
                    [&second_id],
                )
                .is_err()
        );
        assert!(
            store
                .connection
                .execute(
                    "INSERT OR REPLACE INTO registry_activations(scope_kind,scope_id,snapshot_id,revision) VALUES ('user','u1',?1,99)",
                    [&second_id],
                )
                .is_err()
        );
        assert_eq!(store.activation_pointer("user", "u1").unwrap(), Some(first));

        let second = store
            .activate_default("user", "u1", Some(1), &second_id)
            .unwrap();
        assert_eq!(second.snapshot_id, second_id);
        assert_eq!(second.revision, 2);
        assert!(
            store
                .connection
                .execute(
                    "DELETE FROM registry_activations WHERE scope_kind='user' AND scope_id='u1'",
                    [],
                )
                .is_err()
        );
        assert!(
            store
                .connection
                .execute(
                    "INSERT OR REPLACE INTO registry_activations(scope_kind,scope_id,snapshot_id,revision) VALUES ('user','u1',?1,1)",
                    [&first_id],
                )
                .is_err()
        );
        assert_eq!(
            store.activation_pointer("user", "u1").unwrap(),
            Some(second)
        );
        assert!(
            store
                .activate_default("user", "u1", Some(1), &first_id)
                .is_err()
        );
    }

    #[test]
    fn reopened_file_store_mints_fresh_owner_instead_of_reusing_persisted_lease() {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("control.db");
        let prior = {
            let lock = Arc::new(StoreLock::acquire(&database).unwrap());
            let connection = Connection::open(&database).unwrap();
            baseline(&connection);
            let owner = StoreOwner::claim(&connection, Some(lock), "2026-09-23T00:00:00Z").unwrap();
            (owner.owner().to_owned(), owner.epoch())
        };

        let lock = Arc::new(StoreLock::acquire(&database).unwrap());
        let connection = Connection::open(&database).unwrap();
        let current = StoreOwner::claim(&connection, Some(lock), "2026-09-23T00:01:00Z").unwrap();
        assert_ne!(current.owner(), prior.0);
        assert_eq!(current.epoch(), prior.1 + 1);
        current.verify(&connection).unwrap();
    }

    #[test]
    fn shared_memory_second_connection_cannot_borrow_owner_capability() {
        let uri = "file:registry-second-connection?mode=memory&cache=shared";
        let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
            | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
            | rusqlite::OpenFlags::SQLITE_OPEN_URI;
        let mut owner_connection = Connection::open_with_flags(uri, flags).unwrap();
        baseline(&owner_connection);
        let owner = StoreOwner::claim(&owner_connection, None, "2026-09-23T00:00:00Z").unwrap();
        let mut independent = Connection::open_with_flags(uri, flags).unwrap();
        assert!(StoreOwner::claim(&independent, None, "2026-09-23T00:01:00Z").is_err());
        assert!(RegistryStore::initialize_writer(&mut independent, &owner).is_err());
        assert!(RegistryStore::initialize_in_memory(&mut independent).is_err());
        assert!(RegistryStore::initialize_writer(&mut owner_connection, &owner).is_err());
        mark_startup_ready(&owner_connection);
        let mut store = RegistryStore::initialize_writer(&mut owner_connection, &owner).unwrap();
        assert!(store.admit_registry(&fixture_registry()).is_ok());
    }

    #[test]
    fn file_backed_registry_writer_requires_startup_bound_connection_and_current_lease() {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("control.db");
        let lock = Arc::new(StoreLock::acquire(&database).unwrap());
        let mut owner = Connection::open(&database).unwrap();
        baseline(&owner);
        let owner_cap =
            StoreOwner::claim(&owner, Some(Arc::clone(&lock)), "2026-09-23T00:00:00Z").unwrap();
        assert!(RegistryStore::initialize_writer(&mut owner, &owner_cap).is_err());
        mark_startup_ready(&owner);

        let first = fixture_registry();
        let second = second_registry();
        let first_id = {
            let mut store = RegistryStore::initialize_writer(&mut owner, &owner_cap).unwrap();
            let first_id = store.admit_registry(&first).unwrap();
            store
                .activate_default("user", "u1", None, &first_id)
                .unwrap();
            first_id
        };

        let mut independent = Connection::open(&database).unwrap();
        assert!(RegistryStore::initialize_in_memory(&mut independent).is_err());
        assert!(RegistryStore::initialize_writer(&mut independent, &owner_cap).is_err());
        assert!(
            RegistryStore::initialize(&mut independent)
                .unwrap()
                .admit_registry(&second)
                .is_err()
        );

        let mut stale = RegistryStore::initialize_writer(&mut owner, &owner_cap).unwrap();

        independent
            .execute(
                "UPDATE task_manager_lease SET owner_id='owner-b',fence_epoch=2 WHERE singleton_id=1",
                [],
            )
            .unwrap();
        assert!(stale.admit_registry(&second).is_err());
        assert!(
            stale
                .set_snapshot_state(&first_id, SnapshotState::Revoked)
                .is_err()
        );
        assert!(
            stale
                .activate_default("user", "u1", Some(1), &first_id)
                .is_err()
        );
        assert!(stale.open_snapshot(&first_id).is_ok());
        let admission_state: String = stale
            .connection
            .query_row(
                "SELECT state FROM registry_snapshot_admissions WHERE snapshot_id=?1",
                [&first_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(admission_state, "ADMITTED");
        assert_eq!(
            stale
                .activation_pointer("user", "u1")
                .unwrap()
                .unwrap()
                .revision,
            1
        );
    }

    #[test]
    fn in_memory_fixture_writer_stops_when_manager_lease_appears() {
        let mut connection = Connection::open_in_memory().unwrap();
        baseline(&connection);
        let mut store = RegistryStore::initialize_in_memory(&mut connection).unwrap();
        let first_id = store.admit_registry(&fixture_registry()).unwrap();
        store
            .connection
            .execute(
                "INSERT INTO task_manager_lease(singleton_id,owner_id,fence_epoch,acquired_at) VALUES (1,'owner-a',1,'2026-09-23T00:00:00Z')",
                [],
            )
            .unwrap();
        assert!(store.admit_registry(&second_registry()).is_err());
        assert!(
            store
                .set_snapshot_state(&first_id, SnapshotState::Revoked)
                .is_err()
        );
        assert!(
            store
                .activate_default("user", "u1", None, &first_id)
                .is_err()
        );
        assert_eq!(
            store.open_snapshot(&first_id).unwrap().snapshot_id(),
            first_id
        );
    }

    #[test]
    fn lease_change_during_activation_rolls_back_before_commit() {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("control.db");
        let lock = Arc::new(StoreLock::acquire(&database).unwrap());
        let mut connection = Connection::open(&database).unwrap();
        baseline(&connection);
        let owner_cap =
            StoreOwner::claim(&connection, Some(Arc::clone(&lock)), "2026-09-23T00:00:00Z")
                .unwrap();
        mark_startup_ready(&connection);
        let mut store = RegistryStore::initialize_writer(&mut connection, &owner_cap).unwrap();
        let first_id = store.admit_registry(&fixture_registry()).unwrap();
        let second_id = store.admit_registry(&second_registry()).unwrap();
        let first = store
            .activate_default("user", "u1", None, &first_id)
            .unwrap();

        // A connection-local trigger changes the lease as a side effect of the
        // activation write. The final fence check must abort the entire write.
        store
            .connection
            .execute_batch(
                "CREATE TEMP TRIGGER change_lease_during_activation
                 AFTER UPDATE ON main.registry_activations BEGIN
                   UPDATE task_manager_lease SET owner_id='owner-b',fence_epoch=2 WHERE singleton_id=1;
                 END;",
            )
            .unwrap();
        assert!(
            store
                .activate_default("user", "u1", Some(first.revision), &second_id)
                .is_err()
        );
        assert_eq!(store.activation_pointer("user", "u1").unwrap(), Some(first));
        let lease: (String, i64) = store
            .connection
            .query_row(
                "SELECT owner_id,fence_epoch FROM task_manager_lease WHERE singleton_id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(lease, (owner_cap.owner().to_owned(), owner_cap.epoch()));
    }

    #[test]
    fn default_selection_uses_one_read_snapshot_across_concurrent_revoke_and_switch() {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("control.db");
        let (first_id, second_id) = {
            let mut connection = Connection::open(&database).unwrap();
            connection
                .pragma_update(None, "journal_mode", "WAL")
                .unwrap();
            baseline(&connection);
            let mut store = RegistryStore::initialize_unfenced_fixture(&mut connection).unwrap();
            let first_id = store.admit_registry(&fixture_registry()).unwrap();
            let second_id = store.admit_registry(&second_registry()).unwrap();
            store
                .activate_default("user", "u1", None, &first_id)
                .unwrap();
            (first_id, second_id)
        };

        let mut reader = Connection::open(&database).unwrap();
        let store = RegistryStore::initialize_unfenced_fixture(&mut reader).unwrap();
        let writer = Connection::open(&database).unwrap();
        writer
            .busy_timeout(std::time::Duration::from_secs(5))
            .unwrap();

        // The callback runs after the reader has loaded the old pointer. WAL
        // permits another connection to commit while that read is in flight.
        let selected = store
            .default_snapshot_with_interleave("user", "u1", || {
                writer.execute_batch("BEGIN IMMEDIATE").unwrap();
                writer
                    .execute(
                        "UPDATE registry_snapshot_admissions SET state='REVOKED' WHERE snapshot_id=?1",
                        [&first_id],
                    )
                    .unwrap();
                writer
                    .execute(
                        "UPDATE registry_activations SET snapshot_id=?1,revision=2 WHERE scope_kind='user' AND scope_id='u1'",
                        [&second_id],
                    )
                    .unwrap();
                writer.execute_batch("COMMIT").unwrap();
            })
            .unwrap()
            .unwrap();
        assert_eq!(selected.snapshot_id, first_id);
        assert_eq!(selected.revision, 1);

        // The next call sees the newly committed default and containment.
        let current = store.default_snapshot("user", "u1").unwrap().unwrap();
        assert_eq!(current.snapshot_id, second_id);
        assert_eq!(current.revision, 2);
        assert_eq!(
            writer
                .query_row(
                    "SELECT state FROM registry_snapshot_admissions WHERE snapshot_id=?1",
                    [&first_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "REVOKED"
        );
    }

    #[test]
    fn direct_sql_cannot_reverse_containment_or_restore_a_default_after_reopen() {
        for contained_state in [SnapshotState::Quarantined, SnapshotState::Revoked] {
            let temp = tempfile::tempdir().unwrap();
            let database = temp.path().join("control.db");
            let (id, activation) = {
                let mut connection = Connection::open(&database).unwrap();
                baseline(&connection);
                let mut store =
                    RegistryStore::initialize_unfenced_fixture(&mut connection).unwrap();
                let id = store.admit_registry(&fixture_registry()).unwrap();
                let activation = store.activate_default("user", "u1", None, &id).unwrap();
                store
                    .connection
                    .execute(
                        "UPDATE registry_snapshot_admissions SET state=?2 WHERE snapshot_id=?1",
                        params![id, contained_state.as_str()],
                    )
                    .unwrap();
                for attempted_state in ["ADMITTED", "DEPRECATED"] {
                    assert!(store.connection.execute(
                        "UPDATE registry_snapshot_admissions SET state=?2 WHERE snapshot_id=?1",
                        params![id, attempted_state],
                    ).is_err(), "{contained_state:?} -> {attempted_state}");
                    assert!(store.connection.execute(
                        "INSERT OR REPLACE INTO registry_snapshot_admissions(snapshot_id,state) VALUES (?1,?2)",
                        params![id, attempted_state],
                    ).is_err(), "REPLACE {contained_state:?} -> {attempted_state}");
                }
                assert!(store.default_snapshot("user", "u1").unwrap().is_none());
                (id, activation)
            };

            let mut connection = Connection::open(&database).unwrap();
            let mut store = RegistryStore::initialize_unfenced_fixture(&mut connection).unwrap();
            assert_eq!(
                store.activation_pointer("user", "u1").unwrap(),
                Some(activation.clone())
            );
            assert!(store.default_snapshot("user", "u1").unwrap().is_none());
            assert_eq!(store.open_snapshot(&id).unwrap().snapshot_id(), id);
            assert!(matches!(
                store.activate_default("user", "u1", Some(activation.revision), &id),
                Err(RegistryStoreError::NotActivatable)
            ));
            let state: String = store
                .connection
                .query_row(
                    "SELECT state FROM registry_snapshot_admissions WHERE snapshot_id=?1",
                    [&id],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(state, contained_state.as_str());
        }
    }

    #[test]
    fn stamped_0012_store_with_missing_guards_requires_fenced_upgrade() {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("control.db");
        let id = {
            let mut connection = Connection::open(&database).unwrap();
            baseline(&connection);
            let mut store = RegistryStore::initialize_unfenced_fixture(&mut connection).unwrap();
            let id = store.admit_registry(&fixture_registry()).unwrap();
            store
                .set_snapshot_state(&id, SnapshotState::Quarantined)
                .unwrap();
            store
                .connection
                .execute_batch("DROP TRIGGER one_way_registry_snapshot_admissions_update")
                .unwrap();
            store
                .connection
                .execute_batch(
                    "DROP TRIGGER immutable_registry_snapshot_admissions_reinsert;
                 DROP TRIGGER immutable_admitted_registry_snapshots_reinsert;
                 DROP TRIGGER immutable_admitted_registry_snapshots_target_update;
                 DROP TRIGGER immutable_semantic_type_contracts_reinsert;
                 DROP TRIGGER immutable_semantic_capability_contracts_reinsert;
                 DROP TRIGGER immutable_registry_snapshot_entries_reinsert;
                 DROP TRIGGER immutable_admitted_registry_snapshot_entries_insert;",
                )
                .unwrap();
            id
        };

        let mut connection = Connection::open(&database).unwrap();
        assert!(RegistryStore::initialize_unfenced_fixture(&mut connection).is_err());
        connection
            .execute_batch(include_str!(
                "../../../specs/persistence-v0.1-0012-semantic-registry.sql"
            ))
            .unwrap();
        let store = RegistryStore::initialize_unfenced_fixture(&mut connection).unwrap();
        assert!(
            store
                .connection
                .execute(
                    "UPDATE registry_snapshot_admissions SET state='ADMITTED' WHERE snapshot_id=?1",
                    [&id],
                )
                .is_err()
        );
        assert!(store.connection.execute(
            "INSERT OR REPLACE INTO registry_snapshot_admissions(snapshot_id,state) VALUES (?1,'ADMITTED')",
            [&id],
        ).is_err());
        let original_manifest: String = store
            .connection
            .query_row(
                "SELECT manifest_json FROM registry_snapshots WHERE snapshot_id=?1",
                [&id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(store.connection.execute(
            "INSERT OR REPLACE INTO registry_snapshots(snapshot_id,manifest_json,created_at) VALUES (?1,'{}','2026-09-19T00:00:00Z')",
            [&id],
        ).is_err());
        let retained_manifest: String = store
            .connection
            .query_row(
                "SELECT manifest_json FROM registry_snapshots WHERE snapshot_id=?1",
                [&id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retained_manifest, original_manifest);
        assert!(store.connection.execute(
            "INSERT INTO registry_snapshot_entries(snapshot_id,contract_class,semantic_id,major,full_version,content_hash) VALUES (?1,'type','forged.type',1,'1.0','sha256:0000000000000000000000000000000000000000000000000000000000000000')",
            [&id],
        ).is_err());
        let retained: (String, String) = store.connection.query_row(
            "SELECT s.snapshot_id,a.state FROM registry_snapshots s JOIN registry_snapshot_admissions a USING(snapshot_id) WHERE s.snapshot_id=?1",
            [&id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert_eq!(retained, (id.clone(), "QUARANTINED".to_owned()));
        assert_eq!(store.open_snapshot(&id).unwrap().snapshot_id(), id);
        let (count, checksum): (i64, String) = store
            .connection
            .query_row(
                "SELECT COUNT(*),MIN(checksum) FROM schema_migrations WHERE migration_id=?1",
                [MIGRATION_ID],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((count, checksum.as_str()), (1, MIGRATION_CHECKSUM));
    }

    #[test]
    fn same_semantic_identity_accepts_excluded_metadata_without_overwrite() {
        let mut connection = Connection::open_in_memory().unwrap();
        baseline(&connection);
        let mut store = RegistryStore::initialize_unfenced_fixture(&mut connection).unwrap();
        let original = fixture_registry();
        let id = store.admit_registry(&original).unwrap();
        let original_manifest: String = store
            .connection
            .query_row(
                "SELECT manifest_json FROM registry_snapshots WHERE snapshot_id=?1",
                [&id],
                |row| row.get(0),
            )
            .unwrap();
        let original_contract: String = store.connection.query_row(
            "SELECT contract_json FROM semantic_capability_contracts WHERE semantic_id='artifact.hash'", [], |row| row.get(0),
        ).unwrap();
        let mut snapshot = original.snapshot().clone();
        snapshot.generation = Some("alternate-label".to_owned());
        snapshot.notes.push("different editorial note".to_owned());
        let types = original.type_contracts().cloned().collect();
        let mut capabilities: Vec<CapabilityContract> =
            original.capability_contracts().cloned().collect();
        capabilities
            .iter_mut()
            .find(|c| c.capability == "artifact.hash")
            .unwrap()
            .description = Some("alternate prose".to_owned());
        let alternative = SemanticRegistry::from_records(
            snapshot,
            types,
            capabilities,
            RegistryBuildOptions::default(),
        )
        .unwrap();
        assert_eq!(alternative.snapshot_id(), id);
        assert_eq!(store.admit_registry(&alternative).unwrap(), id);
        let retained_manifest: String = store
            .connection
            .query_row(
                "SELECT manifest_json FROM registry_snapshots WHERE snapshot_id=?1",
                [&id],
                |row| row.get(0),
            )
            .unwrap();
        let retained_contract: String = store.connection.query_row(
            "SELECT contract_json FROM semantic_capability_contracts WHERE semantic_id='artifact.hash'", [], |row| row.get(0),
        ).unwrap();
        assert_eq!(retained_manifest, original_manifest);
        assert_eq!(retained_contract, original_contract);
    }

    #[test]
    fn reopens_offline_after_source_bundle_is_deleted() {
        let temp = tempfile::tempdir().unwrap();
        let bundle = temp.path().join("bundle");
        fs::create_dir(&bundle).unwrap();
        fs::write(bundle.join("registry-snapshot.json"), SNAPSHOT).unwrap();
        fs::write(bundle.join("type-contracts.json"), TYPES).unwrap();
        fs::write(bundle.join("capability-contracts.json"), CAPABILITIES).unwrap();
        let database = temp.path().join("control.db");
        let snapshot_id = {
            let mut connection = Connection::open(&database).unwrap();
            baseline(&connection);
            RegistryStore::initialize_unfenced_fixture(&mut connection)
                .unwrap()
                .admit_bundle(&bundle)
                .unwrap()
        };
        fs::remove_dir_all(&bundle).unwrap();
        let mut connection = Connection::open(&database).unwrap();
        let store = RegistryStore::initialize_unfenced_fixture(&mut connection).unwrap();
        let reopened = store.open_snapshot(&snapshot_id).unwrap();
        assert!(
            reopened
                .resolve_capability("artifact.hash@1")
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn rejects_entry_append_and_blocks_direct_mutation() {
        let mut connection = Connection::open_in_memory().unwrap();
        baseline(&connection);
        let mut store = RegistryStore::initialize_unfenced_fixture(&mut connection).unwrap();
        let id = store.admit_registry(&fixture_registry()).unwrap();
        assert!(
            store
                .connection
                .execute(
                    "UPDATE registry_snapshots SET manifest_json='{}' WHERE snapshot_id=?1",
                    [&id]
                )
                .is_err()
        );
        let entries_before: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM registry_snapshot_entries WHERE snapshot_id=?1",
                [&id],
                |row| row.get(0),
            )
            .unwrap();
        let append_error = store.connection.execute(
            "INSERT INTO registry_snapshot_entries(snapshot_id,contract_class,semantic_id,major,full_version,content_hash) VALUES (?1,'type','forged.type',1,'1.0','sha256:0000000000000000000000000000000000000000000000000000000000000000')",
            [&id],
        ).unwrap_err();
        assert!(
            append_error
                .to_string()
                .contains("admitted registry snapshot entry set is immutable")
        );
        assert!(store.open_snapshot(&id).is_ok());
        store
            .connection
            .execute(
                "DELETE FROM registry_snapshot_entries WHERE snapshot_id=?1",
                [&id],
            )
            .unwrap_err();
        let entries_after: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM registry_snapshot_entries WHERE snapshot_id=?1",
                [&id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(entries_after, entries_before);
        let admissions: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM registry_snapshot_admissions",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(admissions, 1);
    }

    #[test]
    fn published_entry_set_stays_complete_and_immutable_after_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("control.db");
        let id = {
            let mut connection = Connection::open(&database).unwrap();
            baseline(&connection);
            let mut store = RegistryStore::initialize_unfenced_fixture(&mut connection).unwrap();
            let id = store.admit_registry(&fixture_registry()).unwrap();
            store.activate_default("user", "u1", None, &id).unwrap();
            let expected_entries: i64 = store
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM registry_snapshot_entries WHERE snapshot_id=?1",
                    [&id],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(expected_entries > 0);
            let error = store.connection.execute(
                "INSERT INTO registry_snapshot_entries(snapshot_id,contract_class,semantic_id,major,full_version,content_hash) VALUES (?1,'type','forged.type',1,'1.0','sha256:0000000000000000000000000000000000000000000000000000000000000000')",
                [&id],
            ).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("admitted registry snapshot entry set is immutable")
            );
            id
        };

        let mut connection = Connection::open(&database).unwrap();
        let mut store = RegistryStore::initialize_unfenced_fixture(&mut connection).unwrap();
        assert_eq!(store.admit_registry(&fixture_registry()).unwrap(), id);
        assert_eq!(
            store
                .default_snapshot("user", "u1")
                .unwrap()
                .unwrap()
                .snapshot_id,
            id
        );
        assert_eq!(store.open_snapshot(&id).unwrap().snapshot_id(), id);
        let mut fk_check = store
            .connection
            .prepare("PRAGMA foreign_key_check")
            .unwrap();
        assert!(fk_check.query([]).unwrap().next().unwrap().is_none());
        let deferral: i64 = store
            .connection
            .query_row("PRAGMA defer_foreign_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(deferral, 0);
    }

    #[test]
    fn stamped_same_name_noop_entry_guard_fails_before_migration_ddl() {
        let mut connection = Connection::open_in_memory().unwrap();
        baseline(&connection);
        RegistryStore::initialize_unfenced_fixture(&mut connection).unwrap();
        connection
            .execute_batch(
                "DROP TRIGGER immutable_admitted_registry_snapshot_entries_insert;
             CREATE TRIGGER immutable_admitted_registry_snapshot_entries_insert
             BEFORE INSERT ON registry_snapshot_entries BEGIN SELECT 1; END;",
            )
            .unwrap();
        let before: String = connection.query_row(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name='immutable_admitted_registry_snapshot_entries_insert'",
            [],
            |row| row.get(0),
        ).unwrap();
        assert!(matches!(
            RegistryStore::initialize_unfenced_fixture(&mut connection),
            Err(RegistryStoreError::Conflict(
                "semantic registry admission guard definition mismatch"
            ))
        ));
        let after: String = connection.query_row(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name='immutable_admitted_registry_snapshot_entries_insert'",
            [],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(after, before);
    }

    #[test]
    fn stamped_legacy_immutability_guard_rejects_noop_but_accepts_line_endings() {
        let mut connection = Connection::open_in_memory().unwrap();
        baseline(&connection);
        RegistryStore::initialize_unfenced_fixture(&mut connection).unwrap();
        let name = "immutable_registry_snapshot_entries_update";
        let canonical: String = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                [name],
                |row| row.get(0),
            )
            .unwrap();
        connection
            .execute_batch(&format!(
                "DROP TRIGGER {name}; CREATE TRIGGER {name} BEFORE UPDATE ON registry_snapshot_entries BEGIN SELECT 1; END;"
            ))
            .unwrap();
        assert!(matches!(
            RegistryStore::initialize_unfenced_fixture(&mut connection),
            Err(RegistryStoreError::Conflict(
                "semantic registry schema definition mismatch"
            ))
        ));
        connection
            .execute_batch(&format!("DROP TRIGGER {name}"))
            .unwrap();
        let alternate_line_endings = canonical.replace("\r\n", "\n").replace('\n', "\r\n");
        connection.execute_batch(&alternate_line_endings).unwrap();
        RegistryStore::initialize_unfenced_fixture(&mut connection).unwrap();
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "checks each immutable row before and after direct SQL replacement attempts"
    )]
    fn direct_sql_replace_cannot_rewrite_immutable_registry_rows() {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("control.db");
        let id = {
            let mut connection = Connection::open(&database).unwrap();
            baseline(&connection);
            let mut store = RegistryStore::initialize_unfenced_fixture(&mut connection).unwrap();
            let id = store.admit_registry(&fixture_registry()).unwrap();
            let snapshot: (String, String) = store
                .connection
                .query_row(
                    "SELECT snapshot_id,manifest_json FROM registry_snapshots WHERE snapshot_id=?1",
                    [&id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            let type_contract: (String, String, String, String) = store.connection.query_row(
                "SELECT content_hash,semantic_id,full_version,contract_json FROM semantic_type_contracts ORDER BY content_hash LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            ).unwrap();
            let capability_contract: (String, String, String, String) = store.connection.query_row(
                "SELECT content_hash,semantic_id,full_version,contract_json FROM semantic_capability_contracts ORDER BY content_hash LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            ).unwrap();
            let entry: (String, String, String, i64, String, String) = store.connection.query_row(
                "SELECT snapshot_id,contract_class,semantic_id,major,full_version,content_hash FROM registry_snapshot_entries WHERE snapshot_id=?1 ORDER BY contract_class,semantic_id LIMIT 1",
                [&id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
            ).unwrap();
            let entry_major = entry.3.to_string();

            store.connection.execute(
                "INSERT INTO registry_snapshots(snapshot_id,manifest_json,created_at) VALUES ('unadmitted-update-source','{}','2026-09-19T00:00:00Z')",
                [],
            ).unwrap();
            let update_error = store.connection.execute(
                "UPDATE OR REPLACE registry_snapshots SET snapshot_id=?1 WHERE snapshot_id='unadmitted-update-source'",
                [&id],
            ).unwrap_err();
            assert!(
                update_error
                    .to_string()
                    .contains("admitted registry snapshot cannot be replaced")
            );

            for (sql, parameters, reason) in [
                (
                    "INSERT OR REPLACE INTO registry_snapshots(snapshot_id,manifest_json,created_at) VALUES (?1,'{}','2026-09-19T00:00:00Z')",
                    vec![id.as_str()],
                    "admitted registry snapshot cannot be replaced",
                ),
                (
                    "INSERT OR REPLACE INTO semantic_type_contracts(content_hash,semantic_id,full_version,contract_json) VALUES (?1,?2,'9.9','{}')",
                    vec![type_contract.0.as_str(), type_contract.1.as_str()],
                    "semantic type contract cannot be replaced",
                ),
                (
                    "INSERT OR REPLACE INTO semantic_capability_contracts(content_hash,semantic_id,full_version,contract_json) VALUES (?1,?2,'9.9','{}')",
                    vec![
                        capability_contract.0.as_str(),
                        capability_contract.1.as_str(),
                    ],
                    "semantic capability contract cannot be replaced",
                ),
                (
                    "INSERT OR REPLACE INTO registry_snapshot_entries(snapshot_id,contract_class,semantic_id,major,full_version,content_hash) VALUES (?1,?2,?3,?4,'9.9',?5)",
                    vec![
                        entry.0.as_str(),
                        entry.1.as_str(),
                        entry.2.as_str(),
                        entry_major.as_str(),
                        entry.5.as_str(),
                    ],
                    "admitted registry snapshot entry set is immutable",
                ),
            ] {
                let error = store
                    .connection
                    .execute(sql, rusqlite::params_from_iter(parameters))
                    .unwrap_err();
                assert!(error.to_string().contains(reason), "{error}");
            }
            assert_eq!(store.connection.query_row(
                "SELECT snapshot_id,manifest_json FROM registry_snapshots WHERE snapshot_id=?1", [&id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).unwrap(), snapshot);
            assert_eq!(store.connection.query_row(
                "SELECT content_hash,semantic_id,full_version,contract_json FROM semantic_type_contracts WHERE content_hash=?1", [&type_contract.0],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            ).unwrap(), type_contract);
            assert_eq!(store.connection.query_row(
                "SELECT content_hash,semantic_id,full_version,contract_json FROM semantic_capability_contracts WHERE content_hash=?1", [&capability_contract.0],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            ).unwrap(), capability_contract);
            assert_eq!(store.connection.query_row(
                "SELECT snapshot_id,contract_class,semantic_id,major,full_version,content_hash FROM registry_snapshot_entries WHERE snapshot_id=?1 AND contract_class=?2 AND semantic_id=?3 AND major=?4",
                params![&entry.0, &entry.1, &entry.2, entry.3],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
            ).unwrap(), entry);
            id
        };

        let mut connection = Connection::open(&database).unwrap();
        let store = RegistryStore::initialize_unfenced_fixture(&mut connection).unwrap();
        assert_eq!(store.open_snapshot(&id).unwrap().snapshot_id(), id);
    }

    #[test]
    fn rejects_tampered_stored_contract_on_reopen() {
        let mut connection = Connection::open_in_memory().unwrap();
        baseline(&connection);
        let mut store = RegistryStore::initialize_unfenced_fixture(&mut connection).unwrap();
        let id = store.admit_registry(&fixture_registry()).unwrap();
        store
            .connection
            .execute_batch("DROP TRIGGER immutable_semantic_capability_contracts_update")
            .unwrap();
        store.connection.execute(
            "UPDATE semantic_capability_contracts SET contract_json='{}' WHERE semantic_id='artifact.hash'",
            [],
        ).unwrap();
        assert!(store.open_snapshot(&id).is_err());
    }

    #[test]
    fn corrupt_admission_can_be_contained_without_rewriting_history() {
        for containment in [SnapshotState::Quarantined, SnapshotState::Revoked] {
            let mut connection = Connection::open_in_memory().unwrap();
            baseline(&connection);
            let mut store = RegistryStore::initialize_unfenced_fixture(&mut connection).unwrap();
            let id = store.admit_registry(&fixture_registry()).unwrap();
            let original_manifest: String = store
                .connection
                .query_row(
                    "SELECT manifest_json FROM registry_snapshots WHERE snapshot_id=?1",
                    [&id],
                    |row| row.get(0),
                )
                .unwrap();
            let activation = store.activate_default("user", "u1", None, &id).unwrap();
            store
                .connection
                .execute_batch("DROP TRIGGER immutable_semantic_capability_contracts_update")
                .unwrap();
            store
                .connection
                .execute(
                    "UPDATE semantic_capability_contracts SET contract_json='{}' WHERE semantic_id='artifact.hash'",
                    [],
                )
                .unwrap();

            assert!(store.open_snapshot(&id).is_err());
            assert!(
                store
                    .set_snapshot_state(&id, SnapshotState::Deprecated)
                    .is_err()
            );
            assert!(store.activate_default("user", "u2", None, &id).is_err());
            let state: String = store
                .connection
                .query_row(
                    "SELECT state FROM registry_snapshot_admissions WHERE snapshot_id=?1",
                    [&id],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(state, "ADMITTED");

            store.set_snapshot_state(&id, containment).unwrap();
            assert!(store.default_snapshot("user", "u1").unwrap().is_none());
            assert_eq!(
                store.activation_pointer("user", "u1").unwrap(),
                Some(activation)
            );
            assert!(store.open_snapshot(&id).is_err());
            let retained: (String, String, String) = store
                .connection
                .query_row(
                    "SELECT s.manifest_json, a.state, c.contract_json FROM registry_snapshots s JOIN registry_snapshot_admissions a USING(snapshot_id) JOIN registry_snapshot_entries e USING(snapshot_id) JOIN semantic_capability_contracts c ON c.content_hash=e.content_hash WHERE s.snapshot_id=?1 AND e.semantic_id='artifact.hash'",
                    [&id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            assert_eq!(
                retained,
                (
                    original_manifest,
                    containment.as_str().to_owned(),
                    "{}".to_owned()
                )
            );
            if containment == SnapshotState::Quarantined {
                store
                    .set_snapshot_state(&id, SnapshotState::Revoked)
                    .unwrap();
                assert!(
                    store
                        .set_snapshot_state(&id, SnapshotState::Admitted)
                        .is_err()
                );
            }
        }
    }

    #[test]
    fn cannot_contain_unadmitted_snapshot() {
        let mut connection = Connection::open_in_memory().unwrap();
        baseline(&connection);
        let mut store = RegistryStore::initialize_unfenced_fixture(&mut connection).unwrap();
        assert!(matches!(
            store.set_snapshot_state("missing", SnapshotState::Revoked),
            Err(RegistryStoreError::NotAdmitted)
        ));
    }

    #[test]
    fn persisted_underflow_token_fails_before_typed_numeric_rounding() {
        let mut connection = Connection::open_in_memory().unwrap();
        baseline(&connection);
        let mut store = RegistryStore::initialize_unfenced_fixture(&mut connection).unwrap();
        let id = store.admit_registry(&fixture_registry()).unwrap();
        let json: String = store.connection.query_row(
            "SELECT contract_json FROM semantic_capability_contracts WHERE semantic_id='stats.compare_periods'",
            [], |row| row.get(0),
        ).unwrap();
        let needle = "\"numeric_absolute_tolerance\":";
        let start = json.find(needle).unwrap() + needle.len();
        let end = json[start..].find([',', '}']).unwrap() + start;
        let mut hostile = json.clone();
        hostile.replace_range(start..end, "1e-10000");
        store
            .connection
            .execute_batch("DROP TRIGGER immutable_semantic_capability_contracts_update")
            .unwrap();
        store.connection.execute(
            "UPDATE semantic_capability_contracts SET contract_json=?1 WHERE semantic_id='stats.compare_periods'",
            [&hostile],
        ).unwrap();
        assert!(store.open_snapshot(&id).is_err());
    }

    #[test]
    fn migration_preflight_rejects_unknown_bad_checksum_and_incomplete_stamp() {
        for mutation in ["unknown", "checksum", "missing-trigger"] {
            let mut connection = Connection::open_in_memory().unwrap();
            baseline(&connection);
            match mutation {
                "unknown" => {
                    connection.execute(
                    "INSERT INTO schema_migrations(migration_id,checksum,applied_at) VALUES ('9999_future','x','2026-09-19T00:00:00Z')", [],
                ).unwrap();
                }
                "checksum" => {
                    connection
                        .execute(
                            "UPDATE schema_migrations SET checksum='wrong' WHERE migration_id=?1",
                            [MIGRATION_ID],
                        )
                        .unwrap();
                }
                _ => {
                    RegistryStore::initialize_unfenced_fixture(&mut connection).unwrap();
                    connection
                        .execute_batch("DROP TRIGGER immutable_registry_snapshot_entries_delete")
                        .unwrap();
                }
            }
            assert!(
                RegistryStore::initialize_unfenced_fixture(&mut connection).is_err(),
                "{mutation}"
            );
            let present: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='immutable_registry_snapshot_entries_delete')",
                [], |row| row.get(0),
            ).unwrap();
            assert_eq!(present, mutation != "missing-trigger", "{mutation}");
        }
    }

    #[test]
    fn migration_preflight_rejects_changed_table_ddl_and_orphaned_rows() {
        let mut changed = Connection::open_in_memory().unwrap();
        baseline(&changed);
        changed
            .execute_batch("ALTER TABLE registry_activations ADD COLUMN bypass TEXT")
            .unwrap();
        assert!(matches!(
            RegistryStore::initialize_unfenced_fixture(&mut changed),
            Err(RegistryStoreError::Conflict(
                "semantic registry schema definition mismatch"
            ))
        ));

        let mut orphaned = Connection::open_in_memory().unwrap();
        baseline(&orphaned);
        orphaned.pragma_update(None, "foreign_keys", "OFF").unwrap();
        orphaned
            .execute(
                "INSERT INTO registry_snapshot_admissions(snapshot_id,state) VALUES ('missing','ADMITTED')",
                [],
            )
            .unwrap();
        assert!(matches!(
            RegistryStore::initialize_unfenced_fixture(&mut orphaned),
            Err(RegistryStoreError::Conflict(
                "control-plane foreign key integrity violation"
            ))
        ));
    }

    #[test]
    fn preseeded_contract_conflict_rolls_back_all_new_admission_rows() {
        let mut connection = Connection::open_in_memory().unwrap();
        baseline(&connection);
        let mut store = RegistryStore::initialize_unfenced_fixture(&mut connection).unwrap();
        let registry = fixture_registry();
        let contract = registry.capability_contract("artifact.hash", 1).unwrap();
        let hash = registry
            .capability_contract_hash("artifact.hash", 1)
            .unwrap();
        store.connection.execute(
            "INSERT INTO semantic_capability_contracts(content_hash,semantic_id,full_version,contract_json) VALUES (?1,?2,?3,'{}')",
            params![hash.as_str(), contract.capability, contract.version],
        ).unwrap();
        assert!(store.admit_registry(&registry).is_err());
        let counts: (i64, i64, i64) = store
            .connection
            .query_row(
                "SELECT (SELECT COUNT(*) FROM registry_snapshots),
                    (SELECT COUNT(*) FROM registry_snapshot_admissions),
                    (SELECT COUNT(*) FROM registry_snapshot_entries)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(counts, (0, 0, 0));
    }

    #[test]
    fn invalid_bundle_admission_is_atomic() {
        let temp = tempfile::tempdir().unwrap();
        let bundle = temp.path().join("bundle");
        fs::create_dir(&bundle).unwrap();
        fs::write(bundle.join("type-contracts.json"), TYPES).unwrap();
        fs::write(bundle.join("capability-contracts.json"), CAPABILITIES).unwrap();
        let mut connection = Connection::open_in_memory().unwrap();
        baseline(&connection);
        let mut store = RegistryStore::initialize_unfenced_fixture(&mut connection).unwrap();
        let source: serde_json::Value = serde_json::from_str(SNAPSHOT).unwrap();
        for mutation in ["duplicate-major", "missing-source", "hash-mismatch"] {
            let mut snapshot = source.clone();
            match mutation {
                "duplicate-major" => {
                    let entries = snapshot["capability_contracts"].as_array_mut().unwrap();
                    entries.push(entries[0].clone());
                }
                "missing-source" => snapshot["type_contracts"][0]["source"] = "absent.json".into(),
                _ => {
                    snapshot["capability_contracts"][0]["content_hash"] =
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .into();
                }
            }
            fs::write(
                bundle.join("registry-snapshot.json"),
                serde_json::to_vec(&snapshot).unwrap(),
            )
            .unwrap();
            assert!(store.admit_bundle(&bundle).is_err(), "{mutation}");
            let counts: (i64, i64, i64) = store
                .connection
                .query_row(
                    "SELECT (SELECT COUNT(*) FROM registry_snapshot_admissions),
                        (SELECT COUNT(*) FROM semantic_type_contracts),
                        (SELECT COUNT(*) FROM registry_snapshot_entries)",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            assert_eq!(counts, (0, 0, 0), "{mutation}");
        }
    }
}
