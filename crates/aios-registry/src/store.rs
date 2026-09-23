//! Durable, local semantic snapshot admission and default selection.
//!
//! The caller supplies a connection to the trusted control-plane database. This
//! module never discovers contracts, executes providers, or changes Task evidence.

#![allow(
    clippy::missing_errors_doc,
    reason = "the store methods return one coded operational error type"
)]

use std::collections::BTreeSet;
use std::path::Path;

use aios_contracts::{CapabilityContract, RegistrySnapshot, TypeContract};
use rusqlite::{Connection, OptionalExtension, params};

use crate::schema::{self, RecordKind};
use crate::{
    HashVerificationMode, RegistryBuildOptions, RegistryLoadOptions, SemanticRegistry,
    StrictJsonLimits,
};

const MIGRATION_ID: &str = "0012_semantic_registry_store";
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
    ];
    let mut stamped = false;
    let mut baseline = false;
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
    }
    if !baseline {
        return Err(RegistryStoreError::Conflict(
            "trusted control-plane baseline is required",
        ));
    }
    for (kind, name) in STORE_OBJECTS {
        let present: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type=?1 AND name=?2)",
            params![kind, name],
            |row| row.get(0),
        )?;
        if present != stamped {
            return Err(RegistryStoreError::Conflict(
                "semantic registry migration is incomplete or unstamped",
            ));
        }
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
}

impl<'a> RegistryStore<'a> {
    /// Installs additive schema over a Task Manager initialized control-plane DB.
    /// Existing historical fixture rows remain untouched and are not admitted.
    pub fn initialize(connection: &'a mut Connection) -> Result<Self> {
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        preflight_store_migration(connection)?;
        let transaction = connection.transaction()?;
        let existing: Option<String> = transaction
            .query_row(
                "SELECT checksum FROM schema_migrations WHERE migration_id=?1",
                [MIGRATION_ID],
                |row| row.get(0),
            )
            .optional()?;
        if existing.is_none() {
            transaction.execute_batch(include_str!(
                "../../../specs/persistence-v0.1-0012-semantic-registry.sql"
            ))?;
            transaction.execute(
                "INSERT INTO schema_migrations(migration_id,checksum,applied_at) VALUES (?1,?2,strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
                params![MIGRATION_ID, MIGRATION_CHECKSUM],
            )?;
        }
        transaction.commit()?;
        Ok(Self { connection })
    }

    /// Strictly validates an explicitly supplied local bundle before any write.
    pub fn admit_bundle(&mut self, directory: impl AsRef<Path>) -> Result<String> {
        let registry = SemanticRegistry::load_bundle(directory, RegistryLoadOptions::default())?;
        self.admit_registry(&registry)
    }

    /// Persists only a strictly verified, immutable semantic registry.
    pub fn admit_registry(&mut self, registry: &SemanticRegistry) -> Result<String> {
        if !registry.is_strictly_verified() {
            return Err(RegistryStoreError::NotAdmitted);
        }
        let snapshot_id = registry.snapshot_id().to_owned();
        let manifest_json = serde_json::to_string(registry.snapshot())?;
        let transaction = self.connection.transaction()?;
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
        transaction.execute(
            "INSERT OR IGNORE INTO registry_snapshot_admissions(snapshot_id,state) VALUES (?1,'ADMITTED')",
            [&snapshot_id],
        )?;
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
        transaction.commit()?;
        // Read back through the same strict builder; persisted records, rather
        // than caller memory, become the admissible historical source.
        self.open_snapshot(&snapshot_id)?;
        Ok(snapshot_id)
    }

    /// Rebuilds and re-verifies a historical snapshot without source files/network.
    #[allow(
        clippy::too_many_lines,
        reason = "keeps stored manifest and contract re-verification together"
    )]
    pub fn open_snapshot(&self, snapshot_id: &str) -> Result<SemanticRegistry> {
        let manifest_json: Option<String> = self.connection.query_row(
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
        self.open_snapshot(snapshot_id)?;
        let current: String = self.connection.query_row(
            "SELECT state FROM registry_snapshot_admissions WHERE snapshot_id=?1",
            [snapshot_id],
            |row| row.get(0),
        )?;
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
        let affected = self.connection.execute(
            "UPDATE registry_snapshot_admissions SET state=?2 WHERE snapshot_id=?1 AND state=?3",
            params![snapshot_id, state.as_str(), current],
        )?;
        if affected != 1 {
            return Err(RegistryStoreError::Conflict("snapshot state changed"));
        }
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
        if !matches!(scope_kind, "device" | "user" | "organization") || scope_id.is_empty() {
            return Err(RegistryStoreError::Conflict("invalid activation scope"));
        }
        self.open_snapshot(snapshot_id)?;
        let transaction = self.connection.transaction()?;
        let state: Option<String> = transaction
            .query_row(
                "SELECT state FROM registry_snapshot_admissions WHERE snapshot_id=?1",
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
        if current.and_then(|value| u64::try_from(value).ok()) != expected_revision {
            return Err(RegistryStoreError::Conflict("activation revision changed"));
        }
        let next = current
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(RegistryStoreError::Conflict("activation revision overflow"))?;
        transaction.execute(
            "INSERT INTO registry_activations(scope_kind,scope_id,snapshot_id,revision) VALUES (?1,?2,?3,?4)
             ON CONFLICT(scope_kind,scope_id) DO UPDATE SET snapshot_id=excluded.snapshot_id,revision=excluded.revision",
            params![scope_kind, scope_id, snapshot_id, next],
        )?;
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
        let Some(activation) = self.activation_pointer(scope_kind, scope_id)? else {
            return Ok(None);
        };
        let snapshot_id = &activation.snapshot_id;
        let state: String = self.connection.query_row(
            "SELECT state FROM registry_snapshot_admissions WHERE snapshot_id=?1",
            [&snapshot_id],
            |row| row.get(0),
        )?;
        if state != "ADMITTED" {
            return Ok(None);
        }
        self.open_snapshot(snapshot_id)?;
        Ok(Some(activation))
    }
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
            "INSERT OR IGNORE INTO semantic_type_contracts(content_hash,semantic_id,full_version,contract_json) VALUES (?1,?2,?3,?4)"
        }
        "semantic_capability_contracts" => {
            "INSERT OR IGNORE INTO semantic_capability_contracts(content_hash,semantic_id,full_version,contract_json) VALUES (?1,?2,?3,?4)"
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
        "INSERT OR IGNORE INTO registry_snapshot_entries(snapshot_id,contract_class,semantic_id,major,full_version,content_hash) VALUES (?1,?2,?3,?4,?5,?6)",
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
        let mut store = RegistryStore::initialize(&mut connection).unwrap();
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
    fn same_semantic_identity_accepts_excluded_metadata_without_overwrite() {
        let mut connection = Connection::open_in_memory().unwrap();
        baseline(&connection);
        let mut store = RegistryStore::initialize(&mut connection).unwrap();
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
            RegistryStore::initialize(&mut connection)
                .unwrap()
                .admit_bundle(&bundle)
                .unwrap()
        };
        fs::remove_dir_all(&bundle).unwrap();
        let mut connection = Connection::open(&database).unwrap();
        let store = RegistryStore::initialize(&mut connection).unwrap();
        let reopened = store.open_snapshot(&snapshot_id).unwrap();
        assert!(
            reopened
                .resolve_capability("artifact.hash@1")
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn rejects_extra_entry_and_blocks_direct_mutation() {
        let mut connection = Connection::open_in_memory().unwrap();
        baseline(&connection);
        let mut store = RegistryStore::initialize(&mut connection).unwrap();
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
        store.connection.execute(
            "INSERT INTO registry_snapshot_entries(snapshot_id,contract_class,semantic_id,major,full_version,content_hash) VALUES (?1,'type','forged.type',1,'1.0','sha256:0000000000000000000000000000000000000000000000000000000000000000')",
            [&id],
        ).unwrap();
        assert!(matches!(
            store.open_snapshot(&id),
            Err(RegistryStoreError::Conflict(_))
        ));
        store
            .connection
            .execute(
                "DELETE FROM registry_snapshot_entries WHERE semantic_id='forged.type'",
                [],
            )
            .unwrap_err();
        let count: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM registry_snapshot_admissions",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn rejects_tampered_stored_contract_on_reopen() {
        let mut connection = Connection::open_in_memory().unwrap();
        baseline(&connection);
        let mut store = RegistryStore::initialize(&mut connection).unwrap();
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
    fn persisted_underflow_token_fails_before_typed_numeric_rounding() {
        let mut connection = Connection::open_in_memory().unwrap();
        baseline(&connection);
        let mut store = RegistryStore::initialize(&mut connection).unwrap();
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
                    connection.execute(
                    "INSERT INTO schema_migrations(migration_id,checksum,applied_at) VALUES (?1,'wrong','2026-09-19T00:00:00Z')",
                    [MIGRATION_ID],
                ).unwrap();
                }
                _ => {
                    RegistryStore::initialize(&mut connection).unwrap();
                    connection
                        .execute_batch("DROP TRIGGER immutable_registry_snapshot_entries_delete")
                        .unwrap();
                }
            }
            assert!(
                RegistryStore::initialize(&mut connection).is_err(),
                "{mutation}"
            );
            let present: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='immutable_registry_snapshot_entries_delete')",
                [], |row| row.get(0),
            ).unwrap();
            assert!(!present, "{mutation}");
        }
    }

    #[test]
    fn preseeded_contract_conflict_rolls_back_all_new_admission_rows() {
        let mut connection = Connection::open_in_memory().unwrap();
        baseline(&connection);
        let mut store = RegistryStore::initialize(&mut connection).unwrap();
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
        let mut store = RegistryStore::initialize(&mut connection).unwrap();
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
