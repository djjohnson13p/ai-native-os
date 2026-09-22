//! Local, append-oriented AIOS provenance journal primitives.
//!
//! The journal is tamper-evident under verification. It is not tamper-proof
//! against an actor able to rewrite the database and every trusted checkpoint.

#![allow(missing_docs, reason = "public DTO fields mirror the v0.1 contracts")]

use std::fmt;
use std::fmt::Write as _;
use std::sync::OnceLock;

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub const SCHEMA_VERSION: &str = "0.1";
pub const HASH_PROFILE: &str = "aios-provenance-event-v0.1";
pub const MAX_EVENT_BYTES: usize = 65_536;
pub const MAX_DETAILS_BYTES: usize = 32_768;
pub const MAX_JSON_DEPTH: usize = 32;
pub const MAX_PAGE_SIZE: u32 = 256;
/// Maximum canonical JSON size of one privacy-redacted projected event.
///
/// Aliases are deliberately larger than the source strings they replace. This
/// cap covers the maximum 512-item Task step set while keeping offline input
/// independently bounded.
pub const MAX_PROJECTED_EVENT_BYTES: usize = 262_144;
const MAX_PROJECTED_RECORD_BYTES: usize = MAX_PROJECTED_EVENT_BYTES + 4_096;
const MAX_PROJECTION_EXPORT_BYTES: usize = 8 * 1_024 * 1_024;
const MAX_PROJECTION_RECORDS: u64 = 10_000;
const MAX_PROJECTION_SOURCE_BYTES: u64 = 32 * 1_024 * 1_024;
const MAX_STRING_CHARS: usize = 4096;
const MAX_ARRAY_ITEMS: usize = 512;
const MAX_OBJECT_FIELDS: usize = 256;
const HASH_DOMAIN: &[u8] = b"AIOS-PROVENANCE-EVENT\0v0.1\0";
const PROJECTION_HASH_PROFILE: &str = "aios-provenance-redacted-projection-v1";
const PROJECTION_RECORD_DOMAIN: &[u8] = b"AIOS-PROVENANCE-PROJECTION-RECORD\0v1\0";
const PROJECTION_DESCRIPTOR_DOMAIN: &[u8] = b"AIOS-PROVENANCE-PROJECTION-DESCRIPTOR\0v1\0";
const PROJECTION_ALIAS_DOMAIN: &[u8] = b"AIOS-PROVENANCE-PROJECTION-ALIAS\0v1\0";
const EVENT_SCHEMA: &str = include_str!("../../../specs/provenance-event.schema.json");
const PROJECTION_MANIFEST_SCHEMA: &str =
    include_str!("../../../specs/provenance-projection-manifest.schema.json");
const PROJECTED_RECORD_SCHEMA: &str =
    include_str!("../../../specs/provenance-projected-record.schema.json");
const PROJECTION_VERIFICATION_RESULT_SCHEMA: &str =
    include_str!("../../../specs/provenance-projection-verification-result.schema.json");

#[derive(Debug)]
pub enum Error {
    Storage(rusqlite::Error),
    Serialization(serde_json::Error),
    Canonicalization(String),
    InvalidRecord(String),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(formatter, "provenance storage failure: {error}"),
            Self::Serialization(error) => write!(formatter, "provenance JSON failure: {error}"),
            Self::Canonicalization(error) => {
                write!(formatter, "provenance canonicalization failure: {error}")
            }
            Self::InvalidRecord(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for Error {}

impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage(error)
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialization(error)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedHead {
    Any,
    Empty,
    Exact { sequence: u64, event_hash: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamHead {
    pub stream_id: String,
    pub sequence: u64,
    pub event_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalRecord {
    pub schema_version: String,
    pub hash_profile: String,
    pub stream_id: String,
    pub sequence: u64,
    pub previous_event_hash: Option<String>,
    pub event: Value,
    pub event_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordPage {
    pub records: Vec<JournalRecord>,
    pub next_cursor: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationDiagnostic {
    pub severity: Severity,
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierIdentity {
    pub id: String,
    pub version: String,
    pub build_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationResult {
    pub schema_version: String,
    pub valid: bool,
    pub stream_id: String,
    pub from_sequence: u64,
    pub to_sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_head_hash: Option<String>,
    pub computed_head_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint_id: Option<String>,
    pub verifier: VerifierIdentity,
    pub diagnostics: Vec<VerificationDiagnostic>,
    pub diagnostics_truncated: bool,
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointExpectation {
    pub checkpoint_id: String,
    pub event_hash: String,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyExportManifest {
    pub schema_version: String,
    pub export_profile: String,
    pub hash_profile: String,
    pub stream_id: String,
    pub record_count: u64,
    pub head_sequence: u64,
    pub head_event_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionPortableExport {
    pub manifest_json: String,
    pub records_jsonl: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionManifest {
    pub schema_version: String,
    pub export_profile: String,
    pub projection_hash_profile: String,
    pub bundle_id: String,
    pub record_count: u64,
    pub head_sequence: u64,
    pub head_projection_hash: String,
    pub descriptor_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectedRecord {
    pub schema_version: String,
    pub projection_hash_profile: String,
    pub bundle_id: String,
    pub sequence: u64,
    pub previous_projection_hash: Option<String>,
    pub projected_event: Value,
    pub projection_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionVerificationResult {
    pub schema_version: String,
    pub scope: String,
    pub valid: bool,
    pub original_chain_verified_offline: bool,
    pub original_chain_linkage_proven: bool,
    pub bundle_id: String,
    pub from_sequence: u64,
    pub to_sequence: u64,
    pub computed_projection_head_hash: Option<String>,
    pub diagnostics: Vec<VerificationDiagnostic>,
    pub verified_at: String,
}

/// Derives the deterministic opaque stream identity for a validated Task ID.
///
/// # Errors
/// Returns an error when the Task ID cannot satisfy the v0.1 identifier profile.
pub fn stream_id(task_id: &str) -> Result<String> {
    validate_task_id(task_id)?;
    let mut hasher = Sha256::new();
    hasher.update(b"AIOS-TASK-PROVENANCE-STREAM-ID\0v1\0");
    hasher.update(task_id.as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in hasher.finalize() {
        write!(&mut hex, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(format!("task:v1:sha256:{hex}"))
}

/// Validates and appends one event without committing the caller's transaction.
///
/// # Errors
/// Returns an error for invalid events, stale heads, storage failures, or hashing failures.
pub fn append_in_tx(
    transaction: &Transaction<'_>,
    task_id: &str,
    event: &Value,
    expected_head: &ExpectedHead,
) -> Result<JournalRecord> {
    validate_event(task_id, event)?;
    let stream_id = stream_id(task_id)?;
    let head = get_head(transaction, &stream_id)?;
    match (expected_head, &head) {
        (ExpectedHead::Any, _) | (ExpectedHead::Empty, None) => {}
        (
            ExpectedHead::Exact {
                sequence,
                event_hash,
            },
            Some(actual),
        ) if *sequence == actual.sequence && *event_hash == actual.event_hash => {}
        _ => {
            return Err(Error::InvalidRecord(
                "stale provenance stream head".to_owned(),
            ));
        }
    }
    let sequence = head
        .as_ref()
        .map_or(1, |value| value.sequence.saturating_add(1));
    if sequence == u64::MAX {
        return Err(Error::InvalidRecord(
            "provenance sequence overflow".to_owned(),
        ));
    }
    validate_sequence_event_invariant(sequence, event)?;
    let previous_event_hash = head.map(|value| value.event_hash);
    let event_hash = hash_record(&stream_id, sequence, previous_event_hash.as_deref(), event)?;
    let event_id = string_field(event, "event_id")
        .ok_or_else(|| Error::InvalidRecord("validated event has no event ID".to_owned()))?;
    transaction.execute(
        "INSERT INTO provenance_events (schema_version, hash_profile, event_id, task_id, stream_id, sequence, timestamp, event_type, semantic_program_hash, ir_version, registry_snapshot_id, node_id, execution_binding_id, provider_id, status, previous_event_hash, event_hash, event_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
        params![SCHEMA_VERSION, HASH_PROFILE, event_id, task_id, stream_id, i64::try_from(sequence).map_err(|_| Error::InvalidRecord("provenance sequence exceeds SQLite range".to_owned()))?, string_field(event, "timestamp"), string_field(event, "event_type"), string_field(event, "semantic_program_hash"), string_field(event, "ir_version"), string_field(event, "registry_snapshot_id"), string_field(event, "step_id"), string_field(event, "execution_binding_id"), string_field(event, "provider_id"), string_field(event, "status"), previous_event_hash, event_hash, serde_json::to_string(event)?],
    )?;
    Ok(JournalRecord {
        schema_version: SCHEMA_VERSION.to_owned(),
        hash_profile: HASH_PROFILE.to_owned(),
        stream_id,
        sequence,
        previous_event_hash,
        event: event.clone(),
        event_hash,
    })
}

/// Reads the current head of one stream.
///
/// # Errors
/// Returns an error for an invalid stream ID, malformed stored sequence, or storage failure.
pub fn get_head(connection: &Connection, stream_id: &str) -> Result<Option<StreamHead>> {
    validate_stream_id(stream_id)?;
    connection
        .query_row(
            "SELECT sequence, event_hash FROM provenance_events WHERE stream_id=?1 ORDER BY sequence DESC LIMIT 1",
            [stream_id],
            |row| Ok((row.get::<_, i64>(0)?, bounded_row_text(row, 1)?)),
        )
        .optional()?
        .map(|(sequence, event_hash)| {
            if !valid_hash(&event_hash) {
                return Err(Error::InvalidRecord(
                    "stored provenance head hash is invalid".to_owned(),
                ));
            }
            Ok(StreamHead {
                stream_id: stream_id.to_owned(),
                sequence: u64::try_from(sequence).map_err(|_| {
                    Error::InvalidRecord("stored provenance sequence is invalid".to_owned())
                })?,
                event_hash,
            })
        })
        .transpose()
}

/// Reads a bounded page ordered by sequence.
///
/// # Errors
/// Returns an error for invalid bounds, malformed stored records, or storage failure.
pub fn list_events(
    connection: &Connection,
    stream_id: &str,
    after_sequence: Option<u64>,
    limit: u32,
) -> Result<RecordPage> {
    validate_stream_id(stream_id)?;
    if limit == 0 || limit > MAX_PAGE_SIZE {
        return Err(Error::InvalidRecord(
            "provenance page limit is out of bounds".to_owned(),
        ));
    }
    let after = i64::try_from(after_sequence.unwrap_or(0))
        .map_err(|_| Error::InvalidRecord("provenance cursor exceeds SQLite range".to_owned()))?;
    let mut statement = connection.prepare(
        "SELECT schema_version, hash_profile, stream_id, sequence, previous_event_hash, event_json, event_hash FROM provenance_events WHERE stream_id=?1 AND sequence>?2 ORDER BY sequence LIMIT ?3",
    )?;
    let rows = statement.query_map(
        params![stream_id, after, i64::from(limit) + 1],
        row_to_record,
    )?;
    let mut records = rows.collect::<std::result::Result<Vec<_>, _>>()?;
    let next_cursor = if records.len() > limit as usize {
        records.pop();
        records.last().map(|record| record.sequence)
    } else {
        None
    };
    Ok(RecordPage {
        records,
        next_cursor,
    })
}

/// Verifies one stored stream and returns contract-shaped reason-coded diagnostics.
///
/// # Errors
/// Returns an error only when verification cannot run, such as a storage failure or invalid request.
#[allow(clippy::too_many_lines)]
pub fn verify_stream(
    connection: &Connection,
    stream_id: &str,
    through_sequence: Option<u64>,
    checkpoint: Option<&CheckpointExpectation>,
    verified_at: &str,
) -> Result<VerificationResult> {
    validate_stream_id(stream_id)?;
    validate_timestamp(verified_at)?;
    let upper = through_sequence
        .map(i64::try_from)
        .transpose()
        .map_err(|_| {
            Error::InvalidRecord("verification sequence exceeds SQLite range".to_owned())
        })?;
    let mut statement = connection.prepare(
        "SELECT schema_version,hash_profile,stream_id,sequence,previous_event_hash,event_json,event_hash,event_id,task_id,timestamp,event_type,semantic_program_hash,ir_version,registry_snapshot_id,node_id,execution_binding_id,provider_id,status FROM provenance_events WHERE stream_id=?1 AND (?2 IS NULL OR sequence<=?2) ORDER BY sequence",
    )?;
    let rows = statement.query_map(params![stream_id, upper], |row| {
        Ok((
            row_to_record(row)?,
            JournalIndex {
                event_id: bounded_row_text(row, 7)?,
                task_id: bounded_row_text(row, 8)?,
                timestamp: bounded_row_text(row, 9)?,
                event_type: bounded_row_text(row, 10)?,
                semantic_program_hash: bounded_nullable_row_text(row, 11)?,
                ir_version: bounded_nullable_row_text(row, 12)?,
                registry_snapshot_id: bounded_nullable_row_text(row, 13)?,
                node_id: bounded_nullable_row_text(row, 14)?,
                execution_binding_id: bounded_nullable_row_text(row, 15)?,
                provider_id: bounded_nullable_row_text(row, 16)?,
                status: bounded_nullable_row_text(row, 17)?,
            },
        ))
    })?;
    let mut previous: Option<String> = None;
    let mut expected_sequence = 1_u64;
    for row in rows {
        let Ok((record, index)) = row else {
            return Ok(failure(
                stream_id,
                verified_at,
                "PROVENANCE_SCHEMA_INVALID",
                "stored journal record is malformed",
                None,
                None,
                previous,
                checkpoint,
            ));
        };
        let computed = match verify_one_record(
            &record,
            stream_id,
            expected_sequence,
            previous.as_deref(),
            false,
            checkpoint,
            verified_at,
        ) {
            Ok(computed) => computed,
            Err(result) => return Ok(*result),
        };
        if !index.matches(&record.event) {
            return Ok(failure(
                stream_id,
                verified_at,
                "PROVENANCE_SCHEMA_INVALID",
                "journal index columns conflict with the hashed event",
                Some(record.sequence),
                Some(index.event_id),
                Some(computed),
                checkpoint,
            ));
        }
        previous = Some(computed);
        expected_sequence = expected_sequence.saturating_add(1);
    }
    let mut result = finish_verification(
        stream_id,
        expected_sequence,
        previous,
        checkpoint,
        verified_at,
    );
    if result.valid {
        if let Some(through) = through_sequence {
            if result.to_sequence != through {
                result = failure(
                    stream_id,
                    verified_at,
                    "PROVENANCE_SEQUENCE_GAP",
                    "requested provenance prefix is incomplete",
                    Some(result.to_sequence.saturating_add(1)),
                    None,
                    result.computed_head_hash,
                    checkpoint,
                );
            }
        }
    }
    Ok(result)
}

struct JournalIndex {
    event_id: String,
    task_id: String,
    timestamp: String,
    event_type: String,
    semantic_program_hash: Option<String>,
    ir_version: Option<String>,
    registry_snapshot_id: Option<String>,
    node_id: Option<String>,
    execution_binding_id: Option<String>,
    provider_id: Option<String>,
    status: Option<String>,
}

impl JournalIndex {
    fn matches(&self, event: &Value) -> bool {
        self.event_id == string_field(event, "event_id").unwrap_or_default()
            && self.task_id == string_field(event, "task_id").unwrap_or_default()
            && self.timestamp == string_field(event, "timestamp").unwrap_or_default()
            && self.event_type == string_field(event, "event_type").unwrap_or_default()
            && self.semantic_program_hash.as_deref() == string_field(event, "semantic_program_hash")
            && self.ir_version.as_deref() == string_field(event, "ir_version")
            && self.registry_snapshot_id.as_deref() == string_field(event, "registry_snapshot_id")
            && self.node_id.as_deref() == string_field(event, "step_id")
            && self.execution_binding_id.as_deref() == string_field(event, "execution_binding_id")
            && self.provider_id.as_deref() == string_field(event, "provider_id")
            && self.status.as_deref() == string_field(event, "status")
    }
}
fn verify_one_record(
    record: &JournalRecord,
    stream_id: &str,
    expected_sequence: u64,
    previous: Option<&str>,
    expected_sequence_appears_later: bool,
    checkpoint: Option<&CheckpointExpectation>,
    verified_at: &str,
) -> std::result::Result<String, Box<VerificationResult>> {
    let event_id = string_field(&record.event, "event_id").map(str::to_owned);
    let invalid = |code: &str, message: &str, head: Option<String>| {
        Box::new(failure(
            stream_id,
            verified_at,
            code,
            message,
            Some(record.sequence),
            event_id.clone(),
            head,
            checkpoint,
        ))
    };
    if record.sequence < expected_sequence || expected_sequence_appears_later {
        return Err(invalid(
            "PROVENANCE_SEQUENCE_ORDER_INVALID",
            "records are not in strictly increasing sequence",
            previous.map(str::to_owned),
        ));
    }
    if record.sequence > expected_sequence {
        return Err(invalid(
            "PROVENANCE_SEQUENCE_GAP",
            "provenance stream contains a sequence gap",
            previous.map(str::to_owned),
        ));
    }
    if record.schema_version != SCHEMA_VERSION {
        return Err(invalid(
            "PROVENANCE_SCHEMA_INVALID",
            "journal record schema version is unsupported",
            previous.map(str::to_owned),
        ));
    }
    if record.hash_profile != HASH_PROFILE {
        return Err(invalid(
            "PROVENANCE_HASH_PROFILE_UNSUPPORTED",
            "journal record hash profile is unsupported",
            previous.map(str::to_owned),
        ));
    }
    if record.stream_id != stream_id
        || string_field(&record.event, "task_id").and_then(|id| self::stream_id(id).ok())
            != Some(stream_id.to_owned())
    {
        return Err(invalid(
            "PROVENANCE_STREAM_ID_MISMATCH",
            "journal record identity does not match the verified stream",
            previous.map(str::to_owned),
        ));
    }
    if record.previous_event_hash.as_deref() != previous {
        return Err(invalid(
            "PROVENANCE_PREVIOUS_HASH_MISMATCH",
            "previous_event_hash does not match the prior computed head",
            previous.map(str::to_owned),
        ));
    }
    let task_id = string_field(&record.event, "task_id").unwrap_or_default();
    if validate_event(task_id, &record.event).is_err()
        || validate_sequence_event_invariant(record.sequence, &record.event).is_err()
        || !valid_hash(&record.event_hash)
        || record
            .previous_event_hash
            .as_deref()
            .is_some_and(|hash| !valid_hash(hash))
    {
        return Err(invalid(
            "PROVENANCE_SCHEMA_INVALID",
            "journal record or event is structurally invalid",
            previous.map(str::to_owned),
        ));
    }
    let computed = hash_record(
        stream_id,
        record.sequence,
        record.previous_event_hash.as_deref(),
        &record.event,
    )
    .map_err(|_| {
        invalid(
            "PROVENANCE_SCHEMA_INVALID",
            "journal record cannot be canonicalized",
            previous.map(str::to_owned),
        )
    })?;
    if computed != record.event_hash {
        return Err(invalid(
            "PROVENANCE_EVENT_HASH_MISMATCH",
            "recomputed journal-record hash does not match event_hash",
            Some(computed),
        ));
    }
    Ok(computed)
}

fn finish_verification(
    stream_id: &str,
    expected_sequence: u64,
    previous: Option<String>,
    checkpoint: Option<&CheckpointExpectation>,
    verified_at: &str,
) -> VerificationResult {
    let Some(computed_head_hash) = previous else {
        return failure(
            stream_id,
            verified_at,
            "PROVENANCE_SEQUENCE_GAP",
            "provenance stream is empty",
            Some(1),
            None,
            None,
            checkpoint,
        );
    };
    if let Some(checkpoint) = checkpoint {
        if checkpoint.event_hash != computed_head_hash {
            return failure(
                stream_id,
                verified_at,
                "PROVENANCE_CHECKPOINT_HEAD_MISMATCH",
                "computed stream head does not match the supplied checkpoint",
                Some(expected_sequence - 1),
                None,
                Some(computed_head_hash),
                Some(checkpoint),
            );
        }
    }
    VerificationResult {
        schema_version: SCHEMA_VERSION.to_owned(),
        valid: true,
        stream_id: stream_id.to_owned(),
        from_sequence: 1,
        to_sequence: expected_sequence - 1,
        expected_head_hash: checkpoint.map(|value| value.event_hash.clone()),
        computed_head_hash: Some(computed_head_hash),
        checkpoint_id: checkpoint.map(|value| value.checkpoint_id.clone()),
        verifier: verifier(),
        diagnostics: Vec::new(),
        diagnostics_truncated: false,
        verified_at: verified_at.to_owned(),
    }
}

/// Verifies journal records already loaded in their presented order.
#[allow(clippy::too_many_lines)]
pub fn verify_records(
    records: &[JournalRecord],
    stream_id: &str,
    checkpoint: Option<&CheckpointExpectation>,
    verified_at: &str,
) -> VerificationResult {
    let mut previous: Option<String> = None;
    let mut expected_sequence = 1_u64;
    for (index, record) in records.iter().enumerate() {
        let expected_later = record.sequence > expected_sequence
            && records[index..]
                .iter()
                .any(|candidate| candidate.sequence == expected_sequence);
        match verify_one_record(
            record,
            stream_id,
            expected_sequence,
            previous.as_deref(),
            expected_later,
            checkpoint,
            verified_at,
        ) {
            Ok(computed) => previous = Some(computed),
            Err(failure) => return *failure,
        }
        expected_sequence = expected_sequence.saturating_add(1);
    }
    finish_verification(
        stream_id,
        expected_sequence,
        previous,
        checkpoint,
        verified_at,
    )
}
/// Produces a separately hashed privacy-redacted projection and manifest.
///
/// # Errors
/// Returns an error when the stream is invalid, unsafe to export, or cannot be read.
pub fn export_jsonl(
    connection: &Connection,
    stream_id: &str,
    verified_at: &str,
) -> Result<ProjectionPortableExport> {
    export_jsonl_with_validation(connection, stream_id, verified_at, |_| Ok(()))
}

/// Exports one snapshot after the caller validates its private Task state in
/// that same transaction. The callback must not commit or mutate the journal.
///
/// # Errors
/// Returns an error when validation, verification, projection, or storage fails.
#[allow(
    clippy::too_many_lines,
    reason = "keeps snapshot validation, projection, and bounded export in one transaction"
)]
pub fn export_jsonl_with_validation<F>(
    connection: &Connection,
    stream_id: &str,
    verified_at: &str,
    validate: F,
) -> Result<ProjectionPortableExport>
where
    F: FnOnce(&Connection) -> Result<()>,
{
    validate_timestamp(verified_at)?;
    validate_stream_id(stream_id)?;
    let transaction = connection.unchecked_transaction()?;
    let (record_count, source_bytes): (i64, i64) = transaction.query_row(
        "SELECT COUNT(*),COALESCE(SUM(LENGTH(CAST(event_json AS BLOB))),0) FROM provenance_events WHERE stream_id=?1",
        [stream_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if u64::try_from(record_count).map_or(true, |count| count > MAX_PROJECTION_RECORDS) {
        return Err(Error::InvalidRecord(
            "portable provenance export exceeds record-count bound".to_owned(),
        ));
    }
    if u64::try_from(source_bytes).map_or(true, |bytes| bytes > MAX_PROJECTION_SOURCE_BYTES) {
        return Err(Error::InvalidRecord(
            "portable provenance export exceeds source-byte bound".to_owned(),
        ));
    }
    validate(&transaction)?;
    let verification = verify_stream(&transaction, stream_id, None, None, verified_at)?;
    if !verification.valid {
        return Err(Error::InvalidRecord(
            "cannot export an invalid provenance stream".to_owned(),
        ));
    }
    let alias_key =
        transaction.query_row("SELECT randomblob(32)", [], |row| row.get::<_, Vec<u8>>(0))?;
    if alias_key.len() != 32 {
        return Err(Error::InvalidRecord(
            "projection alias key generation failed".to_owned(),
        ));
    }
    let bundle_random = transaction.query_row("SELECT hex(randomblob(32))", [], |row| {
        row.get::<_, String>(0)
    })?;
    let bundle_id = format!("bundle:v1:{}", bundle_random.to_ascii_lowercase());
    let mut records_jsonl = String::new();
    let mut cursor = None;
    let mut previous = None;
    let mut head_sequence = 0;
    let mut projected_count = 0_u64;
    loop {
        let page = list_events(&transaction, stream_id, cursor, MAX_PAGE_SIZE)?;
        for record in page.records {
            validate_stored_event(&record.event)?;
            let projected_event = project_event(&record.event, &alias_key)?;
            validate_projected_event(&projected_event)?;
            let projection_hash = hash_projected_record(
                &bundle_id,
                record.sequence,
                previous.as_deref(),
                &projected_event,
            )?;
            let projected_record = ProjectedRecord {
                schema_version: SCHEMA_VERSION.to_owned(),
                projection_hash_profile: PROJECTION_HASH_PROFILE.to_owned(),
                bundle_id: bundle_id.clone(),
                sequence: record.sequence,
                previous_projection_hash: previous,
                projected_event,
                projection_hash: projection_hash.clone(),
            };
            if !projected_record_validator()?.is_valid(&serde_json::to_value(&projected_record)?) {
                return Err(Error::InvalidRecord(
                    "generated projected record is invalid".to_owned(),
                ));
            }
            let line = serde_json::to_string(&projected_record)?;
            if records_jsonl.len() + line.len() + 1 > MAX_PROJECTION_EXPORT_BYTES {
                return Err(Error::InvalidRecord(
                    "portable provenance export exceeds bounds".to_owned(),
                ));
            }
            records_jsonl.push_str(&line);
            records_jsonl.push('\n');
            head_sequence = record.sequence;
            projected_count += 1;
            previous = Some(projection_hash);
        }
        let Some(next) = page.next_cursor else { break };
        cursor = Some(next);
    }
    let head_projection_hash = previous.ok_or_else(|| {
        Error::InvalidRecord("cannot export an empty projected stream".to_owned())
    })?;
    let mut manifest = ProjectionManifest {
        schema_version: SCHEMA_VERSION.to_owned(),
        export_profile: "privacy-redacted-projection-v1".to_owned(),
        projection_hash_profile: PROJECTION_HASH_PROFILE.to_owned(),
        bundle_id,
        record_count: projected_count,
        head_sequence,
        head_projection_hash,
        descriptor_hash: String::new(),
    };
    manifest.descriptor_hash = hash_projection_descriptor(&manifest)?;
    let manifest_value = serde_json::to_value(&manifest)?;
    if !projection_manifest_validator()?.is_valid(&manifest_value) {
        return Err(Error::InvalidRecord(
            "generated projection manifest is invalid".to_owned(),
        ));
    }
    transaction.commit()?;
    Ok(ProjectionPortableExport {
        manifest_json: serde_json::to_string_pretty(&manifest_value)?,
        records_jsonl,
    })
}

/// Verifies only the exported projection without a database or network access.
///
/// This does not verify or prove linkage to the original journal chain.
///
/// # Errors
/// Returns an error for malformed, unsupported, unsafe, or over-bound export input.
pub fn verify_jsonl_export(
    manifest_json: &str,
    records_jsonl: &str,
    verified_at: &str,
) -> Result<ProjectionVerificationResult> {
    if manifest_json.len() > MAX_EVENT_BYTES || records_jsonl.len() > MAX_PROJECTION_EXPORT_BYTES {
        return Err(Error::InvalidRecord(
            "portable provenance export exceeds bounds".to_owned(),
        ));
    }
    validate_timestamp(verified_at)?;
    let manifest_value: Value = serde_json::from_str(manifest_json)?;
    if !projection_manifest_validator()?.is_valid(&manifest_value) {
        return Err(Error::InvalidRecord(
            "unsupported portable provenance export manifest".to_owned(),
        ));
    }
    let manifest: ProjectionManifest = serde_json::from_value(manifest_value)?;
    if manifest.schema_version != SCHEMA_VERSION
        || manifest.projection_hash_profile != PROJECTION_HASH_PROFILE
        || manifest.export_profile != "privacy-redacted-projection-v1"
        || !valid_bundle_id(&manifest.bundle_id)
        || hash_projection_descriptor(&manifest)? != manifest.descriptor_hash
    {
        return Err(Error::InvalidRecord(
            "unsupported portable provenance export manifest".to_owned(),
        ));
    }
    let mut records = Vec::new();
    for line in records_jsonl.lines() {
        if line.is_empty() || line.len() > MAX_PROJECTED_RECORD_BYTES {
            return Err(Error::InvalidRecord(
                "malformed portable provenance JSONL".to_owned(),
            ));
        }
        let record_value: Value = serde_json::from_str(line)?;
        if !projected_record_validator()?.is_valid(&record_value) {
            return Err(Error::InvalidRecord(
                "malformed projected provenance record".to_owned(),
            ));
        }
        let record: ProjectedRecord = serde_json::from_value(record_value)?;
        records.push(record);
    }
    let result = verify_projected_records(&manifest, &records, verified_at);
    if !projection_verification_result_validator()?.is_valid(&serde_json::to_value(&result)?) {
        return Err(Error::InvalidRecord(
            "projection verifier produced an invalid result".to_owned(),
        ));
    }
    Ok(result)
}

fn projection_failure(
    manifest: &ProjectionManifest,
    verified_at: &str,
    code: &str,
    message: &str,
    sequence: Option<u64>,
    head: Option<String>,
) -> ProjectionVerificationResult {
    ProjectionVerificationResult {
        schema_version: SCHEMA_VERSION.to_owned(),
        scope: "exported-projection".to_owned(),
        valid: false,
        original_chain_verified_offline: false,
        original_chain_linkage_proven: false,
        bundle_id: manifest.bundle_id.clone(),
        from_sequence: 1,
        to_sequence: sequence.unwrap_or(0),
        computed_projection_head_hash: head,
        diagnostics: vec![VerificationDiagnostic {
            severity: Severity::Error,
            code: code.to_owned(),
            message: message.to_owned(),
            sequence,
            event_id: None,
            related: Vec::new(),
        }],
        verified_at: verified_at.to_owned(),
    }
}

fn verify_projected_records(
    manifest: &ProjectionManifest,
    records: &[ProjectedRecord],
    verified_at: &str,
) -> ProjectionVerificationResult {
    let mut previous = None;
    let mut task_alias: Option<&str> = None;
    let mut event_aliases = std::collections::BTreeSet::new();
    for (index, record) in records.iter().enumerate() {
        let expected_sequence = index as u64 + 1;
        if record.schema_version != SCHEMA_VERSION
            || record.projection_hash_profile != PROJECTION_HASH_PROFILE
            || record.bundle_id != manifest.bundle_id
            || record.sequence != expected_sequence
            || record.previous_projection_hash != previous
            || validate_projected_event(&record.projected_event).is_err()
        {
            return projection_failure(
                manifest,
                verified_at,
                "PROJECTION_RECORD_INVALID",
                "projected record shape, order, or predecessor is invalid",
                Some(record.sequence),
                previous,
            );
        }
        let projected_task_alias = record
            .projected_event
            .pointer("/task_id/alias")
            .and_then(Value::as_str);
        let projected_event_alias = record
            .projected_event
            .pointer("/event_id/alias")
            .and_then(Value::as_str);
        if (index == 0
            && string_field(&record.projected_event, "event_type") != Some("task.created"))
            || projected_task_alias.is_none()
            || projected_event_alias.is_none()
            || task_alias.is_some_and(|first| Some(first) != projected_task_alias)
            || !event_aliases.insert(projected_event_alias.unwrap_or_default())
        {
            return projection_failure(
                manifest,
                verified_at,
                "PROJECTION_RECORD_INVALID",
                "projected stream genesis or event identity is invalid",
                Some(record.sequence),
                previous,
            );
        }
        task_alias = projected_task_alias;
        let Ok(computed) = hash_projected_record(
            &manifest.bundle_id,
            record.sequence,
            previous.as_deref(),
            &record.projected_event,
        ) else {
            return projection_failure(
                manifest,
                verified_at,
                "PROJECTION_RECORD_INVALID",
                "projected record cannot be canonicalized",
                Some(record.sequence),
                previous,
            );
        };
        if computed != record.projection_hash {
            return projection_failure(
                manifest,
                verified_at,
                "PROJECTION_HASH_MISMATCH",
                "projected record hash does not match its contents",
                Some(record.sequence),
                Some(computed),
            );
        }
        previous = Some(computed);
    }
    if records.len() as u64 != manifest.record_count
        || records.last().map(|record| record.sequence) != Some(manifest.head_sequence)
        || previous.as_deref() != Some(manifest.head_projection_hash.as_str())
    {
        return projection_failure(
            manifest,
            verified_at,
            "PROJECTION_MANIFEST_MISMATCH",
            "projection manifest does not match its records",
            records.last().map(|record| record.sequence),
            previous,
        );
    }
    ProjectionVerificationResult {
        schema_version: SCHEMA_VERSION.to_owned(),
        scope: "exported-projection".to_owned(),
        valid: true,
        original_chain_verified_offline: false,
        original_chain_linkage_proven: false,
        bundle_id: manifest.bundle_id.clone(),
        from_sequence: 1,
        to_sequence: manifest.head_sequence,
        computed_projection_head_hash: Some(manifest.head_projection_hash.clone()),
        diagnostics: Vec::new(),
        verified_at: verified_at.to_owned(),
    }
}

fn project_event(event: &Value, alias_key: &[u8]) -> Result<Value> {
    validate_stored_event(event)?;
    project_value(event, &mut Vec::new(), alias_key)
}

fn project_value(value: &Value, path: &mut Vec<String>, alias_key: &[u8]) -> Result<Value> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(value.clone()),
        Value::String(text) => {
            let key = path.last().map(String::as_str).unwrap_or_default();
            if retained_projection_string(path, key, text) {
                Ok(value.clone())
            } else {
                Ok(alias_value(alias_key, alias_namespace(path, key), text))
            }
        }
        Value::Array(values) => values
            .iter()
            .map(|value| project_value(value, path, alias_key))
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
        Value::Object(object) => {
            if is_private_commitment(object) {
                return Ok(value.clone());
            }
            let mut projected = serde_json::Map::new();
            for (key, value) in object {
                path.push(key.clone());
                projected.insert(key.clone(), project_value(value, path, alias_key)?);
                path.pop();
            }
            Ok(Value::Object(projected))
        }
    }
}

fn alias_value(alias_key: &[u8], namespace: &str, value: &str) -> Value {
    let mut hasher = Sha256::new();
    hasher.update(PROJECTION_ALIAS_DOMAIN);
    hasher.update(alias_key);
    hasher.update(namespace.as_bytes());
    hasher.update([0]);
    hasher.update(value.as_bytes());
    let digest = hex_digest(hasher.finalize().as_slice());
    json!({
        "kind":"bundle-local-alias",
        "version":"v1",
        "namespace":namespace,
        "alias":format!("sha256:{digest}")
    })
}

fn alias_namespace(path: &[String], key: &str) -> &'static str {
    match key {
        "task_id" => "task",
        "event_id" | "admission_event_id" | "provenance_event_ids" => "event",
        "workspace_id" => "workspace",
        "plan_id" => "plan",
        "step_id" | "node_id" | "active_step_ids" => "step",
        "related_ids" => "related",
        "input_artifacts" | "output_artifacts" | "data_refs" => "artifact",
        "id" if path
            .iter()
            .any(|part| part == "actor" || part == "principal") =>
        {
            "principal"
        }
        "id" if path.iter().any(|part| part == "waiting_on") => "waiting",
        "id" if path.iter().any(|part| part == "skill") => "skill",
        "id" => "identifier",
        "transition_id" => "transition",
        "provider_id" | "validator_id" => "provider",
        "execution_binding_id" | "binding_id" => "binding",
        "operation_id" | "unknown_operation_ids" => "operation",
        "allocation_id" => "allocation",
        "publication_id" => "publication",
        "import_id" => "import",
        "registry_snapshot_id" => "registry-snapshot",
        "validation_result_id" => "validation-result",
        "authority_token_id" => "authority-token",
        "policy_decision_id" => "policy-decision",
        "approval_id" => "approval",
        _ => "opaque-value",
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "keeps the reviewed literal-string projection vocabulary in one audit table"
)]
fn retained_projection_string(path: &[String], key: &str, value: &str) -> bool {
    match key {
        "schema_version" => value == SCHEMA_VERSION,
        "timestamp" | "created_at" | "validated_at" | "observed_at" | "resulted_at" => {
            validate_timestamp(value).is_ok()
        }
        "event_type" => matches!(
            value,
            "task.created"
                | "task.transitioned"
                | "task.paused"
                | "task.resumed"
                | "task.cancelled"
                | "task.completed"
                | "task.failed"
                | "intent.normalized"
                | "plan.created"
                | "plan.revised"
                | "ir.validation.started"
                | "ir.validation.completed"
                | "ir.validation.failed"
                | "registry.snapshot.selected"
                | "capability.resolved"
                | "authorization.requested"
                | "authorization.granted"
                | "authorization.denied"
                | "approval.requested"
                | "approval.granted"
                | "approval.denied"
                | "provider.selected"
                | "placement.selected"
                | "execution.bound"
                | "execution.started"
                | "execution.completed"
                | "execution.failed"
                | "model.invoked"
                | "model.completed"
                | "egress.started"
                | "egress.completed"
                | "artifact.imported"
                | "artifact.created"
                | "artifact.exported"
                | "artifact.verified"
                | "artifact.integrity-failed"
                | "verification.started"
                | "verification.completed"
                | "verification.failed"
                | "rollback.started"
                | "rollback.completed"
                | "skill.proposed"
                | "skill.created"
                | "skill.validated"
                | "skill.compiled"
                | "skill.executed"
                | "skill.invalidated"
        ),
        "kind" if path.iter().any(|part| part == "waiting_on") => matches!(
            value,
            "input" | "approval" | "resource" | "provider" | "validation"
        ),
        "kind"
            if path
                .iter()
                .any(|part| part == "actor" || part == "principal") =>
        {
            matches!(
                value,
                "user"
                    | "agent"
                    | "provider"
                    | "model-provider"
                    | "system-service"
                    | "legacy-app"
                    | "policy-engine"
                    | "validator"
                    | "peer-node"
            )
        }
        "status" => matches!(
            value,
            "success" | "failure" | "denied" | "partial" | "pending" | "cancelled"
        ),
        "previous_state" | "new_state" => matches!(
            value,
            "CREATED"
                | "PLANNING"
                | "WAITING_FOR_INPUT"
                | "WAITING_FOR_AUTH"
                | "RUNNABLE"
                | "RUNNING"
                | "VERIFYING"
                | "PAUSED"
                | "RECOVERING"
                | "ROLLING_BACK"
                | "COMPLETED"
                | "FAILED"
                | "CANCELLED"
                | "ROLLED_BACK"
        ),
        "locality" => matches!(value, "local" | "remote" | "peer" | "cloud"),
        "isolation_class" => matches!(value, "P0" | "P1" | "P2" | "P3"),
        "phase" => matches!(
            value,
            "admitted" | "delivered" | "pre-destination-admission" | "effect-boundary-armed"
        ),
        "outcome_certainty" | "certainty" => matches!(
            value,
            "NOT_STARTED"
                | "STARTED_NO_EFFECT"
                | "COMPLETED"
                | "FAILED_NO_EFFECT"
                | "FAILED_PARTIAL_EFFECT"
                | "OUTCOME_UNKNOWN"
        ),
        "effect_boundary" => value == "destination-not-invoked",
        "safe_action" => matches!(
            value,
            "CREATE_NEW_ATTEMPT"
                | "RECONCILE_STATE"
                | "MARK_ATTEMPT_FAILED"
                | "REQUIRE_EXTERNAL_RECONCILIATION"
                | "FAIL_TASK"
                | "NO_ACTION"
                | "CLEAN_STAGING"
        ),
        "source" => value == "user-selected",
        "previous_durability_state" | "durability_state" => matches!(
            value,
            "STAGED" | "DURABLE" | "ORPHANED" | "CORRUPT" | "MISSING"
        ),
        _ => false,
    }
}

fn is_private_commitment(object: &serde_json::Map<String, Value>) -> bool {
    object.len() == 5
        && object.get("kind").and_then(Value::as_str) == Some("task-field-commitment")
        && object.get("version").and_then(Value::as_str) == Some("v1")
        && object.get("algorithm").and_then(Value::as_str) == Some("sha256-keyed-prefix")
        && object
            .get("field")
            .and_then(Value::as_str)
            .is_some_and(|field| {
                matches!(
                    field,
                    "original_intent"
                        | "normalized_intent"
                        | "reason_message"
                        | "waiting_message"
                        | "failure_summary"
                )
            })
        && object
            .get("commitment")
            .and_then(Value::as_str)
            .is_some_and(valid_hash)
}

fn validate_projected_event(event: &Value) -> Result<()> {
    if serde_json::to_vec(event)?.len() > MAX_PROJECTED_EVENT_BYTES
        || json_depth(event) > MAX_JSON_DEPTH
        || !within_shape_bounds(event)
    {
        return Err(Error::InvalidRecord(
            "projected event exceeds bounds".to_owned(),
        ));
    }
    let source_shape = projected_source_shape(event, &mut Vec::new())?;
    let task_id = string_field(&source_shape, "task_id").unwrap_or_default();
    validate_event_contract(task_id, &source_shape, false)
}

fn projected_source_shape(value: &Value, path: &mut Vec<String>) -> Result<Value> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(value.clone()),
        Value::String(text) => {
            let key = path.last().map(String::as_str).unwrap_or_default();
            if retained_projection_string(path, key, text) {
                Ok(value.clone())
            } else {
                Err(Error::InvalidRecord(
                    "raw string in projected event".to_owned(),
                ))
            }
        }
        Value::Array(values) => {
            if values.len() > MAX_ARRAY_ITEMS {
                return Err(Error::InvalidRecord(
                    "projected array exceeds bounds".to_owned(),
                ));
            }
            values
                .iter()
                .map(|value| projected_source_shape(value, path))
                .collect::<Result<Vec<_>>>()
                .map(Value::Array)
        }
        Value::Object(object) => {
            if is_private_commitment(object) {
                return Ok(value.clone());
            }
            if object.get("kind").and_then(Value::as_str) == Some("bundle-local-alias") {
                validate_alias(object)?;
                let key = path.last().map(String::as_str).unwrap_or_default();
                let expected_namespace = alias_namespace(path, key);
                if object.get("namespace").and_then(Value::as_str) != Some(expected_namespace) {
                    return Err(Error::InvalidRecord(
                        "projected alias has the wrong path namespace".to_owned(),
                    ));
                }
                return Ok(Value::String(projected_placeholder(path, key, object)));
            }
            if object.len() > MAX_OBJECT_FIELDS
                || object.keys().any(|key| {
                    matches!(
                        key.as_str(),
                        "stream_id" | "event_hash" | "previous_event_hash" | "head_event_hash"
                    )
                })
            {
                return Err(Error::InvalidRecord(
                    "projected object is invalid".to_owned(),
                ));
            }
            let mut source = serde_json::Map::new();
            for (key, value) in object {
                path.push(key.clone());
                source.insert(key.clone(), projected_source_shape(value, path)?);
                path.pop();
            }
            Ok(Value::Object(source))
        }
    }
}

fn projected_placeholder(
    path: &[String],
    key: &str,
    alias: &serde_json::Map<String, Value>,
) -> String {
    let digest = alias
        .get("alias")
        .and_then(Value::as_str)
        .expect("validated alias has a digest");
    if matches!(
        key,
        "semantic_program_hash"
            | "capability_contract_hash"
            | "manifest_hash"
            | "content_hash"
            | "intent_hash"
            | "admission_event_hash"
            | "request_digest"
            | "proof_hash"
            | "subject_hash"
            | "semantic_hash"
            | "program_content_digest"
    ) {
        return digest.to_owned();
    }
    if key == "reason_code" || (key == "code" && path.iter().any(|part| part == "failure")) {
        return format!("PROJECTED_{}", digest[7..].to_ascii_uppercase());
    }
    if key == "ir_version" && path.iter().any(|part| part == "active_program") {
        return digest[7..].to_owned();
    }
    digest.to_owned()
}

fn validate_alias(object: &serde_json::Map<String, Value>) -> Result<()> {
    if object.len() != 4
        || object.get("version").and_then(Value::as_str) != Some("v1")
        || !object
            .get("alias")
            .and_then(Value::as_str)
            .is_some_and(valid_hash)
        || !object
            .get("namespace")
            .and_then(Value::as_str)
            .is_some_and(|namespace| {
                matches!(
                    namespace,
                    "task"
                        | "event"
                        | "workspace"
                        | "plan"
                        | "step"
                        | "related"
                        | "artifact"
                        | "principal"
                        | "waiting"
                        | "skill"
                        | "identifier"
                        | "transition"
                        | "provider"
                        | "binding"
                        | "operation"
                        | "allocation"
                        | "publication"
                        | "import"
                        | "registry-snapshot"
                        | "validation-result"
                        | "authority-token"
                        | "policy-decision"
                        | "approval"
                        | "opaque-value"
                )
            })
    {
        return Err(Error::InvalidRecord(
            "projected alias is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn hash_projected_record(
    bundle_id: &str,
    sequence: u64,
    previous: Option<&str>,
    event: &Value,
) -> Result<String> {
    let view = json!({"schema_version":SCHEMA_VERSION,"projection_hash_profile":PROJECTION_HASH_PROFILE,"bundle_id":bundle_id,"sequence":sequence,"previous_projection_hash":previous,"projected_event":event});
    hash_canonical(PROJECTION_RECORD_DOMAIN, &view)
}

fn hash_projection_descriptor(manifest: &ProjectionManifest) -> Result<String> {
    let view = json!({"schema_version":manifest.schema_version,"export_profile":manifest.export_profile,"projection_hash_profile":manifest.projection_hash_profile,"bundle_id":manifest.bundle_id,"record_count":manifest.record_count,"head_sequence":manifest.head_sequence,"head_projection_hash":manifest.head_projection_hash});
    hash_canonical(PROJECTION_DESCRIPTOR_DOMAIN, &view)
}

fn hash_canonical(domain: &[u8], value: &Value) -> Result<String> {
    let canonical = serde_json_canonicalizer::to_vec(value)
        .map_err(|error| Error::Canonicalization(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical);
    Ok(format!(
        "sha256:{}",
        hex_digest(hasher.finalize().as_slice())
    ))
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut hex, "{byte:02x}").expect("writing to String cannot fail");
    }
    hex
}

fn valid_bundle_id(value: &str) -> bool {
    value.len() == 74
        && value.starts_with("bundle:v1:")
        && value[10..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Computes the v0.1 domain-separated canonical journal-record hash.
///
/// # Errors
/// Returns an error when the event is not an object or cannot be canonicalized.
pub fn hash_record(
    stream_id: &str,
    sequence: u64,
    previous: Option<&str>,
    event: &Value,
) -> Result<String> {
    let mut event = event.clone();
    let object = event
        .as_object_mut()
        .ok_or_else(|| Error::InvalidRecord("provenance event must be an object".to_owned()))?;
    object.remove("event_hash");
    object.remove("previous_event_hash");
    let view = json!({"schema_version":SCHEMA_VERSION,"hash_profile":HASH_PROFILE,"stream_id":stream_id,"sequence":sequence,"previous_event_hash":previous,"event":event});
    let canonical = serde_json_canonicalizer::to_vec(&view)
        .map_err(|error| Error::Canonicalization(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(HASH_DOMAIN);
    hasher.update(canonical);
    let mut hex = String::with_capacity(64);
    for byte in hasher.finalize() {
        write!(&mut hex, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(format!("sha256:{hex}"))
}

fn event_validator() -> Result<&'static jsonschema::Validator> {
    static VALIDATOR: OnceLock<std::result::Result<jsonschema::Validator, String>> =
        OnceLock::new();
    VALIDATOR
        .get_or_init(|| {
            let schema: Value =
                serde_json::from_str(EVENT_SCHEMA).map_err(|error| error.to_string())?;
            jsonschema::validator_for(&schema).map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|error| Error::InvalidRecord(format!("provenance schema unavailable: {error}")))
}

fn projection_manifest_validator() -> Result<&'static jsonschema::Validator> {
    static VALIDATOR: OnceLock<std::result::Result<jsonschema::Validator, String>> =
        OnceLock::new();
    VALIDATOR
        .get_or_init(|| {
            let schema: Value = serde_json::from_str(PROJECTION_MANIFEST_SCHEMA)
                .map_err(|error| error.to_string())?;
            jsonschema::validator_for(&schema).map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|error| Error::InvalidRecord(format!("projection schema unavailable: {error}")))
}

fn projected_record_validator() -> Result<&'static jsonschema::Validator> {
    static VALIDATOR: OnceLock<std::result::Result<jsonschema::Validator, String>> =
        OnceLock::new();
    VALIDATOR
        .get_or_init(|| {
            let schema: Value =
                serde_json::from_str(PROJECTED_RECORD_SCHEMA).map_err(|error| error.to_string())?;
            jsonschema::validator_for(&schema).map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|error| Error::InvalidRecord(format!("projection schema unavailable: {error}")))
}

fn projection_verification_result_validator() -> Result<&'static jsonschema::Validator> {
    static VALIDATOR: OnceLock<std::result::Result<jsonschema::Validator, String>> =
        OnceLock::new();
    VALIDATOR
        .get_or_init(|| {
            let schema: Value = serde_json::from_str(PROJECTION_VERIFICATION_RESULT_SCHEMA)
                .map_err(|error| error.to_string())?;
            jsonschema::validator_for(&schema).map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|error| Error::InvalidRecord(format!("projection schema unavailable: {error}")))
}

fn validate_event(task_id: &str, event: &Value) -> Result<()> {
    validate_event_contract(task_id, event, true)
}

fn validate_event_contract(task_id: &str, event: &Value, source_size_bounds: bool) -> Result<()> {
    validate_task_id(task_id)?;
    let bytes = serde_json::to_vec(event)?;
    if (source_size_bounds && bytes.len() > MAX_EVENT_BYTES)
        || json_depth(event) > MAX_JSON_DEPTH
        || !within_shape_bounds(event)
    {
        return Err(Error::InvalidRecord(
            "provenance event exceeds size or depth bounds".to_owned(),
        ));
    }
    if source_size_bounds
        && event.get("details").is_some_and(|value| {
            serde_json::to_vec(value).map_or(true, |bytes| bytes.len() > MAX_DETAILS_BYTES)
        })
    {
        return Err(Error::InvalidRecord(
            "provenance details exceed size bounds".to_owned(),
        ));
    }
    if event.get("event_hash").is_some() || event.get("previous_event_hash").is_some() {
        return Err(Error::InvalidRecord(
            "event payload must not supply journal hash fields".to_owned(),
        ));
    }
    if !event_validator()?.is_valid(event) {
        return Err(Error::InvalidRecord(
            "provenance event does not match the typed event contract".to_owned(),
        ));
    }
    if string_field(event, "task_id") != Some(task_id) {
        return Err(Error::InvalidRecord(
            "provenance event Task identity mismatch".to_owned(),
        ));
    }
    for key in ["event_id", "task_id"] {
        let value = string_field(event, key).unwrap_or_default();
        if value.chars().count() > 256 {
            return Err(Error::InvalidRecord(format!(
                "provenance {key} exceeds bounds"
            )));
        }
    }
    let actor_id = event
        .pointer("/actor/id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if actor_id.chars().count() > 256 {
        return Err(Error::InvalidRecord(
            "provenance actor ID exceeds bounds".to_owned(),
        ));
    }
    validate_timestamp(string_field(event, "timestamp").unwrap_or_default())?;
    if event.get("event_type").and_then(Value::as_str) == Some("task.transitioned") {
        let transition = &event["task_transition"];
        let previous = transition.get("previous_revision").and_then(Value::as_u64);
        let next = transition.get("new_revision").and_then(Value::as_u64);
        if previous.and_then(|value| value.checked_add(1)) != next {
            return Err(Error::InvalidRecord(
                "invalid typed Task transition provenance".to_owned(),
            ));
        }
    }
    validate_details_vocabulary(event)
}

fn validate_stored_event(event: &Value) -> Result<()> {
    let task_id = string_field(event, "task_id").ok_or_else(|| {
        Error::InvalidRecord("provenance event has no typed Task identity".to_owned())
    })?;
    validate_event(task_id, event)
}

fn validate_task_id(task_id: &str) -> Result<()> {
    let count = task_id.chars().count();
    if count == 0 {
        return Err(Error::InvalidRecord("Task ID is empty".to_owned()));
    }
    if count > 256 {
        return Err(Error::InvalidRecord(
            "Task ID exceeds 256 Unicode scalars".to_owned(),
        ));
    }
    Ok(())
}

fn validate_stream_id(value: &str) -> Result<()> {
    let key = value
        .strip_prefix("task:")
        .ok_or_else(|| Error::InvalidRecord("invalid provenance stream ID".to_owned()))?;
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return Err(Error::InvalidRecord(
            "invalid provenance stream ID".to_owned(),
        ));
    };
    if value.len() > 256
        || !first.is_ascii_alphanumeric()
        || !chars.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | ':' | '-')
        })
    {
        return Err(Error::InvalidRecord(
            "invalid provenance stream ID".to_owned(),
        ));
    }
    Ok(())
}

fn validate_sequence_event_invariant(sequence: u64, event: &Value) -> Result<()> {
    if sequence == 1 && string_field(event, "event_type") != Some("task.created") {
        return Err(Error::InvalidRecord(
            "provenance genesis event must be task.created".to_owned(),
        ));
    }
    Ok(())
}

fn validate_timestamp(value: &str) -> Result<()> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map(|_| ())
        .map_err(|_| Error::InvalidRecord("provenance timestamp is not RFC 3339".to_owned()))
}

fn valid_hash(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_details_vocabulary(event: &Value) -> Result<()> {
    let Some(details) = event.get("details") else {
        return Ok(());
    };
    let details = details
        .as_object()
        .ok_or_else(|| Error::InvalidRecord("provenance details must be an object".to_owned()))?;
    let event_type = string_field(event, "event_type").unwrap_or_default();
    for (key, value) in details {
        if !allowed_detail_key(event_type, key) {
            return Err(Error::InvalidRecord(format!(
                "provenance details field `{key}` is not in the privacy-safe vocabulary"
            )));
        }
        validate_detail_value(event_type, key, value)?;
    }
    if event_type == "task.created"
        && [
            "revision",
            "creation",
            "active_plan",
            "active_step_ids",
            "waiting_on",
            "failure",
            "recovery",
        ]
        .iter()
        .any(|key| !details.contains_key(*key))
    {
        return Err(invalid_details(
            "task.created is missing its typed creation projection",
        ));
    }
    Ok(())
}

fn allowed_detail_key(event_type: &str, key: &str) -> bool {
    match event_type {
        "task.created" => matches!(
            key,
            "revision"
                | "creation"
                | "active_plan"
                | "active_step_ids"
                | "waiting_on"
                | "failure"
                | "recovery"
                | "fixture"
        ),
        "task.transitioned" => matches!(
            key,
            "related_ids" | "reason_message_ref" | "active_program" | "mutation_text_commitments"
        ),
        "authorization.granted" => matches!(key, "actions" | "resource" | "resources"),
        "plan.created" | "plan.revised" => matches!(key, "plan_id" | "revision"),
        "provider.selected" | "placement.selected" => {
            matches!(key, "locality" | "isolation_class")
        }
        "execution.started" => matches!(
            key,
            "attempt_id"
                | "binding_id"
                | "node_id"
                | "operation_id"
                | "phase"
                | "intent_hash"
                | "admission_event_id"
                | "admission_event_hash"
                | "execution_profile"
        ),
        "execution.completed" | "execution.failed" => matches!(
            key,
            "operation_id"
                | "outcome_certainty"
                | "effect_boundary"
                | "certainty"
                | "export_reconciliation"
                | "recovery_ref"
                | "inventory_id"
                | "safe_action"
                | "reason_code"
                | "phase"
                | "admission_event_id"
                | "admission_event_hash"
                | "attempt"
                | "duration_ms"
        ),
        "artifact.imported" => matches!(
            key,
            "content_hash"
                | "size_bytes"
                | "blob_reused"
                | "import_id"
                | "request_digest"
                | "source"
        ),
        "artifact.created" => matches!(
            key,
            "allocation_id"
                | "publication_id"
                | "content_hash"
                | "size_bytes"
                | "blob_reused"
                | "type"
        ),
        "artifact.exported" => matches!(key, "operation_id" | "size_bytes"),
        "artifact.integrity-failed" => matches!(
            key,
            "content_hash"
                | "observation_ordinal"
                | "previous_durability_state"
                | "durability_state"
                | "publication_id"
                | "allocation_id"
                | "request_digest"
                | "reason_code"
                | "resulted_at"
        ),
        "verification.started" | "verification.completed" | "verification.failed" => {
            matches!(key, "index" | "verified_claims" | "failed_claims")
        }
        "task.completed" => matches!(key, "revision" | "external_egress" | "verified"),
        _ => false,
    }
}

#[allow(
    clippy::too_many_lines,
    clippy::match_same_arms,
    reason = "keeps the closed event-type and detail-key value contract auditable as one dispatch table"
)]
fn validate_detail_value(event_type: &str, key: &str, value: &Value) -> Result<()> {
    match (event_type, key) {
        ("task.created", "revision") => expect_integer(value, 1, Some(1)),
        ("task.created", "creation") => validate_creation_details(value),
        ("task.created", "active_plan") => expect_null(value),
        ("task.created", "active_step_ids") => expect_task_string_array(value, 512, 128, true),
        ("task.created", "waiting_on") => validate_waiting_on(value, false),
        ("task.created", "failure" | "recovery") => expect_null(value),
        ("task.created", "fixture") => expect_bool(value),
        ("task.transitioned", "related_ids") => expect_task_string_array(value, 32, 512, false),
        ("task.transitioned", "reason_message_ref") => {
            validate_commitment(value, "reason_message", true)
        }
        ("task.transitioned", "active_program") => validate_active_program(value),
        ("task.transitioned", "mutation_text_commitments") => validate_mutation_commitments(value),
        ("authorization.granted", "actions") => expect_token_array(value, 64, 128),
        ("authorization.granted", "resource") => expect_identifier(value, 256),
        ("authorization.granted", "resources") => expect_identifier_array(value, 64, 256),
        ("plan.created" | "plan.revised", "plan_id") => expect_task_string(value, 256, true),
        ("plan.created" | "plan.revised", "revision") => expect_integer(value, 1, None),
        ("provider.selected" | "placement.selected", "locality") => {
            expect_one_of(value, &["local", "remote", "peer", "cloud"])
        }
        ("provider.selected" | "placement.selected", "isolation_class") => {
            expect_one_of(value, &["P0", "P1", "P2", "P3"])
        }
        ("execution.started", "attempt_id") => expect_identifier(value, 256),
        ("execution.started", "binding_id") => expect_identifier(value, 256),
        ("execution.started", "node_id") => expect_identifier(value, 128),
        ("execution.started" | "execution.completed" | "execution.failed", "operation_id") => {
            expect_identifier(value, 256)
        }
        ("execution.started" | "execution.completed" | "execution.failed", "phase") => {
            expect_one_of(
                value,
                &[
                    "admitted",
                    "delivered",
                    "pre-destination-admission",
                    "effect-boundary-armed",
                ],
            )
        }
        ("execution.started", "intent_hash") => expect_digest(value),
        (
            "execution.started" | "execution.completed" | "execution.failed",
            "admission_event_id",
        ) => expect_nullable_identifier(value, 256),
        (
            "execution.started" | "execution.completed" | "execution.failed",
            "admission_event_hash",
        ) => expect_nullable_digest(value),
        ("execution.started", "execution_profile") => expect_identifier(value, 256),
        ("execution.completed" | "execution.failed", "outcome_certainty") => {
            expect_certainty(value)
        }
        ("execution.completed" | "execution.failed", "effect_boundary") => {
            expect_one_of(value, &["destination-not-invoked"])
        }
        ("execution.completed" | "execution.failed", "certainty") => expect_certainty(value),
        ("execution.completed" | "execution.failed", "export_reconciliation") => {
            validate_export_reconciliation(value)
        }
        ("execution.completed" | "execution.failed", "recovery_ref") => {
            expect_identifier(value, 256)
        }
        ("execution.completed" | "execution.failed", "inventory_id") => {
            expect_identifier(value, 256)
        }
        ("execution.completed" | "execution.failed", "safe_action") => expect_one_of(
            value,
            &[
                "CREATE_NEW_ATTEMPT",
                "RECONCILE_STATE",
                "MARK_ATTEMPT_FAILED",
                "REQUIRE_EXTERNAL_RECONCILIATION",
                "FAIL_TASK",
                "NO_ACTION",
                "CLEAN_STAGING",
            ],
        ),
        ("execution.completed" | "execution.failed", "reason_code") => expect_reason_code(value),
        ("execution.completed" | "execution.failed", "attempt") => expect_integer(value, 1, None),
        ("execution.completed" | "execution.failed", "duration_ms") => {
            expect_integer(value, 0, None)
        }
        (
            "artifact.imported" | "artifact.created" | "artifact.integrity-failed",
            "content_hash",
        ) => expect_digest(value),
        ("artifact.imported" | "artifact.created" | "artifact.exported", "size_bytes") => {
            expect_integer(value, 0, None)
        }
        ("artifact.imported" | "artifact.created", "blob_reused") => expect_bool(value),
        ("artifact.imported", "import_id") => expect_nullable_identifier(value, 256),
        ("artifact.imported" | "artifact.integrity-failed", "request_digest") => {
            expect_digest(value)
        }
        ("artifact.imported", "source") => expect_one_of(value, &["user-selected"]),
        ("artifact.created" | "artifact.integrity-failed", "allocation_id") => {
            expect_identifier(value, 256)
        }
        ("artifact.created" | "artifact.integrity-failed", "publication_id") => {
            expect_identifier(value, 256)
        }
        ("artifact.created", "type") => expect_token(value, 256),
        ("artifact.exported", "operation_id") => expect_identifier(value, 256),
        ("artifact.integrity-failed", "observation_ordinal") => expect_integer(value, 1, None),
        ("artifact.integrity-failed", "previous_durability_state") => {
            expect_nullable_durability_state(value)
        }
        ("artifact.integrity-failed", "durability_state") => expect_durability_state(value),
        ("artifact.integrity-failed", "reason_code") => expect_reason_code(value),
        ("artifact.integrity-failed", "resulted_at") => expect_timestamp(value),
        ("verification.started" | "verification.completed" | "verification.failed", "index") => {
            expect_integer(value, 1, None)
        }
        (
            "verification.started" | "verification.completed" | "verification.failed",
            "verified_claims" | "failed_claims",
        ) => expect_integer(value, 0, None),
        ("task.completed", "revision") => expect_integer(value, 1, None),
        ("task.completed", "external_egress" | "verified") => expect_bool(value),
        _ => Err(invalid_details("detail field has no typed value contract")),
    }
}

fn validate_creation_details(value: &Value) -> Result<()> {
    let object = expect_exact_object(
        value,
        &[
            "principal",
            "workspace_id",
            "original_intent_ref",
            "normalized_intent_ref",
            "constraints",
            "created_at",
        ],
    )?;
    for (key, value) in object {
        match key.as_str() {
            "principal" => validate_principal(value)?,
            "workspace_id" => expect_nullable_task_string(value, 256)?,
            "original_intent_ref" => validate_commitment(value, "original_intent", false)?,
            "normalized_intent_ref" => {
                validate_commitment(value, "normalized_intent", true)?;
            }
            "constraints" => expect_null(value)?,
            "created_at" => expect_timestamp(value)?,
            _ => unreachable!("object keys were checked"),
        }
    }
    Ok(())
}

fn validate_principal(value: &Value) -> Result<()> {
    let object = expect_exact_object(value, &["kind", "id"])?;
    expect_one_of(&object["kind"], &["user", "system-service"])?;
    expect_task_string(&object["id"], 256, true)
}

fn validate_active_program(value: &Value) -> Result<()> {
    if value.is_null() {
        return Ok(());
    }
    let object = expect_exact_object(
        value,
        &[
            "program_id",
            "ir_version",
            "semantic_hash",
            "registry_snapshot_id",
            "validation_result_id",
            "validated_at",
            "validator_id",
            "validator_version",
            "program_content_digest",
        ],
    )?;
    expect_identifier(&object["program_id"], 256)?;
    expect_token(&object["ir_version"], 64)?;
    expect_digest(&object["semantic_hash"])?;
    expect_identifier(&object["registry_snapshot_id"], 256)?;
    expect_nullable_identifier(&object["validation_result_id"], 256)?;
    expect_nullable_timestamp(&object["validated_at"])?;
    expect_nullable_identifier(&object["validator_id"], 256)?;
    expect_nullable_token(&object["validator_version"], 128)?;
    expect_digest(&object["program_content_digest"])
}

fn validate_mutation_commitments(value: &Value) -> Result<()> {
    let object = expect_exact_object(value, &["waiting_on", "failure_summary"])?;
    validate_waiting_on(&object["waiting_on"], true)?;
    validate_commitment(&object["failure_summary"], "failure_summary", true)
}

fn validate_waiting_on(value: &Value, with_commitments: bool) -> Result<()> {
    if value.is_null() && with_commitments {
        return Ok(());
    }
    let values = value
        .as_array()
        .ok_or_else(|| invalid_details("waiting_on must be an array"))?;
    if values.len() > 64 {
        return Err(invalid_details("waiting_on exceeds its item bound"));
    }
    for value in values {
        let keys: &[&str] = if with_commitments {
            &["kind", "id", "message_ref"]
        } else {
            &["kind", "id"]
        };
        let object = expect_exact_object(value, keys)?;
        expect_one_of(
            &object["kind"],
            &["input", "approval", "resource", "provider", "validation"],
        )?;
        expect_task_string(&object["id"], 256, true)?;
        if with_commitments {
            validate_commitment(&object["message_ref"], "waiting_message", true)?;
        }
    }
    Ok(())
}

fn validate_export_reconciliation(value: &Value) -> Result<()> {
    let object = expect_exact_object(
        value,
        &[
            "verifier_id",
            "evidence_ref",
            "proof_hash",
            "challenge",
            "observed_at",
            "subject_hash",
            "recovery_ref",
        ],
    )?;
    expect_identifier(&object["verifier_id"], 256)?;
    expect_identifier(&object["evidence_ref"], 256)?;
    expect_digest(&object["proof_hash"])?;
    expect_identifier(&object["challenge"], 128)?;
    expect_timestamp(&object["observed_at"])?;
    expect_digest(&object["subject_hash"])?;
    expect_identifier(&object["recovery_ref"], 256)
}

fn validate_commitment(value: &Value, expected_field: &str, nullable: bool) -> Result<()> {
    if value.is_null() {
        return if nullable {
            Ok(())
        } else {
            Err(invalid_details("required commitment is null"))
        };
    }
    let object = expect_exact_object(
        value,
        &["kind", "version", "algorithm", "field", "commitment"],
    )?;
    if object.get("kind").and_then(Value::as_str) != Some("task-field-commitment")
        || object.get("version").and_then(Value::as_str) != Some("v1")
        || object.get("algorithm").and_then(Value::as_str) != Some("sha256-keyed-prefix")
        || object.get("field").and_then(Value::as_str) != Some(expected_field)
    {
        return Err(invalid_details("commitment profile or field is invalid"));
    }
    expect_digest(&object["commitment"])
}

fn expect_exact_object<'a>(
    value: &'a Value,
    keys: &[&str],
) -> Result<&'a serde_json::Map<String, Value>> {
    let object = expect_object_keys(value, keys)?;
    if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
        return Err(invalid_details("typed detail object has missing fields"));
    }
    Ok(object)
}

fn expect_object_keys<'a>(
    value: &'a Value,
    keys: &[&str],
) -> Result<&'a serde_json::Map<String, Value>> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid_details("typed detail value must be an object"))?;
    if object.keys().any(|key| !keys.contains(&key.as_str())) {
        return Err(invalid_details("typed detail object has an unknown field"));
    }
    Ok(object)
}

fn expect_integer(value: &Value, minimum: u64, maximum: Option<u64>) -> Result<()> {
    if value
        .as_u64()
        .is_some_and(|value| value >= minimum && maximum.is_none_or(|maximum| value <= maximum))
    {
        Ok(())
    } else {
        Err(invalid_details(
            "detail value must be a bounded unsigned integer",
        ))
    }
}

fn expect_bool(value: &Value) -> Result<()> {
    if value.is_boolean() {
        Ok(())
    } else {
        Err(invalid_details("detail value must be a boolean"))
    }
}

fn expect_null(value: &Value) -> Result<()> {
    if value.is_null() {
        Ok(())
    } else {
        Err(invalid_details("detail value must be null"))
    }
}

fn expect_identifier(value: &Value, maximum: usize) -> Result<()> {
    let value = value
        .as_str()
        .ok_or_else(|| invalid_details("identifier detail must be a string"))?;
    let length = value.chars().count();
    if length == 0
        || length > maximum
        || !value.chars().all(|character| {
            character.is_alphanumeric()
                || matches!(character, '.' | '_' | ':' | '/' | '@' | '+' | '-')
        })
    {
        return Err(invalid_details("identifier detail has invalid syntax"));
    }
    Ok(())
}

fn expect_nullable_identifier(value: &Value, maximum: usize) -> Result<()> {
    if value.is_null() {
        Ok(())
    } else {
        expect_identifier(value, maximum)
    }
}

fn expect_task_string(value: &Value, maximum: usize, nonempty: bool) -> Result<()> {
    let value = value
        .as_str()
        .ok_or_else(|| invalid_details("Task-origin detail must be a string"))?;
    let length = value.chars().count();
    if length > maximum || (nonempty && length == 0) {
        return Err(invalid_details(
            "Task-origin detail exceeds its Unicode-scalar bounds",
        ));
    }
    Ok(())
}

fn expect_nullable_task_string(value: &Value, maximum: usize) -> Result<()> {
    if value.is_null() {
        Ok(())
    } else {
        expect_task_string(value, maximum, true)
    }
}

fn expect_task_string_array(
    value: &Value,
    maximum_items: usize,
    maximum_chars: usize,
    nonempty: bool,
) -> Result<()> {
    let values = value
        .as_array()
        .ok_or_else(|| invalid_details("Task-origin collection must be an array"))?;
    if values.len() > maximum_items {
        return Err(invalid_details(
            "Task-origin collection exceeds its item bound",
        ));
    }
    let mut unique = std::collections::BTreeSet::new();
    for value in values {
        expect_task_string(value, maximum_chars, nonempty)?;
        let value = value
            .as_str()
            .expect("Task-origin string was validated above");
        if !unique.insert(value) {
            return Err(invalid_details(
                "Task-origin collection contains duplicate values",
            ));
        }
    }
    Ok(())
}

fn expect_token(value: &Value, maximum: usize) -> Result<()> {
    expect_identifier(value, maximum)
}

fn expect_nullable_token(value: &Value, maximum: usize) -> Result<()> {
    expect_nullable_identifier(value, maximum)
}

fn expect_identifier_array(
    value: &Value,
    maximum_items: usize,
    maximum_chars: usize,
) -> Result<()> {
    let values = value
        .as_array()
        .ok_or_else(|| invalid_details("identifier collection must be an array"))?;
    if values.len() > maximum_items {
        return Err(invalid_details(
            "identifier collection exceeds its item bound",
        ));
    }
    for value in values {
        expect_identifier(value, maximum_chars)?;
    }
    Ok(())
}

fn expect_token_array(value: &Value, maximum_items: usize, maximum_chars: usize) -> Result<()> {
    expect_identifier_array(value, maximum_items, maximum_chars)
}

fn expect_one_of(value: &Value, allowed: &[&str]) -> Result<()> {
    if value.as_str().is_some_and(|value| allowed.contains(&value)) {
        Ok(())
    } else {
        Err(invalid_details(
            "detail value is not an allowed enum member",
        ))
    }
}

fn expect_reason_code(value: &Value) -> Result<()> {
    let value = value
        .as_str()
        .ok_or_else(|| invalid_details("reason code must be a string"))?;
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().enumerate().all(|(index, byte)| {
            (index != 0 || byte.is_ascii_uppercase())
                && (byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        })
    {
        return Err(invalid_details("reason code has invalid syntax"));
    }
    Ok(())
}

fn expect_digest(value: &Value) -> Result<()> {
    if value.as_str().is_some_and(valid_hash) {
        Ok(())
    } else {
        Err(invalid_details("digest detail must be lowercase sha256"))
    }
}

fn expect_nullable_digest(value: &Value) -> Result<()> {
    if value.is_null() {
        Ok(())
    } else {
        expect_digest(value)
    }
}

fn expect_timestamp(value: &Value) -> Result<()> {
    value
        .as_str()
        .ok_or_else(|| invalid_details("timestamp detail must be a string"))
        .and_then(validate_timestamp)
}

fn expect_nullable_timestamp(value: &Value) -> Result<()> {
    if value.is_null() {
        Ok(())
    } else {
        expect_timestamp(value)
    }
}

fn expect_certainty(value: &Value) -> Result<()> {
    expect_one_of(
        value,
        &[
            "NOT_STARTED",
            "STARTED_NO_EFFECT",
            "COMPLETED",
            "FAILED_NO_EFFECT",
            "FAILED_PARTIAL_EFFECT",
            "OUTCOME_UNKNOWN",
        ],
    )
}

fn expect_durability_state(value: &Value) -> Result<()> {
    expect_one_of(
        value,
        &["STAGED", "DURABLE", "ORPHANED", "CORRUPT", "MISSING"],
    )
}

fn expect_nullable_durability_state(value: &Value) -> Result<()> {
    if value.is_null() {
        Ok(())
    } else {
        expect_durability_state(value)
    }
}

fn invalid_details(message: &str) -> Error {
    Error::InvalidRecord(format!(
        "invalid privacy-safe provenance details: {message}"
    ))
}

fn json_depth(value: &Value) -> usize {
    match value {
        Value::Array(values) => 1 + values.iter().map(json_depth).max().unwrap_or(0),
        Value::Object(values) => 1 + values.values().map(json_depth).max().unwrap_or(0),
        _ => 1,
    }
}

fn within_shape_bounds(value: &Value) -> bool {
    match value {
        Value::String(value) => value.chars().count() <= MAX_STRING_CHARS,
        Value::Array(values) => {
            values.len() <= MAX_ARRAY_ITEMS && values.iter().all(within_shape_bounds)
        }
        Value::Object(values) => {
            values.len() <= MAX_OBJECT_FIELDS
                && values
                    .iter()
                    .all(|(key, value)| key.chars().count() <= 256 && within_shape_bounds(value))
        }
        _ => true,
    }
}

fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<JournalRecord> {
    let sequence = row.get::<_, i64>(3)?;
    let event_bytes = match row.get_ref(5)? {
        rusqlite::types::ValueRef::Text(bytes) => bytes,
        value => {
            return Err(rusqlite::Error::InvalidColumnType(
                5,
                "event_json".to_owned(),
                value.data_type(),
            ));
        }
    };
    if event_bytes.len() > MAX_EVENT_BYTES {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            5,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "stored provenance event exceeds its byte bound",
            )),
        ));
    }
    let event = serde_json::from_slice(event_bytes).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(JournalRecord {
        schema_version: bounded_row_text(row, 0)?,
        hash_profile: bounded_row_text(row, 1)?,
        stream_id: bounded_row_text(row, 2)?,
        sequence: u64::try_from(sequence).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                3,
                rusqlite::types::Type::Integer,
                Box::new(error),
            )
        })?,
        previous_event_hash: bounded_nullable_row_text(row, 4)?,
        event,
        event_hash: bounded_row_text(row, 6)?,
    })
}

fn bounded_row_text(row: &rusqlite::Row<'_>, column: usize) -> rusqlite::Result<String> {
    if let rusqlite::types::ValueRef::Text(bytes) = row.get_ref(column)? {
        if bytes.len() > MAX_EVENT_BYTES {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                column,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "stored provenance text column exceeds its byte bound",
                )),
            ));
        }
    }
    row.get(column)
}

fn bounded_nullable_row_text(
    row: &rusqlite::Row<'_>,
    column: usize,
) -> rusqlite::Result<Option<String>> {
    match row.get_ref(column)? {
        rusqlite::types::ValueRef::Null => Ok(None),
        rusqlite::types::ValueRef::Text(_) => bounded_row_text(row, column).map(Some),
        _ => row.get(column),
    }
}

fn string_field<'a>(event: &'a Value, key: &str) -> Option<&'a str> {
    event.get(key).and_then(Value::as_str)
}

fn verifier() -> VerifierIdentity {
    VerifierIdentity {
        id: "aios-provenance".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        build_hash: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn failure(
    stream_id: &str,
    verified_at: &str,
    code: &str,
    message: &str,
    sequence: Option<u64>,
    event_id: Option<String>,
    computed_head_hash: Option<String>,
    checkpoint: Option<&CheckpointExpectation>,
) -> VerificationResult {
    VerificationResult {
        schema_version: SCHEMA_VERSION.to_owned(),
        valid: false,
        stream_id: stream_id.to_owned(),
        from_sequence: 1,
        to_sequence: sequence.unwrap_or(1).max(1),
        expected_head_hash: checkpoint.map(|value| value.event_hash.clone()),
        computed_head_hash,
        checkpoint_id: checkpoint.map(|value| value.checkpoint_id.clone()),
        verifier: verifier(),
        diagnostics: vec![VerificationDiagnostic {
            severity: Severity::Error,
            code: code.to_owned(),
            message: message.to_owned(),
            sequence,
            event_id,
            related: Vec::new(),
        }],
        diagnostics_truncated: false,
        verified_at: verified_at.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: &str = "2026-09-21T12:00:00Z";

    fn connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        initialize(&connection);
        connection
    }

    fn initialize(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE provenance_events (
                schema_version TEXT NOT NULL,
                hash_profile TEXT NOT NULL,
                event_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                stream_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
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
                UNIQUE(stream_id, sequence)
            );",
            )
            .unwrap();
    }

    fn event(task_id: &str, index: u64) -> Value {
        if index == 1 {
            let mut event = typed_creation_event(task_id, 1);
            event["event_id"] = json!("event-1");
            return event;
        }
        json!({
            "schema_version":"0.1",
            "event_id":format!("event-{index}"),
            "task_id":task_id,
            "event_type":"verification.started",
            "timestamp":NOW,
            "actor":{"kind":"system-service","id":"service:test"},
            "status":"success",
            "details":{"index":index}
        })
    }

    fn commitment(field: &str) -> Value {
        json!({
            "kind":"task-field-commitment",
            "version":"v1",
            "algorithm":"sha256-keyed-prefix",
            "field":field,
            "commitment":format!("sha256:{}", "a".repeat(64))
        })
    }

    fn typed_creation_event(task_id: &str, suffix: usize) -> Value {
        json!({
            "schema_version":"0.1",
            "event_id":format!("event-typed-{suffix}"),
            "task_id":task_id,
            "event_type":"task.created",
            "timestamp":NOW,
            "actor":{"kind":"system-service","id":"service:test"},
            "status":"success",
            "details":{
                "revision":1,
                "creation":{
                    "principal":{"kind":"user","id":"user:test"},
                    "workspace_id":"workspace:test",
                    "original_intent_ref":commitment("original_intent"),
                    "normalized_intent_ref":null,
                    "constraints":null,
                    "created_at":NOW
                },
                "active_plan":null,
                "active_step_ids":["step:test"],
                "waiting_on":[],
                "failure":null,
                "recovery":null
            }
        })
    }

    fn typed_transition_event(task_id: &str) -> Value {
        json!({
            "schema_version":"0.1",
            "event_id":"event-typed-transition",
            "task_id":task_id,
            "event_type":"task.transitioned",
            "timestamp":NOW,
            "actor":{"kind":"system-service","id":"service:test"},
            "status":"success",
            "task_transition":{
                "transition_id":"transition:test",
                "previous_state":"CREATED",
                "new_state":"PLANNING",
                "previous_revision":1,
                "new_revision":2,
                "reason_code":"PLANNING_REQUESTED"
            },
            "committed_mutation":{
                "active_plan":null,
                "active_step_ids":null,
                "waiting_on":null,
                "failure":null,
                "recovery":null
            },
            "details":{
                "related_ids":[],
                "reason_message_ref":commitment("reason_message"),
                "active_program":null,
                "mutation_text_commitments":{"waiting_on":null,"failure_summary":null}
            }
        })
    }

    fn append_many(connection: &mut Connection, count: u64) -> Vec<JournalRecord> {
        let transaction = connection.transaction().unwrap();
        let mut records = Vec::new();
        for index in 1..=count {
            records.push(
                append_in_tx(
                    &transaction,
                    "T-provenance",
                    &event("T-provenance", index),
                    &ExpectedHead::Any,
                )
                .unwrap(),
            );
        }
        transaction.commit().unwrap();
        records
    }

    fn rehash_projection(
        export: &ProjectionPortableExport,
        mutate: impl FnOnce(&mut Vec<ProjectedRecord>),
    ) -> ProjectionPortableExport {
        let mut records = export
            .records_jsonl
            .lines()
            .map(|line| serde_json::from_str::<ProjectedRecord>(line).unwrap())
            .collect::<Vec<_>>();
        mutate(&mut records);
        let mut previous = None;
        for (index, record) in records.iter_mut().enumerate() {
            record.sequence = index as u64 + 1;
            record.previous_projection_hash = previous;
            record.projection_hash = hash_projected_record(
                &record.bundle_id,
                record.sequence,
                record.previous_projection_hash.as_deref(),
                &record.projected_event,
            )
            .unwrap();
            previous = Some(record.projection_hash.clone());
        }
        let mut manifest: ProjectionManifest = serde_json::from_str(&export.manifest_json).unwrap();
        manifest.record_count = records.len() as u64;
        manifest.head_sequence = records.last().map_or(0, |record| record.sequence);
        manifest.head_projection_hash = records
            .last()
            .map_or_else(String::new, |record| record.projection_hash.clone());
        manifest.descriptor_hash = hash_projection_descriptor(&manifest).unwrap();
        ProjectionPortableExport {
            manifest_json: serde_json::to_string(&manifest).unwrap(),
            records_jsonl: records
                .iter()
                .map(|record| serde_json::to_string(record).unwrap())
                .collect::<Vec<_>>()
                .join("\n")
                + "\n",
        }
    }

    fn projection_rejected(export: &ProjectionPortableExport) -> bool {
        verify_jsonl_export(&export.manifest_json, &export.records_jsonl, NOW)
            .map_or(true, |result| !result.valid)
    }

    #[test]
    fn hundred_event_stream_pages_and_verifies() {
        let mut connection = connection();
        append_many(&mut connection, 100);
        let stream = stream_id("T-provenance").unwrap();
        let debug_page = list_events(&connection, &stream, None, 1).unwrap();
        assert!(validate_event("T-provenance", &debug_page.records[0].event).is_ok());
        assert!(
            valid_hash(&debug_page.records[0].event_hash),
            "{}",
            debug_page.records[0].event_hash
        );
        let result = verify_stream(&connection, &stream, None, None, NOW).unwrap();
        assert!(result.valid, "{result:?}");
        assert_eq!(result.to_sequence, 100);
        let first = list_events(&connection, &stream, None, 40).unwrap();
        assert_eq!(first.records.len(), 40);
        let second = list_events(&connection, &stream, first.next_cursor, 40).unwrap();
        assert_eq!(second.records[0].sequence, 41);
        assert_eq!(
            get_head(&connection, &stream).unwrap().unwrap().sequence,
            100
        );
    }

    #[test]
    fn task_stream_identity_is_regression_locked() {
        assert_eq!(
            stream_id("T-provenance").unwrap(),
            "task:v1:sha256:880d20240feb241c692d7172e1831e11cc3cd2550183bfc477660ee23ffdde53"
        );
    }

    #[test]
    fn structured_verification_detects_field_previous_delete_and_reorder_tamper() {
        let mut connection = connection();
        let records = append_many(&mut connection, 4);
        let stream = stream_id("T-provenance").unwrap();

        let mut field = records.clone();
        field[2].event["status"] = json!("failure");
        assert_eq!(
            verify_records(&field, &stream, None, NOW).diagnostics[0].code,
            "PROVENANCE_EVENT_HASH_MISMATCH"
        );

        let mut previous = records.clone();
        previous[3].previous_event_hash = Some(format!("sha256:{}", "a".repeat(64)));
        assert_eq!(
            verify_records(&previous, &stream, None, NOW).diagnostics[0].code,
            "PROVENANCE_PREVIOUS_HASH_MISMATCH"
        );

        let mut deleted = records.clone();
        deleted.remove(1);
        let result = verify_records(&deleted, &stream, None, NOW);
        assert_eq!(result.diagnostics[0].code, "PROVENANCE_SEQUENCE_GAP");
        assert_eq!(result.diagnostics[0].sequence, Some(3));

        let mut reordered = records;
        reordered.swap(1, 2);
        assert_eq!(
            verify_records(&reordered, &stream, None, NOW).diagnostics[0].code,
            "PROVENANCE_SEQUENCE_ORDER_INVALID"
        );
    }

    #[test]
    fn streaming_verification_preserves_sequence_hash_and_index_diagnostics() {
        for (sql, expected_code) in [
            (
                "DELETE FROM provenance_events WHERE sequence=2",
                "PROVENANCE_SEQUENCE_GAP",
            ),
            (
                "UPDATE provenance_events SET previous_event_hash='sha256:bad' WHERE sequence=2",
                "PROVENANCE_PREVIOUS_HASH_MISMATCH",
            ),
            (
                "UPDATE provenance_events SET event_hash='sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' WHERE sequence=2",
                "PROVENANCE_EVENT_HASH_MISMATCH",
            ),
            (
                "UPDATE provenance_events SET status='failure' WHERE sequence=2",
                "PROVENANCE_SCHEMA_INVALID",
            ),
            (
                "UPDATE provenance_events SET sequence=5 WHERE sequence=2",
                "PROVENANCE_SEQUENCE_GAP",
            ),
        ] {
            let mut connection = connection();
            append_many(&mut connection, 4);
            connection.execute_batch(sql).unwrap();
            let stream = stream_id("T-provenance").unwrap();
            let result = verify_stream(&connection, &stream, None, None, NOW).unwrap();
            assert!(!result.valid, "{sql}");
            assert_eq!(result.diagnostics[0].code, expected_code, "{sql}");
        }
    }

    #[test]
    fn oversized_stored_event_is_rejected_before_json_parse_by_all_row_readers() {
        let mut connection = connection();
        append_many(&mut connection, 1);
        let stream = stream_id("T-provenance").unwrap();
        let event_json: String = connection
            .query_row(
                "SELECT event_json FROM provenance_events WHERE stream_id=?1",
                [&stream],
                |row| row.get(0),
            )
            .unwrap();
        let oversized = format!("{event_json}{}", " ".repeat(1_048_576));
        connection
            .execute(
                "UPDATE provenance_events SET event_json=?2 WHERE stream_id=?1",
                params![stream, oversized],
            )
            .unwrap();
        let result = verify_stream(&connection, &stream, None, None, NOW).unwrap();
        assert!(!result.valid);
        assert_eq!(result.diagnostics[0].code, "PROVENANCE_SCHEMA_INVALID");
        assert!(
            list_events(&connection, &stream, None, 1)
                .unwrap_err()
                .to_string()
                .contains("stored provenance event exceeds its byte bound")
        );
    }

    #[test]
    fn oversized_stored_index_columns_fail_before_owned_text_materialization() {
        for column in ["event_id", "event_hash"] {
            let mut connection = connection();
            append_many(&mut connection, 1);
            let stream = stream_id("T-provenance").unwrap();
            let oversized = "x".repeat(1_048_576);
            connection
                .execute(
                    &format!("UPDATE provenance_events SET {column}=?1 WHERE stream_id=?2"),
                    params![oversized, stream],
                )
                .unwrap();
            let result = verify_stream(&connection, &stream, None, None, NOW).unwrap();
            assert!(!result.valid, "{column}");
            assert_eq!(result.diagnostics[0].code, "PROVENANCE_SCHEMA_INVALID");
            if column == "event_hash" {
                assert!(
                    list_events(&connection, &stream, None, 1)
                        .unwrap_err()
                        .to_string()
                        .contains("stored provenance text column exceeds its byte bound")
                );
                assert!(get_head(&connection, &stream).is_err());
                let transaction = connection.transaction().unwrap();
                assert!(
                    append_in_tx(
                        &transaction,
                        "T-provenance",
                        &event("T-provenance", 2),
                        &ExpectedHead::Any,
                    )
                    .is_err()
                );
            }
        }

        let mut connection = connection();
        append_many(&mut connection, 1);
        let stream = stream_id("T-provenance").unwrap();
        connection
            .execute(
                "UPDATE provenance_events SET event_hash='invalid' WHERE stream_id=?1",
                [&stream],
            )
            .unwrap();
        assert!(get_head(&connection, &stream).is_err());
    }

    #[test]
    fn append_rejects_payload_hash_fields_bounds_and_stale_heads() {
        let mut invalid_genesis_connection = connection();
        let invalid_genesis_tx = invalid_genesis_connection.transaction().unwrap();
        assert!(
            append_in_tx(
                &invalid_genesis_tx,
                "T-provenance",
                &event("T-provenance", 2),
                &ExpectedHead::Empty,
            )
            .is_err()
        );

        let mut connection = connection();
        let transaction = connection.transaction().unwrap();
        let first = append_in_tx(
            &transaction,
            "T-provenance",
            &event("T-provenance", 1),
            &ExpectedHead::Empty,
        )
        .unwrap();
        let mut injected = event("T-provenance", 2);
        injected["event_hash"] = Value::Null;
        assert!(append_in_tx(&transaction, "T-provenance", &injected, &ExpectedHead::Any).is_err());
        let base_hash = hash_record(
            &stream_id("T-provenance").unwrap(),
            2,
            Some(&first.event_hash),
            &event("T-provenance", 2),
        )
        .unwrap();
        injected["previous_event_hash"] = json!(format!("sha256:{}", "b".repeat(64)));
        assert_eq!(
            base_hash,
            hash_record(
                &stream_id("T-provenance").unwrap(),
                2,
                Some(&first.event_hash),
                &injected
            )
            .unwrap()
        );
        let stale = ExpectedHead::Exact {
            sequence: 1,
            event_hash: format!("sha256:{}", "f".repeat(64)),
        };
        assert!(
            append_in_tx(
                &transaction,
                "T-provenance",
                &event("T-provenance", 2),
                &stale
            )
            .is_err()
        );
        let exact = ExpectedHead::Exact {
            sequence: 1,
            event_hash: first.event_hash,
        };
        append_in_tx(
            &transaction,
            "T-provenance",
            &event("T-provenance", 2),
            &exact,
        )
        .unwrap();
        let mut oversized = event("T-provenance", 3);
        oversized["details"] = json!({"value":"x".repeat(MAX_DETAILS_BYTES + 1)});
        assert!(
            append_in_tx(&transaction, "T-provenance", &oversized, &ExpectedHead::Any).is_err()
        );
    }

    #[test]
    fn details_vocabulary_rejects_private_aliases_and_unknown_nested_keys() {
        let mut connection = connection();
        let transaction = connection.transaction().unwrap();
        append_in_tx(
            &transaction,
            "T-provenance",
            &event("T-provenance", 1),
            &ExpectedHead::Empty,
        )
        .unwrap();
        for (index, key) in [
            "model_prompt",
            "apiKey",
            "prompt",
            "body",
            "content",
            "debug_dump",
            "credential",
            "api_key",
            "accessToken",
            "authorizationHeader",
        ]
        .into_iter()
        .enumerate()
        {
            let mut candidate = event("T-provenance", index as u64 + 2);
            candidate["details"] = json!({(key):"private"});
            assert!(
                append_in_tx(&transaction, "T-provenance", &candidate, &ExpectedHead::Any).is_err(),
                "unexpectedly accepted private detail alias {key}"
            );
        }

        let mut nested = event("T-nested", 1);
        nested["details"] = json!({
            "revision":1,
            "creation":{"original_intent_ref":null,"apiKey":"private"}
        });
        assert!(append_in_tx(&transaction, "T-nested", &nested, &ExpectedHead::Empty).is_err());

        let stream = stream_id("T-nested").unwrap();
        let event_hash = hash_record(&stream, 1, None, &nested).unwrap();
        let record = JournalRecord {
            schema_version: SCHEMA_VERSION.to_owned(),
            hash_profile: HASH_PROFILE.to_owned(),
            stream_id: stream.clone(),
            sequence: 1,
            previous_event_hash: None,
            event: nested,
            event_hash: event_hash.clone(),
        };
        let manifest = LegacyExportManifest {
            schema_version: SCHEMA_VERSION.to_owned(),
            export_profile: "privacy-safe-original-chain".to_owned(),
            hash_profile: HASH_PROFILE.to_owned(),
            stream_id: stream,
            record_count: 1,
            head_sequence: 1,
            head_event_hash: event_hash,
        };
        assert!(
            verify_jsonl_export(
                &serde_json::to_string(&manifest).unwrap(),
                &format!("{}\n", serde_json::to_string(&record).unwrap()),
                NOW,
            )
            .is_err()
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "covers append, offline verification, and export with one shared adversarial vector set"
    )]
    fn typed_details_reject_private_scalars_and_malformed_commitments_everywhere() {
        let mut connection = connection();
        let transaction = connection.transaction().unwrap();
        let mut cases = Vec::new();

        let mut wrong_revision = typed_creation_event("T-typed-revision", 1);
        wrong_revision["details"]["revision"] = json!("raw private text");
        cases.push(wrong_revision);

        let mut empty_workspace = typed_creation_event("T-typed-workspace", 2);
        empty_workspace["details"]["creation"]["workspace_id"] = json!("");
        cases.push(empty_workspace);

        let mut wrong_number = typed_creation_event("T-typed-number", 3);
        wrong_number["details"]["revision"] = json!(1.5);
        cases.push(wrong_number);

        let mut null_required = typed_creation_event("T-typed-null-commitment", 4);
        null_required["details"]["creation"]["original_intent_ref"] = Value::Null;
        cases.push(null_required);

        let mut missing_field = typed_creation_event("T-typed-missing-commitment", 5);
        missing_field["details"]["creation"]["original_intent_ref"]
            .as_object_mut()
            .unwrap()
            .remove("algorithm");
        cases.push(missing_field);

        for (suffix, path, value) in [
            (
                6,
                "/details/creation/original_intent_ref/kind",
                json!("other"),
            ),
            (
                7,
                "/details/creation/original_intent_ref/version",
                json!("v2"),
            ),
            (
                8,
                "/details/creation/original_intent_ref/algorithm",
                json!("sha256"),
            ),
            (
                9,
                "/details/creation/original_intent_ref/field",
                json!("normalized_intent"),
            ),
            (
                10,
                "/details/creation/original_intent_ref/commitment",
                json!(format!("sha256:{}", "A".repeat(64))),
            ),
        ] {
            let task_id = format!("T-typed-commitment-{suffix}");
            let mut candidate = typed_creation_event(&task_id, suffix);
            *candidate.pointer_mut(path).unwrap() = value;
            cases.push(candidate);
        }

        let mut wrong_normalized = typed_creation_event("T-typed-normalized-field", 11);
        wrong_normalized["details"]["creation"]["normalized_intent_ref"] =
            commitment("original_intent");
        cases.push(wrong_normalized);

        for candidate in cases {
            let task_id = candidate["task_id"].as_str().unwrap();
            assert!(
                append_in_tx(&transaction, task_id, &candidate, &ExpectedHead::Empty).is_err(),
                "unexpectedly accepted typed private or malformed detail: {candidate}"
            );
        }

        append_in_tx(
            &transaction,
            "T-typed-transition",
            &typed_creation_event("T-typed-transition", 12),
            &ExpectedHead::Empty,
        )
        .unwrap();
        let mut bad_reason = typed_transition_event("T-typed-transition");
        bad_reason["details"]["reason_message_ref"]["field"] = json!("original_intent");
        assert!(
            append_in_tx(
                &transaction,
                "T-typed-transition",
                &bad_reason,
                &ExpectedHead::Any
            )
            .is_err()
        );
        let bad_machine_identifier = json!({
            "schema_version":"0.1",
            "event_id":"event-typed-machine-id",
            "task_id":"T-typed-transition",
            "event_type":"execution.started",
            "timestamp":NOW,
            "actor":{"kind":"system-service","id":"service:test"},
            "status":"pending",
            "details":{"attempt_id":"raw secret value"}
        });
        assert!(
            append_in_tx(
                &transaction,
                "T-typed-transition",
                &bad_machine_identifier,
                &ExpectedHead::Any
            )
            .is_err()
        );
        let bad_size = json!({
            "schema_version":"0.1",
            "event_id":"event-typed-size",
            "task_id":"T-typed-transition",
            "event_type":"artifact.exported",
            "timestamp":NOW,
            "actor":{"kind":"system-service","id":"service:test"},
            "input_artifacts":["artifact:test"],
            "output_artifacts":[],
            "external_transfer":{"destination":"local","data_refs":["artifact:test"]},
            "status":"success",
            "details":{"operation_id":"operation:test","size_bytes":"raw secret"}
        });
        assert!(
            append_in_tx(
                &transaction,
                "T-typed-transition",
                &bad_size,
                &ExpectedHead::Any
            )
            .is_err()
        );
        let bad_content_hash = json!({
            "schema_version":"0.1",
            "event_id":"event-typed-content-hash",
            "task_id":"T-typed-transition",
            "event_type":"artifact.created",
            "timestamp":NOW,
            "actor":{"kind":"system-service","id":"service:test"},
            "status":"success",
            "details":{
                "allocation_id":"allocation:test",
                "publication_id":"publication:test",
                "content_hash":"raw secret",
                "size_bytes":1,
                "blob_reused":false
            }
        });
        assert!(
            append_in_tx(
                &transaction,
                "T-typed-transition",
                &bad_content_hash,
                &ExpectedHead::Any
            )
            .is_err()
        );
        transaction.commit().unwrap();

        let mut invalid = typed_creation_event("T-offline-private", 13);
        invalid["details"]["creation"]["workspace_id"] = json!("");
        let stream = stream_id("T-offline-private").unwrap();
        let event_hash = hash_record(&stream, 1, None, &invalid).unwrap();
        let record = JournalRecord {
            schema_version: SCHEMA_VERSION.to_owned(),
            hash_profile: HASH_PROFILE.to_owned(),
            stream_id: stream.clone(),
            sequence: 1,
            previous_event_hash: None,
            event: invalid,
            event_hash: event_hash.clone(),
        };
        let manifest = LegacyExportManifest {
            schema_version: SCHEMA_VERSION.to_owned(),
            export_profile: "privacy-safe-original-chain".to_owned(),
            hash_profile: HASH_PROFILE.to_owned(),
            stream_id: stream,
            record_count: 1,
            head_sequence: 1,
            head_event_hash: event_hash,
        };
        assert!(
            verify_jsonl_export(
                &serde_json::to_string(&manifest).unwrap(),
                &format!("{}\n", serde_json::to_string(&record).unwrap()),
                NOW,
            )
            .is_err()
        );

        let mut export_connection = Connection::open_in_memory().unwrap();
        initialize(&export_connection);
        let transaction = export_connection.transaction().unwrap();
        let appended = append_in_tx(
            &transaction,
            "T-export-private",
            &event("T-export-private", 1),
            &ExpectedHead::Empty,
        )
        .unwrap();
        transaction.commit().unwrap();
        let mut forged = event("T-export-private", 1);
        forged["details"]["revision"] = json!("raw secret");
        let stream = stream_id("T-export-private").unwrap();
        let forged_hash = hash_record(&stream, 1, None, &forged).unwrap();
        export_connection
            .execute(
                "UPDATE provenance_events SET event_json=?2,event_hash=?3 WHERE event_id=?1",
                params![
                    appended.event["event_id"].as_str().unwrap(),
                    forged.to_string(),
                    forged_hash
                ],
            )
            .unwrap();
        assert!(export_jsonl(&export_connection, &stream, NOW).is_err());
    }

    #[test]
    fn portable_export_reverifies_offline_and_fails_closed() {
        let mut connection = connection();
        append_many(&mut connection, 4);
        let stream = stream_id("T-provenance").unwrap();
        let export = export_jsonl(&connection, &stream, NOW).unwrap();
        assert!(
            verify_jsonl_export(&export.manifest_json, &export.records_jsonl, NOW)
                .unwrap()
                .valid
        );
        let tampered = export
            .records_jsonl
            .replacen("\"success\"", "\"failure\"", 1);
        assert!(
            !verify_jsonl_export(&export.manifest_json, &tampered, NOW)
                .unwrap()
                .valid
        );
        assert!(verify_jsonl_export("{}", &export.records_jsonl, NOW).is_err());
        assert!(verify_jsonl_export(&export.manifest_json, "not-json\n", NOW).is_err());
        let records = list_events(&connection, &stream, None, 10).unwrap().records;
        let checkpoint = CheckpointExpectation {
            checkpoint_id: "checkpoint:test".to_owned(),
            event_hash: format!("sha256:{}", "c".repeat(64)),
        };
        let result = verify_records(&records, &stream, Some(&checkpoint), NOW);
        assert_eq!(
            result.diagnostics[0].code,
            "PROVENANCE_CHECKPOINT_HEAD_MISMATCH"
        );

        let invalid_event = event("T-provenance", 2);
        let invalid_hash = hash_record(&stream, 1, None, &invalid_event).unwrap();
        let invalid_record = JournalRecord {
            schema_version: SCHEMA_VERSION.to_owned(),
            hash_profile: HASH_PROFILE.to_owned(),
            stream_id: stream.clone(),
            sequence: 1,
            previous_event_hash: None,
            event: invalid_event,
            event_hash: invalid_hash.clone(),
        };
        let invalid_manifest = LegacyExportManifest {
            schema_version: SCHEMA_VERSION.to_owned(),
            export_profile: "privacy-safe-original-chain".to_owned(),
            hash_profile: HASH_PROFILE.to_owned(),
            stream_id: stream.clone(),
            record_count: 1,
            head_sequence: 1,
            head_event_hash: invalid_hash,
        };
        let invalid_jsonl = format!("{}\n", serde_json::to_string(&invalid_record).unwrap());
        assert!(
            verify_jsonl_export(
                &serde_json::to_string(&invalid_manifest).unwrap(),
                &invalid_jsonl,
                NOW,
            )
            .is_err()
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "projection privacy and adversarial integrity vectors share one fixture"
    )]
    fn redacted_projection_hides_all_identifier_channels_and_has_bounded_claims() {
        let secret = "api_key=sk-live/private text";
        let task_id = format!("task/{secret}");
        let mut connection = connection();
        let transaction = connection.transaction().unwrap();
        let mut created = typed_creation_event(&task_id, 1);
        created["event_id"] = json!(format!("event/{secret}"));
        created["actor"]["id"] = json!(secret);
        created["details"]["creation"]["principal"]["id"] = json!(secret);
        created["details"]["creation"]["workspace_id"] = json!(secret);
        created["details"]["active_step_ids"] = json!([secret, "Cafe\u{301}", "Café", "plan = 🧭"]);
        let first = append_in_tx(&transaction, &task_id, &created, &ExpectedHead::Empty).unwrap();
        let mut transitioned = typed_transition_event(&task_id);
        transitioned["event_id"] = json!(format!("transition-event/{secret}"));
        transitioned["step_id"] = json!(secret);
        transitioned["approval_id"] = json!(secret);
        transitioned["actor"]["id"] = json!(secret);
        transitioned["task_transition"]["transition_id"] = json!(secret);
        transitioned["committed_mutation"]["active_plan"] = json!({"plan_id":secret,"revision":1});
        transitioned["committed_mutation"]["active_step_ids"] = json!([secret]);
        transitioned["committed_mutation"]["waiting_on"] = json!([{"kind":"input","id":secret}]);
        transitioned["details"]["related_ids"] = json!([secret]);
        transitioned["details"]["mutation_text_commitments"]["waiting_on"] =
            json!([{"kind":"input","id":secret,"message_ref":null}]);
        append_in_tx(&transaction, &task_id, &transitioned, &ExpectedHead::Any).unwrap();
        transaction.commit().unwrap();

        let stream = stream_id(&task_id).unwrap();
        let source_before = list_events(&connection, &stream, None, 10).unwrap().records;
        let export = export_jsonl(&connection, &stream, NOW).unwrap();
        let source_after = list_events(&connection, &stream, None, 10).unwrap().records;
        assert_eq!(source_before, source_after);
        assert_eq!(source_before[0].event_hash, first.event_hash);
        assert!(!export.manifest_json.contains(&stream));
        assert!(!export.records_jsonl.contains(secret));
        assert!(!export.records_jsonl.contains(&task_id));
        for record in &source_before {
            assert!(!export.manifest_json.contains(&record.event_hash));
            assert!(!export.records_jsonl.contains(&record.event_hash));
        }

        let result =
            verify_jsonl_export(&export.manifest_json, &export.records_jsonl, NOW).unwrap();
        assert!(result.valid, "{result:?}");
        assert_eq!(result.scope, "exported-projection");
        assert!(!result.original_chain_verified_offline);
        assert!(!result.original_chain_linkage_proven);

        let projected = export
            .records_jsonl
            .lines()
            .map(|line| serde_json::from_str::<ProjectedRecord>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(projected.len(), source_before.len());
        assert_eq!(
            projected
                .iter()
                .map(|record| record.sequence)
                .collect::<Vec<_>>(),
            source_before
                .iter()
                .map(|record| record.sequence)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            projected[0].projected_event.pointer("/actor/id"),
            projected[0]
                .projected_event
                .pointer("/details/creation/principal/id")
        );
        assert_ne!(
            projected[0]
                .projected_event
                .pointer("/details/active_step_ids/1"),
            projected[0]
                .projected_event
                .pointer("/details/active_step_ids/2")
        );
        assert_ne!(
            projected[1].projected_event.pointer("/step_id"),
            projected[1]
                .projected_event
                .pointer("/details/related_ids/0")
        );
        assert!(
            projected[1]
                .projected_event
                .pointer("/committed_mutation/active_plan/plan_id/alias")
                .is_some()
        );
        assert_eq!(
            projected[1]
                .projected_event
                .pointer("/approval_id/namespace")
                .and_then(Value::as_str),
            Some("approval")
        );

        let tampered = export
            .records_jsonl
            .replacen("\"success\"", "\"failure\"", 1);
        assert!(
            !verify_jsonl_export(&export.manifest_json, &tampered, NOW)
                .unwrap()
                .valid
        );
        let lines = export.records_jsonl.lines().collect::<Vec<_>>();
        assert!(
            !verify_jsonl_export(&export.manifest_json, &format!("{}\n", lines[0]), NOW)
                .unwrap()
                .valid
        );
        let reordered = format!("{}\n{}\n", lines[1], lines[0]);
        assert!(
            !verify_jsonl_export(&export.manifest_json, &reordered, NOW)
                .unwrap()
                .valid
        );
        let other = export_jsonl(&connection, &stream, NOW).unwrap();
        let splice = format!(
            "{}\n{}\n",
            lines[0],
            other.records_jsonl.lines().nth(1).unwrap()
        );
        assert!(
            !verify_jsonl_export(&export.manifest_json, &splice, NOW)
                .unwrap()
                .valid
        );
        let mut injected: Value = serde_json::from_str(&export.manifest_json).unwrap();
        injected["projection_hash_profile"] = json!("attacker-profile");
        assert!(verify_jsonl_export(&injected.to_string(), &export.records_jsonl, NOW).is_err());

        let mut legacy = Connection::open_in_memory().unwrap();
        initialize(&legacy);
        let transaction = legacy.transaction().unwrap();
        append_in_tx(
            &transaction,
            "legacy/private task",
            &typed_creation_event("legacy/private task", 99),
            &ExpectedHead::Empty,
        )
        .unwrap();
        transaction.commit().unwrap();
        let legacy_stream = stream_id("legacy/private task").unwrap();
        let legacy_export = export_jsonl(&legacy, &legacy_stream, NOW).unwrap();
        assert_eq!(legacy_export.records_jsonl.lines().count(), 1);
        assert!(!legacy_export.manifest_json.contains(&legacy_stream));
        assert!(!legacy_export.records_jsonl.contains("legacy/private task"));
        assert!(!legacy_export.records_jsonl.contains("\"event_hash\""));
        assert!(!legacy_export.records_jsonl.contains("\"stream_id\""));
        let mut unsupported_record: ProjectedRecord =
            serde_json::from_str(legacy_export.records_jsonl.trim()).unwrap();
        unsupported_record.projected_event["debug"] = json!(false);
        unsupported_record.projection_hash = hash_projected_record(
            &unsupported_record.bundle_id,
            1,
            None,
            &unsupported_record.projected_event,
        )
        .unwrap();
        let mut unsupported_manifest: ProjectionManifest =
            serde_json::from_str(&legacy_export.manifest_json).unwrap();
        unsupported_manifest.head_projection_hash = unsupported_record.projection_hash.clone();
        unsupported_manifest.descriptor_hash =
            hash_projection_descriptor(&unsupported_manifest).unwrap();
        let unsupported = verify_jsonl_export(
            &serde_json::to_string(&unsupported_manifest).unwrap(),
            &format!("{}\n", serde_json::to_string(&unsupported_record).unwrap()),
            NOW,
        )
        .unwrap();
        assert!(!unsupported.valid);
        assert_eq!(unsupported.diagnostics[0].code, "PROJECTION_RECORD_INVALID");
    }

    #[test]
    fn recomputed_projection_rejects_null_required_fields_and_wrong_typed_paths() {
        let mut connection = connection();
        let transaction = connection.transaction().unwrap();
        append_in_tx(
            &transaction,
            "T-projection-shape",
            &typed_creation_event("T-projection-shape", 1),
            &ExpectedHead::Empty,
        )
        .unwrap();
        transaction.commit().unwrap();
        let export =
            export_jsonl(&connection, &stream_id("T-projection-shape").unwrap(), NOW).unwrap();

        for key in [
            "schema_version",
            "event_id",
            "task_id",
            "event_type",
            "timestamp",
            "actor",
        ] {
            let forged = rehash_projection(&export, |records| {
                records[0].projected_event[key] = Value::Null;
            });
            assert!(projection_rejected(&forged), "accepted null `{key}`");
        }

        let commitment = commitment("original_intent");
        let forged = rehash_projection(&export, |records| {
            records[0].projected_event["task_id"] = commitment.clone();
        });
        assert!(projection_rejected(&forged));
        let forged = rehash_projection(&export, |records| {
            records[0].projected_event["details"]["revision"] = commitment.clone();
        });
        assert!(projection_rejected(&forged));
        let forged = rehash_projection(&export, |records| {
            records[0].projected_event["task_id"] =
                records[0].projected_event["actor"]["id"].clone();
        });
        assert!(projection_rejected(&forged));

        for invalid_commitment in [
            json!({
                "kind":"task-field-commitment", "version":"v1",
                "algorithm":"sha256-keyed-prefix", "field":"reason_message",
                "commitment":format!("sha256:{}", "a".repeat(64))
            }),
            json!({
                "kind":"task-field-commitment", "version":"v1",
                "field":"original_intent", "commitment":format!("sha256:{}", "a".repeat(64))
            }),
            json!({
                "kind":"task-field-commitment", "version":"v2",
                "algorithm":"sha256-keyed-prefix", "field":"original_intent",
                "commitment":format!("sha256:{}", "a".repeat(64))
            }),
            json!({
                "kind":"task-field-commitment", "version":"v1",
                "algorithm":"sha256", "field":"original_intent",
                "commitment":format!("sha256:{}", "a".repeat(64))
            }),
            json!({
                "kind":"task-field-commitment", "version":"v1",
                "algorithm":"sha256-keyed-prefix", "field":"original_intent",
                "commitment":"sha256:ABCDEF"
            }),
        ] {
            let forged = rehash_projection(&export, |records| {
                records[0].projected_event["details"]["creation"]["original_intent_ref"] =
                    invalid_commitment;
            });
            assert!(projection_rejected(&forged));
        }
    }

    #[test]
    fn projection_bounds_cover_maximum_step_set_and_reject_plus_one() {
        let steps = (0..512)
            .map(|index| format!("s{index}"))
            .collect::<Vec<_>>();
        let mut connection = connection();
        let transaction = connection.transaction().unwrap();
        let mut maximum = typed_creation_event("T-max-projection", 1);
        maximum["details"]["active_step_ids"] = json!(steps);
        append_in_tx(
            &transaction,
            "T-max-projection",
            &maximum,
            &ExpectedHead::Empty,
        )
        .unwrap();
        transaction.commit().unwrap();
        let export =
            export_jsonl(&connection, &stream_id("T-max-projection").unwrap(), NOW).unwrap();
        assert!(export.records_jsonl.len() > MAX_EVENT_BYTES);
        assert!(export.records_jsonl.len() <= MAX_PROJECTED_RECORD_BYTES);
        assert!(
            verify_jsonl_export(&export.manifest_json, &export.records_jsonl, NOW)
                .unwrap()
                .valid
        );

        let mut too_many = typed_creation_event("T-too-many-steps", 2);
        too_many["details"]["active_step_ids"] = json!(
            (0..513)
                .map(|index| format!("step-{index}"))
                .collect::<Vec<_>>()
        );
        let transaction = connection.transaction().unwrap();
        assert!(
            append_in_tx(
                &transaction,
                "T-too-many-steps",
                &too_many,
                &ExpectedHead::Empty
            )
            .is_err()
        );
    }

    #[test]
    fn projected_verifier_enforces_direct_resource_bounds_and_result_schema() {
        let mut connection = connection();
        let transaction = connection.transaction().unwrap();
        append_in_tx(
            &transaction,
            "T-projection-bounds",
            &typed_creation_event("T-projection-bounds", 1),
            &ExpectedHead::Empty,
        )
        .unwrap();
        transaction.commit().unwrap();
        let export =
            export_jsonl(&connection, &stream_id("T-projection-bounds").unwrap(), NOW).unwrap();
        let valid = verify_jsonl_export(&export.manifest_json, &export.records_jsonl, NOW).unwrap();
        assert!(
            projection_verification_result_validator()
                .unwrap()
                .is_valid(&serde_json::to_value(&valid).unwrap())
        );

        assert!(verify_jsonl_export(&"x".repeat(MAX_EVENT_BYTES + 1), "", NOW).is_err());
        assert!(
            verify_jsonl_export(
                &export.manifest_json,
                &"x".repeat(MAX_PROJECTION_EXPORT_BYTES + 1),
                NOW
            )
            .is_err()
        );
        assert!(
            verify_jsonl_export(
                &export.manifest_json,
                &"x".repeat(MAX_PROJECTED_RECORD_BYTES + 1),
                NOW
            )
            .is_err()
        );

        let too_many_items = rehash_projection(&export, |records| {
            let template = records[0].projected_event["details"]["active_step_ids"][0].clone();
            let mut values = Vec::new();
            for index in 0..513_u64 {
                let mut alias = template.clone();
                alias["alias"] = json!(format!("sha256:{index:064x}"));
                values.push(alias);
            }
            records[0].projected_event["details"]["active_step_ids"] = Value::Array(values);
        });
        assert!(projection_rejected(&too_many_items));

        let too_many_keys = rehash_projection(&export, |records| {
            let object = (0..257)
                .map(|index| (format!("field-{index}"), Value::Bool(false)))
                .collect();
            records[0].projected_event["overflow"] = Value::Object(object);
        });
        assert!(projection_rejected(&too_many_keys));

        let too_deep = rehash_projection(&export, |records| {
            let mut value = Value::Bool(false);
            for index in 0..33 {
                value = json!({format!("depth-{index}"):value});
            }
            records[0].projected_event["overflow"] = value;
        });
        assert!(projection_rejected(&too_deep));

        let hash_tampered = export
            .records_jsonl
            .replacen("\"success\"", "\"failure\"", 1);
        let invalid = verify_jsonl_export(&export.manifest_json, &hash_tampered, NOW).unwrap();
        assert!(!invalid.valid);
        assert!(
            projection_verification_result_validator()
                .unwrap()
                .is_valid(&serde_json::to_value(&invalid).unwrap())
        );
        let mut invalid_shape = serde_json::to_value(valid).unwrap();
        invalid_shape["scope"] = json!("original-chain");
        assert!(
            !projection_verification_result_validator()
                .unwrap()
                .is_valid(&invalid_shape)
        );
    }

    #[test]
    fn plan_projection_preserves_exact_unicode_scalar_boundaries() {
        for event_type in ["plan.created", "plan.revised"] {
            let task_id = format!("T-{event_type}");
            let mut connection = connection();
            let transaction = connection.transaction().unwrap();
            append_in_tx(
                &transaction,
                &task_id,
                &typed_creation_event(&task_id, 1),
                &ExpectedHead::Empty,
            )
            .unwrap();
            let boundary = "🧭".repeat(256);
            let valid = json!({
                "schema_version":SCHEMA_VERSION,
                "event_id":format!("event-{event_type}"),
                "task_id":task_id,
                "event_type":event_type,
                "timestamp":NOW,
                "actor":{"kind":"system-service","id":"service:test"},
                "status":"success",
                "details":{"plan_id":boundary,"revision":1}
            });
            append_in_tx(&transaction, &task_id, &valid, &ExpectedHead::Any).unwrap();
            let mut too_long = valid.clone();
            too_long["event_id"] = json!(format!("event-too-long-{event_type}"));
            too_long["details"]["plan_id"] = json!("🧭".repeat(257));
            assert!(append_in_tx(&transaction, &task_id, &too_long, &ExpectedHead::Any).is_err());
            transaction.commit().unwrap();
            let export = export_jsonl(&connection, &stream_id(&task_id).unwrap(), NOW).unwrap();
            assert!(
                verify_jsonl_export(&export.manifest_json, &export.records_jsonl, NOW)
                    .unwrap()
                    .valid
            );
        }
    }

    #[test]
    fn active_program_ir_version_projects_with_its_source_bound() {
        let task_id = "T-active-program-projection";
        let mut connection = connection();
        let transaction = connection.transaction().unwrap();
        append_in_tx(
            &transaction,
            task_id,
            &typed_creation_event(task_id, 1),
            &ExpectedHead::Empty,
        )
        .unwrap();
        let mut transition = typed_transition_event(task_id);
        transition["details"]["active_program"] = json!({
            "program_id":"program:test",
            "ir_version":"0.1",
            "semantic_hash":format!("sha256:{}", "a".repeat(64)),
            "registry_snapshot_id":"snapshot:test",
            "validation_result_id":"validation:test",
            "validated_at":NOW,
            "validator_id":"validator:test",
            "validator_version":"1.0",
            "program_content_digest":format!("sha256:{}", "b".repeat(64))
        });
        append_in_tx(&transaction, task_id, &transition, &ExpectedHead::Any).unwrap();
        transaction.commit().unwrap();

        let export = export_jsonl(&connection, &stream_id(task_id).unwrap(), NOW).unwrap();
        let result =
            verify_jsonl_export(&export.manifest_json, &export.records_jsonl, NOW).unwrap();
        assert!(result.valid, "{result:?}");
        let projected: ProjectedRecord =
            serde_json::from_str(export.records_jsonl.lines().nth(1).unwrap()).unwrap();
        assert_eq!(
            projected.projected_event["details"]["active_program"]["ir_version"]["kind"],
            "bundle-local-alias"
        );
    }

    #[test]
    fn rehashed_projection_rejects_mixed_tasks_duplicate_events_and_wrong_genesis() {
        let mut connection = connection();
        append_many(&mut connection, 2);
        let export = export_jsonl(&connection, &stream_id("T-provenance").unwrap(), NOW).unwrap();
        let mixed_tasks = rehash_projection(&export, |records| {
            records[1].projected_event["task_id"]["alias"] =
                json!(format!("sha256:{}", "f".repeat(64)));
        });
        assert!(projection_rejected(&mixed_tasks));

        let duplicate_events = rehash_projection(&export, |records| {
            records[1].projected_event["event_id"] = records[0].projected_event["event_id"].clone();
        });
        assert!(projection_rejected(&duplicate_events));

        let wrong_genesis = rehash_projection(&export, |records| {
            records.remove(0);
        });
        assert!(projection_rejected(&wrong_genesis));
    }

    #[test]
    fn export_runs_private_validation_and_rejects_overbound_record_count() {
        let mut connection = connection();
        append_many(&mut connection, 1);
        let stream = stream_id("T-provenance").unwrap();
        let mut callback_ran = false;
        let refused = export_jsonl_with_validation(&connection, &stream, NOW, |snapshot| {
            callback_ran = true;
            let count: i64 = snapshot.query_row(
                "SELECT COUNT(*) FROM provenance_events WHERE stream_id=?1",
                [&stream],
                |row| row.get(0),
            )?;
            assert_eq!(count, 1);
            Err(Error::InvalidRecord(
                "private Task validation failed".to_owned(),
            ))
        });
        assert!(callback_ran);
        assert!(refused.is_err());

        connection.execute(
            "WITH RECURSIVE numbered(value) AS (SELECT 1 UNION ALL SELECT value+1 FROM numbered WHERE value<10000) INSERT INTO provenance_events (schema_version,hash_profile,event_id,task_id,stream_id,sequence,timestamp,event_type,event_hash,event_json) SELECT '0.1','aios-provenance-event-v0.1','extra-' || value,'T-provenance',?1,value+1,?2,'verification.started',?3,'{}' FROM numbered",
            params![stream, NOW, format!("sha256:{}", "a".repeat(64))],
        ).unwrap();
        let error = export_jsonl(&connection, &stream, NOW).unwrap_err();
        assert!(error.to_string().contains("record-count bound"));
    }

    #[test]
    fn export_rejects_overbound_source_before_private_validation() {
        let task_id = "T-large-source";
        let stream = stream_id(task_id).unwrap();
        let mut connection = connection();
        let transaction = connection.transaction().unwrap();
        let genesis = append_in_tx(
            &transaction,
            task_id,
            &typed_creation_event(task_id, 1),
            &ExpectedHead::Empty,
        )
        .unwrap();
        let mut event = event(task_id, 2);
        let artifacts = (0..500)
            .map(|index| format!("artifact:{index:03}:{}", "x".repeat(100)))
            .collect::<Vec<_>>();
        event["input_artifacts"] = json!(artifacts);
        assert!(validate_event(task_id, &event).is_ok());
        let event_bytes = serde_json::to_vec(&event).unwrap().len() as u64;
        assert!(event_bytes < MAX_EVENT_BYTES as u64);
        let event_count = MAX_PROJECTION_SOURCE_BYTES / event_bytes + 2;
        assert!(event_count < MAX_PROJECTION_RECORDS);
        let mut previous = genesis.event_hash;
        for sequence in 2..=event_count {
            let event_id = format!("event-large-{sequence}");
            event["event_id"] = json!(event_id);
            event["details"]["index"] = json!(sequence);
            let hash = hash_record(&stream, sequence, Some(&previous), &event).unwrap();
            transaction.execute(
                "INSERT INTO provenance_events (schema_version,hash_profile,event_id,task_id,stream_id,sequence,timestamp,event_type,status,previous_event_hash,event_hash,event_json) VALUES (?1,?2,?3,?4,?5,?6,?7,'verification.started','success',?8,?9,?10)",
                params![SCHEMA_VERSION,HASH_PROFILE,event_id,task_id,stream,i64::try_from(sequence).unwrap(),NOW,previous,hash,serde_json::to_string(&event).unwrap()],
            ).unwrap();
            previous = hash;
        }
        transaction.commit().unwrap();
        assert!(
            verify_stream(&connection, &stream, None, None, NOW)
                .unwrap()
                .valid
        );
        let mut callback_ran = false;
        let error = export_jsonl_with_validation(&connection, &stream, NOW, |_| {
            callback_ran = true;
            Ok(())
        })
        .unwrap_err();
        assert!(!callback_ran);
        assert!(error.to_string().contains("source-byte bound"));
    }

    #[test]
    fn projection_export_uses_one_snapshot_during_concurrent_append() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("projection-snapshot.sqlite3");
        let mut setup = Connection::open(&path).unwrap();
        initialize(&setup);
        setup.pragma_update(None, "journal_mode", "WAL").unwrap();
        let transaction = setup.transaction().unwrap();
        append_in_tx(
            &transaction,
            "T-snapshot",
            &event("T-snapshot", 1),
            &ExpectedHead::Empty,
        )
        .unwrap();
        transaction.commit().unwrap();
        drop(setup);

        let barrier = Arc::new(Barrier::new(3));
        let export_path = path.clone();
        let export_barrier = Arc::clone(&barrier);
        let exporter = thread::spawn(move || {
            let connection = Connection::open(export_path).unwrap();
            export_barrier.wait();
            export_jsonl(&connection, &stream_id("T-snapshot").unwrap(), NOW).unwrap()
        });
        let append_path = path.clone();
        let append_barrier = Arc::clone(&barrier);
        let appender = thread::spawn(move || {
            let mut connection = Connection::open(append_path).unwrap();
            append_barrier.wait();
            let transaction = connection.transaction().unwrap();
            append_in_tx(
                &transaction,
                "T-snapshot",
                &event("T-snapshot", 2),
                &ExpectedHead::Any,
            )
            .unwrap();
            transaction.commit().unwrap();
        });
        barrier.wait();
        let export = exporter.join().unwrap();
        appender.join().unwrap();
        let verification =
            verify_jsonl_export(&export.manifest_json, &export.records_jsonl, NOW).unwrap();
        assert!(verification.valid, "{verification:?}");
        assert!(matches!(export.records_jsonl.lines().count(), 1 | 2));
    }

    #[test]
    fn transaction_ownership_remains_with_caller() {
        let mut connection = connection();
        {
            let transaction = connection.transaction().unwrap();
            append_in_tx(
                &transaction,
                "T-provenance",
                &event("T-provenance", 1),
                &ExpectedHead::Any,
            )
            .unwrap();
        }
        assert!(
            get_head(&connection, &stream_id("T-provenance").unwrap())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn concurrent_exact_head_append_has_one_winner_and_valid_chain() {
        use std::sync::{Arc, Barrier};
        use std::thread;
        use std::time::Duration;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("provenance.sqlite3");
        let mut setup = Connection::open(&path).unwrap();
        initialize(&setup);
        let transaction = setup.transaction().unwrap();
        append_in_tx(
            &transaction,
            "T-concurrent",
            &event("T-concurrent", 1),
            &ExpectedHead::Empty,
        )
        .unwrap();
        transaction.commit().unwrap();
        let stream = stream_id("T-concurrent").unwrap();
        let observed = get_head(&setup, &stream).unwrap().unwrap();
        drop(setup);

        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for worker in 0..2_u64 {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            let expected = ExpectedHead::Exact {
                sequence: observed.sequence,
                event_hash: observed.event_hash.clone(),
            };
            workers.push(thread::spawn(move || {
                let mut connection = Connection::open(path).unwrap();
                connection.busy_timeout(Duration::from_secs(5)).unwrap();
                barrier.wait();
                let transaction = connection
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                    .unwrap();
                let mut candidate = event("T-concurrent", worker + 2);
                candidate["event_id"] = json!(format!("event-concurrent-{worker}"));
                match append_in_tx(&transaction, "T-concurrent", &candidate, &expected) {
                    Ok(_) => {
                        transaction.commit().unwrap();
                        true
                    }
                    Err(error) => {
                        assert!(error.to_string().contains("stale provenance stream head"));
                        false
                    }
                }
            }));
        }
        barrier.wait();
        let outcomes = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(outcomes.iter().filter(|won| **won).count(), 1);

        let connection = Connection::open(path).unwrap();
        let verification = verify_stream(&connection, &stream, None, None, NOW).unwrap();
        assert!(verification.valid, "{verification:?}");
        assert_eq!(verification.to_sequence, 2);
    }
}
