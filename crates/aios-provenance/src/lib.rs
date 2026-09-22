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
const MAX_STRING_CHARS: usize = 4096;
const MAX_ARRAY_ITEMS: usize = 512;
const MAX_OBJECT_FIELDS: usize = 256;
const HASH_DOMAIN: &[u8] = b"AIOS-PROVENANCE-EVENT\0v0.1\0";
const EVENT_SCHEMA: &str = include_str!("../../../specs/provenance-event.schema.json");

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportManifest {
    pub schema_version: String,
    pub export_profile: String,
    pub hash_profile: String,
    pub stream_id: String,
    pub record_count: u64,
    pub head_sequence: u64,
    pub head_event_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortableExport {
    pub manifest_json: String,
    pub records_jsonl: String,
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
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .map(|(sequence, event_hash)| {
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
        "SELECT schema_version, hash_profile, stream_id, sequence, previous_event_hash, event_json, event_hash FROM provenance_events WHERE stream_id=?1 AND (?2 IS NULL OR sequence<=?2) ORDER BY sequence",
    )?;
    let rows = statement.query_map(params![stream_id, upper], row_to_record)?;
    let mut records = Vec::new();
    for row in rows {
        match row {
            Ok(record) => records.push(record),
            Err(_) => {
                return Ok(failure(
                    stream_id,
                    verified_at,
                    "PROVENANCE_SCHEMA_INVALID",
                    "stored journal record is malformed",
                    None,
                    None,
                    None,
                    checkpoint,
                ));
            }
        }
    }
    let mut result = verify_records(&records, stream_id, checkpoint, verified_at);
    if result.valid {
        let mut statement = connection.prepare(
            "SELECT sequence,event_id,task_id,stream_id,timestamp,event_type,semantic_program_hash,ir_version,registry_snapshot_id,node_id,execution_binding_id,provider_id,status,event_json FROM provenance_events WHERE stream_id=?1 AND (?2 IS NULL OR sequence<=?2) ORDER BY sequence",
        )?;
        let rows = statement.query_map(params![stream_id, upper], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, Option<String>>(10)?,
                row.get::<_, Option<String>>(11)?,
                row.get::<_, Option<String>>(12)?,
                row.get::<_, String>(13)?,
            ))
        })?;
        for row in rows {
            let (
                sequence,
                event_id,
                task_id,
                stored_stream,
                timestamp,
                event_type,
                semantic_program_hash,
                ir_version,
                registry_snapshot_id,
                node_id,
                execution_binding_id,
                provider_id,
                status,
                event_json,
            ) = row?;
            let sequence = u64::try_from(sequence).unwrap_or(0);
            let Ok(event) = serde_json::from_str::<Value>(&event_json) else {
                return Ok(failure(
                    stream_id,
                    verified_at,
                    "PROVENANCE_SCHEMA_INVALID",
                    "stored event JSON is malformed",
                    Some(sequence),
                    Some(event_id),
                    result.computed_head_hash,
                    checkpoint,
                ));
            };
            let coherent = event_id == string_field(&event, "event_id").unwrap_or_default()
                && task_id == string_field(&event, "task_id").unwrap_or_default()
                && stored_stream == stream_id
                && timestamp == string_field(&event, "timestamp").unwrap_or_default()
                && event_type == string_field(&event, "event_type").unwrap_or_default()
                && semantic_program_hash.as_deref()
                    == string_field(&event, "semantic_program_hash")
                && ir_version.as_deref() == string_field(&event, "ir_version")
                && registry_snapshot_id.as_deref() == string_field(&event, "registry_snapshot_id")
                && node_id.as_deref() == string_field(&event, "step_id")
                && execution_binding_id.as_deref() == string_field(&event, "execution_binding_id")
                && provider_id.as_deref() == string_field(&event, "provider_id")
                && status.as_deref() == string_field(&event, "status")
                && (sequence != 1 || event_type == "task.created");
            if !coherent {
                return Ok(failure(
                    stream_id,
                    verified_at,
                    "PROVENANCE_SCHEMA_INVALID",
                    "journal index columns conflict with the hashed event",
                    Some(sequence),
                    Some(event_id),
                    result.computed_head_hash,
                    checkpoint,
                ));
            }
        }
    }
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
        let event_id = string_field(&record.event, "event_id").map(str::to_owned);
        if record.sequence < expected_sequence {
            return failure(
                stream_id,
                verified_at,
                "PROVENANCE_SEQUENCE_ORDER_INVALID",
                "records are not in strictly increasing sequence",
                Some(record.sequence),
                event_id,
                previous,
                checkpoint,
            );
        }
        if record.sequence > expected_sequence {
            let (code, message) = if records[index..]
                .iter()
                .any(|candidate| candidate.sequence == expected_sequence)
            {
                (
                    "PROVENANCE_SEQUENCE_ORDER_INVALID",
                    "records are not in strictly increasing sequence",
                )
            } else {
                (
                    "PROVENANCE_SEQUENCE_GAP",
                    "provenance stream contains a sequence gap",
                )
            };
            return failure(
                stream_id,
                verified_at,
                code,
                message,
                Some(record.sequence),
                event_id,
                previous,
                checkpoint,
            );
        }
        if record.schema_version != SCHEMA_VERSION {
            return failure(
                stream_id,
                verified_at,
                "PROVENANCE_SCHEMA_INVALID",
                "journal record schema version is unsupported",
                Some(record.sequence),
                event_id,
                previous,
                checkpoint,
            );
        }
        if record.hash_profile != HASH_PROFILE {
            return failure(
                stream_id,
                verified_at,
                "PROVENANCE_HASH_PROFILE_UNSUPPORTED",
                "journal record hash profile is unsupported",
                Some(record.sequence),
                event_id,
                previous,
                checkpoint,
            );
        }
        if record.stream_id != stream_id
            || string_field(&record.event, "task_id").and_then(|id| self::stream_id(id).ok())
                != Some(stream_id.to_owned())
        {
            return failure(
                stream_id,
                verified_at,
                "PROVENANCE_STREAM_ID_MISMATCH",
                "journal record identity does not match the verified stream",
                Some(record.sequence),
                event_id,
                previous,
                checkpoint,
            );
        }
        if record.previous_event_hash != previous {
            return failure(
                stream_id,
                verified_at,
                "PROVENANCE_PREVIOUS_HASH_MISMATCH",
                "previous_event_hash does not match the prior computed head",
                Some(record.sequence),
                event_id,
                previous,
                checkpoint,
            );
        }
        let task_id = string_field(&record.event, "task_id").unwrap_or_default();
        if validate_event(task_id, &record.event).is_err()
            || !valid_hash(&record.event_hash)
            || record
                .previous_event_hash
                .as_deref()
                .is_some_and(|hash| !valid_hash(hash))
        {
            return failure(
                stream_id,
                verified_at,
                "PROVENANCE_SCHEMA_INVALID",
                "journal record or event is structurally invalid",
                Some(record.sequence),
                event_id,
                previous,
                checkpoint,
            );
        }
        let Ok(computed) = hash_record(
            stream_id,
            record.sequence,
            record.previous_event_hash.as_deref(),
            &record.event,
        ) else {
            return failure(
                stream_id,
                verified_at,
                "PROVENANCE_SCHEMA_INVALID",
                "journal record cannot be canonicalized",
                Some(record.sequence),
                event_id,
                previous,
                checkpoint,
            );
        };
        if computed != record.event_hash {
            return failure(
                stream_id,
                verified_at,
                "PROVENANCE_EVENT_HASH_MISMATCH",
                "recomputed journal-record hash does not match event_hash",
                Some(record.sequence),
                event_id,
                Some(computed),
                checkpoint,
            );
        }
        previous = Some(computed);
        expected_sequence = expected_sequence.saturating_add(1);
    }
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

/// Produces a privacy-screened JSONL copy and verification manifest.
///
/// # Errors
/// Returns an error when the stream is invalid, unsafe to export, or cannot be read.
pub fn export_jsonl(
    connection: &Connection,
    stream_id: &str,
    verified_at: &str,
) -> Result<PortableExport> {
    let verification = verify_stream(connection, stream_id, None, None, verified_at)?;
    if !verification.valid {
        return Err(Error::InvalidRecord(
            "cannot export an invalid provenance stream".to_owned(),
        ));
    }
    let mut records = Vec::new();
    let mut cursor = None;
    loop {
        let page = list_events(connection, stream_id, cursor, MAX_PAGE_SIZE)?;
        for record in page.records {
            ensure_export_safe(&record.event)?;
            records.push(record);
        }
        let Some(next) = page.next_cursor else { break };
        cursor = Some(next);
    }
    let head = records.last().ok_or_else(|| {
        Error::InvalidRecord("cannot export an empty provenance stream".to_owned())
    })?;
    let manifest = ExportManifest {
        schema_version: SCHEMA_VERSION.to_owned(),
        export_profile: "privacy-safe-original-chain".to_owned(),
        hash_profile: HASH_PROFILE.to_owned(),
        stream_id: stream_id.to_owned(),
        record_count: records.len() as u64,
        head_sequence: head.sequence,
        head_event_hash: head.event_hash.clone(),
    };
    let mut records_jsonl = String::new();
    for record in records {
        records_jsonl.push_str(&serde_json::to_string(&record)?);
        records_jsonl.push('\n');
    }
    Ok(PortableExport {
        manifest_json: serde_json::to_string_pretty(&manifest)?,
        records_jsonl,
    })
}

/// Re-verifies a portable export without a database or network access.
///
/// # Errors
/// Returns an error for malformed, unsupported, unsafe, or over-bound export input.
pub fn verify_jsonl_export(
    manifest_json: &str,
    records_jsonl: &str,
    verified_at: &str,
) -> Result<VerificationResult> {
    if manifest_json.len() > MAX_EVENT_BYTES
        || records_jsonl.len() > MAX_EVENT_BYTES.saturating_mul(10_000)
    {
        return Err(Error::InvalidRecord(
            "portable provenance export exceeds bounds".to_owned(),
        ));
    }
    validate_timestamp(verified_at)?;
    let manifest: ExportManifest = serde_json::from_str(manifest_json)?;
    if manifest.schema_version != SCHEMA_VERSION
        || manifest.hash_profile != HASH_PROFILE
        || manifest.export_profile != "privacy-safe-original-chain"
    {
        return Err(Error::InvalidRecord(
            "unsupported portable provenance export manifest".to_owned(),
        ));
    }
    validate_stream_id(&manifest.stream_id)?;
    let mut records = Vec::new();
    for line in records_jsonl.lines() {
        if line.is_empty() || line.len() > MAX_EVENT_BYTES.saturating_mul(2) {
            return Err(Error::InvalidRecord(
                "malformed portable provenance JSONL".to_owned(),
            ));
        }
        let record: JournalRecord = serde_json::from_str(line)?;
        ensure_export_safe(&record.event)?;
        records.push(record);
    }
    if records.len() as u64 != manifest.record_count
        || records
            .last()
            .map(|value| (value.sequence, value.event_hash.as_str()))
            != Some((manifest.head_sequence, manifest.head_event_hash.as_str()))
    {
        return Ok(failure(
            &manifest.stream_id,
            verified_at,
            "PROVENANCE_CHECKPOINT_HEAD_MISMATCH",
            "portable export manifest does not match its JSONL records",
            records.last().map(|value| value.sequence),
            None,
            records.last().map(|value| value.event_hash.clone()),
            Some(&CheckpointExpectation {
                checkpoint_id: "export-manifest".to_owned(),
                event_hash: manifest.head_event_hash,
            }),
        ));
    }
    Ok(verify_records(
        &records,
        &manifest.stream_id,
        Some(&CheckpointExpectation {
            checkpoint_id: "export-manifest".to_owned(),
            event_hash: manifest.head_event_hash,
        }),
        verified_at,
    ))
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

fn validate_event(task_id: &str, event: &Value) -> Result<()> {
    validate_task_id(task_id)?;
    let bytes = serde_json::to_vec(event)?;
    if bytes.len() > MAX_EVENT_BYTES
        || json_depth(event) > MAX_JSON_DEPTH
        || !within_shape_bounds(event)
    {
        return Err(Error::InvalidRecord(
            "provenance event exceeds size or depth bounds".to_owned(),
        ));
    }
    if event.get("details").is_some_and(|value| {
        serde_json::to_vec(value).map_or(true, |bytes| bytes.len() > MAX_DETAILS_BYTES)
    }) {
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
    ensure_export_safe(event)
}

fn validate_task_id(task_id: &str) -> Result<()> {
    let mut chars = task_id.chars();
    let Some(first) = chars.next() else {
        return Err(Error::InvalidRecord("Task ID is empty".to_owned()));
    };
    if !first.is_ascii_alphanumeric()
        || task_id.len() > 256
        || !chars.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | ':' | '-')
        })
    {
        return Err(Error::InvalidRecord(
            "Task ID cannot form a valid provenance stream ID".to_owned(),
        ));
    }
    Ok(())
}

fn validate_stream_id(value: &str) -> Result<()> {
    let task_id = value
        .strip_prefix("task:")
        .ok_or_else(|| Error::InvalidRecord("invalid provenance stream ID".to_owned()))?;
    validate_task_id(task_id)
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

fn ensure_export_safe(value: &Value) -> Result<()> {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if matches!(
                    key.as_str(),
                    "original_intent"
                        | "normalized_intent"
                        | "intent_commitment_nonce"
                        | "raw_secret"
                        | "password"
                        | "authorization_header"
                ) {
                    return Err(Error::InvalidRecord(
                        "provenance contains a private-content field".to_owned(),
                    ));
                }
                ensure_export_safe(value)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                ensure_export_safe(value)?;
            }
        }
        _ => {}
    }
    Ok(())
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
    let event_json = row.get::<_, String>(5)?;
    let event = serde_json::from_str(&event_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            event_json.len(),
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })?;
    Ok(JournalRecord {
        schema_version: row.get(0)?,
        hash_profile: row.get(1)?,
        stream_id: row.get(2)?,
        sequence: u64::try_from(sequence).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                3,
                rusqlite::types::Type::Integer,
                Box::new(error),
            )
        })?,
        previous_event_hash: row.get(4)?,
        event,
        event_hash: row.get(6)?,
    })
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
        connection
    }

    fn event(task_id: &str, index: u64) -> Value {
        let event_type = if index == 1 {
            "task.created"
        } else {
            "verification.started"
        };
        json!({
            "schema_version":"0.1",
            "event_id":format!("event-{index}"),
            "task_id":task_id,
            "event_type":event_type,
            "timestamp":NOW,
            "actor":{"kind":"system-service","id":"service:test"},
            "status":"success",
            "details":{"index":index}
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
    fn append_rejects_payload_hash_fields_bounds_and_stale_heads() {
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
}
