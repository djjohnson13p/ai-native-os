use std::sync::Arc;

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::{Clock, Result, TaskManagerError};

pub(super) const MIGRATION: &str =
    include_str!("../../../specs/persistence-v0.1-0018-trusted-time.sql");
pub(super) const INFLIGHT_MIGRATION: &str =
    include_str!("../../../specs/persistence-v0.1-0019-inflight-time.sql");
const ROLLBACK_TOLERANCE_NANOS: i64 = 2_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeSource {
    SystemClock,
    InjectedClock,
}

impl TimeSource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SystemClock => "SYSTEM_CLOCK",
            Self::InjectedClock => "INJECTED_CLOCK",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityClockSample {
    pub wall: String,
    pub monotonic_nanos: u64,
    pub source: TimeSource,
}

#[cfg(test)]
pub(crate) fn synthetic_sample(wall: String) -> SecurityClockSample {
    use std::sync::atomic::{AtomicU64, Ordering};
    static TICKS: AtomicU64 = AtomicU64::new(0);
    SecurityClockSample {
        wall,
        monotonic_nanos: TICKS.fetch_add(1_000_000_000, Ordering::SeqCst),
        source: TimeSource::InjectedClock,
    }
}

pub(crate) struct TimeAssessment {
    confidence: String,
    effective_nanos: Option<i64>,
}

pub(crate) struct LockedTimeObservation {
    sample: Option<SecurityClockSample>,
    effective_nanos: Option<i64>,
}

#[allow(
    dead_code,
    reason = "external effect call sites follow the durable marker foundation"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExternalEffectKind {
    Read,
    StagingWrite,
    StagingSeal,
    Publication,
    ExportConstruction,
    ExportCopy,
    ExportFinalize,
}

impl ExternalEffectKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "ARTIFACT_READ",
            Self::StagingWrite => "ARTIFACT_STAGING_WRITE",
            Self::StagingSeal => "ARTIFACT_STAGING_SEAL",
            Self::Publication => "ARTIFACT_PUBLICATION",
            Self::ExportConstruction => "ARTIFACT_EXPORT_CONSTRUCTION",
            Self::ExportCopy => "ARTIFACT_EXPORT_COPY",
            Self::ExportFinalize => "ARTIFACT_EXPORT_FINALIZE",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExternalResolutionKind {
    EffectInvoked,
    NoEffect,
}

impl ExternalResolutionKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::EffectInvoked => "EFFECT_INVOKED",
            Self::NoEffect => "NO_EFFECT",
        }
    }
}

#[allow(
    dead_code,
    reason = "external effect call sites follow the durable marker foundation"
)]
pub(crate) struct ExternalTimePermit {
    marker_id: String,
    task_id: String,
    subject_kind: ExternalEffectKind,
    subject_id: String,
    owner_id: String,
    owner_epoch: i64,
    prepared_state_revision: i64,
}

impl ExternalTimePermit {
    pub(crate) fn marker_id(&self) -> &str {
        &self.marker_id
    }
}

#[allow(
    dead_code,
    reason = "external effect call sites follow the durable marker foundation"
)]
pub(crate) struct ExternalEntrySample<'transaction, 'connection> {
    transaction: &'transaction Transaction<'connection>,
    marker_id: String,
    observation: LockedTimeObservation,
}

#[allow(
    dead_code,
    reason = "external effect call sites follow the durable marker foundation"
)]
impl ExternalEntrySample<'_, '_> {
    pub(crate) fn require_trusted_time(&self) -> Result<String> {
        self.observation.require_trusted_time()
    }
}

impl LockedTimeObservation {
    pub(crate) fn require_trusted_time(&self) -> Result<String> {
        let nanos = self
            .effective_nanos
            .ok_or(TaskManagerError::InvalidRecord("TIME_UNCERTAIN"))?;
        format_nanos(nanos)
    }

    pub(crate) fn commit(self, connection: &Connection) -> Result<TimeAssessment> {
        assess_sample(connection, self.sample.as_ref())
    }

    /// Include the exact locked sample in the protected commit. A crash after
    /// that commit cannot leave its effect ahead of the durable expiry floor.
    pub(crate) fn commit_in(&self, connection: &Connection) -> Result<TimeAssessment> {
        apply_sample_in_transaction(connection, self.sample.as_ref())
    }
}

fn format_nanos(nanos: i64) -> Result<String> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(nanos))
        .map_err(|_| TaskManagerError::InvalidRecord("TIME_UNCERTAIN"))?
        .format(&Rfc3339)
        .map_err(|_| TaskManagerError::InvalidRecord("TIME_UNCERTAIN"))
}

fn state_matches_audit(connection: &Connection) -> Result<bool> {
    let state: Option<(String, Option<i64>, Option<i64>, i64)> = connection
        .query_row(
            "SELECT confidence,high_water_unix_nanos,expiry_floor_unix_nanos,revision
             FROM trusted_time_state WHERE singleton_id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let Some(state) = state else {
        return Ok(false);
    };
    let count: i64 =
        connection.query_row("SELECT COUNT(*) FROM trusted_time_state", [], |r| r.get(0))?;
    if count != 1 || state.3 < 0 {
        return Ok(false);
    }
    let audit: (i64, Option<i64>, Option<i64>, Option<i64>, Option<String>) = connection.query_row(
        "SELECT COUNT(*),MIN(state_revision),MAX(state_revision),
         (SELECT high_water_unix_nanos FROM trusted_time_observations ORDER BY state_revision DESC LIMIT 1),
         (SELECT confidence FROM trusted_time_observations ORDER BY state_revision DESC LIMIT 1)
         FROM trusted_time_observations",
        [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
    if state.3 == 0 {
        return Ok(state.0 == "UNASSESSED"
            && state.1.is_none()
            && state.2.is_none()
            && audit.0 == 0);
    }
    let latest: Option<(Option<i64>, String)> = connection
        .query_row(
            "SELECT expiry_floor_unix_nanos,confidence FROM trusted_time_observations
         WHERE state_revision=?1",
            [state.3],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    Ok(audit.0 == state.3
        && audit.1 == Some(1)
        && audit.2 == Some(state.3)
        && audit.3 == state.1
        && audit.4.as_deref() == Some(state.0.as_str())
        && latest == Some((state.2, state.0)))
}

// Protected operations check the indexed tail. The full ledger scan remains in
// startup preflight, while immutable SQL guards protect intervening rows.
fn state_matches_audit_tail(connection: &Connection) -> Result<bool> {
    let state: Option<(String, Option<i64>, Option<i64>, i64)> = connection
        .query_row(
            "SELECT confidence,high_water_unix_nanos,expiry_floor_unix_nanos,revision
             FROM trusted_time_state WHERE singleton_id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let Some(state) = state else { return Ok(false) };
    let latest: Option<(i64, Option<i64>, Option<i64>, String)> = connection
        .query_row(
            "SELECT state_revision,high_water_unix_nanos,expiry_floor_unix_nanos,confidence
             FROM trusted_time_observations ORDER BY state_revision DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    if state.3 == 0 {
        return Ok(state.0 == "UNASSESSED"
            && state.1.is_none()
            && state.2.is_none()
            && latest.is_none());
    }
    Ok(latest == Some((state.3, state.1, state.2, state.0)))
}

impl TimeAssessment {
    pub(crate) fn require_trusted_time(&self) -> Result<String> {
        if self.confidence != "TRUSTED_LOCAL" {
            return Err(TaskManagerError::InvalidRecord("TIME_UNCERTAIN"));
        }
        let nanos = self
            .effective_nanos
            .ok_or(TaskManagerError::InvalidRecord("TIME_UNCERTAIN"))?;
        format_nanos(nanos)
    }
}

/// Commits the adverse observation before its caller starts a protected transaction.
/// A later authorization denial cannot roll back the high-water or uncertainty state.
pub(crate) fn assess(connection: &Connection, clock: &Arc<dyn Clock>) -> Result<TimeAssessment> {
    if pending_marker_exists(connection)? {
        return Err(TaskManagerError::InvalidRecord("TIME_UNCERTAIN"));
    }
    #[cfg(test)]
    BEFORE_ASSESS_LOCK_TEST_HOOK.with(|hook| {
        let callback = hook.borrow_mut().take();
        if let Some(callback) = callback {
            callback();
        }
    });
    assess_sample_with_pending_policy(connection, || clock.security_sample(), PendingPolicy::Deny)
}

pub(crate) fn startup_assess(
    connection: &Connection,
    clock: &Arc<dyn Clock>,
) -> Result<TimeAssessment> {
    assess_sample_with_pending_policy(connection, || clock.security_sample(), PendingPolicy::Latch)
}

fn pending_marker_exists(connection: &Connection) -> Result<bool> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM trusted_time_effect_pending LIMIT 1)",
            [],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

pub(crate) fn capture_locked(
    connection: &Connection,
    clock: &Arc<dyn Clock>,
) -> Result<LockedTimeObservation> {
    capture_locked_with_permit(connection, clock, None)
}

fn capture_locked_with_permit(
    connection: &Connection,
    clock: &Arc<dyn Clock>,
    permitted_marker: Option<&str>,
) -> Result<LockedTimeObservation> {
    if !state_matches_audit_tail(connection)? {
        return Err(TaskManagerError::InvalidRecord("TIME_STATE_INVALID"));
    }
    let pending: Option<String> = connection
        .query_row(
            "SELECT marker_id FROM trusted_time_effect_pending LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    match (permitted_marker, pending.as_deref()) {
        (None, None) => {}
        (Some(expected), Some(actual)) if expected == actual => {
            let pending_count: i64 = connection.query_row(
                "SELECT COUNT(*) FROM trusted_time_effect_pending",
                [],
                |row| row.get(0),
            )?;
            if pending_count != 1 {
                return Err(TaskManagerError::InvalidRecord("TIME_UNCERTAIN"));
            }
        }
        _ => return Err(TaskManagerError::InvalidRecord("TIME_UNCERTAIN")),
    }
    let sample = clock.security_sample();
    let (confidence, floor): (String, Option<i64>) = connection.query_row(
        "SELECT confidence,expiry_floor_unix_nanos FROM trusted_time_state WHERE singleton_id=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let observed = sample.as_ref().and_then(|sample| {
        OffsetDateTime::parse(&sample.wall, &Rfc3339)
            .ok()
            .and_then(|time| i64::try_from(time.unix_timestamp_nanos()).ok())
    });
    let effective_nanos = if confidence == "TRUSTED_LOCAL" {
        match (floor, observed) {
            (Some(floor), Some(now)) if now >= floor.saturating_sub(ROLLBACK_TOLERANCE_NANOS) => {
                Some(floor.max(now))
            }
            _ => None,
        }
    } else {
        None
    };
    Ok(LockedTimeObservation {
        sample,
        effective_nanos,
    })
}

fn assess_sample(
    connection: &Connection,
    sample: Option<&SecurityClockSample>,
) -> Result<TimeAssessment> {
    assess_sample_with_pending_policy(connection, || sample.cloned(), PendingPolicy::RecordOnly)
}

#[derive(Clone, Copy)]
enum PendingPolicy {
    Deny,
    Latch,
    RecordOnly,
}

fn assess_sample_with_pending_policy<F>(
    connection: &Connection,
    sample: F,
    pending_policy: PendingPolicy,
) -> Result<TimeAssessment>
where
    F: FnOnce() -> Option<SecurityClockSample>,
{
    connection.execute_batch("BEGIN IMMEDIATE")?;
    let result = (|| -> Result<TimeAssessment> {
        let pending = pending_marker_exists(connection)?;
        if matches!(pending_policy, PendingPolicy::Deny) && pending {
            return Err(TaskManagerError::InvalidRecord("TIME_UNCERTAIN"));
        }
        let sample = sample();
        apply_sample_in_transaction_with_unresolved(
            connection,
            sample.as_ref(),
            matches!(pending_policy, PendingPolicy::Latch) && pending,
        )
    })();
    match result {
        Ok(assessment) => {
            connection.execute_batch("COMMIT")?;
            Ok(assessment)
        }
        Err(error) => {
            connection.execute_batch("ROLLBACK")?;
            Err(error)
        }
    }
}

fn apply_sample_in_transaction(
    connection: &Connection,
    sample: Option<&SecurityClockSample>,
) -> Result<TimeAssessment> {
    apply_sample_in_transaction_with_unresolved(connection, sample, false)
}

fn apply_sample_in_transaction_with_unresolved(
    connection: &Connection,
    sample: Option<&SecurityClockSample>,
    unresolved: bool,
) -> Result<TimeAssessment> {
    let parsed = sample.and_then(|sample| {
        OffsetDateTime::parse(&sample.wall, &Rfc3339)
            .ok()
            .and_then(|wall| i64::try_from(wall.unix_timestamp_nanos()).ok())
            .map(|nanos| (nanos, sample.monotonic_nanos, sample.source.as_str()))
    });
    (|| -> Result<TimeAssessment> {
        if !state_matches_audit_tail(connection)? {
            return Err(TaskManagerError::InvalidRecord("TIME_STATE_INVALID"));
        }
        let old: (String, Option<i64>, Option<i64>, i64) = connection
            .query_row(
                "SELECT confidence,high_water_unix_nanos,expiry_floor_unix_nanos,revision
                 FROM trusted_time_state WHERE singleton_id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?
            .ok_or(TaskManagerError::InvalidRecord("TIME_STATE_MISSING"))?;
        if !matches!(
            old.0.as_str(),
            "UNASSESSED" | "TRUSTED_LOCAL" | "TIME_UNCERTAIN"
        ) || old.3 < 0
            || old.2.zip(old.1).is_some_and(|(floor, high)| floor < high)
        {
            return Err(TaskManagerError::InvalidRecord("TIME_STATE_INVALID"));
        }
        let (observed, monotonic, source) = parsed
            .map_or((None, None, "UNAVAILABLE"), |(wall, ticks, source)| {
                (Some(wall), i64::try_from(ticks).ok(), source)
            });
        let rolled_back = observed
            .zip(old.1)
            .is_some_and(|(wall, high)| wall < high.saturating_sub(ROLLBACK_TOLERANCE_NANOS));
        let confidence =
            if old.0 == "TIME_UNCERTAIN" || unresolved || observed.is_none() || rolled_back {
                "TIME_UNCERTAIN"
            } else {
                "TRUSTED_LOCAL"
            };
        let reason = if old.0 == "TIME_UNCERTAIN" {
            "TIME_UNCERTAIN"
        } else if unresolved {
            "TIME_EFFECT_UNRESOLVED"
        } else if observed.is_none() {
            "TIME_SOURCE_UNAVAILABLE"
        } else if rolled_back {
            "TIME_ROLLBACK_DETECTED"
        } else {
            "TIME_OK"
        };
        let high = match (old.1, observed) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        let floor = match (old.2, high) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        let revision = old
            .3
            .checked_add(1)
            .ok_or(TaskManagerError::InvalidRecord("TIME_STATE_INVALID"))?;
        if connection.execute(
            "UPDATE trusted_time_state SET confidence=?1,high_water_unix_nanos=?2,
             expiry_floor_unix_nanos=?3,reason_code=?4,revision=?5
             WHERE singleton_id=1 AND revision=?6",
            params![confidence, high, floor, reason, revision, old.3],
        )? != 1
        {
            return Err(TaskManagerError::InvalidRecord("TIME_STATE_INVALID"));
        }
        connection.execute(
            "INSERT INTO trusted_time_observations(state_revision,observed_unix_nanos,
             monotonic_nanos,high_water_unix_nanos,expiry_floor_unix_nanos,confidence,reason_code,source_class)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![revision, observed, monotonic, high, floor, confidence, reason, source],
        )?;
        Ok(TimeAssessment {
            confidence: confidence.to_owned(),
            effective_nanos: floor,
        })
    })()
}

#[allow(
    dead_code,
    reason = "external effect call sites follow the durable marker foundation"
)]
#[allow(
    clippy::too_many_arguments,
    reason = "the time marker binds the complete Task, effect subject, and owner epoch"
)]
pub(crate) fn prepare_external_effect(
    connection: &Connection,
    clock: &Arc<dyn Clock>,
    owner_id: &str,
    owner_epoch: i64,
    task_id: &str,
    subject_kind: ExternalEffectKind,
    subject_id: &str,
) -> Result<ExternalTimePermit> {
    if owner_epoch < 1
        || task_id.is_empty()
        || task_id.chars().count() > 256
        || subject_id.is_empty()
        || subject_id.chars().count() > 256
        || task_id.contains('\0')
        || subject_id.contains('\0')
    {
        return Err(TaskManagerError::InvalidRecord(
            "invalid in-flight time subject",
        ));
    }
    assess(connection, clock)?.require_trusted_time()?;
    let mut locked_time = None;
    let result = (|| -> Result<ExternalTimePermit> {
        let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Immediate)?;
        crate::assert_manager_lease(&transaction, owner_id, owner_epoch)?;
        locked_time = Some(capture_locked(&transaction, clock)?);
        let fresh = locked_time
            .as_ref()
            .ok_or(TaskManagerError::InvalidRecord("TIME_UNCERTAIN"))?;
        fresh.require_trusted_time()?;
        fresh.commit_in(&transaction)?.require_trusted_time()?;
        let (prepared_state_revision, prepared_observed_unix_nanos): (i64, i64) = transaction
            .query_row(
                "SELECT s.revision,o.observed_unix_nanos FROM trusted_time_state s
                 JOIN trusted_time_observations o ON o.state_revision=s.revision
                 WHERE s.singleton_id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
        let marker_id: String =
            transaction.query_row("SELECT lower(hex(randomblob(16)))", [], |row| row.get(0))?;
        transaction.execute(
            "INSERT INTO trusted_time_effect_preparations(
             marker_id,task_id,subject_kind,subject_id,owner_id,owner_epoch,
             prepared_state_revision,prepared_observed_unix_nanos)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                marker_id,
                task_id,
                subject_kind.as_str(),
                subject_id,
                owner_id,
                owner_epoch,
                prepared_state_revision,
                prepared_observed_unix_nanos,
            ],
        )?;
        transaction.commit()?;
        locked_time = None;
        Ok(ExternalTimePermit {
            marker_id,
            task_id: task_id.to_owned(),
            subject_kind,
            subject_id: subject_id.to_owned(),
            owner_id: owner_id.to_owned(),
            owner_epoch,
            prepared_state_revision,
        })
    })();
    if let Some(fresh) = locked_time {
        fresh.commit(connection)?;
    }
    result
}

fn permit_matches_locked(transaction: &Transaction<'_>, permit: &ExternalTimePermit) -> Result<()> {
    crate::assert_manager_lease(transaction, &permit.owner_id, permit.owner_epoch)?;
    let exact: bool = transaction.query_row(
        "SELECT EXISTS(
         SELECT 1 FROM trusted_time_effect_preparations p
         JOIN trusted_time_effect_pending x ON x.marker_id=p.marker_id
         WHERE p.marker_id=?1 AND p.task_id=?2 AND p.subject_kind=?3
           AND p.subject_id=?4 AND p.owner_id=?5 AND p.owner_epoch=?6
           AND p.prepared_state_revision=?7
           AND NOT EXISTS (SELECT 1 FROM trusted_time_effect_resolutions r
                           WHERE r.marker_id=p.marker_id))",
        params![
            permit.marker_id,
            permit.task_id,
            permit.subject_kind.as_str(),
            permit.subject_id,
            permit.owner_id,
            permit.owner_epoch,
            permit.prepared_state_revision,
        ],
        |row| row.get(0),
    )?;
    if !exact {
        return Err(TaskManagerError::InvalidRecord("TIME_UNCERTAIN"));
    }
    Ok(())
}

#[allow(
    dead_code,
    reason = "external effect call sites follow the durable marker foundation"
)]
pub(crate) fn capture_external_entry<'transaction, 'connection>(
    transaction: &'transaction Transaction<'connection>,
    clock: &Arc<dyn Clock>,
    permit: &ExternalTimePermit,
) -> Result<ExternalEntrySample<'transaction, 'connection>> {
    permit_matches_locked(transaction, permit)?;
    let observation = capture_locked_with_permit(transaction, clock, Some(&permit.marker_id))?;
    Ok(ExternalEntrySample {
        transaction,
        marker_id: permit.marker_id.clone(),
        observation,
    })
}

#[allow(
    dead_code,
    reason = "external effect call sites follow the durable marker foundation"
)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "consuming the entry sample prevents a second resolution attempt"
)]
pub(crate) fn resolve_external_entry_in(
    permit: &ExternalTimePermit,
    entry: ExternalEntrySample<'_, '_>,
) -> Result<TimeAssessment> {
    resolve_external_entry_in_kind(permit, entry, ExternalResolutionKind::EffectInvoked)
}

#[allow(
    dead_code,
    reason = "external effect call sites follow the durable marker foundation"
)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "consuming the entry sample prevents a second resolution attempt"
)]
pub(crate) fn resolve_external_no_effect_in(
    permit: &ExternalTimePermit,
    entry: ExternalEntrySample<'_, '_>,
) -> Result<TimeAssessment> {
    resolve_external_entry_in_kind(permit, entry, ExternalResolutionKind::NoEffect)
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "the helper consumes the one-shot entry sample on either resolution path"
)]
fn resolve_external_entry_in_kind(
    permit: &ExternalTimePermit,
    entry: ExternalEntrySample<'_, '_>,
    resolution_kind: ExternalResolutionKind,
) -> Result<TimeAssessment> {
    let ExternalEntrySample {
        transaction,
        marker_id,
        observation,
    } = entry;
    if marker_id != permit.marker_id {
        return Err(TaskManagerError::InvalidRecord("TIME_UNCERTAIN"));
    }
    permit_matches_locked(transaction, permit)?;
    if resolution_kind == ExternalResolutionKind::EffectInvoked {
        observation.require_trusted_time()?;
    }
    let assessment = observation.commit_in(transaction)?;
    if resolution_kind == ExternalResolutionKind::EffectInvoked {
        assessment.require_trusted_time()?;
    }
    let (revision, observed): (i64, Option<i64>) = transaction.query_row(
        "SELECT s.revision,o.observed_unix_nanos FROM trusted_time_state s
         JOIN trusted_time_observations o ON o.state_revision=s.revision
         WHERE s.singleton_id=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    transaction.execute(
        "INSERT INTO trusted_time_effect_resolutions(
         marker_id,resolved_state_revision,entry_observed_unix_nanos,resolution_kind)
         VALUES (?1,?2,?3,?4)",
        params![
            permit.marker_id,
            revision,
            observed,
            resolution_kind.as_str()
        ],
    )?;
    Ok(assessment)
}

pub(crate) fn protected_now(connection: &Connection, clock: &Arc<dyn Clock>) -> Result<String> {
    assess(connection, clock)?.require_trusted_time()
}

/// Commits a successful protected effect with its sampled expiry floor. A
/// denied effect rolls back, then durably records that exact sample.
pub(crate) fn with_protected_immediate<T>(
    connection: &Connection,
    clock: &Arc<dyn Clock>,
    operation: impl FnOnce(&Transaction<'_>, &str) -> Result<T>,
) -> Result<T> {
    protected_now(connection, clock)?;
    #[cfg(test)]
    BEFORE_PROTECTED_LOCK_TEST_HOOK.with(|hook| {
        if let Some(callback) = hook.borrow_mut().take() {
            callback();
        }
    });
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Immediate)?;
    let fresh = capture_locked(&transaction, clock)?;
    let now = match fresh.require_trusted_time() {
        Ok(now) => now,
        Err(error) => {
            drop(transaction);
            fresh.commit(connection)?;
            return Err(error);
        }
    };
    match operation(&transaction, &now) {
        Ok(value) => {
            if let Err(error) = fresh
                .commit_in(&transaction)
                .and_then(|observation| observation.require_trusted_time().map(|_| ()))
            {
                drop(transaction);
                fresh.commit(connection)?;
                return Err(error);
            }
            match transaction.commit() {
                Ok(()) => Ok(value),
                Err(error) => {
                    // Preserve the sampled expiry floor even if SQLite did not
                    // durably acknowledge the protected transaction.
                    fresh.commit(connection)?;
                    Err(error.into())
                }
            }
        }
        Err(error) => {
            drop(transaction);
            fresh.commit(connection)?;
            Err(error)
        }
    }
}

#[cfg(test)]
thread_local! {
    static BEFORE_PROTECTED_LOCK_TEST_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
    static BEFORE_ASSESS_LOCK_TEST_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

pub(super) fn objects_current(connection: &Connection, stamped: bool) -> Result<bool> {
    let canonical = if stamped {
        let db = Connection::open_in_memory()?;
        db.execute_batch(super::MIGRATION)?;
        db.execute_batch(MIGRATION)?;
        Some(db)
    } else {
        None
    };
    for name in [
        "trusted_time_state",
        "trusted_time_observations",
        "trusted_time_state_no_duplicate",
        "trusted_time_state_monotone",
        "trusted_time_state_no_delete",
        "trusted_time_observation_no_duplicate",
        "trusted_time_observation_no_update",
        "trusted_time_observation_no_delete",
    ] {
        let actual: Option<String> = connection
            .query_row("SELECT sql FROM sqlite_master WHERE name=?1", [name], |r| {
                r.get(0)
            })
            .optional()?;
        let expected = canonical
            .as_ref()
            .map(|db| {
                db.query_row("SELECT sql FROM sqlite_master WHERE name=?1", [name], |r| {
                    r.get::<_, String>(0)
                })
            })
            .transpose()?;
        if actual.map(|sql| super::normalize_schema_sql(&sql))
            != expected.map(|sql| super::normalize_schema_sql(&sql))
        {
            return Ok(false);
        }
    }
    if stamped && !state_matches_audit(connection)? {
        return Ok(false);
    }
    Ok(true)
}

pub(super) fn inflight_objects_current(connection: &Connection, stamped: bool) -> Result<bool> {
    let canonical = if stamped {
        let db = Connection::open_in_memory()?;
        db.execute_batch(super::MIGRATION)?;
        db.execute_batch(MIGRATION)?;
        db.execute_batch(INFLIGHT_MIGRATION)?;
        Some(db)
    } else {
        None
    };
    for name in [
        "trusted_time_effect_preparations",
        "trusted_time_effect_resolutions",
        "trusted_time_effect_pending",
        "trusted_time_effect_prepare_no_duplicate",
        "trusted_time_effect_prepare_exact_insert",
        "trusted_time_effect_prepare_project",
        "trusted_time_effect_prepare_no_update",
        "trusted_time_effect_prepare_no_delete",
        "trusted_time_effect_resolution_no_duplicate",
        "trusted_time_effect_resolution_exact_insert",
        "trusted_time_effect_resolution_project",
        "trusted_time_effect_resolution_no_update",
        "trusted_time_effect_resolution_no_delete",
        "trusted_time_effect_pending_no_duplicate",
        "trusted_time_effect_pending_exact_insert",
        "trusted_time_effect_pending_no_update",
        "trusted_time_effect_pending_no_unresolved_delete",
    ] {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE name=?1",
                [name],
                |row| row.get(0),
            )
            .optional()?;
        let expected = canonical
            .as_ref()
            .map(|db| {
                db.query_row(
                    "SELECT sql FROM sqlite_master WHERE name=?1",
                    [name],
                    |row| row.get::<_, String>(0),
                )
            })
            .transpose()?;
        if actual.map(|sql| super::normalize_schema_sql(&sql))
            != expected.map(|sql| super::normalize_schema_sql(&sql))
        {
            return Ok(false);
        }
    }
    if stamped && !inflight_rows_coherent(connection)? {
        return Ok(false);
    }
    Ok(true)
}

fn inflight_rows_coherent(connection: &Connection) -> Result<bool> {
    let invalid: bool = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM trusted_time_effect_preparations p
            LEFT JOIN tasks t ON t.task_id=p.task_id
            LEFT JOIN trusted_time_observations o ON o.state_revision=p.prepared_state_revision
            LEFT JOIN trusted_time_effect_resolutions r ON r.marker_id=p.marker_id
            LEFT JOIN trusted_time_effect_pending x ON x.marker_id=p.marker_id
            WHERE t.task_id IS NULL OR o.state_revision IS NULL
               OR o.confidence<>'TRUSTED_LOCAL'
               OR o.observed_unix_nanos IS NULL
               OR o.observed_unix_nanos<>p.prepared_observed_unix_nanos
               OR p.owner_id='' OR p.owner_epoch<1
               OR (r.marker_id IS NULL AND x.marker_id IS NULL)
               OR (r.marker_id IS NOT NULL AND x.marker_id IS NOT NULL)
        UNION ALL
            SELECT 1 FROM trusted_time_effect_resolutions r
            LEFT JOIN trusted_time_effect_preparations p ON p.marker_id=r.marker_id
            LEFT JOIN trusted_time_observations o ON o.state_revision=r.resolved_state_revision
            WHERE p.marker_id IS NULL OR o.state_revision IS NULL
               OR r.resolved_state_revision<=p.prepared_state_revision
               OR o.observed_unix_nanos IS NOT r.entry_observed_unix_nanos
               OR (r.resolution_kind='EFFECT_INVOKED'
                   AND (o.confidence<>'TRUSTED_LOCAL' OR o.observed_unix_nanos IS NULL))
               OR (r.resolution_kind='NO_EFFECT'
                   AND o.confidence NOT IN ('TRUSTED_LOCAL','TIME_UNCERTAIN'))
        UNION ALL
            SELECT 1 FROM trusted_time_effect_pending x
            LEFT JOIN trusted_time_effect_preparations p ON p.marker_id=x.marker_id
            WHERE p.marker_id IS NULL
        LIMIT 1)",
        [],
        |row| row.get(0),
    )?;
    Ok(!invalid)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    };

    use tempfile::tempdir;

    use super::{
        BEFORE_ASSESS_LOCK_TEST_HOOK, BEFORE_PROTECTED_LOCK_TEST_HOOK, ExternalEffectKind,
        ExternalEntrySample, ExternalTimePermit, SecurityClockSample, TimeSource, assess,
        capture_external_entry, capture_locked, inflight_objects_current, prepare_external_effect,
        protected_now, resolve_external_entry_in, resolve_external_no_effect_in,
        with_protected_immediate,
    };
    use crate::{Actor, Clock, CreateTask, TaskManager, TaskManagerError};

    #[derive(Clone)]
    struct MutableClock {
        wall: Arc<Mutex<Option<String>>>,
        ticks: Arc<AtomicU64>,
    }

    impl MutableClock {
        fn new(wall: &str) -> Self {
            Self {
                wall: Arc::new(Mutex::new(Some(wall.to_owned()))),
                ticks: Arc::new(AtomicU64::new(0)),
            }
        }

        fn set(&self, wall: Option<&str>) {
            *self.wall.lock().unwrap() = wall.map(str::to_owned);
        }
    }

    impl Clock for MutableClock {
        fn now(&self) -> String {
            self.wall
                .lock()
                .unwrap()
                .clone()
                .unwrap_or_else(|| "2026-09-19T22:00:00Z".to_owned())
        }

        fn security_sample(&self) -> Option<SecurityClockSample> {
            Some(SecurityClockSample {
                wall: self.wall.lock().unwrap().clone()?,
                monotonic_nanos: self.ticks.fetch_add(1_000_000_000, Ordering::SeqCst),
                source: TimeSource::InjectedClock,
            })
        }
    }

    fn manager_with_time_subject(path: &std::path::Path, clock: &MutableClock) -> TaskManager {
        let mut manager = TaskManager::open_with_clock(path, Box::new(clock.clone())).unwrap();
        manager
            .create_task(&CreateTask {
                task_id: "T-time-effect".to_owned(),
                principal: Actor {
                    kind: "user".to_owned(),
                    id: "user:time-test".to_owned(),
                },
                workspace_id: None,
                original_intent: "test external time marker".to_owned(),
                normalized_intent: None,
                active_step_ids: Vec::new(),
            })
            .unwrap();
        manager
    }

    fn prepare_test_marker(manager: &TaskManager) -> super::ExternalTimePermit {
        prepare_external_effect(
            &manager.connection,
            &manager.clock,
            &manager.lease_owner,
            manager.lease_epoch,
            "T-time-effect",
            ExternalEffectKind::ExportCopy,
            "export-op:1",
        )
        .unwrap()
    }

    #[test]
    fn external_entry_type_retains_the_capturing_transaction_borrow() {
        fn capture_borrowed<'transaction, 'connection>(
            transaction: &'transaction rusqlite::Transaction<'connection>,
            clock: &Arc<dyn Clock>,
            permit: &ExternalTimePermit,
        ) -> crate::Result<ExternalEntrySample<'transaction, 'connection>> {
            capture_external_entry(transaction, clock, permit)
        }

        let directory = tempdir().unwrap();
        let path = directory.path().join("borrowed-entry.sqlite3");
        let clock = MutableClock::new("2026-09-19T22:00:00Z");
        let manager = manager_with_time_subject(&path, &clock);
        let permit = prepare_test_marker(&manager);
        let transaction = rusqlite::Transaction::new_unchecked(
            &manager.connection,
            rusqlite::TransactionBehavior::Immediate,
        )
        .unwrap();
        let entry = capture_borrowed(&transaction, &manager.clock, &permit).unwrap();
        // The borrowed entry prevents dropping this transaction and starting a
        // replacement one before resolution; the resolver accepts no new transaction.
        assert_eq!(
            entry.require_trusted_time().unwrap(),
            "2026-09-19T22:00:00Z"
        );
        resolve_external_entry_in(&permit, entry).unwrap();
        transaction.commit().unwrap();
    }

    #[test]
    fn forward_expiry_floor_never_falls_and_adverse_denial_is_committed() {
        let clock = MutableClock::new("2026-09-19T21:00:00Z");
        let manager = TaskManager::open_in_memory_with_clock(Box::new(clock.clone())).unwrap();
        clock.set(Some("2026-09-19T22:00:00Z"));
        assert_eq!(
            assess(&manager.connection, &manager.clock)
                .unwrap()
                .require_trusted_time()
                .unwrap(),
            "2026-09-19T22:00:00Z"
        );
        clock.set(Some("2026-09-19T21:59:59Z"));
        assert_eq!(
            assess(&manager.connection, &manager.clock)
                .unwrap()
                .require_trusted_time()
                .unwrap(),
            "2026-09-19T22:00:00Z"
        );
        clock.set(Some("2026-09-19T21:00:00Z"));
        assert!(
            assess(&manager.connection, &manager.clock)
                .unwrap()
                .require_trusted_time()
                .is_err()
        );
        let (confidence, high, floor, reason): (String, i64, i64, String) = manager.connection.query_row(
            "SELECT confidence,high_water_unix_nanos,expiry_floor_unix_nanos,reason_code FROM trusted_time_state WHERE singleton_id=1",
            [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
        assert_eq!(confidence, "TIME_UNCERTAIN");
        assert_eq!(high, floor);
        assert_eq!(reason, "TIME_ROLLBACK_DETECTED");
        clock.set(Some("2026-09-19T23:00:00Z"));
        assert!(
            assess(&manager.connection, &manager.clock)
                .unwrap()
                .require_trusted_time()
                .is_err()
        );
        let count: i64 = manager
            .connection
            .query_row("SELECT COUNT(*) FROM trusted_time_observations", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(count >= 5);
    }

    #[test]
    fn restart_rollback_and_unavailable_samples_remain_uncertain() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("trusted-time.sqlite3");
        let clock = MutableClock::new("2026-09-19T22:00:00Z");
        let manager = TaskManager::open_with_clock(&path, Box::new(clock.clone())).unwrap();
        drop(manager);
        clock.set(Some("2026-09-19T21:00:00Z"));
        let manager = TaskManager::open_with_clock(&path, Box::new(clock.clone())).unwrap();
        assert!(
            assess(&manager.connection, &manager.clock)
                .unwrap()
                .require_trusted_time()
                .is_err()
        );
        assert!(manager.get_task("nonexistent").unwrap().is_none());
        drop(manager);
        clock.set(Some("2026-09-19T23:00:00Z"));
        let manager = TaskManager::open_with_clock(&path, Box::new(clock.clone())).unwrap();
        assert!(
            assess(&manager.connection, &manager.clock)
                .unwrap()
                .require_trusted_time()
                .is_err()
        );
        drop(manager);
        clock.set(None);
        let manager = TaskManager::open_with_clock(&path, Box::new(clock.clone())).unwrap();
        assert!(
            assess(&manager.connection, &manager.clock)
                .unwrap()
                .require_trusted_time()
                .is_err()
        );
    }

    #[test]
    fn malformed_or_missing_security_sample_and_schema_tamper_fail_closed() {
        for sample in [Some("not-a-time"), None] {
            let directory = tempdir().unwrap();
            let path = directory.path().join("trusted-time.sqlite3");
            let clock = MutableClock::new("2026-09-19T22:00:00Z");
            let manager = TaskManager::open_with_clock(&path, Box::new(clock.clone())).unwrap();
            clock.set(sample);
            assert!(
                assess(&manager.connection, &manager.clock)
                    .unwrap()
                    .require_trusted_time()
                    .is_err()
            );
            manager
                .connection
                .execute_batch("DROP TRIGGER trusted_time_state_no_duplicate")
                .unwrap();
            drop(manager);
            assert!(TaskManager::open_with_clock(&path, Box::new(clock)).is_err());
        }
    }

    #[test]
    fn stamped_state_divergence_from_immutable_audit_fails_on_reopen() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("trusted-time.sqlite3");
        let clock = MutableClock::new("2026-09-19T22:00:00Z");
        let manager = TaskManager::open_with_clock(&path, Box::new(clock.clone())).unwrap();
        manager
            .connection
            .execute(
                "UPDATE trusted_time_state SET high_water_unix_nanos=high_water_unix_nanos+1,
                 expiry_floor_unix_nanos=expiry_floor_unix_nanos+1,revision=revision+1
                 WHERE singleton_id=1",
                [],
            )
            .unwrap();
        drop(manager);
        assert!(TaskManager::open_with_clock(&path, Box::new(clock)).is_err());
    }

    #[test]
    fn clock_advance_between_precheck_and_locked_decision_denies_without_effect() {
        let clock = MutableClock::new("2026-09-19T21:00:00Z");
        let manager = TaskManager::open_in_memory_with_clock(Box::new(clock.clone())).unwrap();
        manager
            .connection
            .execute_batch("CREATE TABLE protected_time_effect(id INTEGER PRIMARY KEY)")
            .unwrap();
        let advancing_clock = clock.clone();
        BEFORE_PROTECTED_LOCK_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                advancing_clock.set(Some("2026-09-19T22:00:00Z"));
            }));
        });
        assert!(matches!(
            with_protected_immediate(&manager.connection, &manager.clock, |transaction, now| {
                if now == "2026-09-19T22:00:00Z" {
                    return Err(TaskManagerError::InvalidRecord("TIME_EXPIRED"));
                }
                transaction.execute("INSERT INTO protected_time_effect(id) VALUES (1)", [])?;
                Ok(())
            }),
            Err(TaskManagerError::InvalidRecord("TIME_EXPIRED"))
        ));
        let effects: i64 = manager
            .connection
            .query_row("SELECT COUNT(*) FROM protected_time_effect", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(effects, 0);
        clock.set(Some("2026-09-19T21:00:00Z"));
        assert!(matches!(
            protected_now(&manager.connection, &manager.clock),
            Err(TaskManagerError::InvalidRecord("TIME_UNCERTAIN"))
        ));
    }

    #[test]
    fn local_effect_rolls_back_if_its_time_observation_cannot_commit() {
        let clock = MutableClock::new("2026-09-19T21:00:00Z");
        let manager = TaskManager::open_in_memory_with_clock(Box::new(clock)).unwrap();
        manager
            .connection
            .execute_batch("CREATE TABLE protected_time_effect(id INTEGER PRIMARY KEY)")
            .unwrap();
        let result = with_protected_immediate(
            &manager.connection,
            &manager.clock,
            |transaction, _| {
                transaction.execute("INSERT INTO protected_time_effect(id) VALUES (1)", [])?;
                transaction.execute_batch(
                    "CREATE TEMP TRIGGER refuse_time_audit BEFORE INSERT ON trusted_time_observations
                     BEGIN SELECT RAISE(ABORT,'time audit refused'); END",
                )?;
                Ok(())
            },
        );
        assert!(result.is_err());
        let effects: i64 = manager
            .connection
            .query_row("SELECT COUNT(*) FROM protected_time_effect", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(effects, 0);
    }

    #[test]
    fn failed_time_observation_preserves_exact_locked_forward_sample() {
        let clock = MutableClock::new("2026-09-19T21:00:00Z");
        let manager = TaskManager::open_in_memory_with_clock(Box::new(clock.clone())).unwrap();
        manager
            .connection
            .execute_batch(
                "CREATE TABLE protected_time_effect(id INTEGER PRIMARY KEY);
                 CREATE TEMP TRIGGER refuse_tentative_effect_time
                 BEFORE INSERT ON trusted_time_observations
                 WHEN EXISTS(SELECT 1 FROM protected_time_effect)
                 BEGIN SELECT RAISE(ABORT,'tentative effect time audit refused'); END",
            )
            .unwrap();
        let advancing_clock = clock.clone();
        BEFORE_PROTECTED_LOCK_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                advancing_clock.set(Some("2026-09-19T22:00:00Z"));
            }));
        });
        let result =
            with_protected_immediate(&manager.connection, &manager.clock, |transaction, _| {
                transaction.execute("INSERT INTO protected_time_effect(id) VALUES (1)", [])?;
                Ok(())
            });
        assert!(result.is_err());
        let effects: i64 = manager
            .connection
            .query_row("SELECT COUNT(*) FROM protected_time_effect", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(effects, 0);
        let high: i64 = manager
            .connection
            .query_row(
                "SELECT high_water_unix_nanos FROM trusted_time_state WHERE singleton_id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            i128::from(high),
            super::OffsetDateTime::parse("2026-09-19T22:00:00Z", &super::Rfc3339)
                .unwrap()
                .unix_timestamp_nanos()
        );
        clock.set(Some("2026-09-19T21:00:00Z"));
        assert!(matches!(
            protected_now(&manager.connection, &manager.clock),
            Err(TaskManagerError::InvalidRecord("TIME_UNCERTAIN"))
        ));
    }

    #[test]
    fn unresolved_external_time_marker_latches_uncertainty_before_recovery_on_reopen() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("inflight-time.sqlite3");
        let clock = MutableClock::new("2026-09-19T22:00:00Z");
        let manager = manager_with_time_subject(&path, &clock);
        let permit = prepare_test_marker(&manager);
        assert_eq!(permit.task_id, "T-time-effect");
        assert!(matches!(
            protected_now(&manager.connection, &manager.clock),
            Err(TaskManagerError::InvalidRecord("TIME_UNCERTAIN"))
        ));
        let live_confidence: String = manager
            .connection
            .query_row(
                "SELECT confidence FROM trusted_time_state WHERE singleton_id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(live_confidence, "TRUSTED_LOCAL");
        drop(manager);
        clock.set(Some("2026-09-19T21:00:00Z"));
        let reopened = TaskManager::open_with_clock(&path, Box::new(clock)).unwrap();
        let (confidence, reason): (String, String) = reopened
            .connection
            .query_row(
                "SELECT confidence,reason_code FROM trusted_time_state WHERE singleton_id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(confidence, "TIME_UNCERTAIN");
        assert_eq!(reason, "TIME_EFFECT_UNRESOLVED");
        assert!(reopened.get_task("T-time-effect").unwrap().is_some());
        assert!(matches!(
            protected_now(&reopened.connection, &reopened.clock),
            Err(TaskManagerError::InvalidRecord("TIME_UNCERTAIN"))
        ));
    }

    #[test]
    fn unresolved_marker_reopen_latches_even_without_wall_rollback() {
        for reopened_wall in ["2026-09-19T22:00:00Z", "2026-09-19T23:00:00Z"] {
            let directory = tempdir().unwrap();
            let path = directory.path().join("unresolved-forward.sqlite3");
            let clock = MutableClock::new("2026-09-19T22:00:00Z");
            let manager = manager_with_time_subject(&path, &clock);
            let _permit = prepare_test_marker(&manager);
            drop(manager);
            clock.set(Some(reopened_wall));
            let reopened = TaskManager::open_with_clock(&path, Box::new(clock)).unwrap();
            let (confidence, reason): (String, String) = reopened
                .connection
                .query_row(
                    "SELECT confidence,reason_code FROM trusted_time_state WHERE singleton_id=1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(confidence, "TIME_UNCERTAIN");
            assert_eq!(reason, "TIME_EFFECT_UNRESOLVED");
            assert!(matches!(
                protected_now(&reopened.connection, &reopened.clock),
                Err(TaskManagerError::InvalidRecord("TIME_UNCERTAIN"))
            ));
        }
    }

    #[test]
    fn resolved_external_time_marker_reopens_without_time_uncertainty() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("resolved-time.sqlite3");
        let clock = MutableClock::new("2026-09-19T22:00:00Z");
        let manager = manager_with_time_subject(&path, &clock);
        let permit = prepare_test_marker(&manager);
        let transaction = rusqlite::Transaction::new_unchecked(
            &manager.connection,
            rusqlite::TransactionBehavior::Immediate,
        )
        .unwrap();
        let entry = capture_external_entry(&transaction, &manager.clock, &permit).unwrap();
        assert_eq!(
            entry.require_trusted_time().unwrap(),
            "2026-09-19T22:00:00Z"
        );
        resolve_external_entry_in(&permit, entry).unwrap();
        transaction.commit().unwrap();
        assert!(
            manager
                .connection
                .execute(
                    "INSERT OR REPLACE INTO trusted_time_effect_resolutions
                 SELECT * FROM trusted_time_effect_resolutions WHERE marker_id=?1",
                    [&permit.marker_id],
                )
                .is_err()
        );
        assert!(
            manager
                .connection
                .execute(
                    "UPDATE trusted_time_effect_resolutions
                 SET entry_observed_unix_nanos=entry_observed_unix_nanos+1
                 WHERE marker_id=?1",
                    [&permit.marker_id],
                )
                .is_err()
        );
        assert_eq!(
            manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM trusted_time_effect_pending",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        drop(manager);
        let reopened = TaskManager::open_with_clock(&path, Box::new(clock)).unwrap();
        assert!(protected_now(&reopened.connection, &reopened.clock).is_ok());
        assert!(inflight_objects_current(&reopened.connection, true).unwrap());
    }

    #[test]
    fn distinct_resolved_entry_time_sets_floor_and_rejects_reopen_rollback() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("resolved-forward-entry.sqlite3");
        let clock = MutableClock::new("2026-09-19T22:00:00Z");
        let manager = manager_with_time_subject(&path, &clock);
        let permit = prepare_test_marker(&manager);
        let prepared: i64 = manager
            .connection
            .query_row(
                "SELECT prepared_observed_unix_nanos FROM trusted_time_effect_preparations WHERE marker_id=?1",
                [&permit.marker_id],
                |row| row.get(0),
            )
            .unwrap();
        clock.set(Some("2026-09-19T23:00:00Z"));
        let transaction = rusqlite::Transaction::new_unchecked(
            &manager.connection,
            rusqlite::TransactionBehavior::Immediate,
        )
        .unwrap();
        let entry = capture_external_entry(&transaction, &manager.clock, &permit).unwrap();
        assert_eq!(
            entry.require_trusted_time().unwrap(),
            "2026-09-19T23:00:00Z"
        );
        resolve_external_entry_in(&permit, entry).unwrap();
        transaction.commit().unwrap();
        let (resolved, floor): (i64, i64) = manager
            .connection
            .query_row(
                "SELECT r.entry_observed_unix_nanos,s.expiry_floor_unix_nanos
                 FROM trusted_time_effect_resolutions r CROSS JOIN trusted_time_state s
                 WHERE r.marker_id=?1 AND s.singleton_id=1",
                [&permit.marker_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(resolved > prepared);
        assert_eq!(resolved, floor);
        drop(manager);
        clock.set(Some("2026-09-19T22:00:00Z"));
        let reopened = TaskManager::open_with_clock(&path, Box::new(clock)).unwrap();
        assert!(matches!(
            protected_now(&reopened.connection, &reopened.clock),
            Err(TaskManagerError::InvalidRecord("TIME_UNCERTAIN"))
        ));
    }

    #[test]
    fn revoked_task_before_callback_resolves_no_effect_without_poisoning_time() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("revoked-before-effect.sqlite3");
        let clock = MutableClock::new("2026-09-19T22:00:00Z");
        let manager = manager_with_time_subject(&path, &clock);
        let permit = prepare_test_marker(&manager);
        manager
            .connection
            .execute(
                "UPDATE tasks SET state='RECOVERING' WHERE task_id='T-time-effect'",
                [],
            )
            .unwrap();
        let transaction = rusqlite::Transaction::new_unchecked(
            &manager.connection,
            rusqlite::TransactionBehavior::Immediate,
        )
        .unwrap();
        let entry = capture_external_entry(&transaction, &manager.clock, &permit).unwrap();
        let revoked: bool = transaction
            .query_row(
                "SELECT state='RECOVERING' FROM tasks WHERE task_id='T-time-effect'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(revoked);
        resolve_external_no_effect_in(&permit, entry).unwrap();
        transaction.commit().unwrap();
        let (kind, pending, confidence): (String, i64, String) = manager
            .connection
            .query_row(
                "SELECT r.resolution_kind,
                   (SELECT COUNT(*) FROM trusted_time_effect_pending),s.confidence
                 FROM trusted_time_effect_resolutions r CROSS JOIN trusted_time_state s
                 WHERE s.singleton_id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            (kind.as_str(), pending, confidence.as_str()),
            ("NO_EFFECT", 0, "TRUSTED_LOCAL")
        );
        assert!(protected_now(&manager.connection, &manager.clock).is_ok());
    }

    #[test]
    fn rolled_back_entry_resolves_no_effect_and_keeps_time_uncertain() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("rollback-before-effect.sqlite3");
        let clock = MutableClock::new("2026-09-19T22:00:00Z");
        let manager = manager_with_time_subject(&path, &clock);
        let permit = prepare_test_marker(&manager);
        clock.set(Some("2026-09-19T21:00:00Z"));
        let transaction = rusqlite::Transaction::new_unchecked(
            &manager.connection,
            rusqlite::TransactionBehavior::Immediate,
        )
        .unwrap();
        let entry = capture_external_entry(&transaction, &manager.clock, &permit).unwrap();
        assert!(entry.require_trusted_time().is_err());
        resolve_external_no_effect_in(&permit, entry).unwrap();
        transaction.commit().unwrap();
        let (kind, pending, confidence): (String, i64, String) = manager
            .connection
            .query_row(
                "SELECT r.resolution_kind,
                   (SELECT COUNT(*) FROM trusted_time_effect_pending),s.confidence
                 FROM trusted_time_effect_resolutions r CROSS JOIN trusted_time_state s
                 WHERE s.singleton_id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            (kind.as_str(), pending, confidence.as_str()),
            ("NO_EFFECT", 0, "TIME_UNCERTAIN")
        );
        drop(manager);
        clock.set(Some("2026-09-19T23:00:00Z"));
        let reopened = TaskManager::open_with_clock(&path, Box::new(clock)).unwrap();
        assert!(matches!(
            protected_now(&reopened.connection, &reopened.clock),
            Err(TaskManagerError::InvalidRecord("TIME_UNCERTAIN"))
        ));
    }

    #[test]
    fn unavailable_entry_resolves_no_effect_with_null_observation() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("unavailable-before-effect.sqlite3");
        let clock = MutableClock::new("2026-09-19T22:00:00Z");
        let manager = manager_with_time_subject(&path, &clock);
        let permit = prepare_test_marker(&manager);
        clock.set(None);
        let transaction = rusqlite::Transaction::new_unchecked(
            &manager.connection,
            rusqlite::TransactionBehavior::Immediate,
        )
        .unwrap();
        let entry = capture_external_entry(&transaction, &manager.clock, &permit).unwrap();
        assert!(entry.require_trusted_time().is_err());
        resolve_external_no_effect_in(&permit, entry).unwrap();
        transaction.commit().unwrap();
        let (kind, observed, confidence): (String, Option<i64>, String) = manager
            .connection
            .query_row(
                "SELECT r.resolution_kind,r.entry_observed_unix_nanos,s.confidence
                 FROM trusted_time_effect_resolutions r CROSS JOIN trusted_time_state s
                 WHERE s.singleton_id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            (kind.as_str(), observed, confidence.as_str()),
            ("NO_EFFECT", None, "TIME_UNCERTAIN")
        );
        assert!(inflight_objects_current(&manager.connection, true).unwrap());
    }

    #[test]
    fn marker_duplicate_tamper_and_wrong_epoch_fail_closed() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("marker-tamper.sqlite3");
        let clock = MutableClock::new("2026-09-19T22:00:00Z");
        let manager = manager_with_time_subject(&path, &clock);
        let mut permit = prepare_test_marker(&manager);
        assert!(
            manager
                .connection
                .execute(
                    "INSERT OR REPLACE INTO trusted_time_effect_preparations
                 SELECT * FROM trusted_time_effect_preparations WHERE marker_id=?1",
                    [&permit.marker_id],
                )
                .is_err()
        );
        assert!(manager
            .connection
            .execute(
                "UPDATE trusted_time_effect_preparations SET subject_id='forged' WHERE marker_id=?1",
                [&permit.marker_id],
            )
            .is_err());
        assert!(
            manager
                .connection
                .execute(
                    "DELETE FROM trusted_time_effect_pending WHERE marker_id=?1",
                    [&permit.marker_id],
                )
                .is_err()
        );
        assert!(
            manager
                .connection
                .execute(
                "INSERT INTO trusted_time_effect_resolutions(
                 marker_id,resolved_state_revision,entry_observed_unix_nanos,resolution_kind)
                 SELECT marker_id,prepared_state_revision,prepared_observed_unix_nanos,'EFFECT_INVOKED'
                 FROM trusted_time_effect_preparations WHERE marker_id=?1",
                    [&permit.marker_id],
                )
                .is_err()
        );
        permit.owner_epoch += 1;
        let transaction = rusqlite::Transaction::new_unchecked(
            &manager.connection,
            rusqlite::TransactionBehavior::Immediate,
        )
        .unwrap();
        assert!(capture_external_entry(&transaction, &manager.clock, &permit).is_err());
        drop(transaction);
        manager
            .connection
            .execute_batch("DROP TRIGGER trusted_time_effect_prepare_no_duplicate")
            .unwrap();
        drop(manager);
        assert!(TaskManager::open_with_clock(&path, Box::new(clock)).is_err());
    }

    #[test]
    fn old_permit_fails_after_real_owner_epoch_rotation() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("rotated-owner.sqlite3");
        let clock = MutableClock::new("2026-09-19T22:00:00Z");
        let manager = manager_with_time_subject(&path, &clock);
        let permit = prepare_test_marker(&manager);
        let old_epoch = manager.lease_epoch;
        drop(manager);
        let reopened = TaskManager::open_with_clock(&path, Box::new(clock)).unwrap();
        assert!(reopened.lease_epoch > old_epoch);
        let transaction = rusqlite::Transaction::new_unchecked(
            &reopened.connection,
            rusqlite::TransactionBehavior::Immediate,
        )
        .unwrap();
        assert!(capture_external_entry(&transaction, &reopened.clock, &permit).is_err());
    }

    #[test]
    fn failed_resolution_commit_preserves_pending_marker_on_reopen() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("failed-resolution.sqlite3");
        let clock = MutableClock::new("2026-09-19T22:00:00Z");
        let manager = manager_with_time_subject(&path, &clock);
        let permit = prepare_test_marker(&manager);
        let before_revision: i64 = manager
            .connection
            .query_row(
                "SELECT revision FROM trusted_time_state WHERE singleton_id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        manager
            .connection
            .execute_batch(
                "CREATE TEMP TRIGGER fail_resolution BEFORE INSERT ON trusted_time_effect_resolutions
                 BEGIN SELECT RAISE(ABORT,'simulated resolution commit failure'); END",
            )
            .unwrap();
        let transaction = rusqlite::Transaction::new_unchecked(
            &manager.connection,
            rusqlite::TransactionBehavior::Immediate,
        )
        .unwrap();
        let entry = capture_external_entry(&transaction, &manager.clock, &permit).unwrap();
        assert!(resolve_external_entry_in(&permit, entry).is_err());
        drop(transaction);
        let (revision, pending, resolved): (i64, i64, i64) = manager
            .connection
            .query_row(
                "SELECT s.revision,
                   (SELECT COUNT(*) FROM trusted_time_effect_pending),
                   (SELECT COUNT(*) FROM trusted_time_effect_resolutions)
                 FROM trusted_time_state s WHERE s.singleton_id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!((revision, pending, resolved), (before_revision, 1, 0));
        drop(manager);
        let reopened = TaskManager::open_with_clock(&path, Box::new(clock)).unwrap();
        assert!(matches!(
            protected_now(&reopened.connection, &reopened.clock),
            Err(TaskManagerError::InvalidRecord("TIME_UNCERTAIN"))
        ));
    }

    #[test]
    fn stamped_0018_store_upgrades_0019_and_unstamped_lookalike_is_quarantined() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("prior-time-migration.sqlite3");
        let clock = MutableClock::new("2026-09-19T22:00:00Z");
        let manager = TaskManager::open_with_clock(&path, Box::new(clock.clone())).unwrap();
        manager
            .connection
            .execute_batch(
                "DROP TRIGGER artifact_placement_receipt_no_delete;
                 DROP TRIGGER artifact_placement_receipt_no_update;
                 DROP TRIGGER artifact_placement_receipt_exact_insert;
                 DROP TABLE artifact_placement_receipts;
                 DELETE FROM schema_migrations WHERE migration_id='0020_artifact_placement_receipts';
                 DROP TABLE trusted_time_effect_pending;
                 DROP TABLE trusted_time_effect_resolutions;
                 DROP TABLE trusted_time_effect_preparations;
                 DELETE FROM schema_migrations WHERE migration_id='0019_inflight_time'",
            )
            .unwrap();
        assert!(inflight_objects_current(&manager.connection, false).unwrap());
        drop(manager);
        let upgraded = TaskManager::open_with_clock(&path, Box::new(clock.clone())).unwrap();
        assert!(inflight_objects_current(&upgraded.connection, true).unwrap());
        drop(upgraded);

        let lookalike_path = directory.path().join("unstamped-lookalike.sqlite3");
        let lookalike =
            TaskManager::open_with_clock(&lookalike_path, Box::new(clock.clone())).unwrap();
        lookalike
            .connection
            .execute_batch(
                "DROP TRIGGER artifact_placement_receipt_no_delete;
                 DROP TRIGGER artifact_placement_receipt_no_update;
                 DROP TRIGGER artifact_placement_receipt_exact_insert;
                 DROP TABLE artifact_placement_receipts;
                 DELETE FROM schema_migrations WHERE migration_id='0020_artifact_placement_receipts';
                 DELETE FROM schema_migrations WHERE migration_id='0019_inflight_time';",
            )
            .unwrap();
        drop(lookalike);
        assert!(TaskManager::open_with_clock(&lookalike_path, Box::new(clock)).is_err());
        let raw = rusqlite::Connection::open(&lookalike_path).unwrap();
        let stamps: i64 = raw
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE migration_id='0019_inflight_time'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stamps, 0);
    }

    #[test]
    fn live_permit_cannot_bypass_an_unrelated_pending_marker() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("unrelated-marker.sqlite3");
        let clock = MutableClock::new("2026-09-19T22:00:00Z");
        let manager = manager_with_time_subject(&path, &clock);
        let permit = prepare_test_marker(&manager);
        manager
            .connection
            .execute(
                "INSERT INTO trusted_time_effect_preparations(
                 marker_id,task_id,subject_kind,subject_id,owner_id,owner_epoch,
                 prepared_state_revision,prepared_observed_unix_nanos)
                 SELECT 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',task_id,subject_kind,
                        'unrelated-subject',owner_id,owner_epoch,
                        prepared_state_revision,prepared_observed_unix_nanos
                 FROM trusted_time_effect_preparations WHERE marker_id=?1",
                [&permit.marker_id],
            )
            .unwrap();
        let transaction = rusqlite::Transaction::new_unchecked(
            &manager.connection,
            rusqlite::TransactionBehavior::Immediate,
        )
        .unwrap();
        assert!(capture_external_entry(&transaction, &manager.clock, &permit).is_err());
        drop(transaction);
        assert!(matches!(
            protected_now(&manager.connection, &manager.clock),
            Err(TaskManagerError::InvalidRecord("TIME_UNCERTAIN"))
        ));
    }

    #[test]
    fn marker_prepared_between_assess_precheck_and_lock_is_denied() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("assess-marker-race.sqlite3");
        let clock = MutableClock::new("2026-09-19T22:00:00Z");
        let manager = manager_with_time_subject(&path, &clock);
        clock.set(Some("2026-09-20T00:00:00Z"));
        let before_ticks = clock.ticks.load(Ordering::SeqCst);
        BEFORE_ASSESS_LOCK_TEST_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                let connection = rusqlite::Connection::open(&path).unwrap();
                connection
                    .execute(
                        "INSERT INTO trusted_time_effect_preparations(
                     marker_id,task_id,subject_kind,subject_id,owner_id,owner_epoch,
                     prepared_state_revision,prepared_observed_unix_nanos)
                     SELECT 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','T-time-effect',
                            'ARTIFACT_EXPORT_COPY','racing-export',l.owner_id,l.fence_epoch,
                            s.revision,o.observed_unix_nanos
                     FROM trusted_time_state s
                     JOIN trusted_time_observations o ON o.state_revision=s.revision
                     JOIN task_manager_lease l ON l.singleton_id=1
                     WHERE s.singleton_id=1",
                        [],
                    )
                    .unwrap();
            }));
        });
        assert!(matches!(
            protected_now(&manager.connection, &manager.clock),
            Err(TaskManagerError::InvalidRecord("TIME_UNCERTAIN"))
        ));
        assert_eq!(clock.ticks.load(Ordering::SeqCst), before_ticks);
        let (pending, confidence): (i64, String) = manager
            .connection
            .query_row(
                "SELECT (SELECT COUNT(*) FROM trusted_time_effect_pending),confidence
             FROM trusted_time_state WHERE singleton_id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(pending, 1);
        assert_eq!(confidence, "TRUSTED_LOCAL");
    }

    #[test]
    fn ordinary_locked_capture_checks_pending_before_sampling_clock() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("capture-marker-race.sqlite3");
        let clock = MutableClock::new("2026-09-19T22:00:00Z");
        let manager = manager_with_time_subject(&path, &clock);
        let _permit = prepare_test_marker(&manager);
        clock.set(Some("2026-09-20T00:00:00Z"));
        let before_ticks = clock.ticks.load(Ordering::SeqCst);
        let transaction = rusqlite::Transaction::new_unchecked(
            &manager.connection,
            rusqlite::TransactionBehavior::Immediate,
        )
        .unwrap();
        assert!(matches!(
            capture_locked(&transaction, &manager.clock),
            Err(TaskManagerError::InvalidRecord("TIME_UNCERTAIN"))
        ));
        assert_eq!(clock.ticks.load(Ordering::SeqCst), before_ticks);
    }
}
