use std::sync::Arc;

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::{Clock, Result, TaskManagerError};

pub(super) const MIGRATION: &str =
    include_str!("../../../specs/persistence-v0.1-0018-trusted-time.sql");
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
    assess_sample(connection, clock.security_sample().as_ref())
}

pub(crate) fn capture_locked(
    connection: &Connection,
    clock: &Arc<dyn Clock>,
) -> Result<LockedTimeObservation> {
    let sample = clock.security_sample();
    if !state_matches_audit_tail(connection)? {
        return Err(TaskManagerError::InvalidRecord("TIME_STATE_INVALID"));
    }
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
    connection.execute_batch("BEGIN IMMEDIATE")?;
    let result = apply_sample_in_transaction(connection, sample);
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
        let confidence = if old.0 == "TIME_UNCERTAIN" || observed.is_none() || rolled_back {
            "TIME_UNCERTAIN"
        } else {
            "TRUSTED_LOCAL"
        };
        let reason = if old.0 == "TIME_UNCERTAIN" {
            "TIME_UNCERTAIN"
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
            fresh.commit_in(&transaction)?.require_trusted_time()?;
            transaction.commit()?;
            Ok(value)
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

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    };

    use tempfile::tempdir;

    use super::{
        BEFORE_PROTECTED_LOCK_TEST_HOOK, SecurityClockSample, TimeSource, assess, protected_now,
        with_protected_immediate,
    };
    use crate::{Clock, TaskManager, TaskManagerError};

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
}
