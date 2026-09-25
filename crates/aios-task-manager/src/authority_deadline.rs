//! Checked, session-local expiry arithmetic for coordinator-issued Artifact grants.
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{Result, TaskManagerError, trusted_time::ProtectedTimeContext};

/// A bounded local issuance profile until policy carries an explicit lifetime.
const LOCAL_ARTIFACT_GRANT_NANOS: i64 = 300_000_000_000;

fn reject() -> TaskManagerError {
    TaskManagerError::InvalidRecord("authority grant deadline is not admissible")
}

pub(super) struct ApprovalExpirySources<'a> {
    pub request_expires_at: &'a str,
    pub approved_until: &'a str,
}

#[allow(dead_code, reason = "consumed by the coordinator finalizer")]
pub(super) struct PreparedGrantDeadline {
    pub grant_expires_at: String,
    pub grant_expiry_unix_nanos: i64,
    pub approval_request_expiry_unix_nanos: Option<i64>,
    pub approved_until_unix_nanos: Option<i64>,
    pub effective_expiry_unix_nanos: i64,
    pub deadline_monotonic_nanos: i64,
}

/// The caller must still enforce the grant's Task, binding, state, use count,
/// and resource scope. Expired outcomes may be durably latched by its owner.
#[allow(dead_code, reason = "consumed by protected admission boundaries")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GrantDeadlineStatus {
    Valid,
    ExpiredMonotonic,
    ExpiredWall,
    InvalidOrIncomplete,
}

/// Checks an already-issued grant without issuing, renewing, or latching it.
/// The caller holds the authority fence and has advanced the current clock
/// session to this exact paired observation in the same transaction. Immutable
/// observations since issuance also prevent an advisory preflight from seeing
/// expiry and a later regressed locked sample from reviving the grant.
#[allow(
    dead_code,
    clippy::too_many_lines,
    clippy::type_complexity,
    reason = "keeps the exact grant, receipt, session, paired-time, and approval evidence in one auditable query"
)]
pub(super) fn check_grant_deadline(
    connection: &Connection,
    grant_id: &str,
    lease_owner: &str,
    lease_epoch: i64,
    time: &ProtectedTimeContext,
) -> Result<GrantDeadlineStatus> {
    let evidence: Option<(
        String,
        i64,
        Option<String>,
        Option<i64>,
        Option<String>,
        Option<i64>,
        i64,
        i64,
        i64,
        i64,
    )> = connection
        .query_row(
            "SELECT d.grant_expires_at,d.grant_expiry_unix_nanos,
                    d.approval_request_expires_at,d.approval_request_expiry_unix_nanos,
                    d.approved_until,d.approved_until_unix_nanos,
                    d.issued_monotonic_nanos,d.issued_effective_unix_nanos,
                    d.deadline_monotonic_nanos,d.effective_expiry_unix_nanos
             FROM authority_grant_deadlines d
             JOIN authority_grants g ON g.grant_id=d.grant_id
               AND g.token_id=d.token_id AND g.task_id=d.task_id
               AND g.execution_binding_id=d.execution_binding_id
               AND g.attempt_id=d.attempt_id AND g.policy_decision_id=d.policy_decision_id
               AND g.issued_at=d.issued_at AND g.expires_at=d.grant_expires_at
               AND g.approval_id IS d.approval_id
             JOIN authority_issuance_receipts r ON r.grant_id=d.grant_id
               AND r.token_id=d.token_id AND r.task_id=d.task_id
               AND r.execution_binding_id=d.execution_binding_id
               AND r.attempt_id=d.attempt_id AND r.policy_decision_id=d.policy_decision_id
               AND r.issued_at=d.issued_at
               AND r.issuance_profile='coordinator-issued-v0.1'
             JOIN authority_clock_sessions c ON c.session_id=d.session_id
               AND c.owner_id=d.owner_id AND c.owner_epoch=d.owner_epoch
             JOIN task_manager_lease l ON l.singleton_id=1
               AND l.owner_id=d.owner_id AND l.fence_epoch=d.owner_epoch
             JOIN trusted_time_observations issued ON issued.state_revision=d.issued_state_revision
               AND issued.confidence='TRUSTED_LOCAL'
               AND issued.monotonic_nanos=d.issued_monotonic_nanos
               AND issued.observed_unix_nanos=d.issued_observed_unix_nanos
               AND issued.expiry_floor_unix_nanos=d.issued_effective_unix_nanos
             JOIN trusted_time_state s ON s.singleton_id=1
               AND s.confidence='TRUSTED_LOCAL' AND s.revision=?4
               AND s.expiry_floor_unix_nanos=?7
             JOIN trusted_time_observations observed ON observed.state_revision=s.revision
               AND observed.confidence='TRUSTED_LOCAL'
               AND observed.monotonic_nanos=?5 AND observed.observed_unix_nanos=?6
               AND observed.expiry_floor_unix_nanos=?7
             LEFT JOIN approval_requests a ON a.approval_id=d.approval_id
             LEFT JOIN approval_decisions ad ON ad.decision_id=d.approval_decision_id
             WHERE d.grant_id=?1 AND d.owner_id=?2 AND d.owner_epoch=?3
               AND c.high_water_state_revision=?4
               AND c.high_water_monotonic_nanos=?5
               AND c.high_water_observed_unix_nanos=?6
               AND d.issued_state_revision<=?4 AND d.issued_monotonic_nanos<=?5
               AND d.issued_effective_unix_nanos<=?7
               AND d.issued_monotonic_nanos>=0 AND d.issued_effective_unix_nanos>=0
               AND typeof(d.grant_expiry_unix_nanos)='integer'
               AND typeof(d.issued_monotonic_nanos)='integer'
               AND typeof(d.issued_effective_unix_nanos)='integer'
               AND typeof(d.deadline_monotonic_nanos)='integer'
               AND typeof(d.effective_expiry_unix_nanos)='integer'
               AND ((d.approval_id IS NULL AND d.approval_request_expires_at IS NULL
                     AND d.approval_request_expiry_unix_nanos IS NULL
                     AND d.approval_decision_id IS NULL AND d.approved_until IS NULL
                     AND d.approved_until_unix_nanos IS NULL)
                 OR (d.approval_id IS NOT NULL AND a.status='APPROVED'
                     AND a.expires_at=d.approval_request_expires_at
                     AND ad.approval_id=d.approval_id AND ad.decision='APPROVE'
                     AND ad.approved_until=d.approved_until
                     AND typeof(d.approval_request_expiry_unix_nanos)='integer'
                     AND typeof(d.approved_until_unix_nanos)='integer'))
               AND NOT EXISTS (SELECT 1 FROM authority_grant_expiry_latches x
                               WHERE x.grant_id=d.grant_id)
               AND NOT EXISTS (SELECT 1 FROM trusted_time_observations prior
                               WHERE prior.state_revision>=d.issued_state_revision
                                 AND prior.state_revision<?4
                                 AND prior.confidence='TRUSTED_LOCAL'
                                 AND (prior.monotonic_nanos IS NULL
                                      OR prior.monotonic_nanos>?5))",
            params![
                grant_id,
                lease_owner,
                lease_epoch,
                time.state_revision(),
                time.monotonic_nanos(),
                time.observed_unix_nanos(),
                time.effective_unix_nanos()
            ],
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
                    row.get(9)?,
                ))
            },
        )
        .optional()?;
    let Some((
        grant_expiry_text,
        grant_expiry,
        request_text,
        request_expiry,
        approved_text,
        approved_expiry,
        issued_mono,
        issued_wall,
        deadline_mono,
        effective_expiry,
    )) = evidence
    else {
        return Ok(GrantDeadlineStatus::InvalidOrIncomplete);
    };
    let caps_match = parse_nanos(&grant_expiry_text).ok() == Some(grant_expiry)
        && request_text
            .as_deref()
            .map(parse_nanos)
            .transpose()
            .ok()
            .flatten()
            == request_expiry
        && approved_text
            .as_deref()
            .map(parse_nanos)
            .transpose()
            .ok()
            .flatten()
            == approved_expiry;
    let duration_matches = effective_expiry
        .checked_sub(issued_wall)
        .filter(|duration| *duration > 0)
        .and_then(|duration| issued_mono.checked_add(duration))
        == Some(deadline_mono);
    let shortest_cap = grant_expiry
        .min(request_expiry.unwrap_or(i64::MAX))
        .min(approved_expiry.unwrap_or(i64::MAX));
    if !caps_match || !duration_matches || effective_expiry != shortest_cap {
        return Ok(GrantDeadlineStatus::InvalidOrIncomplete);
    }
    Ok(if time.monotonic_nanos() >= deadline_mono {
        GrantDeadlineStatus::ExpiredMonotonic
    } else if time.effective_unix_nanos() >= effective_expiry {
        GrantDeadlineStatus::ExpiredWall
    } else {
        GrantDeadlineStatus::Valid
    })
}

/// Latches a witnessed expiry before a protected admission may return denial.
/// Callers must commit this transaction on a `false` result so a later wall or
/// monotonic clock regression cannot make the same grant usable again.
pub(super) fn check_and_latch_grant_deadline(
    transaction: &Transaction<'_>,
    grant_id: &str,
    lease_owner: &str,
    lease_epoch: i64,
    time: &ProtectedTimeContext,
) -> Result<bool> {
    let reason = match check_grant_deadline(transaction, grant_id, lease_owner, lease_epoch, time)?
    {
        GrantDeadlineStatus::Valid => return Ok(true),
        GrantDeadlineStatus::ExpiredMonotonic => "MONOTONIC_DEADLINE",
        GrantDeadlineStatus::ExpiredWall => "WALL_EXPIRY",
        GrantDeadlineStatus::InvalidOrIncomplete => return Ok(false),
    };
    let changed = transaction.execute(
        "INSERT INTO authority_grant_expiry_latches(
         grant_id,session_id,owner_id,owner_epoch,observed_state_revision,
         observed_monotonic_nanos,observed_unix_nanos,observed_effective_unix_nanos,reason)
         SELECT d.grant_id,d.session_id,d.owner_id,d.owner_epoch,?2,?3,?4,?5,?6
         FROM authority_grant_deadlines d
         WHERE d.grant_id=?1 AND d.owner_id=?7 AND d.owner_epoch=?8",
        params![
            grant_id,
            time.state_revision(),
            time.monotonic_nanos(),
            time.observed_unix_nanos(),
            time.effective_unix_nanos(),
            reason,
            lease_owner,
            lease_epoch
        ],
    )?;
    if changed != 1 {
        return Err(TaskManagerError::InvalidRecord(
            "AUTHORITY_EXPIRY_LATCH_FAILED",
        ));
    }
    Ok(false)
}

/// A previously committed latch is expiry evidence only while its immutable
/// grant/receipt/deadline and paired observation still authenticate together.
/// Missing or incomplete evidence is a generic denial, never an expiry reason.
pub(super) fn authenticated_expiry_latch(
    connection: &Connection,
    grant_id: &str,
    lease_owner: &str,
    lease_epoch: i64,
) -> Result<bool> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM authority_grant_expiry_latches x
         JOIN authority_grant_deadlines d ON d.grant_id=x.grant_id
           AND d.session_id=x.session_id AND d.owner_id=x.owner_id
           AND d.owner_epoch=x.owner_epoch
         JOIN authority_grants g ON g.grant_id=d.grant_id AND g.token_id=d.token_id
           AND g.task_id=d.task_id AND g.execution_binding_id=d.execution_binding_id
           AND g.attempt_id=d.attempt_id AND g.policy_decision_id=d.policy_decision_id
           AND g.issued_at=d.issued_at AND g.expires_at=d.grant_expires_at
         JOIN authority_issuance_receipts r ON r.grant_id=g.grant_id
           AND r.token_id=g.token_id AND r.task_id=g.task_id
           AND r.execution_binding_id=g.execution_binding_id
           AND r.attempt_id=g.attempt_id AND r.policy_decision_id=g.policy_decision_id
           AND r.issued_at=g.issued_at AND r.issuance_profile='coordinator-issued-v0.1'
         JOIN authority_clock_sessions c ON c.session_id=d.session_id
           AND c.owner_id=d.owner_id AND c.owner_epoch=d.owner_epoch
         JOIN trusted_time_observations o ON o.state_revision=x.observed_state_revision
           AND o.confidence='TRUSTED_LOCAL'
           AND o.monotonic_nanos=x.observed_monotonic_nanos
           AND o.observed_unix_nanos=x.observed_unix_nanos
           AND o.expiry_floor_unix_nanos=x.observed_effective_unix_nanos
         WHERE x.grant_id=?1 AND x.owner_id=?2 AND x.owner_epoch=?3
           AND c.high_water_state_revision>=x.observed_state_revision
           AND c.high_water_monotonic_nanos>=x.observed_monotonic_nanos
           AND ((x.reason='MONOTONIC_DEADLINE'
                 AND x.observed_monotonic_nanos>=d.deadline_monotonic_nanos)
             OR (x.reason='WALL_EXPIRY'
                 AND x.observed_effective_unix_nanos>=d.effective_expiry_unix_nanos)))",
            params![grant_id, lease_owner, lease_epoch],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

fn parse_nanos(raw: &str) -> Result<i64> {
    let parsed = OffsetDateTime::parse(raw, &Rfc3339).map_err(|_| reject())?;
    i64::try_from(parsed.unix_timestamp_nanos()).map_err(|_| reject())
}

fn format_nanos(nanos: i64) -> Result<String> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(nanos))
        .map_err(|_| reject())?
        .format(&Rfc3339)
        .map_err(|_| reject())
}

fn derive(
    effective_now: i64,
    monotonic_now: i64,
    approval: Option<ApprovalExpirySources<'_>>,
) -> Result<PreparedGrantDeadline> {
    if effective_now < 0 || monotonic_now < 0 {
        return Err(reject());
    }
    let grant_cap = effective_now
        .checked_add(LOCAL_ARTIFACT_GRANT_NANOS)
        .ok_or_else(reject)?;
    let (request_cap, approved_cap) = match approval {
        Some(sources) => (
            Some(parse_nanos(sources.request_expires_at)?),
            Some(parse_nanos(sources.approved_until)?),
        ),
        None => (None, None),
    };
    let effective_expiry = request_cap
        .into_iter()
        .chain(approved_cap)
        .fold(grant_cap, i64::min);
    // The durable grant itself carries the shortest cap. Existing launch and
    // Artifact checks compare its expires_at to approval evidence directly.
    let grant_expires_at = format_nanos(effective_expiry)?;
    let ttl = effective_expiry
        .checked_sub(effective_now)
        .filter(|ttl| *ttl > 0)
        .ok_or_else(reject)?;
    let deadline = monotonic_now.checked_add(ttl).ok_or_else(reject)?;
    Ok(PreparedGrantDeadline {
        grant_expires_at,
        grant_expiry_unix_nanos: effective_expiry,
        approval_request_expiry_unix_nanos: request_cap,
        approved_until_unix_nanos: approved_cap,
        effective_expiry_unix_nanos: effective_expiry,
        deadline_monotonic_nanos: deadline,
    })
}

/// Uses the same paired wall floor and monotonic sample that will be persisted
/// with the grant. A replay must read the original row instead of calling this.
#[allow(dead_code, reason = "consumed by the coordinator finalizer")]
pub(super) fn prepare_local_artifact_deadline(
    context: &ProtectedTimeContext,
    approval: Option<ApprovalExpirySources<'_>>,
) -> Result<PreparedGrantDeadline> {
    derive(
        context.effective_unix_nanos(),
        context.monotonic_nanos(),
        approval,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trusted_time::{
        SecurityClockSample, TimeSource, advance_clock_session_in, with_protected_observation,
    };
    use crate::{Clock, TaskManager};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    };

    #[derive(Clone)]
    struct TestClock {
        wall: Arc<Mutex<String>>,
        ticks: Arc<AtomicU64>,
    }

    impl Clock for TestClock {
        fn now(&self) -> String {
            self.wall.lock().unwrap().clone()
        }

        fn security_sample(&self) -> Option<SecurityClockSample> {
            Some(SecurityClockSample {
                wall: self.now(),
                monotonic_nanos: self.ticks.fetch_add(1_000_000_000, Ordering::SeqCst),
                source: TimeSource::InjectedClock,
            })
        }
    }

    #[test]
    fn persisted_deadline_requires_exact_evidence_and_enforces_both_clocks() {
        let clock = TestClock {
            wall: Arc::new(Mutex::new("2026-09-24T12:00:00Z".to_owned())),
            ticks: Arc::new(AtomicU64::new(0)),
        };
        let manager = TaskManager::open_in_memory_with_clock(Box::new(clock.clone())).unwrap();
        // This fixture supplies a synthetic predecessor receipt without the
        // full policy chain; the deadline check itself authenticates the row.
        manager
            .connection
            .execute_batch(
                "PRAGMA foreign_keys=OFF;
             DROP TRIGGER authority_issuance_receipt_exact_insert;",
            )
            .unwrap();
        let (owner, epoch): (String, i64) = manager
            .connection
            .query_row(
                "SELECT owner_id,fence_epoch FROM task_manager_lease WHERE singleton_id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let issued_mono = with_protected_observation(&manager.connection, &manager.clock, |tx, time| {
            advance_clock_session_in(tx, &owner, epoch, time)?;
            let expiry = time.effective_unix_nanos() + 300_000_000_000;
            tx.execute(
                "INSERT INTO authority_grants
                 (grant_id,token_id,task_id,semantic_program_hash,node_id,capability,
                  principal_kind,principal_id,execution_binding_id,attempt_id,
                  policy_decision_id,policy_snapshot_id,grants_json,scope,state,issued_at,expires_at)
                 VALUES ('grant','token','task','hash','node','cap','provider','principal',
                         'binding','attempt','decision','snapshot','[]','TIME_LIMITED','ACTIVE',?1,?2)",
                params![time.now(), format_nanos(expiry)?],
            )?;
            tx.execute(
                "INSERT INTO authority_issuance_receipts VALUES
                 ('grant','token','task','binding','attempt','decision',?1,'coordinator-issued-v0.1')",
                [time.now()],
            )?;
            tx.execute(
                "INSERT INTO authority_grant_deadlines
                 (grant_id,token_id,task_id,execution_binding_id,attempt_id,policy_decision_id,
                  issued_at,grant_expires_at,grant_expiry_unix_nanos,session_id,owner_id,owner_epoch,
                  issued_state_revision,issued_monotonic_nanos,deadline_monotonic_nanos,
                  issued_observed_unix_nanos,issued_effective_unix_nanos,effective_expiry_unix_nanos)
                 VALUES ('grant','token','task','binding','attempt','decision',?1,?2,?3,
                         ?4,?4,?5,?6,?7,?8,?9,?10,?3)",
                params![time.now(), format_nanos(expiry)?, expiry, owner, epoch,
                        time.state_revision(), time.monotonic_nanos(),
                        time.monotonic_nanos() + 300_000_000_000,
                        time.observed_unix_nanos(), time.effective_unix_nanos()],
            )?;
            Ok(time.monotonic_nanos())
        }).unwrap();
        let check = || {
            with_protected_observation(&manager.connection, &manager.clock, |tx, time| {
                advance_clock_session_in(tx, &owner, epoch, time)?;
                Ok((
                    check_grant_deadline(tx, "grant", &owner, epoch, time)?,
                    check_grant_deadline(tx, "grant", "wrong-owner", epoch, time)?,
                    check_grant_deadline(tx, "missing", &owner, epoch, time)?,
                ))
            })
            .unwrap()
        };
        assert_eq!(
            check(),
            (
                GrantDeadlineStatus::Valid,
                GrantDeadlineStatus::InvalidOrIncomplete,
                GrantDeadlineStatus::InvalidOrIncomplete
            )
        );
        *clock.wall.lock().unwrap() = "2026-09-24T12:05:00Z".to_owned();
        assert_eq!(check().0, GrantDeadlineStatus::ExpiredWall);
        clock.ticks.store(
            u64::try_from(issued_mono).unwrap() + 301_000_000_000,
            Ordering::SeqCst,
        );
        assert_eq!(check().0, GrantDeadlineStatus::ExpiredMonotonic);
    }

    #[test]
    fn approval_caps_local_grant_to_the_earliest_exact_instant() {
        let start = parse_nanos("2026-09-24T12:00:00Z").unwrap();
        let sources = ApprovalExpirySources {
            request_expires_at: "2026-09-24T07:01:00-05:00",
            approved_until: "2026-09-24T12:00:30.000000001Z",
        };
        let cap = derive(start, 1_000, Some(sources)).unwrap();
        assert_eq!(cap.grant_expiry_unix_nanos, start + 30_000_000_001);
        assert_eq!(cap.grant_expires_at, "2026-09-24T12:00:30.000000001Z");
        assert_eq!(cap.effective_expiry_unix_nanos, start + 30_000_000_001);
        assert_eq!(cap.deadline_monotonic_nanos, 30_000_001_001);
        assert_eq!(
            cap.approval_request_expiry_unix_nanos,
            Some(start + 60_000_000_000)
        );
        assert_eq!(cap.approved_until_unix_nanos, Some(start + 30_000_000_001));
    }

    #[test]
    fn expired_malformed_and_overflowing_sources_fail_closed() {
        let start = parse_nanos("2026-09-24T12:00:00Z").unwrap();
        for (request_expires_at, approved_until) in [
            ("2026-09-24T12:00:00Z", "2026-09-24T12:01:00Z"),
            ("2026-09-24T12:01:00Z", "2026-09-24T11:59:59.999999999Z"),
            ("2026-09-24T12:01:00Z", "not-a-time"),
            ("2300-01-01T00:00:00Z", "2026-09-24T12:01:00Z"),
        ] {
            assert!(
                derive(
                    start,
                    0,
                    Some(ApprovalExpirySources {
                        request_expires_at,
                        approved_until,
                    })
                )
                .is_err()
            );
        }
        assert!(derive(i64::MAX, 0, None).is_err());
        assert!(derive(start, i64::MAX, None).is_err());
        assert!(derive(start, -1, None).is_err());
    }
}
