//! Non-executable reservations for deterministic authority evaluation.

use super::{
    Result, TaskManager, TaskManagerError, active_program_validation_valid, assert_manager_lease,
    program_node,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CandidateResourceHandle {
    InputArtifact {
        artifact_id: String,
    },
    OutputAllocation {
        allocation_id: String,
        output_port: String,
    },
}

/// The action and selector are untrusted claims; the durable values come from validated IR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CandidateResourceChoice {
    pub action: String,
    pub semantic_selector: String,
    pub handle: CandidateResourceHandle,
}

#[derive(Clone, Copy)]
pub(crate) struct ReserveAuthorityCandidate<'a> {
    pub candidate_id: &'a str,
    pub binding_id: &'a str,
    pub attempt_id: &'a str,
    pub task_id: &'a str,
    pub semantic_program_hash: &'a str,
    pub registry_snapshot_id: &'a str,
    pub node_id: &'a str,
    pub capability_contract_hash: &'a str,
    pub provider_registration_id: &'a str,
    pub attempt_number: u32,
    pub resources: &'a [CandidateResourceChoice],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingAuthorityCandidate {
    pub candidate_id: String,
    pub binding_id: String,
    pub attempt_id: String,
    pub task_id: String,
    pub semantic_program_hash: String,
    pub registry_snapshot_id: String,
    pub node_id: String,
    pub capability: String,
    pub provider_registration_id: String,
    pub provider_id: String,
    pub provider_build_hash: String,
    pub conformance_evidence_id: String,
    pub execution_profile_ref: String,
    pub isolation_class: String,
    pub placement_locality: &'static str,
    pub resource_count: usize,
}

fn reject() -> TaskManagerError {
    TaskManagerError::InvalidRecord("authority candidate reservation is not admissible")
}

fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256
}

fn task_constraints_allow_local(raw: Option<&str>, checked: OffsetDateTime) -> bool {
    let Some(raw) = raw else { return true };
    let Ok(value) = aios_registry::parse_strict_value(
        raw.as_bytes(),
        aios_registry::StrictJsonLimits::default(),
    ) else {
        return false;
    };
    let Some(fields) = value.as_object() else {
        return false;
    };
    fields.iter().all(|(key, value)| match key.as_str() {
        "privacy" => matches!(
            value.as_str(),
            Some("local-only" | "local-first" | "remote-allowed")
        ),
        "max_cost_microunits" => value.is_null() || value.as_u64().is_some(),
        "deadline" => {
            value.is_null()
                || value
                    .as_str()
                    .and_then(|raw| OffsetDateTime::parse(raw, &Rfc3339).ok())
                    .is_some_and(|deadline| deadline > checked)
        }
        "preserve_inputs" => value.is_boolean(),
        _ => false,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "keeps the complete evidence freshness check together"
)]
pub(super) fn evidence_still_current(
    transaction: &rusqlite::Transaction<'_>,
    selected: &aios_registry::ProviderCandidate,
    capability: &str,
    contract_hash: &str,
    checked_at: &str,
) -> Result<bool> {
    let checked = OffsetDateTime::parse(checked_at, &Rfc3339).map_err(|_| reject())?;
    let manifest_json: String = transaction
        .query_row(
            "SELECT manifest_json FROM provider_manifest_payloads WHERE registration_id=?1",
            [&selected.registration.registration_id],
            |row| row.get(0),
        )
        .optional()?
        .ok_or_else(reject)?;
    let manifest: aios_contracts::CapabilityManifest = aios_registry::parse_strict_json(
        manifest_json.as_bytes(),
        aios_registry::StrictJsonLimits::default(),
    )
    .map_err(|_| reject())?;
    let mut claims = manifest.provides.iter().filter(|claim| {
        let major = claim.contract.version.split('.').next().unwrap_or("");
        capability == format!("{}@{major}", claim.contract.capability)
            && claim.contract.contract_hash.as_deref() == Some(contract_hash)
    });
    let Some(claim) = claims.next() else {
        return Ok(false);
    };
    if claims.next().is_some() {
        return Ok(false);
    }
    let Some(suite_hash) = claim.conformance.suite_hash.as_deref() else {
        return Ok(false);
    };
    let contract_json: String = transaction
        .query_row(
            "SELECT contract_json FROM semantic_capability_contracts WHERE content_hash=?1",
            [contract_hash],
            |row| row.get(0),
        )
        .optional()?
        .ok_or_else(reject)?;
    let contract: aios_contracts::CapabilityContract = aios_registry::parse_strict_json(
        contract_json.as_bytes(),
        aios_registry::StrictJsonLimits::default(),
    )
    .map_err(|_| reject())?;
    if aios_registry::capability_contract_hash(&contract)
        .map_err(|_| reject())?
        .as_str()
        != contract_hash
    {
        return Ok(false);
    }
    let Some(suite_version) = contract.conformance.suite_version.as_deref() else {
        return Ok(false);
    };
    let mut statement = transaction.prepare(
        "SELECT evidence_id,status,tested_at,evidence_json FROM provider_conformance_evidence
         WHERE registration_id=?1 AND capability=?2 AND contract_hash=?3 AND suite_id=?4 AND suite_hash=?5",
    )?;
    let rows = statement.query_map(
        params![
            selected.registration.registration_id,
            capability,
            contract_hash,
            claim.conformance.suite,
            suite_hash,
        ],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
            ))
        },
    )?;
    let mut latest: Option<(OffsetDateTime, String)> = None;
    let mut selected_payload = None;
    let mut tied = false;
    for row in rows {
        let (id, status, tested_at, payload) = row?;
        let Some(tested_raw) = tested_at else {
            return Ok(false);
        };
        let Ok(parsed_tested_at) = OffsetDateTime::parse(&tested_raw, &Rfc3339) else {
            return Ok(false);
        };
        if parsed_tested_at > checked {
            continue;
        }
        if latest
            .as_ref()
            .is_none_or(|(time, _)| parsed_tested_at > *time)
        {
            latest = Some((parsed_tested_at, id.clone()));
            tied = false;
        } else if latest
            .as_ref()
            .is_some_and(|(time, _)| parsed_tested_at == *time)
        {
            tied = true;
        }
        if id == selected.evidence_id {
            selected_payload = Some((status, tested_raw, payload));
        }
    }
    if tied || latest.as_ref().map(|(_, id)| id.as_str()) != Some(selected.evidence_id.as_str()) {
        return Ok(false);
    }
    let Some((status, tested_at, payload)) = selected_payload else {
        return Ok(false);
    };
    Ok(aios_registry::evidence_matches_binding(
        payload.as_bytes(),
        &aios_registry::EvidenceMatch {
            evidence_id: &selected.evidence_id,
            provider_id: &selected.registration.provider_id,
            provider_version: &selected.registration.provider_version,
            build_hash: &selected.registration.build_hash,
            capability,
            contract_version: &claim.contract.version,
            contract_hash,
            suite_id: &claim.conformance.suite,
            suite_hash,
            suite_version,
            status: &status,
            tested_at: &tested_at,
            evaluated_at: checked_at,
        },
    ))
}

fn replay_existing(
    connection: &Connection,
    request: &ReserveAuthorityCandidate<'_>,
) -> Result<Option<PendingAuthorityCandidate>> {
    let row=connection.query_row(
        "SELECT c.binding_id,c.attempt_id,c.task_id,c.semantic_program_hash,c.registry_snapshot_id,
         c.node_id,c.capability,c.capability_contract_hash,c.provider_registration_id,c.provider_id,
         c.provider_build_hash,c.conformance_evidence_id,c.attempt_number,c.resource_count,s.state
         FROM authority_candidate_reservations c JOIN authority_candidate_status s USING(candidate_id)
         WHERE c.candidate_id=?1",
        [request.candidate_id],|row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,
            row.get::<_,String>(2)?,row.get::<_,String>(3)?,row.get::<_,String>(4)?,
            row.get::<_,String>(5)?,row.get::<_,String>(6)?,row.get::<_,String>(7)?,
            row.get::<_,String>(8)?,row.get::<_,String>(9)?,row.get::<_,String>(10)?,
            row.get::<_,String>(11)?,row.get::<_,i64>(12)?,row.get::<_,i64>(13)?,
            row.get::<_,String>(14)?)),
    ).optional()?;
    let Some(row) = row else { return Ok(None) };
    if row.0 != request.binding_id
        || row.1 != request.attempt_id
        || row.2 != request.task_id
        || row.3 != request.semantic_program_hash
        || row.4 != request.registry_snapshot_id
        || row.5 != request.node_id
        || row.7 != request.capability_contract_hash
        || row.8 != request.provider_registration_id
        || row.12 != i64::from(request.attempt_number)
        || row.13 != i64::try_from(request.resources.len()).map_err(|_| reject())?
        || row.14 != "PENDING"
    {
        return Err(reject());
    }
    let mut statement = connection.prepare(
        "SELECT action,semantic_selector,resource_kind,resource_id,output_port
         FROM authority_candidate_resources WHERE candidate_id=?1",
    )?;
    let stored = statement
        .query_map([request.candidate_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut requested = Vec::with_capacity(request.resources.len());
    for choice in request.resources {
        let (kind, id, port) = match &choice.handle {
            CandidateResourceHandle::InputArtifact { artifact_id } => {
                ("artifact", artifact_id.as_str(), None)
            }
            CandidateResourceHandle::OutputAllocation {
                allocation_id,
                output_port,
            } => (
                "output-allocation",
                allocation_id.as_str(),
                Some(output_port.as_str()),
            ),
        };
        requested.push((
            choice.action.clone(),
            choice.semantic_selector.clone(),
            kind.to_owned(),
            id.to_owned(),
            port.map(str::to_owned),
        ));
    }
    let mut stored = stored;
    stored.sort();
    requested.sort();
    if stored != requested {
        return Err(reject());
    }
    let (profile, isolation, placement): (String, String, String) = connection.query_row(
        "SELECT execution_profile_ref,isolation_class,placement_locality
         FROM authority_candidate_reservations WHERE candidate_id=?1",
        [request.candidate_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if profile != format!("profile:stage1-local:{isolation}") || placement != "local" {
        return Err(reject());
    }
    Ok(Some(PendingAuthorityCandidate {
        candidate_id: request.candidate_id.to_owned(),
        binding_id: row.0,
        attempt_id: row.1,
        task_id: row.2,
        semantic_program_hash: row.3,
        registry_snapshot_id: row.4,
        node_id: row.5,
        capability: row.6,
        provider_registration_id: row.8,
        provider_id: row.9,
        provider_build_hash: row.10,
        conformance_evidence_id: row.11,
        execution_profile_ref: profile,
        isolation_class: isolation,
        placement_locality: "local",
        resource_count: stored.len(),
    }))
}

impl TaskManager {
    /// Reserves identities before policy or grant issuance. The result cannot launch or use Artifacts.
    #[allow(
        clippy::too_many_lines,
        reason = "keeps all pre-policy evidence on one reservation boundary"
    )]
    pub(crate) fn reserve_authority_candidate(
        &mut self,
        request: &ReserveAuthorityCandidate<'_>,
    ) -> Result<PendingAuthorityCandidate> {
        if !valid_id(request.candidate_id)
            || !valid_id(request.binding_id)
            || !valid_id(request.attempt_id)
            || !valid_id(request.task_id)
            || !valid_id(request.provider_registration_id)
            || request.node_id.is_empty()
            || request.node_id.len() > 128
            || !(1..=100).contains(&request.attempt_number)
            || request.resources.is_empty()
            || request.resources.len() > 32
        {
            return Err(reject());
        }
        let replay = {
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            assert_manager_lease(&transaction, &self.lease_owner, self.lease_epoch)?;
            let existing = replay_existing(&transaction, request)?;
            transaction.commit()?;
            existing
        };
        if let Some(existing) = replay {
            return Ok(existing);
        }
        let now = self.clock.now();
        let _ = OffsetDateTime::parse(&now, &Rfc3339).map_err(|_| reject())?;
        // This API is privileged and the provider store's strict candidate path
        // checks registry admission, build, trust, and conformance evidence.
        let (program_json, ir_version): (String, String) = self
            .connection
            .query_row(
                "SELECT p.program_json,p.ir_version FROM tasks t
             JOIN semantic_program_revisions p ON p.task_id=t.task_id
               AND p.program_revision=t.active_program_revision AND p.status='active'
             WHERE t.task_id=?1 AND p.semantic_hash=?2 AND p.registry_snapshot_id=?3
               AND t.state IN ('WAITING_FOR_AUTH','RUNNABLE','RUNNING')",
                params![
                    request.task_id,
                    request.semantic_program_hash,
                    request.registry_snapshot_id
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or_else(reject)?;
        let program: Value = serde_json::from_str(&program_json).map_err(|_| reject())?;
        let node = program_node(&program, request.node_id).ok_or_else(reject)?;
        let capability = node
            .pointer("/operation/capability")
            .and_then(Value::as_str)
            .ok_or_else(reject)?
            .to_owned();
        let candidates = self.provider_store_writer()?.eligible_candidates(
            &capability,
            request.capability_contract_hash,
            request.registry_snapshot_id,
            &now,
        )?;
        let mut eligible = candidates.into_iter().filter(|candidate| {
            candidate.registration.registration_id == request.provider_registration_id
        });
        let candidate = eligible.next().ok_or_else(reject)?;
        if eligible.next().is_some() {
            return Err(reject());
        }
        let lease_owner = self.lease_owner.clone();
        let lease_epoch = self.lease_epoch;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_manager_lease(&tx, &lease_owner, lease_epoch)?;
        if !active_program_validation_valid(&tx, request.task_id, request.semantic_program_hash)? {
            return Err(reject());
        }
        let current: (String, String, Option<String>) = tx
            .query_row(
                "SELECT p.program_json,p.ir_version,t.constraints_json FROM tasks t
             JOIN semantic_program_revisions p ON p.task_id=t.task_id
               AND p.program_revision=t.active_program_revision AND p.status='active'
             WHERE t.task_id=?1 AND p.semantic_hash=?2 AND p.registry_snapshot_id=?3
               AND t.state IN ('WAITING_FOR_AUTH','RUNNABLE','RUNNING')",
                params![
                    request.task_id,
                    request.semantic_program_hash,
                    request.registry_snapshot_id
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
            .ok_or_else(reject)?;
        if current.0 != program_json || current.1 != ir_version {
            return Err(reject());
        }
        let checked_at = self.clock.now();
        let selected_at = OffsetDateTime::parse(&now, &Rfc3339).map_err(|_| reject())?;
        let checked_time = OffsetDateTime::parse(&checked_at, &Rfc3339).map_err(|_| reject())?;
        if checked_time < selected_at
            || !task_constraints_allow_local(current.2.as_deref(), checked_time)
            || node.pointer("/constraints/locality").is_some_and(|value| {
                !value.as_array().is_some_and(|values| {
                    values.iter().any(|value| value.as_str() == Some("local"))
                })
            })
        {
            return Err(reject());
        }
        let (capability_id, major) = capability.rsplit_once('@').ok_or_else(reject)?;
        let major: i64 = major.parse().map_err(|_| reject())?;
        let snapshot_current: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM registry_snapshot_entries e
             JOIN semantic_current_usable_snapshots a ON a.snapshot_id=e.snapshot_id
             WHERE e.snapshot_id=?1 AND a.state='ADMITTED' AND e.contract_class='capability'
               AND e.semantic_id=?2 AND e.major=?3 AND e.content_hash=?4)",
            params![
                request.registry_snapshot_id,
                capability_id,
                major,
                request.capability_contract_hash
            ],
            |row| row.get(0),
        )?;
        if !snapshot_current
            || !evidence_still_current(
                &tx,
                &candidate,
                &capability,
                request.capability_contract_hash,
                &checked_at,
            )?
        {
            return Err(reject());
        }
        let latest:i64=tx.query_row(
            "SELECT MAX(attempt_number) FROM (
                SELECT attempt AS attempt_number FROM execution_bindings WHERE task_id=?1 AND semantic_program_hash=?2 AND node_id=?3
                UNION ALL SELECT attempt_number FROM authority_candidate_reservations WHERE task_id=?1 AND semantic_program_hash=?2 AND node_id=?3
                UNION ALL SELECT attempt_number FROM step_executions WHERE task_id=?1 AND semantic_program_hash=?2 AND node_id=?3)",
            params![request.task_id,request.semantic_program_hash,request.node_id],
            |row| row.get::<_,Option<i64>>(0),
        )?.unwrap_or(0);
        if i64::from(request.attempt_number) != latest + 1 {
            return Err(reject());
        }
        let manifest_json: String = tx
            .query_row(
                "SELECT manifest_json FROM provider_manifest_payloads WHERE registration_id=?1",
                [request.provider_registration_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(reject)?;
        let manifest: aios_contracts::CapabilityManifest = aios_registry::parse_strict_json(
            manifest_json.as_bytes(),
            aios_registry::StrictJsonLimits::default(),
        )
        .map_err(|_| reject())?;
        let manifest_value = aios_registry::parse_strict_value(
            manifest_json.as_bytes(),
            aios_registry::StrictJsonLimits::default(),
        )
        .map_err(|_| reject())?;
        let provides = manifest_value
            .get("provides")
            .and_then(Value::as_array)
            .ok_or_else(reject)?;
        let mut claims = provides.iter().filter(|claim| {
            claim
                .pointer("/contract/capability")
                .and_then(Value::as_str)
                == Some(capability_id)
                && claim
                    .pointer("/contract/contract_hash")
                    .and_then(Value::as_str)
                    == Some(request.capability_contract_hash)
        });
        let claim = claims.next().ok_or_else(reject)?;
        if claims.next().is_some()
            || node.pointer("/egress/mode").and_then(Value::as_str) != Some("deny")
            || claim
                .pointer("/execution/network_default")
                .and_then(Value::as_str)
                != Some("none")
            || !claim
                .pointer("/execution/locality")
                .and_then(Value::as_array)
                .is_some_and(|values| values.iter().any(|value| value.as_str() == Some("local")))
        {
            return Err(reject());
        }
        let isolation = claim
            .pointer("/execution/minimum_isolation")
            .and_then(Value::as_str)
            .ok_or_else(reject)?;
        if !matches!(isolation, "P0" | "P1" | "P2" | "P3" | "P4" | "P5") {
            return Err(reject());
        }
        let profile_ref = format!("profile:stage1-local:{isolation}");
        let (trust, trust_source) = aios_registry::verified_provider_trust_source_at(
            &tx,
            &candidate.registration,
            &manifest,
            &checked_at,
        )
        .map_err(|_| reject())?;
        if !matches!(
            trust,
            aios_registry::ProviderTrustStatus::LocallyTrusted
                | aios_registry::ProviderTrustStatus::ProjectReviewed
                | aios_registry::ProviderTrustStatus::OrganizationApproved
        ) {
            return Err(reject());
        }
        let enabled_at: Option<String> = tx
            .query_row(
                "SELECT updated_at FROM provider_registrations WHERE registration_id=?1",
                [&candidate.registration.registration_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        if enabled_at
            .as_deref()
            .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
            .is_none_or(|enabled| enabled > checked_time)
        {
            return Err(reject());
        }
        let current_epoch: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM provider_registrations r
             JOIN provider_state_epochs e ON e.registration_id=r.registration_id
             WHERE r.registration_id=?1 AND r.state='registered'
               AND e.state='registered' AND e.transitioned_at=r.updated_at
               AND e.revision=(SELECT MAX(revision) FROM provider_state_epochs
                               WHERE registration_id=r.registration_id))",
            [&candidate.registration.registration_id],
            |row| row.get(0),
        )?;
        if !current_epoch {
            return Err(reject());
        }
        let registered:bool=tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM provider_registrations r
             JOIN provider_conformance_evidence e ON e.registration_id=r.registration_id
             WHERE r.registration_id=?1 AND r.provider_id=?2 AND r.provider_version=?3
               AND r.manifest_hash=?4 AND r.package_content_hash=?5 AND r.state='registered'
               AND e.evidence_id=?6 AND e.capability=?7 AND e.contract_hash=?8 AND e.status='pass')",
            params![candidate.registration.registration_id,candidate.registration.provider_id,
                candidate.registration.provider_version,candidate.registration.manifest_hash,
                candidate.registration.build_hash,candidate.evidence_id,capability,request.capability_contract_hash],
            |row| row.get(0))?;
        if !registered {
            return Err(reject());
        }
        let declared = node
            .get("authority_requests")
            .and_then(Value::as_array)
            .ok_or_else(reject)?;
        if declared.len() != request.resources.len() {
            return Err(reject());
        }
        let mut resolved = Vec::new();
        for semantic in declared {
            let action = semantic
                .get("action")
                .and_then(Value::as_str)
                .ok_or_else(reject)?;
            let selector = semantic
                .get("resource")
                .and_then(Value::as_str)
                .ok_or_else(reject)?;
            let mut choices = request
                .resources
                .iter()
                .filter(|choice| choice.action == action && choice.semantic_selector == selector);
            let choice = choices.next().ok_or_else(reject)?;
            if choices.next().is_some()
                || resolved.iter().any(
                    |r: &(String, String, String, String, Option<String>, String)| {
                        r.0 == action && r.1 == selector
                    },
                )
            {
                return Err(reject());
            }
            let (kind, id, port, semantic_type) = match (&choice.handle, action, selector) {
                (
                    CandidateResourceHandle::InputArtifact { artifact_id },
                    "artifact.read",
                    selector,
                ) => {
                    let name = selector.strip_prefix("input:").ok_or_else(reject)?;
                    let expected = program
                        .get("inputs")
                        .and_then(Value::as_object)
                        .and_then(|inputs| inputs.get(name))
                        .and_then(|input| input.get("type"))
                        .and_then(Value::as_str)
                        .ok_or_else(reject)?;
                    let same_type_inputs = program
                        .get("inputs")
                        .and_then(Value::as_object)
                        .ok_or_else(reject)?
                        .values()
                        .filter(|input| input.get("type").and_then(Value::as_str) == Some(expected))
                        .count();
                    let wired = node
                        .get("inputs")
                        .and_then(Value::as_object)
                        .ok_or_else(reject)?
                        .values()
                        .any(|value| {
                            value.get("source").and_then(Value::as_str) == Some("input")
                                && value.get("name").and_then(Value::as_str) == Some(name)
                        });
                    let exact: (i64, Option<String>) = tx.query_row(
                        "SELECT COUNT(*),MIN(CASE WHEN a.integrity_state='verified' THEN a.artifact_id END)
                         FROM task_artifacts ta
                         JOIN artifacts a USING(artifact_id)
                         WHERE ta.task_id=?1 AND ta.role='input'
                           AND a.semantic_type=?2",
                        params![request.task_id, expected],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )?;
                    if !wired
                        || same_type_inputs != 1
                        || exact.0 != 1
                        || exact.1.as_deref() != Some(artifact_id)
                    {
                        return Err(reject());
                    }
                    ("artifact", artifact_id.as_str(), None, expected)
                }
                (
                    CandidateResourceHandle::OutputAllocation {
                        allocation_id,
                        output_port,
                    },
                    "artifact.write",
                    "task.output",
                ) => {
                    let outputs = node
                        .get("outputs")
                        .and_then(Value::as_object)
                        .ok_or_else(reject)?;
                    // A single semantic write request currently covers one exact allocation.
                    if outputs.len() != 1 {
                        return Err(reject());
                    }
                    let expected = outputs
                        .get(output_port)
                        .and_then(Value::as_str)
                        .ok_or_else(reject)?;
                    let exists:bool=tx.query_row(
                        "SELECT EXISTS(SELECT 1 FROM artifact_output_allocations WHERE allocation_id=?1)",
                        [allocation_id],|row| row.get(0))?;
                    if !valid_id(allocation_id) || exists {
                        return Err(reject());
                    }
                    (
                        "output-allocation",
                        allocation_id.as_str(),
                        Some(output_port.clone()),
                        expected,
                    )
                }
                _ => return Err(reject()),
            };
            resolved.push((
                action.to_owned(),
                selector.to_owned(),
                kind.to_owned(),
                id.to_owned(),
                port,
                semantic_type.to_owned(),
            ));
        }
        tx.execute("INSERT INTO authority_candidate_reservations(
            candidate_id,binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,
            ir_version,node_id,capability,capability_contract_hash,provider_registration_id,
            provider_id,provider_version,provider_manifest_hash,provider_build_hash,
            conformance_evidence_id,provider_trust_source_id,execution_profile_ref,isolation_class,
            placement_locality,attempt_number,resource_count,created_at)
            VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23)",
            params![request.candidate_id,request.binding_id,request.attempt_id,request.task_id,
                request.semantic_program_hash,request.registry_snapshot_id,current.1,request.node_id,
                capability,request.capability_contract_hash,candidate.registration.registration_id,
                candidate.registration.provider_id,candidate.registration.provider_version,
                candidate.registration.manifest_hash,candidate.registration.build_hash,
                candidate.evidence_id,trust_source,profile_ref,isolation,"local",
                i64::from(request.attempt_number),i64::try_from(resolved.len()).map_err(|_| reject())?,checked_at])?;
        for (action, selector, kind, id, port, semantic_type) in &resolved {
            tx.execute(
                "INSERT INTO authority_candidate_resources(candidate_id,action,semantic_selector,
                resource_kind,resource_id,output_port,expected_semantic_type)
                VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    request.candidate_id,
                    action,
                    selector,
                    kind,
                    id,
                    port,
                    semantic_type
                ],
            )?;
        }
        tx.execute(
            "INSERT INTO authority_candidate_status(candidate_id,revision,state,updated_at)
            VALUES (?1,1,'PENDING',?2)",
            params![request.candidate_id, checked_at],
        )?;
        tx.commit()?;
        Ok(PendingAuthorityCandidate {
            candidate_id: request.candidate_id.to_owned(),
            binding_id: request.binding_id.to_owned(),
            attempt_id: request.attempt_id.to_owned(),
            task_id: request.task_id.to_owned(),
            semantic_program_hash: request.semantic_program_hash.to_owned(),
            registry_snapshot_id: request.registry_snapshot_id.to_owned(),
            node_id: request.node_id.to_owned(),
            capability,
            provider_registration_id: candidate.registration.registration_id,
            provider_id: candidate.registration.provider_id,
            provider_build_hash: candidate.registration.build_hash,
            conformance_evidence_id: candidate.evidence_id,
            execution_profile_ref: profile_ref,
            isolation_class: isolation.to_owned(),
            placement_locality: "local",
            resource_count: resolved.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Clock, CreateStepExecution, StepState};
    use aios_contracts::{CapabilityContract, RegistrySnapshot, TypeContract};
    use aios_registry::{
        ProviderTrustStatus, RegistryBuildOptions, SemanticRegistry, SnapshotHashEntry,
    };
    use serde_json::json;
    use std::{
        path::Path,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use tempfile::tempdir;

    const NOW: &str = "2026-09-19T00:00:00Z";
    const SUITE: &str = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> String {
            NOW.to_owned()
        }
        fn security_sample(&self) -> Option<crate::SecurityClockSample> {
            Some(crate::trusted_time::synthetic_sample(self.now()))
        }
    }
    struct LaterClock;
    impl Clock for LaterClock {
        fn now(&self) -> String {
            "2026-09-19T02:00:00Z".to_owned()
        }
        fn security_sample(&self) -> Option<crate::SecurityClockSample> {
            Some(crate::trusted_time::synthetic_sample(self.now()))
        }
    }
    struct LockedExpiryClock(AtomicUsize);
    impl Clock for LockedExpiryClock {
        fn now(&self) -> String {
            NOW.to_owned()
        }
        fn security_sample(&self) -> Option<crate::SecurityClockSample> {
            let wall = if self.0.fetch_add(1, Ordering::SeqCst) < 2 {
                NOW
            } else {
                "2026-09-19T02:00:00Z"
            };
            Some(crate::trusted_time::synthetic_sample(wall.to_owned()))
        }
    }

    struct RollbackClock(AtomicUsize);
    impl Clock for RollbackClock {
        fn now(&self) -> String {
            let call = self.0.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                NOW.to_owned()
            } else {
                "2026-09-18T23:59:59Z".to_owned()
            }
        }
        fn security_sample(&self) -> Option<crate::SecurityClockSample> {
            Some(crate::trusted_time::synthetic_sample(self.now()))
        }
    }

    #[test]
    fn reservation_fixture_schema_accepts_pending_and_rejects_invalid_variants() {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../specs/authority-candidate-reservation.schema.json"
        ))
        .unwrap();
        let validator = jsonschema::options()
            .should_validate_formats(true)
            .build(&schema)
            .unwrap();
        let valid: Value = serde_json::from_str(include_str!(
            "../../../examples/authority/candidate-reservation.json"
        ))
        .unwrap();
        assert!(validator.is_valid(&valid));
        let mut missing_port = valid.clone();
        missing_port["resources"][1]
            .as_object_mut()
            .unwrap()
            .remove("output_port");
        assert!(!validator.is_valid(&missing_port));
        let mut premature = valid;
        premature["status"]["state"] = json!("FINALIZED");
        assert!(!validator.is_valid(&premature));
    }

    #[test]
    fn stamped_reservation_guard_tamper_fails_on_disk_reopen() {
        for statement in [
            "DROP TRIGGER authority_candidate_status_exact_insert;",
            "DROP TRIGGER authority_candidate_status_exact_insert;
             CREATE TRIGGER authority_candidate_status_exact_insert BEFORE INSERT ON authority_candidate_status BEGIN SELECT 1; END;",
            "DROP INDEX ux_authority_candidate_output_identity;",
        ] {
            let directory=tempdir().unwrap();
            let path=directory.path().join("candidate.sqlite3");
            let manager=TaskManager::open_with_clock(&path,Box::new(FixedClock)).unwrap();
            manager.connection.execute_batch(statement).unwrap();
            drop(manager);
            assert!(TaskManager::open_with_clock(&path,Box::new(FixedClock)).is_err());
        }
    }

    #[test]
    fn pre_0016_stamped_store_upgrades_without_rewriting_legacy_artifact() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("pre-0016.sqlite3");
        let manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        manager
            .connection
            .execute(
                "INSERT INTO artifacts(artifact_id,uri,semantic_type,media_type,sensitivity,
             origin_kind,integrity_state,created_at) VALUES ('artifact:legacy','artifact://legacy',
             'artifact.file@1','text/plain','local','user','verified',?1)",
                [NOW],
            )
            .unwrap();
        let mut statement = manager
            .connection
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='trigger'
             AND name LIKE 'authority_candidate_%'",
            )
            .unwrap();
        let guards = statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        drop(statement);
        for guard in guards {
            manager
                .connection
                .execute_batch(&format!("DROP TRIGGER \"{}\"", guard.replace('"', "\"\"")))
                .unwrap();
        }
        manager
            .connection
            .execute_batch(
                "DROP TABLE authority_candidate_status;
             DROP TABLE authority_candidate_resources;
             DROP TABLE authority_candidate_reservations;
             DELETE FROM schema_migrations
             WHERE migration_id='0016_authority_candidate_reservations';",
            )
            .unwrap();
        drop(manager);
        let reopened = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        let legacy: (String, String) = reopened
            .connection
            .query_row(
                "SELECT uri,integrity_state FROM artifacts WHERE artifact_id='artifact:legacy'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(legacy, ("artifact://legacy".into(), "verified".into()));
        let candidates: i64 = reopened
            .connection
            .query_row(
                "SELECT COUNT(*) FROM authority_candidate_reservations",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(candidates, 0);
        crate::preflight_migration_state(&reopened.connection).unwrap();
    }

    fn fixture() -> (TaskManager, String, String, String) {
        fixture_at(None)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "builds one complete provider and Task admission fixture"
    )]
    fn fixture_at(path: Option<&Path>) -> (TaskManager, String, String, String) {
        let mut manager = match path {
            Some(path) => TaskManager::open_with_clock(path, Box::new(FixedClock)).unwrap(),
            None => TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap(),
        };
        manager
            .connection
            .execute(
                "INSERT INTO tasks(task_id,revision,state,principal_kind,principal_id,
            original_intent,active_program_revision,constraints_json,created_at,updated_at)
            VALUES ('T-candidate',1,'WAITING_FOR_AUTH','user','user:test','copy source',1,
              '{\"privacy\":\"local-only\",\"max_cost_microunits\":1000,\"preserve_inputs\":true}',?1,?1)",
                [NOW],
            )
            .unwrap();
        let mut snapshot: RegistrySnapshot = serde_json::from_str(include_str!(
            "../../../examples/aios-ir/registry-snapshot.json"
        ))
        .unwrap();
        let types: Vec<TypeContract> = serde_json::from_str(include_str!(
            "../../../examples/aios-ir/type-contracts.json"
        ))
        .unwrap();
        let mut contracts: Vec<CapabilityContract> = serde_json::from_str(include_str!(
            "../../../examples/aios-ir/capability-contracts.json"
        ))
        .unwrap();
        let selected = contracts
            .iter_mut()
            .find(|contract| contract.capability == "artifact.copy")
            .unwrap();
        selected.conformance.suite_hash = Some(SUITE.into());
        let contract_hash = aios_registry::capability_contract_hash(selected)
            .unwrap()
            .to_string();
        snapshot
            .capability_contracts
            .iter_mut()
            .find(|entry| entry.id == "artifact.copy")
            .unwrap()
            .content_hash = contract_hash.clone();
        let view = |entry: &aios_contracts::ContractRef| SnapshotHashEntry {
            id: entry.id.clone(),
            version: entry.version.clone(),
            content_hash: entry.content_hash.clone(),
        };
        snapshot.snapshot_id = aios_registry::registry_snapshot_id(
            &snapshot.schema_version,
            &snapshot.type_contracts.iter().map(view).collect::<Vec<_>>(),
            &snapshot
                .capability_contracts
                .iter()
                .map(view)
                .collect::<Vec<_>>(),
        )
        .unwrap()
        .to_string();
        let registry = SemanticRegistry::from_records(
            snapshot,
            types,
            contracts,
            RegistryBuildOptions::default(),
        )
        .unwrap();
        manager
            .registry_store_writer()
            .unwrap()
            .admit_registry(&registry)
            .unwrap();
        let cases: Value = serde_json::from_str(include_str!(
            "../../../examples/aios-ir/provider-conformance-cases.json"
        ))
        .unwrap();
        let mut manifest = cases[0]["provider"].clone();
        manifest["provides"][0]["contract"]["capability"] = json!("artifact.copy");
        manifest["provides"][0]["contract"]["contract_hash"] = json!(contract_hash);
        manifest["provides"][0]["conformance"]["suite"] = json!("conformance://artifact.copy/1");
        manifest["provides"][0]["conformance"]["suite_hash"] = json!(SUITE);
        manifest["provides"][0]["effect_classes"] = json!(["ARTIFACT_READ", "ARTIFACT_WRITE"]);
        manifest["provides"][0]["authority"]["actions"] =
            json!(["artifact.read", "artifact.write"]);
        let build = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let registration = manager
            .provider_store_writer()
            .unwrap()
            .register(
                &registry,
                &serde_json::to_vec(&manifest).unwrap(),
                build,
                ProviderTrustStatus::LocallyTrusted,
                NOW,
            )
            .unwrap();
        let evidence = json!({
            "schema_version":"0.1","result_id":"evidence-candidate",
            "provider_id":registration.provider_id,"provider_version":registration.provider_version,
            "provider_build_identity":{"kind":"build_hash","value":build},
            "semantic_capability_ref":"artifact.copy@1","semantic_contract_version":"1.0",
            "semantic_contract_hash":contract_hash,
            "conformance_suite":{"id":"conformance://artifact.copy/1","version":"0.1","hash":SUITE},
            "harness":{"id":"fixture-harness","version":"1"},
            "result":"pass","tests_total":1,"tests_passed":1,"tests_failed":0,
            "executed_at":NOW,"expires_at":"2026-09-20T00:00:00Z"
        });
        manager
            .provider_store_writer()
            .unwrap()
            .record_evidence(
                &registration.registration_id,
                &serde_json::to_vec(&evidence).unwrap(),
            )
            .unwrap();
        manager
            .provider_store_writer()
            .unwrap()
            .enable(&registration.registration_id, NOW)
            .unwrap();
        let program = json!({
            "ir_version":"0.1","program_id":"program-candidate","kind":"task_graph",
            "inputs":{"source":{"type":"artifact.file@1"}},
            "nodes":[{"id":"copy","operation":{"kind":"invoke","capability":"artifact.copy@1"},
                "execution_class":"deterministic","inputs":{"source":{"source":"input","name":"source"}},
                "outputs":{"copy":"artifact.file@1"},
                "authority_requests":[{"action":"artifact.read","resource":"input:source"},
                    {"action":"artifact.write","resource":"task.output"}],
                "egress":{"mode":"deny"},"failure":{"on_error":"stop"},"cache":"never"}],
            "outputs":{"copy":{"source":"node","node":"copy","port":"copy"}}
        });
        let program_json = program.to_string();
        let hash = aios_ir::recompute_semantic_hash(program_json.as_bytes()).unwrap();
        let validation = json!({
            "schema_version":"0.1","program_id":"program-candidate","ir_version":"0.1",
            "valid":true,"semantic_hash":hash,"semantic_hash_profile":"aios-ir-v0.1",
            "registry_snapshot_id":registry.snapshot_id(),"validator":{"id":"validator:test","version":"0.1","build_hash":null},
            "diagnostics":[],"diagnostics_truncated":false,"validated_at":NOW
        });
        manager.connection.execute("INSERT INTO validation_results(validation_result_id,task_id,program_id,
            ir_version,valid,semantic_hash,registry_snapshot_id,validator_id,validator_version,result_json,validated_at)
            VALUES ('validation-candidate','T-candidate','program-candidate','0.1',1,?1,?2,'validator:test','0.1',?3,?4)",
            params![hash,registry.snapshot_id(),validation.to_string(),NOW]).unwrap();
        manager.connection.execute("INSERT INTO semantic_program_revisions(task_id,program_revision,program_id,
            ir_version,semantic_hash,registry_snapshot_id,validation_result_id,status,program_json,created_at)
            VALUES ('T-candidate',1,'program-candidate','0.1',?1,?2,'validation-candidate','active',?3,?4)",
            params![hash,registry.snapshot_id(),program_json,NOW]).unwrap();
        manager
            .connection
            .execute(
                "INSERT INTO artifacts(artifact_id,uri,semantic_type,media_type,sensitivity,
            retention_class,origin_kind,integrity_state,created_at) VALUES ('artifact:source','artifact://source',
            'artifact.file@1','text/plain','local','task','user','verified',?1)",
                [NOW],
            )
            .unwrap();
        manager
            .connection
            .execute(
                "INSERT INTO task_artifacts(task_id,artifact_id,role,added_at)
            VALUES ('T-candidate','artifact:source','input',?1)",
                [NOW],
            )
            .unwrap();
        (
            manager,
            hash,
            registry.snapshot_id().to_owned(),
            registration.registration_id,
        )
    }

    fn choices() -> Vec<CandidateResourceChoice> {
        vec![
            CandidateResourceChoice {
                action: "artifact.read".into(),
                semantic_selector: "input:source".into(),
                handle: CandidateResourceHandle::InputArtifact {
                    artifact_id: "artifact:source".into(),
                },
            },
            CandidateResourceChoice {
                action: "artifact.write".into(),
                semantic_selector: "task.output".into(),
                handle: CandidateResourceHandle::OutputAllocation {
                    allocation_id: "allocation:copy".into(),
                    output_port: "copy".into(),
                },
            },
        ]
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "keeps the full approval lifecycle and non-executable assertions together"
    )]
    fn policy_evaluation_approval_replay_and_hard_deny_do_not_issue_authority() {
        use crate::authority_policy::{AuthenticatedApprover, PolicyEffect};
        let (mut manager, hash, snapshot, registration) = fixture();
        let resources = choices();
        let contract = contract_hash(&manager, &snapshot);
        manager
            .reserve_authority_candidate(&ReserveAuthorityCandidate {
                candidate_id: "candidate:policy",
                binding_id: "binding:policy",
                attempt_id: "attempt:policy",
                task_id: "T-candidate",
                semantic_program_hash: &hash,
                registry_snapshot_id: &snapshot,
                node_id: "copy",
                capability_contract_hash: &contract,
                provider_registration_id: &registration,
                attempt_number: 1,
                resources: &resources,
            })
            .unwrap();
        let policy = json!({"schema_version":"0.1","rules":[
            {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"local"},
            {"effect":"REQUIRE_APPROVAL","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"}
        ]});
        let revision = manager
            .activate_local_authority_policy(policy.to_string().as_bytes())
            .unwrap();
        let initial = manager
            .evaluate_pending_authority_candidate("candidate:policy")
            .unwrap();
        for (table, column, schema) in [
            (
                "policy_snapshots",
                "snapshot_json",
                include_str!("../../../specs/policy-snapshot.schema.json"),
            ),
            (
                "authority_requests",
                "request_json",
                include_str!("../../../specs/authority-evaluation-request.schema.json"),
            ),
            (
                "policy_decisions",
                "decision_json",
                include_str!("../../../specs/policy-decision.schema.json"),
            ),
            (
                "approval_requests",
                "request_json",
                include_str!("../../../specs/approval-request.schema.json"),
            ),
        ] {
            let schema: Value = serde_json::from_str(schema).unwrap();
            let validator = jsonschema::options()
                .should_validate_formats(true)
                .build(&schema)
                .unwrap();
            let mut stmt = manager
                .connection
                .prepare(&format!("SELECT {column} FROM {table}"))
                .unwrap();
            let rows = stmt.query_map([], |r| r.get::<_, String>(0)).unwrap();
            for row in rows {
                let value: Value = serde_json::from_str(&row.unwrap()).unwrap();
                assert!(validator.is_valid(&value), "{table}: {value}");
            }
        }
        assert_eq!(initial.activation_revision, revision);
        assert_eq!(
            initial
                .decisions
                .iter()
                .map(|d| d.effect)
                .collect::<Vec<_>>(),
            vec![PolicyEffect::Allow, PolicyEffect::RequireApproval]
        );
        let approval = initial.decisions[1].approval_id.as_deref().unwrap();
        assert_eq!(
            manager
                .evaluate_pending_authority_candidate("candidate:policy")
                .unwrap(),
            initial
        );
        assert!(
            manager
                .decide_candidate_approval(
                    approval,
                    &AuthenticatedApprover {
                        principal_id: "provider:fake"
                    },
                    true
                )
                .is_err()
        );
        manager
            .decide_candidate_approval(
                approval,
                &AuthenticatedApprover {
                    principal_id: "user:test",
                },
                true,
            )
            .unwrap();
        let decision_json: String = manager
            .connection
            .query_row(
                "SELECT decision_json FROM approval_decisions WHERE approval_id=?1",
                [approval],
                |r| r.get(0),
            )
            .unwrap();
        let schema: Value =
            serde_json::from_str(include_str!("../../../specs/approval-decision.schema.json"))
                .unwrap();
        let validator = jsonschema::options()
            .should_validate_formats(true)
            .build(&schema)
            .unwrap();
        assert!(validator.is_valid(&serde_json::from_str::<Value>(&decision_json).unwrap()));
        let approved = manager
            .evaluate_pending_authority_candidate("candidate:policy")
            .unwrap();
        assert_eq!(approved.decisions[1].effect, PolicyEffect::Allow);
        assert_ne!(
            approved.decisions[1].decision_id,
            initial.decisions[1].decision_id
        );
        assert_eq!(
            approved.decisions[1].authority_request_id,
            initial.decisions[1].authority_request_id
        );
        assert_eq!(
            manager
                .evaluate_pending_authority_candidate("candidate:policy")
                .unwrap(),
            approved
        );
        manager
            .connection
            .execute(
                "UPDATE policy_decisions SET principal_id='provider:forged' WHERE decision_id=?1",
                [&approved.decisions[1].decision_id],
            )
            .unwrap();
        assert!(
            manager
                .evaluate_pending_authority_candidate("candidate:policy")
                .is_err()
        );
        let provider_id:String=manager.connection.query_row("SELECT provider_id FROM authority_candidate_reservations WHERE candidate_id='candidate:policy'",[],|r|r.get(0)).unwrap();
        manager
            .connection
            .execute(
                "UPDATE policy_decisions SET principal_id=?1 WHERE decision_id=?2",
                params![provider_id, approved.decisions[1].decision_id],
            )
            .unwrap();
        manager
            .revoke_candidate_approval(
                approval,
                &AuthenticatedApprover {
                    principal_id: "user:test",
                },
            )
            .unwrap();
        assert!(
            manager
                .evaluate_pending_authority_candidate("candidate:policy")
                .is_err()
        );
        let reactivated = manager
            .activate_local_authority_policy(policy.to_string().as_bytes())
            .unwrap();
        assert_eq!(reactivated, revision + 1);
        let fresh = manager
            .evaluate_pending_authority_candidate("candidate:policy")
            .unwrap();
        assert_eq!(fresh.decisions[1].effect, PolicyEffect::RequireApproval);
        assert_ne!(
            fresh.decisions[1].approval_id,
            initial.decisions[1].approval_id
        );
        let denied = json!({"schema_version":"0.1","rules":[
            {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"local"},
            {"effect":"REQUIRE_APPROVAL","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"},
            {"effect":"DENY","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"}
        ]});
        manager
            .activate_local_authority_policy(denied.to_string().as_bytes())
            .unwrap();
        let hard = manager
            .evaluate_pending_authority_candidate("candidate:policy")
            .unwrap();
        assert_eq!(hard.decisions[1].effect, PolicyEffect::Deny);
        assert!(
            manager
                .decide_candidate_approval(
                    approval,
                    &AuthenticatedApprover {
                        principal_id: "user:test"
                    },
                    true
                )
                .is_err()
        );
        for table in [
            "authority_grants",
            "execution_bindings",
            "step_executions",
            "artifact_output_allocations",
        ] {
            let count: i64 = manager
                .connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                .unwrap();
            assert_eq!(count, 0, "{table}");
        }
        let requests: i64 = manager
            .connection
            .query_row("SELECT COUNT(*) FROM authority_requests", [], |r| r.get(0))
            .unwrap();
        assert_eq!(requests, 2);
    }

    #[test]
    fn approval_denial_and_changed_resource_are_fail_closed() {
        use crate::authority_policy::{AuthenticatedApprover, PolicyEffect};
        let (mut manager, hash, snapshot, registration) = fixture();
        let resources = choices();
        let contract = contract_hash(&manager, &snapshot);
        manager
            .reserve_authority_candidate(&ReserveAuthorityCandidate {
                candidate_id: "candidate:stale",
                binding_id: "binding:stale",
                attempt_id: "attempt:stale",
                task_id: "T-candidate",
                semantic_program_hash: &hash,
                registry_snapshot_id: &snapshot,
                node_id: "copy",
                capability_contract_hash: &contract,
                provider_registration_id: &registration,
                attempt_number: 1,
                resources: &resources,
            })
            .unwrap();
        let policy = json!({"schema_version":"0.1","rules":[
            {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"local"},
            {"effect":"REQUIRE_APPROVAL","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"}
        ]});
        manager
            .activate_local_authority_policy(policy.to_string().as_bytes())
            .unwrap();
        let initial = manager
            .evaluate_pending_authority_candidate("candidate:stale")
            .unwrap();
        let approval = initial.decisions[1].approval_id.as_deref().unwrap();
        manager
            .decide_candidate_approval(
                approval,
                &AuthenticatedApprover {
                    principal_id: "user:test",
                },
                false,
            )
            .unwrap();
        let denied = manager
            .evaluate_pending_authority_candidate("candidate:stale")
            .unwrap();
        assert_eq!(denied.decisions[1].effect, PolicyEffect::Deny);
        assert_ne!(
            denied.decisions[1].decision_id,
            initial.decisions[1].decision_id
        );
        assert!(
            manager
                .decide_candidate_approval(
                    approval,
                    &AuthenticatedApprover {
                        principal_id: "user:test"
                    },
                    true
                )
                .is_err()
        );
        manager
            .connection
            .execute(
                "UPDATE artifacts SET sensitivity='private' WHERE artifact_id='artifact:source'",
                [],
            )
            .unwrap();
        assert!(
            manager
                .evaluate_pending_authority_candidate("candidate:stale")
                .is_err()
        );
        assert!(
            manager
                .decide_candidate_approval(
                    approval,
                    &AuthenticatedApprover {
                        principal_id: "user:test"
                    },
                    true
                )
                .is_err()
        );
        assert!(manager.activate_local_authority_policy(br#"{"schema_version":"0.1","rules":[{"effect":"ALLOW","action":"network.send","resource_kind":"artifact","sensitivity":"local"}]}"#).is_err());
        assert!(
            manager
                .activate_local_authority_policy(
                    br#"{"schema_version":"0.1","rules":[],"unexpected":true}"#
                )
                .is_err()
        );
    }

    #[test]
    fn stamped_policy_schema_tamper_fails_on_reopen() {
        for statement in [
            "DROP TRIGGER authority_policy_payload_no_duplicate;",
            "DROP TRIGGER authority_approval_decision_no_duplicate;",
            "DROP TABLE authority_evaluation_fingerprints;",
        ] {
            let directory = tempdir().unwrap();
            let path = directory.path().join("policy.sqlite3");
            let manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
            manager.connection.execute_batch(statement).unwrap();
            drop(manager);
            assert!(TaskManager::open_with_clock(&path, Box::new(FixedClock)).is_err());
        }
    }

    fn remove_0017_schema_for_upgrade_test(manager: &TaskManager) {
        let triggers = manager
            .connection
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='trigger'
            AND (name LIKE 'authority_policy_%' OR name LIKE 'authority_evaluation_%'
              OR name LIKE 'authority_approval_%')",
            )
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        for trigger in triggers {
            manager
                .connection
                .execute_batch(&format!(
                    "DROP TRIGGER \"{}\"",
                    trigger.replace('"', "\"\"")
                ))
                .unwrap();
        }
        manager
            .connection
            .execute_batch(
                "DROP TABLE authority_approval_bindings;
            DROP TABLE authority_evaluation_fingerprints; DROP TABLE authority_policy_activations;
            DROP TABLE authority_policy_payloads;
            DELETE FROM schema_migrations WHERE migration_id='0017_authority_policy_evaluation';",
            )
            .unwrap();
    }

    #[test]
    fn pre_0017_store_upgrades_without_approval_backfill() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("pre-0017.sqlite3");
        let manager = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        remove_0017_schema_for_upgrade_test(&manager);
        drop(manager);
        let reopened = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        crate::preflight_migration_state(&reopened.connection).unwrap();
        let count: i64 = reopened
            .connection
            .query_row(
                "SELECT COUNT(*) FROM authority_approval_bindings",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn legacy_approval_row_survives_upgrade_but_cannot_become_bound() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("legacy-approval.sqlite3");
        let (mut manager, hash, snapshot, registration) = fixture_at(Some(&path));
        let resources = choices();
        let contract = contract_hash(&manager, &snapshot);
        manager
            .reserve_authority_candidate(&ReserveAuthorityCandidate {
                candidate_id: "candidate:upgrade",
                binding_id: "binding:upgrade",
                attempt_id: "attempt:upgrade",
                task_id: "T-candidate",
                semantic_program_hash: &hash,
                registry_snapshot_id: &snapshot,
                node_id: "copy",
                capability_contract_hash: &contract,
                provider_registration_id: &registration,
                attempt_number: 1,
                resources: &resources,
            })
            .unwrap();
        let policy = json!({"schema_version":"0.1","rules":[
            {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"local"},
            {"effect":"REQUIRE_APPROVAL","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"}
        ]});
        manager
            .activate_local_authority_policy(policy.to_string().as_bytes())
            .unwrap();
        let initial = manager
            .evaluate_pending_authority_candidate("candidate:upgrade")
            .unwrap();
        let approval = initial.decisions[1].approval_id.clone().unwrap();
        let requiring_decision = initial.decisions[1].decision_id.clone();
        let fingerprint = initial.decisions[1].evaluation_fingerprint.clone();
        remove_0017_schema_for_upgrade_test(&manager);
        drop(manager);
        let connection = Connection::open(&path).unwrap();
        crate::preflight_migration_state(&connection).unwrap();
        connection
            .execute_batch(include_str!(
                "../../../specs/persistence-v0.1-0017-authority-policy-evaluation.sql"
            ))
            .unwrap();
        connection
            .execute(
                "INSERT INTO schema_migrations(migration_id,checksum,applied_at)
            VALUES ('0017_authority_policy_evaluation','authority-policy-evaluation-v0.1',?1)",
                [NOW],
            )
            .unwrap();
        crate::preflight_migration_state(&connection).unwrap();
        let old: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM approval_requests WHERE approval_id=?1",
                [&approval],
                |r| r.get(0),
            )
            .unwrap();
        let bound: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM authority_approval_bindings WHERE approval_id=?1",
                [&approval],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!((old, bound), (1, 0));
        assert!(
            connection
                .execute(
                    "INSERT INTO authority_approval_bindings(approval_id,candidate_id,
                     fingerprint,activation_revision,requiring_decision_id)
                     VALUES (?1,'candidate:upgrade',?2,1,?3)",
                    params![approval, fingerprint, requiring_decision],
                )
                .is_err()
        );
    }

    fn pending_policy_fixture() -> (TaskManager, String, String) {
        let (mut manager, hash, snapshot, registration) = fixture();
        let resources = choices();
        let contract = contract_hash(&manager, &snapshot);
        manager
            .reserve_authority_candidate(&ReserveAuthorityCandidate {
                candidate_id: "candidate:fresh",
                binding_id: "binding:fresh",
                attempt_id: "attempt:fresh",
                task_id: "T-candidate",
                semantic_program_hash: &hash,
                registry_snapshot_id: &snapshot,
                node_id: "copy",
                capability_contract_hash: &contract,
                provider_registration_id: &registration,
                attempt_number: 1,
                resources: &resources,
            })
            .unwrap();
        manager.activate_local_authority_policy(json!({"schema_version":"0.1","rules":[
            {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"local"},
            {"effect":"REQUIRE_APPROVAL","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"}
        ]}).to_string().as_bytes()).unwrap();
        let evaluation = manager
            .evaluate_pending_authority_candidate("candidate:fresh")
            .unwrap();
        (
            manager,
            evaluation.decisions[1].approval_id.clone().unwrap(),
            registration,
        )
    }

    #[test]
    fn approval_expiry_provider_change_and_forged_status_fail_closed() {
        use crate::authority_policy::AuthenticatedApprover;
        let (mut expired, approval, _) = pending_policy_fixture();
        expired.clock = Arc::new(LaterClock);
        assert!(
            expired
                .decide_candidate_approval(
                    &approval,
                    &AuthenticatedApprover {
                        principal_id: "user:test"
                    },
                    true
                )
                .is_err()
        );
        assert!(
            expired
                .evaluate_pending_authority_candidate("candidate:fresh")
                .is_err()
        );
        let (mut changed, approval, registration) = pending_policy_fixture();
        changed
            .provider_store_writer()
            .unwrap()
            .disable(&registration, NOW)
            .unwrap();
        assert!(
            changed
                .decide_candidate_approval(
                    &approval,
                    &AuthenticatedApprover {
                        principal_id: "user:test"
                    },
                    true
                )
                .is_err()
        );
        assert!(
            changed
                .evaluate_pending_authority_candidate("candidate:fresh")
                .is_err()
        );
        let (mut forged, approval, _) = pending_policy_fixture();
        forged
            .connection
            .execute(
                "UPDATE approval_requests SET status='APPROVED' WHERE approval_id=?1",
                [&approval],
            )
            .unwrap();
        assert!(
            forged
                .evaluate_pending_authority_candidate("candidate:fresh")
                .is_err()
        );
    }

    #[test]
    fn approval_expiry_during_locked_decision_does_not_record_approval() {
        use crate::authority_policy::AuthenticatedApprover;
        let (mut manager, approval, _) = pending_policy_fixture();
        manager.clock = Arc::new(LockedExpiryClock(AtomicUsize::new(0)));
        assert!(
            manager
                .decide_candidate_approval(
                    &approval,
                    &AuthenticatedApprover {
                        principal_id: "user:test"
                    },
                    true,
                )
                .is_err()
        );
        let (status, decisions): (String, i64) = manager
            .connection
            .query_row(
                "SELECT status,(SELECT COUNT(*) FROM approval_decisions WHERE approval_id=?1)
                 FROM approval_requests WHERE approval_id=?1",
                [&approval],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((status.as_str(), decisions), ("PENDING", 0));
        manager.clock = Arc::new(FixedClock);
        assert!(matches!(
            crate::trusted_time::protected_now(&manager.connection, &manager.clock),
            Err(crate::TaskManagerError::InvalidRecord("TIME_UNCERTAIN"))
        ));
    }

    #[test]
    fn valid_new_trust_admission_invalidates_pinned_candidate() {
        use crate::authority_policy::AuthenticatedApprover;
        let (mut manager, approval, registration) = pending_policy_fixture();
        manager
            .provider_store_writer()
            .unwrap()
            .admit_trust(
                &registration,
                "decision:new-trust",
                ProviderTrustStatus::ProjectReviewed,
                "reviewer:test",
                NOW,
            )
            .unwrap();
        assert!(
            manager
                .evaluate_pending_authority_candidate("candidate:fresh")
                .is_err()
        );
        assert!(
            manager
                .decide_candidate_approval(
                    &approval,
                    &AuthenticatedApprover {
                        principal_id: "user:test"
                    },
                    true
                )
                .is_err()
        );
    }

    #[test]
    fn detached_or_replaced_input_and_claimed_output_fail_closed() {
        use crate::authority_policy::AuthenticatedApprover;
        let (mut detached, approval, _) = pending_policy_fixture();
        detached.connection.execute("DELETE FROM task_artifacts WHERE task_id='T-candidate' AND artifact_id='artifact:source'",[]).unwrap();
        assert!(
            detached
                .evaluate_pending_authority_candidate("candidate:fresh")
                .is_err()
        );
        assert!(
            detached
                .decide_candidate_approval(
                    &approval,
                    &AuthenticatedApprover {
                        principal_id: "user:test"
                    },
                    true
                )
                .is_err()
        );
        detached.connection.execute("INSERT INTO artifacts(artifact_id,uri,semantic_type,media_type,sensitivity,
            retention_class,origin_kind,integrity_state,created_at) VALUES ('artifact:replacement','artifact://replacement',
            'artifact.file@1','text/plain','local','task','user','verified',?1)",[NOW]).unwrap();
        detached
            .connection
            .execute(
                "INSERT INTO task_artifacts(task_id,artifact_id,role,added_at)
            VALUES ('T-candidate','artifact:replacement','input',?1)",
                [NOW],
            )
            .unwrap();
        assert!(
            detached
                .evaluate_pending_authority_candidate("candidate:fresh")
                .is_err()
        );

        let (mut claimed, approval, _) = pending_policy_fixture();
        let hash:String=claimed.connection.query_row("SELECT semantic_program_hash FROM authority_candidate_reservations WHERE candidate_id='candidate:fresh'",[],|r|r.get(0)).unwrap();
        assert!(
            claimed
                .connection
                .execute(
                    "INSERT INTO artifact_output_allocations(allocation_id,task_id,
            semantic_program_hash,node_id,sensitivity,retention,state,created_at,expires_at)
            VALUES ('allocation:copy','T-candidate',?1,'copy','private','task','ALLOCATED',?2,?2)",
                    params![hash, NOW]
                )
                .is_err()
        );
        // Simulate a damaged older guard in this disposable store; the
        // coordinator must still reject the now-consumed reservation.
        claimed
            .connection
            .execute_batch("DROP TRIGGER authority_candidate_allocation_insert_guard")
            .unwrap();
        claimed
            .connection
            .execute(
                "INSERT INTO artifact_output_allocations(allocation_id,task_id,
            semantic_program_hash,node_id,sensitivity,retention,state,created_at,expires_at)
            VALUES ('allocation:copy','T-candidate',?1,'copy','private','task','ALLOCATED',?2,?2)",
                params![hash, NOW],
            )
            .unwrap();
        assert!(
            claimed
                .evaluate_pending_authority_candidate("candidate:fresh")
                .is_err()
        );
        assert!(
            claimed
                .decide_candidate_approval(
                    &approval,
                    &AuthenticatedApprover {
                        principal_id: "user:test"
                    },
                    true
                )
                .is_err()
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "checks one durable approval ledger against replacement and legacy backfill"
    )]
    fn bound_approval_rows_and_evaluation_sidecars_reject_replacement() {
        let (mut manager, approval, _) = pending_policy_fixture();
        assert!(
            manager
                .connection
                .execute(
                    "UPDATE approval_requests SET request_json='{}'
            WHERE approval_id=?1",
                    [&approval]
                )
                .is_err()
        );
        assert!(
            manager
                .connection
                .execute(
                    "UPDATE approval_requests SET action='artifact.read'
            WHERE approval_id=?1",
                    [&approval]
                )
                .is_err()
        );
        assert!(
            manager
                .connection
                .execute(
                    "INSERT OR REPLACE INTO approval_requests
            SELECT * FROM approval_requests WHERE approval_id=?1",
                    [&approval]
                )
                .is_err()
        );
        assert!(
            manager
                .connection
                .execute(
                    "INSERT OR REPLACE INTO authority_approval_bindings
            SELECT * FROM authority_approval_bindings WHERE approval_id=?1",
                    [&approval]
                )
                .is_err()
        );
        let decision: String = manager
            .connection
            .query_row(
                "SELECT requiring_decision_id FROM authority_approval_bindings
            WHERE approval_id=?1",
                [&approval],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            manager
                .connection
                .execute(
                    "INSERT OR REPLACE INTO authority_evaluation_fingerprints
            SELECT * FROM authority_evaluation_fingerprints WHERE decision_id=?1",
                    [&decision]
                )
                .is_err()
        );
        // A legacy approval row has no 0017 requiring decision/fingerprint.
        let request: String = manager
            .connection
            .query_row(
                "SELECT authority_request_id FROM approval_requests
            WHERE approval_id=?1",
                [&approval],
                |r| r.get(0),
            )
            .unwrap();
        let hash: String = manager
            .connection
            .query_row(
                "SELECT semantic_program_hash FROM authority_candidate_reservations
            WHERE candidate_id='candidate:fresh'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        manager.connection.execute("INSERT INTO approval_requests(approval_id,authority_request_id,task_id,
            semantic_program_hash,node_id,action,status,request_json,created_at,expires_at)
            VALUES ('approval:legacy',?1,'T-candidate',?2,'copy','artifact.write','PENDING','{}',?3,?4)",
            params![request,hash,NOW,"2026-09-19T01:00:00Z"]).unwrap();
        let fingerprint: String = manager
            .connection
            .query_row(
                "SELECT fingerprint FROM authority_approval_bindings
            WHERE approval_id=?1",
                [&approval],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            manager
                .connection
                .execute(
                    "INSERT INTO authority_approval_bindings(approval_id,candidate_id,
            fingerprint,activation_revision,requiring_decision_id)
            VALUES ('approval:legacy','candidate:fresh',?1,1,?2)",
                    params![fingerprint, decision]
                )
                .is_err()
        );
        manager
            .connection
            .execute_batch("DROP TRIGGER authority_evaluation_no_delete")
            .unwrap();
        manager
            .connection
            .execute(
                "DELETE FROM authority_evaluation_fingerprints WHERE decision_id=?1",
                [&decision],
            )
            .unwrap();
        assert!(
            manager
                .evaluate_pending_authority_candidate("candidate:fresh")
                .is_err()
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "checks the same sealed decision across all mutable columns and approval states"
    )]
    fn original_requiring_decision_must_remain_exact_before_and_after_approval() {
        use crate::authority_policy::AuthenticatedApprover;
        let (mut manager, approval, _) = pending_policy_fixture();
        let decision: String = manager
            .connection
            .query_row(
                "SELECT requiring_decision_id FROM authority_approval_bindings WHERE approval_id=?1",
                [&approval],
                |r| r.get(0),
            )
            .unwrap();
        manager
            .connection
            .execute(
                "INSERT INTO policy_snapshots
             SELECT 'forged',scope_kind,scope_id,policy_language,policy_language_version,
                    policy_set_hash,entity_schema_hash,configuration_hash,engine_id,
                    engine_version,snapshot_json,created_at
             FROM policy_snapshots WHERE snapshot_id=(SELECT policy_snapshot_id
             FROM policy_decisions WHERE decision_id=?1)",
                [&decision],
            )
            .unwrap();
        for column in [
            "principal_kind",
            "principal_id",
            "resolved_resource_kind",
            "resolved_resource_id",
            "policy_snapshot_id",
            "reason_codes_json",
            "decision_json",
            "decided_at",
        ] {
            let original: String = manager
                .connection
                .query_row(
                    &format!("SELECT {column} FROM policy_decisions WHERE decision_id=?1"),
                    [&decision],
                    |r| r.get(0),
                )
                .unwrap();
            manager
                .connection
                .execute(
                    &format!("UPDATE policy_decisions SET {column}='forged' WHERE decision_id=?1"),
                    [&decision],
                )
                .unwrap();
            assert!(
                manager
                    .decide_candidate_approval(
                        &approval,
                        &AuthenticatedApprover {
                            principal_id: "user:test",
                        },
                        true,
                    )
                    .is_err(),
                "approval accepted forged {column}"
            );
            assert!(
                manager
                    .evaluate_pending_authority_candidate("candidate:fresh")
                    .is_err(),
                "evaluation accepted forged {column}"
            );
            manager
                .connection
                .execute(
                    &format!("UPDATE policy_decisions SET {column}=?1 WHERE decision_id=?2"),
                    params![original, decision],
                )
                .unwrap();
        }
        manager
            .decide_candidate_approval(
                &approval,
                &AuthenticatedApprover {
                    principal_id: "user:test",
                },
                true,
            )
            .unwrap();
        manager
            .connection
            .execute(
                "UPDATE policy_decisions SET decision_json='{}' WHERE decision_id=?1",
                [&decision],
            )
            .unwrap();
        assert!(
            manager
                .evaluate_pending_authority_candidate("candidate:fresh")
                .is_err()
        );

        let (mut denied, denied_approval, _) = pending_policy_fixture();
        denied
            .decide_candidate_approval(
                &denied_approval,
                &AuthenticatedApprover {
                    principal_id: "user:test",
                },
                false,
            )
            .unwrap();
        denied
            .connection
            .execute(
                "UPDATE policy_decisions SET reason_codes_json='[]'
                 WHERE decision_id=(SELECT requiring_decision_id FROM authority_approval_bindings
                 WHERE approval_id=?1)",
                [&denied_approval],
            )
            .unwrap();
        assert!(
            denied
                .evaluate_pending_authority_candidate("candidate:fresh")
                .is_err()
        );
    }

    #[test]
    fn bound_approval_decision_rejects_replace_even_when_new_target_is_unbound() {
        use crate::authority_policy::AuthenticatedApprover;
        let (mut manager, approval, _) = pending_policy_fixture();
        manager
            .decide_candidate_approval(
                &approval,
                &AuthenticatedApprover {
                    principal_id: "user:test",
                },
                true,
            )
            .unwrap();
        let decision_id: String = manager
            .connection
            .query_row(
                "SELECT decision_id FROM approval_decisions WHERE approval_id=?1",
                [&approval],
                |r| r.get(0),
            )
            .unwrap();
        let original: (String, String, String) = manager.connection.query_row(
            "SELECT approval_id,decision_json,decided_at FROM approval_decisions WHERE decision_id=?1",
            [&decision_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).unwrap();
        let recursive_triggers: i64 = manager
            .connection
            .query_row("PRAGMA recursive_triggers", [], |r| r.get(0))
            .unwrap();
        assert_eq!(recursive_triggers, 0);
        assert!(
            manager
                .connection
                .execute(
                    "INSERT OR REPLACE INTO approval_decisions
                     SELECT * FROM approval_decisions WHERE decision_id=?1",
                    [&decision_id],
                )
                .is_err()
        );
        assert!(
            manager
                .connection
                .execute(
                    "INSERT OR REPLACE INTO approval_decisions
             SELECT decision_id,approval_id,task_id,decision,decided_by_kind,decided_by_id,
                    scope,approved_until,'{}','2026-09-19T02:00:00Z'
             FROM approval_decisions WHERE decision_id=?1",
                    [&decision_id],
                )
                .is_err()
        );
        manager
            .connection
            .execute(
                "INSERT INTO approval_requests(approval_id,authority_request_id,task_id,
             semantic_program_hash,node_id,action,status,request_json,created_at,expires_at)
             SELECT 'approval:unbound',authority_request_id,task_id,semantic_program_hash,
                    node_id,action,'PENDING',request_json,created_at,expires_at
             FROM approval_requests WHERE approval_id=?1",
                [&approval],
            )
            .unwrap();
        assert!(
            manager
                .connection
                .execute(
                    "INSERT OR REPLACE INTO approval_decisions
             SELECT decision_id,'approval:unbound',task_id,decision,decided_by_kind,decided_by_id,
                    scope,approved_until,decision_json,decided_at
             FROM approval_decisions WHERE decision_id=?1",
                    [&decision_id],
                )
                .is_err()
        );
        let row: (String, String, String) = manager.connection.query_row(
            "SELECT approval_id,decision_json,decided_at FROM approval_decisions WHERE decision_id=?1",
            [&decision_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).unwrap();
        assert_eq!(row, original);
        assert!(
            manager
                .evaluate_pending_authority_candidate("candidate:fresh")
                .is_ok()
        );
    }

    #[test]
    fn reserves_read_and_write_without_binding_or_grant_and_replays_exactly() {
        let (mut manager, hash, snapshot, registration) = fixture();
        let resources = choices();
        let request = ReserveAuthorityCandidate {
            candidate_id: "candidate:one",
            binding_id: "binding:one",
            attempt_id: "attempt:one",
            task_id: "T-candidate",
            semantic_program_hash: &hash,
            registry_snapshot_id: &snapshot,
            node_id: "copy",
            capability_contract_hash: &contract_hash(&manager, &snapshot),
            provider_registration_id: &registration,
            attempt_number: 1,
            resources: &resources,
        };
        let candidate = manager.reserve_authority_candidate(&request).unwrap();
        assert_eq!(candidate.resource_count, 2);
        assert_eq!(
            manager.reserve_authority_candidate(&request).unwrap(),
            candidate
        );
        let colliding_output = ReserveAuthorityCandidate {
            candidate_id: "candidate:two",
            binding_id: "binding:two",
            attempt_id: "attempt:two",
            attempt_number: 2,
            ..request
        };
        assert!(
            manager
                .reserve_authority_candidate(&colliding_output)
                .is_err()
        );
        let candidate_count: i64 = manager
            .connection
            .query_row(
                "SELECT COUNT(*) FROM authority_candidate_reservations",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(candidate_count, 1);
        for table in [
            "execution_bindings",
            "step_executions",
            "authority_grants",
            "artifact_output_allocations",
        ] {
            let count: i64 = manager
                .connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "{table}");
        }
        let mut changed = resources.clone();
        changed[0].handle = CandidateResourceHandle::InputArtifact {
            artifact_id: "artifact:alternate".into(),
        };
        let changed_request = ReserveAuthorityCandidate {
            resources: &changed,
            ..request
        };
        assert!(
            manager
                .reserve_authority_candidate(&changed_request)
                .is_err()
        );
    }

    #[test]
    fn disk_reopen_replays_pending_but_terminal_state_and_identity_reuse_fail() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("candidate.sqlite3");
        let (mut manager, hash, snapshot, registration) = fixture_at(Some(&path));
        let resources = choices();
        let contract = contract_hash(&manager, &snapshot);
        let request = ReserveAuthorityCandidate {
            candidate_id: "candidate:reopen",
            binding_id: "binding:reopen",
            attempt_id: "attempt:reopen",
            task_id: "T-candidate",
            semantic_program_hash: &hash,
            registry_snapshot_id: &snapshot,
            node_id: "copy",
            capability_contract_hash: &contract,
            provider_registration_id: &registration,
            attempt_number: 1,
            resources: &resources,
        };
        let expected = manager.reserve_authority_candidate(&request).unwrap();
        drop(manager);
        let reopened = Connection::open(&path).unwrap();
        crate::preflight_migration_state(&reopened).unwrap();
        assert_eq!(
            replay_existing(&reopened, &request).unwrap(),
            Some(expected)
        );
        assert!(reopened.execute(
            "UPDATE authority_candidate_status SET state='FINALIZED',revision=2 WHERE candidate_id=?1",
            [request.candidate_id],
        ).is_err());
        reopened.execute(
            "UPDATE authority_candidate_status SET state='STALE',revision=2 WHERE candidate_id=?1",
            [request.candidate_id],
        ).unwrap();
        assert!(replay_existing(&reopened, &request).is_err());
        let reused = ReserveAuthorityCandidate {
            candidate_id: "candidate:reused",
            attempt_number: 2,
            ..request
        };
        assert!(reopened.execute(
            "UPDATE authority_candidate_reservations SET binding_id=?1 WHERE candidate_id=?2",
            params![reused.binding_id, request.candidate_id],
        ).is_err());
    }

    #[test]
    fn ambiguous_input_and_existing_allocation_fail_closed() {
        let (mut manager, hash, snapshot, registration) = fixture();
        let resources = choices();
        let contract = contract_hash(&manager, &snapshot);
        let request = ReserveAuthorityCandidate {
            candidate_id: "candidate:ambiguous",
            binding_id: "binding:ambiguous",
            attempt_id: "attempt:ambiguous",
            task_id: "T-candidate",
            semantic_program_hash: &hash,
            registry_snapshot_id: &snapshot,
            node_id: "copy",
            capability_contract_hash: &contract,
            provider_registration_id: &registration,
            attempt_number: 1,
            resources: &resources,
        };
        manager.connection.execute(
            "INSERT INTO artifacts(artifact_id,uri,semantic_type,media_type,sensitivity,
             origin_kind,integrity_state,created_at) VALUES ('artifact:alternate','artifact://alternate',
             'artifact.file@1','text/plain','local','user','verified',?1)", [NOW],
        ).unwrap();
        manager
            .connection
            .execute(
                "INSERT INTO task_artifacts(task_id,artifact_id,role,added_at)
             VALUES ('T-candidate','artifact:alternate','input',?1)",
                [NOW],
            )
            .unwrap();
        assert!(manager.reserve_authority_candidate(&request).is_err());
        manager.connection.execute(
            "UPDATE artifacts SET integrity_state='pending' WHERE artifact_id='artifact:alternate'",
            [],
        ).unwrap();
        assert!(manager.reserve_authority_candidate(&request).is_err());
        manager
            .connection
            .execute(
                "DELETE FROM task_artifacts WHERE artifact_id='artifact:alternate'",
                [],
            )
            .unwrap();
        manager.connection.execute(
            "INSERT INTO artifact_output_allocations(allocation_id,task_id,semantic_program_hash,
             node_id,sensitivity,retention,state,created_at,expires_at)
             VALUES ('allocation:copy','T-candidate',?1,'copy','local','task','ALLOCATED',?2,?2)",
            params![hash,NOW],
        ).unwrap();
        assert!(manager.reserve_authority_candidate(&request).is_err());
    }

    #[test]
    fn incomplete_resource_set_cannot_be_sealed_or_reuse_binding_identity() {
        let (mut manager, hash, snapshot, registration) = fixture();
        let resources = choices();
        let contract = contract_hash(&manager, &snapshot);
        let request = ReserveAuthorityCandidate {
            candidate_id: "candidate:complete",
            binding_id: "binding:complete",
            attempt_id: "attempt:complete",
            task_id: "T-candidate",
            semantic_program_hash: &hash,
            registry_snapshot_id: &snapshot,
            node_id: "copy",
            capability_contract_hash: &contract,
            provider_registration_id: &registration,
            attempt_number: 1,
            resources: &resources,
        };
        manager.reserve_authority_candidate(&request).unwrap();
        let clone_sql = "INSERT INTO authority_candidate_reservations SELECT
            ?1,?2,?3,task_id,semantic_program_hash,registry_snapshot_id,ir_version,node_id,
            capability,capability_contract_hash,provider_registration_id,provider_id,
            provider_version,provider_manifest_hash,provider_build_hash,conformance_evidence_id,
            provider_trust_source_id,execution_profile_ref,isolation_class,placement_locality,
            attempt_number+1,resource_count,created_at
            FROM authority_candidate_reservations WHERE candidate_id='candidate:complete'";
        assert!(
            manager
                .connection
                .execute(
                    clone_sql,
                    params!["candidate:reused", "binding:complete", "attempt:other"],
                )
                .is_err()
        );
        manager
            .connection
            .execute(
                clone_sql,
                params!["candidate:partial", "binding:partial", "attempt:partial"],
            )
            .unwrap();
        let seal = "INSERT INTO authority_candidate_status(candidate_id,revision,state,updated_at)
            VALUES ('candidate:partial',1,'PENDING',?1)";
        assert!(manager.connection.execute(seal, [NOW]).is_err());
        manager
            .connection
            .execute(
                "INSERT INTO authority_candidate_resources SELECT 'candidate:partial',action,
             semantic_selector,resource_kind,resource_id,output_port,expected_semantic_type
             FROM authority_candidate_resources WHERE candidate_id='candidate:complete'
             AND action='artifact.read'",
                [],
            )
            .unwrap();
        assert!(manager.connection.execute(seal, [NOW]).is_err());
        manager
            .connection
            .execute_batch("PRAGMA recursive_triggers=OFF")
            .unwrap();
        let header_replacement = manager
            .connection
            .execute(
                "INSERT OR REPLACE INTO authority_candidate_reservations SELECT *
             FROM authority_candidate_reservations WHERE candidate_id='candidate:partial'",
                [],
            )
            .unwrap_err();
        assert!(
            header_replacement
                .to_string()
                .contains("reservation already exists")
        );
        let status_replacement = manager
            .connection
            .execute(
                "INSERT OR REPLACE INTO authority_candidate_status SELECT *
             FROM authority_candidate_status WHERE candidate_id='candidate:complete'",
                [],
            )
            .unwrap_err();
        assert!(
            status_replacement
                .to_string()
                .contains("status already exists")
        );
        let replacement = manager
            .connection
            .execute(
                "INSERT OR REPLACE INTO authority_candidate_resources SELECT *
             FROM authority_candidate_resources WHERE candidate_id='candidate:partial'",
                [],
            )
            .unwrap_err();
        assert!(replacement.to_string().contains("resource already exists"));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "exercises the complete reserved identity collision and finalization order"
    )]
    fn pending_reservation_blocks_step_binding_and_allocation_identity_theft() {
        let (mut manager, hash, snapshot, registration) = fixture();
        let resources = choices();
        let contract = contract_hash(&manager, &snapshot);
        let request = ReserveAuthorityCandidate {
            candidate_id: "candidate:guard",
            binding_id: "binding:guard",
            attempt_id: "attempt:guard",
            task_id: "T-candidate",
            semantic_program_hash: &hash,
            registry_snapshot_id: &snapshot,
            node_id: "copy",
            capability_contract_hash: &contract,
            provider_registration_id: &registration,
            attempt_number: 1,
            resources: &resources,
        };
        manager.reserve_authority_candidate(&request).unwrap();
        let unbound = CreateStepExecution {
            attempt_id: request.attempt_id.into(),
            task_id: request.task_id.into(),
            semantic_program_hash: hash.clone(),
            registry_snapshot_id: Some(snapshot.clone()),
            node_id: request.node_id.into(),
            binding_id: None,
            provider_id: None,
            provider_version: None,
            attempt_number: 1,
            state: StepState::Pending,
            operation_id: None,
            idempotency_key: None,
            outcome_certainty: None,
            input_artifacts: vec![],
            output_artifacts: vec![],
            failure: None,
            started_at: None,
            finished_at: None,
        };
        assert!(manager.create_step_execution(&unbound).is_err());
        let alternate_attempt = CreateStepExecution {
            attempt_id: "attempt:alternate".into(),
            ..unbound
        };
        assert!(manager.create_step_execution(&alternate_attempt).is_err());
        let unrelated_step = CreateStepExecution {
            attempt_number: 2,
            ..alternate_attempt
        };
        manager.create_step_execution(&unrelated_step).unwrap();
        let step_update_error = manager
            .connection
            .execute(
                "UPDATE step_executions SET attempt_id='attempt:guard',attempt_number=1
             WHERE attempt_id='attempt:alternate'",
                [],
            )
            .unwrap_err();
        assert!(
            step_update_error
                .to_string()
                .contains("reserved authority candidate")
        );
        manager.connection.execute(
            "INSERT INTO artifact_output_allocations(allocation_id,task_id,semantic_program_hash,
             node_id,sensitivity,retention,state,created_at,expires_at)
             VALUES ('allocation:unrelated','T-candidate',?1,'copy','local','task','ALLOCATED',?2,?2)",
            params![hash,NOW],
        ).unwrap();
        let allocation_update_error = manager
            .connection
            .execute(
                "UPDATE artifact_output_allocations SET allocation_id='allocation:copy'
             WHERE allocation_id='allocation:unrelated'",
                [],
            )
            .unwrap_err();
        assert!(
            allocation_update_error
                .to_string()
                .contains("reserved authority candidate")
        );
        // Isolate the new collision trigger from older admission triggers in
        // this disposable in-memory fixture; the production database keeps all.
        let other_binding_guards = manager.connection.prepare(
            "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='execution_bindings'
             AND name<>'authority_candidate_binding_insert_guard'"
        ).unwrap().query_map([], |row| row.get::<_, String>(0)).unwrap()
            .collect::<std::result::Result<Vec<_>, _>>().unwrap();
        for name in other_binding_guards {
            manager
                .connection
                .execute_batch(&format!("DROP TRIGGER \"{}\"", name.replace('"', "\"\"")))
                .unwrap();
        }
        let binding_error = manager.connection.execute(
            "INSERT INTO execution_bindings(binding_id,attempt_id,task_id,semantic_program_hash,
             registry_snapshot_id,ir_version,node_id,capability,provider_id,provider_version,
             attempt,policy_decision_refs_json,grant_refs_json,execution_profile_ref,placement_json,
             binding_json,created_at) VALUES (?1,'attempt:stolen','T-candidate',?2,?3,'0.1',
             'copy','artifact.copy@1','provider:stolen','1.0',1,'[]','[]','profile:stolen',
             '{}','{}',?4)",
            params![request.binding_id,hash,snapshot,NOW],
        ).unwrap_err();
        assert!(
            binding_error
                .to_string()
                .contains("reserved authority candidate"),
            "{binding_error}"
        );
        let allocation_error = manager.connection.execute(
            "INSERT INTO artifact_output_allocations(allocation_id,task_id,semantic_program_hash,
             node_id,sensitivity,retention,state,created_at,expires_at)
             VALUES ('allocation:copy','T-candidate',?1,'copy','local','task','ALLOCATED',?2,?2)",
            params![hash,NOW],
        ).unwrap_err();
        assert!(
            allocation_error
                .to_string()
                .contains("reserved authority candidate")
        );
        let insert_exact_shape = "INSERT INTO execution_bindings(
            binding_id,attempt_id,task_id,semantic_program_hash,registry_snapshot_id,ir_version,
            node_id,capability,capability_contract_hash,provider_registration_id,provider_id,
            provider_version,provider_manifest_hash,provider_build_hash,attempt,
            policy_decision_refs_json,grant_refs_json,execution_profile_ref,placement_json,
            binding_json,created_at)
            SELECT c.binding_id,c.attempt_id,c.task_id,c.semantic_program_hash,c.registry_snapshot_id,
              c.ir_version,c.node_id,c.capability,c.capability_contract_hash,
              c.provider_registration_id,c.provider_id,c.provider_version,c.provider_manifest_hash,
              c.provider_build_hash,c.attempt_number,'[]','[]',c.execution_profile_ref,?1,
              json_object('conformance_evidence_id',?2,
                          'provider_trust_source_id',c.provider_trust_source_id),c.created_at
            FROM authority_candidate_reservations c WHERE c.candidate_id='candidate:guard'";
        for (placement, evidence) in [
            ("{\"locality\":\"local\"}", "evidence:wrong"),
            ("{\"locality\":\"remote\"}", "evidence-candidate"),
        ] {
            let error = manager
                .connection
                .execute(insert_exact_shape, params![placement, evidence])
                .unwrap_err();
            assert!(
                error.to_string().contains("reserved authority candidate"),
                "{error}"
            );
        }
        // The exact reserved binding shape is allowed by this collision guard;
        // the older admission guards, removed above only for this test, enforce
        // the complete receipt and issued authority in production.
        manager
            .connection
            .execute(
                insert_exact_shape,
                params!["{\"locality\":\"local\"}", "evidence-candidate"],
            )
            .unwrap();
        let finalize = "UPDATE authority_candidate_status SET state='FINALIZED',revision=2
            WHERE candidate_id='candidate:guard'";
        assert!(manager.connection.execute(finalize, []).is_err());
        manager.connection.execute(
            "INSERT INTO artifact_output_allocations(allocation_id,task_id,semantic_program_hash,
             node_id,binding_id,attempt_id,output_port,expected_semantic_type,
             sensitivity,retention,state,created_at,expires_at)
             VALUES ('allocation:copy','T-candidate',?1,'copy','binding:guard','attempt:guard',
             'copy','artifact.file@1','local','task','ALLOCATED',?2,?2)",
            params![hash,NOW],
        ).unwrap();
        assert!(manager.connection.execute(finalize, []).is_err());
        let provider_version: String = manager
            .connection
            .query_row(
                "SELECT provider_version FROM authority_candidate_reservations
             WHERE candidate_id='candidate:guard'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let provider_id: String = manager
            .connection
            .query_row(
                "SELECT provider_id FROM authority_candidate_reservations
             WHERE candidate_id='candidate:guard'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let bound_step = CreateStepExecution {
            attempt_id: request.attempt_id.into(),
            task_id: request.task_id.into(),
            semantic_program_hash: hash.clone(),
            registry_snapshot_id: Some(snapshot.clone()),
            node_id: request.node_id.into(),
            binding_id: Some(request.binding_id.into()),
            provider_id: Some(provider_id),
            provider_version: Some(provider_version),
            attempt_number: 1,
            state: StepState::Pending,
            operation_id: None,
            idempotency_key: None,
            outcome_certainty: None,
            input_artifacts: vec![],
            output_artifacts: vec![],
            failure: None,
            started_at: None,
            finished_at: None,
        };
        manager.create_step_execution(&bound_step).unwrap();
        manager
            .connection
            .execute_batch("PRAGMA recursive_triggers=OFF")
            .unwrap();
        let step_replace = manager
            .connection
            .execute(
                "INSERT OR REPLACE INTO step_executions SELECT * FROM step_executions
             WHERE attempt_id='attempt:guard'",
                [],
            )
            .unwrap_err();
        assert!(
            step_replace
                .to_string()
                .contains("reserved authority candidate")
        );
        let allocation_replace = manager
            .connection
            .execute(
                "INSERT OR REPLACE INTO artifact_output_allocations SELECT *
             FROM artifact_output_allocations WHERE allocation_id='allocation:copy'",
                [],
            )
            .unwrap_err();
        assert!(
            allocation_replace
                .to_string()
                .contains("reserved authority candidate")
        );
        manager.connection.execute(finalize, []).unwrap();
        let step_update_away = manager
            .connection
            .execute(
                "UPDATE step_executions SET attempt_id='attempt:away'
             WHERE attempt_id='attempt:guard'",
                [],
            )
            .unwrap_err();
        assert!(
            step_update_away
                .to_string()
                .contains("reserved authority candidate")
        );
        let allocation_update_away = manager
            .connection
            .execute(
                "UPDATE artifact_output_allocations SET allocation_id='allocation:away'
             WHERE allocation_id='allocation:copy'",
                [],
            )
            .unwrap_err();
        assert!(
            allocation_update_away
                .to_string()
                .contains("reserved authority candidate")
        );
        assert!(
            manager
                .connection
                .execute(
                    "DELETE FROM step_executions WHERE attempt_id='attempt:guard'",
                    [],
                )
                .unwrap_err()
                .to_string()
                .contains("durable")
        );
        assert!(
            manager
                .connection
                .execute(
                    "DELETE FROM artifact_output_allocations WHERE allocation_id='allocation:copy'",
                    [],
                )
                .unwrap_err()
                .to_string()
                .contains("durable")
        );
        assert!(
            manager
                .connection
                .execute(
                    "INSERT OR REPLACE INTO authority_candidate_reservations SELECT *
             FROM authority_candidate_reservations WHERE candidate_id='candidate:guard'",
                    [],
                )
                .is_err()
        );
        assert!(manager.connection.execute(
            "INSERT OR REPLACE INTO authority_candidate_status(candidate_id,revision,state,updated_at)
             VALUES ('candidate:guard',1,'PENDING',?1)", [NOW],
        ).unwrap_err().to_string().contains("status already exists"));
        manager
            .connection
            .execute(
                "UPDATE step_executions SET state='BLOCKED' WHERE attempt_id='attempt:guard'",
                [],
            )
            .unwrap();
    }

    #[test]
    fn unrequested_action_wrong_pins_and_alternate_artifact_fail_closed() {
        let (mut manager, hash, snapshot, registration) = fixture();
        let resources = choices();
        let contract = contract_hash(&manager, &snapshot);
        let request = ReserveAuthorityCandidate {
            candidate_id: "candidate:mismatch",
            binding_id: "binding:mismatch",
            attempt_id: "attempt:mismatch",
            task_id: "T-candidate",
            semantic_program_hash: &hash,
            registry_snapshot_id: &snapshot,
            node_id: "copy",
            capability_contract_hash: &contract,
            provider_registration_id: &registration,
            attempt_number: 1,
            resources: &resources,
        };
        assert!(
            manager
                .reserve_authority_candidate(&ReserveAuthorityCandidate {
                    task_id: "T-other",
                    ..request
                })
                .is_err()
        );
        assert!(
            manager
                .reserve_authority_candidate(&ReserveAuthorityCandidate {
                    provider_registration_id: "registration:other",
                    ..request
                })
                .is_err()
        );
        assert!(
            manager
                .reserve_authority_candidate(&ReserveAuthorityCandidate {
                    attempt_number: 2,
                    ..request
                })
                .is_err()
        );
        assert!(manager.reserve_authority_candidate(&ReserveAuthorityCandidate {
            semantic_program_hash: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ..request
        }).is_err());
        let mut changed = resources.clone();
        changed[0].action = "artifact.write".into();
        assert!(
            manager
                .reserve_authority_candidate(&ReserveAuthorityCandidate {
                    resources: &changed,
                    ..request
                })
                .is_err()
        );
        changed[0] = resources[0].clone();
        changed[0].handle = CandidateResourceHandle::InputArtifact {
            artifact_id: "artifact:alternate".into(),
        };
        assert!(
            manager
                .reserve_authority_candidate(&ReserveAuthorityCandidate {
                    resources: &changed,
                    ..request
                })
                .is_err()
        );
    }

    #[test]
    fn expired_or_newer_evidence_and_clock_rollback_fail_closed() {
        let (mut manager, hash, snapshot, registration) = fixture();
        let resources = choices();
        let contract = contract_hash(&manager, &snapshot);
        let selected = manager
            .provider_store_writer()
            .unwrap()
            .eligible_candidates("artifact.copy@1", &contract, &snapshot, NOW)
            .unwrap()
            .into_iter()
            .find(|item| item.registration.registration_id == registration)
            .unwrap();
        let transaction = manager.connection.transaction().unwrap();
        assert!(
            !evidence_still_current(
                &transaction,
                &selected,
                "artifact.copy@1",
                &contract,
                "2026-09-21T00:00:00Z"
            )
            .unwrap()
        );
        transaction.rollback().unwrap();
        let raw: String = manager.connection.query_row(
            "SELECT evidence_json FROM provider_conformance_evidence WHERE evidence_id='evidence-candidate'",
            [], |row| row.get(0),
        ).unwrap();
        let mut newer: Value = serde_json::from_str(&raw).unwrap();
        newer["result_id"] = json!("evidence-newer-fail");
        newer["result"] = json!("fail");
        newer["tests_passed"] = json!(0);
        newer["tests_failed"] = json!(1);
        newer["executed_at"] = json!("2026-09-19T01:00:00Z");
        manager
            .provider_store_writer()
            .unwrap()
            .record_evidence(&registration, &serde_json::to_vec(&newer).unwrap())
            .unwrap();
        let transaction = manager.connection.transaction().unwrap();
        assert!(
            !evidence_still_current(
                &transaction,
                &selected,
                "artifact.copy@1",
                &contract,
                "2026-09-19T02:00:00Z"
            )
            .unwrap()
        );
        transaction.rollback().unwrap();
        let request = ReserveAuthorityCandidate {
            candidate_id: "candidate:clock",
            binding_id: "binding:clock",
            attempt_id: "attempt:clock",
            task_id: "T-candidate",
            semantic_program_hash: &hash,
            registry_snapshot_id: &snapshot,
            node_id: "copy",
            capability_contract_hash: &contract,
            provider_registration_id: &registration,
            attempt_number: 1,
            resources: &resources,
        };
        manager.clock = Arc::new(RollbackClock(AtomicUsize::new(0)));
        assert!(manager.reserve_authority_candidate(&request).is_err());
        let count: i64 = manager
            .connection
            .query_row(
                "SELECT COUNT(*) FROM authority_candidate_reservations",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    fn contract_hash(manager: &TaskManager, snapshot: &str) -> String {
        manager
            .connection
            .query_row(
                "SELECT content_hash FROM registry_snapshot_entries
            WHERE snapshot_id=?1 AND contract_class='capability' AND semantic_id='artifact.copy'",
                [snapshot],
                |row| row.get(0),
            )
            .unwrap()
    }
}
