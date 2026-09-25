//! Non-executable reservations for deterministic authority evaluation.

use super::{
    AuthorityDenial, AuthorityDenialReason, AuthorityDenialStage, CreateStepExecution, Result,
    StepState, TaskManager, TaskManagerError, active_program_validation_valid, all_unique,
    assert_manager_lease, canonical_json, program_node,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
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
    /// Resolved only against the coordinator-owned service catalog. The source
    /// must also appear as an exact `artifact.read` choice in this candidate.
    ExternalExport {
        service_id: String,
        source_artifact_id: String,
        operation_id: String,
        purpose: String,
        max_size_bytes: u64,
    },
    /// An untrusted proposed service claim. This Stage-1 local profile never
    /// resolves or issues network authority from this handle.
    NetworkService {
        service_id: String,
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

fn semantic_request_mismatch() -> TaskManagerError {
    TaskManagerError::AuthorityDenied(AuthorityDenial {
        stage: AuthorityDenialStage::CandidateReservation,
        reason: AuthorityDenialReason::SemanticRequestMismatch,
    })
}

fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256
}

fn valid_export_identifier(value: &str) -> bool {
    valid_id(value) && !value.chars().any(|c| c.is_whitespace() || c.is_control())
}

fn export_service_hash(service_id: &str, class: &str, adapter_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"AIOS-TRUSTED-EXPORT-SERVICE\0v1\0");
    for field in [service_id, class, adapter_id] {
        hasher.update(field.as_bytes());
        hasher.update([0]);
    }
    let mut hash = String::from("sha256:");
    for byte in hasher.finalize() {
        use std::fmt::Write;
        write!(&mut hash, "{byte:02x}").expect("string write");
    }
    hash
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExportPin {
    pub selector: String,
    pub service_id: String,
    pub destination_class: String,
    pub descriptor_hash: String,
    pub adapter_id: String,
    pub operation_id: String,
    pub source_artifact_id: String,
    pub source_content_hash: String,
    pub purpose: String,
    pub sensitivity: String,
    pub max_size_bytes: u64,
}

pub(super) fn load_export_pin(
    connection: &Connection,
    candidate_id: &str,
) -> Result<Option<ExportPin>> {
    let pin = connection
        .query_row(
            "SELECT p.semantic_selector,p.service_id,p.destination_class,p.descriptor_hash,
                p.adapter_id,p.operation_id,p.source_artifact_id,p.source_content_hash,
                p.purpose,p.sensitivity,p.max_size_bytes
         FROM authority_candidate_export_pins p WHERE p.candidate_id=?1",
            [candidate_id],
            |r| {
                Ok(ExportPin {
                    selector: r.get(0)?,
                    service_id: r.get(1)?,
                    destination_class: r.get(2)?,
                    descriptor_hash: r.get(3)?,
                    adapter_id: r.get(4)?,
                    operation_id: r.get(5)?,
                    source_artifact_id: r.get(6)?,
                    source_content_hash: r.get(7)?,
                    purpose: r.get(8)?,
                    sensitivity: r.get(9)?,
                    max_size_bytes: u64::try_from(r.get::<_, i64>(10)?)
                        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(10, -1))?,
                })
            },
        )
        .optional()?;
    Ok(pin)
}

pub(super) fn load_current_export_pin(
    connection: &Connection,
    candidate_id: &str,
) -> Result<Option<ExportPin>> {
    let Some(pin) = load_export_pin(connection, candidate_id)? else {
        return Ok(None);
    };
    let current: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM authority_export_services s
         JOIN authority_export_service_states st USING(service_id)
         JOIN authority_candidate_export_pins p ON p.service_id=s.service_id
         JOIN authority_candidate_reservations c ON c.candidate_id=p.candidate_id
         JOIN tasks t ON t.task_id=c.task_id
         JOIN artifacts a ON a.artifact_id=?5
         WHERE p.candidate_id=?9 AND s.service_id=?1 AND s.destination_class=?2 AND s.descriptor_hash=?3
           AND s.adapter_id=?4 AND st.state='READY'
           AND json_extract(t.constraints_json,'$.privacy') IN ('local-first','remote-allowed')
           AND a.content_hash=?6 AND a.sensitivity=?7 AND a.integrity_state='verified'
           AND a.size_bytes<=?8)",
        params![pin.service_id,pin.destination_class,pin.descriptor_hash,pin.adapter_id,
            pin.source_artifact_id,pin.source_content_hash,pin.sensitivity,
            i64::try_from(pin.max_size_bytes).map_err(|_|reject())?,candidate_id],
        |r| r.get(0),
    )?;
    if !current
        || !valid_export_identifier(&pin.service_id)
        || !valid_export_identifier(&pin.adapter_id)
        || !valid_export_identifier(&pin.operation_id)
        || export_service_hash(&pin.service_id, &pin.destination_class, &pin.adapter_id)
            != pin.descriptor_hash
    {
        return Err(reject());
    }
    Ok(Some(pin))
}

impl TaskManager {
    /// Privileged control-plane registration. Provider sessions cannot call this
    /// crate-private API or select catalog identity facts at export use.
    pub(crate) fn register_trusted_export_service(
        &mut self,
        service_id: &str,
        destination_class: &str,
        adapter_id: &str,
    ) -> Result<()> {
        if !service_id.starts_with("service://")
            || !valid_export_identifier(service_id)
            || !valid_export_identifier(destination_class)
            || !valid_export_identifier(adapter_id)
            || !destination_class
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            return Err(reject());
        }
        let hash = export_service_hash(service_id, destination_class, adapter_id);
        let now = self.clock.now();
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_manager_lease(&tx, &self.lease_owner, self.lease_epoch)?;
        tx.execute("INSERT INTO authority_export_services(service_id,destination_class,adapter_id,descriptor_hash,registered_at)
            VALUES (?1,?2,?3,?4,?5)",params![service_id,destination_class,adapter_id,hash,now])?;
        tx.execute(
            "INSERT INTO authority_export_service_states(service_id,state,revision,updated_at)
            VALUES (?1,'READY',1,?2)",
            params![service_id, now],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn disable_trusted_export_service(&mut self, service_id: &str) -> Result<()> {
        let now = self.clock.now();
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_manager_lease(&tx, &self.lease_owner, self.lease_epoch)?;
        if tx.execute("UPDATE authority_export_service_states SET state='DISABLED',revision=revision+1,updated_at=?2
            WHERE service_id=?1 AND state='READY'",params![service_id,now])? != 1 { return Err(reject()); }
        tx.commit()?;
        Ok(())
    }
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

#[allow(
    clippy::too_many_lines,
    reason = "candidate replay compares the entire persisted reservation and exact export pin"
)]
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
    let stored_export = load_current_export_pin(connection, request.candidate_id)?;
    // A replay cannot widen the sealed semantic request. Diagnose this at the
    // same reservation fence, before the generic resource-count/replay checks.
    if request.resources.iter().any(|claim| {
        !stored.iter().any(|(action, selector, ..)| {
            action == &claim.action && selector == &claim.semantic_selector
        }) && !stored_export.as_ref().is_some_and(|pin| {
            claim.action == "data.egress" && claim.semantic_selector == pin.selector
        })
    }) {
        return Err(semantic_request_mismatch());
    }
    if row.13
        != i64::try_from(
            request
                .resources
                .iter()
                .filter(|r| !matches!(r.handle, CandidateResourceHandle::ExternalExport { .. }))
                .count(),
        )
        .map_err(|_| reject())?
    {
        return Err(reject());
    }
    let mut requested = Vec::with_capacity(request.resources.len());
    let mut requested_export = None;
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
            CandidateResourceHandle::ExternalExport {
                service_id,
                source_artifact_id,
                operation_id,
                purpose,
                max_size_bytes,
            } => {
                if choice.action != "data.egress" {
                    return Err(reject());
                }
                if requested_export
                    .replace((
                        choice.action.as_str(),
                        choice.semantic_selector.as_str(),
                        service_id.as_str(),
                        source_artifact_id.as_str(),
                        operation_id.as_str(),
                        purpose.as_str(),
                        *max_size_bytes,
                    ))
                    .is_some()
                {
                    return Err(reject());
                }
                continue;
            }
            CandidateResourceHandle::NetworkService { .. } => return Err(reject()),
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
    match (requested_export, stored_export) {
        (None, None) => {}
        (Some((action, selector, service, source, operation, purpose, ceiling)), Some(pin))
            if action == "data.egress"
                && pin.selector == selector
                && pin.service_id == service
                && pin.source_artifact_id == source
                && pin.operation_id == operation
                && pin.purpose == purpose
                && pin.max_size_bytes == ceiling => {}
        _ => return Err(reject()),
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

struct BindingPins {
    binding_id: String,
    attempt_id: String,
    task_id: String,
    hash: String,
    snapshot: String,
    ir_version: String,
    node_id: String,
    capability: String,
    contract_hash: String,
    registration_id: String,
    provider_id: String,
    provider_version: String,
    manifest_hash: String,
    build_hash: String,
    evidence_id: String,
    trust_source_id: String,
    profile_ref: String,
    locality: String,
    attempt: i64,
    resource_count: i64,
    reserved_at: String,
    program_json: String,
}

struct BindingResource {
    action: String,
    selector: String,
    kind: String,
    id: String,
    port: Option<String>,
    semantic_type: String,
}

/// Consumes only a PENDING reservation in the coordinator's existing transaction.
/// The caller has already evaluated current policy and issued the exact grants.
#[allow(
    clippy::too_many_lines,
    reason = "the binding receipt and its guarded insert form one auditable projection"
)]
pub(super) fn insert_reserved_binding_in(
    transaction: &Transaction<'_>,
    candidate_id: &str,
    policy_decision_ids: &[String],
    grant_ids: &[String],
    created_at: &str,
) -> Result<()> {
    if !valid_id(candidate_id)
        || policy_decision_ids.is_empty()
        || policy_decision_ids.len() > 32
        || policy_decision_ids.len() != grant_ids.len()
        || !all_unique(policy_decision_ids)
        || !all_unique(grant_ids)
        || policy_decision_ids.iter().any(|id| !valid_id(id))
        || grant_ids.iter().any(|id| !valid_id(id))
    {
        return Err(reject());
    }
    let created = OffsetDateTime::parse(created_at, &Rfc3339).map_err(|_| reject())?;
    let pins = transaction
        .query_row(
            "SELECT c.binding_id,c.attempt_id,c.task_id,c.semantic_program_hash,
          c.registry_snapshot_id,c.ir_version,c.node_id,c.capability,
          c.capability_contract_hash,c.provider_registration_id,c.provider_id,
          c.provider_version,c.provider_manifest_hash,c.provider_build_hash,
          c.conformance_evidence_id,c.provider_trust_source_id,c.execution_profile_ref,
          c.placement_locality,c.attempt_number,c.resource_count,c.created_at,p.program_json
         FROM authority_candidate_reservations c
         JOIN authority_candidate_status s USING(candidate_id)
         JOIN tasks t ON t.task_id=c.task_id
         JOIN semantic_program_revisions p ON p.task_id=t.task_id
           AND p.program_revision=t.active_program_revision AND p.status='active'
           AND p.semantic_hash=c.semantic_program_hash
           AND p.registry_snapshot_id=c.registry_snapshot_id
         WHERE c.candidate_id=?1 AND s.state='PENDING'",
            [candidate_id],
            |row| {
                Ok(BindingPins {
                    binding_id: row.get(0)?,
                    attempt_id: row.get(1)?,
                    task_id: row.get(2)?,
                    hash: row.get(3)?,
                    snapshot: row.get(4)?,
                    ir_version: row.get(5)?,
                    node_id: row.get(6)?,
                    capability: row.get(7)?,
                    contract_hash: row.get(8)?,
                    registration_id: row.get(9)?,
                    provider_id: row.get(10)?,
                    provider_version: row.get(11)?,
                    manifest_hash: row.get(12)?,
                    build_hash: row.get(13)?,
                    evidence_id: row.get(14)?,
                    trust_source_id: row.get(15)?,
                    profile_ref: row.get(16)?,
                    locality: row.get(17)?,
                    attempt: row.get(18)?,
                    resource_count: row.get(19)?,
                    reserved_at: row.get(20)?,
                    program_json: row.get(21)?,
                })
            },
        )
        .optional()?
        .ok_or_else(reject)?;
    let export_pin = load_current_export_pin(transaction, candidate_id)?;
    if pins.resource_count + i64::from(export_pin.is_some())
        != i64::try_from(policy_decision_ids.len()).map_err(|_| reject())?
        || OffsetDateTime::parse(&pins.reserved_at, &Rfc3339).map_err(|_| reject())? > created
        || pins.locality != "local"
    {
        return Err(reject());
    }
    let mut resources = {
        let mut statement = transaction.prepare(
            "SELECT action,semantic_selector,resource_kind,resource_id,output_port,
                    expected_semantic_type FROM authority_candidate_resources
             WHERE candidate_id=?1 ORDER BY action,semantic_selector",
        )?;
        statement
            .query_map([candidate_id], |row| {
                Ok(BindingResource {
                    action: row.get(0)?,
                    selector: row.get(1)?,
                    kind: row.get(2)?,
                    id: row.get(3)?,
                    port: row.get(4)?,
                    semantic_type: row.get(5)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    if let Some(pin) = &export_pin {
        resources.push(BindingResource {
            action: "data.egress".into(),
            selector: pin.selector.clone(),
            kind: "external-destination".into(),
            id: pin.service_id.clone(),
            port: None,
            semantic_type: "external.export@1".into(),
        });
    }
    if resources.len() != policy_decision_ids.len() {
        return Err(reject());
    }
    let expected = resources
        .iter()
        .map(|r| (r.action.as_str(), r.selector.as_str()))
        .collect::<BTreeSet<_>>();
    if expected.len() != resources.len() {
        return Err(reject());
    }
    let mut covered = BTreeSet::new();
    for decision_id in policy_decision_ids {
        let key: Option<(String, String)> = transaction
            .query_row(
                "SELECT r.action,r.semantic_selector FROM policy_decisions d
             JOIN authority_requests r ON r.request_id=d.authority_request_id
             WHERE d.decision_id=?1 AND d.decision='ALLOW'
               AND (EXISTS(SELECT 1 FROM authority_candidate_resources cr
                    WHERE cr.candidate_id=?2 AND cr.action=r.action
                      AND cr.semantic_selector=r.semantic_selector
                      AND cr.resource_kind=r.resolved_resource_kind
                      AND cr.resource_id=r.resolved_resource_id)
                  OR EXISTS(SELECT 1 FROM authority_candidate_export_pins p
                    WHERE p.candidate_id=?2 AND r.action='data.egress'
                      AND r.semantic_selector=p.semantic_selector
                      AND r.resolved_resource_kind='external-destination'
                      AND r.resolved_resource_id=p.service_id))
               AND r.task_id=?3 AND r.semantic_program_hash=?4
               AND r.registry_snapshot_id=?5 AND r.node_id=?6
               AND r.execution_binding_id=?7 AND r.attempt_id=?8
               AND r.capability=?9 AND r.principal_kind='provider'
               AND r.principal_id=?10 AND d.task_id=r.task_id
               AND d.semantic_program_hash=r.semantic_program_hash
               AND d.node_id=r.node_id AND d.action=r.action
               AND d.resolved_resource_kind=r.resolved_resource_kind
               AND d.resolved_resource_id=r.resolved_resource_id
               AND d.principal_kind=r.principal_kind AND d.principal_id=r.principal_id",
                params![
                    decision_id,
                    candidate_id,
                    pins.task_id,
                    pins.hash,
                    pins.snapshot,
                    pins.node_id,
                    pins.binding_id,
                    pins.attempt_id,
                    pins.capability,
                    pins.provider_id
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (action, selector) = key.ok_or_else(reject)?;
        if !covered.insert((action, selector)) {
            return Err(reject());
        }
    }
    if covered
        .iter()
        .map(|(action, selector)| (action.as_str(), selector.as_str()))
        .collect::<BTreeSet<_>>()
        != expected
    {
        return Err(reject());
    }
    let mut covered_decisions = BTreeSet::new();
    for grant_id in grant_ids {
        let decision_id: Option<String> = transaction
            .query_row(
                "SELECT g.policy_decision_id FROM authority_grants g
             JOIN authority_issuance_receipts i ON i.grant_id=g.grant_id
               AND i.token_id=g.token_id AND i.task_id=g.task_id
               AND i.execution_binding_id=g.execution_binding_id
               AND i.attempt_id=g.attempt_id AND i.policy_decision_id=g.policy_decision_id
               AND i.issued_at=g.issued_at AND i.issuance_profile='coordinator-issued-v0.1'
             WHERE g.grant_id=?1 AND g.task_id=?2 AND g.semantic_program_hash=?3
               AND g.node_id=?4 AND g.capability=?5 AND g.principal_kind='provider'
               AND g.principal_id=?6 AND g.execution_binding_id=?7 AND g.attempt_id=?8
               AND g.state='ACTIVE' AND g.uses_consumed=0
               AND g.delegable=0 AND g.max_delegation_depth=0",
                params![
                    grant_id,
                    pins.task_id,
                    pins.hash,
                    pins.node_id,
                    pins.capability,
                    pins.provider_id,
                    pins.binding_id,
                    pins.attempt_id
                ],
                |row| row.get(0),
            )
            .optional()?;
        let decision_id = decision_id.ok_or_else(reject)?;
        if !policy_decision_ids.contains(&decision_id) || !covered_decisions.insert(decision_id) {
            return Err(reject());
        }
    }
    let program: Value = serde_json::from_str(&pins.program_json).map_err(|_| reject())?;
    let node = program_node(&program, &pins.node_id).ok_or_else(reject)?;
    if node
        .pointer("/operation/capability")
        .and_then(Value::as_str)
        != Some(pins.capability.as_str())
    {
        return Err(reject());
    }
    let mut inputs = Map::new();
    let node_inputs = node
        .get("inputs")
        .and_then(Value::as_object)
        .ok_or_else(reject)?;
    for (port, wiring) in node_inputs {
        if wiring.get("source").and_then(Value::as_str) != Some("input") {
            return Err(reject());
        }
        let name = wiring
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(reject)?;
        let selector = format!("input:{name}");
        let resource = resources
            .iter()
            .find(|r| {
                r.action == "artifact.read"
                    && r.selector == selector
                    && r.kind == "artifact"
                    && r.port.is_none()
            })
            .ok_or_else(reject)?;
        let program_type = program
            .pointer(&format!("/inputs/{name}/type"))
            .and_then(Value::as_str)
            .ok_or_else(reject)?;
        if resource.semantic_type != program_type {
            return Err(reject());
        }
        inputs.insert(
            port.clone(),
            json!({"semantic_type":resource.semantic_type,
            "artifact_or_value_ref":resource.id}),
        );
    }
    let mut outputs = Map::new();
    let node_outputs = node
        .get("outputs")
        .and_then(Value::as_object)
        .ok_or_else(reject)?;
    for (port, semantic_type) in node_outputs {
        let resource = resources
            .iter()
            .find(|r| {
                r.action == "artifact.write"
                    && r.kind == "output-allocation"
                    && r.port.as_deref() == Some(port)
            })
            .ok_or_else(reject)?;
        if semantic_type.as_str() != Some(resource.semantic_type.as_str()) {
            return Err(reject());
        }
        outputs.insert(
            port.clone(),
            json!({"semantic_type":resource.semantic_type,
            "allocation_ref":resource.id}),
        );
    }
    if resources.iter().filter(|r| r.kind == "artifact").count() != inputs.len()
        || resources
            .iter()
            .filter(|r| r.kind == "output-allocation")
            .count()
            != outputs.len()
    {
        return Err(reject());
    }
    let policy_json = canonical_json(&policy_decision_ids)?;
    let grants_json = canonical_json(&grant_ids)?;
    let placement = json!({"locality":pins.locality});
    let placement_json = canonical_json(&placement)?;
    let mut receipt_value = json!({
        "schema_version":"0.1","binding_id":pins.binding_id,"attempt_id":pins.attempt_id,
        "task_id":pins.task_id,"semantic_program_hash":pins.hash,
        "registry_snapshot_id":pins.snapshot,"ir_version":pins.ir_version,
        "node_id":pins.node_id,"capability":pins.capability,
        "capability_contract_hash":pins.contract_hash,
        "conformance_evidence_id":pins.evidence_id,
        "provider_trust_source_id":pins.trust_source_id,
        "provider":{"id":pins.provider_id,"version":pins.provider_version,
            "manifest_hash":pins.manifest_hash,"package_or_build_hash":pins.build_hash},
        "inputs":inputs,"outputs":outputs,"policy_decision_refs":policy_decision_ids,
        "authority":{"grant_refs":grant_ids},
        "execution_profile":{"profile_ref":pins.profile_ref},"placement":placement,
        "attempt":pins.attempt,"created_at":created_at,
    });
    if let Some(pin) = &export_pin {
        receipt_value["external_export"] = json!(pin);
    }
    let receipt = canonical_json(&receipt_value)?;
    transaction.execute(
        "INSERT INTO execution_bindings(binding_id,attempt_id,task_id,semantic_program_hash,
         registry_snapshot_id,ir_version,node_id,capability,capability_contract_hash,
         provider_registration_id,provider_id,provider_version,provider_manifest_hash,
         provider_build_hash,attempt,policy_decision_refs_json,grant_refs_json,
         execution_profile_ref,placement_json,binding_json,created_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)",
        params![
            pins.binding_id,
            pins.attempt_id,
            pins.task_id,
            pins.hash,
            pins.snapshot,
            pins.ir_version,
            pins.node_id,
            pins.capability,
            pins.contract_hash,
            pins.registration_id,
            pins.provider_id,
            pins.provider_version,
            pins.manifest_hash,
            pins.build_hash,
            pins.attempt,
            policy_json,
            grants_json,
            pins.profile_ref,
            placement_json,
            receipt,
            created_at
        ],
    )?;
    Ok(())
}

/// Inserts the one READY attempt for a freshly bound candidate. Its input IDs
/// must cover the entire reserved read set and the binding's exact input map.
#[allow(dead_code, reason = "called by the coordinator finalizer")]
pub(super) fn insert_reserved_ready_step_in(
    transaction: &Transaction<'_>,
    candidate_id: &str,
    created_at: &str,
) -> Result<()> {
    let (
        attempt_id,
        task_id,
        hash,
        snapshot,
        node_id,
        binding_id,
        provider_id,
        provider_version,
        attempt_number,
        binding_json,
    ): (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        i64,
        String,
    ) = transaction
        .query_row(
            "SELECT c.attempt_id,c.task_id,c.semantic_program_hash,c.registry_snapshot_id,
                    c.node_id,c.binding_id,c.provider_id,c.provider_version,c.attempt_number,
                    b.binding_json
             FROM authority_candidate_reservations c
             JOIN authority_candidate_status s USING(candidate_id)
             JOIN execution_bindings b ON b.binding_id=c.binding_id AND b.attempt_id=c.attempt_id
             WHERE c.candidate_id=?1 AND s.state='PENDING'",
            [candidate_id],
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
        .optional()?
        .ok_or_else(reject)?;
    let input_artifacts = exact_reserved_step_inputs(transaction, candidate_id, &binding_json)?;
    let request = CreateStepExecution {
        attempt_id,
        task_id,
        semantic_program_hash: hash,
        registry_snapshot_id: Some(snapshot),
        node_id,
        binding_id: Some(binding_id),
        provider_id: Some(provider_id),
        provider_version: Some(provider_version),
        attempt_number: u16::try_from(attempt_number).map_err(|_| reject())?,
        state: StepState::Ready,
        operation_id: None,
        idempotency_key: None,
        outcome_certainty: None,
        input_artifacts,
        output_artifacts: Vec::new(),
        failure: None,
        started_at: None,
        finished_at: None,
    };
    TaskManager::create_step_execution_in(transaction, &request, created_at)
}

fn exact_reserved_step_inputs(
    transaction: &Transaction<'_>,
    candidate_id: &str,
    binding_json: &str,
) -> Result<Vec<String>> {
    let input_artifacts: Vec<String> = transaction
        .prepare(
            "SELECT resource_id FROM authority_candidate_resources
         WHERE candidate_id=?1 AND action='artifact.read' AND resource_kind='artifact'
         ORDER BY semantic_selector",
        )?
        .query_map([candidate_id], |row| row.get(0))?
        .collect::<std::result::Result<_, _>>()?;
    if !all_unique(&input_artifacts) {
        return Err(reject());
    }
    let receipt: Value = aios_registry::parse_strict_value(
        binding_json.as_bytes(),
        aios_registry::StrictJsonLimits::default(),
    )
    .map_err(|_| reject())?;
    let inputs = receipt
        .get("inputs")
        .and_then(Value::as_object)
        .ok_or_else(reject)?;
    let mut bound_ids = BTreeSet::new();
    for binding in inputs.values() {
        let id = binding
            .get("artifact_or_value_ref")
            .and_then(Value::as_str)
            .ok_or_else(reject)?;
        if !bound_ids.insert(id.to_owned()) {
            return Err(reject());
        }
    }
    if bound_ids != input_artifacts.iter().cloned().collect() {
        return Err(reject());
    }
    Ok(input_artifacts)
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
               AND t.state IN ('PLANNING','WAITING_FOR_AUTH','RUNNABLE','RUNNING')",
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
               AND t.state IN ('PLANNING','WAITING_FOR_AUTH','RUNNABLE','RUNNING')",
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
            || !matches!(
                node.pointer("/egress/mode").and_then(Value::as_str),
                Some("deny" | "policy")
            )
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
        let declared_pairs = declared
            .iter()
            .map(|request| {
                Ok((
                    request
                        .get("action")
                        .and_then(Value::as_str)
                        .ok_or_else(reject)?,
                    request
                        .get("resource")
                        .and_then(Value::as_str)
                        .ok_or_else(reject)?,
                ))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        if request.resources.iter().any(|claim| {
            !declared_pairs.contains(&(claim.action.as_str(), claim.semantic_selector.as_str()))
        }) {
            return Err(semantic_request_mismatch());
        }
        if declared.len() != request.resources.len() {
            return Err(reject());
        }
        let mut resolved = Vec::new();
        let mut export_pin: Option<ExportPin> = None;
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
            if let (
                "data.egress",
                CandidateResourceHandle::ExternalExport {
                    service_id,
                    source_artifact_id,
                    operation_id,
                    purpose,
                    max_size_bytes,
                },
            ) = (action, &choice.handle)
            {
                let class = selector.strip_prefix("destination:").ok_or_else(reject)?;
                let classes = node
                    .pointer("/egress/destination_classes")
                    .and_then(Value::as_array)
                    .ok_or_else(reject)?;
                let privacy = current.2.as_deref().unwrap_or("{}");
                let constraints = aios_registry::parse_strict_value(
                    privacy.as_bytes(),
                    aios_registry::StrictJsonLimits::default(),
                )
                .map_err(|_| reject())?;
                if export_pin.is_some()
                    || node.pointer("/egress/mode").and_then(Value::as_str)!=Some("policy")
                    || !classes.iter().any(|v|v.as_str()==Some(class))
                    || !matches!(constraints.pointer("/privacy").and_then(Value::as_str),
                        Some("local-first"|"remote-allowed"))
                    || !valid_export_identifier(operation_id) || !valid_id(purpose)
                    || *max_size_bytes==0 || *max_size_bytes>8*1024*1024
                    || !request.resources.iter().any(|r| r.action=="artifact.read"
                        && matches!(&r.handle,CandidateResourceHandle::InputArtifact{artifact_id}
                            if artifact_id==source_artifact_id))
                { return Err(reject()); }
                let service:Option<(String,String,String,String)>=tx.query_row(
                    "SELECT s.destination_class,s.adapter_id,s.descriptor_hash,st.state
                     FROM authority_export_services s JOIN authority_export_service_states st USING(service_id)
                     WHERE s.service_id=?1",[service_id],
                    |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
                let (registered_class, adapter_id, descriptor_hash, state) =
                    service.ok_or_else(reject)?;
                if registered_class != class
                    || state != "READY"
                    || export_service_hash(service_id, class, &adapter_id) != descriptor_hash
                {
                    return Err(reject());
                }
                let artifact: Option<(String, String, i64, String)> = tx
                    .query_row(
                        "SELECT a.content_hash,a.sensitivity,a.size_bytes,a.integrity_state
                     FROM artifacts a JOIN task_artifacts ta USING(artifact_id)
                     WHERE ta.task_id=?1 AND ta.role='input' AND a.artifact_id=?2",
                        params![request.task_id, source_artifact_id],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                    )
                    .optional()?;
                let (source_content_hash, sensitivity, size, integrity) =
                    artifact.ok_or_else(reject)?;
                if integrity != "verified"
                    || u64::try_from(size).map_or(true, |size| size > *max_size_bytes)
                {
                    return Err(reject());
                }
                export_pin = Some(ExportPin {
                    selector: selector.to_owned(),
                    service_id: service_id.clone(),
                    destination_class: class.to_owned(),
                    descriptor_hash,
                    adapter_id,
                    operation_id: operation_id.clone(),
                    source_artifact_id: source_artifact_id.clone(),
                    source_content_hash,
                    purpose: purpose.clone(),
                    sensitivity,
                    max_size_bytes: *max_size_bytes,
                });
                continue;
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
        if (node.pointer("/egress/mode").and_then(Value::as_str) == Some("policy"))
            != export_pin.is_some()
        {
            return Err(reject());
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
        if let Some(pin) = &export_pin {
            tx.execute("INSERT INTO authority_candidate_export_pins(candidate_id,semantic_selector,
                service_id,destination_class,descriptor_hash,adapter_id,operation_id,
                source_artifact_id,source_content_hash,purpose,sensitivity,max_size_bytes,reserved_at)
                VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                params![request.candidate_id,pin.selector,pin.service_id,pin.destination_class,
                    pin.descriptor_hash,pin.adapter_id,pin.operation_id,pin.source_artifact_id,
                    pin.source_content_hash,pin.purpose,pin.sensitivity,
                    i64::try_from(pin.max_size_bytes).map_err(|_|reject())?,checked_at])?;
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
    use crate::artifact_store::{
        ArtifactExpectedState, ArtifactLineage, ArtifactOriginKind, ArtifactPublicationRequest,
        ImportArtifactRequest, RetentionClass, Sensitivity,
    };
    use crate::{
        ActivePlan, Actor, Clock, CreateStepExecution, CreateTask, StepState, TaskMutation,
        TaskState, TransitionReason, TransitionRequest, WaitingKind, WaitingOn,
    };
    use aios_contracts::{CapabilityContract, RegistrySnapshot, TypeContract};
    use aios_registry::{
        ProviderTrustStatus, RegistryBuildOptions, SemanticRegistry, SnapshotHashEntry,
    };
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    use std::{
        io::{Cursor, Read, Seek, SeekFrom, Write},
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
    struct FrozenWallClock {
        monotonic: Arc<std::sync::atomic::AtomicU64>,
    }
    impl Clock for FrozenWallClock {
        fn now(&self) -> String {
            NOW.to_owned()
        }
        fn security_sample(&self) -> Option<crate::SecurityClockSample> {
            Some(crate::SecurityClockSample {
                wall: NOW.to_owned(),
                monotonic_nanos: self.monotonic.load(Ordering::SeqCst),
                source: crate::TimeSource::InjectedClock,
            })
        }
    }
    struct PreflightRegressionClock {
        baseline: Arc<std::sync::atomic::AtomicU64>,
        phase: Arc<AtomicUsize>,
        expired: u64,
    }
    impl Clock for PreflightRegressionClock {
        fn now(&self) -> String {
            NOW.to_owned()
        }
        fn security_sample(&self) -> Option<crate::SecurityClockSample> {
            let monotonic_nanos = match self.phase.load(Ordering::SeqCst) {
                1 => {
                    self.phase.store(2, Ordering::SeqCst);
                    self.expired
                }
                _ => self.baseline.load(Ordering::SeqCst),
            };
            Some(crate::SecurityClockSample {
                wall: NOW.to_owned(),
                monotonic_nanos,
                source: crate::TimeSource::InjectedClock,
            })
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
                "DROP TABLE authority_candidate_export_pins;
             DROP TABLE authority_export_service_states;
             DROP TABLE authority_export_services;
             DELETE FROM schema_migrations
             WHERE migration_id='0022_exact_export_authority';
             DROP TABLE authority_candidate_status;
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

    fn coherent_planning_fixture(path: &Path) -> (TaskManager, String, String, String) {
        fixture_at_mode(Some(path), true, false, None, true)
    }

    fn fixture_at(path: Option<&Path>) -> (TaskManager, String, String, String) {
        fixture_at_mode(path, false, false, None, true)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "builds one complete provider and Task admission fixture"
    )]
    fn fixture_at_mode(
        path: Option<&Path>,
        coherent_planning: bool,
        export: bool,
        provider_id: Option<&str>,
        seed_placeholder_source: bool,
    ) -> (TaskManager, String, String, String) {
        let mut manager = match path {
            Some(path) => TaskManager::open_with_clock(path, Box::new(FixedClock)).unwrap(),
            None => TaskManager::open_in_memory_with_clock(Box::new(FixedClock)).unwrap(),
        };
        manager
            .create_task(&CreateTask {
                task_id: "T-candidate".into(),
                principal: Actor {
                    kind: "user".into(),
                    id: "user:test".into(),
                },
                workspace_id: None,
                original_intent: "copy source".into(),
                normalized_intent: None,
                active_step_ids: vec!["copy".into()],
            })
            .unwrap();
        if !coherent_planning {
            manager.connection.execute(
                "UPDATE tasks SET state='WAITING_FOR_AUTH',active_program_revision=1,
                 active_plan_revision=1,
                 constraints_json='{\"privacy\":\"local-only\",\"max_cost_microunits\":1000,\"preserve_inputs\":true}'
                 WHERE task_id='T-candidate'",
                [],
            ).unwrap();
        }
        if export {
            manager.connection.execute("UPDATE tasks SET constraints_json='{\"privacy\":\"remote-allowed\",\"preserve_inputs\":true}'
                WHERE task_id='T-candidate'",[]).unwrap();
        }
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
        if export {
            selected
                .allowed_effect_classes
                .push(aios_contracts::EffectClass::DataEgress);
            selected
                .allowed_authority_classes
                .push("data.egress".into());
            selected
                .allowed_egress_modes
                .push(aios_contracts::EgressMode::Policy);
        }
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
        if let Some(provider_id) = provider_id {
            manifest["id"] = json!(provider_id);
        }
        manifest["provides"][0]["contract"]["capability"] = json!("artifact.copy");
        manifest["provides"][0]["contract"]["contract_hash"] = json!(contract_hash);
        manifest["provides"][0]["conformance"]["suite"] = json!("conformance://artifact.copy/1");
        manifest["provides"][0]["conformance"]["suite_hash"] = json!(SUITE);
        manifest["provides"][0]["effect_classes"] = json!(["ARTIFACT_READ", "ARTIFACT_WRITE"]);
        manifest["provides"][0]["authority"]["actions"] =
            json!(["artifact.read", "artifact.write"]);
        if export {
            manifest["provides"][0]["effect_classes"] =
                json!(["ARTIFACT_READ", "ARTIFACT_WRITE", "DATA_EGRESS"]);
            manifest["provides"][0]["authority"]["actions"] =
                json!(["artifact.read", "artifact.write", "data.egress"]);
        }
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
        let mut program = json!({
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
        if export {
            program["nodes"][0]["authority_requests"]
                .as_array_mut()
                .unwrap()
                .push(json!({"action":"data.egress","resource":"destination:fixture_remote"}));
            program["nodes"][0]["egress"] = json!({"mode":"policy",
                "destination_classes":["fixture_remote"]});
        }
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
        manager
            .connection
            .execute(
                "INSERT INTO plan_revisions(task_id,plan_revision,plan_id,plan_json,created_at)
             VALUES ('T-candidate',1,'plan-candidate','{}',?1)",
                [NOW],
            )
            .unwrap();
        manager.connection.execute("INSERT INTO semantic_program_revisions(task_id,program_revision,program_id,
            ir_version,semantic_hash,registry_snapshot_id,validation_result_id,status,program_json,
            created_from_plan_revision,created_at)
            VALUES ('T-candidate',1,'program-candidate','0.1',?1,?2,'validation-candidate','active',?3,1,?4)",
            params![hash,registry.snapshot_id(),program_json,NOW]).unwrap();
        if seed_placeholder_source {
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
        }
        if coherent_planning {
            manager
                .connection
                .execute(
                    "UPDATE tasks SET active_program_revision=1 WHERE task_id='T-candidate'",
                    [],
                )
                .unwrap();
            let result = manager
                .transition(&TransitionRequest {
                    schema_version: "0.1".into(),
                    transition_id: "transition:candidate-planning".into(),
                    task_id: "T-candidate".into(),
                    expected_revision: 1,
                    expected_state: TaskState::Created,
                    to_state: TaskState::Planning,
                    requested_by: Actor {
                        kind: "system-service".into(),
                        id: "aiosd.coordinator".into(),
                    },
                    reason: TransitionReason {
                        code: "PLAN_STARTED".into(),
                        message: None,
                        related_ids: vec![],
                    },
                    mutation: TaskMutation {
                        active_plan: Some(ActivePlan {
                            plan_id: "plan-candidate".into(),
                            revision: 1,
                        }),
                        ..TaskMutation::default()
                    },
                })
                .unwrap();
            assert!(result.applied, "{result:?}");
        }
        (
            manager,
            hash,
            registry.snapshot_id().to_owned(),
            registration.registration_id,
        )
    }

    fn choices() -> Vec<CandidateResourceChoice> {
        choices_with_source("artifact:source")
    }

    fn authority_case(name: &str) -> Value {
        let cases: Vec<Value> = serde_json::from_str(include_str!(
            "../../../examples/authority/authority-cases.json"
        ))
        .unwrap();
        let mut matching = cases.into_iter().filter(|case| case["name"] == name);
        let case = matching.next().expect("named authority fixture exists");
        assert!(
            matching.next().is_none(),
            "authority fixture name is unique"
        );
        case
    }

    #[allow(
        clippy::too_many_lines,
        reason = "issues one genuine coordinator read grant for lifecycle fixtures"
    )]
    fn issued_fixture_read(
        read_requires_approval: bool,
        enter_running: bool,
    ) -> (
        TaskManager,
        String,
        crate::artifact_store::ProviderArtifactSession,
        String,
        String,
    ) {
        use crate::authority_policy::AuthenticatedApprover;
        let (mut manager, hash, snapshot, registration) =
            fixture_at_mode(None, true, false, None, false);
        let source = manager
            .import_artifact(
                &ImportArtifactRequest {
                    schema_version: "0.1".into(),
                    import_id: Some("import:grant-lifecycle".into()),
                    task_id: "T-candidate".into(),
                    origin_kind: ArtifactOriginKind::User,
                    semantic_type: Some("artifact.file@1".into()),
                    media_type: "text/plain".into(),
                    format: None,
                    sensitivity: Sensitivity::Local,
                    retention: RetentionClass::Task,
                    expires_at: None,
                    labels: vec![],
                    max_size_bytes: Some(1024),
                },
                &mut Cursor::new(b"grant lifecycle source"),
            )
            .unwrap();
        let resources =
            choices_with_source_and_output(&source.artifact_id, "allocation:grant-lifecycle");
        manager
            .reserve_authority_candidate(&ReserveAuthorityCandidate {
                candidate_id: "candidate:grant-lifecycle",
                binding_id: "binding:grant-lifecycle",
                attempt_id: "attempt:grant-lifecycle",
                task_id: "T-candidate",
                semantic_program_hash: &hash,
                registry_snapshot_id: &snapshot,
                node_id: "copy",
                capability_contract_hash: &contract_hash(&manager, &snapshot),
                provider_registration_id: &registration,
                attempt_number: 1,
                resources: &resources,
            })
            .unwrap();
        let read_effect = if read_requires_approval {
            "REQUIRE_APPROVAL"
        } else {
            "ALLOW"
        };
        manager.activate_local_authority_policy(json!({"schema_version":"0.1","rules":[
            {"effect":read_effect,"action":"artifact.read","resource_kind":"artifact","sensitivity":"local"},
            {"effect":"ALLOW","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"}
        ]}).to_string().as_bytes()).unwrap();
        let evaluation = manager
            .evaluate_pending_authority_candidate("candidate:grant-lifecycle")
            .unwrap();
        let mut revision = 2;
        let mut state = TaskState::Planning;
        if read_requires_approval {
            let approval = evaluation.decisions[0].approval_id.as_deref().unwrap();
            assert!(
                manager
                    .transition(&TransitionRequest {
                        schema_version: "0.1".into(),
                        transition_id: "transition:grant-waiting".into(),
                        task_id: "T-candidate".into(),
                        expected_revision: 2,
                        expected_state: TaskState::Planning,
                        to_state: TaskState::WaitingForAuth,
                        requested_by: Actor {
                            kind: "system-service".into(),
                            id: "aiosd.coordinator".into()
                        },
                        reason: TransitionReason {
                            code: "APPROVAL_REQUIRED".into(),
                            message: None,
                            related_ids: vec![approval.into()]
                        },
                        mutation: TaskMutation {
                            waiting_on: Some(vec![WaitingOn {
                                kind: WaitingKind::Approval,
                                id: approval.into(),
                                message: None
                            }]),
                            ..TaskMutation::default()
                        },
                    })
                    .unwrap()
                    .applied
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
            revision = 3;
            state = TaskState::WaitingForAuth;
        }
        manager
            .finalize_pending_authority_candidate("candidate:grant-lifecycle")
            .unwrap();
        // Admit the unique selected input first; a later same-Task import
        // cannot widen the finalized exact-resource grant.
        let unbound = manager
            .import_artifact(
                &ImportArtifactRequest {
                    schema_version: "0.1".into(),
                    import_id: Some("import:grant-lifecycle-unbound".into()),
                    task_id: "T-candidate".into(),
                    origin_kind: ArtifactOriginKind::User,
                    semantic_type: Some("artifact.file@1".into()),
                    media_type: "text/plain".into(),
                    format: None,
                    sensitivity: Sensitivity::Local,
                    retention: RetentionClass::Task,
                    expires_at: None,
                    labels: vec![],
                    max_size_bytes: Some(1024),
                },
                &mut Cursor::new(b"same task but unbound"),
            )
            .unwrap();
        for (id, next) in [
            ("transition:grant-runnable", TaskState::Runnable),
            ("transition:grant-running", TaskState::Running),
        ] {
            if next == TaskState::Running && !enter_running {
                break;
            }
            assert!(
                manager
                    .transition(&TransitionRequest {
                        schema_version: "0.1".into(),
                        transition_id: id.into(),
                        task_id: "T-candidate".into(),
                        expected_revision: revision,
                        expected_state: state,
                        to_state: next,
                        requested_by: Actor {
                            kind: "system-service".into(),
                            id: "aiosd.coordinator".into()
                        },
                        reason: TransitionReason {
                            code: "AUTHORITY_READY".into(),
                            message: None,
                            related_ids: vec![]
                        },
                        mutation: TaskMutation::default(),
                    })
                    .unwrap()
                    .applied
            );
            revision += 1;
            state = next;
        }
        let grant_id: String = manager.connection.query_row(
            "SELECT g.grant_id FROM authority_grants g JOIN policy_decisions d ON d.decision_id=g.policy_decision_id
             WHERE g.execution_binding_id='binding:grant-lifecycle' AND d.action='artifact.read' AND d.resolved_resource_id=?1",
            [&source.artifact_id], |row| row.get(0),
        ).unwrap();
        let session = manager
            .issue_provider_artifact_session("T-candidate", "binding:grant-lifecycle")
            .unwrap();
        (
            manager,
            source.artifact_id,
            session,
            grant_id,
            unbound.artifact_id,
        )
    }

    #[test]
    fn fixture_one_shot_read_exhaustion_preserves_only_authenticated_replay() {
        let case = authority_case("one-shot-grant-already-consumed");
        assert_eq!(case["expected"], "DENY");
        let (mut manager, source, session, grant_id, unbound) = issued_fixture_read(true, true);
        let (scope, maximum, consumed, state): (String, Option<i64>, i64, String) = manager
            .connection
            .query_row(
                "SELECT scope,max_uses,uses_consumed,state FROM authority_grants WHERE grant_id=?1",
                [&grant_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(scope, case["facts"]["scope"]);
        assert_eq!(maximum, Some(case["facts"]["max_uses"].as_i64().unwrap()));
        assert_eq!((consumed, state.as_str()), (0, "ACTIVE"));
        let read_scope = manager
            .scope_artifact_reads(&session, std::slice::from_ref(&source))
            .unwrap();
        let first = manager.open_artifact_reader(&read_scope, &source).unwrap();
        let operation: String = manager.connection.query_row(
            "SELECT operation_id FROM operations WHERE task_id='T-candidate' AND effect_class='ARTIFACT_READ'",
            [], |row| row.get(0),
        ).unwrap();
        drop(first); // no bytes delivered: the same pending admission may replay
        let mut replay = manager.open_artifact_reader(&read_scope, &source).unwrap();
        let replayed_operation: String = manager.connection.query_row(
            "SELECT operation_id FROM operations WHERE task_id='T-candidate' AND effect_class='ARTIFACT_READ'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(replayed_operation, operation);
        let mut bytes = Vec::new();
        replay.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"grant lifecycle source");
        let (consumed, state, operations): (i64, String, i64) = manager.connection.query_row(
            "SELECT g.uses_consumed,g.state,(SELECT COUNT(*) FROM operations o WHERE o.task_id=g.task_id AND o.effect_class='ARTIFACT_READ')
             FROM authority_grants g WHERE g.grant_id=?1",
            [&grant_id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).unwrap();
        assert_eq!(consumed, case["facts"]["uses_consumed"]);
        assert_eq!(state, "CONSUMED");
        assert_eq!(operations, 1);
        let error = manager
            .scope_artifact_reads(&session, std::slice::from_ref(&source))
            .unwrap_err();
        assert_eq!(error.to_string(), "ARTIFACT_AUTHORITY_DENIED");
        let denial = error.authority_denial().unwrap();
        assert_eq!(denial.stage, AuthorityDenialStage::ArtifactAdmission);
        assert_eq!(denial.reason.code(), case["reason_code"]);
        let old_scope_error = match manager.open_artifact_reader(&read_scope, &source) {
            Ok(_) => panic!("delivered one-shot admission reopened a reader"),
            Err(error) => error,
        };
        assert_eq!(old_scope_error.to_string(), "ARTIFACT_AUTHORITY_DENIED");
        let old_scope_denial = old_scope_error.authority_denial().unwrap();
        assert_eq!(
            old_scope_denial.stage,
            AuthorityDenialStage::ArtifactAdmission
        );
        assert_eq!(old_scope_denial.reason.code(), case["reason_code"]);
        let wrong_artifact = manager
            .scope_artifact_reads(&session, std::slice::from_ref(&unbound))
            .unwrap_err();
        assert_eq!(wrong_artifact.to_string(), "ARTIFACT_AUTHORITY_DENIED");
        assert!(wrong_artifact.authority_denial().is_none());
        let (uses_after_denial, operations_after_denial): (i64, i64) = manager
            .connection
            .query_row(
                "SELECT g.uses_consumed,(SELECT COUNT(*) FROM operations o WHERE o.task_id=g.task_id AND o.effect_class='ARTIFACT_READ')
                 FROM authority_grants g WHERE g.grant_id=?1",
                [&grant_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            (uses_after_denial, operations_after_denial),
            (consumed, operations)
        );
        replay.seek(SeekFrom::Start(0)).unwrap();
        let mut again = Vec::new();
        replay.read_to_end(&mut again).unwrap();
        assert_eq!(again, bytes);
        let operation_count: i64 = manager.connection.query_row(
            "SELECT COUNT(*) FROM operations WHERE task_id='T-candidate' AND effect_class='ARTIFACT_READ'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(operation_count, 1);
    }

    #[test]
    fn fixture_expired_grant_denies_retained_bytes_and_new_admission() {
        let case = authority_case("expired-grant");
        assert_eq!(case["expected"], "DENY");
        assert_eq!(case["facts"]["effective_grant_state"], "EXPIRED");
        assert_eq!(
            case["facts"]["expiry_evidence"],
            "authenticated_expiry_latch"
        );
        let (mut manager, source, session, grant_id, _) = issued_fixture_read(false, true);
        let (issued, deadline): (i64, i64) = manager
            .connection
            .query_row(
                "SELECT issued_monotonic_nanos,deadline_monotonic_nanos
             FROM authority_grant_deadlines WHERE grant_id=?1",
                [&grant_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let high_water: i64 = manager
            .connection
            .query_row(
                "SELECT MAX(monotonic_nanos) FROM trusted_time_observations",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let baseline = issued.max(high_water) + 1_000_000_000;
        assert!(baseline < deadline);
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(
            u64::try_from(baseline).unwrap(),
        ));
        manager.clock = Arc::new(FrozenWallClock {
            monotonic: Arc::clone(&monotonic),
        });
        let scope = manager
            .scope_artifact_reads(&session, std::slice::from_ref(&source))
            .unwrap();
        let mut reader = manager.open_artifact_reader(&scope, &source).unwrap();
        let mut first = [0_u8; 1];
        assert_eq!(reader.read(&mut first).unwrap(), 1);
        let position = reader.raw_position_for_test().unwrap();
        let before_denial: (i64, i64) = manager.connection.query_row(
            "SELECT g.uses_consumed,(SELECT COUNT(*) FROM operations o WHERE o.task_id=g.task_id AND o.effect_class='ARTIFACT_READ')
             FROM authority_grants g WHERE g.grant_id=?1",
            [&grant_id], |row| Ok((row.get(0)?,row.get(1)?)),
        ).unwrap();
        monotonic.store(u64::try_from(deadline + 1).unwrap(), Ordering::SeqCst);
        let mut denied = [0xa5_u8; 1];
        let error = reader.read(&mut denied).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(error.to_string(), "ARTIFACT_AUTHORITY_DENIED");
        let inner = error
            .get_ref()
            .unwrap()
            .downcast_ref::<TaskManagerError>()
            .unwrap();
        let denial = inner.authority_denial().unwrap();
        assert_eq!(denial.stage, AuthorityDenialStage::ArtifactRead);
        assert_eq!(denial.reason.code(), case["reason_code"]);
        assert_eq!(denied, [0xa5]);
        assert_eq!(reader.raw_position_for_test().unwrap(), position);
        let latched: i64 = manager
            .connection
            .query_row(
                "SELECT COUNT(*) FROM authority_grant_expiry_latches WHERE grant_id=?1",
                [&grant_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(latched, 1);
        let persisted_state: String = manager
            .connection
            .query_row(
                "SELECT state FROM authority_grants WHERE grant_id=?1",
                [&grant_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(persisted_state, case["facts"]["persisted_grant_state"]);
        let error = manager
            .scope_artifact_reads(&session, std::slice::from_ref(&source))
            .unwrap_err();
        assert_eq!(error.to_string(), "ARTIFACT_AUTHORITY_DENIED");
        let denial = error.authority_denial().unwrap();
        assert_eq!(denial.stage, AuthorityDenialStage::ArtifactAdmission);
        assert_eq!(denial.reason.code(), case["reason_code"]);
        let after_denial: (i64, i64) = manager.connection.query_row(
            "SELECT g.uses_consumed,(SELECT COUNT(*) FROM operations o WHERE o.task_id=g.task_id AND o.effect_class='ARTIFACT_READ')
             FROM authority_grants g WHERE g.grant_id=?1",
            [&grant_id], |row| Ok((row.get(0)?,row.get(1)?)),
        ).unwrap();
        assert_eq!(after_denial, before_denial);
    }

    #[test]
    fn fixture_cancel_revokes_real_grant_and_retained_reader() {
        let case = authority_case("revoked-grant-after-task-cancel");
        assert_eq!(case["expected"], "DENY");
        let (mut manager, source, session, grant_id, _) = issued_fixture_read(false, false);
        let scope = manager
            .scope_artifact_reads(&session, std::slice::from_ref(&source))
            .unwrap();
        let mut reader = manager.open_artifact_reader(&scope, &source).unwrap();
        let mut first = [0_u8; 1];
        assert_eq!(reader.read(&mut first).unwrap(), 1);
        let position = reader.raw_position_for_test().unwrap();
        let before_denial: (i64, i64) = manager.connection.query_row(
            "SELECT g.uses_consumed,(SELECT COUNT(*) FROM operations o WHERE o.task_id=g.task_id AND o.effect_class='ARTIFACT_READ')
             FROM authority_grants g WHERE g.grant_id=?1",
            [&grant_id], |row| Ok((row.get(0)?,row.get(1)?)),
        ).unwrap();
        let completed: i64 = manager.connection.query_row(
            "SELECT COUNT(*) FROM operations WHERE task_id='T-candidate'
             AND effect_class='ARTIFACT_READ' AND state='SUCCEEDED' AND outcome_certainty='COMPLETED'
             AND json_extract(external_receipt,'$.kind')='artifact-reader-admission-delivered'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(completed, 1);
        let cancellation = manager
            .transition(&TransitionRequest {
                schema_version: "0.1".into(),
                transition_id: "transition:fixture-grant-cancel".into(),
                task_id: "T-candidate".into(),
                expected_revision: 3,
                expected_state: TaskState::Runnable,
                to_state: TaskState::Cancelled,
                requested_by: Actor {
                    kind: "system-service".into(),
                    id: "aiosd.coordinator".into(),
                },
                reason: TransitionReason {
                    code: "TASK_CANCELLED".into(),
                    message: None,
                    related_ids: vec![],
                },
                mutation: TaskMutation::default(),
            })
            .unwrap();
        assert!(cancellation.applied, "{cancellation:?}");
        assert_eq!(
            manager
                .get_task("T-candidate")
                .unwrap()
                .unwrap()
                .state
                .as_str(),
            case["facts"]["task_state"]
        );
        let (state, reason, revoked_at): (String, Option<String>, Option<String>) = manager.connection.query_row(
            "SELECT state,revocation_reason_code,revoked_at FROM authority_grants WHERE grant_id=?1",
            [&grant_id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).unwrap();
        assert_eq!(state, case["facts"]["grant_state"]);
        assert_eq!(reason.as_deref(), Some("AUTH_GRANT_REVOKED"));
        assert!(revoked_at.is_some());
        let mut denied = [0xa5_u8; 1];
        let error = reader.read(&mut denied).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(error.to_string(), "ARTIFACT_AUTHORITY_DENIED");
        let inner = error
            .get_ref()
            .unwrap()
            .downcast_ref::<TaskManagerError>()
            .unwrap();
        let denial = inner.authority_denial().unwrap();
        assert_eq!(denial.stage, AuthorityDenialStage::ArtifactRead);
        assert_eq!(denial.reason.code(), case["reason_code"]);
        assert_eq!(denied, [0xa5]);
        assert_eq!(reader.raw_position_for_test().unwrap(), position);
        let error = manager
            .scope_artifact_reads(&session, std::slice::from_ref(&source))
            .unwrap_err();
        let denial = error.authority_denial().unwrap();
        assert_eq!(denial.stage, AuthorityDenialStage::ArtifactAdmission);
        assert_eq!(denial.reason.code(), case["reason_code"]);
        let after_denial: (i64, i64) = manager.connection.query_row(
            "SELECT g.uses_consumed,(SELECT COUNT(*) FROM operations o WHERE o.task_id=g.task_id AND o.effect_class='ARTIFACT_READ')
             FROM authority_grants g WHERE g.grant_id=?1",
            [&grant_id], |row| Ok((row.get(0)?,row.get(1)?)),
        ).unwrap();
        assert_eq!(after_denial, before_denial);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "follows one fixture claim through real admission, policy, grant, binding, and byte read"
    )]
    fn fixture_exact_local_read_allows_only_bound_imported_source() {
        use crate::authority_policy::PolicyEffect;
        let case = authority_case("exact-local-artifact-read-allowed");
        assert_eq!(case["expected"], "ALLOW");
        let claim = case["facts"]["validated_semantic_request"]
            .as_str()
            .unwrap();
        let (action, selector) = claim.split_once(' ').unwrap();
        let principal = case["facts"]["principal"].as_str().unwrap();
        let symbolic_uri = case["facts"]["resolved_resource"].as_str().unwrap();
        let binding = case["facts"]["binding"].as_str().unwrap();
        assert_eq!(case["facts"]["approval"], Value::Null);
        assert_eq!(case["facts"]["policy"], "allow exact selected input");
        let (mut manager, hash, snapshot, registration) =
            fixture_at_mode(None, true, false, Some(principal), false);
        let bytes = b"fixture A17 local source";
        let source = manager
            .import_artifact(
                &ImportArtifactRequest {
                    schema_version: "0.1".into(),
                    import_id: Some("import:fixture-A17".into()),
                    task_id: "T-candidate".into(),
                    origin_kind: ArtifactOriginKind::User,
                    semantic_type: Some("artifact.file@1".into()),
                    media_type: "text/plain".into(),
                    format: None,
                    sensitivity: Sensitivity::Local,
                    retention: RetentionClass::Task,
                    expires_at: None,
                    labels: vec![],
                    max_size_bytes: Some(1024),
                },
                &mut Cursor::new(bytes),
            )
            .unwrap();
        // A17 is a symbolic fixture URI. This public import is its concrete
        // Task input; all runtime admission uses the returned Artifact ID.
        assert_eq!(symbolic_uri, "artifact://A17");
        assert_eq!(
            source.uri.as_str(),
            format!("artifact://{}", source.artifact_id)
        );
        manager
            .create_task(&CreateTask {
                task_id: "T-unbound".into(),
                principal: Actor {
                    kind: "user".into(),
                    id: "user:test".into(),
                },
                workspace_id: None,
                original_intent: "separate source".into(),
                normalized_intent: None,
                active_step_ids: vec![],
            })
            .unwrap();
        let other = manager
            .import_artifact(
                &ImportArtifactRequest {
                    schema_version: "0.1".into(),
                    import_id: Some("import:fixture-other".into()),
                    task_id: "T-unbound".into(),
                    origin_kind: ArtifactOriginKind::User,
                    semantic_type: Some("artifact.file@1".into()),
                    media_type: "text/plain".into(),
                    format: None,
                    sensitivity: Sensitivity::Local,
                    retention: RetentionClass::Task,
                    expires_at: None,
                    labels: vec![],
                    max_size_bytes: Some(1024),
                },
                &mut Cursor::new(b"other source"),
            )
            .unwrap();
        let program_json: String = manager.connection.query_row(
            "SELECT program_json FROM semantic_program_revisions WHERE task_id='T-candidate' AND semantic_hash=?1",
            [&hash], |row| row.get(0),
        ).unwrap();
        let program: Value = serde_json::from_str(&program_json).unwrap();
        assert!(
            program_node(&program, "copy").unwrap()["authority_requests"]
                .as_array()
                .unwrap()
                .iter()
                .any(|request| request["action"] == action && request["resource"] == selector)
        );
        let resources =
            choices_with_source_and_output(&source.artifact_id, "allocation:fixture-A17");
        let contract = contract_hash(&manager, &snapshot);
        manager
            .reserve_authority_candidate(&ReserveAuthorityCandidate {
                candidate_id: "candidate:fixture-A17",
                binding_id: binding,
                attempt_id: "attempt:fixture-A17",
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
            {"effect":"ALLOW","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"}
        ]}).to_string().as_bytes()).unwrap();
        let evaluated = manager
            .evaluate_pending_authority_candidate("candidate:fixture-A17")
            .unwrap();
        let (decision_id, resolved, decision_principal, reason, approval): (String, String, String, String, Option<String>) =
            manager.connection.query_row(
                "SELECT d.decision_id,r.resolved_resource_id,d.principal_id,d.reason_codes_json,d.approval_request_id
                 FROM authority_requests r JOIN policy_decisions d ON d.authority_request_id=r.request_id
                 WHERE r.action=?1 AND r.semantic_selector=?2",
                params![action, selector],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
            ).unwrap();
        assert_eq!(resolved, source.artifact_id);
        assert_eq!(decision_principal, principal);
        assert_eq!(approval, None);
        let read = evaluated
            .decisions
            .iter()
            .find(|d| d.decision_id == decision_id)
            .unwrap();
        assert_eq!(read.effect, PolicyEffect::Allow);
        assert_eq!(read.reason_code, case["reason_code"]);
        assert_eq!(
            serde_json::from_str::<Value>(&reason).unwrap(),
            json!([case["reason_code"]])
        );
        let finalized = manager
            .finalize_pending_authority_candidate("candidate:fixture-A17")
            .unwrap();
        assert_eq!(finalized.binding_id, binding);
        assert_eq!(finalized.grant_ids.len(), 2);
        let (grant_binding, grant_principal, grant_state): (String, String, String) = manager
            .connection
            .query_row(
                "SELECT g.execution_binding_id,g.principal_id,g.state FROM authority_grants g
             WHERE g.policy_decision_id=?1",
                [&decision_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            (
                grant_binding.as_str(),
                grant_principal.as_str(),
                grant_state.as_str()
            ),
            (binding, principal, "ACTIVE")
        );
        let bound_principal: String = manager
            .connection
            .query_row(
                "SELECT provider_id FROM execution_bindings WHERE binding_id=?1",
                [binding],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(bound_principal, principal);
        // Admission selected A17 while it was the unique semantic input. A
        // later legitimate import into the same Task must not widen its grant.
        let unselected = manager
            .import_artifact(
                &ImportArtifactRequest {
                    schema_version: "0.1".into(),
                    import_id: Some("import:fixture-unselected".into()),
                    task_id: "T-candidate".into(),
                    origin_kind: ArtifactOriginKind::User,
                    semantic_type: Some("artifact.file@1".into()),
                    media_type: "text/plain".into(),
                    format: None,
                    sensitivity: Sensitivity::Local,
                    retention: RetentionClass::Task,
                    expires_at: None,
                    labels: vec![],
                    max_size_bytes: Some(1024),
                },
                &mut Cursor::new(b"unselected same-task source"),
            )
            .unwrap();
        for (id, revision, from, to) in [
            (
                "transition:fixture-A17-runnable",
                2,
                TaskState::Planning,
                TaskState::Runnable,
            ),
            (
                "transition:fixture-A17-running",
                3,
                TaskState::Runnable,
                TaskState::Running,
            ),
        ] {
            assert!(
                manager
                    .transition(&TransitionRequest {
                        schema_version: "0.1".into(),
                        transition_id: id.into(),
                        task_id: "T-candidate".into(),
                        expected_revision: revision,
                        expected_state: from,
                        to_state: to,
                        requested_by: Actor {
                            kind: "system-service".into(),
                            id: "aiosd.coordinator".into()
                        },
                        reason: TransitionReason {
                            code: "AUTHORITY_READY".into(),
                            message: None,
                            related_ids: vec![]
                        },
                        mutation: TaskMutation::default(),
                    })
                    .unwrap()
                    .applied
            );
        }
        let session = manager
            .issue_provider_artifact_session("T-candidate", binding)
            .unwrap();
        assert!(
            manager
                .scope_artifact_reads(&session, std::slice::from_ref(&other.artifact_id))
                .is_err()
        );
        assert!(
            manager
                .scope_artifact_reads(&session, std::slice::from_ref(&unselected.artifact_id))
                .is_err()
        );
        let scope = manager
            .scope_artifact_reads(&session, std::slice::from_ref(&source.artifact_id))
            .unwrap();
        assert!(
            manager
                .open_artifact_reader(&scope, &other.artifact_id)
                .is_err()
        );
        assert!(
            manager
                .open_artifact_reader(&scope, &unselected.artifact_id)
                .is_err()
        );
        let mut reader = manager
            .open_artifact_reader(&scope, &source.artifact_id)
            .unwrap();
        let mut delivered = Vec::new();
        reader.read_to_end(&mut delivered).unwrap();
        assert_eq!(delivered, bytes);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "follows one private fixture source and exact destination through evaluation and pending-approval denial"
    )]
    fn fixture_private_egress_requires_approval_before_any_export_authority() {
        use crate::authority_policy::PolicyEffect;
        let case = authority_case("private-data-egress-requires-approval");
        assert_eq!(case["expected"], "REQUIRE_APPROVAL");
        let action = case["facts"]["action"].as_str().unwrap();
        let symbolic_source = case["facts"]["resource"].as_str().unwrap();
        let destination = case["facts"]["destination"].as_str().unwrap();
        let sensitivity = case["facts"]["sensitivity"].as_str().unwrap();
        assert_eq!(symbolic_source, "artifact://METRICS-92");
        assert_eq!(sensitivity, "private");
        let (mut manager, hash, snapshot, registration) =
            fixture_at_mode(None, true, true, None, false);
        let source = manager
            .import_artifact(
                &ImportArtifactRequest {
                    schema_version: "0.1".into(),
                    import_id: Some("import:fixture-METRICS-92".into()),
                    task_id: "T-candidate".into(),
                    origin_kind: ArtifactOriginKind::User,
                    semantic_type: Some("artifact.file@1".into()),
                    media_type: "text/plain".into(),
                    format: None,
                    sensitivity: Sensitivity::Private,
                    retention: RetentionClass::Task,
                    expires_at: None,
                    labels: vec![],
                    max_size_bytes: Some(1024),
                },
                &mut Cursor::new(b"private METRICS-92"),
            )
            .unwrap();
        assert_eq!(
            source.uri.as_str(),
            format!("artifact://{}", source.artifact_id)
        );
        manager
            .register_trusted_export_service(destination, "fixture_remote", "adapter:memory")
            .unwrap();
        let mut resources =
            choices_with_source_and_output(&source.artifact_id, "allocation:fixture-METRICS-92");
        resources.push(CandidateResourceChoice {
            action: action.into(),
            semantic_selector: "destination:fixture_remote".into(),
            handle: CandidateResourceHandle::ExternalExport {
                service_id: destination.into(),
                source_artifact_id: source.artifact_id.clone(),
                operation_id: "export:fixture-METRICS-92".into(),
                purpose: "fixture private analysis".into(),
                max_size_bytes: 1024,
            },
        });
        manager
            .reserve_authority_candidate(&ReserveAuthorityCandidate {
                candidate_id: "candidate:fixture-METRICS-92",
                binding_id: "binding:fixture-METRICS-92",
                attempt_id: "attempt:fixture-METRICS-92",
                task_id: "T-candidate",
                semantic_program_hash: &hash,
                registry_snapshot_id: &snapshot,
                node_id: "copy",
                capability_contract_hash: &contract_hash(&manager, &snapshot),
                provider_registration_id: &registration,
                attempt_number: 1,
                resources: &resources,
            })
            .unwrap();
        let pin = load_current_export_pin(&manager.connection, "candidate:fixture-METRICS-92")
            .unwrap()
            .unwrap();
        assert_eq!(pin.source_artifact_id, source.artifact_id);
        assert_eq!(pin.service_id, destination);
        assert_eq!(pin.sensitivity, sensitivity);
        manager.activate_local_authority_policy(json!({"schema_version":"0.1","rules":[
            {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"private"},
            {"effect":"ALLOW","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"},
            {"effect":"REQUIRE_APPROVAL","action":"data.egress","resource_kind":"external-destination","sensitivity":"private"}
        ]}).to_string().as_bytes()).unwrap();
        let evaluated = manager
            .evaluate_pending_authority_candidate("candidate:fixture-METRICS-92")
            .unwrap();
        let (decision_id, request_json, decision_json, approval_id): (String, String, String, String) =
            manager.connection.query_row(
                "SELECT d.decision_id,r.request_json,d.decision_json,d.approval_request_id
                 FROM authority_requests r JOIN policy_decisions d ON d.authority_request_id=r.request_id
                 WHERE r.action=?1 AND r.semantic_selector='destination:fixture_remote'",
                [action], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
            ).unwrap();
        let decision = evaluated
            .decisions
            .iter()
            .find(|d| d.decision_id == decision_id)
            .unwrap();
        assert_eq!(decision.effect, PolicyEffect::RequireApproval);
        assert_eq!(decision.reason_code, case["reason_code"]);
        assert_eq!(decision.approval_id.as_deref(), Some(approval_id.as_str()));
        let request: Value = serde_json::from_str(&request_json).unwrap();
        let decided: Value = serde_json::from_str(&decision_json).unwrap();
        assert_eq!(request["egress"]["service_id"], destination);
        assert_eq!(request["egress"]["data_refs"], json!([source.artifact_id]));
        assert_eq!(request["resource"]["sensitivity"], sensitivity);
        assert_eq!(decided["decision"], case["expected"]);
        assert_eq!(decided["reason_codes"], json!([case["reason_code"]]));
        assert_eq!(
            decided["resource"]["external_export"]["source_artifact_id"],
            source.artifact_id
        );
        let (status, prompt_json): (String, String) = manager
            .connection
            .query_row(
                "SELECT status,request_json FROM approval_requests WHERE approval_id=?1",
                [&approval_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(status, "PENDING");
        let prompt: Value = serde_json::from_str(&prompt_json).unwrap();
        assert_eq!(prompt["destination"]["service_id"], destination);
        assert_eq!(prompt["export"]["source_artifact_id"], source.artifact_id);
        assert_eq!(prompt["resource"]["sensitivity"], sensitivity);
        assert_eq!(prompt["policy_reason_codes"], json!([case["reason_code"]]));
        assert!(
            manager
                .finalize_pending_authority_candidate("candidate:fixture-METRICS-92")
                .is_err()
        );
        assert!(
            manager
                .issue_provider_artifact_session("T-candidate", "binding:fixture-METRICS-92")
                .is_err()
        );
        for (table, predicate) in [
            (
                "authority_grants",
                "execution_binding_id='binding:fixture-METRICS-92'",
            ),
            (
                "execution_bindings",
                "binding_id='binding:fixture-METRICS-92'",
            ),
            (
                "artifact_output_allocations",
                "allocation_id='allocation:fixture-METRICS-92'",
            ),
            ("operations", "operation_id='export:fixture-METRICS-92'"),
        ] {
            let count: i64 = manager
                .connection
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE {predicate}"),
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 0, "{table} escaped pending approval");
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "loads fixture facts and proves the full authority boundary has no side effects"
    )]
    fn fixture_undeclared_network_claim_is_typed_denial_before_any_authority() {
        let cases: Vec<Value> = serde_json::from_str(include_str!(
            "../../../examples/authority/authority-cases.json"
        ))
        .unwrap();
        let matching: Vec<&Value> = cases
            .iter()
            .filter(|case| case["name"] == "provider-invents-network-action-not-in-semantic-ir")
            .collect();
        assert_eq!(matching.len(), 1);
        let case = matching[0];
        assert_eq!(case["expected"], "DENY");
        let semantic_claim = case["facts"]["validated_semantic_request"]
            .as_str()
            .unwrap();
        let runtime_claim = case["facts"]["runtime_request"].as_str().unwrap();
        let principal = case["facts"]["principal"].as_str().unwrap();
        let (semantic_action, semantic_selector) = semantic_claim.split_once(' ').unwrap();
        let (runtime_action, runtime_service) = runtime_claim.split_once(' ').unwrap();
        assert_eq!(runtime_action, "network.connect");
        assert!(runtime_service.starts_with("service://"));

        let (mut manager, hash, snapshot, registration) =
            fixture_at_mode(None, false, false, Some(principal), true);
        let registered_principal: String = manager
            .connection
            .query_row(
                "SELECT provider_id FROM provider_registrations WHERE registration_id=?1",
                [&registration],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(registered_principal, principal);
        let program_json: String = manager.connection.query_row(
            "SELECT program_json FROM semantic_program_revisions WHERE task_id='T-candidate' AND semantic_hash=?1",
            [&hash], |row| row.get(0),
        ).unwrap();
        let program: Value = serde_json::from_str(&program_json).unwrap();
        let node = program_node(&program, "copy").unwrap();
        let declared = node["authority_requests"].as_array().unwrap();
        assert!(declared.iter().any(|claim| {
            claim["action"] == semantic_action && claim["resource"] == semantic_selector
        }));
        assert!(
            !declared
                .iter()
                .any(|claim| claim["action"] == runtime_action)
        );

        let authority_counts = |manager: &TaskManager| {
            [
                "authority_candidate_reservations",
                "authority_candidate_resources",
                "policy_decisions",
                "authority_grants",
                "execution_bindings",
                "operations",
            ]
            .map(|table| {
                manager
                    .connection
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .unwrap()
            })
        };
        let before = authority_counts(&manager);
        let mut choices = choices();
        choices.push(CandidateResourceChoice {
            action: runtime_action.to_owned(),
            semantic_selector: runtime_service.to_owned(),
            handle: CandidateResourceHandle::NetworkService {
                service_id: runtime_service.to_owned(),
            },
        });
        let error = manager
            .reserve_authority_candidate(&ReserveAuthorityCandidate {
                candidate_id: "candidate:undeclared-network",
                binding_id: "binding:undeclared-network",
                attempt_id: "attempt:undeclared-network",
                task_id: "T-candidate",
                semantic_program_hash: &hash,
                registry_snapshot_id: &snapshot,
                node_id: "copy",
                capability_contract_hash: &contract_hash(&manager, &snapshot),
                provider_registration_id: &registration,
                attempt_number: 1,
                resources: &choices,
            })
            .unwrap_err();
        let denial = error
            .authority_denial()
            .expect("reservation emitted a typed diagnostic");
        assert_eq!(denial.stage, AuthorityDenialStage::CandidateReservation);
        assert_eq!(
            denial.reason,
            AuthorityDenialReason::SemanticRequestMismatch
        );
        assert_eq!(case["reason_code"], denial.reason.code());
        assert_catalog_reason(denial.reason.code());
        assert_eq!(
            error.to_string(),
            "authority candidate reservation is not admissible"
        );
        let after = authority_counts(&manager);
        assert_eq!(
            after, before,
            "denial cannot reserve or issue authority or an effect"
        );
    }

    #[test]
    fn undeclared_network_claim_on_existing_candidate_is_typed_denial() {
        let (mut manager, hash, snapshot, registration) = fixture();
        let contract = contract_hash(&manager, &snapshot);
        let mut choices = choices();
        manager
            .reserve_authority_candidate(&replay_network_request(
                &hash,
                &snapshot,
                &contract,
                &registration,
                &choices,
            ))
            .unwrap();
        let counts = |manager: &TaskManager| {
            [
                "authority_candidate_reservations",
                "authority_candidate_resources",
                "policy_decisions",
                "authority_grants",
                "execution_bindings",
                "operations",
            ]
            .map(|table| {
                manager
                    .connection
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .unwrap()
            })
        };
        let before = counts(&manager);
        choices.push(CandidateResourceChoice {
            action: "network.connect".into(),
            semantic_selector: "service://unrequested".into(),
            handle: CandidateResourceHandle::NetworkService {
                service_id: "service://unrequested".into(),
            },
        });
        let error = manager
            .reserve_authority_candidate(&replay_network_request(
                &hash,
                &snapshot,
                &contract,
                &registration,
                &choices,
            ))
            .unwrap_err();
        assert_eq!(
            error.authority_denial(),
            Some(AuthorityDenial {
                stage: AuthorityDenialStage::CandidateReservation,
                reason: AuthorityDenialReason::SemanticRequestMismatch,
            })
        );
        assert_eq!(counts(&manager), before);
    }

    fn replay_network_request<'a>(
        hash: &'a str,
        snapshot: &'a str,
        contract: &'a str,
        registration: &'a str,
        resources: &'a [CandidateResourceChoice],
    ) -> ReserveAuthorityCandidate<'a> {
        ReserveAuthorityCandidate {
            candidate_id: "candidate:replay-network",
            binding_id: "binding:replay-network",
            attempt_id: "attempt:replay-network",
            task_id: "T-candidate",
            semantic_program_hash: hash,
            registry_snapshot_id: snapshot,
            node_id: "copy",
            capability_contract_hash: contract,
            provider_registration_id: registration,
            attempt_number: 1,
            resources,
        }
    }

    fn choices_with_source(artifact_id: &str) -> Vec<CandidateResourceChoice> {
        choices_with_source_and_output(artifact_id, "allocation:copy")
    }

    fn choices_with_source_and_output(
        artifact_id: &str,
        allocation_id: &str,
    ) -> Vec<CandidateResourceChoice> {
        vec![
            CandidateResourceChoice {
                action: "artifact.read".into(),
                semantic_selector: "input:source".into(),
                handle: CandidateResourceHandle::InputArtifact {
                    artifact_id: artifact_id.into(),
                },
            },
            CandidateResourceChoice {
                action: "artifact.write".into(),
                semantic_selector: "task.output".into(),
                handle: CandidateResourceHandle::OutputAllocation {
                    allocation_id: allocation_id.into(),
                    output_port: "copy".into(),
                },
            },
        ]
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "public-path fixture covers admission, approval, issuance, export, and adversarial substitutions"
    )]
    fn exact_export_candidate_requires_trusted_service_and_pinned_source_read() {
        use crate::artifact_store::ArtifactExportWriter;
        use crate::authority_policy::{AuthenticatedApprover, PolicyEffect};
        struct MemorySink(Arc<std::sync::Mutex<Vec<u8>>>);
        impl Write for MemorySink {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl ArtifactExportWriter for MemorySink {
            fn finalize(&mut self) -> std::io::Result<()> {
                self.flush()
            }
        }
        let (mut manager, hash, snapshot, registration) =
            fixture_at_mode(None, true, true, None, true);
        let bytes = b"private fixture export";
        let imported = manager
            .import_artifact(
                &ImportArtifactRequest {
                    schema_version: "0.1".into(),
                    import_id: Some("import:export-source".into()),
                    task_id: "T-candidate".into(),
                    origin_kind: ArtifactOriginKind::User,
                    semantic_type: Some("artifact.file@1".into()),
                    media_type: "text/plain".into(),
                    format: None,
                    sensitivity: Sensitivity::Private,
                    retention: RetentionClass::Task,
                    expires_at: None,
                    labels: vec![],
                    max_size_bytes: Some(1024),
                },
                &mut Cursor::new(bytes),
            )
            .unwrap();
        manager
            .connection
            .execute(
                "DELETE FROM task_artifacts WHERE task_id='T-candidate'
            AND artifact_id='artifact:source'",
                [],
            )
            .unwrap();
        manager
            .register_trusted_export_service(
                "service://fixture/a",
                "fixture_remote",
                "adapter:memory",
            )
            .unwrap();
        manager
            .register_trusted_export_service(
                "service://fixture/b",
                "fixture_remote",
                "adapter:memory",
            )
            .unwrap();
        assert!(
            manager
                .register_trusted_export_service(
                    "service://fixture/bad",
                    "fixture_remote",
                    "adapter:memory sink"
                )
                .is_err()
        );
        let mut choices =
            choices_with_source_and_output(&imported.artifact_id, "allocation:export");
        choices.push(CandidateResourceChoice {
            action: "data.egress".into(),
            semantic_selector: "destination:fixture_remote".into(),
            handle: CandidateResourceHandle::ExternalExport {
                service_id: "service://fixture/a".into(),
                source_artifact_id: imported.artifact_id.clone(),
                operation_id: "export:exact-a".into(),
                purpose: "fixture evaluation".into(),
                max_size_bytes: 1024,
            },
        });
        let contract = contract_hash(&manager, &snapshot);
        let request = ReserveAuthorityCandidate {
            candidate_id: "candidate:exact-export",
            binding_id: "binding:exact-export",
            attempt_id: "attempt:exact-export",
            task_id: "T-candidate",
            semantic_program_hash: &hash,
            registry_snapshot_id: &snapshot,
            node_id: "copy",
            capability_contract_hash: &contract,
            provider_registration_id: &registration,
            attempt_number: 1,
            resources: &choices,
        };
        let mut missing_read = choices.clone();
        missing_read.remove(0);
        assert!(
            manager
                .reserve_authority_candidate(&ReserveAuthorityCandidate {
                    resources: &missing_read,
                    ..request
                })
                .is_err()
        );
        let mut low_cap = choices.clone();
        if let CandidateResourceHandle::ExternalExport { max_size_bytes, .. } =
            &mut low_cap[2].handle
        {
            *max_size_bytes = 1;
        }
        assert!(
            manager
                .reserve_authority_candidate(&ReserveAuthorityCandidate {
                    resources: &low_cap,
                    ..request
                })
                .is_err()
        );
        let mut unregistered = choices.clone();
        if let CandidateResourceHandle::ExternalExport { service_id, .. } =
            &mut unregistered[2].handle
        {
            *service_id = "service://fixture/unregistered".into();
        }
        assert!(
            manager
                .reserve_authority_candidate(&ReserveAuthorityCandidate {
                    resources: &unregistered,
                    ..request
                })
                .is_err()
        );
        manager
            .connection
            .execute(
                "UPDATE tasks SET constraints_json='{\"privacy\":\"local-only\"}'
            WHERE task_id='T-candidate'",
                [],
            )
            .unwrap();
        assert!(manager.reserve_authority_candidate(&request).is_err());
        manager.connection.execute("UPDATE tasks SET constraints_json='{\"privacy\":\"remote-allowed\",\"preserve_inputs\":true}'
            WHERE task_id='T-candidate'",[]).unwrap();
        let mut substituted = choices.clone();
        if let CandidateResourceHandle::ExternalExport { service_id, .. } =
            &mut substituted[2].handle
        {
            *service_id = "service://fixture/b".into();
        }
        assert!(
            manager
                .reserve_authority_candidate(&ReserveAuthorityCandidate {
                    resources: &substituted,
                    ..request
                })
                .is_ok()
        );
        assert!(
            manager
                .reserve_authority_candidate(&ReserveAuthorityCandidate {
                    resources: &substituted,
                    ..request
                })
                .is_ok()
        );
        let mut changed_action = substituted.clone();
        changed_action[2].action = "artifact.read".into();
        assert!(
            manager
                .reserve_authority_candidate(&ReserveAuthorityCandidate {
                    resources: &changed_action,
                    ..request
                })
                .is_err(),
            "a changed export action must not replay a pending candidate"
        );
        assert!(
            manager
                .reserve_authority_candidate(&ReserveAuthorityCandidate {
                    resources: &substituted,
                    ..request
                })
                .is_ok()
        );
        assert!(
            manager.reserve_authority_candidate(&request).is_err(),
            "same-class service change cannot replay the pending identity"
        );
        manager.activate_local_authority_policy(json!({"schema_version":"0.1","rules":[
            {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"private"},
            {"effect":"ALLOW","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"},
            {"effect":"REQUIRE_APPROVAL","action":"data.egress","resource_kind":"external-destination","sensitivity":"private"}
        ]}).to_string().as_bytes()).unwrap();
        let evaluated = manager
            .evaluate_pending_authority_candidate("candidate:exact-export")
            .unwrap();
        assert_eq!(evaluated.decisions.len(), 3);
        assert_eq!(evaluated.decisions[2].effect, PolicyEffect::RequireApproval);
        assert_eq!(evaluated.decisions[2].reason_code, "AUTH_REQUIRE_APPROVAL");
        let approval = evaluated.decisions[2].approval_id.as_deref().unwrap();
        manager
            .transition(&TransitionRequest {
                schema_version: "0.1".into(),
                transition_id: "transition:export-waiting".into(),
                task_id: "T-candidate".into(),
                expected_revision: 2,
                expected_state: TaskState::Planning,
                to_state: TaskState::WaitingForAuth,
                requested_by: Actor {
                    kind: "system-service".into(),
                    id: "aiosd.coordinator".into(),
                },
                reason: TransitionReason {
                    code: "APPROVAL_REQUIRED".into(),
                    message: None,
                    related_ids: vec![approval.into()],
                },
                mutation: TaskMutation {
                    waiting_on: Some(vec![WaitingOn {
                        kind: WaitingKind::Approval,
                        id: approval.into(),
                        message: None,
                    }]),
                    ..TaskMutation::default()
                },
            })
            .unwrap();
        manager
            .decide_candidate_approval(
                approval,
                &AuthenticatedApprover {
                    principal_id: "user:test",
                },
                true,
            )
            .unwrap();
        let finalized = manager
            .finalize_pending_authority_candidate("candidate:exact-export")
            .unwrap();
        assert_eq!(finalized.grant_ids.len(), 3);
        for (transition_id, revision, from, to) in [
            (
                "transition:export-runnable",
                3,
                TaskState::WaitingForAuth,
                TaskState::Runnable,
            ),
            (
                "transition:export-running",
                4,
                TaskState::Runnable,
                TaskState::Running,
            ),
        ] {
            manager
                .transition(&TransitionRequest {
                    schema_version: "0.1".into(),
                    transition_id: transition_id.into(),
                    task_id: "T-candidate".into(),
                    expected_revision: revision,
                    expected_state: from,
                    to_state: to,
                    requested_by: Actor {
                        kind: "system-service".into(),
                        id: "aiosd.coordinator".into(),
                    },
                    reason: TransitionReason {
                        code: "AUTHORITY_READY".into(),
                        message: None,
                        related_ids: vec![],
                    },
                    mutation: TaskMutation::default(),
                })
                .unwrap();
        }
        let session = manager
            .issue_provider_artifact_session("T-candidate", "binding:exact-export")
            .unwrap();
        let scope = manager
            .scope_artifact_reads(&session, std::slice::from_ref(&imported.artifact_id))
            .unwrap();
        let opens = Arc::new(AtomicUsize::new(0));
        assert!(
            manager
                .issue_bound_artifact_export_destination(
                    &session,
                    &scope,
                    "export:class-only",
                    &imported.artifact_id,
                    "fixture_remote",
                    1024,
                    {
                        let opens = Arc::clone(&opens);
                        move || {
                            opens.fetch_add(1, Ordering::SeqCst);
                            Ok(MemorySink(Arc::new(std::sync::Mutex::new(Vec::new()))))
                        }
                    }
                )
                .is_err(),
            "the production class-only issuer must deny in test builds too"
        );
        assert_eq!(opens.load(Ordering::SeqCst), 0);
        assert!(
            manager
                .issue_exact_bound_artifact_export_destination(
                    &session,
                    &scope,
                    "export:exact-a",
                    &imported.artifact_id,
                    "service://fixture/a",
                    "adapter:memory",
                    {
                        let opens = Arc::clone(&opens);
                        move || {
                            opens.fetch_add(1, Ordering::SeqCst);
                            Ok(MemorySink(Arc::new(std::sync::Mutex::new(Vec::new()))))
                        }
                    }
                )
                .is_err()
        );
        assert_eq!(opens.load(Ordering::SeqCst), 0);
        let sink = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut destination = manager
            .issue_exact_bound_artifact_export_destination(
                &session,
                &scope,
                "export:exact-a",
                &imported.artifact_id,
                "service://fixture/b",
                "adapter:memory",
                {
                    let sink = Arc::clone(&sink);
                    let opens = Arc::clone(&opens);
                    move || {
                        opens.fetch_add(1, Ordering::SeqCst);
                        Ok(MemorySink(sink))
                    }
                },
            )
            .unwrap();
        assert_eq!(opens.load(Ordering::SeqCst), 0);
        assert_eq!(
            manager
                .export_artifact(&scope, &imported.artifact_id, &mut destination)
                .unwrap(),
            u64::try_from(bytes.len()).unwrap()
        );
        assert_eq!(*sink.lock().unwrap(), bytes);
        assert_eq!(opens.load(Ordering::SeqCst), 1);
        for (query, schema) in [
            (
                "SELECT request_json FROM authority_requests WHERE action='data.egress'",
                include_str!("../../../specs/authority-evaluation-request.schema.json"),
            ),
            (
                "SELECT decision_json FROM policy_decisions WHERE action='data.egress'",
                include_str!("../../../specs/policy-decision.schema.json"),
            ),
            (
                "SELECT request_json FROM approval_requests WHERE action='data.egress'",
                include_str!("../../../specs/approval-request.schema.json"),
            ),
            (
                "SELECT binding_json FROM execution_bindings WHERE binding_id='binding:exact-export'",
                include_str!("../../../specs/execution-binding.schema.json"),
            ),
            (
                "SELECT event_json FROM provenance_events WHERE event_type='artifact.exported'",
                include_str!("../../../specs/provenance-event.schema.json"),
            ),
        ] {
            let schema: serde_json::Value = serde_json::from_str(schema).unwrap();
            let validator = jsonschema::options()
                .should_validate_formats(true)
                .build(&schema)
                .unwrap();
            let mut statement = manager.connection.prepare(query).unwrap();
            let documents = statement
                .query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap();
            assert!(!documents.is_empty(), "{query}");
            for document in documents {
                let value: serde_json::Value = serde_json::from_str(&document).unwrap();
                assert!(validator.is_valid(&value), "{query}: {value}");
            }
        }
        assert_eq!(
            manager
                .replay_bound_artifact_export(&session, "export:exact-a")
                .unwrap(),
            u64::try_from(bytes.len()).unwrap()
        );
        manager
            .disable_trusted_export_service("service://fixture/b")
            .unwrap();
        assert!(
            manager
                .issue_exact_bound_artifact_export_destination(
                    &session,
                    &scope,
                    "export:exact-a",
                    &imported.artifact_id,
                    "service://fixture/b",
                    "adapter:memory",
                    {
                        let opens = Arc::clone(&opens);
                        move || {
                            opens.fetch_add(1, Ordering::SeqCst);
                            Ok(MemorySink(Arc::new(std::sync::Mutex::new(Vec::new()))))
                        }
                    }
                )
                .is_err()
        );
        assert_eq!(opens.load(Ordering::SeqCst), 1);
        assert_eq!(
            manager
                .replay_bound_artifact_export(&session, "export:exact-a")
                .unwrap(),
            u64::try_from(bytes.len()).unwrap()
        );
    }

    struct ExactExportFixture {
        _directory: tempfile::TempDir,
        path: std::path::PathBuf,
        manager: TaskManager,
        artifact_id: String,
        grant_ids: Vec<String>,
        session: crate::artifact_store::ProviderArtifactSession,
        scope: crate::artifact_store::ArtifactReadScope,
    }

    #[allow(
        clippy::too_many_lines,
        reason = "sets up one real approved exact export on disk"
    )]
    fn exact_export_fixture() -> ExactExportFixture {
        use crate::authority_policy::AuthenticatedApprover;
        let directory = tempdir().unwrap();
        let path = directory.path().join("exact-export.sqlite3");
        let (mut manager, hash, snapshot, registration) =
            fixture_at_mode(Some(&path), true, true, None, true);
        let imported = manager
            .import_artifact(
                &ImportArtifactRequest {
                    schema_version: "0.1".into(),
                    import_id: Some("import:exact-adversarial".into()),
                    task_id: "T-candidate".into(),
                    origin_kind: ArtifactOriginKind::User,
                    semantic_type: Some("artifact.file@1".into()),
                    media_type: "text/plain".into(),
                    format: None,
                    sensitivity: Sensitivity::Private,
                    retention: RetentionClass::Task,
                    expires_at: None,
                    labels: vec![],
                    max_size_bytes: Some(1024),
                },
                &mut Cursor::new(b"exact private payload"),
            )
            .unwrap();
        manager.connection.execute(
            "DELETE FROM task_artifacts WHERE task_id='T-candidate' AND artifact_id='artifact:source'",
            [],
        ).unwrap();
        manager
            .register_trusted_export_service(
                "service://fixture/exact",
                "fixture_remote",
                "adapter:memory",
            )
            .unwrap();
        let mut resources =
            choices_with_source_and_output(&imported.artifact_id, "allocation:exact-adversarial");
        resources.push(CandidateResourceChoice {
            action: "data.egress".into(),
            semantic_selector: "destination:fixture_remote".into(),
            handle: CandidateResourceHandle::ExternalExport {
                service_id: "service://fixture/exact".into(),
                source_artifact_id: imported.artifact_id.clone(),
                operation_id: "export:exact-adversarial".into(),
                purpose: "adversarial fixture".into(),
                max_size_bytes: 1024,
            },
        });
        manager
            .reserve_authority_candidate(&ReserveAuthorityCandidate {
                candidate_id: "candidate:exact-adversarial",
                binding_id: "binding:exact-adversarial",
                attempt_id: "attempt:exact-adversarial",
                task_id: "T-candidate",
                semantic_program_hash: &hash,
                registry_snapshot_id: &snapshot,
                node_id: "copy",
                capability_contract_hash: &contract_hash(&manager, &snapshot),
                provider_registration_id: &registration,
                attempt_number: 1,
                resources: &resources,
            })
            .unwrap();
        manager.activate_local_authority_policy(json!({"schema_version":"0.1","rules":[
            {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"private"},
            {"effect":"ALLOW","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"},
            {"effect":"REQUIRE_APPROVAL","action":"data.egress","resource_kind":"external-destination","sensitivity":"private"}
        ]}).to_string().as_bytes()).unwrap();
        let evaluation = manager
            .evaluate_pending_authority_candidate("candidate:exact-adversarial")
            .unwrap();
        let approval_id = evaluation.decisions[2].approval_id.clone().unwrap();
        manager
            .transition(&TransitionRequest {
                schema_version: "0.1".into(),
                transition_id: "transition:exact-waiting".into(),
                task_id: "T-candidate".into(),
                expected_revision: 2,
                expected_state: TaskState::Planning,
                to_state: TaskState::WaitingForAuth,
                requested_by: Actor {
                    kind: "system-service".into(),
                    id: "aiosd.coordinator".into(),
                },
                reason: TransitionReason {
                    code: "APPROVAL_REQUIRED".into(),
                    message: None,
                    related_ids: vec![approval_id.clone()],
                },
                mutation: TaskMutation {
                    waiting_on: Some(vec![WaitingOn {
                        kind: WaitingKind::Approval,
                        id: approval_id.clone(),
                        message: None,
                    }]),
                    ..TaskMutation::default()
                },
            })
            .unwrap();
        manager
            .decide_candidate_approval(
                &approval_id,
                &AuthenticatedApprover {
                    principal_id: "user:test",
                },
                true,
            )
            .unwrap();
        let finalized = manager
            .finalize_pending_authority_candidate("candidate:exact-adversarial")
            .unwrap();
        for (id, revision, from, to) in [
            (
                "transition:exact-runnable",
                3,
                TaskState::WaitingForAuth,
                TaskState::Runnable,
            ),
            (
                "transition:exact-running",
                4,
                TaskState::Runnable,
                TaskState::Running,
            ),
        ] {
            manager
                .transition(&TransitionRequest {
                    schema_version: "0.1".into(),
                    transition_id: id.into(),
                    task_id: "T-candidate".into(),
                    expected_revision: revision,
                    expected_state: from,
                    to_state: to,
                    requested_by: Actor {
                        kind: "system-service".into(),
                        id: "aiosd.coordinator".into(),
                    },
                    reason: TransitionReason {
                        code: "AUTHORITY_READY".into(),
                        message: None,
                        related_ids: vec![],
                    },
                    mutation: TaskMutation::default(),
                })
                .unwrap();
        }
        let session = manager
            .issue_provider_artifact_session("T-candidate", "binding:exact-adversarial")
            .unwrap();
        let scope = manager
            .scope_artifact_reads(&session, std::slice::from_ref(&imported.artifact_id))
            .unwrap();
        ExactExportFixture {
            _directory: directory,
            path,
            manager,
            artifact_id: imported.artifact_id,
            grant_ids: finalized.grant_ids,
            session,
            scope,
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "prepares a real exact candidate through authenticated approval before issuance"
    )]
    fn pending_exact_export_fixture() -> (TaskManager, String) {
        use crate::authority_policy::AuthenticatedApprover;
        let (mut manager, hash, snapshot, registration) =
            fixture_at_mode(None, true, true, None, true);
        let imported = manager
            .import_artifact(
                &ImportArtifactRequest {
                    schema_version: "0.1".into(),
                    import_id: Some("import:pending-exact".into()),
                    task_id: "T-candidate".into(),
                    origin_kind: ArtifactOriginKind::User,
                    semantic_type: Some("artifact.file@1".into()),
                    media_type: "text/plain".into(),
                    format: None,
                    sensitivity: Sensitivity::Private,
                    retention: RetentionClass::Task,
                    expires_at: None,
                    labels: vec![],
                    max_size_bytes: Some(1024),
                },
                &mut Cursor::new(b"pending exact export"),
            )
            .unwrap();
        manager.connection.execute("DELETE FROM task_artifacts WHERE task_id='T-candidate' AND artifact_id='artifact:source'", []).unwrap();
        manager
            .register_trusted_export_service(
                "service://fixture/pending",
                "fixture_remote",
                "adapter:memory",
            )
            .unwrap();
        let mut resources =
            choices_with_source_and_output(&imported.artifact_id, "allocation:pending-exact");
        resources.push(CandidateResourceChoice {
            action: "data.egress".into(),
            semantic_selector: "destination:fixture_remote".into(),
            handle: CandidateResourceHandle::ExternalExport {
                service_id: "service://fixture/pending".into(),
                source_artifact_id: imported.artifact_id,
                operation_id: "export:pending-exact".into(),
                purpose: "pending fixture".into(),
                max_size_bytes: 1024,
            },
        });
        manager
            .reserve_authority_candidate(&ReserveAuthorityCandidate {
                candidate_id: "candidate:pending-exact",
                binding_id: "binding:pending-exact",
                attempt_id: "attempt:pending-exact",
                task_id: "T-candidate",
                semantic_program_hash: &hash,
                registry_snapshot_id: &snapshot,
                node_id: "copy",
                capability_contract_hash: &contract_hash(&manager, &snapshot),
                provider_registration_id: &registration,
                attempt_number: 1,
                resources: &resources,
            })
            .unwrap();
        manager.activate_local_authority_policy(json!({"schema_version":"0.1","rules":[
            {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"private"},
            {"effect":"ALLOW","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"},
            {"effect":"REQUIRE_APPROVAL","action":"data.egress","resource_kind":"external-destination","sensitivity":"private"}
        ]}).to_string().as_bytes()).unwrap();
        let evaluated = manager
            .evaluate_pending_authority_candidate("candidate:pending-exact")
            .unwrap();
        let approval = evaluated.decisions[2].approval_id.clone().unwrap();
        manager
            .transition(&TransitionRequest {
                schema_version: "0.1".into(),
                transition_id: "transition:pending-exact-waiting".into(),
                task_id: "T-candidate".into(),
                expected_revision: 2,
                expected_state: TaskState::Planning,
                to_state: TaskState::WaitingForAuth,
                requested_by: Actor {
                    kind: "system-service".into(),
                    id: "aiosd.coordinator".into(),
                },
                reason: TransitionReason {
                    code: "APPROVAL_REQUIRED".into(),
                    message: None,
                    related_ids: vec![approval.clone()],
                },
                mutation: TaskMutation {
                    waiting_on: Some(vec![WaitingOn {
                        kind: WaitingKind::Approval,
                        id: approval.clone(),
                        message: None,
                    }]),
                    ..TaskMutation::default()
                },
            })
            .unwrap();
        manager
            .decide_candidate_approval(
                &approval,
                &AuthenticatedApprover {
                    principal_id: "user:test",
                },
                true,
            )
            .unwrap();
        (manager, approval)
    }

    #[test]
    fn exact_export_finalization_rechecks_policy_and_approval_freshness() {
        use crate::authority_policy::AuthenticatedApprover;
        for scenario in ["policy", "policy-reactivation", "approval"] {
            let (mut manager, approval) = pending_exact_export_fixture();
            match scenario {
                "policy" => {
                    manager.activate_local_authority_policy(json!({"schema_version":"0.1","rules":[
                    {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"private"},
                    {"effect":"ALLOW","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"},
                    {"effect":"DENY","action":"data.egress","resource_kind":"external-destination","sensitivity":"private"}
                ]}).to_string().as_bytes()).unwrap();
                }
                "policy-reactivation" => {
                    manager.activate_local_authority_policy(json!({"schema_version":"0.1","rules":[
                        {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"private"},
                        {"effect":"ALLOW","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"},
                        {"effect":"REQUIRE_APPROVAL","action":"data.egress","resource_kind":"external-destination","sensitivity":"private"}
                    ]}).to_string().as_bytes()).unwrap();
                }
                "approval" => {
                    manager
                        .revoke_candidate_approval(
                            &approval,
                            &AuthenticatedApprover {
                                principal_id: "user:test",
                            },
                        )
                        .unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                manager
                    .finalize_pending_authority_candidate("candidate:pending-exact")
                    .is_err(),
                "{scenario}"
            );
            for table in ["authority_grants", "execution_bindings"] {
                let count: i64 = manager
                    .connection
                    .query_row(
                        &format!("SELECT COUNT(*) FROM {table} WHERE task_id='T-candidate'"),
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(count, 0, "{scenario} issued {table}");
            }
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "retained handles are checked against each independently withdrawn authority"
    )]
    fn retained_exact_export_denies_changed_service_approval_policy_or_read_grant() {
        use crate::authority_policy::AuthenticatedApprover;
        for scenario in ["service", "approval", "policy", "read-grant"] {
            let (mut manager, hash, snapshot, registration) =
                fixture_at_mode(None, true, true, None, true);
            let imported = manager
                .import_artifact(
                    &ImportArtifactRequest {
                        schema_version: "0.1".into(),
                        import_id: Some(format!("import:{scenario}")),
                        task_id: "T-candidate".into(),
                        origin_kind: ArtifactOriginKind::User,
                        semantic_type: Some("artifact.file@1".into()),
                        media_type: "text/plain".into(),
                        format: None,
                        sensitivity: Sensitivity::Private,
                        retention: RetentionClass::Task,
                        expires_at: None,
                        labels: vec![],
                        max_size_bytes: Some(1024),
                    },
                    &mut Cursor::new(b"retained private data"),
                )
                .unwrap();
            manager
                .connection
                .execute(
                    "DELETE FROM task_artifacts WHERE task_id='T-candidate'
                AND artifact_id='artifact:source'",
                    [],
                )
                .unwrap();
            manager
                .register_trusted_export_service(
                    "service://fixture/retained",
                    "fixture_remote",
                    "adapter:memory",
                )
                .unwrap();
            let mut resources =
                choices_with_source_and_output(&imported.artifact_id, "allocation:retained");
            resources.push(CandidateResourceChoice {
                action: "data.egress".into(),
                semantic_selector: "destination:fixture_remote".into(),
                handle: CandidateResourceHandle::ExternalExport {
                    service_id: "service://fixture/retained".into(),
                    source_artifact_id: imported.artifact_id.clone(),
                    operation_id: format!("export:retained:{scenario}"),
                    purpose: "retained fixture".into(),
                    max_size_bytes: 1024,
                },
            });
            let contract = contract_hash(&manager, &snapshot);
            manager
                .reserve_authority_candidate(&ReserveAuthorityCandidate {
                    candidate_id: "candidate:retained",
                    binding_id: "binding:retained",
                    attempt_id: "attempt:retained",
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
                {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"private"},
                {"effect":"ALLOW","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"},
                {"effect":"REQUIRE_APPROVAL","action":"data.egress","resource_kind":"external-destination","sensitivity":"private"}
            ]}).to_string().as_bytes()).unwrap();
            let evaluation = manager
                .evaluate_pending_authority_candidate("candidate:retained")
                .unwrap();
            let approval = evaluation.decisions[2].approval_id.as_deref().unwrap();
            manager
                .transition(&TransitionRequest {
                    schema_version: "0.1".into(),
                    transition_id: "transition:retained-waiting".into(),
                    task_id: "T-candidate".into(),
                    expected_revision: 2,
                    expected_state: TaskState::Planning,
                    to_state: TaskState::WaitingForAuth,
                    requested_by: Actor {
                        kind: "system-service".into(),
                        id: "aiosd.coordinator".into(),
                    },
                    reason: TransitionReason {
                        code: "APPROVAL_REQUIRED".into(),
                        message: None,
                        related_ids: vec![approval.into()],
                    },
                    mutation: TaskMutation {
                        waiting_on: Some(vec![WaitingOn {
                            kind: WaitingKind::Approval,
                            id: approval.into(),
                            message: None,
                        }]),
                        ..TaskMutation::default()
                    },
                })
                .unwrap();
            manager
                .decide_candidate_approval(
                    approval,
                    &AuthenticatedApprover {
                        principal_id: "user:test",
                    },
                    true,
                )
                .unwrap();
            let finalized = manager
                .finalize_pending_authority_candidate("candidate:retained")
                .unwrap();
            for (id, revision, from, to) in [
                (
                    "transition:retained-runnable",
                    3,
                    TaskState::WaitingForAuth,
                    TaskState::Runnable,
                ),
                (
                    "transition:retained-running",
                    4,
                    TaskState::Runnable,
                    TaskState::Running,
                ),
            ] {
                manager
                    .transition(&TransitionRequest {
                        schema_version: "0.1".into(),
                        transition_id: id.into(),
                        task_id: "T-candidate".into(),
                        expected_revision: revision,
                        expected_state: from,
                        to_state: to,
                        requested_by: Actor {
                            kind: "system-service".into(),
                            id: "aiosd.coordinator".into(),
                        },
                        reason: TransitionReason {
                            code: "AUTHORITY_READY".into(),
                            message: None,
                            related_ids: vec![],
                        },
                        mutation: TaskMutation::default(),
                    })
                    .unwrap();
            }
            let session = manager
                .issue_provider_artifact_session("T-candidate", "binding:retained")
                .unwrap();
            let scope = manager
                .scope_artifact_reads(&session, std::slice::from_ref(&imported.artifact_id))
                .unwrap();
            let opens = Arc::new(AtomicUsize::new(0));
            let mut destination = manager
                .issue_exact_bound_artifact_export_destination(
                    &session,
                    &scope,
                    &format!("export:retained:{scenario}"),
                    &imported.artifact_id,
                    "service://fixture/retained",
                    "adapter:memory",
                    {
                        let opens = Arc::clone(&opens);
                        move || {
                            opens.fetch_add(1, Ordering::SeqCst);
                            Ok(Vec::<u8>::new())
                        }
                    },
                )
                .unwrap();
            match scenario {
                "service" => manager
                    .disable_trusted_export_service("service://fixture/retained")
                    .unwrap(),
                "approval" => manager
                    .revoke_candidate_approval(
                        approval,
                        &AuthenticatedApprover {
                            principal_id: "user:test",
                        },
                    )
                    .unwrap(),
                "policy" => {
                    manager.activate_local_authority_policy(json!({"schema_version":"0.1","rules":[
                    {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"private"},
                    {"effect":"ALLOW","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"},
                    {"effect":"DENY","action":"data.egress","resource_kind":"external-destination","sensitivity":"private"}
                ]}).to_string().as_bytes()).unwrap();
                }
                "read-grant" => {
                    let read_grant = &finalized.grant_ids[0];
                    manager
                        .connection
                        .execute(
                            "UPDATE authority_grants SET state='REVOKED',
                        revoked_at=?2,revocation_reason_code='TEST_REVOKED' WHERE grant_id=?1",
                            params![read_grant, NOW],
                        )
                        .unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                manager
                    .export_artifact(&scope, &imported.artifact_id, &mut destination)
                    .is_err(),
                "{scenario} must stop a retained export before any destination effect"
            );
            assert_eq!(
                opens.load(Ordering::SeqCst),
                0,
                "{scenario} opened a destination"
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "real export callbacks prove withdrawal after an external effect"
    )]
    fn exact_export_withdrawal_after_construction_and_bytes_stops_later_callbacks() {
        use crate::artifact_store::{
            ArtifactExportWriter, ExactExportTestPhase, install_exact_export_test_hook,
        };
        struct CountingSink {
            bytes: Arc<std::sync::Mutex<Vec<u8>>>,
            flushes: Arc<AtomicUsize>,
            finalizes: Arc<AtomicUsize>,
            partial: bool,
        }
        impl Write for CountingSink {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                let count = if self.partial { 1 } else { bytes.len() };
                self.bytes
                    .lock()
                    .unwrap()
                    .extend_from_slice(&bytes[..count]);
                Ok(count)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.flushes.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }
        impl ArtifactExportWriter for CountingSink {
            fn finalize(&mut self) -> std::io::Result<()> {
                self.finalizes.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }
        for phase in ["after-write", "pre-flush", "pre-finalize"] {
            let mut fixture = exact_export_fixture();
            let bytes = Arc::new(std::sync::Mutex::new(Vec::new()));
            let flushes = Arc::new(AtomicUsize::new(0));
            let finalizes = Arc::new(AtomicUsize::new(0));
            let opens = Arc::new(AtomicUsize::new(0));
            let mut destination = fixture
                .manager
                .issue_exact_bound_artifact_export_destination(
                    &fixture.session,
                    &fixture.scope,
                    "export:exact-adversarial",
                    &fixture.artifact_id,
                    "service://fixture/exact",
                    "adapter:memory",
                    {
                        let bytes = Arc::clone(&bytes);
                        let flushes = Arc::clone(&flushes);
                        let finalizes = Arc::clone(&finalizes);
                        let opens = Arc::clone(&opens);
                        move || {
                            opens.fetch_add(1, Ordering::SeqCst);
                            Ok(CountingSink {
                                bytes,
                                flushes,
                                finalizes,
                                partial: phase == "after-write",
                            })
                        }
                    },
                )
                .unwrap();
            let path = fixture.path.clone();
            let grant = fixture.grant_ids[0].clone();
            install_exact_export_test_hook(
                match phase {
                    "after-write" => ExactExportTestPhase::AfterWrite,
                    "pre-flush" => ExactExportTestPhase::PreFlush,
                    "pre-finalize" => ExactExportTestPhase::PreFinalize,
                    _ => unreachable!(),
                },
                move || {
                    rusqlite::Connection::open(path)?.execute(
                        "UPDATE authority_grants SET state='REVOKED',revoked_at=?2,
                     revocation_reason_code='TEST_REVOKED' WHERE grant_id=?1",
                        rusqlite::params![grant, NOW],
                    )?;
                    Ok(())
                },
            );
            assert!(
                matches!(
                    fixture.manager.export_artifact(
                        &fixture.scope,
                        &fixture.artifact_id,
                        &mut destination
                    ),
                    Err(crate::TaskManagerError::InvalidRecord(
                        "ARTIFACT_EXPORT_OUTCOME_UNKNOWN"
                    ))
                ),
                "{phase}"
            );
            assert_eq!(opens.load(Ordering::SeqCst), 1, "{phase}");
            assert_eq!(
                bytes.lock().unwrap().len(),
                if phase == "after-write" {
                    1
                } else {
                    b"exact private payload".len()
                },
                "{phase}"
            );
            assert_eq!(
                flushes.load(Ordering::SeqCst),
                usize::from(phase == "pre-finalize"),
                "{phase}"
            );
            assert_eq!(finalizes.load(Ordering::SeqCst), 0, "{phase}");
            let state: String = fixture.manager.connection.query_row(
                "SELECT state || ':' || outcome_certainty FROM operations WHERE operation_id='export:exact-adversarial'",
                [], |row| row.get(0),
            ).unwrap();
            assert_eq!(state, "UNKNOWN:OUTCOME_UNKNOWN", "{phase}");
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "checks the exact authority tuple in each durable artifact and at writer use"
    )]
    fn exact_export_grant_tuple_substitution_never_opens_writer() {
        for field in [
            "source_artifact_id",
            "operation_id",
            "adapter_id",
            "max_size_bytes",
        ] {
            let mut fixture = exact_export_fixture();
            let expected = json!(
                load_current_export_pin(&fixture.manager.connection, "candidate:exact-adversarial")
                    .unwrap()
                    .unwrap()
            );
            for (query, key) in [
                (
                    "SELECT decision_json FROM policy_decisions WHERE action='data.egress'",
                    "resource",
                ),
                (
                    "SELECT request_json FROM approval_requests WHERE action='data.egress'",
                    "export",
                ),
                (
                    "SELECT grants_json FROM authority_grants WHERE grant_id=?1",
                    "grant",
                ),
            ] {
                let raw: String = if key == "grant" {
                    fixture
                        .manager
                        .connection
                        .query_row(query, [&fixture.grant_ids[2]], |row| row.get(0))
                        .unwrap()
                } else {
                    fixture
                        .manager
                        .connection
                        .query_row(query, [], |row| row.get(0))
                        .unwrap()
                };
                let value: Value = serde_json::from_str(&raw).unwrap();
                let actual = match key {
                    "resource" => &value["resource"]["external_export"],
                    "export" => &value["export"],
                    "grant" => &value[0]["external_export"],
                    _ => unreachable!(),
                };
                assert_eq!(actual, &expected, "{key} must seal the entire tuple");
            }
            let opens = Arc::new(AtomicUsize::new(0));
            let mut destination = fixture
                .manager
                .issue_exact_bound_artifact_export_destination(
                    &fixture.session,
                    &fixture.scope,
                    "export:exact-adversarial",
                    &fixture.artifact_id,
                    "service://fixture/exact",
                    "adapter:memory",
                    {
                        let opens = Arc::clone(&opens);
                        move || {
                            opens.fetch_add(1, Ordering::SeqCst);
                            Ok(Vec::<u8>::new())
                        }
                    },
                )
                .unwrap();
            let raw: String = fixture
                .manager
                .connection
                .query_row(
                    "SELECT grants_json FROM authority_grants WHERE grant_id=?1",
                    [&fixture.grant_ids[2]],
                    |row| row.get(0),
                )
                .unwrap();
            let mut grant: Value = serde_json::from_str(&raw).unwrap();
            grant[0]["external_export"][field] = match field {
                "source_artifact_id" => json!("artifact:substituted"),
                "operation_id" => json!("export:substituted"),
                "adapter_id" => json!("adapter:substituted"),
                "max_size_bytes" => json!(2048),
                _ => unreachable!(),
            };
            let replacement = canonical_json(&grant).unwrap();
            assert!(
                fixture
                    .manager
                    .connection
                    .execute(
                        "UPDATE authority_grants SET grants_json=?2 WHERE grant_id=?1",
                        rusqlite::params![fixture.grant_ids[2], replacement],
                    )
                    .is_err(),
                "durable grant guard must reject {field}"
            );
            // Deliberately disable the storage guard to probe the independent use fence.
            fixture
                .manager
                .connection
                .execute_batch("DROP TRIGGER authority_grant_deadline_grant_identity_guard")
                .unwrap();
            fixture
                .manager
                .connection
                .execute(
                    "UPDATE authority_grants SET grants_json=?2 WHERE grant_id=?1",
                    rusqlite::params![fixture.grant_ids[2], replacement],
                )
                .unwrap();
            assert!(
                fixture
                    .manager
                    .export_artifact(&fixture.scope, &fixture.artifact_id, &mut destination)
                    .is_err(),
                "{field}"
            );
            assert_eq!(opens.load(Ordering::SeqCst), 0, "{field}");
        }
    }

    #[test]
    fn exact_export_response_loss_replays_after_disk_restart_without_second_writer() {
        use crate::artifact_store::{ExactExportTestPhase, install_exact_export_test_hook};
        let mut fixture = exact_export_fixture();
        let opens = Arc::new(AtomicUsize::new(0));
        let mut destination = fixture
            .manager
            .issue_exact_bound_artifact_export_destination(
                &fixture.session,
                &fixture.scope,
                "export:exact-adversarial",
                &fixture.artifact_id,
                "service://fixture/exact",
                "adapter:memory",
                {
                    let opens = Arc::clone(&opens);
                    move || {
                        opens.fetch_add(1, Ordering::SeqCst);
                        Ok(Vec::<u8>::new())
                    }
                },
            )
            .unwrap();
        install_exact_export_test_hook(ExactExportTestPhase::CompletionCommitResult, || {
            Err(crate::TaskManagerError::InvalidRecord(
                "injected response loss",
            ))
        });
        assert_eq!(
            fixture
                .manager
                .export_artifact(&fixture.scope, &fixture.artifact_id, &mut destination)
                .unwrap(),
            21
        );
        assert_eq!(opens.load(Ordering::SeqCst), 1);
        assert_eq!(
            fixture
                .manager
                .replay_bound_artifact_export(&fixture.session, "export:exact-adversarial")
                .unwrap(),
            21
        );
        // fixture_at_mode sets Task privacy by direct SQL for export admission, while the
        // pre-existing creation provenance records null. Restore that original provenanced
        // value only after export; completed-operation replay cannot renew export authority.
        fixture
            .manager
            .connection
            .execute(
                "UPDATE tasks SET constraints_json=NULL WHERE task_id='T-candidate'",
                [],
            )
            .unwrap();
        let path = fixture.path.clone();
        let artifact_id = fixture.artifact_id.clone();
        drop(destination);
        let ExactExportFixture {
            _directory,
            manager,
            session,
            scope,
            ..
        } = fixture;
        drop(scope);
        drop(session);
        drop(manager);
        let reopened = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        let session = reopened
            .issue_provider_artifact_session("T-candidate", "binding:exact-adversarial")
            .unwrap();
        assert_eq!(
            reopened
                .replay_bound_artifact_export(&session, "export:exact-adversarial")
                .unwrap(),
            21
        );
        assert!(
            reopened
                .scope_artifact_reads(&session, &[artifact_id])
                .is_err(),
            "one-shot read is consumed"
        );
        assert_eq!(opens.load(Ordering::SeqCst), 1);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "checks both retained-handle cancellation and unresolved-effect containment through Task transitions"
    )]
    fn cancelling_exact_export_revokes_issued_grants_but_cannot_hide_unresolved_export() {
        use crate::artifact_store::{
            ArtifactExportWriter, ExactExportTestPhase, install_exact_export_test_hook,
        };
        struct CancelledSink(Arc<AtomicUsize>);
        impl Write for CancelledSink {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.fetch_add(bytes.len(), Ordering::SeqCst);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl ArtifactExportWriter for CancelledSink {
            fn finalize(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let cancel = |revision, state| TransitionRequest {
            schema_version: "0.1".into(),
            transition_id: "transition:exact-cancel".into(),
            task_id: "T-candidate".into(),
            expected_revision: revision,
            expected_state: state,
            to_state: TaskState::Cancelled,
            requested_by: Actor {
                kind: "system-service".into(),
                id: "aiosd.coordinator".into(),
            },
            reason: TransitionReason {
                code: "TASK_CANCELLED".into(),
                message: None,
                related_ids: vec![],
            },
            mutation: TaskMutation::default(),
        };
        let (mut ready, _) = pending_exact_export_fixture();
        let finalized = ready
            .finalize_pending_authority_candidate("candidate:pending-exact")
            .unwrap();
        assert_eq!(finalized.grant_ids.len(), 3);
        let runnable = ready
            .transition(&TransitionRequest {
                schema_version: "0.1".into(),
                transition_id: "transition:pending-exact-runnable".into(),
                task_id: "T-candidate".into(),
                expected_revision: 3,
                expected_state: TaskState::WaitingForAuth,
                to_state: TaskState::Runnable,
                requested_by: Actor {
                    kind: "system-service".into(),
                    id: "aiosd.coordinator".into(),
                },
                reason: TransitionReason {
                    code: "AUTHORITY_READY".into(),
                    message: None,
                    related_ids: vec![],
                },
                mutation: TaskMutation::default(),
            })
            .unwrap();
        assert!(runnable.applied, "{runnable:?}");
        let pin = load_current_export_pin(&ready.connection, "candidate:pending-exact")
            .unwrap()
            .unwrap();
        let session = ready
            .issue_provider_artifact_session("T-candidate", "binding:pending-exact")
            .unwrap();
        let scope = ready
            .scope_artifact_reads(&session, std::slice::from_ref(&pin.source_artifact_id))
            .unwrap();
        let cancelled_opens = Arc::new(AtomicUsize::new(0));
        let cancelled_bytes = Arc::new(AtomicUsize::new(0));
        let mut retained = ready
            .issue_exact_bound_artifact_export_destination(
                &session,
                &scope,
                &pin.operation_id,
                &pin.source_artifact_id,
                &pin.service_id,
                &pin.adapter_id,
                {
                    let opens = Arc::clone(&cancelled_opens);
                    let bytes = Arc::clone(&cancelled_bytes);
                    move || {
                        opens.fetch_add(1, Ordering::SeqCst);
                        Ok(CancelledSink(bytes))
                    }
                },
            )
            .unwrap();
        let cancelled = ready.transition(&cancel(4, TaskState::Runnable)).unwrap();
        assert!(cancelled.applied, "{cancelled:?}");
        assert_eq!(
            ready.get_task("T-candidate").unwrap().unwrap().state,
            TaskState::Cancelled
        );
        let revoked: i64 = ready.connection.query_row(
            "SELECT COUNT(*) FROM authority_grants WHERE task_id='T-candidate' AND state='REVOKED' AND revoked_at IS NOT NULL",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(revoked, 3);
        assert!(
            ready
                .export_artifact(&scope, &pin.source_artifact_id, &mut retained)
                .is_err()
        );
        assert_eq!(cancelled_opens.load(Ordering::SeqCst), 0);
        assert_eq!(cancelled_bytes.load(Ordering::SeqCst), 0);

        let mut fixture = exact_export_fixture();
        let opens = Arc::new(AtomicUsize::new(0));
        let mut destination = fixture
            .manager
            .issue_exact_bound_artifact_export_destination(
                &fixture.session,
                &fixture.scope,
                "export:exact-adversarial",
                &fixture.artifact_id,
                "service://fixture/exact",
                "adapter:memory",
                {
                    let opens = Arc::clone(&opens);
                    move || {
                        opens.fetch_add(1, Ordering::SeqCst);
                        Ok(Vec::<u8>::new())
                    }
                },
            )
            .unwrap();
        install_exact_export_test_hook(ExactExportTestPhase::AfterArm, || {
            Err(crate::TaskManagerError::InvalidRecord(
                "injected response loss after arm",
            ))
        });
        assert!(
            fixture
                .manager
                .export_artifact(&fixture.scope, &fixture.artifact_id, &mut destination)
                .is_err()
        );
        assert_eq!(opens.load(Ordering::SeqCst), 0);
        let state: String = fixture
            .manager
            .connection
            .query_row(
                "SELECT state FROM operations WHERE operation_id='export:exact-adversarial'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "STARTED");
        let rejected = fixture
            .manager
            .transition(&cancel(5, TaskState::Running))
            .unwrap();
        assert!(!rejected.applied);
        assert_eq!(rejected.reason_code, "TASK_TRANSITION_GUARD_FAILED");
        let active: i64 = fixture.manager.connection.query_row(
            "SELECT COUNT(*) FROM authority_grants WHERE task_id='T-candidate' AND state='ACTIVE'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(active, 2);
        let consumed: i64 = fixture.manager.connection.query_row(
            "SELECT COUNT(*) FROM authority_grants WHERE task_id='T-candidate' AND state='CONSUMED'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(consumed, 1);
    }

    fn assert_catalog_reason(code: &str) {
        let catalog: Value =
            serde_json::from_str(include_str!("../../../specs/authority-reason-codes.json"))
                .unwrap();
        assert!(
            catalog["codes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["code"] == code),
            "reason code is absent from authority catalog: {code}"
        );
    }

    fn assert_policy_decision_reason(
        manager: &TaskManager,
        decision_id: &str,
        expected_effect: &str,
        expected_code: &str,
    ) {
        let (effect, codes, body): (String, String, String) = manager
            .connection
            .query_row(
                "SELECT decision,reason_codes_json,decision_json FROM policy_decisions WHERE decision_id=?1",
                [decision_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let codes: Value = serde_json::from_str(&codes).unwrap();
        let body: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(effect, expected_effect);
        assert_eq!(body["decision"], expected_effect);
        assert_eq!(codes, json!([expected_code]));
        assert_eq!(body["reason_codes"], codes);
        assert_catalog_reason(expected_code);
    }

    fn assert_approval_request_reason(manager: &TaskManager, approval_id: &str) {
        let body: String = manager
            .connection
            .query_row(
                "SELECT request_json FROM approval_requests WHERE approval_id=?1",
                [approval_id],
                |row| row.get(0),
            )
            .unwrap();
        let body: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            body["policy_reason_codes"],
            json!(["AUTH_REQUIRE_APPROVAL"])
        );
        assert_catalog_reason("AUTH_REQUIRE_APPROVAL");
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
        assert_eq!(initial.decisions[0].reason_code, "AUTH_ALLOW");
        assert_eq!(initial.decisions[1].reason_code, "AUTH_REQUIRE_APPROVAL");
        assert_policy_decision_reason(
            &manager,
            &initial.decisions[0].decision_id,
            "ALLOW",
            "AUTH_ALLOW",
        );
        assert_policy_decision_reason(
            &manager,
            &initial.decisions[1].decision_id,
            "REQUIRE_APPROVAL",
            "AUTH_REQUIRE_APPROVAL",
        );
        let approval = initial.decisions[1].approval_id.as_deref().unwrap();
        assert_approval_request_reason(&manager, approval);
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
        assert_policy_decision_reason(
            &manager,
            &approved.decisions[1].decision_id,
            "ALLOW",
            "AUTH_REQUIRE_APPROVAL",
        );
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
        assert!(crate::approval_not_withdrawn(&manager.connection, Some(approval)).unwrap());
        manager
            .revoke_candidate_approval(
                approval,
                &AuthenticatedApprover {
                    principal_id: "user:test",
                },
            )
            .unwrap();
        assert!(!crate::approval_not_withdrawn(&manager.connection, Some(approval)).unwrap());
        let first_withdrawal: String = manager
            .connection
            .query_row(
                "SELECT revoked_at FROM authority_approval_bindings WHERE approval_id=?1",
                [approval],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            manager
                .revoke_candidate_approval(
                    approval,
                    &AuthenticatedApprover {
                        principal_id: "user:wrong",
                    },
                )
                .is_err()
        );
        manager
            .revoke_candidate_approval(
                approval,
                &AuthenticatedApprover {
                    principal_id: "user:test",
                },
            )
            .unwrap();
        let replayed_withdrawal: String = manager
            .connection
            .query_row(
                "SELECT revoked_at FROM authority_approval_bindings WHERE approval_id=?1",
                [approval],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(replayed_withdrawal, first_withdrawal);
        let (status, decision): (String, String) = manager
            .connection
            .query_row(
                "SELECT a.status,d.decision FROM approval_requests a
                 JOIN approval_decisions d USING(approval_id) WHERE a.approval_id=?1",
                [approval],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            (status.as_str(), decision.as_str()),
            ("APPROVED", "APPROVE")
        );
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
        assert_eq!(hard.decisions[1].reason_code, "AUTH_DENY_POLICY");
        assert_policy_decision_reason(
            &manager,
            &hard.decisions[1].decision_id,
            "DENY",
            "AUTH_DENY_POLICY",
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
            .activate_local_authority_policy(
                json!({"schema_version":"0.1","rules":[
                    {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"local"}
                ]})
                .to_string()
                .as_bytes(),
            )
            .unwrap();
        let default_denied = manager
            .evaluate_pending_authority_candidate("candidate:policy")
            .unwrap();
        assert_policy_decision_reason(
            &manager,
            &default_denied.decisions[1].decision_id,
            "DENY",
            "AUTH_DENY_DEFAULT",
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
        assert_policy_decision_reason(
            &manager,
            &denied.decisions[1].decision_id,
            "DENY",
            "AUTH_APPROVAL_DENIED",
        );
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
    #[allow(
        clippy::too_many_lines,
        reason = "exercises the complete issuance sequence and rollback in one transaction"
    )]
    fn grant_deadline_and_exact_binding_join_one_rollback_boundary() {
        use crate::artifact_store::{OutputAllocationRequest, RetentionClass, Sensitivity};
        let (mut manager, hash, snapshot, registration) = fixture();
        let contract = contract_hash(&manager, &snapshot);
        manager
            .reserve_authority_candidate(&ReserveAuthorityCandidate {
                candidate_id: "candidate:issuance-rollback",
                binding_id: "binding:issuance-rollback",
                attempt_id: "attempt:issuance-rollback",
                task_id: "T-candidate",
                semantic_program_hash: &hash,
                registry_snapshot_id: &snapshot,
                node_id: "copy",
                capability_contract_hash: &contract,
                provider_registration_id: &registration,
                attempt_number: 1,
                resources: &choices(),
            })
            .unwrap();
        manager.activate_local_authority_policy(json!({"schema_version":"0.1","rules":[
            {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"local"},
            {"effect":"ALLOW","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"}
        ]}).to_string().as_bytes()).unwrap();
        let evaluated = manager
            .evaluate_pending_authority_candidate("candidate:issuance-rollback")
            .unwrap();
        let decisions: Vec<String> = evaluated
            .decisions
            .iter()
            .map(|d| d.decision_id.clone())
            .collect();
        let owner = manager.lease_owner.clone();
        let epoch = manager.lease_epoch;
        let result = crate::trusted_time::with_protected_observation(
            &manager.connection,
            &manager.clock,
            |tx, time| {
                let grants = TaskManager::issue_candidate_grants_in(
                    tx,
                    "candidate:issuance-rollback",
                    &evaluated,
                    time,
                    &owner,
                    epoch,
                )?;
                insert_reserved_binding_in(
                    tx,
                    "candidate:issuance-rollback",
                    &decisions,
                    &grants,
                    time.now(),
                )?;
                insert_reserved_ready_step_in(tx, "candidate:issuance-rollback", time.now())?;
                assert_eq!(grants.len(), 2);
                let expires_at: String = tx.query_row(
                    "SELECT expires_at FROM authority_grants WHERE grant_id=?1",
                    [&grants[1]],
                    |row| row.get(0),
                )?;
                let allocation = OutputAllocationRequest {
                    schema_version: "0.1".into(),
                    allocation_id: "allocation:copy".into(),
                    task_id: "T-candidate".into(),
                    semantic_program_hash: hash.clone(),
                    node_id: "copy".into(),
                    binding_id: Some("binding:issuance-rollback".into()),
                    attempt_id: Some("attempt:issuance-rollback".into()),
                    output_port: Some("copy".into()),
                    expected_semantic_type: Some("artifact.file@1".into()),
                    allowed_media_types: vec![],
                    max_size_bytes: Some(8 * 1024 * 1024),
                    sensitivity: Sensitivity::Private,
                    retention: RetentionClass::Task,
                    expires_at,
                };
                for bad in [
                    OutputAllocationRequest {
                        allocation_id: "allocation:wrong".into(),
                        ..allocation.clone()
                    },
                    OutputAllocationRequest {
                        output_port: Some("wrong".into()),
                        ..allocation.clone()
                    },
                ] {
                    assert!(
                        TaskManager::allocate_reserved_candidate_output_in(
                            tx,
                            "candidate:issuance-rollback",
                            &bad,
                            time,
                            &owner,
                            epoch,
                        )
                        .is_err()
                    );
                }
                assert!(tx.execute(
                    "UPDATE authority_candidate_status SET state='FINALIZED',revision=revision+1
                     WHERE candidate_id='candidate:issuance-rollback' AND state='PENDING'",
                    [],
                ).is_err(), "a missing output allocation must block finalization");
                TaskManager::allocate_reserved_candidate_output_in(
                    tx,
                    "candidate:issuance-rollback",
                    &allocation,
                    time,
                    &owner,
                    epoch,
                )?;
                assert_eq!(tx.execute(
                    "UPDATE authority_candidate_status SET state='FINALIZED',revision=revision+1
                     WHERE candidate_id='candidate:issuance-rollback' AND state='PENDING' AND revision=1",
                    [],
                )?, 1);
                Err::<(), _>(TaskManagerError::InvalidRecord("test issuance rollback"))
            },
        );
        assert!(
            matches!(
                result,
                Err(TaskManagerError::InvalidRecord("test issuance rollback"))
            ),
            "{result:?}"
        );
        let count: i64 = manager.connection.query_row(
            "SELECT (SELECT COUNT(*) FROM authority_grants WHERE execution_binding_id='binding:issuance-rollback')
                  +(SELECT COUNT(*) FROM execution_bindings WHERE binding_id='binding:issuance-rollback')
                  +(SELECT COUNT(*) FROM step_executions WHERE binding_id='binding:issuance-rollback')
                  +(SELECT COUNT(*) FROM artifact_output_allocations WHERE allocation_id='allocation:copy')
                  +(SELECT COUNT(*) FROM authority_grant_deadlines WHERE execution_binding_id='binding:issuance-rollback')",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn coordinator_finalizes_exact_candidate_as_one_issuance() {
        let (mut manager, hash, snapshot, registration) = fixture();
        let contract = contract_hash(&manager, &snapshot);
        manager
            .reserve_authority_candidate(&ReserveAuthorityCandidate {
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
                resources: &choices(),
            })
            .unwrap();
        manager.activate_local_authority_policy(json!({"schema_version":"0.1","rules":[
            {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"local"},
            {"effect":"ALLOW","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"}
        ]}).to_string().as_bytes()).unwrap();
        let finalized = manager
            .finalize_pending_authority_candidate("candidate:complete")
            .unwrap();
        assert_eq!(finalized.grant_ids.len(), 2);
        assert_eq!(finalized.allocation_ids, ["allocation:copy"]);
        assert_eq!(finalized.binding_id, "binding:complete");
        let status: (String, i64) = manager.connection.query_row(
            "SELECT state,revision FROM authority_candidate_status WHERE candidate_id='candidate:complete'",
            [], |row| Ok((row.get(0)?,row.get(1)?)),
        ).unwrap();
        assert_eq!(status, ("FINALIZED".into(), 2));
        let state: String = manager
            .connection
            .query_row(
                "SELECT state FROM tasks WHERE task_id='T-candidate'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "WAITING_FOR_AUTH");
        let grant_events: i64 = manager
            .connection
            .query_row(
                "SELECT COUNT(*) FROM provenance_events
             WHERE task_id='T-candidate' AND event_type='authorization.granted'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(grant_events, 2);
        assert!(manager.open_artifact_output("allocation:copy").is_err());
        assert_eq!(
            manager
                .finalize_pending_authority_candidate("candidate:complete")
                .unwrap(),
            finalized,
            "a lost finalization response must replay the same committed identities"
        );
        let replayed_events: i64 = manager
            .connection
            .query_row(
                "SELECT COUNT(*) FROM provenance_events WHERE task_id='T-candidate'
             AND event_type='authorization.granted'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(replayed_events, 2);
    }

    #[test]
    fn hard_deny_activation_blocks_prepared_task_before_runnable() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("policy-before-runnable.sqlite3");
        let (mut manager, hash, snapshot, registration) = coherent_planning_fixture(&path);
        let contract = contract_hash(&manager, &snapshot);
        manager
            .reserve_authority_candidate(&ReserveAuthorityCandidate {
                candidate_id: "candidate:policy-before-runnable",
                binding_id: "binding:policy-before-runnable",
                attempt_id: "attempt:policy-before-runnable",
                task_id: "T-candidate",
                semantic_program_hash: &hash,
                registry_snapshot_id: &snapshot,
                node_id: "copy",
                capability_contract_hash: &contract,
                provider_registration_id: &registration,
                attempt_number: 1,
                resources: &choices(),
            })
            .unwrap();
        manager.activate_local_authority_policy(json!({"schema_version":"0.1","rules":[
            {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"local"},
            {"effect":"ALLOW","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"}
        ]}).to_string().as_bytes()).unwrap();
        let finalized = manager
            .finalize_pending_authority_candidate("candidate:policy-before-runnable")
            .unwrap();
        manager.activate_local_authority_policy(json!({"schema_version":"0.1","rules":[
            {"effect":"DENY","action":"artifact.read","resource_kind":"artifact","sensitivity":"local"},
            {"effect":"DENY","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"}
        ]}).to_string().as_bytes()).unwrap();
        let runnable = manager
            .transition(&TransitionRequest {
                schema_version: "0.1".into(),
                transition_id: "transition:policy-before-runnable".into(),
                task_id: "T-candidate".into(),
                expected_revision: 2,
                expected_state: TaskState::Planning,
                to_state: TaskState::Runnable,
                requested_by: Actor {
                    kind: "system-service".into(),
                    id: "aiosd.coordinator".into(),
                },
                reason: TransitionReason {
                    code: "AUTHORITY_READY".into(),
                    message: None,
                    related_ids: vec![],
                },
                mutation: TaskMutation::default(),
            })
            .unwrap();
        assert!(
            !runnable.applied,
            "stale grants cannot start a prepared task"
        );
        assert_eq!(
            manager.get_task("T-candidate").unwrap().unwrap().state,
            TaskState::Planning
        );
        assert_eq!(
            manager
                .finalize_pending_authority_candidate("candidate:policy-before-runnable")
                .unwrap(),
            finalized
        );
    }

    #[test]
    fn planning_unconditional_allow_prepares_but_does_not_launch() {
        let (mut manager, hash, snapshot, registration) = fixture();
        manager
            .connection
            .execute(
                "UPDATE tasks SET state='PLANNING' WHERE task_id='T-candidate'",
                [],
            )
            .unwrap();
        let contract = contract_hash(&manager, &snapshot);
        manager
            .reserve_authority_candidate(&ReserveAuthorityCandidate {
                candidate_id: "candidate:planning-allow",
                binding_id: "binding:planning-allow",
                attempt_id: "attempt:planning-allow",
                task_id: "T-candidate",
                semantic_program_hash: &hash,
                registry_snapshot_id: &snapshot,
                node_id: "copy",
                capability_contract_hash: &contract,
                provider_registration_id: &registration,
                attempt_number: 1,
                resources: &choices(),
            })
            .unwrap();
        manager.activate_local_authority_policy(json!({"schema_version":"0.1","rules":[
            {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"local"},
            {"effect":"ALLOW","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"}
        ]}).to_string().as_bytes()).unwrap();
        let evaluated = manager
            .evaluate_pending_authority_candidate("candidate:planning-allow")
            .unwrap();
        assert!(
            evaluated
                .decisions
                .iter()
                .all(|decision| decision.approval_id.is_none())
        );
        let prepared = manager
            .finalize_pending_authority_candidate("candidate:planning-allow")
            .unwrap();
        assert_eq!(prepared.grant_ids.len(), 2);
        assert!(manager.open_artifact_output("allocation:copy").is_err());
        let state: String = manager
            .connection
            .query_row(
                "SELECT state FROM tasks WHERE task_id='T-candidate'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "PLANNING");
    }

    #[test]
    fn planning_approval_condition_cannot_issue_or_be_decided_early() {
        use crate::authority_policy::AuthenticatedApprover;
        let (mut manager, hash, snapshot, registration) = fixture();
        manager
            .connection
            .execute(
                "UPDATE tasks SET state='PLANNING' WHERE task_id='T-candidate'",
                [],
            )
            .unwrap();
        let contract = contract_hash(&manager, &snapshot);
        manager
            .reserve_authority_candidate(&ReserveAuthorityCandidate {
                candidate_id: "candidate:planning-approval",
                binding_id: "binding:planning-approval",
                attempt_id: "attempt:planning-approval",
                task_id: "T-candidate",
                semantic_program_hash: &hash,
                registry_snapshot_id: &snapshot,
                node_id: "copy",
                capability_contract_hash: &contract,
                provider_registration_id: &registration,
                attempt_number: 1,
                resources: &choices(),
            })
            .unwrap();
        manager.activate_local_authority_policy(json!({"schema_version":"0.1","rules":[
            {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"local"},
            {"effect":"REQUIRE_APPROVAL","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"}
        ]}).to_string().as_bytes()).unwrap();
        let evaluated = manager
            .evaluate_pending_authority_candidate("candidate:planning-approval")
            .unwrap();
        let approval_id = evaluated
            .decisions
            .iter()
            .find_map(|decision| decision.approval_id.as_deref())
            .unwrap();
        let approver = AuthenticatedApprover {
            principal_id: "user:test",
        };
        assert!(
            manager
                .decide_candidate_approval(approval_id, &approver, true)
                .is_err()
        );
        assert!(
            manager
                .finalize_pending_authority_candidate("candidate:planning-approval")
                .is_err()
        );
        let grants: i64 = manager.connection.query_row(
            "SELECT COUNT(*) FROM authority_grants WHERE execution_binding_id='binding:planning-approval'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(grants, 0);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "covers real import, exact issuance, restart retirement, historical replay, and idempotent second restart"
    )]
    fn coherent_task_replans_after_old_session_grants_are_retired() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("coherent-finalization.sqlite3");
        let (mut manager, hash, snapshot, registration) = coherent_planning_fixture(&path);
        assert_eq!(
            manager.get_task("T-candidate").unwrap().unwrap().state,
            TaskState::Planning
        );
        let imported = manager
            .import_artifact(
                &ImportArtifactRequest {
                    schema_version: "0.1".into(),
                    import_id: Some("import:coherent-replan".into()),
                    task_id: "T-candidate".into(),
                    origin_kind: ArtifactOriginKind::User,
                    semantic_type: Some("artifact.file@1".into()),
                    media_type: "text/plain".into(),
                    format: None,
                    sensitivity: Sensitivity::Local,
                    retention: RetentionClass::Task,
                    expires_at: None,
                    labels: vec![],
                    max_size_bytes: Some(1024),
                },
                &mut Cursor::new(b"unused real input"),
            )
            .unwrap();
        manager.connection.execute(
            "DELETE FROM task_artifacts WHERE task_id='T-candidate' AND artifact_id='artifact:source'",
            [],
        ).unwrap();
        let contract = contract_hash(&manager, &snapshot);
        manager
            .reserve_authority_candidate(&ReserveAuthorityCandidate {
                candidate_id: "candidate:coherent",
                binding_id: "binding:coherent",
                attempt_id: "attempt:coherent",
                task_id: "T-candidate",
                semantic_program_hash: &hash,
                registry_snapshot_id: &snapshot,
                node_id: "copy",
                capability_contract_hash: &contract,
                provider_registration_id: &registration,
                attempt_number: 1,
                resources: &choices_with_source(&imported.artifact_id),
            })
            .unwrap();
        manager.activate_local_authority_policy(json!({"schema_version":"0.1","rules":[
            {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"local"},
            {"effect":"ALLOW","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"}
        ]}).to_string().as_bytes()).unwrap();
        let prepared = manager
            .finalize_pending_authority_candidate("candidate:coherent")
            .unwrap();
        assert_eq!(
            manager.get_task("T-candidate").unwrap().unwrap().state,
            TaskState::Planning
        );
        let runnable = manager
            .transition(&TransitionRequest {
                schema_version: "0.1".into(),
                transition_id: "transition:candidate-runnable".into(),
                task_id: "T-candidate".into(),
                expected_revision: 2,
                expected_state: TaskState::Planning,
                to_state: TaskState::Runnable,
                requested_by: Actor {
                    kind: "system-service".into(),
                    id: "aiosd.coordinator".into(),
                },
                reason: TransitionReason {
                    code: "AUTHORITY_READY".into(),
                    message: None,
                    related_ids: vec![],
                },
                mutation: TaskMutation::default(),
            })
            .unwrap();
        assert!(runnable.applied, "{runnable:?}");
        drop(manager);
        crate::FAIL_STARTUP_AFTER_AUTHORITY_RETIRE.with(|flag| flag.set(true));
        assert!(matches!(
            TaskManager::open_with_clock(&path, Box::new(FixedClock)),
            Err(TaskManagerError::InvalidRecord(
                "injected failure after authority retirement"
            ))
        ));
        let interrupted = rusqlite::Connection::open(&path).unwrap();
        let cut: (String, i64) = interrupted
            .query_row(
                "SELECT t.state,(SELECT COUNT(*) FROM authority_grants g
             WHERE g.task_id=t.task_id AND g.state='ACTIVE')
             FROM tasks t WHERE t.task_id='T-candidate'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(cut, ("RUNNABLE".into(), 0));
        drop(interrupted);
        let mut reopened = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        assert_eq!(
            reopened.get_task("T-candidate").unwrap().unwrap().state,
            TaskState::Planning
        );
        let active: i64 = reopened.connection.query_row(
            "SELECT COUNT(*) FROM authority_grants WHERE task_id='T-candidate' AND state='ACTIVE'",
            [],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(active, 0);
        let retired: i64 = reopened
            .connection
            .query_row(
                "SELECT COUNT(*) FROM authority_grants WHERE task_id='T-candidate'
             AND state='REVOKED' AND revocation_reason_code='AUTHORITY_SESSION_RETIRED'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retired, 2);
        assert_eq!(
            reopened
                .finalize_pending_authority_candidate("candidate:coherent")
                .unwrap(),
            prepared
        );
        drop(reopened);
        let mut reopened_again = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        assert_eq!(
            reopened_again
                .get_task("T-candidate")
                .unwrap()
                .unwrap()
                .state,
            TaskState::Planning
        );
        reopened_again
            .reserve_authority_candidate(&ReserveAuthorityCandidate {
                candidate_id: "candidate:fresh-after-restart",
                binding_id: "binding:fresh-after-restart",
                attempt_id: "attempt:fresh-after-restart",
                task_id: "T-candidate",
                semantic_program_hash: &hash,
                registry_snapshot_id: &snapshot,
                node_id: "copy",
                capability_contract_hash: &contract,
                provider_registration_id: &registration,
                attempt_number: 2,
                resources: &choices_with_source_and_output(
                    &imported.artifact_id,
                    "allocation:fresh-after-restart",
                ),
            })
            .unwrap();
        let fresh = reopened_again
            .finalize_pending_authority_candidate("candidate:fresh-after-restart")
            .unwrap();
        assert!(
            fresh
                .grant_ids
                .iter()
                .all(|id| !prepared.grant_ids.contains(id))
        );
        let old_session = reopened_again
            .issue_provider_artifact_session("T-candidate", "binding:coherent")
            .unwrap();
        assert!(
            reopened_again
                .scope_artifact_reads(&old_session, std::slice::from_ref(&imported.artifact_id))
                .is_err()
        );
        let revision = reopened_again
            .get_task("T-candidate")
            .unwrap()
            .unwrap()
            .revision;
        let runnable = reopened_again
            .transition(&TransitionRequest {
                schema_version: "0.1".into(),
                transition_id: "transition:fresh-after-restart-runnable".into(),
                task_id: "T-candidate".into(),
                expected_revision: revision,
                expected_state: TaskState::Planning,
                to_state: TaskState::Runnable,
                requested_by: Actor {
                    kind: "system-service".into(),
                    id: "aiosd.coordinator".into(),
                },
                reason: TransitionReason {
                    code: "AUTHORITY_READY".into(),
                    message: None,
                    related_ids: vec![],
                },
                mutation: TaskMutation::default(),
            })
            .unwrap();
        assert!(runnable.applied, "{runnable:?}");
        let fresh_session = reopened_again
            .issue_provider_artifact_session("T-candidate", "binding:fresh-after-restart")
            .unwrap();
        assert!(
            reopened_again
                .scope_artifact_reads(&fresh_session, std::slice::from_ref(&imported.artifact_id))
                .is_ok()
        );
        assert!(
            reopened_again
                .scope_artifact_reads(&old_session, std::slice::from_ref(&imported.artifact_id))
                .is_err()
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "proves one imported input reaches the actual protected reader through the coordinator path"
    )]
    fn coherent_candidate_opens_real_input_and_restart_does_not_erase_its_use() {
        run_coherent_candidate_reader_and_publication(DeadlineScenario::Never);
    }

    #[test]
    fn finished_output_cannot_publish_after_coordinator_monotonic_deadline() {
        run_coherent_candidate_reader_and_publication(DeadlineScenario::BeforePlacement);
    }

    #[test]
    fn placed_output_cannot_commit_after_coordinator_monotonic_deadline() {
        run_coherent_candidate_reader_and_publication(DeadlineScenario::BeforeFinalCommit);
    }

    #[test]
    fn retained_reader_rejects_expired_preflight_followed_by_monotonic_regression() {
        run_coherent_candidate_reader_and_publication(DeadlineScenario::ReaderPreflightRegression);
    }

    #[test]
    fn hard_deny_activation_stops_retained_reader_and_writer_before_more_bytes() {
        run_coherent_candidate_reader_and_publication(DeadlineScenario::PolicyBeforeWrite);
    }

    #[test]
    fn hard_deny_activation_stops_finished_output_publication() {
        run_coherent_candidate_reader_and_publication(DeadlineScenario::PolicyBeforePublication);
    }

    #[test]
    fn task_cancellation_revokes_outstanding_coordinator_grants() {
        run_coherent_candidate_reader_and_publication(DeadlineScenario::CancelBeforeRunning);
    }

    #[test]
    fn task_cancellation_cannot_hide_an_unfinished_artifact_operation() {
        run_coherent_candidate_reader_and_publication(DeadlineScenario::CancelWithOpenReader);
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum DeadlineScenario {
        Never,
        BeforePlacement,
        BeforeFinalCommit,
        ReaderPreflightRegression,
        PolicyBeforeWrite,
        PolicyBeforePublication,
        CancelBeforeRunning,
        CancelWithOpenReader,
    }

    #[allow(
        clippy::too_many_lines,
        reason = "exercises one real imported reader and completed writer across the publication deadline"
    )]
    fn run_coherent_candidate_reader_and_publication(scenario: DeadlineScenario) {
        let directory = tempdir().unwrap();
        let path = directory.path().join("coherent-reader.sqlite3");
        let (mut manager, hash, snapshot, registration) = coherent_planning_fixture(&path);
        let original = b"a real imported source";
        let imported = manager
            .import_artifact(
                &ImportArtifactRequest {
                    schema_version: "0.1".into(),
                    import_id: Some("import:coherent-reader".into()),
                    task_id: "T-candidate".into(),
                    origin_kind: ArtifactOriginKind::User,
                    semantic_type: Some("artifact.file@1".into()),
                    media_type: "text/plain".into(),
                    format: None,
                    sensitivity: Sensitivity::Local,
                    retention: RetentionClass::Task,
                    expires_at: None,
                    labels: vec![],
                    max_size_bytes: Some(1024),
                },
                &mut Cursor::new(original),
            )
            .unwrap();
        manager.connection.execute(
            "DELETE FROM task_artifacts WHERE task_id='T-candidate' AND artifact_id='artifact:source'",
            [],
        ).unwrap();
        let contract = contract_hash(&manager, &snapshot);
        manager
            .reserve_authority_candidate(&ReserveAuthorityCandidate {
                candidate_id: "candidate:reader",
                binding_id: "binding:reader",
                attempt_id: "attempt:reader",
                task_id: "T-candidate",
                semantic_program_hash: &hash,
                registry_snapshot_id: &snapshot,
                node_id: "copy",
                capability_contract_hash: &contract,
                provider_registration_id: &registration,
                attempt_number: 1,
                resources: &choices_with_source(&imported.artifact_id),
            })
            .unwrap();
        manager.activate_local_authority_policy(json!({"schema_version":"0.1","rules":[
            {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"local"},
            {"effect":"ALLOW","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"}
        ]}).to_string().as_bytes()).unwrap();
        manager
            .finalize_pending_authority_candidate("candidate:reader")
            .unwrap();
        if scenario == DeadlineScenario::CancelBeforeRunning {
            let result = manager
                .transition(&TransitionRequest {
                    schema_version: "0.1".into(),
                    transition_id: "transition:reader-cancelled".into(),
                    task_id: "T-candidate".into(),
                    expected_revision: 2,
                    expected_state: TaskState::Planning,
                    to_state: TaskState::Cancelled,
                    requested_by: Actor {
                        kind: "system-service".into(),
                        id: "aiosd.coordinator".into(),
                    },
                    reason: TransitionReason {
                        code: "TASK_CANCELLED".into(),
                        message: None,
                        related_ids: vec![],
                    },
                    mutation: TaskMutation::default(),
                })
                .unwrap();
            assert!(result.applied, "{result:?}");
            let active: i64 = manager.connection.query_row(
                "SELECT COUNT(*) FROM authority_grants WHERE task_id='T-candidate' AND state='ACTIVE'",
                [], |row| row.get(0),
            ).unwrap();
            let revoked: i64 = manager.connection.query_row(
                "SELECT COUNT(*) FROM authority_grants WHERE task_id='T-candidate' AND state='REVOKED' AND revoked_at IS NOT NULL AND revocation_reason_code='AUTH_GRANT_REVOKED'",
                [], |row| row.get(0),
            ).unwrap();
            assert_eq!(active, 0);
            assert_eq!(revoked, 2);
            let retained = manager
                .issue_provider_artifact_session("T-candidate", "binding:reader")
                .unwrap();
            assert!(
                manager
                    .scope_artifact_reads(&retained, std::slice::from_ref(&imported.artifact_id))
                    .is_err()
            );
            return;
        }
        for (transition_id, expected_revision, from, to) in [
            (
                "transition:reader-runnable",
                2,
                TaskState::Planning,
                TaskState::Runnable,
            ),
            (
                "transition:reader-running",
                3,
                TaskState::Runnable,
                TaskState::Running,
            ),
        ] {
            let result = manager
                .transition(&TransitionRequest {
                    schema_version: "0.1".into(),
                    transition_id: transition_id.into(),
                    task_id: "T-candidate".into(),
                    expected_revision,
                    expected_state: from,
                    to_state: to,
                    requested_by: Actor {
                        kind: "system-service".into(),
                        id: "aiosd.coordinator".into(),
                    },
                    reason: TransitionReason {
                        code: "AUTHORITY_READY".into(),
                        message: None,
                        related_ids: vec![],
                    },
                    mutation: TaskMutation::default(),
                })
                .unwrap();
            assert!(result.applied, "{result:?}");
        }
        let (issued, deadline): (i64, i64) = manager
            .connection
            .query_row(
                "SELECT MIN(issued_monotonic_nanos),MIN(deadline_monotonic_nanos)
             FROM authority_grant_deadlines WHERE execution_binding_id='binding:reader'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let observed_high_water: i64 = manager
            .connection
            .query_row(
                "SELECT MAX(monotonic_nanos) FROM trusted_time_observations",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let initially_admissible = issued.max(observed_high_water) + 1_000_000_000;
        assert!(initially_admissible < deadline);
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(
            u64::try_from(initially_admissible).unwrap(),
        ));
        let regression_phase = Arc::new(AtomicUsize::new(0));
        manager.clock = if scenario == DeadlineScenario::ReaderPreflightRegression {
            Arc::new(PreflightRegressionClock {
                baseline: Arc::clone(&monotonic),
                phase: Arc::clone(&regression_phase),
                expired: u64::try_from(deadline).unwrap() + 1,
            })
        } else {
            Arc::new(FrozenWallClock {
                monotonic: Arc::clone(&monotonic),
            })
        };
        let session = manager
            .issue_provider_artifact_session("T-candidate", "binding:reader")
            .unwrap();
        let scope = manager
            .scope_artifact_reads(&session, std::slice::from_ref(&imported.artifact_id))
            .unwrap();
        let mut reader = manager
            .open_artifact_reader(&scope, &imported.artifact_id)
            .unwrap();
        if scenario == DeadlineScenario::CancelWithOpenReader {
            let result = manager
                .transition(&TransitionRequest {
                    schema_version: "0.1".into(),
                    transition_id: "transition:open-reader-cancel".into(),
                    task_id: "T-candidate".into(),
                    expected_revision: 4,
                    expected_state: TaskState::Running,
                    to_state: TaskState::Cancelled,
                    requested_by: Actor {
                        kind: "system-service".into(),
                        id: "aiosd.coordinator".into(),
                    },
                    reason: TransitionReason {
                        code: "TASK_CANCELLED".into(),
                        message: None,
                        related_ids: vec![],
                    },
                    mutation: TaskMutation::default(),
                })
                .unwrap();
            assert!(!result.applied);
            assert_eq!(result.reason_code, "TASK_TRANSITION_GUARD_FAILED");
            assert_eq!(
                manager.get_task("T-candidate").unwrap().unwrap().state,
                TaskState::Running
            );
            let revoked: i64 = manager.connection.query_row(
                "SELECT COUNT(*) FROM authority_grants WHERE task_id='T-candidate' AND state='REVOKED'",
                [], |row| row.get(0),
            ).unwrap();
            assert_eq!(revoked, 0);
            return;
        }
        if scenario == DeadlineScenario::ReaderPreflightRegression {
            regression_phase.store(1, Ordering::SeqCst);
            let mut denied = [0xa5_u8; 1];
            assert!(reader.read(&mut denied).is_err());
            assert_eq!(
                denied,
                [0xa5],
                "regressed admission cannot deliver source bytes"
            );
            let expired_observation: i64 = manager
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM trusted_time_observations
                 WHERE monotonic_nanos=?1 AND confidence='TRUSTED_LOCAL'",
                    [deadline + 1],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(
                expired_observation > 0,
                "preflight expiry must remain durable evidence"
            );
            assert!(
                reader.read(&mut denied).is_err(),
                "later lower samples cannot revive the grant"
            );
            assert_eq!(denied, [0xa5]);
            return;
        }
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, original);
        reader.seek(SeekFrom::Start(0)).unwrap();
        let mut writer = manager
            .open_bound_artifact_output(&session, "allocation:copy")
            .unwrap();
        writer.write_all(b"copied output").unwrap();
        if scenario == DeadlineScenario::PolicyBeforeWrite {
            manager.activate_local_authority_policy(json!({"schema_version":"0.1","rules":[
                {"effect":"DENY","action":"artifact.read","resource_kind":"artifact","sensitivity":"local"},
                {"effect":"DENY","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"}
            ]}).to_string().as_bytes()).unwrap();
            let mut denied = [0xa5_u8; 1];
            assert!(reader.read(&mut denied).is_err());
            assert_eq!(denied, [0xa5], "revoked reader cannot deliver source bytes");
            assert!(writer.write_all(b"extra").is_err());
            assert_eq!(
                writer.bytes_written(),
                13,
                "revoked writer cannot append bytes"
            );
            assert!(
                manager
                    .scope_artifact_reads(&session, std::slice::from_ref(&imported.artifact_id))
                    .is_err()
            );
            assert_eq!(
                manager
                    .finalize_pending_authority_candidate("candidate:reader")
                    .unwrap()
                    .binding_id,
                "binding:reader"
            );
            return;
        }
        assert_eq!(writer.finish().unwrap(), 13);
        match scenario {
            DeadlineScenario::Never
            | DeadlineScenario::ReaderPreflightRegression
            | DeadlineScenario::PolicyBeforeWrite
            | DeadlineScenario::CancelBeforeRunning
            | DeadlineScenario::CancelWithOpenReader => {}
            DeadlineScenario::PolicyBeforePublication => {
                manager.activate_local_authority_policy(json!({"schema_version":"0.1","rules":[
                    {"effect":"DENY","action":"artifact.read","resource_kind":"artifact","sensitivity":"local"},
                    {"effect":"DENY","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"}
                ]}).to_string().as_bytes()).unwrap();
            }
            DeadlineScenario::BeforePlacement => {
                monotonic.store(u64::try_from(deadline).unwrap() + 1, Ordering::SeqCst);
            }
            DeadlineScenario::BeforeFinalCommit => {
                let monotonic = Arc::clone(&monotonic);
                crate::artifact_store::set_publication_commit_test_hook(move || {
                    monotonic.store(u64::try_from(deadline).unwrap() + 1, Ordering::SeqCst);
                    Ok(())
                });
            }
        }
        let publication = manager.publish_bound_artifact_output(
            &session,
            &ArtifactPublicationRequest {
                schema_version: "0.1".into(),
                publication_id: "publication:reader-copy".into(),
                allocation_id: "allocation:copy".into(),
                task_id: "T-candidate".into(),
                expected_allocation_state: ArtifactExpectedState::Writing,
                semantic_type: Some("artifact.file@1".into()),
                media_type: "text/plain".into(),
                format: None,
                lineage: ArtifactLineage {
                    input_artifact_ids: vec![imported.artifact_id.clone()],
                    ..ArtifactLineage::default()
                },
                labels: vec![],
            },
        );
        if scenario == DeadlineScenario::PolicyBeforePublication {
            assert!(publication.is_err() || !publication.as_ref().unwrap().published);
            let committed: i64 = manager.connection.query_row(
                "SELECT COUNT(*) FROM artifact_publications WHERE publication_id='publication:reader-copy' AND state='COMMITTED'",
                [], |row| row.get(0),
            ).unwrap();
            assert_eq!(committed, 0, "revoked grant cannot publish finished bytes");
            assert_eq!(
                manager
                    .finalize_pending_authority_candidate("candidate:reader")
                    .unwrap()
                    .binding_id,
                "binding:reader"
            );
            return;
        }
        if scenario != DeadlineScenario::Never {
            match &publication {
                Ok(result) => {
                    assert!(
                        !result.published,
                        "expired authority cannot publish finished bytes"
                    );
                    assert_eq!(result.reason_code, "ARTIFACT_AUTHORITY_DENIED");
                }
                Err(error) => assert!(matches!(
                    error,
                    TaskManagerError::InvalidRecord("ARTIFACT_AUTHORITY_DENIED")
                )),
            }
            let committed: i64 = manager.connection.query_row(
                "SELECT COUNT(*) FROM artifact_publications WHERE publication_id='publication:reader-copy' AND state='COMMITTED'",
                [], |row| row.get(0),
            ).unwrap();
            assert_eq!(committed, 0, "expiry cannot create a published artifact");
            let (no_effect, unresolved): (i64, i64) = manager
                .connection
                .query_row(
                    "SELECT
                    (SELECT COUNT(*) FROM trusted_time_effect_resolutions r
                     JOIN trusted_time_effect_preparations p ON p.marker_id=r.marker_id
                     WHERE p.subject_kind='ARTIFACT_PUBLICATION'
                       AND p.subject_id='publication:reader-copy'
                       AND r.resolution_kind='NO_EFFECT'),
                    (SELECT COUNT(*) FROM trusted_time_effect_pending x
                     JOIN trusted_time_effect_preparations p ON p.marker_id=x.marker_id
                     WHERE p.subject_kind='ARTIFACT_PUBLICATION'
                       AND p.subject_id='publication:reader-copy')",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            if scenario == DeadlineScenario::BeforePlacement {
                assert!(
                    no_effect > 0,
                    "expired authority must deny before a placement primitive"
                );
            } else {
                let invoked: i64 = manager
                    .connection
                    .query_row(
                        "SELECT COUNT(*) FROM trusted_time_effect_resolutions r
                     JOIN trusted_time_effect_preparations p ON p.marker_id=r.marker_id
                     WHERE p.subject_kind='ARTIFACT_PUBLICATION'
                       AND p.subject_id='publication:reader-copy'
                       AND r.resolution_kind='EFFECT_INVOKED'",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert!(
                    invoked > 0,
                    "the blob placement must precede expiry at final commit"
                );
                let mut digest = String::with_capacity(64);
                for byte in Sha256::digest(b"copied output") {
                    write!(&mut digest, "{byte:02x}").unwrap();
                }
                let final_ref =
                    format!("blobs/sha256/{}/{}/{}", &digest[..2], &digest[2..4], digest);
                assert!(
                    !manager.artifact_store_root.join(final_ref).exists(),
                    "denied final commit must remove its unreferenced placed blob"
                );
            }
            assert_eq!(
                unresolved, 0,
                "denied placement cannot leave uncertain effect evidence"
            );
            let latched: i64 = manager.connection.query_row(
                "SELECT COUNT(*) FROM authority_grant_expiry_latches x JOIN authority_grant_deadlines d ON d.grant_id=x.grant_id WHERE d.execution_binding_id='binding:reader' AND x.reason='MONOTONIC_DEADLINE'",
                [], |row| row.get(0),
            ).unwrap();
            assert_eq!(
                latched, 2,
                "publication denial must durably latch both expired grants"
            );
            return;
        }
        let published = publication.unwrap();
        assert!(published.published);
        monotonic.store(u64::try_from(deadline).unwrap() + 1, Ordering::SeqCst);
        assert!(
            reader.seek(SeekFrom::Start(0)).is_err(),
            "retained reader seek must stop at the monotonic deadline"
        );
        let mut denied = [0_u8; 1];
        assert!(
            reader.read(&mut denied).is_err(),
            "retained reader must stop at the monotonic deadline"
        );
        drop(reader);
        drop(manager);
        let reopened = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        assert_eq!(
            reopened.get_task("T-candidate").unwrap().unwrap().state,
            TaskState::Recovering
        );
        let reader_admissions: i64 = reopened
            .connection
            .query_row(
                "SELECT COUNT(*) FROM operations WHERE task_id='T-candidate'
             AND effect_class='ARTIFACT_READ'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(reader_admissions, 1);
        let committed_output: i64 = reopened
            .connection
            .query_row(
                "SELECT COUNT(*) FROM artifact_publications
             WHERE publication_id='publication:reader-copy' AND state='COMMITTED'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(committed_output, 1);
    }

    #[test]
    fn restart_does_not_replan_prepared_authority_with_possible_use() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("used-authority.sqlite3");
        let (mut manager, hash, snapshot, registration) = coherent_planning_fixture(&path);
        let contract = contract_hash(&manager, &snapshot);
        manager
            .reserve_authority_candidate(&ReserveAuthorityCandidate {
                candidate_id: "candidate:used",
                binding_id: "binding:used",
                attempt_id: "attempt:used",
                task_id: "T-candidate",
                semantic_program_hash: &hash,
                registry_snapshot_id: &snapshot,
                node_id: "copy",
                capability_contract_hash: &contract,
                provider_registration_id: &registration,
                attempt_number: 1,
                resources: &choices(),
            })
            .unwrap();
        manager.activate_local_authority_policy(json!({"schema_version":"0.1","rules":[
            {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"local"},
            {"effect":"ALLOW","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"}
        ]}).to_string().as_bytes()).unwrap();
        let prepared = manager
            .finalize_pending_authority_candidate("candidate:used")
            .unwrap();
        manager
            .connection
            .execute(
                "UPDATE authority_grants SET uses_consumed=1 WHERE grant_id=?1",
                [&prepared.grant_ids[0]],
            )
            .unwrap();
        drop(manager);
        assert!(matches!(
            TaskManager::open_with_clock(&path, Box::new(FixedClock)),
            Err(TaskManagerError::InvalidRecord(
                "obsolete prepared authority has possible effects or incomplete issuance"
            ))
        ));
        let db = rusqlite::Connection::open(&path).unwrap();
        let state: String = db
            .query_row(
                "SELECT state FROM authority_grants WHERE grant_id=?1",
                [&prepared.grant_ids[0]],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "ACTIVE");
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "covers approval-backed issuance, current activation admission, and historical replay"
    )]
    fn coherent_task_waits_for_real_candidate_approval_before_finalization() {
        use crate::authority_policy::AuthenticatedApprover;
        let directory = tempdir().unwrap();
        let path = directory.path().join("coherent-approval.sqlite3");
        let (mut manager, hash, snapshot, registration) = coherent_planning_fixture(&path);
        let contract = contract_hash(&manager, &snapshot);
        manager
            .reserve_authority_candidate(&ReserveAuthorityCandidate {
                candidate_id: "candidate:coherent-approval",
                binding_id: "binding:coherent-approval",
                attempt_id: "attempt:coherent-approval",
                task_id: "T-candidate",
                semantic_program_hash: &hash,
                registry_snapshot_id: &snapshot,
                node_id: "copy",
                capability_contract_hash: &contract,
                provider_registration_id: &registration,
                attempt_number: 1,
                resources: &choices(),
            })
            .unwrap();
        manager.activate_local_authority_policy(json!({"schema_version":"0.1","rules":[
            {"effect":"REQUIRE_APPROVAL","action":"artifact.read","resource_kind":"artifact","sensitivity":"local"},
            {"effect":"ALLOW","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"}
        ]}).to_string().as_bytes()).unwrap();
        let evaluated = manager
            .evaluate_pending_authority_candidate("candidate:coherent-approval")
            .unwrap();
        let approval_id = evaluated
            .decisions
            .iter()
            .find_map(|decision| decision.approval_id.clone())
            .unwrap();
        assert!(
            manager
                .finalize_pending_authority_candidate("candidate:coherent-approval")
                .is_err()
        );
        let waiting = manager
            .transition(&TransitionRequest {
                schema_version: "0.1".into(),
                transition_id: "transition:candidate-waiting".into(),
                task_id: "T-candidate".into(),
                expected_revision: 2,
                expected_state: TaskState::Planning,
                to_state: TaskState::WaitingForAuth,
                requested_by: Actor {
                    kind: "system-service".into(),
                    id: "aiosd.coordinator".into(),
                },
                reason: TransitionReason {
                    code: "APPROVAL_REQUIRED".into(),
                    message: None,
                    related_ids: vec![approval_id.clone()],
                },
                mutation: TaskMutation {
                    waiting_on: Some(vec![WaitingOn {
                        kind: WaitingKind::Approval,
                        id: approval_id.clone(),
                        message: None,
                    }]),
                    ..TaskMutation::default()
                },
            })
            .unwrap();
        assert!(waiting.applied, "{waiting:?}");
        manager
            .decide_candidate_approval(
                &approval_id,
                &AuthenticatedApprover {
                    principal_id: "user:test",
                },
                true,
            )
            .unwrap();
        let finalized = manager
            .finalize_pending_authority_candidate("candidate:coherent-approval")
            .unwrap();
        assert_eq!(finalized.grant_ids.len(), 2);
        let runnable = manager
            .transition(&TransitionRequest {
                schema_version: "0.1".into(),
                transition_id: "transition:candidate-approved-runnable".into(),
                task_id: "T-candidate".into(),
                expected_revision: 3,
                expected_state: TaskState::WaitingForAuth,
                to_state: TaskState::Runnable,
                requested_by: Actor {
                    kind: "system-service".into(),
                    id: "aiosd.coordinator".into(),
                },
                reason: TransitionReason {
                    code: "AUTHORITY_READY".into(),
                    message: None,
                    related_ids: vec![],
                },
                mutation: TaskMutation::default(),
            })
            .unwrap();
        assert!(runnable.applied, "{runnable:?}");
        manager.activate_local_authority_policy(json!({"schema_version":"0.1","rules":[
            {"effect":"REQUIRE_APPROVAL","action":"artifact.read","resource_kind":"artifact","sensitivity":"local"},
            {"effect":"ALLOW","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"}
        ]}).to_string().as_bytes()).unwrap();
        let running = manager
            .transition(&TransitionRequest {
                schema_version: "0.1".into(),
                transition_id: "transition:candidate-approved-running-after-reactivation".into(),
                task_id: "T-candidate".into(),
                expected_revision: 4,
                expected_state: TaskState::Runnable,
                to_state: TaskState::Running,
                requested_by: Actor {
                    kind: "system-service".into(),
                    id: "aiosd.coordinator".into(),
                },
                reason: TransitionReason {
                    code: "AUTHORITY_READY".into(),
                    message: None,
                    related_ids: vec![],
                },
                mutation: TaskMutation::default(),
            })
            .unwrap();
        assert!(
            !running.applied,
            "same-content policy reactivation must invalidate approved grants"
        );
        assert_eq!(
            manager
                .finalize_pending_authority_candidate("candidate:coherent-approval")
                .unwrap(),
            finalized
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "covers the crash cut between approval-backed finalization and Task Runnable CAS"
    )]
    fn approved_candidate_restarts_from_waiting_with_old_grants_retired() {
        use crate::authority_policy::AuthenticatedApprover;
        let directory = tempdir().unwrap();
        let path = directory.path().join("approved-waiting-restart.sqlite3");
        let (mut manager, hash, snapshot, registration) = coherent_planning_fixture(&path);
        let contract = contract_hash(&manager, &snapshot);
        manager
            .reserve_authority_candidate(&ReserveAuthorityCandidate {
                candidate_id: "candidate:approved-restart",
                binding_id: "binding:approved-restart",
                attempt_id: "attempt:approved-restart",
                task_id: "T-candidate",
                semantic_program_hash: &hash,
                registry_snapshot_id: &snapshot,
                node_id: "copy",
                capability_contract_hash: &contract,
                provider_registration_id: &registration,
                attempt_number: 1,
                resources: &choices(),
            })
            .unwrap();
        manager.activate_local_authority_policy(json!({"schema_version":"0.1","rules":[
            {"effect":"REQUIRE_APPROVAL","action":"artifact.read","resource_kind":"artifact","sensitivity":"local"},
            {"effect":"ALLOW","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"}
        ]}).to_string().as_bytes()).unwrap();
        let evaluated = manager
            .evaluate_pending_authority_candidate("candidate:approved-restart")
            .unwrap();
        let approval_id = evaluated
            .decisions
            .iter()
            .find_map(|decision| decision.approval_id.clone())
            .unwrap();
        let waiting = manager
            .transition(&TransitionRequest {
                schema_version: "0.1".into(),
                transition_id: "transition:approved-restart-waiting".into(),
                task_id: "T-candidate".into(),
                expected_revision: 2,
                expected_state: TaskState::Planning,
                to_state: TaskState::WaitingForAuth,
                requested_by: Actor {
                    kind: "system-service".into(),
                    id: "aiosd.coordinator".into(),
                },
                reason: TransitionReason {
                    code: "APPROVAL_REQUIRED".into(),
                    message: None,
                    related_ids: vec![approval_id.clone()],
                },
                mutation: TaskMutation {
                    waiting_on: Some(vec![WaitingOn {
                        kind: WaitingKind::Approval,
                        id: approval_id.clone(),
                        message: None,
                    }]),
                    ..TaskMutation::default()
                },
            })
            .unwrap();
        assert!(waiting.applied);
        manager
            .decide_candidate_approval(
                &approval_id,
                &AuthenticatedApprover {
                    principal_id: "user:test",
                },
                true,
            )
            .unwrap();
        let prepared = manager
            .finalize_pending_authority_candidate("candidate:approved-restart")
            .unwrap();
        assert_eq!(
            manager.get_task("T-candidate").unwrap().unwrap().state,
            TaskState::WaitingForAuth
        );
        drop(manager);
        let mut reopened = TaskManager::open_with_clock(&path, Box::new(FixedClock)).unwrap();
        let task = reopened.get_task("T-candidate").unwrap().unwrap();
        assert_eq!(task.state, TaskState::Planning);
        assert!(task.waiting_on.is_empty());
        assert_eq!(
            reopened
                .finalize_pending_authority_candidate("candidate:approved-restart")
                .unwrap(),
            prepared
        );
        let active: i64 = reopened.connection.query_row(
            "SELECT COUNT(*) FROM authority_grants WHERE task_id='T-candidate' AND state='ACTIVE'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(active, 0);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "proves one frozen-wall expiry across public scope, retained writer, and durable latches"
    )]
    fn frozen_wall_does_not_extend_a_coordinator_grant_after_monotonic_deadline() {
        run_frozen_wall_coordinator_grant(false);
    }

    #[test]
    fn running_transition_rejects_coordinator_grants_expired_under_frozen_wall() {
        run_frozen_wall_coordinator_grant(true);
    }

    #[allow(
        clippy::too_many_lines,
        reason = "proves coordinator grant admission, active use, and durable expiry under one frozen wall fixture"
    )]
    fn run_frozen_wall_coordinator_grant(expire_before_running: bool) {
        let (mut manager, hash, snapshot, registration) =
            fixture_at_mode(None, true, false, None, true);
        let contract = contract_hash(&manager, &snapshot);
        manager
            .reserve_authority_candidate(&ReserveAuthorityCandidate {
                candidate_id: "candidate:frozen-wall",
                binding_id: "binding:frozen-wall",
                attempt_id: "attempt:frozen-wall",
                task_id: "T-candidate",
                semantic_program_hash: &hash,
                registry_snapshot_id: &snapshot,
                node_id: "copy",
                capability_contract_hash: &contract,
                provider_registration_id: &registration,
                attempt_number: 1,
                resources: &choices(),
            })
            .unwrap();
        manager.activate_local_authority_policy(json!({"schema_version":"0.1","rules":[
            {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"local"},
            {"effect":"ALLOW","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"}
        ]}).to_string().as_bytes()).unwrap();
        manager
            .finalize_pending_authority_candidate("candidate:frozen-wall")
            .unwrap();
        let runnable = manager
            .transition(&TransitionRequest {
                schema_version: "0.1".into(),
                transition_id: "transition:frozen-wall-runnable".into(),
                task_id: "T-candidate".into(),
                expected_revision: 2,
                expected_state: TaskState::Planning,
                to_state: TaskState::Runnable,
                requested_by: Actor {
                    kind: "system-service".into(),
                    id: "aiosd.coordinator".into(),
                },
                reason: TransitionReason {
                    code: "AUTHORITY_READY".into(),
                    message: None,
                    related_ids: vec![],
                },
                mutation: TaskMutation::default(),
            })
            .unwrap();
        assert!(runnable.applied);
        let (issued,deadline): (i64,i64) = manager.connection.query_row(
            "SELECT MIN(issued_monotonic_nanos),MIN(deadline_monotonic_nanos) FROM authority_grant_deadlines
             WHERE execution_binding_id='binding:frozen-wall'",
            [], |row| Ok((row.get(0)?,row.get(1)?)),
        ).unwrap();
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(
            u64::try_from(issued).unwrap() + 1_000_000_000,
        ));
        manager.clock = Arc::new(FrozenWallClock {
            monotonic: Arc::clone(&monotonic),
        });
        let session = manager
            .issue_provider_artifact_session("T-candidate", "binding:frozen-wall")
            .unwrap();
        assert!(
            manager
                .scope_artifact_reads(&session, &["artifact:source".into()])
                .is_ok()
        );
        if expire_before_running {
            monotonic.store(u64::try_from(deadline).unwrap() + 1, Ordering::SeqCst);
        }
        let running = manager
            .transition(&TransitionRequest {
                schema_version: "0.1".into(),
                transition_id: "transition:frozen-wall-running".into(),
                task_id: "T-candidate".into(),
                expected_revision: 3,
                expected_state: TaskState::Runnable,
                to_state: TaskState::Running,
                requested_by: Actor {
                    kind: "system-service".into(),
                    id: "aiosd.coordinator".into(),
                },
                reason: TransitionReason {
                    code: "AUTHORITY_READY".into(),
                    message: None,
                    related_ids: vec![],
                },
                mutation: TaskMutation::default(),
            })
            .unwrap();
        if expire_before_running {
            assert!(
                !running.applied,
                "expired coordinator grants cannot start a task"
            );
            let latched: i64 = manager.connection.query_row(
                "SELECT COUNT(*) FROM authority_grant_expiry_latches x JOIN authority_grant_deadlines d ON d.grant_id=x.grant_id WHERE d.execution_binding_id='binding:frozen-wall' AND x.reason='MONOTONIC_DEADLINE'",
                [], |row| row.get(0),
            ).unwrap();
            assert_eq!(
                latched, 2,
                "rejected task start must latch both expired grants"
            );
            return;
        }
        assert!(running.applied);
        let mut writer = manager
            .open_bound_artifact_output(&session, "allocation:copy")
            .unwrap();
        writer.write_all(b"a").unwrap();
        monotonic.store(u64::try_from(deadline).unwrap() + 1, Ordering::SeqCst);
        assert!(writer.write_all(b"b").is_err());
        assert_eq!(
            writer.bytes_written(),
            1,
            "expired write cannot append bytes"
        );
        let generation_before: i64 = manager
            .connection
            .query_row(
                "SELECT writer_generation FROM artifact_output_allocations
             WHERE allocation_id='allocation:copy'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            manager
                .open_bound_artifact_output(&session, "allocation:copy")
                .is_err(),
            "expired authority cannot reopen a writer"
        );
        let generation_after: i64 = manager
            .connection
            .query_row(
                "SELECT writer_generation FROM artifact_output_allocations
             WHERE allocation_id='allocation:copy'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            generation_after, generation_before,
            "denial cannot rotate the writer generation"
        );
        assert!(
            manager
                .scope_artifact_reads(&session, &["artifact:source".into()])
                .is_err()
        );
        let latched: i64 = manager
            .connection
            .query_row(
                "SELECT COUNT(*) FROM authority_grant_expiry_latches x
             JOIN authority_grant_deadlines d ON d.grant_id=x.grant_id
             WHERE d.execution_binding_id='binding:frozen-wall'
               AND x.reason='MONOTONIC_DEADLINE'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            latched, 2,
            "the denied writer must latch both expired grants"
        );
        monotonic.store(
            u64::try_from(issued).unwrap() + 1_000_000_000,
            Ordering::SeqCst,
        );
        assert!(
            manager
                .scope_artifact_reads(&session, &["artifact:source".into()])
                .is_err(),
            "a regressed clock cannot restore the expired grant"
        );
    }

    #[test]
    fn candidate_finalizer_failure_after_provenance_rolls_back_every_issuance_row() {
        let (mut manager, hash, snapshot, registration) = fixture();
        let contract = contract_hash(&manager, &snapshot);
        manager
            .reserve_authority_candidate(&ReserveAuthorityCandidate {
                candidate_id: "candidate:failed-finalize",
                binding_id: "binding:failed-finalize",
                attempt_id: "attempt:failed-finalize",
                task_id: "T-candidate",
                semantic_program_hash: &hash,
                registry_snapshot_id: &snapshot,
                node_id: "copy",
                capability_contract_hash: &contract,
                provider_registration_id: &registration,
                attempt_number: 1,
                resources: &choices(),
            })
            .unwrap();
        manager.activate_local_authority_policy(json!({"schema_version":"0.1","rules":[
            {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"local"},
            {"effect":"ALLOW","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"}
        ]}).to_string().as_bytes()).unwrap();
        manager.connection.execute_batch(
            "CREATE TRIGGER fail_candidate_finalization
             BEFORE UPDATE ON authority_candidate_status
             WHEN NEW.state='FINALIZED' BEGIN SELECT RAISE(ABORT,'injected final CAS failure'); END;",
        ).unwrap();
        assert!(
            manager
                .finalize_pending_authority_candidate("candidate:failed-finalize")
                .is_err()
        );
        let count: i64 = manager.connection.query_row(
            "SELECT (SELECT COUNT(*) FROM authority_grants WHERE execution_binding_id='binding:failed-finalize')
              +(SELECT COUNT(*) FROM authority_grant_deadlines WHERE execution_binding_id='binding:failed-finalize')
              +(SELECT COUNT(*) FROM execution_bindings WHERE binding_id='binding:failed-finalize')
              +(SELECT COUNT(*) FROM step_executions WHERE binding_id='binding:failed-finalize')
              +(SELECT COUNT(*) FROM artifact_output_allocations WHERE allocation_id='allocation:copy')
              +(SELECT COUNT(*) FROM provenance_events WHERE task_id='T-candidate'
                   AND event_type='authorization.granted')",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn approval_withdrawal_retry_and_durable_marker_preserve_original_time() {
        use crate::authority_policy::AuthenticatedApprover;

        let directory = tempdir().unwrap();
        let path = directory.path().join("withdrawal-replay.sqlite3");
        let (mut manager, hash, snapshot, registration) = fixture_at(Some(&path));
        let resources = choices();
        let contract = contract_hash(&manager, &snapshot);
        manager
            .reserve_authority_candidate(&ReserveAuthorityCandidate {
                candidate_id: "candidate:withdrawal-replay",
                binding_id: "binding:withdrawal-replay",
                attempt_id: "attempt:withdrawal-replay",
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
        manager
            .activate_local_authority_policy(
                json!({"schema_version":"0.1","rules":[
                    {"effect":"ALLOW","action":"artifact.read","resource_kind":"artifact","sensitivity":"local"},
                    {"effect":"REQUIRE_APPROVAL","action":"artifact.write","resource_kind":"output-allocation","sensitivity":"private"}
                ]})
                .to_string()
                .as_bytes(),
            )
            .unwrap();
        let initial = manager
            .evaluate_pending_authority_candidate("candidate:withdrawal-replay")
            .unwrap();
        let approval = initial.decisions[1].approval_id.as_deref().unwrap();
        let owner = AuthenticatedApprover {
            principal_id: "user:test",
        };
        manager
            .decide_candidate_approval(approval, &owner, true)
            .unwrap();
        manager.revoke_candidate_approval(approval, &owner).unwrap();
        manager.revoke_candidate_approval(approval, &owner).unwrap();
        let marker: String = manager
            .connection
            .query_row(
                "SELECT revoked_at FROM authority_approval_bindings WHERE approval_id=?1",
                [approval],
                |row| row.get(0),
            )
            .unwrap();
        drop(manager);
        let reopened = Connection::open(&path).unwrap();
        let replay_marker: String = reopened
            .query_row(
                "SELECT revoked_at FROM authority_approval_bindings WHERE approval_id=?1",
                [approval],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(replay_marker, marker);
        assert!(!crate::approval_not_withdrawn(&reopened, Some(approval)).unwrap());
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
    fn binding_writer_rejects_missing_or_duplicate_authority_refs() {
        let (mut manager, hash, snapshot, registration) = fixture();
        let resources = choices();
        let contract = contract_hash(&manager, &snapshot);
        manager
            .reserve_authority_candidate(&ReserveAuthorityCandidate {
                candidate_id: "candidate:binding-refs",
                binding_id: "binding:binding-refs",
                attempt_id: "attempt:binding-refs",
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
        let transaction = manager
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        for (decisions, grants) in [
            (
                vec!["decision:one".to_owned(), "decision:one".to_owned()],
                vec!["grant:one".to_owned(), "grant:two".to_owned()],
            ),
            (
                vec!["decision:one".to_owned(), "decision:two".to_owned()],
                vec!["grant:one".to_owned(), "grant:two".to_owned()],
            ),
        ] {
            assert!(
                insert_reserved_binding_in(
                    &transaction,
                    "candidate:binding-refs",
                    &decisions,
                    &grants,
                    NOW
                )
                .is_err()
            );
        }
        let count: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM execution_bindings WHERE binding_id='binding:binding-refs'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
        transaction.rollback().unwrap();
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
