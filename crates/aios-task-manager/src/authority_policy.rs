//! Private policy/approval ledger for non-executable 0016 candidates.
use super::{Result, TaskManager, TaskManagerError, assert_manager_lease, canonical_json};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

const MIGRATION: &str =
    include_str!("../../../specs/persistence-v0.1-0017-authority-policy-evaluation.sql");

fn reject() -> TaskManagerError {
    TaskManagerError::InvalidRecord("authority policy evaluation is not admissible")
}

fn digest(domain: &[u8], data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(data.as_bytes());
    let mut result = String::from("sha256:");
    for byte in hasher.finalize() {
        use std::fmt::Write;
        write!(&mut result, "{byte:02x}").expect("string write");
    }
    result
}

fn checked_time(raw: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(raw, &Rfc3339).map_err(|_| reject())
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum PolicyEffect {
    Allow,
    Deny,
    RequireApproval,
}

impl PolicyEffect {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::Deny => "DENY",
            Self::RequireApproval => "REQUIRE_APPROVAL",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyRule {
    effect: PolicyEffect,
    action: String,
    resource_kind: String,
    sensitivity: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LocalPolicy {
    schema_version: String,
    rules: Vec<PolicyRule>,
}

impl LocalPolicy {
    fn parse(raw: &[u8]) -> Result<Self> {
        let policy: Self =
            aios_registry::parse_strict_json(raw, aios_registry::StrictJsonLimits::default())
                .map_err(|_| reject())?;
        if policy.schema_version != "0.1"
            || policy.rules.is_empty()
            || policy.rules.len() > 64
            || policy.rules.iter().any(|rule| {
                !matches!(rule.action.as_str(), "artifact.read" | "artifact.write")
                    || !matches!(
                        rule.resource_kind.as_str(),
                        "artifact" | "output-allocation"
                    )
                    || !matches!(
                        rule.sensitivity.as_str(),
                        "public" | "local" | "private" | "confidential" | "secret"
                    )
                    || (rule.action == "artifact.read" && rule.resource_kind != "artifact")
                    || (rule.action == "artifact.write"
                        && rule.resource_kind != "output-allocation")
            })
        {
            return Err(reject());
        }
        Ok(policy)
    }

    fn decide(&self, action: &str, kind: &str, sensitivity: &str) -> PolicyEffect {
        let mut result = PolicyEffect::Deny;
        for rule in &self.rules {
            if rule.action == action
                && rule.resource_kind == kind
                && rule.sensitivity == sensitivity
            {
                if rule.effect == PolicyEffect::Deny {
                    return PolicyEffect::Deny;
                }
                if rule.effect == PolicyEffect::RequireApproval {
                    result = PolicyEffect::RequireApproval;
                } else if result != PolicyEffect::RequireApproval {
                    result = PolicyEffect::Allow;
                }
            }
        }
        result
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CandidatePolicyDecision {
    pub action: String,
    pub semantic_selector: String,
    pub authority_request_id: String,
    pub decision_id: String,
    pub effect: PolicyEffect,
    pub approval_id: Option<String>,
    pub evaluation_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CandidatePolicyEvaluation {
    pub activation_revision: i64,
    pub decisions: Vec<CandidatePolicyDecision>,
}

pub(crate) struct AuthenticatedApprover<'a> {
    /// Supplied only by the trusted local shell/session adapter, never provider/model input.
    pub principal_id: &'a str,
}

#[derive(Clone)]
struct CandidateFacts {
    candidate_id: String,
    binding_id: String,
    attempt_id: String,
    task_id: String,
    hash: String,
    snapshot: String,
    node: String,
    capability: String,
    contract_hash: String,
    registration: String,
    provider_id: String,
    provider_version: String,
    manifest_hash: String,
    build_hash: String,
    evidence_id: String,
    trust_source_id: String,
    profile: String,
    isolation: String,
    attempt_number: i64,
    task_revision: i64,
    task_state: String,
    task_principal_kind: String,
    task_principal_id: String,
    constraints: Option<String>,
    resources: Vec<ResourceFacts>,
}

#[derive(Clone)]
struct ResourceFacts {
    action: String,
    selector: String,
    kind: String,
    id: String,
    output_port: Option<String>,
    semantic_type: String,
    sensitivity: String,
    retention: Option<String>,
    expires_at: Option<String>,
}

type StoredApprovalRequest = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
);

fn provider_pins_current(
    transaction: &rusqlite::Transaction<'_>,
    facts: &CandidateFacts,
    selected: Vec<aios_registry::ProviderCandidate>,
    checked_at: &str,
) -> Result<bool> {
    let matches: Vec<_> = selected
        .into_iter()
        .filter(|item| {
            item.registration.registration_id == facts.registration
                && item.registration.provider_id == facts.provider_id
                && item.registration.provider_version == facts.provider_version
                && item.registration.manifest_hash == facts.manifest_hash
                && item.registration.build_hash == facts.build_hash
                && item.evidence_id == facts.evidence_id
        })
        .collect();
    if matches.len() != 1
        || !super::authority_candidate::evidence_still_current(
            transaction,
            &matches[0],
            &facts.capability,
            &facts.contract_hash,
            checked_at,
        )?
    {
        return Ok(false);
    }
    let raw: String = transaction
        .query_row(
            "SELECT manifest_json FROM provider_manifest_payloads WHERE registration_id=?1",
            [&facts.registration],
            |r| r.get(0),
        )
        .optional()?
        .ok_or_else(reject)?;
    let manifest: aios_contracts::CapabilityManifest = aios_registry::parse_strict_json(
        raw.as_bytes(),
        aios_registry::StrictJsonLimits::default(),
    )
    .map_err(|_| reject())?;
    let (trust, source) = aios_registry::verified_provider_trust_source_at(
        transaction,
        &matches[0].registration,
        &manifest,
        checked_at,
    )
    .map_err(|_| reject())?;
    Ok(source == facts.trust_source_id
        && matches!(
            trust,
            aios_registry::ProviderTrustStatus::LocallyTrusted
                | aios_registry::ProviderTrustStatus::ProjectReviewed
                | aios_registry::ProviderTrustStatus::OrganizationApproved
        ))
}

impl CandidateFacts {
    #[allow(
        clippy::too_many_lines,
        reason = "rechecks every pinned candidate and resource fact as one fail-closed snapshot"
    )]
    fn load(connection: &Connection, candidate_id: &str, now: OffsetDateTime) -> Result<Self> {
        let mut facts = connection
            .query_row(
                "SELECT c.candidate_id,c.binding_id,c.attempt_id,c.task_id,c.semantic_program_hash,
              c.registry_snapshot_id,c.node_id,c.capability,c.capability_contract_hash,
              c.provider_registration_id,c.provider_id,c.provider_version,c.provider_manifest_hash,
              c.provider_build_hash,c.conformance_evidence_id,c.provider_trust_source_id,
              c.execution_profile_ref,c.isolation_class,c.attempt_number,t.revision,t.state,
              t.principal_kind,t.principal_id,t.constraints_json
             FROM authority_candidate_reservations c
             JOIN authority_candidate_status s USING(candidate_id)
             JOIN tasks t ON t.task_id=c.task_id
             WHERE c.candidate_id=?1 AND s.state='PENDING' AND c.placement_locality='local'
               AND t.state IN ('WAITING_FOR_AUTH','RUNNABLE','RUNNING')",
                [candidate_id],
                |r| {
                    Ok(Self {
                        candidate_id: r.get(0)?,
                        binding_id: r.get(1)?,
                        attempt_id: r.get(2)?,
                        task_id: r.get(3)?,
                        hash: r.get(4)?,
                        snapshot: r.get(5)?,
                        node: r.get(6)?,
                        capability: r.get(7)?,
                        contract_hash: r.get(8)?,
                        registration: r.get(9)?,
                        provider_id: r.get(10)?,
                        provider_version: r.get(11)?,
                        manifest_hash: r.get(12)?,
                        build_hash: r.get(13)?,
                        evidence_id: r.get(14)?,
                        trust_source_id: r.get(15)?,
                        profile: r.get(16)?,
                        isolation: r.get(17)?,
                        attempt_number: r.get(18)?,
                        task_revision: r.get(19)?,
                        task_state: r.get(20)?,
                        task_principal_kind: r.get(21)?,
                        task_principal_id: r.get(22)?,
                        constraints: r.get(23)?,
                        resources: Vec::new(),
                    })
                },
            )
            .optional()?
            .ok_or_else(reject)?;
        if facts.task_revision < 1
            || !matches!(
                facts.task_state.as_str(),
                "WAITING_FOR_AUTH" | "RUNNABLE" | "RUNNING"
            )
            || facts.task_principal_kind != "user"
            || facts.task_principal_id.is_empty()
            || facts.profile != format!("profile:stage1-local:{}", facts.isolation)
        {
            return Err(reject());
        }
        let constraints = facts.constraints.as_deref().unwrap_or("{}");
        let value = aios_registry::parse_strict_value(
            constraints.as_bytes(),
            aios_registry::StrictJsonLimits::default(),
        )
        .map_err(|_| reject())?;
        let Some(map) = value.as_object() else {
            return Err(reject());
        };
        if map.iter().any(|(key, value)| match key.as_str() {
            "privacy" => !matches!(
                value.as_str(),
                Some("local-only" | "local-first" | "remote-allowed")
            ),
            "max_cost_microunits" => !value.is_null() && value.as_u64().is_none(),
            "preserve_inputs" => !value.is_boolean(),
            "deadline" => {
                !value.is_null()
                    && value
                        .as_str()
                        .and_then(|v| checked_time(v).ok())
                        .is_none_or(|deadline| deadline <= now)
            }
            _ => true,
        }) {
            return Err(reject());
        }
        let active: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM semantic_program_revisions p JOIN tasks t ON t.task_id=p.task_id
             WHERE p.task_id=?1 AND p.program_revision=t.active_program_revision AND p.status='active'
               AND p.semantic_hash=?2 AND p.registry_snapshot_id=?3)",
            params![facts.task_id,facts.hash,facts.snapshot], |r| r.get(0),
        )?;
        if !active {
            return Err(reject());
        }
        let mut statement = connection.prepare(
            "SELECT r.action,r.semantic_selector,r.resource_kind,r.resource_id,r.output_port,
              r.expected_semantic_type,a.sensitivity,a.expires_at,a.integrity_state,a.semantic_type,
              a.retention_class
             FROM authority_candidate_resources r LEFT JOIN artifacts a
               ON r.resource_kind='artifact' AND a.artifact_id=r.resource_id
             WHERE r.candidate_id=?1 ORDER BY r.action,r.semantic_selector",
        )?;
        let rows = statement.query_map([candidate_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, Option<String>>(7)?,
                r.get::<_, Option<String>>(8)?,
                r.get::<_, Option<String>>(9)?,
                r.get::<_, Option<String>>(10)?,
            ))
        })?;
        let mut pending_outputs = Vec::new();
        for row in rows {
            let (
                action,
                selector,
                kind,
                id,
                port,
                semantic_type,
                sensitivity,
                expires_at,
                integrity,
                actual_type,
                retention,
            ) = row?;
            let sensitivity = if kind == "artifact" {
                let exact:(i64,Option<String>)=connection.query_row(
                    "SELECT COUNT(*),MIN(CASE WHEN a.integrity_state='verified' THEN a.artifact_id END)
                     FROM task_artifacts ta JOIN artifacts a USING(artifact_id)
                     WHERE ta.task_id=?1 AND ta.role='input' AND a.semantic_type=?2",
                    params![facts.task_id,semantic_type],|r|Ok((r.get(0)?,r.get(1)?)))?;
                if action != "artifact.read"
                    || integrity.as_deref() != Some("verified")
                    || actual_type.as_deref() != Some(semantic_type.as_str())
                    || exact.0 != 1
                    || exact.1.as_deref() != Some(id.as_str())
                    || !matches!(
                        retention.as_deref(),
                        Some("ephemeral" | "task" | "persistent" | "user-managed")
                    )
                {
                    return Err(reject());
                }
                sensitivity.ok_or_else(reject)?
            } else if kind == "output-allocation" && action == "artifact.write" {
                let claimed:bool=connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM artifact_output_allocations WHERE allocation_id=?1)",
                    [&id],|r|r.get(0))?;
                if claimed {
                    return Err(reject());
                }
                pending_outputs.push(facts.resources.len());
                String::new()
            } else {
                return Err(reject());
            };
            if (!sensitivity.is_empty()
                && !matches!(
                    sensitivity.as_str(),
                    "public" | "local" | "private" | "confidential" | "secret"
                ))
                || expires_at
                    .as_deref()
                    .is_some_and(|raw| checked_time(raw).ok().is_none_or(|expiry| expiry <= now))
            {
                return Err(reject());
            }
            facts.resources.push(ResourceFacts {
                action,
                selector,
                kind,
                id,
                output_port: port,
                semantic_type,
                sensitivity,
                retention,
                expires_at,
            });
        }
        let rank = |s: &str| match s {
            "public" => Some(0),
            "local" => Some(1),
            "private" => Some(2),
            "confidential" => Some(3),
            "secret" => Some(4),
            _ => None,
        };
        let max_rank = facts
            .resources
            .iter()
            .filter(|r| r.kind == "artifact")
            .map(|r| rank(&r.sensitivity).ok_or_else(reject))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .max()
            .unwrap_or(0)
            .max(2);
        let inherited = ["public", "local", "private", "confidential", "secret"][max_rank];
        let retention_rank = |s: &str| match s {
            "ephemeral" => Some(0),
            "task" => Some(1),
            "persistent" => Some(2),
            "user-managed" => Some(3),
            _ => None,
        };
        let max_retention = facts
            .resources
            .iter()
            .filter(|r| r.kind == "artifact")
            .map(|r| {
                r.retention
                    .as_deref()
                    .and_then(retention_rank)
                    .ok_or_else(reject)
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .max()
            .unwrap_or(0)
            .max(1);
        let inherited_retention =
            ["ephemeral", "task", "persistent", "user-managed"][max_retention];
        for index in pending_outputs {
            inherited.clone_into(&mut facts.resources[index].sensitivity);
            facts.resources[index].retention = Some(inherited_retention.to_owned());
        }
        let count: i64 = connection.query_row(
            "SELECT resource_count FROM authority_candidate_reservations WHERE candidate_id=?1",
            [candidate_id],
            |r| r.get(0),
        )?;
        if facts.resources.is_empty()
            || facts.resources.len() != usize::try_from(count).map_err(|_| reject())?
        {
            return Err(reject());
        }
        let program_json:String=connection.query_row(
            "SELECT p.program_json FROM semantic_program_revisions p JOIN tasks t ON t.task_id=p.task_id
             WHERE p.task_id=?1 AND p.program_revision=t.active_program_revision AND p.semantic_hash=?2",
            params![facts.task_id,facts.hash],|r|r.get(0))?;
        let program = aios_registry::parse_strict_value(
            program_json.as_bytes(),
            aios_registry::StrictJsonLimits::default(),
        )
        .map_err(|_| reject())?;
        let node = super::program_node(&program, &facts.node).ok_or_else(reject)?;
        let inputs = node
            .get("inputs")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(reject)?;
        for input in inputs.values() {
            if input.get("source").and_then(serde_json::Value::as_str) != Some("input") {
                return Err(reject());
            }
            let name = input
                .get("name")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(reject)?;
            let selector = format!("input:{name}");
            if facts
                .resources
                .iter()
                .filter(|r| {
                    r.action == "artifact.read" && r.selector == selector && r.kind == "artifact"
                })
                .count()
                != 1
            {
                return Err(reject());
            }
        }
        if facts
            .resources
            .iter()
            .filter(|r| r.kind == "artifact")
            .count()
            != inputs.len()
        {
            return Err(reject());
        }
        Ok(facts)
    }

    fn fingerprint(
        &self,
        resource: &ResourceFacts,
        revision: i64,
        content_hash: &str,
    ) -> Result<String> {
        let value = json!({
            "schema_version":"0.1","candidate_id":self.candidate_id,"binding_id":self.binding_id,
            "attempt_id":self.attempt_id,"task_id":self.task_id,
            "task_principal_kind":self.task_principal_kind,
            "task_principal_id":self.task_principal_id,"constraints":self.constraints,
            "semantic_program_hash":self.hash,"registry_snapshot_id":self.snapshot,
            "node_id":self.node,"capability":self.capability,"contract_hash":self.contract_hash,
            "provider_registration_id":self.registration,"provider_id":self.provider_id,
            "provider_version":self.provider_version,"provider_manifest_hash":self.manifest_hash,
            "provider_build_hash":self.build_hash,"conformance_evidence_id":self.evidence_id,
            "provider_trust_source_id":self.trust_source_id,"execution_profile_ref":self.profile,
            "isolation_class":self.isolation,"attempt_number":self.attempt_number,
            "placement_locality":"local","egress":"deny","network":"none",
            "resource":{"action":resource.action,"selector":resource.selector,"kind":resource.kind,
                "id":resource.id,"output_port":resource.output_port,"semantic_type":resource.semantic_type,
                "sensitivity":resource.sensitivity,"retention":resource.retention,"expires_at":resource.expires_at},
            "all_resources":self.resources.iter().map(|r|json!({"action":r.action,"selector":r.selector,
                "kind":r.kind,"id":r.id,"output_port":r.output_port,"semantic_type":r.semantic_type,
                "sensitivity":r.sensitivity,"retention":r.retention,"expires_at":r.expires_at})).collect::<Vec<_>>(),
            "policy_activation_revision":revision,"policy_content_hash":content_hash,
        });
        Ok(digest(
            b"AIOS-AUTHORITY-EVALUATION\0v1\0",
            &canonical_json(&value)?,
        ))
    }
}

fn checked_approval_decision(
    connection: &Connection,
    approval_id: &str,
    status: &str,
    task_id: &str,
    principal_id: &str,
    expires: &str,
    now: OffsetDateTime,
) -> Result<()> {
    let expected = match status {
        "APPROVED" => "APPROVE",
        "DENIED" => "DENY",
        _ => return Err(reject()),
    };
    let id = format!(
        "approval-decision:{}",
        digest(b"AIOS-APPROVAL-DECISION\0v1\0", approval_id)
    );
    let mut statement = connection.prepare(
        "SELECT decision_id,task_id,decision,decided_by_kind,
        decided_by_id,scope,approved_until,decision_json,decided_at
        FROM approval_decisions WHERE approval_id=?1",
    )?;
    let records = statement
        .query_map([approval_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, String>(7)?,
                r.get::<_, String>(8)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let Some(row) = records.first() else {
        return Err(reject());
    };
    if records.len() != 1
        || row.0 != id
        || row.1 != task_id
        || row.2 != expected
        || row.3 != "user"
        || row.4 != principal_id
        || row.5 != "ONE_SHOT"
        || row.6.as_deref()
            != if status == "APPROVED" {
                Some(expires)
            } else {
                None
            }
        || checked_time(&row.8)? > now
    {
        return Err(reject());
    }
    let expected_json = canonical_json(&json!({"schema_version":"0.1","decision_id":id,
        "approval_id":approval_id,"task_id":task_id,"decision":expected,
        "decided_by":{"kind":"user","id":principal_id},"scope":"ONE_SHOT",
        "approved_until":row.6,"decided_at":row.8}))?;
    if row.7 != expected_json {
        return Err(reject());
    }
    Ok(())
}

fn approval_prompt(
    facts: &CandidateFacts,
    resource: &ResourceFacts,
    approval_id: &str,
    request_id: &str,
    created: &str,
    expires: &str,
) -> Result<String> {
    canonical_json(&json!({"schema_version":"0.1","approval_id":approval_id,
        "authority_request_id":request_id,"task_id":facts.task_id,
        "semantic_program_hash":facts.hash,"node_id":facts.node,"action":resource.action,
        "resource":{"kind":resource.kind,"id":resource.id,"display_class":resource.kind,
            "sensitivity":resource.sensitivity},
        "principal":{"kind":"provider","id":facts.provider_id,"version":facts.provider_version},
        "scope":"ONE_SHOT","effect_classes":[if resource.action=="artifact.read"{"ARTIFACT_READ"}else{"ARTIFACT_WRITE"}],
        "status":"PENDING","created_at":created,"expires_at":expires,
        "policy_reason_codes":["POLICY_REQUIRES_APPROVAL"],
        "trusted_summary":format!("{} on {}",resource.action,resource.id)}))
}

#[allow(
    clippy::too_many_arguments,
    reason = "checks the exact sealed approval tuple"
)]
fn checked_approval_request(
    connection: &Connection,
    facts: &CandidateFacts,
    resource: &ResourceFacts,
    approval_id: &str,
    request_id: &str,
    fingerprint: &str,
    revision: i64,
    snapshot_id: &str,
    created: &str,
    expires: &str,
) -> Result<()> {
    let expected_approval_id = format!(
        "approval:{}",
        digest(
            b"AIOS-AUTHORITY-APPROVAL\0v1\0",
            &format!("{request_id}\0{fingerprint}")
        )
    );
    let requiring_decision_id = format!(
        "decision:{}",
        digest(
            b"AIOS-AUTHORITY-DECISION\0v1\0",
            &format!("{request_id}\0{fingerprint}\0initial")
        )
    );
    if approval_id != expected_approval_id {
        return Err(reject());
    }
    let expected_prompt =
        approval_prompt(facts, resource, approval_id, request_id, created, expires)?;
    let reason_codes = canonical_json(&vec!["POLICY_REQUIRES_APPROVAL"])?;
    let expected_decision = canonical_json(&json!({
        "schema_version":"0.1","decision_id":requiring_decision_id,
        "authority_request_id":request_id,"task_id":facts.task_id,
        "semantic_program_hash":facts.hash,"registry_snapshot_id":facts.snapshot,
        "node_id":facts.node,"capability":facts.capability,
        "principal":{"kind":"provider","id":facts.provider_id,
            "version":facts.provider_version,"package_or_build_hash":facts.build_hash},
        "action":resource.action,
        "resource":{"resolved_kind":resource.kind,"resolved_id":resource.id,
            "semantic_selector":resource.selector,"sensitivity":resource.sensitivity},
        "decision":"REQUIRE_APPROVAL","policy_snapshot_id":snapshot_id,
        "reason_codes":["POLICY_REQUIRES_APPROVAL"],
        "approval_request_id":approval_id,
        "engine":{"id":"aios-deterministic","version":"0.1"},
        "decided_at":created,
    }))?;
    let exact: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM approval_requests a
         JOIN authority_approval_bindings b USING(approval_id)
         JOIN policy_decisions d ON d.decision_id=b.requiring_decision_id
         JOIN authority_evaluation_fingerprints e ON e.decision_id=d.decision_id
         WHERE a.approval_id=?1 AND a.authority_request_id=?2 AND a.task_id=?3
           AND a.semantic_program_hash=?4 AND a.node_id=?5 AND a.action=?6
           AND a.request_json=?7 AND a.created_at=?8 AND a.expires_at=?9
           AND b.candidate_id=?10 AND b.fingerprint=?11 AND b.activation_revision=?12
           AND b.requiring_decision_id=?13 AND b.revoked_at IS NULL
           AND d.authority_request_id=?2 AND d.task_id=?3 AND d.semantic_program_hash=?4
           AND d.node_id=?5 AND d.action=?6 AND d.decision='REQUIRE_APPROVAL'
           AND d.approval_request_id=?1 AND d.principal_kind='provider'
           AND d.principal_id=?14 AND d.resolved_resource_kind=?15
           AND d.resolved_resource_id=?16 AND d.policy_snapshot_id=?17
           AND d.reason_codes_json=?18 AND d.decision_json=?19
           AND d.decided_at=?8 AND e.candidate_id=?10 AND e.fingerprint=?11
           AND e.activation_revision=?12 AND e.evaluated_at=?8)",
        params![
            approval_id,
            request_id,
            facts.task_id,
            facts.hash,
            facts.node,
            resource.action,
            expected_prompt,
            created,
            expires,
            facts.candidate_id,
            fingerprint,
            revision,
            requiring_decision_id,
            facts.provider_id,
            resource.kind,
            resource.id,
            snapshot_id,
            reason_codes,
            expected_decision,
        ],
        |r| r.get(0),
    )?;
    if !exact {
        return Err(reject());
    }
    Ok(())
}

pub(super) fn policy_objects_current(connection: &Connection, stamped: bool) -> Result<bool> {
    let canonical = if stamped {
        let db = Connection::open_in_memory()?;
        db.execute_batch(super::MIGRATION)?;
        db.execute_batch(MIGRATION)?;
        Some(db)
    } else {
        None
    };
    for name in [
        "authority_policy_payloads",
        "authority_policy_activations",
        "authority_evaluation_fingerprints",
        "authority_approval_bindings",
        "authority_policy_payload_no_duplicate",
        "authority_policy_activation_no_duplicate",
        "authority_evaluation_no_duplicate",
        "authority_approval_binding_no_duplicate",
        "authority_approval_binding_exact_insert",
        "authority_approval_request_no_duplicate",
        "authority_approval_request_immutable",
        "authority_approval_request_no_delete",
        "authority_approval_decision_no_duplicate",
        "authority_approval_decision_immutable",
        "authority_approval_decision_no_delete",
        "authority_policy_payload_no_update",
        "authority_policy_payload_no_delete",
        "authority_policy_activation_no_update",
        "authority_policy_activation_no_delete",
        "authority_evaluation_no_update",
        "authority_evaluation_no_delete",
        "authority_approval_binding_immutable",
        "authority_approval_binding_no_delete",
        "authority_approval_status_guard",
    ] {
        let actual: Option<String> = connection
            .query_row("SELECT sql FROM sqlite_master WHERE name=?1", [name], |r| {
                r.get(0)
            })
            .optional()?;
        let expected: Option<String> = canonical
            .as_ref()
            .map(|db| {
                db.query_row("SELECT sql FROM sqlite_master WHERE name=?1", [name], |r| {
                    r.get(0)
                })
            })
            .transpose()?;
        if actual.map(|s| super::normalize_schema_sql(&s))
            != expected.map(|s| super::normalize_schema_sql(&s))
        {
            return Ok(false);
        }
    }
    Ok(true)
}

impl TaskManager {
    /// Trusted coordinator configuration path. Activating the same payload twice
    /// still changes the revision and invalidates prior approvals.
    #[allow(
        clippy::needless_borrow,
        reason = "transaction closure keeps existing SQL call sites explicit"
    )]
    pub(crate) fn activate_local_authority_policy(&mut self, raw: &[u8]) -> Result<i64> {
        let policy = LocalPolicy::parse(raw)?;
        let canonical = canonical_json(&policy)?;
        let content_hash = digest(b"AIOS-LOCAL-AUTHORITY-POLICY\0v1\0", &canonical);
        super::trusted_time::with_protected_immediate(&self.connection, &self.clock, |tx, now| {
            checked_time(now)?;
            assert_manager_lease(&tx, &self.lease_owner, self.lease_epoch)?;
            let existing: Option<String> = tx
                .query_row(
                    "SELECT policy_json FROM authority_policy_payloads WHERE content_hash=?1",
                    [&content_hash],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(existing) = existing {
                if existing != canonical {
                    return Err(reject());
                }
            } else {
                tx.execute("INSERT INTO authority_policy_payloads(content_hash,policy_json,created_at) VALUES (?1,?2,?3)",params![content_hash,canonical,now])?;
            }
            let revision: i64 = tx.query_row(
                "SELECT COALESCE(MAX(revision),0)+1 FROM authority_policy_activations",
                [],
                |r| r.get(0),
            )?;
            tx.execute("INSERT INTO authority_policy_activations(revision,content_hash,activated_at) VALUES (?1,?2,?3)",params![revision,content_hash,now])?;
            let snapshot_id = content_hash.clone();
            let entity_hash = digest(
                b"AIOS-LOCAL-POLICY-ENTITY-SCHEMA\0v1\0",
                "task-provider-artifact-allocation-v0.1",
            );
            let prior_snapshot_created: Option<String> = tx
                .query_row(
                    "SELECT created_at FROM policy_snapshots WHERE snapshot_id=?1",
                    [&snapshot_id],
                    |r| r.get(0),
                )
                .optional()?;
            let snapshot_created = prior_snapshot_created.as_deref().unwrap_or(now);
            let snapshot_json =
                canonical_json(&json!({"schema_version":"0.1","snapshot_id":snapshot_id,
            "scope":{"kind":"device","id":"stage1-local"},"policy_language":"builtin",
            "policy_language_version":"0.1","policy_set_hash":content_hash,
            "entity_schema_hash":entity_hash,"engine":{"id":"aios-deterministic","version":"0.1"},
            "created_at":snapshot_created}))?;
            tx.execute("INSERT OR IGNORE INTO policy_snapshots(snapshot_id,scope_kind,scope_id,policy_language,
            policy_language_version,policy_set_hash,entity_schema_hash,engine_id,engine_version,snapshot_json,created_at)
            VALUES (?1,'device','stage1-local','builtin','0.1',?2,?3,'aios-deterministic','0.1',?4,?5)",
            params![snapshot_id,content_hash,entity_hash,snapshot_json,snapshot_created])?;
            let stored: String = tx.query_row(
                "SELECT snapshot_json FROM policy_snapshots WHERE snapshot_id=?1",
                [&snapshot_id],
                |r| r.get(0),
            )?;
            if stored != snapshot_json {
                return Err(reject());
            }
            Ok(revision)
        })
    }

    /// Evaluate all normalized candidate resources. This writes only requests,
    /// decisions, and approval prompts; it cannot issue a grant or launch work.
    #[allow(
        clippy::too_many_lines,
        clippy::needless_borrow,
        reason = "keeps the private evaluation transaction atomic"
    )]
    pub(crate) fn evaluate_pending_authority_candidate(
        &mut self,
        candidate_id: &str,
    ) -> Result<CandidatePolicyEvaluation> {
        let started =
            super::trusted_time::assess(&self.connection, &self.clock)?.require_trusted_time()?;
        let started_at = checked_time(&started)?;
        let preliminary = CandidateFacts::load(&self.connection, candidate_id, started_at)?;
        let selected = self.provider_store_writer()?.eligible_candidates(
            &preliminary.capability,
            &preliminary.contract_hash,
            &preliminary.snapshot,
            &started,
        )?;
        super::trusted_time::with_protected_immediate(
            &self.connection,
            &self.clock,
            |tx, started| {
                let started_at = checked_time(started)?;
                assert_manager_lease(&tx, &self.lease_owner, self.lease_epoch)?;
                let (revision, content_hash, policy_json): (i64, String, String) = tx
            .query_row(
                "SELECT a.revision,a.content_hash,p.policy_json FROM authority_policy_activations a
             JOIN authority_policy_payloads p USING(content_hash)
             WHERE a.revision=(SELECT MAX(revision) FROM authority_policy_activations)",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?
            .ok_or_else(reject)?;
                if digest(b"AIOS-LOCAL-AUTHORITY-POLICY\0v1\0", &policy_json) != content_hash {
                    return Err(reject());
                }
                let policy = LocalPolicy::parse(policy_json.as_bytes())?;
                if canonical_json(&policy)? != policy_json {
                    return Err(reject());
                }
                let activated_at: String = tx.query_row(
                    "SELECT activated_at FROM authority_policy_activations WHERE revision=?1",
                    [revision],
                    |r| r.get(0),
                )?;
                if checked_time(&activated_at)? > started_at {
                    return Err(reject());
                }
                let snapshot_id = content_hash.clone();
                let snapshot:(String,String,String,String,String,String,String,String,String,String)=tx.query_row(
            "SELECT scope_kind,scope_id,policy_language,policy_language_version,policy_set_hash,
              entity_schema_hash,engine_id,engine_version,snapshot_json,created_at
             FROM policy_snapshots WHERE snapshot_id=?1",[&snapshot_id],
            |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?)))
            .optional()?.ok_or_else(reject)?;
                let entity_hash = digest(
                    b"AIOS-LOCAL-POLICY-ENTITY-SCHEMA\0v1\0",
                    "task-provider-artifact-allocation-v0.1",
                );
                if snapshot.0 != "device"
                    || snapshot.1 != "stage1-local"
                    || snapshot.2 != "builtin"
                    || snapshot.3 != "0.1"
                    || snapshot.4 != content_hash
                    || snapshot.5 != entity_hash
                    || snapshot.6 != "aios-deterministic"
                    || snapshot.7 != "0.1"
                    || checked_time(&snapshot.9)? > started_at
                {
                    return Err(reject());
                }
                let expected_snapshot = canonical_json(
                    &json!({"schema_version":"0.1","snapshot_id":snapshot_id,
            "scope":{"kind":"device","id":"stage1-local"},"policy_language":"builtin",
            "policy_language_version":"0.1","policy_set_hash":content_hash,"entity_schema_hash":entity_hash,
            "engine":{"id":"aios-deterministic","version":"0.1"},"created_at":snapshot.9}),
                )?;
                if snapshot.8 != expected_snapshot {
                    return Err(reject());
                }
                let facts = CandidateFacts::load(&tx, candidate_id, started_at)?;
                if !super::active_program_validation_valid(&tx, &facts.task_id, &facts.hash)? {
                    return Err(reject());
                }
                if !provider_pins_current(&tx, &facts, selected, &started)? {
                    return Err(reject());
                }
                let mut decisions = Vec::new();
                for resource in &facts.resources {
                    let fingerprint = facts.fingerprint(resource, revision, &content_hash)?;
                    let request_id = format!(
                        "request:{}",
                        digest(
                            b"AIOS-AUTHORITY-REQUEST\0v1\0",
                            &format!(
                                "{}\0{}\0{}",
                                facts.candidate_id, resource.action, resource.selector
                            )
                        )
                    );
                    let prior: Option<(String, String)> = tx
                .query_row(
                    "SELECT request_json,requested_at FROM authority_requests WHERE request_id=?1",
                    [&request_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
                    let requested_at = prior.as_ref().map_or(started, |(_, at)| at.as_str());
                    if checked_time(requested_at)? > started_at {
                        return Err(reject());
                    }
                    let request_json = canonical_json(
                        &json!({"schema_version":"0.1","request_id":request_id,
                "task_id":facts.task_id,"semantic_program_hash":facts.hash,"registry_snapshot_id":facts.snapshot,
                "node_id":facts.node,"capability":facts.capability,"principal":{"kind":"provider",
                    "id":facts.provider_id,"version":facts.provider_version,"package_or_build_hash":facts.build_hash},
                "action":resource.action,"resource":{"semantic_selector":resource.selector,
                    "resolved_kind":resource.kind,"resolved_id":resource.id,"sensitivity":resource.sensitivity},
                "execution_binding_id":facts.binding_id,"attempt_id":facts.attempt_id,
                "effect_classes":[if resource.action=="artifact.read"{"ARTIFACT_READ"}else{"ARTIFACT_WRITE"}],
                "requested_at":requested_at}),
                    )?;
                    if let Some((prior, _)) = prior {
                        let exact:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM authority_requests WHERE request_id=?1
                    AND task_id=?2 AND semantic_program_hash=?3 AND registry_snapshot_id=?4
                    AND node_id=?5 AND capability=?6 AND principal_kind='provider' AND principal_id=?7
                    AND execution_binding_id=?8 AND attempt_id=?9 AND action=?10
                    AND resolved_resource_kind=?11 AND resolved_resource_id=?12 AND semantic_selector=?13)",
                    params![request_id,facts.task_id,facts.hash,facts.snapshot,facts.node,facts.capability,
                        facts.provider_id,facts.binding_id,facts.attempt_id,resource.action,
                        resource.kind,resource.id,resource.selector],|r|r.get(0))?;
                        if prior != request_json || !exact {
                            return Err(reject());
                        }
                    } else {
                        tx.execute("INSERT INTO authority_requests(request_id,task_id,semantic_program_hash,
                    registry_snapshot_id,node_id,capability,principal_kind,principal_id,
                    execution_binding_id,attempt_id,action,resolved_resource_kind,resolved_resource_id,
                    semantic_selector,request_json,requested_at)
                    VALUES (?1,?2,?3,?4,?5,?6,'provider',?7,?8,?9,?10,?11,?12,?13,?14,?15)",
                    params![request_id,facts.task_id,facts.hash,facts.snapshot,facts.node,facts.capability,
                        facts.provider_id,facts.binding_id,facts.attempt_id,resource.action,resource.kind,
                        resource.id,resource.selector,request_json,started])?;
                    }
                    let base =
                        policy.decide(&resource.action, &resource.kind, &resource.sensitivity);
                    let approval_id = if base == PolicyEffect::RequireApproval {
                        Some(format!(
                            "approval:{}",
                            digest(
                                b"AIOS-AUTHORITY-APPROVAL\0v1\0",
                                &format!("{request_id}\0{fingerprint}")
                            )
                        ))
                    } else {
                        None
                    };
                    let mut effect = base;
                    let mut approval_timing: Option<(String, String)> = None;
                    if let Some(approval_id) = &approval_id {
                        let prior:Option<(String,String,Option<String>,String,String)>=tx.query_row(
                    "SELECT a.status,b.fingerprint,b.revoked_at,a.expires_at,a.created_at FROM approval_requests a
                     JOIN authority_approval_bindings b ON b.approval_id=a.approval_id WHERE a.approval_id=?1",
                    [approval_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
                        if let Some((status, pin, revoked, expires, created)) = prior {
                            if pin != fingerprint
                                || revoked.is_some()
                                || checked_time(&expires)? <= started_at
                            {
                                return Err(reject());
                            }
                            if checked_time(&created)? > started_at {
                                return Err(reject());
                            }
                            checked_approval_request(
                                &tx,
                                &facts,
                                resource,
                                approval_id,
                                &request_id,
                                &fingerprint,
                                revision,
                                &content_hash,
                                &created,
                                &expires,
                            )?;
                            approval_timing = Some((created, expires.clone()));
                            effect = match status.as_str() {
                                "APPROVED" => {
                                    checked_approval_decision(
                                        &tx,
                                        approval_id,
                                        &status,
                                        &facts.task_id,
                                        &facts.task_principal_id,
                                        &expires,
                                        started_at,
                                    )?;
                                    PolicyEffect::Allow
                                }
                                "DENIED" => {
                                    checked_approval_decision(
                                        &tx,
                                        approval_id,
                                        &status,
                                        &facts.task_id,
                                        &facts.task_principal_id,
                                        &expires,
                                        started_at,
                                    )?;
                                    PolicyEffect::Deny
                                }
                                "PENDING" => PolicyEffect::RequireApproval,
                                _ => return Err(reject()),
                            };
                        }
                    }
                    let phase = match effect {
                        PolicyEffect::Allow if base == PolicyEffect::RequireApproval => "approved",
                        PolicyEffect::Deny if base == PolicyEffect::RequireApproval => {
                            "approval-denied"
                        }
                        _ => "initial",
                    };
                    let decision_id = format!(
                        "decision:{}",
                        digest(
                            b"AIOS-AUTHORITY-DECISION\0v1\0",
                            &format!("{request_id}\0{fingerprint}\0{phase}")
                        )
                    );
                    if base == PolicyEffect::RequireApproval && phase == "initial" {
                        let id = approval_id.as_deref().ok_or_else(reject)?;
                        let had_binding = approval_timing.is_some();
                        let (created, expiry) = match approval_timing {
                            Some(pair) => pair,
                            None => (
                                started.to_owned(),
                                (started_at + Duration::hours(1))
                                    .format(&Rfc3339)
                                    .map_err(|_| reject())?,
                            ),
                        };
                        let prompt =
                            approval_prompt(&facts, resource, id, &request_id, &created, &expiry)?;
                        let existing:Option<StoredApprovalRequest>=tx.query_row(
                    "SELECT authority_request_id,task_id,semantic_program_hash,node_id,action,status,
                      request_json,created_at,expires_at FROM approval_requests WHERE approval_id=?1",
                    [id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?))).optional()?;
                        if let Some((
                            stored_request,
                            task,
                            hash,
                            node,
                            action,
                            status,
                            stored_prompt,
                            stored_created,
                            stored_expiry,
                        )) = existing
                        {
                            if !had_binding
                                || stored_request != request_id
                                || task != facts.task_id
                                || hash != facts.hash
                                || node != facts.node
                                || action != resource.action
                                || status != "PENDING"
                                || stored_prompt != prompt
                                || stored_expiry != expiry
                                || stored_created != created
                            {
                                return Err(reject());
                            }
                        } else {
                            tx.execute(
                        "INSERT INTO approval_requests(approval_id,authority_request_id,task_id,
                    semantic_program_hash,node_id,action,status,request_json,created_at,expires_at)
                    VALUES (?1,?2,?3,?4,?5,?6,'PENDING',?7,?8,?9)",
                        params![
                            id,
                            request_id,
                            facts.task_id,
                            facts.hash,
                            facts.node,
                            resource.action,
                            prompt,
                            created,
                            expiry
                        ],
                    )?;
                        }
                    }
                    let existing: Option<(String, String)> = tx
                .query_row(
                    "SELECT decision_json,decided_at FROM policy_decisions WHERE decision_id=?1",
                    [&decision_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
                    let decided_at = existing.as_ref().map_or(started, |(_, at)| at.as_str());
                    if checked_time(decided_at)? > started_at {
                        return Err(reject());
                    }
                    let reason = match (effect, phase) {
                        (PolicyEffect::Allow, "approved") => "APPROVAL_GRANTED",
                        (PolicyEffect::Allow, _) => "POLICY_ALLOW",
                        (PolicyEffect::Deny, "approval-denied") => "APPROVAL_DENIED",
                        (PolicyEffect::Deny, _) => "POLICY_DENY",
                        _ => "POLICY_REQUIRES_APPROVAL",
                    };
                    let decision_json = canonical_json(
                        &json!({"schema_version":"0.1","decision_id":decision_id,
                "authority_request_id":request_id,"task_id":facts.task_id,"semantic_program_hash":facts.hash,
                "registry_snapshot_id":facts.snapshot,"node_id":facts.node,"capability":facts.capability,
                "principal":{"kind":"provider","id":facts.provider_id,"version":facts.provider_version,
                    "package_or_build_hash":facts.build_hash},"action":resource.action,
                "resource":{"resolved_kind":resource.kind,"resolved_id":resource.id,
                    "semantic_selector":resource.selector,"sensitivity":resource.sensitivity},
                "decision":effect.as_str(),"policy_snapshot_id":snapshot_id,"reason_codes":[reason],
                "approval_request_id":approval_id,"engine":{"id":"aios-deterministic","version":"0.1"},
                "decided_at":decided_at}),
                    )?;
                    if let Some((existing, _)) = &existing {
                        let exact: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM policy_decisions d
                    JOIN authority_evaluation_fingerprints e ON e.decision_id=d.decision_id
                    WHERE d.decision_id=?1
                    AND d.authority_request_id=?2 AND d.task_id=?3 AND d.semantic_program_hash=?4
                    AND d.node_id=?5 AND d.principal_kind='provider' AND d.principal_id=?6 AND d.action=?7
                    AND d.resolved_resource_kind=?8 AND d.resolved_resource_id=?9 AND d.decision=?10
                    AND d.policy_snapshot_id=?11 AND d.approval_request_id IS ?12
                    AND d.reason_codes_json=?13 AND e.candidate_id=?14 AND e.fingerprint=?15
                    AND e.activation_revision=?16 AND e.evaluated_at=?17)",
                    params![
                        decision_id,
                        request_id,
                        facts.task_id,
                        facts.hash,
                        facts.node,
                        facts.provider_id,
                        resource.action,
                        resource.kind,
                        resource.id,
                        effect.as_str(),
                        snapshot_id,
                        approval_id,
                        canonical_json(&vec![reason])?,
                        facts.candidate_id,
                        fingerprint,
                        revision,
                        decided_at
                    ],
                    |r| r.get(0),
                )?;
                        if existing != &decision_json || !exact {
                            return Err(reject());
                        }
                    } else {
                        tx.execute(
                            "INSERT INTO policy_decisions(decision_id,authority_request_id,task_id,
                    semantic_program_hash,node_id,principal_kind,principal_id,action,
                    resolved_resource_kind,resolved_resource_id,decision,policy_snapshot_id,
                    approval_request_id,reason_codes_json,decision_json,decided_at)
                    VALUES (?1,?2,?3,?4,?5,'provider',?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
                            params![
                                decision_id,
                                request_id,
                                facts.task_id,
                                facts.hash,
                                facts.node,
                                facts.provider_id,
                                resource.action,
                                resource.kind,
                                resource.id,
                                effect.as_str(),
                                snapshot_id,
                                approval_id,
                                canonical_json(&vec![reason])?,
                                decision_json,
                                started
                            ],
                        )?;
                        tx.execute(
                    "INSERT INTO authority_evaluation_fingerprints(decision_id,candidate_id,
                    fingerprint,activation_revision,evaluated_at) VALUES (?1,?2,?3,?4,?5)",
                    params![
                        decision_id,
                        facts.candidate_id,
                        fingerprint,
                        revision,
                        started
                    ],
                )?;
                    }
                    if base == PolicyEffect::RequireApproval && phase == "initial" {
                        let old: Option<(String, String, i64, String)> = tx
                    .query_row(
                        "SELECT candidate_id,fingerprint,activation_revision,requiring_decision_id
                     FROM authority_approval_bindings WHERE approval_id=?1",
                        [approval_id.as_deref()],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                    )
                    .optional()?;
                        if let Some(old) = old {
                            if old
                                != (
                                    facts.candidate_id.clone(),
                                    fingerprint.clone(),
                                    revision,
                                    decision_id.clone(),
                                )
                            {
                                return Err(reject());
                            }
                        } else {
                            tx.execute(
                                "INSERT INTO authority_approval_bindings(approval_id,candidate_id,
                    fingerprint,activation_revision,requiring_decision_id) VALUES (?1,?2,?3,?4,?5)",
                                params![
                                    approval_id,
                                    facts.candidate_id,
                                    fingerprint,
                                    revision,
                                    decision_id
                                ],
                            )?;
                        }
                    }
                    decisions.push(CandidatePolicyDecision {
                        action: resource.action.clone(),
                        semantic_selector: resource.selector.clone(),
                        authority_request_id: request_id,
                        decision_id,
                        effect,
                        approval_id,
                        evaluation_fingerprint: fingerprint,
                    });
                }
                Ok(CandidatePolicyEvaluation {
                    activation_revision: revision,
                    decisions,
                })
            },
        )
    }

    /// Record a local authenticated user's one-shot decision after validating
    /// the complete current fingerprint. No provider-controlled approval path exists.
    #[allow(
        clippy::too_many_lines,
        clippy::needless_borrow,
        reason = "keeps approval freshness, policy, and durable decision in one transaction"
    )]
    pub(crate) fn decide_candidate_approval(
        &mut self,
        approval_id: &str,
        approver: &AuthenticatedApprover<'_>,
        approve: bool,
    ) -> Result<()> {
        let now =
            super::trusted_time::assess(&self.connection, &self.clock)?.require_trusted_time()?;
        let checked = checked_time(&now)?;
        let candidate_id: String = self
            .connection
            .query_row(
                "SELECT candidate_id FROM authority_approval_bindings WHERE approval_id=?1",
                [approval_id],
                |r| r.get(0),
            )
            .optional()?
            .ok_or_else(reject)?;
        let preliminary = CandidateFacts::load(&self.connection, &candidate_id, checked)?;
        let eligible = self.provider_store_writer()?.eligible_candidates(
            &preliminary.capability,
            &preliminary.contract_hash,
            &preliminary.snapshot,
            &now,
        )?;
        super::trusted_time::with_protected_immediate(&self.connection, &self.clock, |tx, now| {
            let checked = checked_time(now)?;
            assert_manager_lease(&tx, &self.lease_owner, self.lease_epoch)?;
            let (candidate_id,pin,revision,status,expires,principal,created): (String,String,i64,String,String,String,String)=tx.query_row(
            "SELECT b.candidate_id,b.fingerprint,b.activation_revision,a.status,a.expires_at,t.principal_id,a.created_at
             FROM authority_approval_bindings b JOIN approval_requests a USING(approval_id)
             JOIN tasks t ON t.task_id=a.task_id WHERE b.approval_id=?1",
            [approval_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?)))
            .optional()?.ok_or_else(reject)?;
            if status != "PENDING"
                || principal != approver.principal_id
                || principal.is_empty()
                || checked_time(&expires)? <= checked
                || checked_time(&created)? > checked
            {
                return Err(reject());
            }
            let current_revision: i64 = tx.query_row(
                "SELECT MAX(revision) FROM authority_policy_activations",
                [],
                |r| r.get(0),
            )?;
            if revision != current_revision {
                return Err(reject());
            }
            let facts = CandidateFacts::load(&tx, &candidate_id, checked)?;
            if !super::active_program_validation_valid(&tx, &facts.task_id, &facts.hash)? {
                return Err(reject());
            }
            if !provider_pins_current(&tx, &facts, eligible, &now)? {
                return Err(reject());
            }
            let content_hash: String = tx.query_row(
                "SELECT content_hash FROM authority_policy_activations WHERE revision=?1",
                [revision],
                |r| r.get(0),
            )?;
            let policy_json: String = tx
                .query_row(
                    "SELECT policy_json FROM authority_policy_payloads WHERE content_hash=?1",
                    [&content_hash],
                    |r| r.get(0),
                )
                .optional()?
                .ok_or_else(reject)?;
            if digest(b"AIOS-LOCAL-AUTHORITY-POLICY\0v1\0", &policy_json) != content_hash {
                return Err(reject());
            }
            let policy = LocalPolicy::parse(policy_json.as_bytes())?;
            if canonical_json(&policy)? != policy_json {
                return Err(reject());
            }
            let bound:Option<(String,String,String,String)>=tx.query_row(
            "SELECT r.request_id,r.action,r.semantic_selector,r.resolved_resource_id FROM approval_requests a
             JOIN authority_requests r ON r.request_id=a.authority_request_id WHERE a.approval_id=?1",
            [approval_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
            let (request_id, action, selector, id) = bound.ok_or_else(reject)?;
            let resource = facts
                .resources
                .iter()
                .find(|r| r.action == action && r.selector == selector && r.id == id)
                .ok_or_else(reject)?;
            if policy.decide(&resource.action, &resource.kind, &resource.sensitivity)
                != PolicyEffect::RequireApproval
            {
                return Err(reject());
            }
            if facts.fingerprint(resource, revision, &content_hash)? != pin {
                return Err(reject());
            }
            checked_approval_request(
                &tx,
                &facts,
                resource,
                approval_id,
                &request_id,
                &pin,
                revision,
                &content_hash,
                &created,
                &expires,
            )?;
            let decision_id = format!(
                "approval-decision:{}",
                digest(b"AIOS-APPROVAL-DECISION\0v1\0", approval_id)
            );
            let decision_json =
                canonical_json(&json!({"schema_version":"0.1","decision_id":decision_id,
            "approval_id":approval_id,"task_id":facts.task_id,
            "decision":if approve{"APPROVE"}else{"DENY"},
            "decided_by":{"kind":"user","id":principal},"scope":"ONE_SHOT",
            "approved_until":if approve{Some(expires.as_str())}else{None},"decided_at":now}))?;
            tx.execute(
                "INSERT INTO approval_decisions(decision_id,approval_id,task_id,decision,
            decided_by_kind,decided_by_id,scope,approved_until,decision_json,decided_at)
            VALUES (?1,?2,?3,?4,'user',?5,'ONE_SHOT',?6,?7,?8)",
                params![
                    decision_id,
                    approval_id,
                    facts.task_id,
                    if approve { "APPROVE" } else { "DENY" },
                    principal,
                    if approve {
                        Some(expires.as_str())
                    } else {
                        None
                    },
                    decision_json,
                    now
                ],
            )?;
            tx.execute(
                "UPDATE approval_requests SET status=?1 WHERE approval_id=?2 AND status='PENDING'",
                params![if approve { "APPROVED" } else { "DENIED" }, approval_id],
            )?;
            Ok(())
        })
    }

    /// Withdraw a prior approval. The sidecar is deliberately one-way because
    /// the baseline approval tables do not yet represent REVOKE/REVOKED.
    pub(crate) fn revoke_candidate_approval(
        &mut self,
        approval_id: &str,
        approver: &AuthenticatedApprover<'_>,
    ) -> Result<()> {
        let now = self.clock.now();
        let checked = checked_time(&now)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        assert_manager_lease(&tx, &self.lease_owner, self.lease_epoch)?;
        let (owner, status, revoked, created): (String, String, Option<String>,String) = tx
            .query_row(
                "SELECT t.principal_id,a.status,b.revoked_at,a.created_at FROM authority_approval_bindings b
             JOIN approval_requests a USING(approval_id) JOIN tasks t ON t.task_id=a.task_id
             WHERE b.approval_id=?1",
                [approval_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?,r.get(3)?)),
            )
            .optional()?
            .ok_or_else(reject)?;
        if owner != approver.principal_id
            || owner.is_empty()
            || status != "APPROVED"
            || revoked.is_some()
            || checked_time(&created)? > checked
        {
            return Err(reject());
        }
        tx.execute("UPDATE authority_approval_bindings SET revoked_at=?1 WHERE approval_id=?2 AND revoked_at IS NULL",params![now,approval_id])?;
        tx.commit()?;
        Ok(())
    }
}
