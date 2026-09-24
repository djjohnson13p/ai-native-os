//! One exact-key receipt projection for durable admission and launch.

use std::sync::OnceLock;

use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{StrictJsonError, StrictJsonLimits, parse_strict_value};

static EXECUTION_BINDING_SCHEMA: OnceLock<Result<jsonschema::Validator, String>> = OnceLock::new();

/// Immutable columns that a binding receipt must project exactly.
pub struct BindingReceiptColumns<'a> {
    pub binding_id: &'a str,
    pub attempt_id: &'a str,
    pub task_id: &'a str,
    pub semantic_program_hash: &'a str,
    pub registry_snapshot_id: &'a str,
    pub ir_version: &'a str,
    pub node_id: &'a str,
    pub capability: &'a str,
    pub capability_contract_hash: Option<&'a str>,
    pub provider_id: &'a str,
    pub provider_version: &'a str,
    pub provider_manifest_hash: Option<&'a str>,
    pub provider_build_hash: Option<&'a str>,
    pub attempt: i64,
    pub policy_decision_refs_json: &'a str,
    pub grant_refs_json: &'a str,
    pub execution_profile_ref: &'a str,
    pub placement_json: &'a str,
    pub created_at: &'a str,
}

/// A strictly parsed receipt. Accessors use exact Rust object keys throughout.
pub struct BindingReceiptProjection {
    value: Value,
}

impl BindingReceiptProjection {
    /// Parse once with the limits and duplicate-key rules shared by admission and launch.
    ///
    /// # Errors
    /// Returns a strict parser error for malformed, duplicate-key, or over-limit JSON.
    pub fn parse(raw: &[u8]) -> Result<Self, StrictJsonError> {
        parse_strict_value(raw, StrictJsonLimits::default()).map(|value| Self { value })
    }

    /// Stamped provider stores admit the complete public v0.1 receipt contract.
    /// Historical unstamped receipts keep their separate compatibility profile.
    pub fn conforms_to_stamped_schema(&self) -> bool {
        let validator = EXECUTION_BINDING_SCHEMA.get_or_init(|| {
            let schema: Value =
                serde_json::from_str(include_str!("../../../specs/execution-binding.schema.json"))
                    .map_err(|error| error.to_string())?;
            jsonschema::options()
                .should_validate_formats(true)
                .build(&schema)
                .map_err(|error| error.to_string())
        });
        validator
            .as_ref()
            .is_ok_and(|validator| validator.is_valid(&self.value))
    }

    /// Match every column projection that launch needs before the attempt is consumed.
    pub fn matches_columns(&self, columns: &BindingReceiptColumns<'_>) -> bool {
        let value = &self.value;
        let Some(policy) = parse_companion(columns.policy_decision_refs_json) else {
            return false;
        };
        let Some(grants) = parse_companion(columns.grant_refs_json) else {
            return false;
        };
        let Some(placement) = parse_companion(columns.placement_json) else {
            return false;
        };
        columns.attempt >= 1
            && OffsetDateTime::parse(columns.created_at, &Rfc3339).is_ok()
            && valid_refs(&policy)
            && valid_refs(&grants)
            && placement.is_object()
            && value.get("schema_version").and_then(Value::as_str) == Some("0.1")
            && value.get("binding_id").and_then(Value::as_str) == Some(columns.binding_id)
            && value.get("attempt_id").and_then(Value::as_str) == Some(columns.attempt_id)
            && value.get("task_id").and_then(Value::as_str) == Some(columns.task_id)
            && value.get("semantic_program_hash").and_then(Value::as_str)
                == Some(columns.semantic_program_hash)
            && value.get("registry_snapshot_id").and_then(Value::as_str)
                == Some(columns.registry_snapshot_id)
            && value.get("ir_version").and_then(Value::as_str) == Some(columns.ir_version)
            && value.get("node_id").and_then(Value::as_str) == Some(columns.node_id)
            && value.get("capability").and_then(Value::as_str) == Some(columns.capability)
            && value
                .get("capability_contract_hash")
                .and_then(Value::as_str)
                == columns.capability_contract_hash
            && value.pointer("/provider/id").and_then(Value::as_str) == Some(columns.provider_id)
            && value.pointer("/provider/version").and_then(Value::as_str)
                == Some(columns.provider_version)
            && value
                .pointer("/provider/manifest_hash")
                .and_then(Value::as_str)
                == columns.provider_manifest_hash
            && value
                .pointer("/provider/package_or_build_hash")
                .and_then(Value::as_str)
                == columns.provider_build_hash
            && value.get("attempt").and_then(Value::as_i64) == Some(columns.attempt)
            && value.get("policy_decision_refs") == Some(&policy)
            && value.pointer("/authority/grant_refs") == Some(&grants)
            && value
                .pointer("/execution_profile/profile_ref")
                .and_then(Value::as_str)
                == Some(columns.execution_profile_ref)
            && value.get("placement") == Some(&placement)
            && value.get("inputs").is_some_and(Value::is_object)
            && value.get("outputs").is_some_and(Value::is_object)
            && value.get("created_at").and_then(Value::as_str) == Some(columns.created_at)
    }

    /// The exact evidence pin, if its required receipt value has the right shape.
    pub fn evidence_pin(&self) -> Option<&str> {
        bounded_pin(&self.value, "conformance_evidence_id")
    }

    /// The exact trust source pin, if its required receipt value has the right shape.
    pub fn trust_pin(&self) -> Option<&str> {
        bounded_pin(&self.value, "provider_trust_source_id")
    }

    /// A legacy receipt may omit the evidence pin; stamped receipts may not.
    pub fn evidence_pin_matches(&self, latest_id: &str, required: bool) -> bool {
        match self.value.get("conformance_evidence_id") {
            Some(Value::String(_)) => self.evidence_pin() == Some(latest_id),
            None => !required,
            _ => false,
        }
    }
}

fn parse_companion(raw: &str) -> Option<Value> {
    parse_strict_value(raw.as_bytes(), StrictJsonLimits::default()).ok()
}

fn valid_refs(value: &Value) -> bool {
    let Some(refs) = value.as_array() else {
        return false;
    };
    refs.len() <= 64 && refs.iter().all(Value::is_string) && {
        let mut seen = std::collections::HashSet::new();
        refs.iter()
            .all(|value| seen.insert(value.as_str().unwrap()))
    }
}

fn bounded_pin<'a>(value: &'a Value, name: &str) -> Option<&'a str> {
    value.get(name).and_then(Value::as_str).filter(|pin| {
        let length = pin.chars().count();
        (1..=256).contains(&length)
    })
}
