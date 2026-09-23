//! `SQLite` admission uses the same strict, bounded parser as launch-time checks.

use rusqlite::{Connection, functions::FunctionFlags, types::ValueRef};
use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::provider_store::{manifest_claim_matches_registration, trust_admission_matches_insert};
use crate::{
    BindingReceiptColumns, BindingReceiptProjection, EvidenceMatch, FullVersion,
    ProviderRegistration, StrictJsonLimits, evidence_matches_binding, parse_strict_value,
};

/// Register the parser required by the durable execution-binding insert guard.
/// A separate `SQLite` connection without this function cannot insert a binding.
///
/// # Errors
///
/// Returns the `SQLite` registration error if the connection cannot install the function.
#[allow(
    clippy::too_many_lines,
    reason = "registers one versioned admission parser and its companion SQLite predicates"
)]
pub fn register_strict_json_sqlite(connection: &Connection) -> rusqlite::Result<()> {
    let flags = FunctionFlags::SQLITE_UTF8
        | FunctionFlags::SQLITE_DETERMINISTIC
        | FunctionFlags::SQLITE_INNOCUOUS;
    connection.create_scalar_function("aios_strict_json", 1, flags, |context| {
        let valid = match context.get_raw(0) {
            ValueRef::Text(bytes) => parse_strict_value(bytes, StrictJsonLimits::default()).is_ok(),
            _ => false,
        };
        Ok(valid)
    })?;
    connection.create_scalar_function(
        "aios_manifest_capability_matches_v1",
        3,
        flags,
        |context| {
            let (Some(base), Some(version), Some(capability)) = (
                context.get::<Option<String>>(0)?,
                context.get::<Option<String>>(1)?,
                context.get::<Option<String>>(2)?,
            ) else {
                return Ok(false);
            };
            Ok(FullVersion::parse(&version)
                .is_ok_and(|version| capability == format!("{base}@{}", version.major)))
        },
    )?;
    connection.create_scalar_function(
        "aios_manifest_claim_matches_registration_v1",
        11,
        flags,
        |context| {
            let ValueRef::Text(raw) = context.get_raw(0) else {
                return Ok(false);
            };
            let Ok(manifest_json) = std::str::from_utf8(raw) else {
                return Ok(false);
            };
            let fields = (1..11)
                .map(|index| context.get::<Option<String>>(index))
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let Some(fields) = fields.into_iter().collect::<Option<Vec<_>>>() else {
                return Ok(false);
            };
            let registration = ProviderRegistration {
                registration_id: fields[0].clone(),
                provider_id: fields[1].clone(),
                provider_version: fields[2].clone(),
                manifest_hash: fields[3].clone(),
                build_hash: fields[4].clone(),
                snapshot_id: String::new(),
            };
            Ok(manifest_claim_matches_registration(
                manifest_json,
                &registration,
                &fields[5],
                &fields[6],
                &fields[7],
                &fields[8],
                &fields[9],
            ))
        },
    )?;
    connection.create_scalar_function("aios_evidence_unexpired_at_v1", 2, flags, |context| {
        let ValueRef::Text(raw) = context.get_raw(0) else {
            return Ok(false);
        };
        let Ok(evidence) = parse_strict_value(raw, StrictJsonLimits::default()) else {
            return Ok(false);
        };
        let Some(created_at) = context
            .get::<Option<String>>(1)?
            .and_then(|text| OffsetDateTime::parse(&text, &Rfc3339).ok())
        else {
            return Ok(false);
        };
        Ok(match evidence.get("expires_at") {
            None | Some(Value::Null) => true,
            Some(Value::String(text)) => OffsetDateTime::parse(text, &Rfc3339)
                .is_ok_and(|expires_at| expires_at > created_at),
            Some(_) => false,
        })
    })?;
    connection.create_scalar_function(
        "aios_evidence_matches_binding_v1",
        14,
        flags,
        |context| {
            let ValueRef::Text(raw) = context.get_raw(0) else {
                return Ok(false);
            };
            let fields = (1..14)
                .map(|index| context.get::<String>(index))
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let expected = EvidenceMatch {
                evidence_id: &fields[0],
                provider_id: &fields[1],
                provider_version: &fields[2],
                build_hash: &fields[3],
                capability: &fields[4],
                contract_version: &fields[5],
                contract_hash: &fields[6],
                suite_id: &fields[7],
                suite_hash: &fields[8],
                suite_version: &fields[9],
                status: &fields[10],
                tested_at: &fields[11],
                evaluated_at: &fields[12],
            };
            Ok(evidence_matches_binding(raw, &expected))
        },
    )?;
    connection.create_scalar_function("aios_rfc3339_compare_v1", 2, flags, |context| {
        let (Some(left), Some(right)) = (
            context.get::<Option<String>>(0)?,
            context.get::<Option<String>>(1)?,
        ) else {
            return Ok(None::<i64>);
        };
        let (Ok(left), Ok(right)) = (
            OffsetDateTime::parse(&left, &Rfc3339),
            OffsetDateTime::parse(&right, &Rfc3339),
        ) else {
            return Ok(None::<i64>);
        };
        Ok(Some(match left.cmp(&right) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        }))
    })?;
    connection.create_scalar_function(
        "aios_trust_admission_matches_insert_v1",
        11,
        flags,
        |context| {
            let text = |index| match context.get_raw(index) {
                ValueRef::Text(bytes) => std::str::from_utf8(bytes).ok(),
                _ => None,
            };
            let (
                Some(admission_id),
                Some(registration_id),
                Some(decision_id),
                Some(trust_status),
                Some(authority_ref),
                Some(admitted_at),
                Some(receipt_json),
                Some(previous_at),
                Some(initial_trust),
                Some(lifecycle_state),
            ) = (
                text(0),
                text(1),
                text(2),
                text(4),
                text(5),
                text(6),
                text(7),
                text(8),
                text(9),
                text(10),
            )
            else {
                return Ok(false);
            };
            let ValueRef::Integer(revision) = context.get_raw(3) else {
                return Ok(false);
            };
            Ok(trust_admission_matches_insert(
                admission_id,
                registration_id,
                decision_id,
                revision,
                trust_status,
                authority_ref,
                admitted_at,
                receipt_json,
                previous_at,
                initial_trust,
                lifecycle_state,
            ))
        },
    )?;
    connection.create_scalar_function("aios_binding_receipt_matches_v1", 20, flags, |context| {
        let raw: String = context.get(0)?;
        let binding_id: String = context.get(1)?;
        let attempt_id: String = context.get(2)?;
        let task_id: String = context.get(3)?;
        let semantic_program_hash: String = context.get(4)?;
        let registry_snapshot_id: String = context.get(5)?;
        let ir_version: String = context.get(6)?;
        let node_id: String = context.get(7)?;
        let capability: String = context.get(8)?;
        let capability_contract_hash: String = context.get(9)?;
        let provider_id: String = context.get(10)?;
        let provider_version: String = context.get(11)?;
        let provider_manifest_hash: String = context.get(12)?;
        let provider_build_hash: String = context.get(13)?;
        let attempt: i64 = context.get(14)?;
        let policy_decision_refs_json: String = context.get(15)?;
        let grant_refs_json: String = context.get(16)?;
        let execution_profile_ref: String = context.get(17)?;
        let placement_json: String = context.get(18)?;
        let created_at: String = context.get(19)?;
        let Ok(receipt) = BindingReceiptProjection::parse(raw.as_bytes()) else {
            return Ok(false);
        };
        let columns = BindingReceiptColumns {
            binding_id: &binding_id,
            attempt_id: &attempt_id,
            task_id: &task_id,
            semantic_program_hash: &semantic_program_hash,
            registry_snapshot_id: &registry_snapshot_id,
            ir_version: &ir_version,
            node_id: &node_id,
            capability: &capability,
            capability_contract_hash: Some(&capability_contract_hash),
            provider_id: &provider_id,
            provider_version: &provider_version,
            provider_manifest_hash: Some(&provider_manifest_hash),
            provider_build_hash: Some(&provider_build_hash),
            attempt,
            policy_decision_refs_json: &policy_decision_refs_json,
            grant_refs_json: &grant_refs_json,
            execution_profile_ref: &execution_profile_ref,
            placement_json: &placement_json,
            created_at: &created_at,
        };
        Ok(receipt.conforms_to_stamped_schema()
            && receipt.matches_columns(&columns)
            && receipt.evidence_pin().is_some()
            && receipt.trust_pin().is_some())
    })?;
    connection.create_scalar_function("aios_binding_evidence_pin_v1", 1, flags, |context| {
        Ok(match context.get_raw(0) {
            ValueRef::Text(raw) => BindingReceiptProjection::parse(raw)
                .ok()
                .and_then(|receipt| receipt.evidence_pin().map(str::to_owned)),
            _ => None,
        })
    })?;
    connection.create_scalar_function("aios_binding_trust_pin_v1", 1, flags, |context| {
        Ok(match context.get_raw(0) {
            ValueRef::Text(raw) => BindingReceiptProjection::parse(raw)
                .ok()
                .and_then(|receipt| receipt.trust_pin().map(str::to_owned)),
            _ => None,
        })
    })
}

#[cfg(test)]
mod tests {
    use rusqlite::{Connection, params};

    use super::register_strict_json_sqlite;

    #[test]
    fn sqlite_admission_uses_the_launch_parser_and_limits() {
        let connection = Connection::open_in_memory().unwrap();
        register_strict_json_sqlite(&connection).unwrap();
        let accepts = |raw: &str| {
            connection
                .query_row("SELECT aios_strict_json(?1)", params![raw], |row| {
                    row.get::<_, bool>(0)
                })
                .unwrap()
        };
        assert!(accepts(" { \"nested\" : [1] } "));
        assert!(!accepts(r#"{"nested":{"bad":"\ud800"}}"#));
        assert!(!accepts(r#"{"nested":{"key":1,"key":2}}"#));
        assert!(!accepts(&format!("{}0{}", "[".repeat(65), "]".repeat(65))));
        assert!(!accepts(&format!(
            "{}{}",
            " ".repeat(8 * 1024 * 1024),
            "[]"
        )));
        let matches = |base: &str, version: &str, capability: &str| {
            connection
                .query_row(
                    "SELECT aios_manifest_capability_matches_v1(?1,?2,?3)",
                    params![base, version, capability],
                    |row| row.get::<_, bool>(0),
                )
                .unwrap()
        };
        assert!(matches("artifact.hash", "1.9.3", "artifact.hash@1"));
        assert!(!matches("artifact.hash", "1.9.3", "artifact.hash@2"));
        assert!(!matches("artifact.hash", "01.9", "artifact.hash@1"));
        assert!(!matches("artifact.hash", "1.9", "artifact.hash@01"));
        assert!(!matches(
            "artifact.hash",
            "18446744073709551616.0",
            "artifact.hash@1"
        ));
        let unexpired = |raw: &str, created_at: &str| {
            connection
                .query_row(
                    "SELECT aios_evidence_unexpired_at_v1(?1,?2)",
                    params![raw, created_at],
                    |row| row.get::<_, bool>(0),
                )
                .unwrap()
        };
        let created = "2026-09-23T00:00:00Z";
        assert!(unexpired(
            r#"{"expires_at":"2026-09-24T01:00:00+01:00"}"#,
            created
        ));
        assert!(!unexpired(
            r#"{"expires_at":"2026-09-22T00:00:00Z"}"#,
            created
        ));
        assert!(!unexpired(
            r#"{"expires_at":"2026-09-24T00:00:00Z","expires_at":null}"#,
            created,
        ));
        assert!(!unexpired(
            r#"{"expires_at\u0000x":null,"expires_at":"2026-09-22T00:00:00Z"}"#,
            created,
        ));
        assert!(!unexpired(
            r#"{"expires_at":"2026-09-24 00:00:00"}"#,
            created
        ));
        let compare = |left: &str, right: &str| {
            connection
                .query_row(
                    "SELECT aios_rfc3339_compare_v1(?1,?2)",
                    params![left, right],
                    |row| row.get::<_, Option<i64>>(0),
                )
                .unwrap()
        };
        assert_eq!(
            compare("2026-09-23T01:00:00+01:00", "2026-09-23T00:00:00Z"),
            Some(0)
        );
        assert_eq!(
            compare("2026-09-23T00:00:00.000000001Z", "2026-09-23T00:00:00Z"),
            Some(1)
        );
        assert_eq!(compare("2026-09-23 00:00:00", created), None);
    }
}
