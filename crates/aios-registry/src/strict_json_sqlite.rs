//! `SQLite` admission uses the same strict, bounded parser as launch-time checks.

use rusqlite::{Connection, functions::FunctionFlags, types::ValueRef};

use crate::{
    BindingReceiptColumns, BindingReceiptProjection, StrictJsonLimits, parse_strict_value,
};

/// Register the parser required by the durable execution-binding insert guard.
/// A separate `SQLite` connection without this function cannot insert a binding.
///
/// # Errors
///
/// Returns the `SQLite` registration error if the connection cannot install the function.
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
        Ok(receipt.matches_columns(&columns)
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
    }
}
