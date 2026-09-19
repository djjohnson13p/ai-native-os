//! Raw structural admission precedes typed decoding and semantic interpretation.

use std::sync::OnceLock;

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{RegistryError, RegistryResult, StrictJsonLimits, parse_strict_value};

#[derive(Clone, Copy)]
pub(crate) enum RecordKind {
    Snapshot,
    Type,
    Capability,
}

static SNAPSHOT: OnceLock<Result<jsonschema::Validator, String>> = OnceLock::new();
static TYPE: OnceLock<Result<jsonschema::Validator, String>> = OnceLock::new();
static CAPABILITY: OnceLock<Result<jsonschema::Validator, String>> = OnceLock::new();

pub(crate) fn validate(kind: RecordKind, value: &Value) -> RegistryResult<()> {
    let (cache, source) = match kind {
        RecordKind::Snapshot => (
            &SNAPSHOT,
            include_str!("../../../specs/registry-snapshot.schema.json"),
        ),
        RecordKind::Type => (
            &TYPE,
            include_str!("../../../specs/type-contract.schema.json"),
        ),
        RecordKind::Capability => (
            &CAPABILITY,
            include_str!("../../../specs/capability-contract.schema.json"),
        ),
    };
    let validator = cache
        .get_or_init(|| {
            let schema: Value = serde_json::from_str(source).map_err(|error| error.to_string())?;
            // Only embedded schemas with internal refs; dependency resolver features are disabled.
            jsonschema::options()
                .should_validate_formats(true)
                .build(&schema)
                .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|error| RegistryError::schema(format!("embedded registry schema: {error}")))?;
    if let Some(error) = validator.iter_errors(value).next() {
        // Do not render arbitrary instance content or collect a diagnostic storm.
        return Err(RegistryError::schema(format!(
            "registry structural schema violation at {} (schema {})",
            error.instance_path(),
            error.schema_path()
        )));
    }
    Ok(())
}

pub(crate) fn decode<T: DeserializeOwned>(
    bytes: &[u8],
    limits: StrictJsonLimits,
    kind: RecordKind,
    array: bool,
) -> RegistryResult<T> {
    if bytes.len() > limits.max_bytes {
        return Err(RegistryError::schema("registry JSON exceeds byte limit"));
    }
    let bytes =
        crate::numbers::prepare_numbers(bytes, crate::numbers::NumberProfile::RegistryTolerance)
            .map_err(RegistryError::schema)?;
    let value = parse_strict_value(&bytes, limits)?;
    if array {
        let values = value
            .as_array()
            .ok_or_else(|| RegistryError::schema("contract source must be an array"))?;
        for record in values {
            validate(kind, record)?;
        }
    } else {
        if matches!(kind, RecordKind::Snapshot)
            && value
                .get("schema_version")
                .and_then(Value::as_str)
                .is_some_and(|version| version != "0.1")
        {
            return Err(RegistryError::validation(
                aios_contracts::ValidatorReasonCode::RegistryUnsupportedVersion,
                "unsupported registry schema version",
            ));
        }
        validate(kind, &value)?;
    }
    serde_json::from_value(value)
        .map_err(|error| RegistryError::schema(format!("registry typed decoding: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aios_contracts::{CapabilityContract, RegistrySnapshot, TypeContract, ValidatorReasonCode};

    fn fixture(name: &str) -> Value {
        serde_json::from_slice(
            &std::fs::read(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../examples/aios-ir")
                    .join(name),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn decode_record(kind: RecordKind, bytes: &[u8]) -> RegistryResult<()> {
        let limits = StrictJsonLimits::default();
        match kind {
            RecordKind::Snapshot => {
                decode::<RegistrySnapshot>(bytes, limits, kind, false).map(|_| ())
            }
            RecordKind::Type => decode::<TypeContract>(bytes, limits, kind, false).map(|_| ()),
            RecordKind::Capability => {
                decode::<CapabilityContract>(bytes, limits, kind, false).map(|_| ())
            }
        }
    }

    #[test]
    fn registry_optional_fields_match_authored_schema_structure() {
        for case in fixture("registry-structure-repair-cases.json")
            .as_array()
            .unwrap()
        {
            let (kind, mut record) = match case["record"].as_str().unwrap() {
                "type" => (RecordKind::Type, fixture("type-contracts.json")[0].clone()),
                "capability" => (
                    RecordKind::Capability,
                    fixture("capability-contracts.json")[0].clone(),
                ),
                "snapshot" => (RecordKind::Snapshot, fixture("registry-snapshot.json")),
                _ => panic!("unknown fixture kind"),
            };
            let (parent, member) = case["pointer"].as_str().unwrap().rsplit_once('/').unwrap();
            let object = record.pointer_mut(parent).unwrap().as_object_mut().unwrap();
            if case["omit"] == true {
                object.remove(member);
            } else {
                object.insert(member.to_owned(), case["value"].clone());
            }
            let expected = case["valid"].as_bool().unwrap();
            assert_eq!(validate(kind, &record).is_ok(), expected, "schema: {case}");
            let decoded = decode_record(kind, &serde_json::to_vec(&record).unwrap());
            assert_eq!(decoded.is_ok(), expected, "admission: {case}: {decoded:?}");
            if let Err(error) = decoded {
                assert_eq!(
                    error.reason_code(),
                    Some(ValidatorReasonCode::RegistrySchemaInvalid)
                );
            }
        }
    }

    #[test]
    fn both_tolerance_contract_paths_enforce_lexical_profile() {
        for kind in [RecordKind::Type, RecordKind::Capability] {
            for field in ["numeric_absolute_tolerance", "numeric_relative_tolerance"] {
                for case in fixture("review-repair-cases.json")["tolerance_cases"]
                    .as_array()
                    .unwrap()
                {
                    let (mut record, parent) = match kind {
                        RecordKind::Type => (fixture("type-contracts.json")[0].clone(), "equality"),
                        _ => (
                            fixture("capability-contracts.json")[0].clone(),
                            "determinism",
                        ),
                    };
                    record[parent][field] = serde_json::json!("RAW_NUMBER");
                    let bytes = serde_json::to_string(&record)
                        .unwrap()
                        .replace("\"RAW_NUMBER\"", case["token"].as_str().unwrap());
                    let decoded = decode_record(kind, bytes.as_bytes());
                    assert_eq!(
                        decoded.is_ok(),
                        case["valid"].as_bool().unwrap(),
                        "{parent}/{field}: {case}: {decoded:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn tolerance_rounding_is_binary64_ties_even_and_hash_stable() {
        for (authored, rounded) in [
            ("-0.000e999999999999999999999", "0"),
            ("0.10000000000000000", "0.1"),
            ("9007199254740993", "9007199254740992"),
            ("9007199254740995", "9007199254740996"),
            (
                "1.00000000000000011102230246251565404236316680908203125",
                "1",
            ),
            (
                "1.00000000000000011102230246251565404236316680908203126",
                "1.0000000000000002",
            ),
            ("333333333.33333329", "333333333.3333333"),
        ] {
            let mut record = fixture("capability-contracts.json")[0].clone();
            record["determinism"]["numeric_absolute_tolerance"] = serde_json::json!("RAW_NUMBER");
            let template = serde_json::to_string(&record).unwrap();
            let decode_token = |token| {
                decode::<CapabilityContract>(
                    template.replace("\"RAW_NUMBER\"", token).as_bytes(),
                    StrictJsonLimits::default(),
                    RecordKind::Capability,
                    false,
                )
                .unwrap()
            };
            let left = crate::capability_contract_hash(&decode_token(authored)).unwrap();
            let right = crate::capability_contract_hash(&decode_token(rounded)).unwrap();
            assert_eq!(left, right, "{authored} -> {rounded}");
        }
    }
}
