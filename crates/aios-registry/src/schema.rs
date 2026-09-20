//! Raw structural admission precedes typed decoding and semantic interpretation.

use std::sync::OnceLock;

use serde::de::{DeserializeOwned, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
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

pub(crate) fn decode_with_record_limit<T: DeserializeOwned>(
    bytes: &[u8],
    limits: StrictJsonLimits,
    kind: RecordKind,
    array: bool,
    max_records: Option<usize>,
) -> RegistryResult<T> {
    if bytes.len() > limits.max_bytes {
        return Err(RegistryError::schema("registry JSON exceeds byte limit"));
    }
    if array && max_records.is_some_and(|maximum| top_level_array_exceeds_limit(bytes, maximum)) {
        return Err(RegistryError::schema(format!(
            "contract source exceeds the remaining configured maximum of {} records",
            max_records.expect("record maximum was checked as present")
        )));
    }
    if matches!(kind, RecordKind::Snapshot)
        && max_records.is_some_and(|maximum| snapshot_contract_refs_exceed_limit(bytes, maximum))
    {
        return Err(RegistryError::schema(format!(
            "registry snapshot exceeds the configured maximum of {} contract references",
            max_records.expect("record maximum was checked as present")
        )));
    }
    let bytes =
        crate::numbers::prepare_numbers(bytes, crate::numbers::NumberProfile::RegistryTolerance)
            .map_err(RegistryError::schema)?;
    let value = parse_strict_value(&bytes, limits)?;
    if array {
        let values = value
            .as_array()
            .ok_or_else(|| RegistryError::schema("contract source must be an array"))?;
        if let Some(maximum) = max_records
            && values.len() > maximum
        {
            return Err(RegistryError::schema(format!(
                "contract source contains {} records; remaining configured maximum is {}",
                values.len(),
                maximum
            )));
        }
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

fn top_level_array_exceeds_limit(bytes: &[u8], maximum: usize) -> bool {
    let mut index = 0;
    while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
        index += 1;
    }
    if bytes.get(index) != Some(&b'[') {
        return false;
    }
    index += 1;

    let mut depth = 1_usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut in_top_level_value = false;
    let mut count = 0_usize;
    while let Some(&byte) = bytes.get(index) {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }

        if depth == 1
            && !in_top_level_value
            && !byte.is_ascii_whitespace()
            && !matches!(byte, b',' | b']')
        {
            count = count.saturating_add(1);
            if count > maximum {
                return true;
            }
            in_top_level_value = true;
        }

        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => depth = depth.saturating_add(1),
            b'}' | b']' => {
                if depth == 1 {
                    return false;
                }
                depth -= 1;
            }
            b',' if depth == 1 => in_top_level_value = false,
            _ => {}
        }
        index += 1;
    }
    false
}

const SNAPSHOT_LIMIT_SENTINEL: &str = "registry snapshot contract reference limit exceeded";

fn snapshot_contract_refs_exceed_limit(bytes: &[u8], maximum: usize) -> bool {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let mut count = 0_usize;
    match (SnapshotCountSeed {
        count: &mut count,
        maximum,
    })
    .deserialize(&mut deserializer)
    {
        Err(error) => error.to_string().contains(SNAPSHOT_LIMIT_SENTINEL),
        Ok(()) => false,
    }
}

struct SnapshotCountSeed<'a> {
    count: &'a mut usize,
    maximum: usize,
}

impl<'de> DeserializeSeed<'de> for SnapshotCountSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(SnapshotCountVisitor {
            count: self.count,
            maximum: self.maximum,
        })
    }
}

struct SnapshotCountVisitor<'a> {
    count: &'a mut usize,
    maximum: usize,
}

impl<'de> Visitor<'de> for SnapshotCountVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a registry snapshot object")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<String>()? {
            if matches!(key.as_str(), "type_contracts" | "capability_contracts") {
                map.next_value_seed(SnapshotArrayCountSeed {
                    count: self.count,
                    maximum: self.maximum,
                })?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
}

struct SnapshotArrayCountSeed<'a> {
    count: &'a mut usize,
    maximum: usize,
}

impl<'de> DeserializeSeed<'de> for SnapshotArrayCountSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(SnapshotArrayCountVisitor {
            count: self.count,
            maximum: self.maximum,
        })
    }
}

struct SnapshotArrayCountVisitor<'a> {
    count: &'a mut usize,
    maximum: usize,
}

impl<'de> Visitor<'de> for SnapshotArrayCountVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a registry snapshot contract-reference array")
    }

    fn visit_seq<S>(self, mut sequence: S) -> Result<Self::Value, S::Error>
    where
        S: SeqAccess<'de>,
    {
        while sequence.next_element::<IgnoredAny>()?.is_some() {
            *self.count = self.count.saturating_add(1);
            if *self.count > self.maximum {
                return Err(serde::de::Error::custom(SNAPSHOT_LIMIT_SENTINEL));
            }
        }
        Ok(())
    }
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
                decode_with_record_limit::<RegistrySnapshot>(bytes, limits, kind, false, None)
                    .map(|_| ())
            }
            RecordKind::Type => {
                decode_with_record_limit::<TypeContract>(bytes, limits, kind, false, None)
                    .map(|_| ())
            }
            RecordKind::Capability => {
                decode_with_record_limit::<CapabilityContract>(bytes, limits, kind, false, None)
                    .map(|_| ())
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
                decode_with_record_limit::<CapabilityContract>(
                    template.replace("\"RAW_NUMBER\"", token).as_bytes(),
                    StrictJsonLimits::default(),
                    RecordKind::Capability,
                    false,
                    None,
                )
                .unwrap()
            };
            let left = crate::capability_contract_hash(&decode_token(authored)).unwrap();
            let right = crate::capability_contract_hash(&decode_token(rounded)).unwrap();
            assert_eq!(left, right, "{authored} -> {rounded}");
        }
    }

    #[test]
    fn record_limit_precedes_per_record_validation_and_typed_decoding() {
        let error = decode_with_record_limit::<Vec<CapabilityContract>>(
            br"[null,null]",
            StrictJsonLimits::default(),
            RecordKind::Capability,
            true,
            Some(1),
        )
        .expect_err("the raw array count must fail before its invalid records are inspected");

        assert!(
            error.message.contains("remaining configured maximum"),
            "{error}"
        );

        let oversized = format!("[{}]", vec!["null"; 4_097].join(","));
        assert!(top_level_array_exceeds_limit(oversized.as_bytes(), 4_096));
        assert!(!top_level_array_exceeds_limit(
            br#"[{"nested":[1,2,3],"text":","},null]"#,
            2
        ));
    }

    #[test]
    fn snapshot_contract_reference_limit_precedes_materialization() {
        let type_refs = vec!["null"; 2_048].join(",");
        let capability_refs = vec!["null"; 2_049].join(",");
        let oversized = format!(
            r#"{{"type_contracts":[{type_refs}],"capability_contracts":[{capability_refs}]}}"#
        );
        let error = decode_with_record_limit::<RegistrySnapshot>(
            oversized.as_bytes(),
            StrictJsonLimits::default(),
            RecordKind::Snapshot,
            false,
            Some(4_096),
        )
        .expect_err("the combined snapshot arrays must be bounded before structural decoding");
        assert!(error.message.contains("configured maximum"), "{error}");

        let escaped_key = format!(r#"{{"type\u005fcontracts":[{}]}}"#, ["null"; 2].join(","));
        assert!(snapshot_contract_refs_exceed_limit(
            escaped_key.as_bytes(),
            1
        ));
    }
}
