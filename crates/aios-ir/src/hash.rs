//! RFC 8785 serialization and domain-separated semantic hashing.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// AIOS IR v0.1 semantic hash domain.
pub const SEMANTIC_HASH_DOMAIN: &[u8] = b"AIOS-IR-SEMANTIC\0v0.1\0";
const JCS_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const JCS_MIN_SAFE_INTEGER: i64 = -9_007_199_254_740_991;

/// Canonicalizes a semantic JSON value using RFC 8785/JCS.
pub fn canonicalize(value: &Value) -> Result<Vec<u8>, String> {
    ensure_jcs_safe_numbers(value)?;
    serde_json_canonicalizer::to_vec(value).map_err(|error| error.to_string())
}

fn ensure_jcs_safe_numbers(value: &Value) -> Result<(), String> {
    match value {
        Value::Number(number) => {
            if number
                .as_u64()
                .is_some_and(|integer| integer > JCS_MAX_SAFE_INTEGER)
                || number
                    .as_i64()
                    .is_some_and(|integer| integer < JCS_MIN_SAFE_INTEGER)
            {
                return Err(format!(
                    "integer {number} exceeds the RFC 8785/I-JSON exact range"
                ));
            }
        }
        Value::Array(values) => {
            for value in values {
                ensure_jcs_safe_numbers(value)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                ensure_jcs_safe_numbers(value)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::String(_) => {}
    }
    Ok(())
}

/// Computes a lowercase tagged SHA-256 over the AIOS IR semantic domain and JCS bytes.
pub fn semantic_hash(value: &Value) -> Result<String, String> {
    let canonical = canonicalize(value)?;
    let mut digest = Sha256::new();
    digest.update(SEMANTIC_HASH_DOMAIN);
    digest.update(canonical);
    let bytes = digest.finalize();
    let mut tagged = String::with_capacity(7 + bytes.len() * 2);
    tagged.push_str("sha256:");
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut tagged, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(tagged)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{canonicalize, semantic_hash};

    #[test]
    fn canonicalization_orders_object_members() {
        assert_eq!(
            canonicalize(&json!({"z": 1, "a": 2})).unwrap(),
            br#"{"a":2,"z":1}"#
        );
    }

    #[test]
    fn canonicalization_matches_rfc_8785_section_3_vector() {
        // RFC 8785 sections 3.2.2-3.2.3 publish this input/output pair.
        let input: serde_json::Value = serde_json::from_str(
            r#"{
                "numbers": [333333333.33333329, 1E30, 4.50,
                            2e-3, 0.000000000000000000000000001],
                "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
                "literals": [null, true, false]
            }"#,
        )
        .unwrap();

        assert_eq!(
            canonicalize(&input).unwrap(),
            r#"{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}"#
                .as_bytes()
        );
    }

    #[test]
    fn canonicalization_matches_rfc_8785_utf16_sort_vector() {
        // RFC 8785 section 3.2.3 fixes this property order, including the
        // UTF-16-vs-UTF-8-sensitive emoji/Hebrew ordering boundary.
        let input = json!({
            "\u{20ac}": "Euro Sign",
            "\r": "Carriage Return",
            "\u{fb33}": "Hebrew Letter Dalet With Dagesh",
            "1": "One",
            "\u{1f600}": "Emoji: Grinning Face",
            "\u{80}": "Control",
            "\u{f6}": "Latin Small Letter O With Diaeresis"
        });

        assert_eq!(
            canonicalize(&input).unwrap(),
            "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\",\"😀\":\"Emoji: Grinning Face\",\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}"
                .as_bytes()
        );
    }

    #[test]
    fn canonical_bytes_are_stable_after_json_round_trip() {
        let value = json!({"z": [3, {"\u{1f600}": "preserved"}], "a": 2});
        let first = canonicalize(&value).unwrap();
        let reparsed: serde_json::Value = serde_json::from_slice(&first).unwrap();
        let second = canonicalize(&reparsed).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn tagged_hash_is_lowercase_sha256() {
        let hash = semantic_hash(&json!({"a": 1})).unwrap();
        assert_eq!(hash.len(), 71);
        assert!(hash.starts_with("sha256:"));
        assert_eq!(hash, hash.to_ascii_lowercase());
    }

    #[test]
    fn verification_kind_is_inside_semantic_identity() {
        let invoke = json!({"operation":{"kind":"invoke","capability":"same@1"}});
        let verify = json!({"operation":{"kind":"verify","capability":"same@1"}});
        assert_ne!(
            semantic_hash(&invoke).unwrap(),
            semantic_hash(&verify).unwrap()
        );
    }

    #[test]
    fn version_output_type_and_fallback_order_are_inside_semantic_identity() {
        let base = json!({
            "ir_version":"0.1",
            "nodes":[{
                "id":"node",
                "operation":{"kind":"invoke","capability":"example.operation@1"},
                "outputs":{"result":"example.type@1"},
                "failure":{"on_error":"fallback","fallback_capabilities":["fallback.a@1","fallback.b@1"]}
            }],
            "outputs":{"result":{"source":"node","node":"node","port":"result"}}
        });

        let mut version = base.clone();
        version["ir_version"] = json!("0.2");
        assert_ne!(
            semantic_hash(&base).unwrap(),
            semantic_hash(&version).unwrap()
        );

        let mut output_type = base.clone();
        output_type["nodes"][0]["outputs"]["result"] = json!("example.other@1");
        assert_ne!(
            semantic_hash(&base).unwrap(),
            semantic_hash(&output_type).unwrap()
        );

        let mut fallback_order = base.clone();
        fallback_order["nodes"][0]["failure"]["fallback_capabilities"] =
            json!(["fallback.b@1", "fallback.a@1"]);
        assert_ne!(
            semantic_hash(&base).unwrap(),
            semantic_hash(&fallback_order).unwrap()
        );
    }

    #[test]
    fn rejects_integers_that_jcs_would_round_to_one_value() {
        assert!(canonicalize(&json!(9_007_199_254_740_991_u64)).is_ok());
        assert!(canonicalize(&json!(9_007_199_254_740_992_u64)).is_err());
        assert!(canonicalize(&json!(9_007_199_254_740_993_u64)).is_err());
    }
}
