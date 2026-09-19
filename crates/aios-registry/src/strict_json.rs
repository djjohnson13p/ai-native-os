//! Strict, bounded JSON parsing shared by registry ingestion and validator callers.
//!
//! `serde_json::Value` normally keeps the final value for a duplicate object key.
//! That is not acceptable at the semantic trust boundary, so this module builds a
//! value with a custom visitor that rejects a repeated key before typed decoding.

use serde::Deserialize;
use serde::de::{DeserializeOwned, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::fmt;

const DUPLICATE_MARKER: &str = "AIOS_DUPLICATE_JSON_KEY:";

/// Parser limits applied before a value reaches typed contract decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StrictJsonLimits {
    pub max_bytes: usize,
    pub max_depth: usize,
}

impl Default for StrictJsonLimits {
    fn default() -> Self {
        Self {
            max_bytes: 8 * 1024 * 1024,
            max_depth: 64,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrictJsonErrorKind {
    DocumentTooLarge,
    DepthExceeded,
    DuplicateKey,
    InvalidJson,
    TypedDecode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrictJsonError {
    pub kind: StrictJsonErrorKind,
    pub message: String,
}

impl fmt::Display for StrictJsonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for StrictJsonError {}

/// Parse hostile JSON into a value without silently accepting duplicate keys.
///
/// # Errors
///
/// Returns a classified parse error when a configured limit is exceeded, a
/// duplicate key is encountered, or the bytes are not one complete JSON value.
pub fn parse_strict_value(
    bytes: &[u8],
    limits: StrictJsonLimits,
) -> Result<Value, StrictJsonError> {
    if bytes.len() > limits.max_bytes {
        return Err(StrictJsonError {
            kind: StrictJsonErrorKind::DocumentTooLarge,
            message: format!(
                "JSON document is {} bytes; configured maximum is {} bytes",
                bytes.len(),
                limits.max_bytes
            ),
        });
    }

    if limits.max_depth == 0 {
        return Err(StrictJsonError {
            kind: StrictJsonErrorKind::DepthExceeded,
            message: "configured JSON depth limit is zero".to_owned(),
        });
    }

    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let strict = StrictValue::deserialize(&mut deserializer)
        .map_err(|error| classify_parse_error(&error))?;
    deserializer
        .end()
        .map_err(|error| classify_parse_error(&error))?;
    let value = strict.0;

    let depth = json_depth(&value);
    if depth > limits.max_depth {
        return Err(StrictJsonError {
            kind: StrictJsonErrorKind::DepthExceeded,
            message: format!(
                "JSON nesting depth is {depth}; configured maximum is {}",
                limits.max_depth
            ),
        });
    }

    Ok(value)
}

/// Strictly parse first, then decode into a closed typed representation.
///
/// # Errors
///
/// Returns a strict parse error or a typed-decode error when the JSON value is
/// incompatible with `T`.
pub fn parse_strict_json<T: DeserializeOwned>(
    bytes: &[u8],
    limits: StrictJsonLimits,
) -> Result<T, StrictJsonError> {
    let value = parse_strict_value(bytes, limits)?;
    serde_json::from_value(value).map_err(|error| StrictJsonError {
        kind: StrictJsonErrorKind::TypedDecode,
        message: format!("JSON does not satisfy the typed contract: {error}"),
    })
}

fn classify_parse_error(error: &serde_json::Error) -> StrictJsonError {
    let message = error.to_string();
    let kind = if message.contains(DUPLICATE_MARKER) {
        StrictJsonErrorKind::DuplicateKey
    } else {
        StrictJsonErrorKind::InvalidJson
    };
    StrictJsonError { kind, message }
}

fn json_depth(value: &Value) -> usize {
    let mut maximum = 0usize;
    let mut pending = vec![(value, 1usize)];
    while let Some((current, depth)) = pending.pop() {
        maximum = maximum.max(depth);
        match current {
            Value::Array(values) => {
                pending.extend(values.iter().map(|value| (value, depth + 1)));
            }
            Value::Object(values) => {
                pending.extend(values.values().map(|value| (value, depth + 1)));
            }
            _ => {}
        }
    }
    maximum
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(StrictValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        StrictValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            values.push(value.0);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(A::Error::custom(format!("{DUPLICATE_MARKER}{key}")));
            }
            let value = object.next_value::<StrictValue>()?;
            values.insert(key, value.0);
        }
        Ok(StrictValue(Value::Object(values)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Closed {
        value: u64,
    }

    #[test]
    fn rejects_duplicate_keys_at_any_depth() {
        let error = parse_strict_value(
            br#"{"outer":{"capability":"a","capability":"b"}}"#,
            StrictJsonLimits::default(),
        )
        .expect_err("duplicate key must fail");
        assert_eq!(error.kind, StrictJsonErrorKind::DuplicateKey);
    }

    #[test]
    fn rejects_trailing_json() {
        let error = parse_strict_value(b"{} {}", StrictJsonLimits::default())
            .expect_err("trailing JSON must fail");
        assert_eq!(error.kind, StrictJsonErrorKind::InvalidJson);
    }

    #[test]
    fn enforces_byte_and_depth_limits() {
        let byte_error = parse_strict_value(
            br#"{"value":1}"#,
            StrictJsonLimits {
                max_bytes: 2,
                max_depth: 8,
            },
        )
        .expect_err("oversize input must fail");
        assert_eq!(byte_error.kind, StrictJsonErrorKind::DocumentTooLarge);

        let depth_error = parse_strict_value(
            br#"{"a":{"b":1}}"#,
            StrictJsonLimits {
                max_bytes: 1024,
                max_depth: 2,
            },
        )
        .expect_err("deep input must fail");
        assert_eq!(depth_error.kind, StrictJsonErrorKind::DepthExceeded);
    }

    #[test]
    fn typed_decode_preserves_closed_contracts() {
        let value: Closed = parse_strict_json(br#"{"value":3}"#, StrictJsonLimits::default())
            .expect("closed value");
        assert_eq!(value, Closed { value: 3 });

        let error: StrictJsonError = parse_strict_json::<Closed>(
            br#"{"value":3,"extra":true}"#,
            StrictJsonLimits::default(),
        )
        .expect_err("unknown field must fail");
        assert_eq!(error.kind, StrictJsonErrorKind::TypedDecode);
    }
}
