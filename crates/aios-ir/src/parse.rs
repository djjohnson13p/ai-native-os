//! Resource-bounded, duplicate-key rejecting JSON parsing.

use std::fmt;

use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};

const DUPLICATE_MARKER: &str = "AIOS_DUPLICATE_KEY:";

/// Failure returned by the strict JSON reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StrictJsonError {
    /// The document exceeded the configured structural depth.
    DepthLimit,
    /// An object contained the same member name more than once.
    DuplicateKey(String),
    /// The bytes were not one complete JSON value.
    Invalid(String),
}

/// Parses one JSON value while rejecting duplicate object keys.
pub fn parse_strict_json(bytes: &[u8], max_depth: usize) -> Result<Value, StrictJsonError> {
    if exceeds_depth(bytes, max_depth) {
        return Err(StrictJsonError::DepthLimit);
    }

    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value =
        StrictValue::deserialize(&mut deserializer).map_err(|error| classify_error(&error))?;
    deserializer.end().map_err(|error| classify_error(&error))?;
    Ok(value.0)
}

fn classify_error(error: &serde_json::Error) -> StrictJsonError {
    let message = error.to_string();
    if let Some(start) = message.find(DUPLICATE_MARKER) {
        let key = &message[start + DUPLICATE_MARKER.len()..];
        let key = key.split(" at line ").next().unwrap_or(key);
        return StrictJsonError::DuplicateKey(key.chars().take(256).collect());
    }
    StrictJsonError::Invalid(message)
}

fn exceeds_depth(bytes: &[u8], max_depth: usize) -> bool {
    let mut depth = 0_usize;
    let mut in_string = false;
    let mut escaped = false;

    for byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            }
            continue;
        }

        match *byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth = depth.saturating_add(1);
                if depth > max_depth {
                    return true;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
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
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(StrictValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_string(value.to_owned())
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

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(512));
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
                return Err(serde::de::Error::custom(format_args!(
                    "{DUPLICATE_MARKER}{key}"
                )));
            }
            let value = object.next_value::<StrictValue>()?;
            values.insert(key, value.0);
        }
        Ok(StrictValue(Value::Object(values)))
    }
}

#[cfg(test)]
mod tests {
    use super::{StrictJsonError, parse_strict_json};

    #[test]
    fn rejects_duplicate_keys() {
        let result = parse_strict_json(br#"{"a": 1, "a": 2}"#, 8);
        assert_eq!(result, Err(StrictJsonError::DuplicateKey("a".to_owned())));
    }

    #[test]
    fn depth_scanner_ignores_brackets_inside_strings() {
        let result = parse_strict_json(br#"{"a":"[[[[", "b":[1]}"#, 2);
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_depth_at_boundary_plus_one() {
        assert!(parse_strict_json(br"[0]", 2).is_ok());
        assert!(parse_strict_json(br"[[0]]", 2).is_ok());
        assert_eq!(
            parse_strict_json(br"[[[0]]]", 2),
            Err(StrictJsonError::DepthLimit)
        );
    }
}
