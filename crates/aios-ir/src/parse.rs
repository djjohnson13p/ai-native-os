//! Resource-bounded, duplicate-key rejecting JSON parsing.

use std::fmt;

use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};

const DUPLICATE_MARKER: &str = "AIOS_DUPLICATE_KEY:";
pub(crate) const MAX_SUPPORTED_JSON_DEPTH: usize = 127;

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
    let max_depth = max_depth.min(MAX_SUPPORTED_JSON_DEPTH);
    if exceeds_depth(bytes, max_depth) {
        return Err(StrictJsonError::DepthLimit);
    }

    let sanitized = sanitize_out_of_range_metadata_numbers(bytes);
    let prepared = aios_registry::numbers::prepare_numbers(
        &sanitized,
        aios_registry::numbers::NumberProfile::IrIntegers,
    )
    .map_err(StrictJsonError::Invalid)?;
    let mut deserializer = serde_json::Deserializer::from_slice(&prepared);
    let value =
        StrictValue::deserialize(&mut deserializer).map_err(|error| classify_error(&error))?;
    deserializer.end().map_err(|error| classify_error(&error))?;
    Ok(value.0)
}

fn sanitize_out_of_range_metadata_numbers(bytes: &[u8]) -> Vec<u8> {
    let mut scanner = MetadataScanner {
        bytes,
        index: 0,
        replacements: Vec::new(),
    };
    if scanner.scan_value(false, 0).is_err() {
        return bytes.to_vec();
    }
    scanner.skip_whitespace();
    if scanner.index != bytes.len() || scanner.replacements.is_empty() {
        return bytes.to_vec();
    }

    let mut sanitized = Vec::with_capacity(bytes.len());
    let mut copied = 0;
    for (start, end) in scanner.replacements {
        sanitized.extend_from_slice(&bytes[copied..start]);
        sanitized.push(b'0');
        copied = end;
    }
    sanitized.extend_from_slice(&bytes[copied..]);
    sanitized
}

struct MetadataScanner<'a> {
    bytes: &'a [u8],
    index: usize,
    replacements: Vec<(usize, usize)>,
}

impl MetadataScanner<'_> {
    fn scan_value(&mut self, inside_metadata: bool, depth: usize) -> Result<(), ()> {
        if depth > MAX_SUPPORTED_JSON_DEPTH {
            return Err(());
        }
        self.skip_whitespace();
        match self.bytes.get(self.index) {
            Some(b'{') => self.scan_object(inside_metadata, depth),
            Some(b'[') => self.scan_array(inside_metadata, depth),
            Some(b'"') => self.scan_string().map(|_| ()),
            Some(b't') => self.scan_literal(b"true"),
            Some(b'f') => self.scan_literal(b"false"),
            Some(b'n') => self.scan_literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.scan_number(inside_metadata),
            Some(_) | None => Err(()),
        }
    }

    fn scan_object(&mut self, inside_metadata: bool, depth: usize) -> Result<(), ()> {
        self.index += 1;
        self.skip_whitespace();
        if self.consume(b'}') {
            return Ok(());
        }
        loop {
            let key = self.scan_string()?;
            self.skip_whitespace();
            if !self.consume(b':') {
                return Err(());
            }
            self.scan_value(inside_metadata || key == "metadata", depth + 1)?;
            self.skip_whitespace();
            if self.consume(b'}') {
                return Ok(());
            }
            if !self.consume(b',') {
                return Err(());
            }
            self.skip_whitespace();
        }
    }

    fn scan_array(&mut self, inside_metadata: bool, depth: usize) -> Result<(), ()> {
        self.index += 1;
        self.skip_whitespace();
        if self.consume(b']') {
            return Ok(());
        }
        loop {
            self.scan_value(inside_metadata, depth + 1)?;
            self.skip_whitespace();
            if self.consume(b']') {
                return Ok(());
            }
            if !self.consume(b',') {
                return Err(());
            }
        }
    }

    fn scan_string(&mut self) -> Result<String, ()> {
        let start = self.index;
        if !self.consume(b'"') {
            return Err(());
        }
        let mut escaped = false;
        while let Some(byte) = self.bytes.get(self.index).copied() {
            self.index += 1;
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                return serde_json::from_slice(&self.bytes[start..self.index]).map_err(|_| ());
            }
        }
        Err(())
    }

    fn scan_literal(&mut self, literal: &[u8]) -> Result<(), ()> {
        if self.bytes.get(self.index..self.index + literal.len()) == Some(literal) {
            self.index += literal.len();
            Ok(())
        } else {
            Err(())
        }
    }

    fn scan_number(&mut self, inside_metadata: bool) -> Result<(), ()> {
        let start = self.index;
        self.consume(b'-');
        match self.bytes.get(self.index) {
            Some(b'0') => self.index += 1,
            Some(b'1'..=b'9') => {
                self.index += 1;
                while self.bytes.get(self.index).is_some_and(u8::is_ascii_digit) {
                    self.index += 1;
                }
            }
            Some(_) | None => return Err(()),
        }
        if self.consume(b'.') {
            let fraction_start = self.index;
            while self.bytes.get(self.index).is_some_and(u8::is_ascii_digit) {
                self.index += 1;
            }
            if self.index == fraction_start {
                return Err(());
            }
        }
        if self
            .bytes
            .get(self.index)
            .is_some_and(|byte| matches!(byte, b'e' | b'E'))
        {
            self.index += 1;
            if self
                .bytes
                .get(self.index)
                .is_some_and(|byte| matches!(byte, b'+' | b'-'))
            {
                self.index += 1;
            }
            let exponent_start = self.index;
            while self.bytes.get(self.index).is_some_and(u8::is_ascii_digit) {
                self.index += 1;
            }
            if self.index == exponent_start {
                return Err(());
            }
        }

        if inside_metadata
            && serde_json::from_slice::<Number>(&self.bytes[start..self.index]).is_err()
        {
            self.replacements.push((start, self.index));
        }
        Ok(())
    }

    fn skip_whitespace(&mut self) {
        while self
            .bytes
            .get(self.index)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.index += 1;
        }
    }

    fn consume(&mut self, expected: u8) -> bool {
        if self.bytes.get(self.index) == Some(&expected) {
            self.index += 1;
            true
        } else {
            false
        }
    }
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
    use super::{MAX_SUPPORTED_JSON_DEPTH, StrictJsonError, parse_strict_json};

    fn nested_metadata_number(depth: usize) -> Vec<u8> {
        assert!(depth >= 1);
        format!(
            "{{\"metadata\":{}1e9999{}}}",
            "[".repeat(depth - 1),
            "]".repeat(depth - 1)
        )
        .into_bytes()
    }

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

    #[test]
    fn accepts_out_of_range_numbers_only_inside_metadata() {
        assert!(parse_strict_json(br#"{"metadata":{"score":1e9999}}"#, 8).is_ok());
        assert!(parse_strict_json(br#"{"score":1e9999}"#, 8).is_err());
    }

    #[test]
    fn metadata_sanitization_preserves_ordinary_private_marker_objects() {
        let value = parse_strict_json(
            br#"{"metadata":{"nested":{"$serde_json::private::Number":"not a number"}}}"#,
            8,
        )
        .unwrap();
        assert_eq!(
            value.pointer("/metadata/nested").unwrap(),
            &serde_json::json!({"$serde_json::private::Number":"not a number"})
        );
    }

    #[test]
    fn configured_depth_is_inclusive_below_the_supported_ceiling() {
        let configured = 96;
        assert!(parse_strict_json(&nested_metadata_number(configured), configured).is_ok());
        assert_eq!(
            parse_strict_json(&nested_metadata_number(configured + 1), configured),
            Err(StrictJsonError::DepthLimit)
        );
    }

    #[test]
    fn configured_depth_above_the_supported_ceiling_is_deterministically_clamped() {
        assert!(
            parse_strict_json(
                &nested_metadata_number(MAX_SUPPORTED_JSON_DEPTH),
                usize::MAX
            )
            .is_ok()
        );
        assert_eq!(
            parse_strict_json(
                &nested_metadata_number(MAX_SUPPORTED_JSON_DEPTH + 1),
                usize::MAX
            ),
            Err(StrictJsonError::DepthLimit)
        );
    }
}
