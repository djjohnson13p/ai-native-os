//! Bounded lexical number handling, before any binary64 conversion.
//!
//! This is not a JSON parser or arbitrary-precision arithmetic engine. The strict
//! duplicate-key parser still validates the complete document. Work is linear in
//! input bytes; exponent magnitude never controls allocation or iteration.

/// Numeric admission policy for a JSON document.
#[derive(Clone, Copy)]
pub enum NumberProfile {
    /// Canonicalize exactly nonnegative, integral, safe values; leave other tokens
    /// to the schema/closed integer decoder, which reject non-integral semantics.
    IrIntegers,
    /// Registry numbers are tolerances: finite, nonnegative binary64 values,
    /// with no nonzero-to-zero underflow. Exact signed zero is canonical zero.
    RegistryTolerance,
}

/// Prepare numeric tokens outside strings without losing exact integer meaning.
/// The caller must bound the input byte count first.
///
/// # Errors
/// Returns an error if registry numeric authoring violates the tolerance profile.
pub fn prepare_numbers(bytes: &[u8], profile: NumberProfile) -> Result<Vec<u8>, String> {
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while let Some(&byte) = bytes.get(index) {
        if in_string {
            output.push(byte);
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
        } else if byte == b'"' {
            in_string = true;
            output.push(byte);
            index += 1;
        } else if byte == b'-' || byte.is_ascii_digit() {
            let start = index;
            while bytes.get(index).is_some_and(|byte| {
                !matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | b',' | b']' | b'}')
            }) {
                index += 1;
            }
            let token = &bytes[start..index];
            // Invalid lexical forms are never repaired into valid JSON.
            let replacement = if let Some(number) = DecimalToken::parse(token) {
                match profile {
                    NumberProfile::IrIntegers => number.safe_integer(),
                    NumberProfile::RegistryTolerance => {
                        if number.is_zero() {
                            Some(0)
                        } else {
                            let value = std::str::from_utf8(token)
                                .ok()
                                .and_then(|token| token.parse::<f64>().ok());
                            if number.negative
                                || !value.is_some_and(|value| value.is_finite() && value > 0.0)
                            {
                                return Err("registry tolerance must be nonnegative and finite, without nonzero underflow".to_owned());
                            }
                            None
                        }
                    }
                }
            } else {
                None
            };
            if let Some(integer) = replacement {
                output.extend_from_slice(integer.to_string().as_bytes());
            } else {
                output.extend_from_slice(token);
            }
        } else {
            output.push(byte);
            index += 1;
        }
    }
    Ok(output)
}

struct DecimalToken {
    negative: bool,
    digits: Vec<u8>,
    fraction: i64,
    exponent: i64,
}

impl DecimalToken {
    fn parse(token: &[u8]) -> Option<Self> {
        let negative = token.first() == Some(&b'-');
        let mut index = usize::from(negative);
        let start = index;
        if token.get(index) == Some(&b'0') {
            index += 1;
        } else {
            if !token
                .get(index)
                .is_some_and(|byte| matches!(byte, b'1'..=b'9'))
            {
                return None;
            }
            while token.get(index).is_some_and(u8::is_ascii_digit) {
                index += 1;
            }
        }
        let mut digits = token[start..index].to_vec();
        let mut fraction = 0;
        if token.get(index) == Some(&b'.') {
            index += 1;
            let start = index;
            while token.get(index).is_some_and(u8::is_ascii_digit) {
                index += 1;
            }
            if start == index {
                return None;
            }
            digits.extend_from_slice(&token[start..index]);
            fraction = i64::try_from(index - start).ok()?;
        }
        let mut exponent = 0_i64;
        if token
            .get(index)
            .is_some_and(|byte| matches!(byte, b'e' | b'E'))
        {
            index += 1;
            let negative_exponent = token.get(index) == Some(&b'-');
            if token
                .get(index)
                .is_some_and(|byte| matches!(byte, b'+' | b'-'))
            {
                index += 1;
            }
            let start = index;
            while let Some(byte) = token.get(index).filter(|byte| byte.is_ascii_digit()) {
                exponent = exponent
                    .saturating_mul(10)
                    .saturating_add(i64::from(*byte - b'0'));
                index += 1;
            }
            if start == index {
                return None;
            }
            if negative_exponent {
                exponent = -exponent;
            }
        }
        (index == token.len()).then_some(Self {
            negative,
            digits,
            fraction,
            exponent,
        })
    }

    fn is_zero(&self) -> bool {
        self.digits.iter().all(|byte| *byte == b'0')
    }

    fn safe_integer(&self) -> Option<u64> {
        let Some(first) = self.digits.iter().position(|byte| *byte != b'0') else {
            return Some(0);
        };
        if self.negative {
            return None;
        }
        let scale = self.exponent.saturating_sub(self.fraction);
        let digits = &self.digits[first..];
        let length = i64::try_from(digits.len()).ok()?.saturating_add(scale);
        if !(1..=16).contains(&length) {
            return None;
        }
        let kept = if scale < 0 {
            let removed = usize::try_from(scale.checked_neg()?).ok()?;
            let kept = digits.len().checked_sub(removed)?;
            if digits[kept..].iter().any(|byte| *byte != b'0') {
                return None;
            }
            &digits[..kept]
        } else {
            digits
        };
        let mut value = 0_u64;
        for byte in kept {
            value = value
                .checked_mul(10)?
                .checked_add(u64::from(*byte - b'0'))?;
        }
        // Proven above to require at most sixteen digits, regardless of exponent spelling.
        for _ in 0..scale.max(0) {
            value = value.checked_mul(10)?;
        }
        (value <= 9_007_199_254_740_991).then_some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_integer_tokens_do_not_round() {
        for (input, expected) in [
            ("1.0", "1"),
            ("1e0", "1"),
            ("-0", "0"),
            ("-0e999999999999999999", "0"),
            ("1000e-3", "1"),
            ("9007199254740991.0", "9007199254740991"),
            ("9007199254740991.1", "9007199254740991.1"),
            ("1e-999999999999999999", "1e-999999999999999999"),
            ("01", "01"),
            ("1.", "1."),
        ] {
            assert_eq!(
                prepare_numbers(input.as_bytes(), NumberProfile::IrIntegers).unwrap(),
                expected.as_bytes()
            );
        }
        assert_eq!(
            prepare_numbers(br#"{"1.0":"-1e999", "n":1.0}"#, NumberProfile::IrIntegers).unwrap(),
            br#"{"1.0":"-1e999", "n":1}"#
        );
    }

    #[test]
    fn tolerance_tokens_validate_sign_and_underflow_before_rounding() {
        for token in ["-1e-9999", "1e-9999", "1e9999", "-0.1"] {
            assert!(prepare_numbers(token.as_bytes(), NumberProfile::RegistryTolerance).is_err());
        }
        for token in [
            "0",
            "-0",
            "0e99999999999999999999",
            "5e-324",
            "1.7976931348623157e308",
            "0.1",
        ] {
            assert!(prepare_numbers(token.as_bytes(), NumberProfile::RegistryTolerance).is_ok());
        }
    }

    #[test]
    fn long_coefficients_and_exponents_never_expand_by_exponent_magnitude() {
        let exact = format!("1{}e-16000", "0".repeat(16_000));
        assert_eq!(
            prepare_numbers(exact.as_bytes(), NumberProfile::IrIntegers).unwrap(),
            b"1"
        );
        let huge = format!("1e{}", "9".repeat(16_000));
        assert_eq!(
            prepare_numbers(huge.as_bytes(), NumberProfile::IrIntegers).unwrap(),
            huge.as_bytes()
        );
        assert!(prepare_numbers(huge.as_bytes(), NumberProfile::RegistryTolerance).is_err());
        let zero = format!("-0e-{}", "9".repeat(16_000));
        assert_eq!(
            prepare_numbers(zero.as_bytes(), NumberProfile::IrIntegers).unwrap(),
            b"0"
        );
    }
}
