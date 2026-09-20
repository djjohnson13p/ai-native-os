//! Explicit hostile-input and diagnostic limits.

use serde_json::Value;

use crate::parse::MAX_SUPPORTED_JSON_DEPTH;

pub(crate) const MAX_OUTPUT_DIAGNOSTICS: usize = 256;

/// Validator resource ceilings. All ceilings are deterministic and inclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationLimits {
    /// Maximum encoded document size.
    pub max_document_bytes: usize,
    /// Requested maximum JSON object/array nesting depth. Validator construction
    /// clamps this to the implementation-supported inclusive maximum of 127.
    pub max_depth: usize,
    /// Maximum number of program nodes.
    pub max_nodes: usize,
    /// Maximum ports in any one input/output interface.
    pub max_ports_per_interface: usize,
    /// Maximum authority requests on one node.
    pub max_authority_requests_per_node: usize,
    /// Maximum ordered fallback capabilities on one node.
    pub max_fallbacks_per_node: usize,
    /// Maximum UTF-8 scalar count in any JSON member name or string value.
    pub max_string_chars: usize,
    /// Requested maximum emitted diagnostics; validator construction clamps it
    /// to `1..=256`, the normative output-schema range.
    pub max_diagnostics: usize,
}

impl Default for ValidationLimits {
    fn default() -> Self {
        Self {
            max_document_bytes: 1_048_576,
            max_depth: 64,
            max_nodes: 512,
            max_ports_per_interface: 128,
            max_authority_requests_per_node: 32,
            max_fallbacks_per_node: 3,
            max_string_chars: 16_384,
            max_diagnostics: 256,
        }
    }
}

impl ValidationLimits {
    pub(crate) fn bounded_for_output(mut self) -> Self {
        self.max_depth = self.max_depth.min(MAX_SUPPORTED_JSON_DEPTH);
        self.max_diagnostics = self.max_diagnostics.clamp(1, MAX_OUTPUT_DIAGNOSTICS);
        self
    }
}

/// A limit violation found after strict parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LimitViolation {
    /// Too many program nodes.
    NodeCount,
    /// Too many ports in a declared interface.
    PortCount,
    /// Too many authority requests on a node.
    AuthorityRequestCount,
    /// Too many fallback capabilities on a node.
    FallbackCount,
    /// A member name or string value was too long.
    StringLength,
}

/// Finds all post-parse resource violations in deterministic code order.
pub fn inspect_value_limits(value: &Value, limits: ValidationLimits) -> Vec<LimitViolation> {
    let mut violations = Vec::new();

    if value
        .get("nodes")
        .and_then(Value::as_array)
        .is_some_and(|nodes| nodes.len() > limits.max_nodes)
    {
        violations.push(LimitViolation::NodeCount);
    }

    if interfaces(value).any(|count| count > limits.max_ports_per_interface) {
        violations.push(LimitViolation::PortCount);
    }

    if value
        .get("nodes")
        .and_then(Value::as_array)
        .is_some_and(|nodes| {
            nodes.iter().any(|node| {
                node.get("authority_requests")
                    .and_then(Value::as_array)
                    .is_some_and(|requests| requests.len() > limits.max_authority_requests_per_node)
            })
        })
    {
        violations.push(LimitViolation::AuthorityRequestCount);
    }

    if value
        .get("nodes")
        .and_then(Value::as_array)
        .is_some_and(|nodes| {
            nodes.iter().any(|node| {
                node.pointer("/failure/fallback_capabilities")
                    .and_then(Value::as_array)
                    .is_some_and(|fallbacks| fallbacks.len() > limits.max_fallbacks_per_node)
            })
        })
    {
        violations.push(LimitViolation::FallbackCount);
    }

    if contains_long_string(value, limits.max_string_chars) {
        violations.push(LimitViolation::StringLength);
    }

    violations
}

fn interfaces(value: &Value) -> impl Iterator<Item = usize> + '_ {
    let program = ["inputs", "outputs"].into_iter().filter_map(|name| {
        value
            .get(name)
            .and_then(Value::as_object)
            .map(serde_json::Map::len)
    });
    let nodes = value
        .get("nodes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|node| {
            ["inputs", "outputs"].into_iter().filter_map(|name| {
                node.get(name)
                    .and_then(Value::as_object)
                    .map(serde_json::Map::len)
            })
        });
    program.chain(nodes)
}

fn contains_long_string(value: &Value, max_chars: usize) -> bool {
    match value {
        Value::String(string) => string.chars().count() > max_chars,
        Value::Array(values) => values
            .iter()
            .any(|value| contains_long_string(value, max_chars)),
        Value::Object(values) => values.iter().any(|(key, value)| {
            key.chars().count() > max_chars || contains_long_string(value, max_chars)
        }),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        LimitViolation, MAX_OUTPUT_DIAGNOSTICS, MAX_SUPPORTED_JSON_DEPTH, ValidationLimits,
        inspect_value_limits,
    };

    #[test]
    fn diagnostic_limit_stays_inside_normative_output_schema() {
        let zero = ValidationLimits {
            max_diagnostics: 0,
            ..ValidationLimits::default()
        };
        assert_eq!(zero.bounded_for_output().max_diagnostics, 1);

        let excessive = ValidationLimits {
            max_diagnostics: usize::MAX,
            ..ValidationLimits::default()
        };
        assert_eq!(
            excessive.bounded_for_output().max_diagnostics,
            MAX_OUTPUT_DIAGNOSTICS
        );
    }

    #[test]
    fn json_depth_limit_stays_inside_the_supported_parser_ceiling() {
        let excessive = ValidationLimits {
            max_depth: usize::MAX,
            ..ValidationLimits::default()
        };
        assert_eq!(
            excessive.bounded_for_output().max_depth,
            MAX_SUPPORTED_JSON_DEPTH
        );
    }

    #[test]
    fn node_limit_is_inclusive() {
        let limits = ValidationLimits {
            max_nodes: 2,
            ..ValidationLimits::default()
        };
        assert!(
            !inspect_value_limits(&json!({"nodes": [{}, {}]}), limits)
                .contains(&LimitViolation::NodeCount)
        );
        assert!(
            inspect_value_limits(&json!({"nodes": [{}, {}, {}]}), limits)
                .contains(&LimitViolation::NodeCount)
        );
    }

    #[test]
    fn string_limit_checks_member_names_and_values() {
        let limits = ValidationLimits {
            max_string_chars: 3,
            ..ValidationLimits::default()
        };
        assert!(
            inspect_value_limits(&json!({"long": "ok"}), limits)
                .contains(&LimitViolation::StringLength)
        );
        assert!(
            inspect_value_limits(&json!({"key": "long"}), limits)
                .contains(&LimitViolation::StringLength)
        );
    }
}
