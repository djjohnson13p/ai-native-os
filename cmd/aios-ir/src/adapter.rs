use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use aios_ir::{ValidationLimits, ValidationReport, Validator, rejected_registry_report};
use aios_registry::{RegistryLoadOptions, SemanticRegistry};
use serde_json::Value;

/// The only boundary between command-line concerns and trusted IR semantics.
pub(crate) struct LibraryAdapter;

impl LibraryAdapter {
    /// Loads the explicitly named immutable registry and validates a bounded program.
    pub(crate) fn validate_path(
        program_path: &Path,
        registry_path: &Path,
    ) -> Result<ValidationReport, AdapterError> {
        let limits = ValidationLimits::default();
        let program = read_bounded(program_path, limits.max_document_bytes)?;
        let registry =
            match SemanticRegistry::load_bundle(registry_path, RegistryLoadOptions::default()) {
                Ok(registry) => registry,
                Err(error) if error.is_operational() => {
                    return Err(AdapterError::operational(
                        "CLI_REGISTRY_LOAD_FAILED",
                        "could not load the explicitly supplied registry",
                    ));
                }
                Err(error) => {
                    let Some(reason_code) = error.reason_code() else {
                        return Err(AdapterError::operational(
                            "CLI_LIBRARY_CONTRACT_VIOLATION",
                            "the registry reported a non-operational error without a reason code",
                        ));
                    };
                    return Ok(rejected_registry_report(reason_code, error.message));
                }
            };
        let validator = Validator::new(registry, limits);

        Ok(validator.validate_bytes(&program))
    }

    /// Returns the library-owned explanation for a stable reason code.
    pub(crate) fn explain_reason(reason_code: &str) -> Result<Value, AdapterError> {
        let explanation = aios_ir::explain_reason(reason_code).ok_or_else(|| {
            AdapterError::operational(
                "CLI_REASON_CODE_UNKNOWN",
                format!("unknown validator reason code: {reason_code}"),
            )
        })?;

        serde_json::to_value(explanation).map_err(|error| {
            AdapterError::operational(
                "CLI_OUTPUT_SERIALIZATION_FAILED",
                format!("could not serialize the reason-code explanation: {error}"),
            )
        })
    }
}

/// An operational CLI failure, distinct from a semantic validation rejection.
#[derive(Debug)]
pub(crate) struct AdapterError {
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

impl AdapterError {
    pub(crate) fn operational(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

fn read_bounded(path: &Path, max_document_bytes: usize) -> Result<Vec<u8>, AdapterError> {
    let file = File::open(path).map_err(|error| program_read_error(&error, "open"))?;

    // One byte beyond the configured maximum is enough for the trusted library to
    // return IR_LIMIT_DOCUMENT_SIZE, without allocating based on hostile file size.
    let read_limit = u64::try_from(max_document_bytes)
        .unwrap_or(u64::MAX - 1)
        .saturating_add(1);
    let initial_capacity = max_document_bytes.saturating_add(1).min(64 * 1024);
    let mut bytes = Vec::with_capacity(initial_capacity);
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|error| program_read_error(&error, "read"))?;

    Ok(bytes)
}

fn program_read_error(error: &io::Error, operation: &str) -> AdapterError {
    AdapterError::operational(
        "CLI_PROGRAM_READ_FAILED",
        format!("could not {operation} the explicitly supplied program: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use super::read_bounded;
    use std::fs;

    #[test]
    fn bounded_reader_keeps_only_one_byte_past_limit() {
        let directory = std::env::temp_dir();
        let path = directory.join(format!("aios-ir-cli-bounded-read-{}", std::process::id()));
        fs::write(&path, b"0123456789").expect("write temporary input");

        let result = read_bounded(&path, 4).expect("read temporary input");
        let _ = fs::remove_file(path);

        assert_eq!(result, b"01234");
    }
}
