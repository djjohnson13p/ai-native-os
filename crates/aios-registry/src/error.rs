use crate::strict_json::{StrictJsonError, StrictJsonErrorKind};
use aios_contracts::ValidatorReasonCode;
use std::fmt;
use std::path::PathBuf;

/// Registry validation failures carry a catalog code. Local I/O/path failures
/// are operational and deliberately carry no `REGISTRY_*` semantic code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryError {
    pub code: Option<ValidatorReasonCode>,
    pub message: String,
    pub path: Option<PathBuf>,
}

impl RegistryError {
    pub fn validation(code: ValidatorReasonCode, message: impl Into<String>) -> Self {
        debug_assert!(code.as_str().starts_with("REGISTRY_"));
        Self {
            code: Some(code),
            message: message.into(),
            path: None,
        }
    }

    pub fn operational(message: impl Into<String>) -> Self {
        Self {
            code: None,
            message: message.into(),
            path: None,
        }
    }

    #[must_use]
    pub fn at_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn is_operational(&self) -> bool {
        self.code.is_none()
    }

    pub fn reason_code(&self) -> Option<ValidatorReasonCode> {
        self.code
    }

    pub(crate) fn schema(message: impl Into<String>) -> Self {
        Self::validation(ValidatorReasonCode::RegistrySchemaInvalid, message)
    }
}

impl fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(code) = self.code {
            write!(formatter, "{code}: ")?;
        }
        formatter.write_str(&self.message)?;
        if let Some(path) = &self.path {
            write!(formatter, " ({})", path.display())?;
        }
        Ok(())
    }
}

impl std::error::Error for RegistryError {}

impl From<StrictJsonError> for RegistryError {
    fn from(error: StrictJsonError) -> Self {
        let detail = match error.kind {
            StrictJsonErrorKind::DuplicateKey => "duplicate JSON key",
            StrictJsonErrorKind::DocumentTooLarge => "document size limit exceeded",
            StrictJsonErrorKind::DepthExceeded => "JSON depth limit exceeded",
            StrictJsonErrorKind::InvalidJson => "invalid JSON",
            StrictJsonErrorKind::TypedDecode => "typed contract mismatch",
        };
        RegistryError::schema(format!("{detail}: {}", error.message))
    }
}

pub type RegistryResult<T> = Result<T, RegistryError>;
