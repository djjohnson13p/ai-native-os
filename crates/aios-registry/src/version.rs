use crate::{RegistryError, RegistryResult};
use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FullVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: Option<u64>,
    source: String,
}

impl FullVersion {
    /// Parse a canonical `MAJOR.MINOR` or `MAJOR.MINOR.PATCH` version.
    ///
    /// # Errors
    ///
    /// Returns a registry schema error when syntax is non-canonical or a
    /// component exceeds the `u64` range.
    pub fn parse(source: &str) -> RegistryResult<Self> {
        let components: Vec<&str> = source.split('.').collect();
        if !(components.len() == 2 || components.len() == 3) {
            return Err(RegistryError::schema(format!(
                "contract version {source:?} must be MAJOR.MINOR or MAJOR.MINOR.PATCH"
            )));
        }
        let major = parse_component(source, components[0])?;
        let minor = parse_component(source, components[1])?;
        let patch = components
            .get(2)
            .map(|value| parse_component(source, value))
            .transpose()?;
        Ok(Self {
            major,
            minor,
            patch,
            source: source.to_owned(),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.source
    }
}

fn parse_component(version: &str, component: &str) -> RegistryResult<u64> {
    if component.is_empty()
        || !component.bytes().all(|byte| byte.is_ascii_digit())
        || (component.len() > 1 && component.starts_with('0'))
    {
        return Err(RegistryError::schema(format!(
            "contract version {version:?} has a non-canonical component"
        )));
    }
    component.parse::<u64>().map_err(|_| {
        RegistryError::schema(format!("contract version {version:?} exceeds u64 range"))
    })
}

impl PartialOrd for FullVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FullVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        (
            self.major,
            self.minor,
            self.patch.unwrap_or(0),
            &self.source,
        )
            .cmp(&(
                other.major,
                other.minor,
                other.patch.unwrap_or(0),
                &other.source,
            ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SemanticRef {
    pub id: String,
    pub major: u64,
}

impl SemanticRef {
    /// Parse a canonical `<semantic-id>@<major>` reference.
    ///
    /// # Errors
    ///
    /// Returns a registry schema error when the identifier or major selector
    /// violates the closed v0.1 grammar.
    pub fn parse(source: &str) -> RegistryResult<Self> {
        let (id, major) = source.rsplit_once('@').ok_or_else(|| {
            RegistryError::schema(format!(
                "semantic reference {source:?} must use <semantic-id>@<major>"
            ))
        })?;
        validate_semantic_id(id)?;
        if major.is_empty()
            || !major.bytes().all(|byte| byte.is_ascii_digit())
            || (major.len() > 1 && major.starts_with('0'))
        {
            return Err(RegistryError::schema(format!(
                "semantic reference {source:?} has an invalid major selector"
            )));
        }
        let major = major.parse::<u64>().map_err(|_| {
            RegistryError::schema(format!(
                "semantic reference {source:?} major exceeds u64 range"
            ))
        })?;
        Ok(Self {
            id: id.to_owned(),
            major,
        })
    }
}

pub(crate) fn validate_semantic_id(id: &str) -> RegistryResult<()> {
    if id.len() < 3 || id.len() > 160 {
        return Err(RegistryError::schema(format!(
            "semantic identifier {id:?} must contain 3..=160 bytes"
        )));
    }
    let mut bytes = id.bytes();
    if !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        || !bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
        })
    {
        return Err(RegistryError::schema(format!(
            "semantic identifier {id:?} violates the v0.1 ASCII grammar"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_versions_and_major_references() {
        assert_eq!(FullVersion::parse("1.2.3").unwrap().major, 1);
        assert_eq!(SemanticRef::parse("data.table@1").unwrap().major, 1);
        assert!(FullVersion::parse("1").is_err());
        assert!(FullVersion::parse("01.0").is_err());
        assert!(SemanticRef::parse("data.table@1.0").is_err());
        assert!(SemanticRef::parse("data.table").is_err());
    }
}
