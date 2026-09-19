//! Closed v0.1 authority-class semantics.

use aios_contracts::EffectClass;

/// Resolve a bootstrap authority class to the semantic effect it necessarily
/// introduces. Unknown classes are intentionally not inferred by prefix.
pub fn effect_for_authority_class(authority: &str) -> Option<EffectClass> {
    match authority {
        "artifact.read" => Some(EffectClass::ArtifactRead),
        "artifact.write" => Some(EffectClass::ArtifactWrite),
        "network.connect" => Some(EffectClass::Network),
        "data.egress" => Some(EffectClass::DataEgress),
        "external.send" => Some(EffectClass::ExternalMessage),
        "secret.use" => Some(EffectClass::SecretAccess),
        "state.write" => Some(EffectClass::PersistentState),
        "device.use" => Some(EffectClass::DeviceAccess),
        "system.change" => Some(EffectClass::SystemChange),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_is_closed_and_does_not_use_prefix_inference() {
        for (authority, effect) in [
            ("artifact.read", EffectClass::ArtifactRead),
            ("artifact.write", EffectClass::ArtifactWrite),
            ("network.connect", EffectClass::Network),
            ("data.egress", EffectClass::DataEgress),
            ("external.send", EffectClass::ExternalMessage),
            ("secret.use", EffectClass::SecretAccess),
            ("state.write", EffectClass::PersistentState),
            ("device.use", EffectClass::DeviceAccess),
            ("system.change", EffectClass::SystemChange),
        ] {
            assert_eq!(effect_for_authority_class(authority), Some(effect));
        }
        assert_eq!(effect_for_authority_class("data.egress.extra"), None);
        assert_eq!(effect_for_authority_class("custom.artifact.read"), None);
    }
}
