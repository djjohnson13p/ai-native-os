//! Exercise raw local-bundle admission, not just the typed construction API.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use aios_contracts::ValidatorReasonCode;
use aios_registry::{RegistryLoadOptions, SemanticRegistry};
use serde_json::{Value, json};

struct Bundle(PathBuf);

impl Bundle {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "aios-review-admission-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/aios-ir");
        for file in [
            "registry-snapshot.json",
            "type-contracts.json",
            "capability-contracts.json",
        ] {
            std::fs::copy(fixture.join(file), root.join(file)).unwrap();
        }
        Self(root)
    }

    fn mutate(&self, file: &str, edit: impl FnOnce(&mut Value)) {
        let path = self.0.join(file);
        let mut value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        edit(&mut value);
        std::fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
    }

    fn reject(&self) {
        let error =
            SemanticRegistry::load_bundle(&self.0, RegistryLoadOptions::default()).unwrap_err();
        assert_eq!(
            error.reason_code(),
            Some(ValidatorReasonCode::RegistrySchemaInvalid),
            "{error}"
        );
    }
}

impl Drop for Bundle {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn raw_schema_failures_precede_contract_and_snapshot_hash_checks() {
    let bundle = Bundle::new();
    assert!(SemanticRegistry::load_bundle(&bundle.0, RegistryLoadOptions::default()).is_ok());
    bundle.mutate("type-contracts.json", |contracts| {
        contracts[0]["unit_semantics"] = json!({"unit_required": null});
    });
    bundle.reject();

    let bundle = Bundle::new();
    bundle.mutate("capability-contracts.json", |contracts| {
        contracts[0]["description"] = Value::Null;
    });
    bundle.reject();

    let bundle = Bundle::new();
    bundle.mutate("registry-snapshot.json", |snapshot| {
        snapshot["publisher"] = json!({"id": null});
    });
    bundle.reject();
}

#[test]
fn nullable_and_omitted_nonsemantic_fields_keep_strict_registry_identity() {
    let bundle = Bundle::new();
    let original =
        SemanticRegistry::load_bundle(&bundle.0, RegistryLoadOptions::default()).unwrap();
    bundle.mutate("capability-contracts.json", |contracts| {
        contracts[0].as_object_mut().unwrap().remove("description");
    });
    bundle.mutate("registry-snapshot.json", |snapshot| {
        snapshot["generation"] = Value::Null;
        snapshot["publisher"] = json!({});
    });
    let admitted =
        SemanticRegistry::load_bundle(&bundle.0, RegistryLoadOptions::default()).unwrap();
    assert_eq!(original.snapshot_id(), admitted.snapshot_id());
}

#[test]
fn raw_negative_underflow_fails_before_hash_interpretation() {
    let bundle = Bundle::new();
    bundle.mutate("capability-contracts.json", |contracts| {
        contracts[0]["determinism"]["numeric_absolute_tolerance"] = json!("RAW_NUMBER");
    });
    let path = bundle.0.join("capability-contracts.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap()
        .replace("\"RAW_NUMBER\"", "-1e-9999");
    std::fs::write(path, raw).unwrap();
    bundle.reject();
}
