//! Process-level contract tests for the JSON-only CLI.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_aios-ir"))
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/aios-ir")
}

fn run_program(command: &str, program: &Path) -> Output {
    cli()
        .arg(command)
        .arg(program)
        .arg("--registry")
        .arg(fixture_root())
        .output()
        .expect("run program command")
}

fn temporary_program(label: &str, bytes: &[u8]) -> PathBuf {
    let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "aios-ir-cli-{label}-{}-{sequence}.json",
        std::process::id()
    ));
    std::fs::write(&path, bytes).expect("write temporary program");
    path
}

fn temporary_directory(label: &str) -> PathBuf {
    let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "aios-ir-cli-{label}-{}-{sequence}",
        std::process::id()
    ));
    std::fs::create_dir(&path).expect("create temporary directory");
    path
}

#[test]
fn help_is_json_on_stdout() {
    let output = cli().arg("--help").output().expect("run CLI");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let response: Value = serde_json::from_slice(&output.stdout).expect("JSON help response");
    assert_eq!(response["ok"], true);
    assert!(
        response["information"]
            .as_str()
            .is_some_and(|text| text.contains("validate"))
    );
}

#[test]
fn argument_failure_is_json_and_operational_exit() {
    let output = cli()
        .args(["validate", "program.json"])
        .output()
        .expect("run CLI");

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let response: Value =
        serde_json::from_slice(&output.stdout).expect("JSON argument-error response");
    assert_eq!(response["ok"], false);
    assert_eq!(response["error"]["code"], "CLI_ARGUMENT_INVALID");
}

#[test]
fn unreadable_program_is_json_and_operational_exit() {
    let output = cli()
        .args([
            "validate",
            "this-program-does-not-exist.json",
            "--registry",
            "this-registry-does-not-exist",
        ])
        .output()
        .expect("run CLI");

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let response: Value =
        serde_json::from_slice(&output.stdout).expect("JSON program-read error response");
    assert_eq!(response["ok"], false);
    assert_eq!(response["error"]["code"], "CLI_PROGRAM_READ_FAILED");
}

#[test]
fn registry_load_errors_do_not_expose_host_paths() {
    let missing_registry = std::env::temp_dir().join(format!(
        "aios-ir-private-registry-path-{}",
        std::process::id()
    ));
    let output = cli()
        .arg("validate")
        .arg(fixture_root().join("demonstration-a.ir.json"))
        .arg("--registry")
        .arg(&missing_registry)
        .output()
        .expect("run CLI");

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let response: Value = serde_json::from_slice(&output.stdout).expect("JSON registry error");
    assert_eq!(response["error"]["code"], "CLI_REGISTRY_LOAD_FAILED");
    let serialized = String::from_utf8(output.stdout).unwrap();
    assert!(!serialized.contains(&missing_registry.display().to_string()));
    assert!(!serialized.contains("aios-ir-private-registry-path"));
}

#[test]
fn all_program_views_succeed_with_json_only_output() {
    let program = fixture_root().join("demonstration-a.ir.json");
    for (command, expected_field) in [
        ("validate", "effect_summary"),
        ("normalize", "normalized"),
        ("hash", "semantic_hash"),
        ("effects", "effect_summary"),
    ] {
        let output = run_program(command, &program);
        assert!(output.status.success(), "{command}");
        assert!(output.stderr.is_empty(), "{command}");
        let response: Value = serde_json::from_slice(&output.stdout).expect("JSON response");
        assert_eq!(response["validation"]["valid"], true, "{command}");
        assert!(!response[expected_field].is_null(), "{command}");
    }
}

#[test]
fn deterministic_rejection_uses_exit_two_and_never_emits_identity() {
    let secret = "Bearer sk-test-duplicate-key-secret";
    let program = temporary_program(
        "rejected",
        br#"{"Bearer sk-test-duplicate-key-secret":0,"Bearer sk-test-duplicate-key-secret":0}"#,
    );
    for command in ["validate", "normalize", "hash", "effects"] {
        let output = run_program(command, &program);
        assert_eq!(output.status.code(), Some(2), "{command}");
        assert!(output.stderr.is_empty(), "{command}");
        let response: Value = serde_json::from_slice(&output.stdout).expect("JSON rejection");
        assert_eq!(response["validation"]["valid"], false, "{command}");
        assert!(!String::from_utf8_lossy(&output.stdout).contains(secret));
        assert!(
            response["validation"]["semantic_hash"].is_null(),
            "{command}"
        );
        match command {
            "validate" | "effects" => assert!(response["effect_summary"].is_null()),
            "normalize" => assert!(response["normalized"].is_null()),
            "hash" => assert!(response["semantic_hash"].is_null()),
            _ => unreachable!(),
        }
    }
    let _ = std::fs::remove_file(program);
}

#[test]
fn schema_rejections_do_not_echo_invalid_instance_values() {
    let secret = "Bearer sk-test-super-secret-do-not-log";
    let base: Value = serde_json::from_slice(
        &std::fs::read(fixture_root().join("demonstration-a.ir.json")).unwrap(),
    )
    .unwrap();
    for (label, pointer) in [
        ("secret-program-id", "/program_id"),
        (
            "secret-authority-resource",
            "/nodes/0/authority_requests/0/resource",
        ),
    ] {
        let mut program = base.clone();
        *program.pointer_mut(pointer).unwrap() = Value::String(secret.to_owned());
        let path = temporary_program(label, &serde_json::to_vec(&program).unwrap());
        let output = run_program("validate", &path);
        let _ = std::fs::remove_file(path);

        assert_eq!(output.status.code(), Some(2));
        assert!(output.stderr.is_empty());
        let response: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            response["validation"]["diagnostics"][0]["code"],
            "IR_SCHEMA_PATTERN"
        );
        assert!(response["validation"]["ir_version"].is_null());
        assert!(response["validation"]["program_id"].is_null());
        assert!(response["validation"]["semantic_hash"].is_null());
        assert!(
            !serde_json::to_string(&response["validation"]["diagnostics"])
                .unwrap()
                .contains(secret)
        );
        assert!(!String::from_utf8(output.stdout).unwrap().contains(secret));
    }
}

#[test]
fn schema_valid_semantic_rejection_preserves_identifiers() {
    let mut program: Value = serde_json::from_slice(
        &std::fs::read(fixture_root().join("demonstration-a.ir.json")).unwrap(),
    )
    .unwrap();
    let expected_program_id = program["program_id"].clone();
    program["nodes"][0]["inputs"]["source"]["name"] = Value::String("missing".to_owned());
    let path = temporary_program(
        "semantic-identifier",
        &serde_json::to_vec(&program).unwrap(),
    );
    let output = run_program("validate", &path);
    let _ = std::fs::remove_file(path);

    assert_eq!(output.status.code(), Some(2));
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["validation"]["ir_version"], "0.1");
    assert_eq!(response["validation"]["program_id"], expected_program_id);
    assert!(response["validation"]["semantic_hash"].is_null());
    assert!(
        response["validation"]["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diagnostic| diagnostic["node_id"] == "import_table")
    );
}

#[test]
fn pre_schema_rejections_do_not_echo_unvalidated_identifiers() {
    let secret = "Bearer sk-test-unvalidated-identifier";
    let base: Value = serde_json::from_slice(
        &std::fs::read(fixture_root().join("demonstration-a.ir.json")).unwrap(),
    )
    .unwrap();

    let mut cases = Vec::new();
    let mut unsupported_version = base.clone();
    unsupported_version["ir_version"] = Value::String(secret.to_owned());
    cases.push((
        "secret-version",
        unsupported_version,
        "IR_VERSION_UNSUPPORTED",
    ));

    let mut unbounded_retry = base.clone();
    unbounded_retry["nodes"][0]["id"] = Value::String(secret.to_owned());
    unbounded_retry["nodes"][0]["failure"] = serde_json::json!({"on_error":"retry"});
    cases.push((
        "secret-node-retry",
        unbounded_retry,
        "IR_FAILURE_POLICY_UNBOUNDED",
    ));

    let mut contradictory_egress = base;
    contradictory_egress["nodes"][0]["id"] = Value::String(secret.to_owned());
    contradictory_egress["nodes"][0]["egress"] =
        serde_json::json!({"mode":"deny","destination_classes":["public"]});
    cases.push((
        "secret-node-egress",
        contradictory_egress,
        "IR_EGRESS_CONTRADICTION",
    ));

    for (label, program, expected_code) in cases {
        let path = temporary_program(label, &serde_json::to_vec(&program).unwrap());
        let output = run_program("validate", &path);
        let _ = std::fs::remove_file(path);

        assert_eq!(output.status.code(), Some(2));
        assert!(output.stderr.is_empty());
        assert!(!String::from_utf8_lossy(&output.stdout).contains(secret));
        let response: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            response["validation"]["diagnostics"][0]["code"],
            expected_code
        );
        assert!(response["validation"]["ir_version"].is_null());
        assert!(response["validation"]["program_id"].is_null());
        assert!(response["validation"]["diagnostics"][0]["node_id"].is_null());
    }
}

#[test]
fn oversized_input_is_bounded_and_rejected() {
    let program = temporary_program("oversized", &vec![b' '; 1_048_577]);
    let output = run_program("validate", &program);
    let _ = std::fs::remove_file(program);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let response: Value = serde_json::from_slice(&output.stdout).expect("JSON rejection");
    assert_eq!(
        response["validation"]["diagnostics"][0]["code"],
        "IR_LIMIT_DOCUMENT_SIZE"
    );
    assert!(response["validation"]["semantic_hash"].is_null());
}

#[test]
fn explain_error_handles_known_and_unknown_codes_as_json() {
    let known = cli()
        .args(["explain-error", "IR_GRAPH_CYCLE"])
        .output()
        .expect("run explain-error");
    assert!(known.status.success());
    assert!(known.stderr.is_empty());
    let response: Value = serde_json::from_slice(&known.stdout).unwrap();
    assert_eq!(response["reason_code"], "IR_GRAPH_CYCLE");

    let unknown = cli()
        .args(["explain-error", "NOT_A_REASON"])
        .output()
        .expect("run explain-error");
    assert_eq!(unknown.status.code(), Some(1));
    assert!(unknown.stderr.is_empty());
    let response: Value = serde_json::from_slice(&unknown.stdout).unwrap();
    assert_eq!(response["error"]["code"], "CLI_REASON_CODE_UNKNOWN");
}

#[test]
fn corrupt_registry_uses_normative_bounded_rejection_output() {
    let directory = temporary_directory("corrupt-registry");
    for name in ["capability-contracts.json", "type-contracts.json"] {
        std::fs::copy(fixture_root().join(name), directory.join(name)).unwrap();
    }
    let snapshot_path = fixture_root().join("registry-snapshot.json");
    let mut snapshot: Value =
        serde_json::from_slice(&std::fs::read(snapshot_path).unwrap()).unwrap();
    snapshot["snapshot_id"] = Value::String(format!("sha256:{}", "a".repeat(64)));
    std::fs::write(
        directory.join("registry-snapshot.json"),
        serde_json::to_vec(&snapshot).unwrap(),
    )
    .unwrap();

    let output = cli()
        .arg("validate")
        .arg(fixture_root().join("demonstration-a.ir.json"))
        .arg("--registry")
        .arg(&directory)
        .output()
        .expect("run registry rejection");
    for name in [
        "capability-contracts.json",
        "type-contracts.json",
        "registry-snapshot.json",
    ] {
        let _ = std::fs::remove_file(directory.join(name));
    }
    let _ = std::fs::remove_dir(directory);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["validation"]["valid"], false);
    assert_eq!(
        response["validation"]["diagnostics"][0]["code"],
        "REGISTRY_SNAPSHOT_HASH_MISMATCH"
    );
    assert!(response["validation"]["semantic_hash"].is_null());
    assert!(response["effect_summary"].is_null());
}

#[test]
fn duplicate_registry_key_text_is_redacted_from_cli_output() {
    let secret = "Bearer sk-test-registry-duplicate-key";
    let directory = temporary_directory("duplicate-key-registry");
    for name in ["capability-contracts.json", "type-contracts.json"] {
        std::fs::copy(fixture_root().join(name), directory.join(name)).unwrap();
    }
    let snapshot = std::fs::read_to_string(fixture_root().join("registry-snapshot.json")).unwrap();
    let injected = snapshot.replacen('{', &format!("{{\"{secret}\":0,\"{secret}\":1,"), 1);
    std::fs::write(directory.join("registry-snapshot.json"), injected).unwrap();

    let output = cli()
        .arg("validate")
        .arg(fixture_root().join("demonstration-a.ir.json"))
        .arg("--registry")
        .arg(&directory)
        .output()
        .expect("run duplicate-key registry rejection");

    for name in [
        "capability-contracts.json",
        "type-contracts.json",
        "registry-snapshot.json",
    ] {
        let _ = std::fs::remove_file(directory.join(name));
    }
    let _ = std::fs::remove_dir(directory);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(secret));
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        response["validation"]["diagnostics"][0]["code"],
        "REGISTRY_SCHEMA_INVALID"
    );
    assert_eq!(
        response["validation"]["diagnostics"][0]["message"],
        "duplicate JSON key"
    );
}
