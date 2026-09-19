//! Static tripwires for the deterministic trusted-library boundary.

const TRUSTED_SOURCES: &[(&str, &str)] = &[
    ("ir/lib.rs", include_str!("../src/lib.rs")),
    ("ir/diagnostics.rs", include_str!("../src/diagnostics.rs")),
    ("ir/explain.rs", include_str!("../src/explain.rs")),
    ("ir/hash.rs", include_str!("../src/hash.rs")),
    ("ir/limits.rs", include_str!("../src/limits.rs")),
    ("ir/normalize.rs", include_str!("../src/normalize.rs")),
    ("ir/parse.rs", include_str!("../src/parse.rs")),
    ("ir/schema.rs", include_str!("../src/schema.rs")),
    ("ir/semantics.rs", include_str!("../src/semantics.rs")),
    ("ir/validator.rs", include_str!("../src/validator.rs")),
    (
        "contracts/diagnostics.rs",
        include_str!("../../aios-contracts/src/diagnostics.rs"),
    ),
    (
        "contracts/ir.rs",
        include_str!("../../aios-contracts/src/ir.rs"),
    ),
    (
        "contracts/lib.rs",
        include_str!("../../aios-contracts/src/lib.rs"),
    ),
    (
        "contracts/output.rs",
        include_str!("../../aios-contracts/src/output.rs"),
    ),
    (
        "contracts/provider.rs",
        include_str!("../../aios-contracts/src/provider.rs"),
    ),
    (
        "contracts/registry.rs",
        include_str!("../../aios-contracts/src/registry.rs"),
    ),
    (
        "contracts/serde_support.rs",
        include_str!("../../aios-contracts/src/serde_support.rs"),
    ),
    (
        "registry/lib.rs",
        include_str!("../../aios-registry/src/lib.rs"),
    ),
    (
        "registry/authority.rs",
        include_str!("../../aios-registry/src/authority.rs"),
    ),
    (
        "registry/error.rs",
        include_str!("../../aios-registry/src/error.rs"),
    ),
    (
        "registry/hash.rs",
        include_str!("../../aios-registry/src/hash.rs"),
    ),
    (
        "registry/loader.rs",
        include_str!("../../aios-registry/src/loader.rs"),
    ),
    (
        "registry/conformance.rs",
        include_str!("../../aios-registry/src/conformance.rs"),
    ),
    (
        "registry/strict_json.rs",
        include_str!("../../aios-registry/src/strict_json.rs"),
    ),
    (
        "registry/version.rs",
        include_str!("../../aios-registry/src/version.rs"),
    ),
];

#[test]
fn trusted_libraries_have_no_process_network_or_runtime_execution_path() {
    for (name, source) in TRUSTED_SOURCES {
        for forbidden in [
            "std::process::Command",
            "Command::new(",
            "std::net::",
            "TcpStream",
            "UdpSocket",
            "reqwest::",
            "hyper::",
            "ureq::",
            "tokio::net",
            "provider.execute",
            "model.invoke",
            "shell_execute",
        ] {
            assert!(
                !source.contains(forbidden),
                "trusted source {name} contains forbidden execution/network primitive {forbidden}"
            );
        }
    }

    for (name, manifest) in [
        ("aios-ir", include_str!("../Cargo.toml")),
        (
            "aios-registry",
            include_str!("../../aios-registry/Cargo.toml"),
        ),
        (
            "aios-contracts",
            include_str!("../../aios-contracts/Cargo.toml"),
        ),
    ] {
        for forbidden_dependency in ["reqwest", "hyper", "ureq", "tokio", "wasmtime"] {
            assert!(
                !manifest.contains(forbidden_dependency),
                "trusted crate {name} declares forbidden runtime dependency {forbidden_dependency}"
            );
        }
    }
}
