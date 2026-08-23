// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-time regression tests for optional format APIs.

use std::env;
use std::fs;
use std::process;
use std::process::Command;

/// Verifies that a separately compiled no-feature dependent crate cannot use
/// a format entry point that is unavailable without its feature.
fn assert_format_api_is_feature_gated(method: &str) {
    let directory = env::temp_dir().join(format!("qubit-redact-feature-gate-{}-{method}", process::id()));
    fs::create_dir_all(directory.join("src")).expect("the temporary dependent crate directory should be creatable");
    let manifest = format!(
        "[package]\nname = \"qubit-redact-feature-gate-{method}\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[workspace]\n\n[dependencies]\nqubit-redact = {{ path = \"{}\", default-features = false }}\n",
        env!("CARGO_MANIFEST_DIR")
    );
    fs::write(directory.join("Cargo.toml"), manifest).expect("the temporary manifest should be writable");
    fs::write(
        directory.join("src/main.rs"),
        format!(
            "use {}::Redactor;\n\nfn main() {{\n    let _ = Redactor::strict().{method}(\"input\");\n}}\n",
            "qubit_redact"
        ),
    )
    .expect("the temporary source should be writable");

    let output = Command::new(env!("CARGO"))
        .args(["check", "--offline"])
        .current_dir(&directory)
        .output()
        .expect("cargo check for the temporary dependent crate should run");
    let diagnostics = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success(), "{method} must require its feature");
    assert!(
        diagnostics.contains(method),
        "the compiler diagnostics must name {method}: {diagnostics}"
    );
    fs::remove_dir_all(directory).expect("the temporary dependent crate directory should be removable");
}

/// Compiles a temporary dependent crate using the supplied dependency feature
/// declaration and returns its Cargo output.
fn check_derive_dependency(case: &str, dependency_options: &str) -> std::process::Output {
    let directory = env::temp_dir().join(format!("qubit-redact-derive-feature-{}-{case}", process::id()));
    fs::create_dir_all(directory.join("src")).expect("the temporary dependent crate directory should be creatable");
    fs::write(
        directory.join("Cargo.toml"),
        format!(
            "[package]\nname = \"qubit-redact-derive-feature-{case}\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[workspace]\n\n[dependencies]\nqubit-redact = {{ path = \"{}\"{dependency_options} }}\n",
            env!("CARGO_MANIFEST_DIR"),
        ),
    )
    .expect("the temporary manifest should be writable");
    fs::write(
        directory.join("src/main.rs"),
        format!(
            "use {}::Redact;\n\n#[derive(Redact)]\nstruct Value;\n\nfn main() {{}}\n",
            "qubit_redact",
        ),
    )
    .expect("the temporary source should be writable");

    let output = Command::new(env!("CARGO"))
        .args(["check", "--offline"])
        .current_dir(&directory)
        .output()
        .expect("cargo check for the temporary dependent crate should run");
    fs::remove_dir_all(directory).expect("the temporary dependent crate directory should be removable");
    output
}

/// JSON methods must not leak from the default feature surface.
#[test]
fn json_api_is_unavailable_without_the_json_feature() {
    assert_format_api_is_feature_gated("redact_json");
    assert_format_api_is_feature_gated("inspect_json");
}

/// HTTP methods must not leak from the default feature surface.
#[test]
fn http_api_is_unavailable_without_the_http_feature() {
    assert_format_api_is_feature_gated("redact_http_url");
    assert_format_api_is_feature_gated("inspect_http_url");
}

/// URI methods must not leak from the default feature surface.
#[test]
fn uri_api_is_unavailable_without_the_uri_feature() {
    assert_format_api_is_feature_gated("redact_uri");
    assert_format_api_is_feature_gated("inspect_uri");
}

/// The default feature set re-exports the derive macro.
#[test]
fn test_default_features_export_the_redact_derive() {
    let output = check_derive_dependency("default", "");
    assert!(
        output.status.success(),
        "default dependency must export the derive macro: {}",
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Disabling defaults removes the derive macro from the dependency surface.
#[test]
fn test_no_default_features_hide_the_redact_derive() {
    let output = check_derive_dependency("no-default", ", default-features = false");
    let diagnostics = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "no-default dependency must not export the derive macro"
    );
    assert!(
        diagnostics.contains("derive macro") && diagnostics.contains("Redact"),
        "compiler diagnostics must identify the missing Redact derive: {diagnostics}",
    );
}

/// Explicitly enabling `derive` restores the macro without other defaults.
#[test]
fn test_explicit_derive_feature_exports_the_redact_derive() {
    let output = check_derive_dependency("explicit", ", default-features = false, features = [\"derive\"]");
    assert!(
        output.status.success(),
        "explicit derive feature must export the macro: {}",
        String::from_utf8_lossy(&output.stderr),
    );
}
