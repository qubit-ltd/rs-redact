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

/// JSON methods must not leak from the default feature surface.
#[test]
fn json_api_is_unavailable_without_the_json_feature() {
    assert_format_api_is_feature_gated("redact_json");
}

/// HTTP methods must not leak from the default feature surface.
#[test]
fn http_api_is_unavailable_without_the_http_feature() {
    assert_format_api_is_feature_gated("redact_http_url");
}

/// URI methods must not leak from the default feature surface.
#[test]
fn uri_api_is_unavailable_without_the_uri_feature() {
    assert_format_api_is_feature_gated("redact_uri");
}
