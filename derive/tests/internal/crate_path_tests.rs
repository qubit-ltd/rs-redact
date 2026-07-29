// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for runtime crate-path resolution.

use std::{
    env,
    ffi::OsString,
    path::PathBuf,
    process::Output,
};

/// Runs Cargo against one isolated runtime-path fixture.
///
/// # Parameters
///
/// * `fixture` - Fixture directory below `tests/fixtures/crates`.
///
/// # Returns
///
/// The complete Cargo output for exact status and diagnostic assertions.
fn check_fixture(fixture: &str) -> Output {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest = manifest_dir
        .join("tests/fixtures/crates")
        .join(fixture)
        .join("Cargo.toml");
    let target_dir = manifest_dir
        .join("../target")
        .join(format!("{fixture}-fixture"));
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));

    crate::support::isolated_cargo::command(&cargo)
        .args(["check", "--manifest-path"])
        .arg(manifest)
        .arg("--target-dir")
        .arg(target_dir)
        .output()
        .expect("the isolated cargo check starts")
}

/// Verifies generated code resolves a renamed runtime dependency.
#[test]
fn test_runtime_crate_path_resolves_renamed_dependency() {
    let output = check_fixture("renamed_dependency");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "{stderr}");
}

/// Verifies a package named `qubit-redact` reaches the `Itself` lookup branch.
#[test]
fn test_runtime_crate_path_resolves_itself() {
    let output = check_fixture("runtime_itself");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains("has unknown container attribute"),
        "{stderr}",
    );
    assert!(
        !stderr.contains("unable to resolve the qubit-redact runtime crate"),
        "{stderr}",
    );
}

/// Verifies a missing runtime dependency emits the targeted public diagnostic.
#[test]
fn test_runtime_crate_path_reports_missing_dependency() {
    let output = check_fixture("runtime_missing");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success(), "{stderr}");
    assert_eq!(
        stderr
            .matches("unable to resolve the qubit-redact runtime crate")
            .count(),
        2,
        "{stderr}",
    );
}
