// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for runtime path resolution.

#![cfg(feature = "derive")]

use std::env;
use std::path::PathBuf;
mod support;

/// Verifies the ordinary direct runtime dependency resolves in expansion.
#[test]
fn test_runtime_path_resolves_direct_dependency() {
    support::assertions::assert_named_redaction();
}

/// Verifies a missing runtime dependency emits the targeted lookup error.
#[test]
fn test_runtime_path_reports_missing_dependency() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest = manifest_dir.join("tests/fixtures/crates/runtime_missing/Cargo.toml");
    let target_dir = manifest_dir.join("target/runtime-missing-fixture");
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = support::isolated_cargo::command(&cargo)
        .args(["check", "--manifest-path"])
        .arg(&manifest)
        .arg("--target-dir")
        .arg(target_dir)
        .output()
        .expect("the isolated cargo check starts");
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

/// Verifies `Itself` resolution happens before container attribute validation.
#[test]
fn test_runtime_path_resolves_itself() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest = manifest_dir.join("tests/fixtures/crates/runtime_itself/Cargo.toml");
    let target_dir = manifest_dir.join("target/runtime-itself-fixture");
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = support::isolated_cargo::command(&cargo)
        .args(["check", "--manifest-path"])
        .arg(&manifest)
        .arg("--target-dir")
        .arg(target_dir)
        .output()
        .expect("the isolated cargo check starts");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("has unknown container attribute"), "{stderr}",);
    assert!(
        !stderr.contains("unable to resolve the qubit-redact runtime crate"),
        "{stderr}",
    );
}

/// Verifies successful generated implementations use the runtime crate itself.
#[test]
fn test_runtime_path_itself_expands_and_runs() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest = manifest_dir.join("tests/fixtures/crates/runtime_itself_success/Cargo.toml");
    let target_dir = manifest_dir.join("target/runtime-itself-success-fixture");
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = support::isolated_cargo::command(&cargo)
        .args(["run", "--manifest-path"])
        .arg(manifest)
        .arg("--target-dir")
        .arg(target_dir)
        .output()
        .expect("the isolated cargo run starts");
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
