// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Verifies direct serde dependency resolution for generated implementations.

use std::{
    env,
    path::PathBuf,
};

#[path = "support/isolated_cargo.rs"]
mod isolated_cargo;

/// Verifies redacted serialization requires serde as a direct dependency.
#[test]
fn test_missing_direct_serde_dependency_is_targeted() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest =
        manifest_dir.join("tests/fixtures/crates/serde_missing/Cargo.toml");
    let target_dir = manifest_dir.join("../target/serde-missing-fixture");
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = isolated_cargo::command(&cargo)
        .args(["check", "--manifest-path"])
        .arg(&manifest)
        .arg("--target-dir")
        .arg(target_dir)
        .output()
        .expect("the isolated cargo check starts");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains(
            "unable to resolve serde; add `serde` as a direct dependency"
        ),
        "{stderr}",
    );
}

/// Verifies generated code honors a renamed serde dependency.
#[test]
fn test_renamed_serde_dependency_compiles() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest =
        manifest_dir.join("tests/fixtures/crates/serde_renamed/Cargo.toml");
    let target_dir = manifest_dir.join("../target/serde-renamed-fixture");
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = isolated_cargo::command(&cargo)
        .args(["check", "--manifest-path"])
        .arg(&manifest)
        .arg("--target-dir")
        .arg(target_dir)
        .output()
        .expect("the isolated cargo check starts");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr),
    );
}
