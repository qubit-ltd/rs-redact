// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Verifies runtime dependency alias resolution.

use std::{
    env,
    path::PathBuf,
};

mod support;

/// Verifies generated code uses the Cargo dependency alias.
#[test]
fn test_renamed_runtime_dependency_compiles() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest = manifest_dir
        .join("tests/fixtures/crates/renamed_dependency/Cargo.toml");
    let target_dir = manifest_dir.join("../target/renamed-dependency-fixture");
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = support::isolated_cargo::command(&cargo)
        .args(["check", "--manifest-path"])
        .arg(manifest)
        .arg("--target-dir")
        .arg(target_dir)
        .output()
        .expect("the isolated cargo check starts");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "{stderr}");
}
