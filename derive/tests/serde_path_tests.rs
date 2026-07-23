// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for direct Serde path resolution.

use std::{
    env,
    path::PathBuf,
};

#[path = "support/isolated_cargo.rs"]
mod isolated_cargo;
mod support;

/// Verifies the direct Serde dependency is usable by generated code.
#[test]
fn test_serde_path_resolves_direct_dependency() {
    support::assertions::assert_serde_expansion();
}

/// Verifies a crate named `serde` resolves through `FoundCrate::Itself`.
#[test]
fn test_serde_path_resolves_itself() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest =
        manifest_dir.join("tests/fixtures/crates/serde_itself/Cargo.toml");
    let target_dir = manifest_dir.join("../target/serde-itself-fixture");
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
        stderr.contains("does not support container `transparent`"),
        "{stderr}",
    );
    assert!(
        !stderr.contains("unable to resolve serde; add `serde`"),
        "{stderr}",
    );
}
