// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Verifies the serde feature guard in an isolated Cargo workspace.

use std::{
    env,
    path::PathBuf,
    process::Command,
};

/// Verifies feature-disabled expansion emits one targeted primary diagnostic.
#[test]
fn test_serde_feature_guard_is_single_and_targeted() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest =
        manifest_dir.join("tests/fixtures/crates/serde_disabled/Cargo.toml");
    let target_dir = manifest_dir.join("../target/serde-disabled-fixture");
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .args(["check", "--manifest-path"])
        .arg(&manifest)
        .arg("--target-dir")
        .arg(target_dir)
        .output()
        .expect("the isolated cargo check starts");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let primary_errors = stderr
        .lines()
        .filter(|line| {
            line.starts_with("error: ") && !line.contains("could not compile")
        })
        .count();

    assert!(!output.status.success());
    assert_eq!(primary_errors, 1, "{stderr}");
    assert!(
        stderr.contains(
            "#[redact(serde)] requires the `serde` feature of qubit-redact"
        ),
        "{stderr}",
    );
    assert!(!stderr.contains("unresolved import `serde`"), "{stderr}");
    assert!(!stderr.contains("failed to resolve"), "{stderr}");
}
