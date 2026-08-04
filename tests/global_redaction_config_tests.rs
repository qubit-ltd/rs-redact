// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for process-wide redaction configuration installation.

use qubit_redact::{
    RedactionFloor,
    RedactionPolicy,
    Sensitivity,
};

/// Verifies startup installation and deterministic explicit snapshots.
#[test]
fn test_global_config_is_installed_once_and_snapshotted() {
    let before = RedactionPolicy::standard();
    let before_builder = RedactionPolicy::builder();
    let floor = RedactionFloor::builder()
        .raise("tenant_floor_blob", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .build()
        .expect("the custom floor should be valid");
    let custom = RedactionPolicy::builder()
        .floor(floor)
        .raise("tenant_protected_blob", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .build()
        .expect("the custom policy should be valid");

    RedactionPolicy::install_global(custom.clone())
        .expect("the first global configuration installation should succeed");

    assert_eq!(RedactionPolicy::global(), &custom);
    assert_eq!(RedactionPolicy::default(), custom);
    assert_eq!(before.sensitivity_for("tenant_protected_blob"), None);
    assert_eq!(
        RedactionPolicy::builder()
            .build()
            .expect("the deterministic builder should remain valid")
            .sensitivity_for("tenant_floor_blob"),
        None,
    );
    assert_eq!(
        before_builder
            .build()
            .expect("the pre-install builder should remain valid")
            .sensitivity_for("tenant_floor_blob"),
        None,
    );
    assert_eq!(
        RedactionPolicy::standard().sensitivity_for("tenant_floor_blob"),
        None
    );
    assert_eq!(
        RedactionPolicy::install_global(RedactionPolicy::standard())
            .expect_err("the global policy can only be installed once")
            .to_string(),
        "the global redaction policy is already installed",
    );
}
