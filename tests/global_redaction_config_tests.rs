// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for process-wide redaction configuration installation.

use qubit_redact::RedactionFloor;
use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;
/// Verifies startup installation and deterministic explicit snapshots.
#[test]
fn test_global_config_is_installed_once_and_snapshotted() {
    let before = RedactionPolicy::default();
    let before_builder = RedactionPolicy::builder();
    let floor = RedactionFloor::builder()
        .raise("tenant_floor_blob", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .build()
        .expect("the custom floor should be valid");
    let mut builder = RedactionPolicy::builder();
    builder
        .fields()
        .floor(floor)
        .raise("tenant_protected_blob", Sensitivity::Secret)
        .expect("the test builder input should be valid");
    let custom = builder.build().expect("the custom policy should be valid");

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
    let rejected = RedactionPolicy::strict();
    let error = RedactionPolicy::install_global(rejected.clone())
        .expect_err("the global policy can only be installed once");
    assert_eq!(
        error.to_string(),
        "the global redaction policy is already installed"
    );
    assert_eq!(error.into_policy(), rejected);
}
