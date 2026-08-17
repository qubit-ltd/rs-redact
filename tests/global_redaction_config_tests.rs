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
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
/// Verifies startup installation and deterministic explicit snapshots.
#[test]
fn test_global_config_is_installed_once_and_snapshotted() {
    let before = Redactor::default().policy().clone();
    let before_builder = RedactionPolicy::builder();
    let floor = RedactionFloor::builder()
        .raise("tenant_floor_blob", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .build()
        .expect("the custom floor should be valid");
    let mut builder = RedactionPolicy::builder();
    builder
        .edit_fields()
        .floor(floor)
        .raise("tenant_protected_blob", Sensitivity::Secret)
        .expect("the test builder input should be valid");
    let custom = builder.build().expect("the custom policy should be valid");

    let previous = Redactor::set_default(Redactor::new(custom.clone()));

    assert_eq!(Redactor::default().policy(), &custom);
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
    let _ = Redactor::set_default(previous);
}
