// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for process-wide redaction configuration installation.

use qubit_redact::{
    GlobalRedactionConfig, GlobalRedactionConfigAlreadyInstalled, RedactionFloor,
    RedactionPolicy, Sensitivity,
};

/// Verifies atomic installation and deterministic builder snapshots.
#[test]
fn test_global_config_is_installed_once_and_snapshotted() {
    let before = RedactionPolicy::default();
    let before_builder = RedactionPolicy::builder();
    let floor = RedactionFloor::builder()
        .raise("tenant_floor_blob", Sensitivity::Secret)
        .build()
        .expect("the custom floor should be valid");
    let custom = RedactionPolicy::builder()
        .floor(floor)
        .raise("tenant_protected_blob", Sensitivity::Secret)
        .build()
        .expect("the custom policy should be valid");

    GlobalRedactionConfig::from_policy(custom.clone())
        .install()
        .expect("the first global configuration installation should succeed");

    assert_eq!(GlobalRedactionConfig::current().policy(), &custom);
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
    assert_eq!(RedactionPolicy::standard().sensitivity_for("tenant_floor_blob"), None);
    assert_eq!(
        GlobalRedactionConfig::standard().install(),
        Err(GlobalRedactionConfigAlreadyInstalled),
    );
}
