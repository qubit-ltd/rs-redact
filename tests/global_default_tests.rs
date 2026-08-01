// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for process-wide default redaction policy installation.

use qubit_redact::{
    GlobalDefaultAlreadySet,
    RedactionFloor,
    RedactionFloorState,
    RedactionPolicy,
    Redactor,
    Sensitivity,
};

/// Verifies one-time installation and snapshot isolation of the global default.
#[test]
fn test_global_default_can_be_installed_once_and_is_snapshotted() {
    let before = RedactionPolicy::default();
    let before_floor_builder = RedactionPolicy::empty_builder();
    let custom = RedactionPolicy::empty_builder()
        .raise("tenant_protected_blob", Sensitivity::Secret)
        .build()
        .expect("the custom global policy should be valid");

    RedactionPolicy::set_global_default(custom)
        .expect("the first global default installation should succeed");

    assert_eq!(
        RedactionPolicy::default().sensitivity_for("tenant_protected_blob"),
        Some(Sensitivity::Secret),
    );
    assert_eq!(
        RedactionPolicy::global_default()
            .sensitivity_for("tenant_protected_blob"),
        Some(Sensitivity::Secret),
    );
    let from_current_default = RedactionPolicy::builder_from_default()
        .build()
        .expect("the current global default snapshot should remain valid");
    assert_eq!(
        from_current_default.sensitivity_for("tenant_protected_blob"),
        Some(Sensitivity::Secret),
    );
    assert_eq!(before.sensitivity_for("tenant_protected_blob"), None);
    assert_eq!(
        RedactionPolicy::standard().sensitivity_for("tenant_protected_blob"),
        None,
    );
    assert_eq!(
        RedactionPolicy::set_global_default(RedactionPolicy::standard()),
        Err(GlobalDefaultAlreadySet),
    );
    assert_eq!(
        GlobalDefaultAlreadySet.to_string(),
        "the requested global redaction default is already set",
    );

    let floor = RedactionFloor::empty_builder()
        .raise("tenant_floor_blob", Sensitivity::Secret)
        .build()
        .expect("the custom global floor should be valid");
    RedactionFloor::set_global_default(floor)
        .expect("the first global floor installation should succeed");

    let before_floor = before_floor_builder
        .build()
        .expect("the pre-install builder snapshot should build");
    let after_floor = RedactionPolicy::empty_builder()
        .build()
        .expect("the post-install builder snapshot should build");

    assert_eq!(
        before_floor.floor_state(),
        RedactionFloorState::GlobalDefault
    );
    assert_eq!(before_floor.sensitivity_for("tenant_floor_blob"), None,);
    assert_eq!(
        after_floor.sensitivity_for("tenant_floor_blob"),
        Some(Sensitivity::Secret),
    );
    assert_eq!(
        Redactor::new(before_floor)
            .redact("tenant_floor_blob", "raw")
            .as_str(),
        "raw",
    );
    assert_eq!(
        RedactionPolicy::default().sensitivity_for("tenant_floor_blob"),
        None,
        "the independently installed policy default must retain its old floor snapshot",
    );
    assert_eq!(
        RedactionPolicy::standard().sensitivity_for("tenant_floor_blob"),
        None,
        "the immutable standard policy must not read the mutable global floor",
    );
    assert_eq!(
        RedactionFloor::global_default()
            .sensitive_rules()
            .find(|rule| rule.field() == "tenantfloorblob")
            .map(|rule| rule.sensitivity()),
        Some(Sensitivity::Secret),
    );
    assert_eq!(
        RedactionFloor::set_global_default(RedactionFloor::standard()),
        Err(GlobalDefaultAlreadySet),
    );
}
