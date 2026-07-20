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
    RedactionPolicy,
    Sensitivity,
};

/// Verifies one-time installation and snapshot isolation of the global default.
#[test]
fn test_global_default_can_be_installed_once_and_is_snapshotted() {
    let before = RedactionPolicy::default();
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
    let from_current_default = RedactionPolicy::builder()
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
}
