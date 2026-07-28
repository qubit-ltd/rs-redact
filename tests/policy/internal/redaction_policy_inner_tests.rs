// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for policy state used by public field matching.

use qubit_redact::{
    RedactionPolicy,
    Sensitivity,
};

/// Verifies internal policy state supports normalized public lookup.
#[test]
fn test_redaction_policy_inner_normalizes_field_name_for_lookup() {
    let policy = RedactionPolicy::builder()
        .raise("tenant_secret", Sensitivity::Secret)
        .build()
        .expect("the configured rule should be valid");

    assert_eq!(
        policy.sensitivity_for("tenant-secret"),
        Some(Sensitivity::Secret),
    );
}
