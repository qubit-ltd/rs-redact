// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for atomic two-layer field resolution.

use qubit_redact::{
    MaskPolicy,
    RedactionFloor,
    RedactionPolicy,
    Redactor,
    Sensitivity,
};

/// Verifies a floor only raises sensitivity and uses the policy mask table.
#[test]
fn test_resolved_field_uses_application_mask_at_floor_level() {
    let floor = RedactionFloor::builder()
        .raise("tenant_secret", Sensitivity::Low)
        .build()
        .expect("the floor should be valid");
    let policy = RedactionPolicy::builder()
        .floor(floor)
        .raise("tenant_secret", Sensitivity::Secret)
        .mask(
            Sensitivity::Secret,
            MaskPolicy::fixed("[application-secret]"),
        )
        .build()
        .expect("the application policy should be valid");

    assert_eq!(
        Redactor::new(policy)
            .redact_field("tenant_secret", "source")
            .as_str(),
        "[application-secret]",
    );
}
