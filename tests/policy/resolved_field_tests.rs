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

/// Verifies a floor owns the masking policy even when the application raises
/// the resulting sensitivity further.
#[test]
fn test_resolved_field_uses_floor_mask_at_application_secret_level() {
    let floor = RedactionFloor::empty_builder()
        .raise("tenant_secret", Sensitivity::Low)
        .mask(Sensitivity::Secret, MaskPolicy::fixed("[floor-secret]"))
        .build()
        .expect("the floor should be valid");
    let policy = RedactionPolicy::empty_builder()
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
            .redact("tenant_secret", "source")
            .as_str(),
        "[floor-secret]",
    );
}
