// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared allocation reuse when combining minimum field-protection floors.

use std::sync::Arc;

use crate::policy::RedactionFloor;

/// Combining an already present standard floor retains both shared indexes.
#[test]
fn test_floor_combine_reuses_standard_allocations() {
    let standard = RedactionFloor::standard();
    let combined = standard.combine(&RedactionFloor::standard());

    assert!(
        Arc::ptr_eq(&standard.layers, &combined.layers),
        "combining an existing standard floor must retain the layer allocation"
    );
    assert!(
        Arc::ptr_eq(&standard.sensitive_index, &combined.sensitive_index),
        "combining an existing standard floor must retain the canonical index"
    );
}
