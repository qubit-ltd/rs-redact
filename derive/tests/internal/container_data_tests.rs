// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for parsed container shape selection.

use crate::support;

/// Verifies enum containers reach immutable expansion.
#[test]
fn test_container_data_selects_enum_shape() {
    support::assertions::assert_enum_redaction();
}
