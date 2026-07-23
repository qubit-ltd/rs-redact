// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for named, tuple, and unit field-shape selection.

use crate::support;

/// Verifies tuple fields preserve their positional shape.
#[test]
fn test_fields_data_selects_tuple_shape() {
    support::assertions::assert_tuple_redaction();
}
