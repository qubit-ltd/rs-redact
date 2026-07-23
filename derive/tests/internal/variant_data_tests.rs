// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for parsed enum variant state.

use crate::support;

/// Verifies parsed variants retain names, order, and field shapes.
#[test]
fn test_variant_data_retains_variant_shapes() {
    support::assertions::assert_enum_redaction();
}
