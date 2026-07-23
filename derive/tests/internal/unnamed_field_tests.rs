// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for parsed positional-field state.

use crate::support;

/// Verifies parsed positional fields retain stable indexes and controls.
#[test]
fn test_unnamed_field_retains_index_and_controls() {
    support::assertions::assert_tuple_redaction();
}
