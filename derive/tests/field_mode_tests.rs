// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for field-mode selection.

mod support;

/// Verifies plain, sensitive, skipped, and map modes remain distinct.
#[test]
fn test_field_modes_generate_distinct_behavior() {
    support::assertions::assert_named_redaction();
}
