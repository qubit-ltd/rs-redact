// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for positional field parsing.

mod support;

/// Verifies positional field indexes drive tuple redaction.
#[test]
fn test_unnamed_fields_use_stable_indexes() {
    support::assertions::assert_tuple_redaction();
}
