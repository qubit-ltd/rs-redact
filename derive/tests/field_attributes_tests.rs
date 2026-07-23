// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for field attribute parsing.

mod support;

/// Verifies mutually exclusive field modes are rejected.
#[test]
fn test_field_attributes_reject_conflicting_modes() {
    support::assertions::assert_compile_fail(
        "tests/fixtures/fail/conflicting_modes.rs",
    );
}
