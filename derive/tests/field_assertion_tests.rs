// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for generated field capability assertions.

mod support;

/// Verifies missing nested capabilities produce a compile-time assertion.
#[test]
fn test_field_assertion_rejects_missing_nested_capability() {
    support::assertions::assert_compile_fail(
        "tests/fixtures/fail/nested_without_redact.rs",
    );
}
