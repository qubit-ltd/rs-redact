// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile tests for redacted serde integration.

#![cfg(feature = "serde")]

/// Verifies supported serde shapes and targeted unsupported-attribute errors.
#[test]
fn test_redacted_serde_ui() {
    let tests = trybuild::TestCases::new();
    tests.pass("tests/fixtures/domain_serde/pass/*.rs");
    tests.compile_fail("tests/fixtures/domain_serde/fail/*.rs");
}
