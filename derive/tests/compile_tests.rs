// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile tests for supported `Redact` derive inputs.

/// Verifies that all supported derive fixtures compile successfully.
#[test]
fn test_pass_fixtures() {
    trybuild::TestCases::new().pass("tests/fixtures/pass/*.rs");
}

/// Verifies that invalid attributes produce stable targeted diagnostics.
#[test]
fn test_compile_fail_fixtures() {
    trybuild::TestCases::new().compile_fail("tests/fixtures/fail/*.rs");
}
