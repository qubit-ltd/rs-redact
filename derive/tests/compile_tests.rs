// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile tests for supported `Redact` derive inputs.

/// Verifies that a generic named-field struct compiles successfully.
#[test]
fn test_basic_named_struct_passes() {
    trybuild::TestCases::new()
        .pass("tests/fixtures/pass/basic_named_struct.rs");
}
