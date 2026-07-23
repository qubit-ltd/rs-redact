// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for safe formatting expansion.

mod support;

/// Verifies generated formatting traits delegate to redaction.
#[test]
fn test_format_expansion_delegates_to_redaction() {
    support::assertions::assert_format_expansion();
}
