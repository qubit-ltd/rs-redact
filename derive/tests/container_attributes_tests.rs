// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for container attribute parsing.

mod support;

/// Verifies accepted container formatting controls affect generated behavior.
#[test]
fn test_container_attributes_generate_safe_formatting() {
    support::assertions::assert_format_expansion();
}
