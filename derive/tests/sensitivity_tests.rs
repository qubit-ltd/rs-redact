// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for sensitivity parsing and expansion.

mod support;

/// Verifies sensitivity literals map into runtime behavior.
#[test]
fn test_sensitivity_literal_maps_to_runtime() {
    support::assertions::assert_sensitivity_expansion();
}
