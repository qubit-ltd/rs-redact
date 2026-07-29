// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for generated capability trait names.

mod support;

/// Verifies map-mode diagnostics retain the required capability trait name.
#[test]
fn test_immutable_trait_name_preserves_map_capability_diagnostic() {
    support::assertions::assert_compile_fail("tests/fixtures/fail/map_without_map_trait.rs");
}
