// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for Serde variant attributes.

mod support;

/// Verifies variant-level representation data reaches generated output.
#[test]
fn test_serde_variant_attributes_reach_output() {
    support::assertions::assert_serde_expansion();
}
