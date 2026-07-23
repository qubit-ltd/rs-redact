// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for mutable implementation expansion.

mod support;

/// Verifies mutable expansion applies the configured sensitivity.
#[test]
fn test_redact_mut_expansion_applies_sensitivity() {
    support::assertions::assert_mutable_redaction();
}
