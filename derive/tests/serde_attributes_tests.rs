// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for Serde field attributes.

mod support;

/// Verifies allowlisted field controls preserve redacted serialization.
#[test]
fn test_serde_field_attributes_preserve_redaction() {
    support::assertions::assert_serde_expansion();
}
