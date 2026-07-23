// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for immutable implementation expansion.

mod support;

/// Verifies immutable expansion preserves enum formatting shapes.
#[test]
fn test_redact_expansion_preserves_enum_shapes() {
    support::assertions::assert_enum_redaction();
}
