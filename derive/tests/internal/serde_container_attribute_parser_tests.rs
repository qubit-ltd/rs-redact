// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for the supported Serde container-attribute parser.

/// Verifies unsupported and incompatible container controls are rejected.
#[test]
fn test_serde_container_attribute_parser_rejects_invalid_controls() {
    crate::support::assertions::assert_compile_fail(
        "tests/fixtures/fail/invalid_serde_container_attributes.rs",
    );
}
