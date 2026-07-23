// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for Serde container attributes.

mod support;

/// Verifies adjacent tag and content controls shape the wire output.
#[test]
fn test_serde_container_attributes_shape_wire_output() {
    support::assertions::assert_serde_expansion();
}
