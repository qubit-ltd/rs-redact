// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for the shared derive input model.

mod support;

/// Verifies the input model preserves every enum variant shape.
#[test]
fn test_input_model_preserves_enum_shapes() {
    support::assertions::assert_enum_redaction();
}
