// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for the proc-macro crate boundary.

mod support;

/// Verifies the exported derive macro produces a usable implementation.
#[test]
fn test_library_macro_boundary_is_usable() {
    support::assertions::assert_named_redaction();
}
