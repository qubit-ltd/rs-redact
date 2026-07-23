// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for mutable derive orchestration.

mod support;

/// Verifies mutable derive orchestration generates destructive redaction.
#[test]
fn test_redact_mut_derive_generates_mutation() {
    support::assertions::assert_mutable_redaction();
}
