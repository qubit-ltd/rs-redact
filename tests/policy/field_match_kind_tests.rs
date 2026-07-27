// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`FieldMatchKind`](qubit_redact::FieldMatchKind).

use qubit_redact::FieldMatchKind;

/// Verifies exact and token-suffix matches remain distinct public outcomes.
#[test]
fn test_field_match_kind_distinguishes_exact_and_token_suffix() {
    assert_ne!(FieldMatchKind::Exact, FieldMatchKind::TokenSuffix);
    assert_eq!(format!("{:?}", FieldMatchKind::Exact), "Exact");
    assert_eq!(format!("{:?}", FieldMatchKind::TokenSuffix), "TokenSuffix",);
}
