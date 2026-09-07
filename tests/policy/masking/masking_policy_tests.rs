// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for masking policy primitives.

use qubit_redact::FieldNameMatching;
use qubit_redact::MaskPolicy;
use qubit_redact::MaskingPolicy;
use qubit_redact::Sensitivity;

/// Verifies that the new default masking model retains the established masks.
#[test]
fn test_default_masking_policy_preserves_existing_semantics() {
    let policy = MaskingPolicy::default();

    assert_eq!(policy.mask(Sensitivity::Low, "abcdefgh"), "ab****gh");
    assert_eq!(policy.mask(Sensitivity::Medium, "abcdefgh"), "*******h");
    assert_eq!(policy.mask(Sensitivity::High, "abcdefgh"), "****");
    assert_eq!(policy.mask(Sensitivity::Secret, "abcdefgh"), "<redacted>");
    assert_eq!(policy.mask(Sensitivity::Secret, ""), "");
}

/// Verifies that matching modes and fixed masks have explicit public behavior.
#[test]
fn test_field_name_matching_names_are_explicit() {
    assert_ne!(FieldNameMatching::Exact, FieldNameMatching::ExactOrTokenSuffix,);
    assert_eq!(MaskPolicy::fixed("x").mask("secret"), "x");
}
