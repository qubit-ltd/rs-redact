// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for masking policy primitives.

use qubit_redact::{FieldNameMatching, MaskPolicy, MaskingPolicy, Sensitivity};

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
    assert_ne!(
        FieldNameMatching::Exact,
        FieldNameMatching::ExactOrTokenSuffix,
    );
    assert_eq!(MaskPolicy::fixed("x").mask("secret"), "x");
}

/// Verifies that construction and lookup select each requested level.
#[test]
fn test_masking_policy_new_and_for_level_select_requested_policy() {
    let policy = MaskingPolicy::new(
        MaskPolicy::fixed("low"),
        MaskPolicy::fixed("medium"),
        MaskPolicy::fixed("high"),
        MaskPolicy::fixed("secret"),
    );

    assert_eq!(policy.mask(Sensitivity::Low, "value"), "low");
    assert_eq!(policy.mask(Sensitivity::Medium, "value"), "medium");
    assert_eq!(policy.mask(Sensitivity::High, "value"), "high");
    assert_eq!(policy.mask(Sensitivity::Secret, "value"), "secret");
}

/// Verifies opaque values use only complete configured replacements.
#[test]
fn test_masking_policy_masks_opaque_values_without_retaining_edges() {
    let policy = MaskingPolicy::new(
        MaskPolicy::preserve_edges(2, 2, "<low>", 0),
        MaskPolicy::preserve_suffix(2, "<medium>", 0),
        MaskPolicy::fixed("<high>"),
        MaskPolicy::empty(),
    );

    assert_eq!(policy.mask_opaque(Sensitivity::Low), "<low>");
    assert_eq!(policy.mask_opaque(Sensitivity::Medium), "<medium>");
    assert_eq!(policy.mask_opaque(Sensitivity::High), "<high>");
    assert_eq!(policy.mask_opaque(Sensitivity::Secret), "");
}

/// Verifies that replacing one level leaves all other levels unchanged.
#[test]
fn test_masking_policy_with_policy_updates_requested_level() {
    let policy = MaskingPolicy::default()
        .with_policy(Sensitivity::Low, MaskPolicy::fixed("<low>"))
        .with_policy(Sensitivity::Medium, MaskPolicy::fixed("<medium>"))
        .with_policy(Sensitivity::High, MaskPolicy::fixed("<high>"))
        .with_policy(Sensitivity::Secret, MaskPolicy::fixed("<secret>"));

    assert_eq!(policy.mask(Sensitivity::Low, "value"), "<low>");
    assert_eq!(policy.mask(Sensitivity::Medium, "value"), "<medium>");
    assert_eq!(policy.mask(Sensitivity::High, "value"), "<high>");
    assert_eq!(policy.mask(Sensitivity::Secret, "value"), "<secret>");
}
