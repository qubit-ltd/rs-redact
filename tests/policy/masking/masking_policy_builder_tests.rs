// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Public construction contracts for the four-level masking builder.

use qubit_redact::MaskPolicy;
use qubit_redact::MaskingPolicy;
use qubit_redact::Sensitivity;

/// Verifies that construction and lookup select each requested level.
#[test]
fn test_masking_policy_builder_and_for_level_select_requested_policy() {
    let mut builder = MaskingPolicy::builder();
    builder
        .low(MaskPolicy::fixed("low"))
        .medium(MaskPolicy::fixed("medium"))
        .high(MaskPolicy::fixed("high"))
        .secret(MaskPolicy::fixed("secret"));
    let policy = builder.build();

    assert_eq!(policy.mask(Sensitivity::Low, "value"), "low");
    assert_eq!(policy.mask(Sensitivity::Medium, "value"), "medium");
    assert_eq!(policy.mask(Sensitivity::High, "value"), "high");
    assert_eq!(policy.mask(Sensitivity::Secret, "value"), "secret");
}

/// Verifies opaque values use only complete configured replacements.
#[test]
fn test_masking_policy_builder_masks_opaque_values_without_retaining_edges() {
    let mut builder = MaskingPolicy::builder();
    builder
        .low(MaskPolicy::preserve_edges(2, 2, "<low>", 0))
        .medium(MaskPolicy::preserve_suffix(2, "<medium>", 0))
        .high(MaskPolicy::fixed("<high>"))
        .secret(MaskPolicy::empty());
    let policy = builder.build();

    assert_eq!(policy.mask_opaque(Sensitivity::Low), "<low>");
    assert_eq!(policy.mask_opaque(Sensitivity::Medium), "<medium>");
    assert_eq!(policy.mask_opaque(Sensitivity::High), "<high>");
    assert_eq!(policy.mask_opaque(Sensitivity::Secret), "");
}

/// Verifies that replacing one level leaves all other levels unchanged.
#[test]
fn test_masking_policy_builder_updates_requested_levels() {
    let mut builder = MaskingPolicy::builder();
    builder
        .low(MaskPolicy::fixed("<low>"))
        .medium(MaskPolicy::fixed("<medium>"))
        .high(MaskPolicy::fixed("<high>"))
        .secret(MaskPolicy::fixed("<secret>"));
    let policy = builder.build();

    assert_eq!(policy.mask(Sensitivity::Low, "value"), "<low>");
    assert_eq!(policy.mask(Sensitivity::Medium, "value"), "<medium>");
    assert_eq!(policy.mask(Sensitivity::High, "value"), "<high>");
    assert_eq!(policy.mask(Sensitivity::Secret, "value"), "<secret>");
}

/// Verifies low and medium builder methods remain independently usable
/// statements, as required by callers that do not use a fluent chain.
#[test]
fn test_masking_policy_builder_sets_low_and_medium_independently() {
    let mut builder = MaskingPolicy::builder();
    builder.low(MaskPolicy::fixed("<low>"));
    builder.medium(MaskPolicy::fixed("<medium>"));
    let policy = builder.build();

    assert_eq!(policy.mask(Sensitivity::Low, "value"), "<low>");
    assert_eq!(policy.mask(Sensitivity::Medium, "value"), "<medium>");
}
