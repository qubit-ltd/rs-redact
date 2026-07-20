// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`MaskPolicy`](qubit_redact::MaskPolicy).

use proptest::prelude::{
    Just,
    any,
    prop_assert_ne,
    prop_oneof,
    proptest,
};

use qubit_redact::MaskPolicy;

#[test]
fn test_mask_policy_fixed_masks_non_empty_value() {
    let policy = MaskPolicy::fixed("****");

    assert_eq!(policy.mask("secret-token"), "****");
}

#[test]
fn test_mask_policy_fixed_keeps_empty_value_empty() {
    let policy = MaskPolicy::fixed("****");

    assert_eq!(policy.mask(""), "");
}

#[test]
fn test_mask_policy_preserve_edges_masks_short_value() {
    let policy = MaskPolicy::preserve_edges(2, 2, "****", 4);

    assert_eq!(policy.mask("abcd"), "****");
}

#[test]
fn test_mask_policy_preserve_edges_keeps_unicode_edges() {
    let policy = MaskPolicy::preserve_edges(1, 1, "****", 2);

    assert_eq!(policy.mask("密钥值"), "密****值");
}

#[test]
fn test_mask_policy_preserve_edges_masks_when_edge_lengths_overflow() {
    let policy = MaskPolicy::preserve_edges(usize::MAX, 1, "****", 0);
    let sanitized = policy.mask("secret-token");

    assert_eq!(sanitized, "****");
    assert!(!sanitized.contains("secret-token"));
}

#[test]
fn test_mask_policy_preserve_suffix_keeps_only_tail() {
    let policy = MaskPolicy::preserve_suffix(4, "****", 4);

    assert_eq!(policy.mask("1234567890"), "****7890");
}

#[test]
fn test_mask_policy_preserve_suffix_keeps_unicode_tail() {
    let policy = MaskPolicy::preserve_suffix(2, "****", 2);

    assert_eq!(policy.mask("甲乙丙丁戊"), "****丁戊");
}

#[test]
fn test_mask_policy_preserve_suffix_masks_short_value() {
    let policy = MaskPolicy::preserve_suffix(4, "****", 4);

    assert_eq!(policy.mask("abcd"), "****");
}

#[test]
fn test_mask_policy_empty_removes_value() {
    let policy = MaskPolicy::empty();

    assert_eq!(policy.mask("secret-token"), "");
}

proptest! {
    #[test]
    fn test_mask_policy_preserve_edges_proptest_never_returns_raw_value(
        prefix_chars in prop_oneof![Just(usize::MAX), any::<usize>()],
        suffix_chars in prop_oneof![Just(usize::MAX), any::<usize>()],
        value in "[A-Za-z0-9]{1,64}",
    ) {
        let policy = MaskPolicy::preserve_edges(
            prefix_chars,
            suffix_chars,
            "****",
            0,
        );
        let sanitized = policy.mask(&value);

        prop_assert_ne!(sanitized.as_ref(), value.as_str());
    }
}
