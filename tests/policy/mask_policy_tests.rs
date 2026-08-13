// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`MaskPolicy`](qubit_redact::MaskPolicy).

use proptest::prelude::Just;
use proptest::prelude::any;
use proptest::prelude::prop_assert_ne;
use proptest::prelude::prop_oneof;
use proptest::prelude::proptest;
use qubit_redact::MaskPolicy;
/// Verifies that a fixed policy masks non-empty values.
#[test]
fn test_mask_policy_fixed_masks_non_empty_value() {
    assert_eq!(MaskPolicy::fixed("****").mask("secret-token"), "****");
}

/// Verifies that a fixed policy preserves an empty value.
#[test]
fn test_mask_policy_fixed_keeps_empty_value_empty() {
    assert_eq!(MaskPolicy::fixed("****").mask(""), "");
}

/// Verifies that an edge policy fully masks values at its threshold.
#[test]
fn test_mask_policy_preserve_edges_masks_short_value() {
    assert_eq!(
        MaskPolicy::preserve_edges(2, 2, "****", 4).mask("abcd"),
        "****",
    );
}

/// Verifies that edge counts use Unicode scalar values rather than bytes.
#[test]
fn test_mask_policy_preserve_edges_keeps_unicode_edges() {
    assert_eq!(
        MaskPolicy::preserve_edges(1, 1, "****", 2).mask("密钥值"),
        "密****值",
    );
}

/// Verifies edge policies retain an empty requested suffix without scanning or
/// exposing an overlapping value.
#[test]
fn test_mask_policy_preserve_edges_keeps_prefix_with_empty_suffix() {
    assert_eq!(
        MaskPolicy::preserve_edges(1, 0, "****", 0).mask("密钥值"),
        "密****",
    );
}

/// Verifies that overflowing edge counts cannot expose the raw value.
#[test]
fn test_mask_policy_preserve_edges_masks_when_edge_lengths_overflow() {
    let redacted = MaskPolicy::preserve_edges(usize::MAX, 1, "****", 0)
        .mask("secret-token");

    assert_eq!(redacted, "****");
    assert!(!redacted.contains("secret-token"));
}

/// Verifies that a suffix policy retains only the requested tail.
#[test]
fn test_mask_policy_preserve_suffix_keeps_only_tail() {
    assert_eq!(
        MaskPolicy::preserve_suffix(4, "****", 4).mask("1234567890"),
        "****7890",
    );
}

/// Verifies that suffix counts use Unicode scalar values rather than bytes.
#[test]
fn test_mask_policy_preserve_suffix_keeps_unicode_tail() {
    assert_eq!(
        MaskPolicy::preserve_suffix(2, "****", 2).mask("甲乙丙丁戊"),
        "****丁戊",
    );
}

/// Verifies a zero-length suffix remains fully masked even above the threshold.
#[test]
fn test_mask_policy_preserve_suffix_masks_when_suffix_is_empty() {
    assert_eq!(
        MaskPolicy::preserve_suffix(0, "****", 0).mask("密钥值"),
        "****",
    );
}

/// Verifies that a suffix policy fully masks values at its threshold.
#[test]
fn test_mask_policy_preserve_suffix_masks_short_value() {
    assert_eq!(
        MaskPolicy::preserve_suffix(4, "****", 4).mask("abcd"),
        "****",
    );
}

/// Verifies that an empty policy removes a non-empty value.
#[test]
fn test_mask_policy_empty_removes_value() {
    let constructor =
        std::hint::black_box(MaskPolicy::empty as fn() -> MaskPolicy);
    assert_eq!(constructor().mask("secret-token"), "");
}

proptest! {
    /// Verifies that arbitrary edge counts never reproduce a non-empty ASCII value.
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
        let redacted = policy.mask(&value);

        prop_assert_ne!(redacted.as_ref(), value.as_str());
    }
}
