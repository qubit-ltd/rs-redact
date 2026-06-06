// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`MaskPolicy`](qubit_sanitize::MaskPolicy).

use qubit_sanitize::MaskPolicy;

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
fn test_mask_policy_preserve_suffix_keeps_only_tail() {
    let policy = MaskPolicy::preserve_suffix(4, "****", 4);

    assert_eq!(policy.mask("1234567890"), "****7890");
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
