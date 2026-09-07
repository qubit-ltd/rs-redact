// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Internal bounded masking and formatter error propagation.

use std::fmt;

use crate::MaskPolicy;

struct FailingWriter;

impl fmt::Write for FailingWriter {
    fn write_str(&mut self, _value: &str) -> fmt::Result {
        Err(fmt::Error)
    }
}

#[test]
fn test_mask_bounded_with_truncation_respects_unicode_boundary() {
    let (masked, truncated) = MaskPolicy::fixed("甲乙丙").mask_bounded_with_truncation("secret", 4);

    assert_eq!(masked, "甲");
    assert!(truncated);
}

#[test]
fn test_mask_bounded_with_truncation_preserves_empty_borrow_without_truncation() {
    let (masked, truncated) = MaskPolicy::fixed("mask").mask_bounded_with_truncation("", 0);

    assert_eq!(masked, "");
    assert!(matches!(masked, std::borrow::Cow::Borrowed("")));
    assert!(!truncated);
}

#[test]
fn test_mask_bounded_with_truncation_covers_edge_and_suffix_outputs() {
    let (edges, edges_truncated) = MaskPolicy::preserve_edges(1, 1, "***", 0).mask_bounded_with_truncation("甲乙丙", 7);
    let (suffix, suffix_truncated) = MaskPolicy::preserve_suffix(1, "***", 0).mask_bounded_with_truncation("甲乙丙", 6);

    assert_eq!(edges, "甲***");
    assert!(edges_truncated);
    assert_eq!(suffix, "***丙");
    assert!(!suffix_truncated);
}

#[test]
fn test_opaque_mask_bounded_uses_complete_utf8_prefix() {
    assert_eq!(MaskPolicy::fixed("甲乙").opaque_mask_bounded(4), "甲");
    assert_eq!(MaskPolicy::empty().opaque_mask_bounded(0), "");
}

#[test]
fn test_write_masked_writes_each_policy_and_propagates_errors() {
    let mut output = String::new();
    MaskPolicy::preserve_edges(1, 1, "*", 0)
        .write_masked("abcd", &mut output)
        .expect("the string writer should accept the mask");
    assert_eq!(output, "a*d");

    output.clear();
    MaskPolicy::preserve_suffix(2, "*", 0)
        .write_masked("abcd", &mut output)
        .expect("the string writer should accept the mask");
    assert_eq!(output, "*cd");

    MaskPolicy::empty()
        .write_masked("secret", &mut output)
        .expect("the empty policy should not write");
    assert_eq!(
        MaskPolicy::fixed("*").write_masked("secret", &mut FailingWriter),
        Err(fmt::Error),
    );
}
