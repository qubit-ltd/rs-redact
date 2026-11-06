// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Unpublished argv rendering and direct adapter capacity contracts.

use std::ffi::OsStr;

use crate::RedactionCompletion;
use crate::RedactionPolicy;
use crate::formats::argv::ArgvItem;
use crate::formats::argv::redaction::redact_heuristically_with_policy;

/// Covers both bounded fallback representations.
#[test]
fn test_heuristic_rendering_bounds_truncated_fallbacks() {
    let policy = RedactionPolicy::standard();
    let item = ArgvItem::plain(OsStr::new("long-visible-value"));

    let fallback = redact_heuristically_with_policy(&policy, [item], 11);
    assert_eq!(
        fallback.text(),
        "<truncated>",
        "a fitting fallback must replace the partial argv"
    );
    assert_eq!(
        fallback.completion(),
        RedactionCompletion::Truncated,
        "a retained fallback must report truncation"
    );

    let empty = redact_heuristically_with_policy(&policy, [item], 0);
    assert!(empty.text().is_empty(), "zero capacity must retain no output");
    assert_eq!(
        empty.completion(),
        RedactionCompletion::Exhausted,
        "zero capacity must report exhaustion"
    );
}
