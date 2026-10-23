// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Internal contracts for environment-pair rendering.

use std::ffi::OsStr;

use crate::RedactionCompletion;
use crate::RedactionPolicy;
use crate::formats::env::redaction::redact_os_pairs_with_policy;

/// Covers sensitive, pass-through, and bounded environment collections.
#[test]
fn test_environment_rendering_covers_classification_and_fallbacks() {
    let policy = RedactionPolicy::standard();
    let pairs = [
        (OsStr::new("MODE"), OsStr::new("debug")),
        (OsStr::new("PASSWORD"), OsStr::new("secret")),
    ];
    let complete = redact_os_pairs_with_policy(&policy, pairs, usize::MAX);
    assert!(complete.text().contains("MODE=debug"));
    assert!(!complete.text().contains("secret"));

    let fallback = redact_os_pairs_with_policy(&policy, pairs, 11);
    assert_eq!(fallback.text(), "<truncated>");
    assert_eq!(fallback.completion(), RedactionCompletion::Truncated);

    let empty = redact_os_pairs_with_policy(&policy, pairs, 0);
    assert!(empty.text().is_empty());
    assert_eq!(empty.completion(), RedactionCompletion::Exhausted);
}
