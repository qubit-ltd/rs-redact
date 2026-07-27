// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`BoundedLogSafeDisplay`](qubit_redact::BoundedLogSafeDisplay).

use qubit_redact::{
    LogOutputLimit,
    Redactor,
};

/// Verifies bounded log-safe text is truncated at the configured byte limit.
#[test]
fn test_bounded_log_safe_display_truncates_at_budget() {
    let limit = LogOutputLimit::new(14)
        .expect("the test budget can contain the truncation marker");
    let text = Redactor::default()
        .redact("message", "abcdefghijklmno")
        .escape_for_log();

    let output = text.with_output_limit(limit).to_string();

    assert_eq!(output, "abc<truncated>");
    assert_eq!(output.len(), limit.max_bytes());
}

/// Verifies truncation preserves a complete pre-generated escape token.
#[test]
fn test_bounded_log_safe_display_does_not_split_preescaped_control() {
    let limit = LogOutputLimit::new(14)
        .expect("the test budget can contain the truncation marker");
    let text = Redactor::default()
        .redact("message", "ab\nremaining-long")
        .escape_for_log();

    let output = text.with_output_limit(limit).to_string();

    assert_eq!(output, "ab<truncated>");
    assert!(!output.ends_with("\\<truncated>"));
}
