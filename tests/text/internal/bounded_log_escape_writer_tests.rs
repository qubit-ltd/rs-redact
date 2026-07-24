// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Public-contract tests for the internal bounded escape writer.

use std::fmt;

use qubit_redact::{
    LogOutputLimit,
    Redact,
    RedactionPolicy,
};

/// Redacted value whose escaped representation exceeds the test budget.
struct LongUnsafeDiagnostic;

impl Redact for LongUnsafeDiagnostic {
    /// Writes a prefix, one control, and an overlong suffix.
    fn fmt_redacted(
        &self,
        _policy: &RedactionPolicy,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        formatter.write_str("ab\nremaining-long")
    }
}

/// Redacted value that rejects formatting.
struct FailingDiagnostic;

impl Redact for FailingDiagnostic {
    /// Returns a formatting error without writing output.
    fn fmt_redacted(
        &self,
        _policy: &RedactionPolicy,
        _formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        Err(fmt::Error)
    }
}

/// Verifies truncation preserves complete generated escape sequences.
#[test]
fn test_bounded_log_escape_writer_keeps_atomic_escape_boundary() {
    let limit = LogOutputLimit::new(14)
        .expect("the test budget can contain the marker");
    let output = LongUnsafeDiagnostic
        .redacted()
        .with_output_limit(limit)
        .to_string();

    assert_eq!(output, "ab<truncated>");
}

/// Verifies a redacted formatter failure is returned unchanged.
#[test]
fn test_bounded_log_escape_writer_propagates_redaction_failure() {
    let limit = LogOutputLimit::new(64)
        .expect("the test budget can contain the marker");
    let result = std::fmt::write(
        &mut String::new(),
        format_args!(
            "{}",
            FailingDiagnostic.redacted().with_output_limit(limit),
        ),
    );

    assert_eq!(result, Err(fmt::Error));
}
