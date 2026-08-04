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
};

/// Redacted value whose escaped representation exceeds the test budget.
struct LongUnsafeDiagnostic;

impl Redact for LongUnsafeDiagnostic {
    /// Writes a prefix, one control, and an overlong suffix.
    fn fmt_redacted(
        &self,
        _session: &qubit_redact::RedactionSession<'_>,
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
        _session: &qubit_redact::RedactionSession<'_>,
        _formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        Err(fmt::Error)
    }
}

/// Redacted value that writes a fixed diagnostic representation.
struct FixedDiagnostic(&'static str);

impl Redact for FixedDiagnostic {
    /// Writes the fixed representation exactly as supplied.
    fn fmt_redacted(
        &self,
        _session: &qubit_redact::RedactionSession<'_>,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        formatter.write_str(self.0)
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

/// Verifies complete and malformed pre-generated debug escapes are handled
/// without changing their text.
#[test]
fn test_bounded_log_escape_writer_parses_debug_escape_forms() {
    let input = r#"\\\"\n\r\t\0\x41\u{202e}\x4g\u{}\u{xyz}\u{12\"#;
    let limit = LogOutputLimit::new(128)
        .expect("the test budget should contain every escape form");

    let output = FixedDiagnostic(input)
        .redacted()
        .with_output_limit(limit)
        .to_string();

    assert_eq!(output, input);
}

/// Verifies an atomic pre-generated escape triggers truncation when the
/// complete escape cannot fit.
#[test]
fn test_bounded_log_escape_writer_truncates_before_atomic_escape() {
    let limit = LogOutputLimit::new(14)
        .expect("the test budget can contain the marker");
    let output = FixedDiagnostic(r"abcdefghijk\x41")
        .redacted()
        .with_output_limit(limit)
        .to_string();

    assert_eq!(output, "abc<truncated>");
}
