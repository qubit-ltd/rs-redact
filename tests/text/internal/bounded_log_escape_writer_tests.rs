// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Public-contract tests for the internal bounded escape writer.

use qubit_redact::LogOutputLimit;
use qubit_redact::domain::Redact;
use qubit_redact::domain::RedactionWriter;
/// Redacted value whose escaped representation exceeds the test budget.
struct LongUnsafeDiagnostic;

impl Redact for LongUnsafeDiagnostic {
    /// Writes a prefix, one control, and an overlong suffix.
    fn write_redacted(&self, writer: &mut RedactionWriter<'_, '_>) {
        writer.literal("ab\nremaining-long");
    }
}

/// Redacted value that writes a fixed diagnostic representation.
struct FixedDiagnostic(&'static str);

impl Redact for FixedDiagnostic {
    /// Writes the fixed representation exactly as supplied.
    fn write_redacted(&self, writer: &mut RedactionWriter<'_, '_>) {
        writer.literal(self.0);
    }
}

/// Verifies truncation preserves complete generated escape sequences.
#[test]
fn test_bounded_log_escape_writer_keeps_atomic_escape_boundary() {
    let limit = LogOutputLimit::builder()
        .max_bytes(14)
        .build()
        .expect("the test budget can contain the marker");
    let output = LongUnsafeDiagnostic.redacted().with_output_limit(limit).to_string();

    assert_eq!(output, "ab<truncated>");
}

/// Verifies the structured writer emits the supplied safe representation.
#[test]
fn test_bounded_log_escape_writer_emits_safe_representation() {
    let limit = LogOutputLimit::builder()
        .max_bytes(64)
        .build()
        .expect("the test budget can contain the marker");
    let output = FixedDiagnostic("<format-error>").redacted().with_output_limit(limit);
    assert_eq!(output.to_string(), "<format-error>");
}

/// Verifies complete and malformed pre-generated debug escapes are handled
/// without changing their text.
#[test]
fn test_bounded_log_escape_writer_parses_debug_escape_forms() {
    let input = r#"\\\"\n\r\t\0\x41\u{202e}\x4g\u{}\u{xyz}\u{12\"#;
    let limit = LogOutputLimit::builder()
        .max_bytes(128)
        .build()
        .expect("the test budget should contain every escape form");

    let output = FixedDiagnostic(input).redacted().with_output_limit(limit).to_string();

    assert_eq!(output, input);
}

/// Verifies an atomic pre-generated escape triggers truncation when the
/// complete escape cannot fit.
#[test]
fn test_bounded_log_escape_writer_truncates_before_atomic_escape() {
    let limit = LogOutputLimit::builder()
        .max_bytes(14)
        .build()
        .expect("the test budget can contain the marker");
    let output = FixedDiagnostic(r"abcdefghijk\x41")
        .redacted()
        .with_output_limit(limit)
        .to_string();

    assert_eq!(output, "abc<truncated>");
}
