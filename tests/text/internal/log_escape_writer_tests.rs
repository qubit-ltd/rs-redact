// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Public-contract tests for the internal streaming escape writer.

use std::fmt;
use std::fmt::Write;

use qubit_redact::Redact;
use qubit_redact::RedactionSession;
/// Redacted value that emits log-unsafe controls.
struct UnsafeDiagnostic;

impl Redact for UnsafeDiagnostic {
    fn redaction_input_bytes(&self) -> usize {
        "line one\nline two\u{202e}".len()
    }

    /// Writes representative log-unsafe controls.
    fn fmt_redacted(
        &self,
        _session: &mut RedactionSession<'_>,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        formatter.write_str("line one\nline two\u{202e}")
    }
}

/// Redacted value whose first character requires escaping.
struct ControlFirstDiagnostic;

impl Redact for ControlFirstDiagnostic {
    fn redaction_input_bytes(&self) -> usize {
        "\nremaining".len()
    }

    /// Writes a control before any ordinary character.
    fn fmt_redacted(
        &self,
        _session: &mut RedactionSession<'_>,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        formatter.write_str("\nremaining")
    }
}

/// Redacted value containing only an ordinary character.
struct SafeDiagnostic;

impl Redact for SafeDiagnostic {
    fn redaction_input_bytes(&self) -> usize {
        1
    }

    /// Writes one ordinary character.
    fn fmt_redacted(
        &self,
        _session: &mut RedactionSession<'_>,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        formatter.write_str("a")
    }
}

/// Formatting destination that rejects every write.
struct FailingWriter;

impl Write for FailingWriter {
    /// Rejects the supplied text.
    fn write_str(&mut self, _value: &str) -> fmt::Result {
        Err(fmt::Error)
    }
}

/// Verifies domain display streams escaped log-safe output.
#[test]
fn test_log_escape_writer_escapes_streamed_controls() {
    let output = UnsafeDiagnostic.redacted().to_string();

    assert_eq!(output, "line one\\nline two\\u{202e}");
}

/// Verifies destination failures propagate for ordinary and escaped text.
#[test]
fn test_log_escape_writer_propagates_destination_failure() {
    let mut output = FailingWriter;
    let safe_result = write!(&mut output, "{}", SafeDiagnostic.redacted());
    let escaped_result = write!(&mut output, "{}", ControlFirstDiagnostic.redacted());

    assert_eq!(safe_result, Err(fmt::Error));
    assert_eq!(escaped_result, Err(fmt::Error));
}
