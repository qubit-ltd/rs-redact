// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Integration tests for typed redacted and log-safe text.

use qubit_redact::Redactor;

/// Verifies that log escaping covers controls, separators, and every Unicode
/// bidirectional formatting control.
#[test]
fn test_escape_for_log_escapes_controls_and_bidi() {
    let input = "a\n\r\t\u{1b}\u{7f}\u{0085}\u{61c}\u{200e}\u{200f}\u{2028}\u{2029}\u{202a}\u{202b}\u{202c}\u{202d}\u{202e}\u{2066}\u{2067}\u{2068}\u{2069}b";
    let expected = r"a\n\r\t\u{1b}\u{7f}\u{85}\u{61c}\u{200e}\u{200f}\u{2028}\u{2029}\u{202a}\u{202b}\u{202c}\u{202d}\u{202e}\u{2066}\u{2067}\u{2068}\u{2069}b";
    let text = Redactor::default().redact("message", input);
    let safe = text.escape_for_log();

    assert_eq!(safe.as_ref(), expected);
    assert_eq!(safe.to_string(), safe.as_ref());
}

/// Verifies that safe text remains borrowed after crossing the log boundary.
#[test]
fn test_escape_for_log_keeps_safe_text_borrowed() {
    let input = String::from("plain text");
    let safe = Redactor::default()
        .redact("message", &input)
        .escape_for_log();

    assert!(std::ptr::eq(safe.as_ref(), input.as_str()));
}
