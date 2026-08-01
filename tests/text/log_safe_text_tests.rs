// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`LogSafeText`](qubit_redact::LogSafeText).

use qubit_redact::Redactor;

/// Verifies log-safe text displays its already escaped contents.
#[test]
fn test_log_safe_text_displays_escaped_contents() {
    let escaped = Redactor::default()
        .redact_field("message", "line\nnext")
        .escape_for_log();

    assert_eq!(escaped.to_string(), r"line\nnext");
}

/// Verifies callers can borrow escaped log-safe text without formatting it.
#[test]
fn test_log_safe_text_as_str_borrows_escaped_contents() {
    let escaped = Redactor::default()
        .redact_field("message", "line\nnext")
        .escape_for_log();

    assert_eq!(escaped.as_str(), r"line\nnext");
}

/// Verifies callers can take ownership of an owned escaped buffer.
#[test]
fn test_log_safe_text_into_owned_returns_escaped_contents() {
    let escaped = Redactor::default()
        .redact_field("message", "line\nnext")
        .escape_for_log();

    assert_eq!(escaped.into_owned(), r"line\nnext");
}
