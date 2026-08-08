// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for log-control escaping used by redacted text.

use qubit_redact::Redactor;
/// Verifies a newline is escaped before a redacted value reaches a text log.
#[test]
fn test_log_escape_escapes_newline() {
    let escaped = Redactor::default()
        .redact_field("message", "first\nsecond")
        .escape_for_log();

    assert_eq!(escaped.as_ref(), r"first\nsecond");
}
