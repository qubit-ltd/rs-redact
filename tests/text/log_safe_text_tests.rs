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
        .redact("message", "line\nnext")
        .escape_for_log();

    assert_eq!(escaped.to_string(), r"line\nnext");
}
