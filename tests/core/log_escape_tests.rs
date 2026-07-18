// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`escape_log_control_characters`](qubit_sanitize::escape_log_control_characters).

use std::borrow::Cow;

use qubit_sanitize::escape_log_control_characters;

#[test]
fn test_escape_log_control_characters_keeps_safe_text_borrowed() {
    let value = "safe UTF-8 text: 你好";

    assert_eq!(escape_log_control_characters(value), Cow::Borrowed(value));
}

#[test]
fn test_escape_log_control_characters_uses_debug_escapes_without_quotes() {
    let value = "first\nsecond\r\t\u{1b}\u{7f}";

    assert_eq!(
        escape_log_control_characters(value),
        Cow::<str>::Owned(r"first\nsecond\r\t\u{1b}\u{7f}".to_string()),
    );
}
