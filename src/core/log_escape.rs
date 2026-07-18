// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use std::borrow::Cow;

/// Escapes control characters for insertion into untrusted log text.
///
/// Every character for which [`char::is_control`] returns `true` is replaced
/// by its [`char::escape_debug`] representation. Printable text is preserved
/// without surrounding quotes. Inputs without control characters are returned
/// as a borrowed string and do not allocate.
///
/// This function only makes a value safe against control-character injection;
/// it does not classify or mask secrets.
///
/// # Parameters
///
/// * `value` - Text to escape at a log boundary.
///
/// # Returns
///
/// Borrowed `value` when no escaping is needed, otherwise an owned escaped
/// string.
#[must_use = "use the escaped value at the log boundary"]
pub fn escape_log_control_characters(value: &str) -> Cow<'_, str> {
    let Some((index, first_control)) = value
        .char_indices()
        .find(|(_, character)| character.is_control())
    else {
        return Cow::Borrowed(value);
    };

    let mut escaped = String::with_capacity(value.len());
    escaped.push_str(&value[..index]);
    escaped.extend(first_control.escape_debug());
    for character in value[index + first_control.len_utf8()..].chars() {
        if character.is_control() {
            escaped.extend(character.escape_debug());
        } else {
            escaped.push(character);
        }
    }
    Cow::Owned(escaped)
}
