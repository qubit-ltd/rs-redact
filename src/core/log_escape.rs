// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use std::borrow::Cow;

/// Escapes log-unsafe characters for insertion into untrusted log text.
///
/// Every character for which [`char::is_control`] returns `true`, every Unicode
/// line or paragraph separator, and every Unicode bidirectional formatting
/// control is replaced by its [`char::escape_debug`] representation. Other
/// text is preserved without surrounding quotes. Inputs without log-unsafe
/// characters are returned as a borrowed string and do not allocate.
///
/// This function only makes a value safe against log-structure and
/// bidirectional-control injection; it does not classify or mask secrets.
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
        .find(|(_, character)| is_log_unsafe_character(*character))
    else {
        return Cow::Borrowed(value);
    };

    let mut escaped = String::with_capacity(value.len());
    escaped.push_str(&value[..index]);
    escaped.extend(first_control.escape_debug());
    for character in value[index + first_control.len_utf8()..].chars() {
        if is_log_unsafe_character(character) {
            escaped.extend(character.escape_debug());
        } else {
            escaped.push(character);
        }
    }
    Cow::Owned(escaped)
}

/// Returns whether one character can alter log structure or visual ordering.
///
/// # Parameters
///
/// * `character` - Character to classify at a text log boundary.
///
/// # Returns
///
/// `true` for control characters, Unicode line and paragraph separators, and
/// Unicode bidirectional formatting controls; otherwise, `false`.
#[must_use]
#[inline]
fn is_log_unsafe_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}
