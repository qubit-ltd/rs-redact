// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Internal escaping for typed log-safe text.

use std::borrow::Cow;

/// Escapes characters that can alter log structure or visual ordering.
///
/// # Parameters
///
/// * `value` - Redacted text crossing a plain-text log boundary.
///
/// # Returns
///
/// The original `Cow` when every character is safe, preserving either its
/// borrowed or owned form; otherwise, a newly allocated escaped string.
#[must_use = "use the escaped value at the log boundary"]
pub(super) fn escape_log_control_characters<'a>(
    value: Cow<'a, str>,
) -> Cow<'a, str> {
    let Some((index, first_unsafe)) = value
        .char_indices()
        .find(|(_, character)| is_log_unsafe_character(*character))
    else {
        return value;
    };

    let mut escaped = String::with_capacity(value.len());
    escaped.push_str(&value[..index]);
    escaped.extend(first_unsafe.escape_debug());
    for character in value[index + first_unsafe.len_utf8()..].chars() {
        if is_log_unsafe_character(character) {
            escaped.extend(character.escape_debug());
        } else {
            escaped.push(character);
        }
    }
    Cow::Owned(escaped)
}

/// Reports whether a character can alter log structure or visual ordering.
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
