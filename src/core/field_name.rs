// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
/// Canonicalizes a field name for sensitivity matching.
///
/// The canonical form trims the name, lowercases it, and removes common word
/// separators. This makes names like `access_token`, `access-token`,
/// `access.token`, `access Token`, and `accessToken` match the same entry.
///
/// # Parameters
///
/// * `name` - Raw field name.
///
/// # Returns
///
/// Canonical field name used as the lookup key.
#[must_use]
pub fn canonicalize_field_name(name: &str) -> String {
    name.trim()
        .chars()
        .filter(|ch| !is_field_separator(*ch))
        .flat_map(char::to_lowercase)
        .collect()
}

/// Canonicalizes a field name and records semantic token starts.
///
/// Boundaries include common separators, camel-case transitions, and the
/// transition from an uppercase acronym to a capitalized word. Each returned
/// byte offset is a valid start of a canonical suffix, ordered from the full
/// canonical name to its shortest token suffix.
///
/// # Parameters
///
/// * `name` - Raw field name.
///
/// # Returns
///
/// The canonical field name and byte offsets of eligible suffix starts.
#[must_use]
pub(crate) fn canonicalize_field_name_with_token_starts(
    name: &str,
) -> (String, Vec<usize>) {
    let mut canonical = String::new();
    let mut token_starts = Vec::new();
    let mut previous = None;
    let mut in_token = false;
    let mut chars = name.trim().chars().peekable();

    while let Some(ch) = chars.next() {
        if is_field_separator(ch) {
            in_token = false;
            previous = Some(ch);
            continue;
        }
        if !in_token || starts_camel_token(previous, ch, chars.peek().copied())
        {
            token_starts.push(canonical.len());
        }
        canonical.extend(ch.to_lowercase());
        in_token = true;
        previous = Some(ch);
    }

    (canonical, token_starts)
}

/// Returns whether a character separates field-name tokens.
///
/// # Parameters
///
/// * `ch` - Character to inspect.
///
/// # Returns
///
/// `true` for a supported punctuation separator or Unicode whitespace.
#[must_use]
#[inline]
fn is_field_separator(ch: char) -> bool {
    matches!(ch, '_' | '-' | '.' | '[' | ']') || ch.is_whitespace()
}

/// Returns whether a character starts a new camel-case token.
///
/// # Parameters
///
/// * `previous` - Previous field-name character, when present.
/// * `current` - Current field-name character.
/// * `next` - Next field-name character, when present.
///
/// # Returns
///
/// `true` at lower-or-number to uppercase transitions and before the final
/// uppercase character of an acronym followed by a lowercase word tail.
#[must_use]
#[inline]
fn starts_camel_token(
    previous: Option<char>,
    current: char,
    next: Option<char>,
) -> bool {
    if !current.is_uppercase() {
        return false;
    }
    let follows_lower_or_number = previous.is_some_and(|previous| {
        previous.is_lowercase() || previous.is_numeric()
    });
    let starts_word_after_acronym = previous.is_some_and(char::is_uppercase)
        && next.is_some_and(char::is_lowercase);
    follows_lower_or_number || starts_word_after_acronym
}
