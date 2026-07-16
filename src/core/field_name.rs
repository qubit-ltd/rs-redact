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

/// Returns canonical suffixes that start at semantic field-name boundaries.
///
/// Boundaries include common separators, camel-case transitions, and the
/// transition from an uppercase acronym to a capitalized word. The returned
/// suffixes are ordered from shortest to longest.
///
/// # Parameters
///
/// * `name` - Raw field name.
///
/// # Returns
///
/// Canonical token suffixes eligible for contextual sensitivity matching.
#[must_use]
pub(crate) fn canonicalize_field_name_suffixes(name: &str) -> Vec<String> {
    let chars = name.trim().chars().collect::<Vec<_>>();
    let mut tokens = Vec::<String>::new();
    let mut token = String::new();

    for (index, ch) in chars.iter().copied().enumerate() {
        if is_field_separator(ch) {
            push_token(&mut tokens, &mut token);
            continue;
        }
        let previous = index
            .checked_sub(1)
            .and_then(|previous| chars.get(previous))
            .copied();
        let next = chars.get(index + 1).copied();
        if !token.is_empty() && starts_camel_token(previous, ch, next) {
            push_token(&mut tokens, &mut token);
        }
        token.extend(ch.to_lowercase());
    }
    push_token(&mut tokens, &mut token);

    let mut suffixes = Vec::with_capacity(tokens.len());
    let mut suffix = String::new();
    for token in tokens.into_iter().rev() {
        suffix.insert_str(0, &token);
        suffixes.push(suffix.clone());
    }
    suffixes
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

/// Moves a non-empty token into the token list.
///
/// # Parameters
///
/// * `tokens` - Completed canonical tokens.
/// * `token` - Current token buffer, cleared after insertion.
#[inline]
fn push_token(tokens: &mut Vec<String>, token: &mut String) {
    if !token.is_empty() {
        tokens.push(std::mem::take(token));
    }
}
