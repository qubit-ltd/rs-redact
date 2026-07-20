// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Canonical field-name and semantic token-suffix generation.

use crate::policy::FieldNameMatching;

/// Canonicalizes `name` by trimming, lowercasing, and removing separators.
///
/// # Parameters
///
/// * `name` - Raw field name.
///
/// # Returns
///
/// The canonical field name used as a lookup key.
#[must_use]
pub(crate) fn canonicalize_field_name(name: &str) -> String {
    let name = name.trim();
    let mut canonical = String::with_capacity(name.len());
    canonical.extend(
        name.chars()
            .filter(|ch| !is_field_separator(*ch))
            .flat_map(char::to_lowercase),
    );
    canonical
}

/// Returns canonical candidates for `name`, ordered longest to shortest.
///
/// Exact matching yields only the complete canonical name. Token-suffix
/// matching additionally yields separator and camel-case suffixes without
/// duplicates.
///
/// # Parameters
///
/// * `name` - Raw field name.
/// * `matching` - Candidate breadth to generate.
///
/// # Returns
///
/// An owned iterator over canonical candidates.
pub(crate) fn canonical_field_candidates(
    name: &str,
    matching: FieldNameMatching,
) -> impl Iterator<Item = String> {
    let canonical = canonicalize_field_name(name);
    let mut candidates = vec![canonical.clone()];
    if matching == FieldNameMatching::ExactOrTokenSuffix {
        append_token_suffixes(name, &canonical, &mut candidates);
    }
    candidates.into_iter()
}

/// Appends semantic token suffixes of `name` to `candidates` without
/// duplicates.
///
/// # Parameters
///
/// * `name` - Raw field name whose boundaries are inspected.
/// * `canonical` - Complete canonical form of `name`.
/// * `candidates` - Destination that already contains the complete form.
fn append_token_suffixes(
    name: &str,
    canonical: &str,
    candidates: &mut Vec<String>,
) {
    let mut canonical_offset = 0;
    let mut previous = None;
    let mut in_token = false;
    let mut chars = name.trim().chars().peekable();

    while let Some(ch) = chars.next() {
        if is_field_separator(ch) {
            in_token = false;
            previous = Some(ch);
            continue;
        }
        if (!in_token
            || starts_camel_token(previous, ch, chars.peek().copied()))
            && canonical_offset > 0
        {
            let candidate = &canonical[canonical_offset..];
            if candidates.last().is_none_or(|last| last != candidate) {
                candidates.push(candidate.to_string());
            }
        }
        canonical_offset +=
            ch.to_lowercase().map(char::len_utf8).sum::<usize>();
        in_token = true;
        previous = Some(ch);
    }
}

/// Returns whether `ch` separates semantic field-name tokens.
///
/// # Parameters
///
/// * `ch` - Character to inspect.
///
/// # Returns
///
/// `true` when `ch` is a supported separator.
#[must_use]
#[inline]
fn is_field_separator(ch: char) -> bool {
    matches!(ch, '_' | '-' | '.' | '[' | ']') || ch.is_whitespace()
}

/// Returns whether `current` begins a camel-case token in its local context.
///
/// # Parameters
///
/// * `previous` - Previous character, when present.
/// * `current` - Character being inspected.
/// * `next` - Following character, when present.
///
/// # Returns
///
/// `true` at a supported camel-case or acronym boundary.
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
