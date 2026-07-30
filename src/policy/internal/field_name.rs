// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Canonical field-name and semantic token-suffix generation.

use std::{
    borrow::Cow,
    ops::ControlFlow,
};

use crate::policy::FieldNameMatching;

/// Canonicalizes `name` by trimming, lowercasing, and removing separators.
///
/// # Parameters
///
/// * `name` - Raw field name.
///
/// # Returns
///
/// The borrowed field name when it is already canonical, otherwise an owned
/// canonical lookup key.
#[must_use]
pub(crate) fn canonicalize_field_name(name: &str) -> Cow<'_, str> {
    let name = name.trim();
    let already_canonical = name.chars().all(|ch| {
        if is_field_separator(ch) {
            return false;
        }
        let mut lowercase = ch.to_lowercase();
        lowercase.next() == Some(ch) && lowercase.next().is_none()
    });
    if already_canonical {
        return Cow::Borrowed(name);
    }
    let mut canonical = String::with_capacity(name.len());
    canonical.extend(
        name.chars()
            .filter(|ch| !is_field_separator(*ch))
            .flat_map(char::to_lowercase),
    );
    Cow::Owned(canonical)
}

/// Visits canonical candidates for `name`, ordered longest to shortest.
///
/// Exact matching yields only the complete canonical name. Token-suffix
/// matching additionally yields separator and camel-case suffixes without
/// duplicates.
///
/// # Type Parameters
///
/// * `B` - Value carried when the visitor stops candidate generation.
///
/// # Parameters
///
/// * `name` - Raw field name.
/// * `matching` - Candidate breadth to generate.
///
/// # Returns
///
/// `Break(value)` from the first visitor call that stops classification, or
/// `Continue(())` after every candidate has been visited.
pub(crate) fn visit_canonical_field_candidates<B>(
    name: &str,
    matching: FieldNameMatching,
    mut visitor: impl FnMut(bool, &str) -> ControlFlow<B>,
) -> ControlFlow<B> {
    let canonical = canonicalize_field_name(name);
    visitor(true, &canonical)?;
    if matching == FieldNameMatching::ExactOrTokenSuffix {
        visit_token_suffixes(name, &canonical, &mut visitor)?;
    }
    ControlFlow::Continue(())
}

/// Visits semantic token suffixes of `name` without allocating candidates.
///
/// # Type Parameters
///
/// * `B` - Value carried when the visitor stops suffix generation.
///
/// # Parameters
///
/// * `name` - Raw field name whose boundaries are inspected.
/// * `canonical` - Complete canonical form of `name`.
/// * `visitor` - Callback receiving suffix candidates in longest-first order.
///
/// # Returns
///
/// `Break(value)` when the visitor stops classification, otherwise
/// `Continue(())` after all suffixes have been visited.
fn visit_token_suffixes<B>(
    name: &str,
    canonical: &str,
    visitor: &mut impl FnMut(bool, &str) -> ControlFlow<B>,
) -> ControlFlow<B> {
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
            visitor(false, candidate)?;
        }
        canonical_offset +=
            ch.to_lowercase().map(char::len_utf8).sum::<usize>();
        in_token = true;
        previous = Some(ch);
    }
    ControlFlow::Continue(())
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
