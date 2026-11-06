// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Strict HTTP header-parameter parsing.

use std::collections::BTreeSet;

use self::segment_cursor::SegmentCursor;

// Implements borrowed traversal with quote and escape tracking.
mod segment_cursor;

/// Parses several named parameters in one strict pass.
///
/// # Type Parameters
///
/// * `N` - Number of parameter names requested and result slots returned.
///
/// # Parameters
///
/// * `value` - Header text containing semicolon parameters.
/// * `names` - Parameter names to find case-insensitively.
///
/// # Returns
///
/// `Some` contains one slot per requested name: `Some(value)` for a matched
/// parameter and `None` for an absent name. The outer `None` indicates
/// malformed syntax or a duplicate parameter name.
#[must_use]
pub(super) fn parse_parameters<const N: usize>(value: &str, names: [&str; N]) -> Option<[Option<String>; N]> {
    if value.bytes().any(is_forbidden_header_byte) {
        return None;
    }
    let mut segments = SegmentCursor::new(value);
    let _ = segments.next_segment().ok()??;
    let mut result = std::array::from_fn(|_| None);
    let mut seen = BTreeSet::new();
    while let Some(segment) = segments.next_segment().ok()? {
        let (name, raw) = segment.split_once('=')?;
        let name = trim_ows(name);
        if name.is_empty() || !name.bytes().all(is_token_byte) {
            return None;
        }
        let canonical_name = name.to_ascii_lowercase();
        if !seen.insert(canonical_name) {
            return None;
        }
        let index = names.iter().position(|wanted| name.eq_ignore_ascii_case(wanted));
        let mut decoded = String::new();
        validate_and_decode(trim_ows(raw), index.map(|_| &mut decoded))?;
        if let Some(index) = index {
            result[index] = Some(decoded);
        }
    }
    Some(result)
}

/// Returns the validated leading token before any parameters.
///
/// # Parameters
///
/// * `value` - Header field value whose first segment must be a token.
///
/// # Returns
///
/// The non-empty leading token, or `None` when controls, quoting, or token
/// grammar are invalid.
#[must_use]
pub(super) fn leading_token(value: &str) -> Option<&str> {
    if value.bytes().any(is_forbidden_header_byte) {
        return None;
    }
    let mut segments = SegmentCursor::new(value);
    let leading = segments.next_segment().ok()??;
    while segments.next_segment().ok()?.is_some() {}
    (!leading.is_empty() && leading.bytes().all(is_token_byte)).then_some(leading)
}

/// Returns the validated first segment before any parameters.
///
/// # Parameters
///
/// * `value` - Header field value to inspect.
///
/// # Returns
///
/// The OWS-trimmed leading segment, or `None` when controls or quoting are
/// malformed.
#[must_use]
pub(super) fn leading_value(value: &str) -> Option<&str> {
    if value.bytes().any(is_forbidden_header_byte) {
        return None;
    }
    let mut segments = SegmentCursor::new(value);
    let leading = segments.next_segment().ok()??;
    while segments.next_segment().ok()?.is_some() {}
    Some(leading)
}

/// Validates a parameter value and optionally decodes it into an output sink.
///
/// # Parameters
///
/// * `value` - Raw parameter value.
/// * `output` - Optional destination for a decoded value. When absent, syntax
///   is checked without constructing a decoded string.
///
/// # Returns
///
/// `Some(())` when the value is valid, or `None` for malformed syntax.
#[must_use]
fn validate_and_decode(value: &str, mut output: Option<&mut String>) -> Option<()> {
    if !value.starts_with('"') {
        if value.is_empty() || !value.bytes().all(is_token_byte) {
            return None;
        }
        if let Some(output) = output {
            output.push_str(value);
        }
        return Some(());
    }
    let mut chars = value[1..].char_indices();
    while let Some(character) = chars.next() {
        let (index, character) = character;
        if character == '"' {
            return trim_ows(&value[index + 2..]).is_empty().then_some(());
        }
        if character == '\\' {
            let (_, escaped) = chars.next()?;
            if !is_quoted_pair_character(escaped) {
                return None;
            }
            if let Some(output) = output.as_deref_mut() {
                output.push(escaped);
            }
        } else if is_qdtext_character(character) {
            if let Some(output) = output.as_deref_mut() {
                output.push(character);
            }
        } else {
            return None;
        }
    }
    None
}

/// Trims HTTP optional whitespace from both ends.
///
/// # Parameters
///
/// * `value` - Text that may have surrounding space or horizontal tabs.
///
/// # Returns
///
/// The subslice without leading or trailing OWS.
#[must_use]
#[inline(always)]
fn trim_ows(value: &str) -> &str {
    value.trim_matches([' ', '\t'])
}

/// Reports whether a byte is forbidden anywhere in a header value.
///
/// # Parameters
///
/// * `byte` - Candidate byte.
///
/// # Returns
///
/// `true` for C0 controls other than horizontal tab, or DEL.
#[must_use]
#[inline]
const fn is_forbidden_header_byte(byte: u8) -> bool {
    matches!(byte, 0x00..=0x08 | 0x0a..=0x1f | 0x7f)
}

/// Reports whether a byte belongs to the HTTP `token` alphabet.
///
/// # Parameters
///
/// * `byte` - Candidate byte.
///
/// # Returns
///
/// `true` for an RFC tchar byte.
#[must_use]
#[inline]
pub(super) const fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        )
}

/// Reports whether a character is legal unescaped quoted-string text.
///
/// # Parameters
///
/// * `character` - Candidate decoded character.
///
/// # Returns
///
/// `true` for HTAB, SP, visible qdtext except backslash and quote, or obs-text.
#[must_use]
#[inline]
const fn is_qdtext_character(character: char) -> bool {
    matches!(character, '\t' | ' ' | '!' | '#'..='[' | ']'..='~') || !character.is_ascii()
}

/// Reports whether a character is legal after a quoted-pair backslash.
///
/// # Parameters
///
/// * `character` - Escaped candidate character.
///
/// # Returns
///
/// `true` for HTAB, SP, visible ASCII, or obs-text.
#[must_use]
#[inline]
const fn is_quoted_pair_character(character: char) -> bool {
    matches!(character, '\t' | ' '..='~') || !character.is_ascii()
}
