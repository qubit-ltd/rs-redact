// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! URL discovery and replacement inside diagnostic text.

use url::Url;

use super::markers;

/// Replaces HTTP URL-looking tokens while preserving surrounding text.
///
/// # Parameters
///
/// * `text` - Diagnostic text that may contain absolute HTTP URLs.
/// * `redact_url` - Renderer for successfully parsed URLs.
///
/// # Returns
///
/// Text with recognized URLs replaced and invalid URL-looking tokens hidden.
pub(in crate::http) fn redact(
    text: &str,
    redact_url: impl Fn(&Url) -> String,
) -> String {
    let mut redacted = String::with_capacity(text.len());
    let mut token_start = None;
    for (index, character) in text.char_indices() {
        if character.is_whitespace() {
            if let Some(start) = token_start.take() {
                redact_token(&mut redacted, &text[start..index], &redact_url);
            }
            redacted.push(character);
        } else if token_start.is_none() {
            token_start = Some(index);
        }
    }
    if let Some(start) = token_start {
        redact_token(&mut redacted, &text[start..], &redact_url);
    }
    redacted
}

/// Replaces every HTTP URL-looking portion of one non-whitespace token.
///
/// # Parameters
///
/// * `output` - Destination for the redacted token.
/// * `token` - Non-whitespace token to inspect.
/// * `redact_url` - Renderer for successfully parsed URLs.
fn redact_token(
    output: &mut String,
    token: &str,
    redact_url: &impl Fn(&Url) -> String,
) {
    let mut cursor = 0;
    while let Some(relative_start) = find_url_scheme_start(&token[cursor..]) {
        let start = cursor + relative_start;
        output.push_str(&token[cursor..start]);

        let next_search_start = start + 1;
        let candidate_limit =
            find_url_scheme_start(&token[next_search_start..])
                .map_or(token.len(), |relative_start| {
                    next_search_start + relative_start
                });
        let end = url_candidate_end(&token[..candidate_limit], start);
        let candidate = &token[start..end];
        if let Ok(url) = Url::parse(candidate) {
            output.push_str(&redact_url(&url));
        } else {
            output.push_str(markers::INVALID_URL);
        }
        cursor = end;
    }
    output.push_str(&token[cursor..]);
}

/// Finds the first absolute HTTP URL scheme inside a token.
///
/// # Parameters
///
/// * `token` - Diagnostic token to inspect.
///
/// # Returns
///
/// The first scheme byte offset, or `None` when no HTTP scheme is present.
fn find_url_scheme_start(token: &str) -> Option<usize> {
    match (
        find_ascii_case_insensitive(token, "http://"),
        find_ascii_case_insensitive(token, "https://"),
    ) {
        (Some(http), Some(https)) => Some(http.min(https)),
        (Some(http), None) => Some(http),
        (None, Some(https)) => Some(https),
        (None, None) => None,
    }
}

/// Finds an ASCII substring without requiring matching case.
///
/// # Parameters
///
/// * `text` - Text to search.
/// * `needle` - Non-empty ASCII substring to find.
///
/// # Returns
///
/// The first byte offset, or `None` when no match exists.
fn find_ascii_case_insensitive(text: &str, needle: &str) -> Option<usize> {
    let needle = needle.as_bytes();
    if needle.is_empty() || text.len() < needle.len() {
        return None;
    }
    text.as_bytes()
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle))
}

/// Excludes punctuation commonly placed after a URL in prose.
///
/// # Parameters
///
/// * `token` - Non-whitespace token containing a URL-looking suffix.
/// * `start` - Byte offset of the detected URL scheme.
///
/// # Returns
///
/// The exclusive end of the URL candidate before trailing prose punctuation.
fn url_candidate_end(token: &str, start: usize) -> usize {
    let mut end = token.len();
    let mut unmatched_closers = unmatched_closer_counts(&token[start..]);
    while let Some((previous, character)) = previous_char_boundary(token, end) {
        if previous <= start
            || !is_trimmable_url_suffix(character, &mut unmatched_closers)
        {
            break;
        }
        end = previous;
    }
    end
}

/// Returns the previous UTF-8 boundary and character.
///
/// # Parameters
///
/// * `text` - Source UTF-8 text.
/// * `end` - Current character boundary.
///
/// # Returns
///
/// The preceding byte offset and character, or `None` at the start.
///
/// # Panics
///
/// Panics when `end` is out of bounds or not a character boundary.
#[inline(always)]
fn previous_char_boundary(text: &str, end: usize) -> Option<(usize, char)> {
    text[..end].char_indices().next_back()
}

/// Reports whether punctuation may be trimmed from the end of a URL token.
///
/// # Parameters
///
/// * `character` - Candidate trailing character.
/// * `unmatched_closers` - Remaining unmatched counts for parentheses,
///   brackets, and braces.
///
/// # Returns
///
/// `true` for punctuation commonly adjacent to URLs in prose.
#[inline(always)]
fn is_trimmable_url_suffix(
    character: char,
    unmatched_closers: &mut [usize; 3],
) -> bool {
    match character {
        ')' => take_unmatched_closer(&mut unmatched_closers[0]),
        ']' => take_unmatched_closer(&mut unmatched_closers[1]),
        '}' => take_unmatched_closer(&mut unmatched_closers[2]),
        '.' | ',' | ';' | ':' | '!' | '?' => true,
        _ => false,
    }
}

/// Counts unmatched closing parentheses, brackets, and braces in one pass.
///
/// # Parameters
///
/// * `candidate` - Complete URL candidate before suffix trimming.
///
/// # Returns
///
/// Excess closing counts for parentheses, brackets, and braces, respectively.
fn unmatched_closer_counts(candidate: &str) -> [usize; 3] {
    let mut openings = [0_usize; 3];
    let mut closings = [0_usize; 3];
    for character in candidate.chars() {
        match character {
            '(' => openings[0] += 1,
            ')' => closings[0] += 1,
            '[' => openings[1] += 1,
            ']' => closings[1] += 1,
            '{' => openings[2] += 1,
            '}' => closings[2] += 1,
            _ => {}
        }
    }
    [
        closings[0].saturating_sub(openings[0]),
        closings[1].saturating_sub(openings[1]),
        closings[2].saturating_sub(openings[2]),
    ]
}

/// Consumes one pre-counted unmatched closer when available.
///
/// # Parameters
///
/// * `count` - Remaining unmatched closers for one delimiter kind.
///
/// # Returns
///
/// `true` after consuming one closer, or `false` when none remain.
#[inline(always)]
fn take_unmatched_closer(count: &mut usize) -> bool {
    if *count == 0 {
        false
    } else {
        *count -= 1;
        true
    }
}
