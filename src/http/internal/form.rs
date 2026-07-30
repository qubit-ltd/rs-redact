// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Strict URL-encoded form parsing.

use form_urlencoded::byte_serialize;

use crate::Redactor;

/// Reports whether every form component decodes unambiguously as UTF-8.
///
/// # Parameters
///
/// * `input` - URL-encoded form bytes.
///
/// # Returns
///
/// `true` only when all names and values decode unambiguously.
#[must_use]
pub(in crate::http) fn is_valid(input: &[u8]) -> bool {
    input.split(|byte| *byte == b'&').all(|pair| {
        let (name, value) = pair
            .iter()
            .position(|byte| *byte == b'=')
            .map_or((pair, &[][..]), |index| {
                (&pair[..index], &pair[index + 1..])
            });
        is_valid_component(name) && is_valid_component(value)
    })
}

/// Redacts a validated form under one aggregate intermediate byte budget.
///
/// # Parameters
///
/// * `redactor` - Field policy executor.
/// * `input` - Previously validated URL-encoded bytes.
/// * `max_output_bytes` - Maximum final output bytes before the caller adds a
///   truncation marker.
///
/// # Returns
///
/// A URL-encoded representation capped at one byte beyond the final budget so
/// the caller can detect and mark truncation.
#[must_use]
pub(in crate::http) fn redact_bounded(
    redactor: &Redactor,
    input: &[u8],
    max_output_bytes: usize,
) -> String {
    let intermediate_limit = max_output_bytes.saturating_add(1);
    let mut output = String::new();
    for (key, value) in form_urlencoded::parse(input) {
        let remaining = intermediate_limit.saturating_sub(output.len());
        let value =
            redactor.redact_bounded(key.as_ref(), value.as_ref(), remaining);
        if !append_pair_bounded(
            &mut output,
            key.as_ref(),
            value.as_str(),
            intermediate_limit,
        ) {
            break;
        }
    }
    output
}

/// Appends one URL-encoded pair under an aggregate byte limit.
///
/// # Parameters
///
/// * `output` - Aggregate URL-encoded destination.
/// * `key` - Decoded field name.
/// * `value` - Decoded redacted field value.
/// * `limit` - Maximum retained intermediate bytes.
///
/// # Returns
///
/// `true` when the complete pair fits, otherwise `false` after recording
/// bounded overflow.
pub(in crate::http) fn append_pair_bounded(
    output: &mut String,
    key: &str,
    value: &str,
    limit: usize,
) -> bool {
    if !output.is_empty() && !append_bounded_piece(output, "&", limit) {
        return false;
    }
    if !append_encoded_bounded(output, key.as_bytes(), limit)
        || !append_bounded_piece(output, "=", limit)
        || !append_encoded_bounded(output, value.as_bytes(), limit)
    {
        return false;
    }
    true
}

/// Appends URL-encoded bytes without exceeding an intermediate limit.
///
/// # Parameters
///
/// * `output` - Aggregate URL-encoded destination.
/// * `value` - Decoded component bytes to encode.
/// * `limit` - Maximum retained intermediate bytes.
///
/// # Returns
///
/// `true` when the complete component fits, otherwise `false` after filling
/// the remaining budget with a safe truncation sentinel.
fn append_encoded_bounded(
    output: &mut String,
    value: &[u8],
    limit: usize,
) -> bool {
    for piece in byte_serialize(value) {
        if !append_bounded_piece(output, piece, limit) {
            return false;
        }
    }
    true
}

/// Appends one URL-encoded piece or records one-byte budget overflow.
///
/// # Parameters
///
/// * `output` - Aggregate URL-encoded destination.
/// * `piece` - Complete ASCII separator or encoded byte sequence.
/// * `limit` - Maximum retained intermediate bytes.
///
/// # Returns
///
/// `true` when `piece` fits completely, otherwise `false`.
fn append_bounded_piece(
    output: &mut String,
    piece: &str,
    limit: usize,
) -> bool {
    if piece.len() <= limit.saturating_sub(output.len()) {
        output.push_str(piece);
        return true;
    }
    output.extend(std::iter::repeat_n('x', limit.saturating_sub(output.len())));
    false
}

/// Validates one encoded component and its decoded UTF-8 representation.
///
/// # Parameters
///
/// * `component` - One encoded name or value.
///
/// # Returns
///
/// `true` when percent escapes and decoded UTF-8 are valid.
#[must_use]
fn is_valid_component(component: &[u8]) -> bool {
    let mut decoded = Vec::with_capacity(component.len());
    let mut index = 0;
    while index < component.len() {
        match component[index] {
            b'%' => {
                let Some(high) = component.get(index + 1).and_then(|b| hex(*b))
                else {
                    return false;
                };
                let Some(low) = component.get(index + 2).and_then(|b| hex(*b))
                else {
                    return false;
                };
                decoded.push((high << 4) | low);
                index += 3;
            }
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    std::str::from_utf8(&decoded).is_ok()
}

/// Decodes one ASCII hexadecimal digit.
///
/// # Parameters
///
/// * `byte` - Candidate ASCII hexadecimal byte.
///
/// # Returns
///
/// Its numeric value, or `None` for another byte.
#[must_use]
#[inline]
const fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
