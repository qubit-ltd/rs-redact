// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Strict URL-encoded form parsing.

use form_urlencoded::Serializer;

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

/// Redacts a previously validated form while preserving order and duplicates.
///
/// # Parameters
///
/// * `redactor` - Field policy executor.
/// * `input` - Previously validated URL-encoded bytes.
///
/// # Returns
///
/// A URL-encoded representation with sensitive values replaced.
#[must_use]
pub(in crate::http) fn redact(redactor: &Redactor, input: &[u8]) -> String {
    let mut serializer = Serializer::new(String::new());
    for (key, value) in form_urlencoded::parse(input) {
        let value = redactor.redact(key.as_ref(), value.as_ref());
        serializer.append_pair(key.as_ref(), value.as_str());
    }
    serializer.finish()
}

/// Redacts a validated form while bounding each generated mask.
///
/// # Parameters
///
/// * `redactor` - Field policy executor.
/// * `input` - Previously validated URL-encoded bytes.
/// * `max_mask_bytes` - Maximum bytes allocated for one generated mask.
///
/// # Returns
///
/// A URL-encoded representation with bounded sensitive replacements.
#[must_use]
pub(in crate::http) fn redact_bounded(
    redactor: &Redactor,
    input: &[u8],
    max_mask_bytes: usize,
) -> String {
    let mut serializer = Serializer::new(String::new());
    for (key, value) in form_urlencoded::parse(input) {
        let value = redactor.redact_bounded(
            key.as_ref(),
            value.as_ref(),
            max_mask_bytes,
        );
        serializer.append_pair(key.as_ref(), value.as_str());
    }
    serializer.finish()
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
