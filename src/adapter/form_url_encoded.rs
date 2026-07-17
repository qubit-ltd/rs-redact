// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared URL-encoded form sanitization helpers.

use form_urlencoded::Serializer;

use crate::{
    FieldSanitizer,
    NameMatchMode,
};

/// Returns whether URL-encoded form bytes use valid percent escapes and decode
/// to UTF-8 field names and values.
///
/// # Parameters
///
/// * `form` - URL-encoded form bytes to validate.
///
/// # Returns
///
/// `true` when every field component is unambiguously decodable.
#[must_use]
pub(crate) fn is_valid_form_urlencoded(form: &[u8]) -> bool {
    form.split(|byte| *byte == b'&').all(|pair| {
        let (name, value) = pair
            .iter()
            .position(|byte| *byte == b'=')
            .map_or((pair, &[][..]), |index| {
                (&pair[..index], &pair[index + 1..])
            });
        is_valid_component(name) && is_valid_component(value)
    })
}

/// Returns whether one URL-encoded component has valid escapes and UTF-8.
#[must_use]
fn is_valid_component(component: &[u8]) -> bool {
    let mut decoded = Vec::with_capacity(component.len());
    let mut index = 0;
    while index < component.len() {
        match component[index] {
            b'%' => {
                let Some(high) =
                    component.get(index + 1).and_then(|byte| hex_value(*byte))
                else {
                    return false;
                };
                let Some(low) =
                    component.get(index + 2).and_then(|byte| hex_value(*byte))
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

/// Converts one ASCII hexadecimal digit to its numeric value.
#[must_use]
#[inline]
const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Sanitizes URL-encoded form bytes with a field sanitizer.
///
/// Field order and duplicate keys are preserved. Malformed percent escapes or
/// percent-decoded non-UTF-8 cause the whole form to be replaced by a fixed
/// redaction marker.
///
/// # Parameters
///
/// * `field_sanitizer` - Core sanitizer used for form field values.
/// * `form` - URL-encoded form bytes.
/// * `match_mode` - Field-name matching mode for form keys.
///
/// # Returns
///
/// Sanitized URL-encoded form text, or a fixed redaction marker when decoding
/// is invalid or ambiguous.
#[must_use = "use the returned sanitized form instead of the original form"]
pub(crate) fn sanitize_form_urlencoded(
    field_sanitizer: &FieldSanitizer,
    form: &[u8],
    match_mode: NameMatchMode,
) -> String {
    if !is_valid_form_urlencoded(form) {
        return "<redacted: invalid URL-encoded form>".to_string();
    }
    let mut serializer = Serializer::new(String::new());
    for (key, value) in form_urlencoded::parse(form) {
        let sanitized_value = field_sanitizer.sanitize_value(
            key.as_ref(),
            value.as_ref(),
            match_mode,
        );
        serializer.append_pair(key.as_ref(), sanitized_value.as_ref());
    }
    serializer.finish()
}
