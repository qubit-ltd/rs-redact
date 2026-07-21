// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Bounded recognition of complete HTTP URLs embedded in field values.

use std::borrow::Cow;

use url::Url;

/// Maximum percent-decoding layers inspected for a nested URL.
const MAX_PERCENT_DECODING_DEPTH: usize = 8;

/// Result of inspecting a complete field value for an embedded HTTP URL.
pub(in crate::http) enum NestedUrl {
    /// The complete value is not an HTTP URL.
    NotUrl,
    /// The complete value is a valid HTTP URL.
    Parsed(
        /// Parsed absolute HTTP URL.
        Url,
    ),
    /// The value starts like an HTTP URL but does not parse.
    Invalid,
    /// Recognition reached the percent-decoding work limit.
    LimitExceeded,
}

/// Recognizes a complete HTTP URL through bounded percent-decoding layers.
///
/// # Parameters
///
/// * `value` - Complete decoded field value to inspect.
///
/// # Returns
///
/// A parsed HTTP URL, a fail-closed condition, or `NotUrl` when the complete
/// value has no nested-URL shape.
pub(in crate::http) fn detect(value: &str) -> NestedUrl {
    let mut candidate = Cow::Borrowed(value);
    let mut malformed = false;
    for depth in 0..=MAX_PERCENT_DECODING_DEPTH {
        if let Ok(url) = Url::parse(candidate.as_ref()) {
            return if matches!(url.scheme(), "http" | "https") {
                if malformed {
                    NestedUrl::Invalid
                } else {
                    NestedUrl::Parsed(url)
                }
            } else {
                NestedUrl::NotUrl
            };
        }
        if starts_with_http_scheme(candidate.as_ref()) {
            return NestedUrl::Invalid;
        }
        if malformed && starts_with_http_name(candidate.as_ref()) {
            return NestedUrl::Invalid;
        }
        if depth == MAX_PERCENT_DECODING_DEPTH {
            return if candidate.as_bytes().contains(&b'%') {
                NestedUrl::LimitExceeded
            } else {
                NestedUrl::NotUrl
            };
        }

        let decoded = match percent_decode_once(candidate.as_ref()) {
            Ok(Some(decoded)) => decoded,
            Ok(None) => return NestedUrl::NotUrl,
            Err(prefix) => {
                if prefix.is_empty() {
                    return NestedUrl::NotUrl;
                }
                malformed = true;
                prefix
            }
        };
        candidate = Cow::Owned(decoded);
    }
    NestedUrl::LimitExceeded
}

/// Reports whether a partial candidate has established the HTTP scheme name.
fn starts_with_http_name(value: &str) -> bool {
    value
        .as_bytes()
        .get(..b"http".len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"http"))
}

/// Reports whether `value` starts with an absolute HTTP URL scheme.
fn starts_with_http_scheme(value: &str) -> bool {
    [b"http://".as_slice(), b"https://".as_slice()]
        .into_iter()
        .any(|scheme| {
            value
                .as_bytes()
                .get(..scheme.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(scheme))
        })
}

/// Decodes one strict percent-encoding layer without applying form `+` rules.
///
/// # Parameters
///
/// * `value` - UTF-8 text that may contain percent escapes.
///
/// # Returns
///
/// `Ok(Some(value))` for decoded UTF-8 text, `Ok(None)` when unchanged, or the
/// valid decoded prefix in `Err` when an escape or UTF-8 sequence is malformed.
fn percent_decode_once(value: &str) -> Result<Option<String>, String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    let mut changed = false;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let Some(high) = bytes.get(index + 1).and_then(|byte| hex(*byte))
            else {
                return Err(valid_utf8_prefix(decoded));
            };
            let Some(low) = bytes.get(index + 2).and_then(|byte| hex(*byte))
            else {
                return Err(valid_utf8_prefix(decoded));
            };
            decoded.push((high << 4) | low);
            index += 3;
            changed = true;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    if changed {
        String::from_utf8(decoded).map(Some).map_err(|error| {
            let valid_up_to = error.utf8_error().valid_up_to();
            String::from_utf8_lossy(&error.into_bytes()[..valid_up_to])
                .into_owned()
        })
    } else {
        Ok(None)
    }
}

/// Converts the valid UTF-8 prefix of partially decoded bytes to text.
fn valid_utf8_prefix(decoded: Vec<u8>) -> String {
    match String::from_utf8(decoded) {
        Ok(text) => text,
        Err(error) => {
            let valid_up_to = error.utf8_error().valid_up_to();
            String::from_utf8_lossy(&error.into_bytes()[..valid_up_to])
                .into_owned()
        }
    }
}

/// Decodes one ASCII hexadecimal digit.
const fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
