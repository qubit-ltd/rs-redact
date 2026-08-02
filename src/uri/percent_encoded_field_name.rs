// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Strict percent decoding for URI field-name components.

/// Strictly percent-decodes a URI field name as UTF-8.
///
/// Unlike HTML form decoding, `+` remains a literal plus. Malformed escapes
/// and invalid UTF-8 return `None`, allowing the caller's URI parser to decide
/// whether the complete input is valid.
#[must_use]
pub fn decode_percent_encoded_field_name(text: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(text.len());
    let input = text.as_bytes();
    let mut index = 0;
    while index < input.len() {
        if input[index] != b'%' {
            bytes.push(input[index]);
            index += 1;
            continue;
        }
        let high = *input.get(index + 1)?;
        let low = *input.get(index + 2)?;
        bytes.push((hex_value(high)? << 4) | hex_value(low)?);
        index += 3;
    }
    String::from_utf8(bytes).ok()
}

/// Decodes one ASCII hexadecimal digit.
const fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}
