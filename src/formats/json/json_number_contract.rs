// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Shared validation for the JSON numeric representation boundary.

use qubit_json::decode::JsonDecoder;

/// Returns whether text follows strict JSON syntax and the qubit 64-bit
/// numeric contract before serde_json materializes a value.
pub(crate) fn is_valid_json_text(text: &str) -> bool {
    JsonDecoder::unlimited().validate_str(text).is_ok()
}

/// Returns whether bytes follow strict JSON syntax and the qubit 64-bit
/// numeric contract before serde_json materializes a value.
#[cfg(feature = "http")]
pub(crate) fn is_valid_json_bytes(bytes: &[u8]) -> bool {
    JsonDecoder::unlimited().validate_utf8(bytes).is_ok()
}
