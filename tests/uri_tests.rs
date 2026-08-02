// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for parser-neutral URI component helpers.

use qubit_redact::uri::decode_percent_encoded_field_name;

/// Verifies strict decoding preserves URI rather than form semantics.
#[test]
fn test_decode_percent_encoded_field_name() {
    assert_eq!(
        decode_percent_encoded_field_name("access%5Ftoken").as_deref(),
        Some("access_token"),
    );
    assert_eq!(
        decode_percent_encoded_field_name("a+b").as_deref(),
        Some("a+b"),
    );
    assert_eq!(decode_percent_encoded_field_name("bad%2"), None);
    assert_eq!(decode_percent_encoded_field_name("%FF"), None);
}
