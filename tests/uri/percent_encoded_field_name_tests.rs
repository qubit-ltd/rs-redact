// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for strict percent decoding of URI field names.

use qubit_redact::uri::decode_percent_encoded_field_name;

/// Verifies valid percent-encoded UTF-8 is decoded without form semantics.
#[test]
fn test_decode_percent_encoded_field_name_decodes_utf8() {
    assert_eq!(
        decode_percent_encoded_field_name("display%E4%B8%AD%E6%96%87")
            .as_deref(),
        Some("display中文"),
    );
    assert_eq!(
        decode_percent_encoded_field_name("literal%2Bplus").as_deref(),
        Some("literal+plus"),
    );
}
