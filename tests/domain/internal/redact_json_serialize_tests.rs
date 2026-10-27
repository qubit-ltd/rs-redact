// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Public JSON text adapter enforces decoder admission before building a tree.

use qubit_redact::RedactionPolicy;
use qubit_redact::domain::internal::RedactedJsonSerializeRef;
use serde_json::to_value;

#[test]
fn test_json_text_serde_adapter_preserves_numbers_and_literal_protocol_keys() {
    let policy = RedactionPolicy::standard();
    for (text, expected) in [
        ("1.5", "1.5"),
        ("1e2", "100.0"),
        ("-0.0", "-0.0"),
        ("-9223372036854775808", "-9223372036854775808"),
        ("18446744073709551615", "18446744073709551615"),
        (r#"{"amount":1.5}"#, r#"{"amount":1.5}"#),
        (
            r#"{"$serde_json::private::Number":"1.5"}"#,
            r#"{"$serde_json::private::Number":"1.5"}"#,
        ),
        (
            r#"{"$serde_json::private::RawValue":"1.5"}"#,
            r#"{"$serde_json::private::RawValue":"1.5"}"#,
        ),
    ] {
        let encoded = to_value(RedactedJsonSerializeRef::new(text, &policy)).expect("JSON-text adapter serialization");

        assert_eq!(encoded, expected, "input: {text}");
    }
}

#[test]
fn test_json_text_serde_adapter_masks_decoded_duplicate_keys() {
    let policy = RedactionPolicy::standard();
    let source = r#"{"password":"first-secret","pass\u0077ord":"second-secret"}"#;

    let encoded = to_value(RedactedJsonSerializeRef::new(source, &policy)).expect("JSON-text adapter serialization");

    assert_eq!(encoded, "<redacted>");
}

/// Verifies JSON-text fields are rejected by the decoder before an
/// over-limit tree can be materialized.
#[test]
fn test_json_text_serde_adapter_enforces_json_decode_limits() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_json_nodes(1);
        })
        .expect("limits")
        .build()
        .expect("redaction policy");
    let source = r#"{"outer":{"token":"raw-secret"}}"#;

    let encoded = to_value(RedactedJsonSerializeRef::new(source, &policy)).expect("JSON-text adapter serialization");

    assert_eq!(encoded, "<redacted>");
}
