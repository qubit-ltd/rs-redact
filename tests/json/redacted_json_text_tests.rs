// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for JSON text redaction and fail-closed fallback.

use qubit_redact::{RedactedJsonText, RedactionPolicy, Sensitivity, redact_json_text_in_place};

/// Verifies in-place JSON text redaction produces compact valid JSON.
#[test]
fn test_redact_json_text_in_place_masks_and_compacts_valid_json() {
    let policy = RedactionPolicy::builder()
        .raise("password", Sensitivity::Secret)
        .build()
        .expect("the policy should build");
    let mut text = "{ \"password\": \"raw-password\", \"name\": \"Ada\" }".to_owned();

    redact_json_text_in_place(&mut text, &policy);

    assert!(!text.contains("raw-password"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&text)
            .expect("redacted text should remain valid JSON")["name"],
        "Ada",
    );
    assert!(!text.contains(' '));
}

/// Verifies invalid JSON text never reaches formatting or mutation output.
#[test]
fn test_redacted_json_text_fails_closed_for_invalid_input() {
    let policy = RedactionPolicy::builder()
        .mask(
            Sensitivity::Secret,
            qubit_redact::MaskPolicy::fixed("[invalid-json]"),
        )
        .build()
        .expect("the policy should build");
    let raw = "not json: raw-secret";
    let debug = format!("{:?}", RedactedJsonText::new(raw, &policy));
    let display = RedactedJsonText::new(raw, &policy).to_string();
    let mut mutated = raw.to_owned();

    redact_json_text_in_place(&mut mutated, &policy);

    assert!(!debug.contains(raw));
    assert!(!display.contains(raw));
    assert!(!mutated.contains(raw));
    assert_eq!(mutated, "[invalid-json]");
}

/// Verifies redacted JSON text remains a JSON string through Serde.
#[cfg(feature = "serde")]
#[test]
fn test_redacted_json_text_serde_preserves_outer_string_shape() {
    let policy = RedactionPolicy::builder()
        .raise("token", Sensitivity::Secret)
        .build()
        .expect("the policy should build");
    let text = r#"{"token":"raw","name":"Ada"}"#;

    let serialized = serde_json::to_value(RedactedJsonText::new(text, &policy))
        .expect("the redacted JSON text should serialize");

    let output = serialized
        .as_str()
        .expect("redacted JSON text should remain a string");
    assert!(!output.contains("raw"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(output)
            .expect("the serialized string should hold valid JSON")["name"],
        "Ada",
    );
}
