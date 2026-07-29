// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for borrowed JSON value redaction.

use qubit_redact::{RedactedJson, RedactionPolicy, Sensitivity, UnknownFieldPolicy};
use serde_json::json;

/// Verifies object keys select recursive JSON redaction without altering
/// unkeyed scalar values.
#[test]
fn test_redacted_json_masks_sensitive_object_values_recursively() {
    let value = json!({
        "password": "raw-password",
        "nested": {
            "token": "raw-token",
            "name": "Ada",
        },
        "items": [
            {"api_key": "raw-key"},
            "visible",
        ],
    });
    let policy = RedactionPolicy::builder()
        .raise("password", Sensitivity::Secret)
        .raise("token", Sensitivity::High)
        .raise("api_key", Sensitivity::Secret)
        .build()
        .expect("the policy should build");

    let output = format!("{:?}", RedactedJson::new(&value, &policy));

    assert!(!output.contains("raw-password"));
    assert!(!output.contains("raw-token"));
    assert!(!output.contains("raw-key"));
    assert!(output.contains("Ada"));
    assert!(output.contains("visible"));
}

/// Verifies fallback policy protects otherwise unclassified JSON object keys.
#[test]
fn test_redacted_json_uses_unknown_field_fallback() {
    let value = json!({"new_field": "raw", "public": "visible"});
    let policy = RedactionPolicy::builder()
        .unknown_field_policy(UnknownFieldPolicy::Redact(Sensitivity::High))
        .allow_exact("public")
        .build()
        .expect("the fallback policy should build");

    let output = format!("{:?}", RedactedJson::new(&value, &policy));

    assert!(!output.contains("raw"));
    assert!(output.contains("visible"));
}

/// Verifies alternate formatting preserves JSON structure while using the same
/// redaction policy.
#[test]
fn test_redacted_json_preserves_pretty_formatter_semantics() {
    let value = json!({"password": "raw", "name": "Ada"});
    let policy = RedactionPolicy::builder()
        .raise("password", Sensitivity::Secret)
        .build()
        .expect("the policy should build");

    let output = format!("{:#?}", RedactedJson::new(&value, &policy));

    assert!(output.contains('\n'));
    assert!(!output.contains("raw"));
    assert!(output.contains("Ada"));
}

/// Verifies redacted JSON serializes as a JSON value rather than a JSON text
/// string when the serde feature is enabled.
#[cfg(feature = "serde")]
#[test]
fn test_redacted_json_serde_preserves_json_value_shape() {
    let value = json!({"password": "raw", "name": "Ada"});
    let policy = RedactionPolicy::builder()
        .raise("password", Sensitivity::Secret)
        .build()
        .expect("the policy should build");

    let serialized = serde_json::to_value(RedactedJson::new(&value, &policy))
        .expect("the redacted JSON value should serialize");

    assert!(serialized.is_object());
    assert_eq!(serialized["name"], "Ada");
    assert_ne!(serialized["password"], "raw");
}
