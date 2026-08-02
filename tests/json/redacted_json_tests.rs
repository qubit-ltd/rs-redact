// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for borrowed JSON value redaction.

use qubit_redact::{
    JsonDepthBudget,
    MaskPolicy,
    RedactedJson,
    RedactionPolicy,
    Sensitivity,
    UnknownFieldPolicy,
};
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
        .expect("the test builder input should be valid")
        .raise("token", Sensitivity::High)
        .expect("the test builder input should be valid")
        .raise("api_key", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .build()
        .expect("the policy should build");

    let output = format!("{:?}", RedactedJson::new(&value, &policy));

    assert!(!output.contains("raw-password"));
    assert!(!output.contains("raw-token"));
    assert!(!output.contains("raw-key"));
    assert!(output.contains("Ada"));
    assert!(output.contains("visible"));
}

/// Verifies strict policy masks root and array scalars but not keyed values
/// that an explicit allow rule releases.
#[test]
fn test_redacted_json_strict_masks_only_unkeyed_scalars() {
    let root = json!("root-secret");
    let array = json!(["array-secret", {"public": "visible"}]);
    let policy = RedactionPolicy::strict()
        .to_builder()
        .allow_canonical_exact("public")
        .expect("the public field should be valid")
        .build()
        .expect("the strict policy should build");

    let root_output = format!("{:?}", RedactedJson::new(&root, &policy));
    let array_output = format!("{:?}", RedactedJson::new(&array, &policy));

    assert!(!root_output.contains("root-secret"));
    assert!(!array_output.contains("array-secret"));
    assert!(array_output.contains("visible"));
}

/// Verifies standard policy preserves unkeyed JSON scalars for compatibility.
#[test]
fn test_redacted_json_standard_preserves_unkeyed_scalars() {
    let value = json!(["visible", 42, true]);

    let output = format!(
        "{:?}",
        RedactedJson::new(&value, &RedactionPolicy::standard()),
    );

    assert!(output.contains("visible"));
    assert!(output.contains("42"));
    assert!(output.contains("true"));
}

/// Verifies fallback policy protects otherwise unclassified JSON object keys.
#[test]
fn test_redacted_json_uses_unknown_field_fallback() {
    let value = json!({"new_field": "raw", "public": "visible"});
    let policy = RedactionPolicy::builder()
        .unknown_field_policy(UnknownFieldPolicy::Redact(Sensitivity::High))
        .allow_canonical_exact("public")
        .expect("the test builder input should be valid")
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
        .expect("the test builder input should be valid")
        .build()
        .expect("the policy should build");

    let output = format!("{:#?}", RedactedJson::new(&value, &policy));

    assert!(output.contains('\n'));
    assert!(!output.contains("raw"));
    assert!(output.contains("Ada"));
}

/// Verifies sensitive non-string JSON values never retain their debug form.
#[test]
fn test_redacted_json_masks_sensitive_non_string_values() {
    let value = json!({
        "secret_number": 42,
        "secret_object": {"nested": "raw"},
        "visible": false,
    });
    let policy = RedactionPolicy::builder()
        .raise("secret_number", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .raise("secret_object", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .build()
        .expect("the policy should build");

    let output = format!("{:?}", RedactedJson::new(&value, &policy));

    assert!(!output.contains("42"));
    assert!(!output.contains("raw"));
    assert!(output.contains("false"));
}

/// Verifies borrowed formatting replaces an over-depth subtree without
/// inspecting or exposing its descendants.
#[test]
fn test_redacted_json_fails_closed_at_depth_budget() {
    let value = json!({
        "shallow": "visible",
        "nested": {"deeper": {"secret": "raw-depth-secret"}},
    });
    let policy = RedactionPolicy::builder()
        .json_depth_budget(
            JsonDepthBudget::new(1).expect("the depth budget is valid"),
        )
        .mask(Sensitivity::Secret, MaskPolicy::fixed("[depth-limit]"))
        .expect("the test mask policy should be valid")
        .build()
        .expect("the policy should build");

    let output = format!("{:?}", RedactedJson::new(&value, &policy));

    assert!(output.contains("visible"));
    assert!(output.contains("[depth-limit]"));
    assert!(!output.contains("raw-depth-secret"));
    assert!(!output.contains("deeper"));
}

/// Verifies redacted JSON serializes as a JSON value rather than a JSON text
/// string when the serde feature is enabled.
#[cfg(feature = "serde")]
#[test]
fn test_redacted_json_serde_preserves_json_value_shape() {
    let value = json!({"password": "raw", "name": "Ada"});
    let policy = RedactionPolicy::builder()
        .raise("password", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .build()
        .expect("the policy should build");

    let serialized = serde_json::to_value(RedactedJson::new(&value, &policy))
        .expect("the redacted JSON value should serialize");

    assert!(serialized.is_object());
    assert_eq!(serialized["name"], "Ada");
    assert_ne!(serialized["password"], "raw");
}

/// Verifies Serde output replaces sensitive non-string values with the
/// configured opaque mask instead of recursively retaining their structure.
#[cfg(feature = "serde")]
#[test]
fn test_redacted_json_serde_masks_sensitive_non_string_values_opaquely() {
    let value = json!({
        "secret_object": {"nested": "raw"},
        "secret_number": 42,
    });
    let policy = RedactionPolicy::builder()
        .raise("secret_object", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .raise("secret_number", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .mask(Sensitivity::Secret, MaskPolicy::fixed("[opaque]"))
        .expect("the test mask policy should be valid")
        .build()
        .expect("the policy should build");

    let serialized = serde_json::to_value(RedactedJson::new(&value, &policy))
        .expect("the redacted JSON value should serialize");

    assert_eq!(
        serialized,
        json!({
            "secret_object": "[opaque]",
            "secret_number": "[opaque]",
        }),
    );
}

/// Verifies Serde serialization applies the same fail-closed depth budget
/// without cloning the complete source tree.
#[cfg(feature = "serde")]
#[test]
fn test_redacted_json_serde_fails_closed_at_depth_budget() {
    let value = json!({
        "shallow": "visible",
        "nested": {"secret": "raw-depth-secret"},
    });
    let policy = RedactionPolicy::builder()
        .json_depth_budget(
            JsonDepthBudget::new(1).expect("the depth budget is valid"),
        )
        .mask(Sensitivity::Secret, MaskPolicy::fixed("[depth-limit]"))
        .expect("the test mask policy should be valid")
        .build()
        .expect("the policy should build");

    let output = serde_json::to_value(RedactedJson::new(&value, &policy))
        .expect("the bounded redacted view should serialize");

    assert_eq!(output["shallow"], "visible");
    assert_eq!(output["nested"], "[depth-limit]");
    assert!(!output.to_string().contains("raw-depth-secret"));
}
