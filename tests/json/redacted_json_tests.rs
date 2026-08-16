// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for borrowed JSON value redaction.

use qubit_redact::InputOutputLimit;
use qubit_redact::JsonDepthLimit;
use qubit_redact::MaskPolicy;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
use qubit_redact::UnknownFieldPolicy;
use qubit_redact::formats::json::RedactedJson;
use serde_json::json;
#[cfg(feature = "serde")]
use serde_json::to_value;
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
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder
            .fields()
            .raise("password", Sensitivity::Secret)
            .expect("the test builder input should be valid");
        builder
            .fields()
            .raise("token", Sensitivity::High)
            .expect("the test builder input should be valid");
        builder
            .fields()
            .raise("api_key", Sensitivity::Secret)
            .expect("the test builder input should be valid");
        builder
    })
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
    let policy = ({
        let mut builder = RedactionPolicy::strict().to_builder();
        builder
            .fields()
            .allow_exact("public")
            .expect("the public field should be valid");
        builder
    })
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
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder
            .fields()
            .unknown_field_policy(UnknownFieldPolicy::Redact(
                Sensitivity::High,
            ));
        builder
            .fields()
            .allow_exact("public")
            .expect("the test builder input should be valid");
        builder
    })
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
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder
            .fields()
            .raise("password", Sensitivity::Secret)
            .expect("the test builder input should be valid");
        builder
    })
    .build()
    .expect("the policy should build");

    let output = format!("{:#?}", RedactedJson::new(&value, &policy));

    assert!(output.contains('\n'));
    assert!(!output.contains("raw"));
    assert!(output.contains("Ada"));
}

/// Verifies nested parsed JSON views consume one shared diagnostic budget.
#[test]
fn test_redacted_json_session_uses_shared_output_budget() {
    let value = json!({
        "message": "diagnostic text that exceeds one fragment",
    });
    let budget = InputOutputLimit::builder()
        .max_input_bytes(1024)
        .max_output_bytes(InputOutputLimit::MIN_OUTPUT_BYTES)
        .build()
        .expect("the diagnostic budget should be valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(budget);
        builder
    })
    .build()
    .expect("the policy should build");
    let redactor = Redactor::new(policy.clone());
    let mut session = redactor.session();

    let first = session.json().redact_value(&value);
    let second = session.json().redact_value(&value);

    assert!(first.as_str().len() <= budget.max_output_bytes());
    assert!(first.as_str().ends_with("<truncated>"));
    assert!(second.as_str().is_empty());
    assert!(
        first.as_str().len().saturating_add(second.as_str().len())
            <= budget.max_output_bytes()
    );
    assert_eq!(session.remaining_output_bytes(), 0);
}

/// Verifies sensitive non-string JSON values never retain their debug form.
#[test]
fn test_redacted_json_masks_sensitive_non_string_values() {
    let value = json!({
        "secret_number": 42,
        "secret_object": {"nested": "raw"},
        "visible": false,
    });
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder
            .fields()
            .raise("secret_number", Sensitivity::Secret)
            .expect("the test builder input should be valid");
        builder
            .fields()
            .raise("secret_object", Sensitivity::Secret)
            .expect("the test builder input should be valid");
        builder
    })
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
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().json_depth(
            JsonDepthLimit::builder()
                .max_depth(1)
                .build()
                .expect("the depth budget is valid"),
        );
        builder
            .fields()
            .mask(Sensitivity::Secret, MaskPolicy::fixed("[depth-limit]"))
            .expect("the test mask policy should be valid");
        builder
    })
    .build()
    .expect("the policy should build");

    let output = format!("{:?}", RedactedJson::new(&value, &policy));

    assert!(output.contains("visible"));
    assert!(output.contains("[depth-limit]"));
    assert!(!output.contains("raw-depth-secret"));
    assert!(!output.contains("deeper"));
}

/// Verifies nested JSON views retain the child container at the next depth.
#[test]
fn test_redacted_json_uses_root_inclusive_depth_budget() {
    let value = json!({
        "nested": {"deeper": {"secret": "raw-depth-secret"}},
    });
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().json_depth(
            JsonDepthLimit::builder()
                .max_depth(2)
                .build()
                .expect("the depth budget is valid"),
        );
        builder
            .fields()
            .mask(Sensitivity::Secret, MaskPolicy::fixed("[depth-limit]"))
            .expect("the test mask policy should be valid");
        builder
    })
    .build()
    .expect("the policy should build");

    let output = format!("{:?}", RedactedJson::new(&value, &policy));

    assert!(output.contains("deeper"));
    assert!(output.contains("[depth-limit]"));
    assert!(!output.contains("raw-depth-secret"));
}

/// Verifies redacted JSON serializes as a JSON value rather than a JSON text
/// string when the serde feature is enabled.
#[cfg(feature = "serde")]
#[test]
fn test_redacted_json_serde_preserves_json_value_shape() {
    let value = json!({"password": "raw", "name": "Ada"});
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder
            .fields()
            .raise("password", Sensitivity::Secret)
            .expect("the test builder input should be valid");
        builder
    })
    .build()
    .expect("the policy should build");

    let serialized = to_value(RedactedJson::new(&value, &policy))
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
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder
            .fields()
            .raise("secret_object", Sensitivity::Secret)
            .expect("the test builder input should be valid");
        builder
            .fields()
            .raise("secret_number", Sensitivity::Secret)
            .expect("the test builder input should be valid");
        builder
            .fields()
            .mask(Sensitivity::Secret, MaskPolicy::fixed("[opaque]"))
            .expect("the test mask policy should be valid");
        builder
    })
    .build()
    .expect("the policy should build");

    let serialized = to_value(RedactedJson::new(&value, &policy))
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
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().json_depth(
            JsonDepthLimit::builder()
                .max_depth(1)
                .build()
                .expect("the depth budget is valid"),
        );
        builder
            .fields()
            .mask(Sensitivity::Secret, MaskPolicy::fixed("[depth-limit]"))
            .expect("the test mask policy should be valid");
        builder
    })
    .build()
    .expect("the policy should build");

    let output = to_value(RedactedJson::new(&value, &policy))
        .expect("the bounded redacted view should serialize");

    assert_eq!(output["shallow"], "visible");
    assert_eq!(output["nested"], "[depth-limit]");
    assert!(!output.to_string().contains("raw-depth-secret"));
}

/// Verifies Serde output covers arrays, nested pass-through values, and
/// unkeyed scalar redaction.
#[cfg(feature = "serde")]
#[test]
fn test_redacted_json_serde_handles_arrays_and_unkeyed_scalars() {
    let array = json!(["visible", {"nested": [1, 2]}]);
    let standard = RedactionPolicy::standard();
    let serialized = to_value(RedactedJson::new(&array, &standard))
        .expect("the array should serialize");
    assert_eq!(serialized, array);

    let strict = RedactionPolicy::strict();
    let scalar = json!("root-secret");
    let serialized = to_value(RedactedJson::new(&scalar, &strict))
        .expect("the scalar should serialize");
    assert_ne!(serialized, scalar);
}
