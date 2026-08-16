// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for explicit JSON text transformation.

use qubit_redact::InputOutputLimit;
use qubit_redact::JsonDepthLimit;
use qubit_redact::MaskPolicy;
use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;
use qubit_redact::formats::json::redact_json_text_in_place;
/// Verifies explicit mutation preserves complete JSON beyond diagnostic limits.
#[test]
fn test_redact_json_text_in_place_is_not_limited_by_diagnostic_budget() {
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(
            InputOutputLimit::builder()
                .max_input_bytes(16)
                .max_output_bytes(64)
                .build()
                .expect("the diagnostic budget should be valid"),
        );
        builder
            .fields()
            .raise("password", Sensitivity::Secret)
            .expect("the test builder input should be valid");
        builder
    })
    .build()
    .expect("the policy should build");
    let mut text =
        format!(r#"{{"name":"{}","password":"raw"}}"#, "a".repeat(128));

    redact_json_text_in_place(&mut text, &policy);

    let value = serde_json::from_str::<serde_json::Value>(&text)
        .expect("the transformed text should remain valid JSON");
    assert_eq!(value["name"], "a".repeat(128));
    assert_ne!(value["password"], "raw");
    assert!(text.len() > policy.limits().diagnostic_event().max_input_bytes());
}

/// Verifies explicit JSON text mutation still obeys the structural depth
/// safety budget even though byte-oriented diagnostic limits do not apply.
#[test]
fn test_redact_json_text_in_place_obeys_json_depth_limit() {
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
    let mut text =
        r#"{"shallow":"visible","nested":{"secret":"raw-depth-secret"}}"#
            .to_owned();

    redact_json_text_in_place(&mut text, &policy);

    let value = serde_json::from_str::<serde_json::Value>(&text)
        .expect("depth-limited output should remain valid JSON");
    assert_eq!(value["shallow"], "visible");
    assert_eq!(value["nested"], "[depth-limit]");
    assert!(!text.contains("raw-depth-secret"));
}

/// Verifies strict explicit transformation masks root and array scalars.
#[test]
fn test_redact_json_text_in_place_masks_strict_unkeyed_scalars() {
    let policy = RedactionPolicy::strict();
    let mut root = String::from("\"root-secret\"");
    let mut array = String::from("[\"array-secret\",42,true]");

    redact_json_text_in_place(&mut root, &policy);
    redact_json_text_in_place(&mut array, &policy);

    assert!(!root.contains("root-secret"));
    assert!(!array.contains("array-secret"));
    assert!(!array.contains("42"));
    assert!(!array.contains("true"));
}

/// Verifies array scalars remain unkeyed below an allowed object field.
#[test]
fn test_redact_json_text_in_place_masks_array_scalars_below_object_field() {
    let policy = ({
        let mut builder = RedactionPolicy::strict().to_builder();
        builder
            .fields()
            .allow_exact("items")
            .expect("the object field should be valid");
        builder
    })
    .build()
    .expect("the strict policy should build");
    let mut text = r#"{"items":["raw-array-secret",42,true]}"#.to_owned();

    redact_json_text_in_place(&mut text, &policy);

    assert!(!text.contains("raw-array-secret"));
    assert!(!text.contains("42"));
    assert!(!text.contains("true"));
}
