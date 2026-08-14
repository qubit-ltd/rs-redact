// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for public effects of JSON redaction traversal state.

use qubit_redact::JsonDepthLimit;
use qubit_redact::MaskPolicy;
#[cfg(feature = "serde")]
use qubit_redact::RedactedJson;
use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;
use qubit_redact::redact_json_text_in_place;
#[cfg(feature = "serde")]
use serde_json::Value;
#[cfg(feature = "serde")]
use serde_json::from_str;
#[cfg(feature = "serde")]
use serde_json::json;
#[cfg(feature = "serde")]
use serde_json::to_string;
#[cfg(feature = "serde")]
use serde_json::to_value;

/// Verifies masking a deep sensitive container removes every descendant without
/// making the replacement invalid JSON.
#[cfg(feature = "serde")]
#[test]
fn test_json_redaction_state_masks_deep_sensitive_containers() {
    let policy = RedactionPolicy::builder()
        .raise("sensitive", Sensitivity::Secret)
        .expect("the test field should be valid")
        .mask(Sensitivity::Secret, MaskPolicy::fixed("[masked]"))
        .expect("the test mask policy should be valid")
        .build()
        .expect("the policy should build");
    let mut text = to_string(&json!({
        "sensitive": {
            "object-secret": "object-secret-value",
            "array": [
                "array-secret-value",
                {"nested-secret": "nested-secret-value"},
                [[{"deep-secret": "deep-secret-value"}]]
            ]
        }
    }))
    .expect("the test JSON should serialize");

    redact_json_text_in_place(&mut text, &policy);

    assert_eq!(text, r#"{"sensitive":"[masked]"}"#);
    assert!(!text.contains("object-secret-value"));
    assert!(!text.contains("array-secret-value"));
    assert!(!text.contains("nested-secret-value"));
    assert!(!text.contains("deep-secret-value"));
    from_str::<Value>(&text).expect("the masked value should remain valid JSON");
}

/// Verifies recursive traversal applies one policy across nested objects.
#[cfg(feature = "serde")]
#[test]
fn test_json_redaction_state_recurses_through_nested_values() {
    let policy = RedactionPolicy::builder()
        .raise("token", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .build()
        .expect("the policy should build");
    let value = json!({"items": [{"token": "raw"}, {"name": "Ada"}]});

    let output =
        to_value(RedactedJson::new(&value, &policy)).expect("the redacted value should serialize");

    assert_ne!(output["items"][0]["token"], "raw");
    assert_eq!(output["items"][1]["name"], "Ada");
}

/// Verifies root-inclusive depth accounting preserves the fail-closed boundary.
#[test]
fn test_json_redaction_state_uses_root_inclusive_depth_budget() {
    let shallow_policy = RedactionPolicy::builder()
        .json_depth_limit(JsonDepthLimit::new(1).expect("the depth budget is valid"))
        .mask(Sensitivity::Secret, MaskPolicy::fixed("[depth-limit]"))
        .expect("the test mask policy should be valid")
        .build()
        .expect("the policy should build");
    let deep_policy = RedactionPolicy::builder()
        .json_depth_limit(JsonDepthLimit::new(2).expect("the depth budget is valid"))
        .mask(Sensitivity::Secret, MaskPolicy::fixed("[depth-limit]"))
        .expect("the test mask policy should be valid")
        .build()
        .expect("the policy should build");
    let mut shallow = r#"{"child":{"visible":"value"}}"#.to_owned();
    let mut deep = shallow.clone();

    redact_json_text_in_place(&mut shallow, &shallow_policy);
    redact_json_text_in_place(&mut deep, &deep_policy);

    assert_eq!(shallow, r#"{"child":"[depth-limit]"}"#);
    assert_eq!(deep, r#"{"child":{"visible":"value"}}"#);
}

/// Verifies mutable JSON text redaction matches the lazy JSON view for every
/// supported JSON shape.
#[cfg(feature = "serde")]
#[test]
fn test_json_redaction_state_mutable_matches_lazy_redaction() {
    let policy = RedactionPolicy::strict()
        .to_builder()
        .allow_canonical_exact("visible")
        .expect("the allowed object field should be valid")
        .build()
        .expect("the strict policy should build");
    let values = [
        json!("root-secret"),
        json!(["root-array-secret", 42, true]),
        json!({"visible": "object-scalar"}),
        json!({"visible": ["object-array-secret", 42, true]}),
        json!({
            "visible": [
                ["nested-array-secret", 42, true],
                {"visible": "array-object-visible", "secret": "array-object-secret"}
            ]
        }),
        json!({"sensitive_container": {"visible": "must-not-leak"}}),
    ];

    for value in values {
        let lazy = to_value(RedactedJson::new(&value, &policy))
            .expect("the lazy redacted view should serialize");
        let mut text = to_string(&value).expect("the source JSON should serialize");
        redact_json_text_in_place(&mut text, &policy);
        let mutable =
            from_str::<Value>(&text).expect("the mutable redaction should remain valid JSON");

        assert_eq!(mutable, lazy, "mutable and lazy JSON redaction diverged");
    }
}
