// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for public effects of JSON redaction traversal state.

use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;
#[cfg(feature = "serde")]
use qubit_redact::RedactedJson;
#[cfg(feature = "serde")]
use serde_json::json;
#[cfg(feature = "serde")]
use serde_json::to_value;
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

    let output = to_value(RedactedJson::new(&value, &policy))
        .expect("the redacted value should serialize");

    assert_ne!(output["items"][0]["token"], "raw");
    assert_eq!(output["items"][1]["name"], "Ada");
}

/// Verifies root-inclusive depth accounting preserves the fail-closed boundary.
#[test]
fn test_json_redaction_state_uses_root_inclusive_depth_budget() {
    let shallow_policy = RedactionPolicy::builder()
        .json_depth_limit(
            qubit_redact::JsonDepthLimit::new(1)
                .expect("the depth budget is valid"),
        )
        .mask(
            Sensitivity::Secret,
            qubit_redact::MaskPolicy::fixed("[depth-limit]"),
        )
        .expect("the test mask policy should be valid")
        .build()
        .expect("the policy should build");
    let deep_policy = RedactionPolicy::builder()
        .json_depth_limit(
            qubit_redact::JsonDepthLimit::new(2)
                .expect("the depth budget is valid"),
        )
        .mask(
            Sensitivity::Secret,
            qubit_redact::MaskPolicy::fixed("[depth-limit]"),
        )
        .expect("the test mask policy should be valid")
        .build()
        .expect("the policy should build");
    let mut shallow = r#"{"child":{"visible":"value"}}"#.to_owned();
    let mut deep = shallow.clone();

    qubit_redact::redact_json_text_in_place(&mut shallow, &shallow_policy);
    qubit_redact::redact_json_text_in_place(&mut deep, &deep_policy);

    assert_eq!(shallow, r#"{"child":"[depth-limit]"}"#);
    assert_eq!(deep, r#"{"child":{"visible":"value"}}"#);
}
