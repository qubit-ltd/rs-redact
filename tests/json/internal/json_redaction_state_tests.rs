// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for public effects of JSON redaction traversal state.

#[cfg(feature = "serde")]
use qubit_redact::RedactedJson;
#[cfg(feature = "serde")]
use qubit_redact::RedactionPolicy;
#[cfg(feature = "serde")]
use qubit_redact::Sensitivity;
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
