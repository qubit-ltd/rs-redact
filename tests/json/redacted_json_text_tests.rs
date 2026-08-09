// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for JSON text redaction and fail-closed fallback.

use qubit_redact::InputOutputLimit;
use qubit_redact::JsonDepthLimit;
use qubit_redact::MaskPolicy;
use qubit_redact::RedactedJsonText;
use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;
use qubit_redact::redact_json_text_in_place;
/// Verifies the constructor preserves the borrowed text and policy behavior.
#[test]
fn test_redacted_json_text_new_constructs_borrowed_view() {
    let policy = RedactionPolicy::builder()
        .allow_canonical_exact("name")
        .expect("the test builder input should be valid")
        .build()
        .expect("the policy should build");
    let view = std::hint::black_box(RedactedJsonText::new(
        r#"{"name":"Ada"}"#,
        &policy,
    ));

    assert_eq!(view.to_string(), r#"{"name":"Ada"}"#);
}

/// Verifies display emits compact, parseable JSON rather than Rust debug text.
#[test]
fn test_redacted_json_text_display_is_compact_valid_json() {
    let policy = RedactionPolicy::builder()
        .raise("password", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .build()
        .expect("the policy should build");
    let output = RedactedJsonText::new(
        r#"{ "n": 1, "ok": true, "none": null, "name": "Ada", "password": "raw" }"#,
        &policy,
    )
    .to_string();
    let value = serde_json::from_str::<serde_json::Value>(&output)
        .expect("display output should remain valid JSON");

    assert_eq!(value["n"], 1);
    assert_eq!(value["ok"], true);
    assert_eq!(value["none"], serde_json::Value::Null);
    assert_eq!(value["name"], "Ada");
    assert_ne!(value["password"], "raw");
    assert!(!output.contains("Number("));
    assert!(!output.contains("String("));
    assert!(!output.contains("Bool("));
    assert!(!output.contains("Null"));
    assert!(!output.contains(' '));
}

/// Verifies diagnostic formatting refuses oversized JSON before parsing it.
#[test]
fn test_redacted_json_text_diagnostic_input_budget_fails_closed() {
    let policy = RedactionPolicy::builder()
        .diagnostic_event(
            InputOutputLimit::new(16, 128)
                .expect("the diagnostic budget should be valid"),
        )
        .mask(Sensitivity::Secret, MaskPolicy::fixed("[input-limit]"))
        .expect("the test mask policy should be valid")
        .build()
        .expect("the policy should build");
    let raw = r#"{"name":"visible-untrusted-value"}"#;
    let view = RedactedJsonText::new(raw, &policy);

    assert!(!format!("{view:?}").contains("visible-untrusted-value"));
    assert_eq!(view.to_string(), "[input-limit]");
}

/// Verifies display applies the configured diagnostic output limit.
#[test]
fn test_redacted_json_text_display_uses_diagnostic_output_budget() {
    let budget = InputOutputLimit::new(256, InputOutputLimit::MIN_OUTPUT_BYTES)
        .expect("the diagnostic budget should be valid");
    let policy = RedactionPolicy::builder()
        .diagnostic_event(budget)
        .allow_canonical_exact("name")
        .expect("the test builder input should be valid")
        .build()
        .expect("the policy should build");
    let raw = format!(r#"{{"name":"{}"}}"#, "a".repeat(128));
    let view = RedactedJsonText::new(&raw, &policy);
    let output = view.to_string();
    let debug = format!("{view:?}");

    assert!(output.len() <= budget.max_output_bytes());
    assert!(output.ends_with("<truncated>"));
    assert!(debug.len() <= budget.max_output_bytes());
    assert!(debug.ends_with("<truncated>"));
}

/// Verifies JSON text diagnostics replace over-depth subtrees while retaining
/// safe shallow siblings.
#[test]
fn test_redacted_json_text_fails_closed_at_depth_budget() {
    let policy = RedactionPolicy::builder()
        .json_depth_limit(
            JsonDepthLimit::new(1).expect("the depth budget is valid"),
        )
        .mask(Sensitivity::Secret, MaskPolicy::fixed("[depth-limit]"))
        .expect("the test mask policy should be valid")
        .build()
        .expect("the policy should build");
    let raw = r#"{"shallow":"visible","nested":{"secret":"raw-depth-secret"}}"#;

    let output = RedactedJsonText::new(raw, &policy).to_string();
    let value = serde_json::from_str::<serde_json::Value>(&output)
        .expect("depth-limited output should remain valid JSON");

    assert_eq!(value["shallow"], "visible");
    assert_eq!(value["nested"], "[depth-limit]");
    assert!(!output.contains("raw-depth-secret"));
}

/// Verifies alternate debug formatting remains log-safe after pretty rendering.
#[test]
fn test_redacted_json_text_debug_preserves_alternate_formatting() {
    let policy = RedactionPolicy::builder()
        .raise("password", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .build()
        .expect("the policy should build");
    let view =
        RedactedJsonText::new(r#"{"password":"raw","name":"Ada"}"#, &policy);

    let output = format!("{view:#?}");

    assert!(output.contains("\\n"));
    assert!(!output.contains("raw"));
    assert!(output.contains("Ada"));
}

/// Verifies in-place JSON text redaction produces compact valid JSON.
#[test]
fn test_redact_json_text_in_place_masks_and_compacts_valid_json() {
    let policy = RedactionPolicy::builder()
        .raise("password", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .build()
        .expect("the policy should build");
    let mut text =
        "{ \"password\": \"raw-password\", \"name\": \"Ada\" }".to_owned();

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
        .mask(Sensitivity::Secret, MaskPolicy::fixed("[invalid-json]"))
        .expect("the test mask policy should be valid")
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
        .expect("the test builder input should be valid")
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
