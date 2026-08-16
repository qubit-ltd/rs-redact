// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for public effects of JSON redaction outcomes.

#[cfg(feature = "http")]
use http::HeaderValue;
#[cfg(feature = "http")]
use qubit_redact::RedactionCompletion;
#[cfg(feature = "http")]
use qubit_redact::RedactionPolicy;
#[cfg(feature = "http")]
use qubit_redact::http::BodyBudget;
#[cfg(feature = "http")]
use qubit_redact::http::BodyCapture;
#[cfg(feature = "http")]
use qubit_redact::http::BodyRedactionStatus;
#[cfg(feature = "http")]
use qubit_redact::http::HttpRedactor;
#[cfg(feature = "http")]
use qubit_redact::http::UnkeyedJsonValuePolicy;

/// Verifies multiple retained unkeyed scalars aggregate into one status.
#[cfg(feature = "http")]
#[test]
fn test_json_redaction_outcome_reports_unkeyed_pass_through() {
    let policy = RedactionPolicy::builder()
        .unkeyed_json_value_policy(UnkeyedJsonValuePolicy::PassThrough)
        .build()
        .expect("the HTTP policy should build");
    let content_type = HeaderValue::from_static("application/json");
    let body = HttpRedactor::new(policy).redact_body(
        BodyCapture::complete(br#"["visible",42,true]"#),
        Some(&content_type),
    );

    assert_eq!(body.status(), BodyRedactionStatus::PassedThrough);
    assert_eq!(body.to_string(), r#"["visible",42,true]"#);
}

/// Verifies exhausted unkeyed JSON masks discard the partially redacted body.
#[cfg(feature = "http")]
#[test]
fn test_json_redaction_outcome_discards_partial_json_on_mask_exhaustion() {
    let body_budget = BodyBudget::builder()
        .max_input_bytes(512)
        .max_output_bytes(BodyBudget::MIN_OUTPUT_BYTES)
        .build()
        .expect("the body budget should be valid");
    let mut builder = RedactionPolicy::builder();
    builder
        .http()
        .body()
        .allow_exact("items")
        .expect("the items field allow rule should be valid");
    builder.limits().http_body(body_budget);
    let policy = builder.build().expect("the HTTP policy should build");
    let content_type = HeaderValue::from_static("application/json");
    let body = HttpRedactor::new(policy).redact_body(
        BodyCapture::complete(
            br#"{"items":["raw-unkeyed-secret","raw-unkeyed-secret"]}"#,
        ),
        Some(&content_type),
    );

    assert_eq!(body.to_string(), "<truncated>");
    assert_eq!(body.completion(), RedactionCompletion::Truncated);
    assert!(!body.to_string().contains("raw-unkeyed-secret"));
}
