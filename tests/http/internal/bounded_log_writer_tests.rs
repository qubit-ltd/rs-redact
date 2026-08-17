// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for bounded HTTP log rendering.

use http::HeaderValue;
use qubit_redact::MaskPolicy;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;
use qubit_redact::formats::http::BodyBudget;
use qubit_redact::formats::http::BodyCapture;
use qubit_redact::formats::http::HttpRedactor;
use qubit_redact::formats::http::TextBodyPolicy;
/// Builds a redactor whose secret mask is intentionally much larger than its
/// output budget.
fn amplified_mask_redactor() -> HttpRedactor {
    let replacement = "X\n".repeat(512 * 1024);
    let body_policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.edit_fields().disable_floor();
        builder
            .edit_fields()
            .raise("password", Sensitivity::Secret)
            .expect("the test builder input should be valid");
        builder
            .edit_fields()
            .raise("api_key", Sensitivity::Secret)
            .expect("the test builder input should be valid");
        builder
            .edit_fields()
            .mask(Sensitivity::Secret, MaskPolicy::fixed(&replacement))
            .expect("the test mask policy should be valid");
        builder
    })
    .build()
    .expect("the body policy is valid");
    let budget = BodyBudget::builder()
        .max_input_bytes(4096)
        .max_output_bytes(64)
        .build()
        .expect("the output can contain the marker");
    let mut builder = RedactionPolicy::builder();
    builder
        .http()
        .body()
        .replace_rules(body_policy.rules().clone())
        .disable_floor();
    builder.limits().http_body(budget);
    builder
        .edit_fields()
        .mask(Sensitivity::Secret, MaskPolicy::fixed(&replacement))
        .expect("the test mask policy should be valid");
    let policy = builder.build().expect("the HTTP policy is valid");
    HttpRedactor::new(policy)
}

/// Verifies structured formats remain bounded under an amplified fixed mask.
#[test]
fn test_structured_formats_bound_amplified_masks() {
    let redactor = amplified_mask_redactor();
    let cases = [
        (
            br#"{"password":"json-secret","api_key":"second-secret"}"#.as_slice(),
            HeaderValue::from_static("application/json"),
        ),
        (
            b"{\"password\":\"ndjson-secret\"}\n{\"api_key\":\"second-secret\"}\n"
                .as_slice(),
            HeaderValue::from_static("application/x-ndjson"),
        ),
        (
            b"password=form-secret&api_key=second-secret".as_slice(),
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        ),
        (
            b"--b\r\nContent-Disposition: form-data; name=password\r\n\r\nmultipart-secret\r\n--b--\r\n"
                .as_slice(),
            HeaderValue::from_static("multipart/form-data; boundary=b"),
        ),
    ];

    for (input, content_type) in cases {
        let result = redactor
            .redact_body(BodyCapture::complete(input), Some(&content_type));
        let rendered = result.to_string();

        assert!(rendered.len() <= 64, "{rendered}");
        assert!(rendered.ends_with("<truncated>"), "{rendered}");
        assert_eq!(result.completion(), RedactionCompletion::Truncated);
        assert!(!rendered.contains("secret"), "{rendered}");
        assert!(!rendered.contains('\n'), "{rendered:?}");
    }
}

/// Verifies output truncation keeps UTF-8 valid and the marker complete.
#[test]
fn test_bounded_output_keeps_utf8_and_marker_complete() {
    let budget = BodyBudget::builder()
        .max_input_bytes(64)
        .max_output_bytes(14)
        .build()
        .expect("the output can contain the marker");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().http_body(budget);
        builder.http().text_body(TextBodyPolicy::PassThrough);
        builder
    })
    .build()
    .expect("the HTTP policy is valid");
    let result = HttpRedactor::new(policy).redact_body(
        BodyCapture::complete("你好吗世界".as_bytes()),
        Some(&HeaderValue::from_static("text/plain")),
    );

    assert_eq!(result.to_string(), "你<truncated>");
}

/// Verifies reserving marker space backs up to a UTF-8 character boundary.
#[test]
fn test_late_truncation_backs_up_to_utf8_boundary() {
    let budget = BodyBudget::builder()
        .max_input_bytes(64)
        .max_output_bytes(15)
        .build()
        .expect("the output can contain the marker");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().http_body(budget);
        builder.http().text_body(TextBodyPolicy::PassThrough);
        builder
    })
    .build()
    .expect("the HTTP policy is valid");
    let result = HttpRedactor::new(policy).redact_body(
        BodyCapture::complete("你你你你你a".as_bytes()),
        Some(&HeaderValue::from_static("text/plain")),
    );

    assert_eq!(result.to_string(), "你<truncated>");
}

/// Verifies an already-truncated source can reserve the entire output budget.
#[test]
fn test_source_truncation_can_use_marker_only_budget() {
    let budget = BodyBudget::builder()
        .max_input_bytes(1)
        .max_output_bytes(11)
        .build()
        .expect("the output can contain the marker");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().http_body(budget);
        builder.http().text_body(TextBodyPolicy::PassThrough);
        builder
    })
    .build()
    .expect("the HTTP policy is valid");
    let capture = BodyCapture::truncated(b"a", 2)
        .expect("the captured prefix has valid metadata");
    let result = HttpRedactor::new(policy)
        .redact_body(capture, Some(&HeaderValue::from_static("text/plain")));

    assert_eq!(result.to_string(), "<truncated>");
}
