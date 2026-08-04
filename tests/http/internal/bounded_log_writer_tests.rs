// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Black-box tests for bounded HTTP log rendering.

use http::HeaderValue;
use qubit_redact::{
    MaskPolicy,
    RedactionPolicy,
    Sensitivity,
    http::{
        BodyBudget,
        BodyCapture,
        HttpFieldContext,
        HttpRedactor,
    },
};

/// Builds a redactor whose secret mask is intentionally much larger than its
/// output budget.
fn amplified_mask_redactor() -> HttpRedactor {
    let replacement = "X\n".repeat(512 * 1024);
    let body_policy = RedactionPolicy::builder()
        .disable_floor()
        .raise("password", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .raise("api_key", Sensitivity::Secret)
        .expect("the test builder input should be valid")
        .mask(Sensitivity::Secret, MaskPolicy::fixed(&replacement))
        .expect("the test mask policy should be valid")
        .build()
        .expect("the body policy is valid");
    let budget =
        BodyBudget::new(4096, 64).expect("the output can contain the marker");
    let policy = RedactionPolicy::builder()
        .http_rules(HttpFieldContext::Body, body_policy.rules().clone())
        .mask(Sensitivity::Secret, MaskPolicy::fixed(&replacement))
        .expect("the test mask policy should be valid")
        .http_disable_floor_for(HttpFieldContext::Body)
        .body_budget(budget)
        .build()
        .expect("the HTTP policy is valid");
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
        assert!(result.is_truncated());
        assert!(!rendered.contains("secret"), "{rendered}");
        assert!(!rendered.contains('\n'), "{rendered:?}");
    }
}

/// Verifies output truncation keeps UTF-8 valid and the marker complete.
#[test]
fn test_bounded_output_keeps_utf8_and_marker_complete() {
    let budget =
        BodyBudget::new(64, 14).expect("the output can contain the marker");
    let policy = RedactionPolicy::builder()
        .body_budget(budget)
        .text_body_policy(qubit_redact::http::TextBodyPolicy::PassThrough)
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
    let budget =
        BodyBudget::new(64, 15).expect("the output can contain the marker");
    let policy = RedactionPolicy::builder()
        .body_budget(budget)
        .text_body_policy(qubit_redact::http::TextBodyPolicy::PassThrough)
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
    let budget =
        BodyBudget::new(1, 11).expect("the output can contain the marker");
    let policy = RedactionPolicy::builder()
        .body_budget(budget)
        .text_body_policy(qubit_redact::http::TextBodyPolicy::PassThrough)
        .build()
        .expect("the HTTP policy is valid");
    let capture = BodyCapture::truncated(b"a", Some(2))
        .expect("the captured prefix has valid metadata");
    let result = HttpRedactor::new(policy)
        .redact_body(capture, Some(&HeaderValue::from_static("text/plain")));

    assert_eq!(result.to_string(), "<truncated>");
}
