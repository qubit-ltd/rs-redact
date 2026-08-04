// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for bounded structured HTTP body rendering.

use http::HeaderValue;
use qubit_redact::RedactionPolicy;
use qubit_redact::http::{
    BodyBudget,
    BodyCapture,
    HttpRedactor,
};

/// Builds a redactor with a deliberately small rendered-body budget.
fn redactor_with_output_limit(max_output_bytes: usize) -> HttpRedactor {
    let policy = RedactionPolicy::builder()
        .body_budget(
            BodyBudget::new(4096, max_output_bytes)
                .expect("the body budget is valid"),
        )
        .build()
        .expect("the HTTP policy is valid");
    HttpRedactor::new(policy)
}
/// Verifies bounded JSON rendering reports truncation without exposing a
/// partially rendered secret.
#[test]
fn test_bounded_json_rendering_truncates_without_partial_secret() {
    let result = redactor_with_output_limit(BodyBudget::MIN_OUTPUT_BYTES)
        .redact_body(
            BodyCapture::complete(br#"{\"password\":\"raw-secret\"}"#),
            Some(&HeaderValue::from_static("application/json")),
        );

    assert!(result.is_truncated());
    assert!(!result.to_string().contains("raw-secret"));
}

/// Verifies NDJSON rendering can truncate after a complete first record.
#[test]
fn test_bounded_ndjson_rendering_truncates_after_complete_record() {
    let result = redactor_with_output_limit(BodyBudget::MIN_OUTPUT_BYTES)
        .redact_body(
            BodyCapture::complete(
                b"{\"mode\":1}\n{\"password\":\"raw-secret\"}",
            ),
            Some(&HeaderValue::from_static("application/x-ndjson")),
        );

    assert!(result.is_truncated());
    assert!(!result.to_string().contains("raw-secret"));
}

/// Verifies NDJSON truncates when a record leaves no room for its separator.
#[test]
fn test_bounded_ndjson_rendering_truncates_at_record_separator() {
    let result = redactor_with_output_limit(BodyBudget::MIN_OUTPUT_BYTES)
        .redact_body(
            BodyCapture::complete(b"{\"a\":\"abc\"}\n{}"),
            Some(&HeaderValue::from_static("application/x-ndjson")),
        );

    assert!(result.is_truncated());
}

/// Verifies NDJSON truncates when a complete final record leaves no room for
/// its original trailing newline.
#[test]
fn test_bounded_ndjson_rendering_truncates_at_trailing_newline() {
    let result = redactor_with_output_limit(BodyBudget::MIN_OUTPUT_BYTES)
        .redact_body(
            BodyCapture::complete(b"{\"a\":\"abc\"}\n"),
            Some(&HeaderValue::from_static("application/x-ndjson")),
        );

    assert!(result.is_truncated());
}

/// Verifies multipart summaries truncate when the opening marker exceeds the
/// configured rendering budget.
#[test]
fn test_bounded_multipart_rendering_truncates_before_first_part() {
    let result = redactor_with_output_limit(BodyBudget::MIN_OUTPUT_BYTES)
        .redact_body(
            BodyCapture::complete(b"--boundary--\r\n"),
            Some(&HeaderValue::from_static(
                "multipart/form-data; boundary=boundary",
            )),
        );

    assert!(result.is_truncated());
}

/// Verifies an empty multipart summary truncates when only its opening marker
/// fits in the output budget.
#[test]
fn test_bounded_empty_multipart_rendering_truncates_at_closing_marker() {
    let result = redactor_with_output_limit("<multipart>\n".len()).redact_body(
        BodyCapture::complete(b"--boundary--\r\n"),
        Some(&HeaderValue::from_static(
            "multipart/form-data; boundary=boundary",
        )),
    );

    assert!(result.is_truncated());
}

/// Verifies multipart rendering truncates before a separator or closing marker
/// can exceed the rendered-body budget.
#[test]
fn test_bounded_multipart_rendering_truncates_at_output_markers() {
    let two_parts = b"--boundary\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nraw\r\n--boundary\r\nContent-Disposition: form-data; name=\"mode\"\r\n\r\ndebug\r\n--boundary--\r\n";
    let separator = redactor_with_output_limit(31).redact_body(
        BodyCapture::complete(two_parts),
        Some(&HeaderValue::from_static(
            "multipart/form-data; boundary=boundary",
        )),
    );
    assert!(separator.is_truncated());

    let one_part = b"--boundary\r\nContent-Disposition: form-data; name=\"mode\"\r\n\r\ndebug\r\n--boundary--\r\n";
    let closing = redactor_with_output_limit(30).redact_body(
        BodyCapture::complete(one_part),
        Some(&HeaderValue::from_static(
            "multipart/form-data; boundary=boundary",
        )),
    );
    assert!(closing.is_truncated());
}

/// Verifies a nested structured multipart part propagates its truncation to
/// the enclosing multipart rendering.
#[test]
fn test_bounded_multipart_rendering_propagates_nested_truncation() {
    let body = b"--boundary\r\nContent-Disposition: form-data; name=\"metadata\"\r\nContent-Type: application/json\r\n\r\n{\"a\":\"a-very-long-value\"}\r\n--boundary--\r\n";
    let result = redactor_with_output_limit(20).redact_body(
        BodyCapture::complete(body),
        Some(&HeaderValue::from_static(
            "multipart/form-data; boundary=boundary",
        )),
    );

    assert!(result.is_truncated());
}
