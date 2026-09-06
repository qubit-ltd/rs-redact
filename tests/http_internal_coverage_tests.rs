// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Regression coverage for HTTP parser and diagnostic boundaries.

#![cfg(feature = "http")]

use http::HeaderMap;
use http::HeaderValue;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionPolicyBuilder;
use qubit_redact::RedactionReason;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
use qubit_redact::formats::http::BodyCapture;
use qubit_redact::formats::http::TextBodyPolicy;

fn configured_redactor(configure: impl FnOnce(&mut RedactionPolicyBuilder)) -> Redactor {
    let mut builder = RedactionPolicy::builder();
    configure(&mut builder);
    Redactor::new(builder.build().expect("test policy must be valid"))
}

#[test]
fn test_http_nested_url_redacts_credentials_fragment_and_percent_encoded_query() {
    let output = Redactor::standard().redact_http_url(
        "https://outer.test/?next=https%3A%2F%2Fuser%3Apassword%40inner.test%2Fp%3Ftoken%3Dnested-secret%23fragment-secret",
    );
    let rendered = output.text().as_str();

    assert!(!rendered.contains("password"));
    assert!(!rendered.contains("nested-secret"));
    assert!(!rendered.contains("fragment-secret"));
    assert!(rendered.contains("inner.test"));
}

#[test]
fn test_http_invalid_url_retains_invalid_uri_provenance() {
    let output = Redactor::standard().redact_http_url("https://[not-a-host");

    assert!(output.text().as_str().contains("invalid"));
    assert!(output.summary().reasons().contains(RedactionReason::InvalidUri));
}

#[test]
fn test_http_body_invalid_content_type_retains_diagnostic_provenance() {
    let content_type = HeaderValue::from_bytes(b"\xff").expect("opaque header must be accepted");
    let output = Redactor::standard().redact_http_body(BodyCapture::complete(b"raw-secret"), Some(&content_type));

    assert!(!output.text().as_str().contains("raw-secret"));
    assert!(output.summary().reasons().contains(RedactionReason::InvalidContentType));
}

#[test]
fn test_http_body_invalid_form_and_truncated_ndjson_fail_closed() {
    let redactor = Redactor::standard();
    let form_type = HeaderValue::from_static("application/x-www-form-urlencoded");
    let form = redactor.redact_http_body(BodyCapture::complete(b"password=%ZZraw-secret"), Some(&form_type));
    assert!(!form.text().as_str().contains("raw-secret"));
    assert!(form.summary().reasons().contains(RedactionReason::InvalidForm));

    let ndjson_type = HeaderValue::from_static("application/x-ndjson");
    let ndjson = redactor.redact_http_body(
        BodyCapture::prefix(b"{\"password\":\"raw-secret\"}\n", 12),
        Some(&ndjson_type),
    );
    assert!(!ndjson.text().as_str().contains("raw-secret"));
    assert!(ndjson.summary().reasons().contains(RedactionReason::InvalidJson));
}

#[test]
fn test_http_body_text_and_binary_dispatches_preserve_policy_boundary() {
    let pass_through = configured_redactor(|builder| {
        *builder = std::mem::take(builder)
            .http(|http| {
                http.text_body(TextBodyPolicy::PassThrough);
            })
            .expect("HTTP policy setup must be valid");
    });
    let text_type = HeaderValue::from_static("text/plain; charset=utf-8");
    let text = pass_through.redact_http_body(BodyCapture::complete(b"visible context"), Some(&text_type));
    assert_eq!(text.text().as_str(), "visible context");

    let binary = Redactor::standard().redact_http_body(
        BodyCapture::complete(&[0, 159, 146, 150]),
        Some(&HeaderValue::from_static("application/octet-stream")),
    );
    assert!(binary.text().as_str().contains("binary 4 bytes"));
}

#[test]
fn test_http_multipart_covers_sensitive_json_text_and_invalid_boundaries() {
    let body = b"--boundary\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nraw-password\r\n--boundary\r\nContent-Disposition: form-data; name=\"payload\"\r\nContent-Type: application/json\r\n\r\n{\"token\":\"json-secret\"}\r\n--boundary\r\nContent-Disposition: form-data; name=\"note\"\r\nContent-Type: text/plain\r\n\r\nplain-secret\r\n--boundary--\r\n";
    let content_type = HeaderValue::from_static("multipart/form-data; boundary=boundary");
    let output = Redactor::standard().redact_http_body(BodyCapture::complete(body), Some(&content_type));
    let rendered = output.text().as_str();

    assert!(!rendered.contains("raw-password"));
    assert!(!rendered.contains("json-secret"));
    assert!(!rendered.contains("plain-secret"));
    assert!(rendered.contains("<multipart>"));

    let malformed = Redactor::standard().redact_http_body(
        BodyCapture::complete(b"not-a-valid-multipart raw-secret"),
        Some(&content_type),
    );
    assert!(!malformed.text().as_str().contains("raw-secret"));
    assert!(
        malformed
            .summary()
            .reasons()
            .contains(RedactionReason::InvalidMultipart)
    );
}

#[test]
fn test_http_multipart_redacts_ndjson_parts_and_rejects_invalid_records() {
    let content_type = HeaderValue::from_static("multipart/form-data; boundary=boundary");
    let body = b"--boundary\r\nContent-Disposition: form-data; name=\"events\"\r\nContent-Type: application/x-ndjson\r\n\r\n{\"password\":\"first-secret\"}\n\n{\"token\":\"second-secret\"}\n\r\n--boundary--\r\n";
    let output = Redactor::standard().redact_http_body(BodyCapture::complete(body), Some(&content_type));
    let rendered = output.text().as_str();

    assert!(!rendered.contains("first-secret"));
    assert!(!rendered.contains("second-secret"));
    assert!(rendered.contains("<multipart>"));

    let invalid = b"--boundary\r\nContent-Disposition: form-data; name=\"events\"\r\nContent-Type: application/x-ndjson\r\n\r\n{\"password\":\"first-secret\"}\nnot-json second-secret\r\n--boundary--\r\n";
    let output = Redactor::standard().redact_http_body(BodyCapture::complete(invalid), Some(&content_type));

    assert!(!output.text().as_str().contains("first-secret"));
    assert!(!output.text().as_str().contains("second-secret"));
}

#[test]
fn test_http_context_rules_are_independent_and_sensitive_headers_override_allowance() {
    let redactor = configured_redactor(|builder| {
        *builder = std::mem::take(builder)
            .http(|http| {
                http.header()
                    .raise("header_only", Sensitivity::Secret)
                    .expect("valid header rule");
                http.query()
                    .raise("query_only", Sensitivity::Secret)
                    .expect("valid query rule");
                http.body()
                    .raise("body_only", Sensitivity::Secret)
                    .expect("valid body rule");
                http.header().allow_exact("x-visible").expect("valid header allow rule");
            })
            .expect("HTTP policy setup must be valid");
    });

    let mut headers = HeaderMap::new();
    headers.insert("header-only", HeaderValue::from_static("header-secret"));
    headers.insert("x-visible", HeaderValue::from_static("visible"));
    let mut native = HeaderValue::from_static("native-secret");
    native.set_sensitive(true);
    headers.insert("native", native);
    let headers = redactor.redact_http_headers(&headers);
    assert!(!headers.text().as_str().contains("header-secret"));
    assert!(headers.text().as_str().contains("visible"));
    assert!(!headers.text().as_str().contains("native-secret"));

    let url = redactor.redact_http_url("https://example.test/?query_only=query-secret&header_only=visible-query");
    assert!(!url.text().as_str().contains("query-secret"));
    assert!(url.text().as_str().contains("visible-query"));

    let body_type = HeaderValue::from_static("application/json");
    let body = redactor.redact_http_body(
        BodyCapture::complete(br#"{"body_only":"body-secret","query_only":"visible-body"}"#),
        Some(&body_type),
    );
    assert!(!body.text().as_str().contains("body-secret"));
    assert!(body.text().as_str().contains("visible-body"));
}

#[test]
fn test_http_tiny_output_budget_marks_truncation_without_exposing_body() {
    let redactor = configured_redactor(|builder| {
        *builder = std::mem::take(builder)
            .limits(|limits| {
                limits.max_output_bytes(12);
            })
            .expect("limits setup must be valid");
    });
    let output = redactor.redact_http_body(
        BodyCapture::complete(br#"{"password":"raw-secret"}"#),
        Some(&HeaderValue::from_static("application/json")),
    );

    assert!(!output.text().as_str().contains("raw-secret"));
    assert_ne!(output.summary().completion(), RedactionCompletion::Complete);
    assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));

    let ndjson = redactor.redact_http_body(
        BodyCapture::complete(b"{\"password\":\"first-secret\"}\n{\"token\":\"second-secret\"}\n"),
        Some(&HeaderValue::from_static("application/x-ndjson")),
    );

    assert!(!ndjson.text().as_str().contains("first-secret"));
    assert!(!ndjson.text().as_str().contains("second-secret"));
    assert_ne!(ndjson.summary().completion(), RedactionCompletion::Complete);
    assert!(ndjson.summary().reasons().contains(RedactionReason::OutputLimitReached));

    let separator_limited = redactor.redact_http_body(
        BodyCapture::complete(b"{\"a\":\"bbbb\"}\n{}"),
        Some(&HeaderValue::from_static("application/x-ndjson")),
    );

    assert_ne!(separator_limited.summary().completion(), RedactionCompletion::Complete);
    assert!(
        separator_limited
            .summary()
            .reasons()
            .contains(RedactionReason::OutputLimitReached)
    );
}

#[test]
fn test_http_disabled_body_truncation_preserves_utf8_boundaries() {
    let policy = RedactionPolicy::disabled()
        .to_builder()
        .limits(|limits| {
            limits.max_output_bytes(15);
        })
        .expect("limits setup must be valid")
        .build()
        .expect("disabled policy must be valid");
    let output = Redactor::new(policy).redact_http_body(BodyCapture::complete("账户🔐visible".as_bytes()), None);

    assert_eq!(output.text().as_str(), "账<truncated>");
    assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);

    let policy = RedactionPolicy::disabled()
        .to_builder()
        .limits(|limits| {
            limits.max_output_bytes(10);
        })
        .expect("limits setup must be valid")
        .build()
        .expect("disabled policy must be valid");
    let exhausted = Redactor::new(policy).redact_http_body(BodyCapture::complete(b"visible diagnostic"), None);
    assert!(exhausted.text().as_str().is_empty());
    assert_eq!(exhausted.summary().completion(), RedactionCompletion::Exhausted);
}

#[test]
fn test_http_json_array_uses_safe_marker_when_source_exceeds_output() {
    let redactor = configured_redactor(|builder| {
        *builder = std::mem::take(builder)
            .limits(|limits| {
                limits.max_output_bytes(16);
            })
            .expect("limits setup must be valid");
    });
    let output = redactor.redact_http_body(
        BodyCapture::complete(br#"["public-value-that-does-not-fit"]"#),
        Some(&HeaderValue::from_static("application/json")),
    );

    assert_eq!(output.text().as_str(), "<truncated>");
    assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
    assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
}
