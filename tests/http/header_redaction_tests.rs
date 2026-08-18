// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

use http::HeaderMap;
use http::HeaderValue;
use http::header::AUTHORIZATION;
use http::header::CONTENT_TYPE;
use http::header::SET_COOKIE;
use proptest::prelude::prop_assert;
use proptest::prelude::proptest;
use qubit_redact::RedactionPolicy;
use qubit_redact::formats::http::HttpRedactor;
use qubit_redact::formats::http::InputOutputLimit;
/// Builds an HTTP redactor with visible test headers and finite diagnostics.
fn redactor_with_diagnostic_budget(input: usize, output: usize) -> HttpRedactor {
    let header_policy = RedactionPolicy::builder()
        .build()
        .expect("the empty header policy should be valid");
    let budget = InputOutputLimit::builder()
        .max_input_bytes(input)
        .max_output_bytes(output)
        .build()
        .expect("test diagnostic budgets satisfy the public lower bounds");
    let mut builder = RedactionPolicy::builder();
    builder.http().header().replace_rules(header_policy.rules().clone());
    builder.limits().diagnostic_event(budget);
    let policy = builder.build().expect("the HTTP policy should be valid");
    HttpRedactor::new(policy)
}

/// Verifies that header redaction groups duplicates deterministically.
#[test]
fn test_header_redaction_groups_duplicates_deterministically() {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.append(SET_COOKIE, HeaderValue::from_static("sid=secret"));
    headers.append(SET_COOKIE, HeaderValue::from_static("theme=light"));

    let rendered = HttpRedactor::default().redact_headers(&headers).to_string();

    assert!(rendered.contains("content-type: [application/json]"));
    assert!(!rendered.contains("sid=secret"));
    assert!(!rendered.contains("theme=light"));
}

/// Verifies that header redaction handles non utf8 and control characters.
#[test]
fn test_header_redaction_handles_non_utf8_and_control_characters() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-binary",
        HeaderValue::from_bytes(b"\xff").expect("opaque header bytes are valid"),
    );
    headers.insert(
        "x-visible",
        HeaderValue::from_bytes(b"line\tvalue").expect("tab is valid in a header value"),
    );
    headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer raw"));

    let result = HttpRedactor::default().redact_headers(&headers);
    let rendered = result.to_string();

    assert!(rendered.contains("<non-utf8>"));
    assert!(rendered.contains(r"line\tvalue"));
    assert!(!rendered.contains('\t'));
    assert!(!rendered.contains("Bearer raw"));
    assert!(!format!("{result:?}").contains("Bearer raw"));
    assert_eq!(result.log_safe_text().as_ref(), rendered);
    assert_eq!(result.into_log_safe_text().as_ref(), rendered);
}

/// Verifies oversized headers return only the fixed diagnostic-limit marker.
#[test]
fn test_header_redaction_fails_closed_at_input_limit() {
    let redactor = redactor_with_diagnostic_budget(8, 128);
    let mut headers = HeaderMap::new();
    headers.insert("x-secret", HeaderValue::from_static("source-secret"));

    assert_eq!(
        redactor.redact_headers(&headers).to_string(),
        "<redacted: diagnostic limit exceeded>",
    );
}

/// Verifies bounded header rendering keeps sorted names and duplicate order.
#[test]
fn test_header_redaction_is_sorted_stable_and_output_bounded() {
    let redactor = redactor_with_diagnostic_budget(256, 256);
    let mut headers = HeaderMap::new();
    headers.append("x-zeta", HeaderValue::from_static("first"));
    headers.append("x-alpha", HeaderValue::from_static("visible"));
    headers.append("x-zeta", HeaderValue::from_static("second"));

    assert_eq!(
        redactor.redact_headers(&headers).to_string(),
        r"x-alpha: [visible]\nx-zeta: [first, second]",
    );

    let bounded = redactor_with_diagnostic_budget(256, InputOutputLimit::MIN_OUTPUT_BYTES + 4)
        .redact_headers(&headers)
        .to_string();
    assert!(bounded.len() <= InputOutputLimit::MIN_OUTPUT_BYTES + 4,);
    assert!(bounded.ends_with("<truncated>"));
}

/// Verifies an exactly full payload still marks an omitted closing delimiter.
#[test]
fn test_header_redaction_marks_truncation_after_exact_payload_boundary() {
    let output_limit = 40;
    let redactor = redactor_with_diagnostic_budget(256, output_limit);
    let mut headers = HeaderMap::new();
    headers.insert("x-a", HeaderValue::from_static("1234567890123456789012345678901234"));

    let rendered = redactor.redact_headers(&headers).to_string();

    assert!(rendered.len() <= output_limit, "{rendered:?}");
    assert!(rendered.ends_with("<truncated>"), "{rendered:?}");
}

proptest! {
    /// Checks across generated inputs that header name policy never leaks secret.
    #[test]
    fn test_header_name_policy_never_leaks_secret(
        secret in "[A-Za-z0-9]{8,64}",
    ) {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_bytes(secret.as_bytes())
                .expect("generated alphanumeric header value is valid"),
        );

        let rendered = HttpRedactor::default().redact_headers(&headers).to_string();

        prop_assert!(!rendered.contains(&secret));
    }

    /// Checks across generated inputs that native sensitive header never leaks secret.
    #[test]
    fn test_native_sensitive_header_never_leaks_secret(
        secret in "[A-Za-z0-9]{8,64}",
    ) {
        let mut value = HeaderValue::from_bytes(secret.as_bytes())
            .expect("generated alphanumeric header value is valid");
        value.set_sensitive(true);
        let mut headers = HeaderMap::new();
        headers.insert("x-diagnostic-value", value);

        let rendered = HttpRedactor::default().redact_headers(&headers).to_string();

        prop_assert!(!rendered.contains(&secret));
    }
}
