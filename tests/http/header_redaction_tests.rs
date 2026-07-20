// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

use http::{
    HeaderMap,
    HeaderValue,
    header::{
        AUTHORIZATION,
        CONTENT_TYPE,
        SET_COOKIE,
    },
};
use proptest::prelude::{
    prop_assert,
    proptest,
};
use qubit_redact::http::HttpRedactor;

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

#[test]
fn test_header_redaction_handles_non_utf8_and_control_characters() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-binary",
        HeaderValue::from_bytes(b"\xff")
            .expect("opaque header bytes are valid"),
    );
    headers.insert(
        "x-visible",
        HeaderValue::from_bytes(b"line\tvalue")
            .expect("tab is valid in a header value"),
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

proptest! {
    #[test]
    fn prop_header_name_policy_never_leaks_secret(
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

    #[test]
    fn prop_native_sensitive_header_never_leaks_secret(
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
