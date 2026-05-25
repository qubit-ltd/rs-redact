/*******************************************************************************
 *
 *    Copyright (c) 2026 Haixing Hu.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    Licensed under the Apache License, Version 2.0.
 *
 ******************************************************************************/
//! Tests for [`HttpHeaderSanitizer`](qubit_sanitize::HttpHeaderSanitizer).

use http::HeaderMap;
use http::header::{
    AUTHORIZATION,
    CONTENT_TYPE,
    COOKIE,
    HeaderName,
    HeaderValue,
    SET_COOKIE,
};

use qubit_sanitize::{
    FieldSanitizer,
    HttpHeaderSanitizer,
    NameMatchMode,
    SensitivityLevel,
};

#[test]
fn test_http_header_sanitizer_field_sanitizer_accessors() {
    let mut sanitizer = HttpHeaderSanitizer::default();

    assert!(
        sanitizer
            .field_sanitizer()
            .policy()
            .sensitive_fields
            .contains("authorization")
    );
    sanitizer
        .field_sanitizer_mut()
        .insert_sensitive_field("x_custom_token", SensitivityLevel::High);

    let name = HeaderName::from_static("x-custom-token");
    let value = HeaderValue::from_static("abcdef");

    assert_eq!(
        sanitizer.sanitize_value(&name, &value, NameMatchMode::ExactOrSuffix),
        "****",
    );
}

#[test]
fn test_http_header_sanitizer_masks_sensitive_header_value() {
    let sanitizer = HttpHeaderSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_value(
            &AUTHORIZATION,
            &HeaderValue::from_static("Bearer abcdef"),
            NameMatchMode::ExactOrSuffix,
        ),
        "****",
    );

    let name = HeaderName::from_static("x-openai-api-key");
    let value = HeaderValue::from_static("abcdef");

    assert_eq!(
        sanitizer.sanitize_value(&name, &value, NameMatchMode::ExactOrSuffix),
        "****",
    );
}

#[test]
fn test_http_header_sanitizer_exact_mode_keeps_prefixed_header_name() {
    let sanitizer = HttpHeaderSanitizer::default();
    let name = HeaderName::from_static("x-openai-api-key");
    let value = HeaderValue::from_static("abcdef");

    assert_eq!(sanitizer.sanitize_value(&name, &value, NameMatchMode::Exact), "abcdef",);
}

#[test]
fn test_http_header_sanitizer_keeps_non_sensitive_header_value() {
    let sanitizer = HttpHeaderSanitizer::default();
    let value = HeaderValue::from_static("application/json");

    assert_eq!(
        sanitizer.sanitize_value(&CONTENT_TYPE, &value, NameMatchMode::ExactOrSuffix),
        "application/json"
    );
}

#[test]
fn test_http_header_sanitizer_renders_non_utf8_header_value() {
    let sanitizer = HttpHeaderSanitizer::default();
    let name = HeaderName::from_static("x-binary");
    let value = HeaderValue::from_bytes(b"\xff").expect("raw header bytes should be accepted");

    assert_eq!(
        sanitizer.sanitize_value(&name, &value, NameMatchMode::ExactOrSuffix),
        "<non-utf8>",
    );
}

#[test]
fn test_http_header_sanitizer_masks_sensitive_non_utf8_header_value() {
    let sanitizer = HttpHeaderSanitizer::default();
    let value = HeaderValue::from_bytes(b"\xff").expect("raw header bytes should be accepted");

    assert_eq!(
        sanitizer.sanitize_value(&AUTHORIZATION, &value, NameMatchMode::ExactOrSuffix),
        "****",
    );
}

#[test]
fn test_http_header_sanitizer_sanitize_pair_preserves_name() {
    let sanitizer = HttpHeaderSanitizer::default();
    let value = HeaderValue::from_static("sid=abcdef");

    assert_eq!(
        sanitizer.sanitize_pair(&COOKIE, &value, NameMatchMode::ExactOrSuffix),
        ("cookie".to_string(), "****".to_string()),
    );
}

#[test]
fn test_http_header_sanitizer_sanitize_headers_groups_values() {
    let sanitizer = HttpHeaderSanitizer::default();
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.append(SET_COOKIE, HeaderValue::from_static("sid=abcdef"));
    headers.append(SET_COOKIE, HeaderValue::from_static("theme=light"));

    let sanitized = sanitizer.sanitize_headers(&headers, NameMatchMode::ExactOrSuffix);

    assert_eq!(
        sanitized.get("content-type").expect("content-type should be present"),
        &vec!["application/json".to_string()],
    );
    assert_eq!(
        sanitized.get("set-cookie").expect("set-cookie should be present"),
        &vec!["****".to_string(), "****".to_string()],
    );
}

#[test]
fn test_http_header_sanitizer_constructed_from_field_sanitizer() {
    let sanitizer = HttpHeaderSanitizer::new(FieldSanitizer::default());

    assert_eq!(
        sanitizer.sanitize_value(
            &AUTHORIZATION,
            &HeaderValue::from_static("Bearer abcdef"),
            NameMatchMode::ExactOrSuffix,
        ),
        "****",
    );
}
