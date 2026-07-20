// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`HttpHeaderSanitizer`](qubit_redact::HttpHeaderSanitizer).

use http::HeaderMap;
use http::header::{
    AUTHORIZATION,
    CONTENT_TYPE,
    COOKIE,
    HeaderName,
    HeaderValue,
    SET_COOKIE,
};
use proptest::prelude::{
    prop_assert,
    proptest,
};

use qubit_redact::{
    FieldSanitizer,
    HttpHeaderSanitizer,
    MaskPolicy,
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
            .sensitive_fields()
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

    assert_eq!(
        sanitizer.sanitize_value(&name, &value, NameMatchMode::Exact),
        "abcdef",
    );
}

#[test]
fn test_http_header_sanitizer_keeps_non_sensitive_header_value() {
    let sanitizer = HttpHeaderSanitizer::default();
    let value = HeaderValue::from_static("application/json");

    assert_eq!(
        sanitizer.sanitize_value(
            &CONTENT_TYPE,
            &value,
            NameMatchMode::ExactOrSuffix
        ),
        "application/json"
    );
}

#[test]
fn test_http_header_sanitizer_renders_non_utf8_header_value() {
    let sanitizer = HttpHeaderSanitizer::default();
    let name = HeaderName::from_static("x-binary");
    let value = HeaderValue::from_bytes(b"\xff")
        .expect("raw header bytes should be accepted");

    assert_eq!(
        sanitizer.sanitize_value(&name, &value, NameMatchMode::ExactOrSuffix),
        "<non-utf8>",
    );
}

#[test]
fn test_http_header_sanitizer_masks_sensitive_non_utf8_header_value() {
    let sanitizer = HttpHeaderSanitizer::default();
    let value = HeaderValue::from_bytes(b"\xff")
        .expect("raw header bytes should be accepted");

    assert_eq!(
        sanitizer.sanitize_value(
            &AUTHORIZATION,
            &value,
            NameMatchMode::ExactOrSuffix
        ),
        "****",
    );
}

#[test]
fn test_http_header_sanitizer_native_sensitive_value_uses_secret_mask() {
    let sanitizer = HttpHeaderSanitizer::default();
    let name = HeaderName::from_static("x-private-token");
    let mut value = HeaderValue::from_static("native-secret");
    value.set_sensitive(true);

    assert_eq!(
        sanitizer.sanitize_value(&name, &value, NameMatchMode::Exact),
        "<redacted>",
    );
}

#[test]
fn test_http_header_sanitizer_native_sensitive_value_uses_secret_policy() {
    let mut sanitizer = HttpHeaderSanitizer::default();
    sanitizer
        .field_sanitizer_mut()
        .policy_mut()
        .mask_policies_mut()
        .set(
            SensitivityLevel::Secret,
            MaskPolicy::fixed("<native-sensitive>"),
        );
    let name = HeaderName::from_static("x-private-token");
    let mut value = HeaderValue::from_static("native-secret");
    value.set_sensitive(true);

    assert_eq!(
        sanitizer.sanitize_value(&name, &value, NameMatchMode::Exact),
        "<native-sensitive>",
    );
}

#[test]
fn test_http_header_sanitizer_exclusion_does_not_override_native_sensitive() {
    let mut sanitizer = HttpHeaderSanitizer::default();
    sanitizer
        .field_sanitizer_mut()
        .exclude_sensitive_field("authorization");
    let mut value = HeaderValue::from_static("native-secret");
    value.set_sensitive(true);

    assert_eq!(
        sanitizer.sanitize_value(
            &AUTHORIZATION,
            &value,
            NameMatchMode::ExactOrSuffix,
        ),
        "<redacted>",
    );
}

#[test]
fn test_http_header_sanitizer_native_sensitive_flag_is_per_value() {
    let sanitizer = HttpHeaderSanitizer::default();
    let name = HeaderName::from_static("x-diagnostic-value");
    let mut headers = HeaderMap::new();
    headers.append(&name, HeaderValue::from_static("visible"));
    let mut secret = HeaderValue::from_static("native-secret");
    secret.set_sensitive(true);
    headers.append(&name, secret);

    let sanitized = sanitizer.sanitize_headers(&headers, NameMatchMode::Exact);

    assert_eq!(
        sanitized
            .get("x-diagnostic-value")
            .expect("header should be present"),
        &vec!["visible".to_string(), "<redacted>".to_string()],
    );
}

#[test]
fn test_http_header_sanitizer_native_sensitive_non_utf8_uses_secret_mask() {
    let sanitizer = HttpHeaderSanitizer::default();
    let name = HeaderName::from_static("x-binary");
    let mut value = HeaderValue::from_bytes(b"\xff")
        .expect("raw header bytes should be accepted");
    value.set_sensitive(true);

    assert_eq!(
        sanitizer.sanitize_value(&name, &value, NameMatchMode::Exact),
        "<redacted>",
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

    let sanitized =
        sanitizer.sanitize_headers(&headers, NameMatchMode::ExactOrSuffix);

    assert_eq!(
        sanitized
            .get("content-type")
            .expect("content-type should be present"),
        &vec!["application/json".to_string()],
    );
    assert_eq!(
        sanitized
            .get("set-cookie")
            .expect("set-cookie should be present"),
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

proptest! {
    #[test]
    fn test_http_header_sanitizer_proptest_never_leaks_sensitive_value(
        secret in "[A-Za-z0-9]{8,64}",
    ) {
        let sanitizer = HttpHeaderSanitizer::default();
        let value = HeaderValue::from_bytes(secret.as_bytes())
            .expect("generated header value should be valid");
        let sanitized = sanitizer.sanitize_value(
            &AUTHORIZATION,
            &value,
            NameMatchMode::ExactOrSuffix,
        );

        prop_assert!(!sanitized.contains(&secret));
    }

    #[test]
    fn test_http_header_sanitizer_proptest_native_sensitive_never_leaks(
        secret in "[A-Za-z0-9]{8,64}",
    ) {
        let sanitizer = HttpHeaderSanitizer::default();
        let name = HeaderName::from_static("x-diagnostic-value");
        let mut value = HeaderValue::from_bytes(secret.as_bytes())
            .expect("generated header value should be valid");
        value.set_sensitive(true);
        let sanitized = sanitizer.sanitize_value(
            &name,
            &value,
            NameMatchMode::Exact,
        );

        prop_assert!(!sanitized.contains(&secret));
    }
}
