// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`HttpBodySanitizer`](qubit_sanitize::HttpBodySanitizer).

use http::HeaderValue;
use proptest::{
    collection,
    prelude::{
        any,
        prop_assert,
        proptest,
    },
};

use qubit_sanitize::{
    BodySanitizationStatus,
    BodySourceLength,
    FieldSanitizePolicy,
    FieldSanitizer,
    HttpBodySanitizer,
    MaskPolicy,
    NameMatchMode,
    SensitivityLevel,
    UnkeyedJsonValuePolicy,
};

#[test]
fn test_http_body_sanitizer_field_sanitizer_accessors() {
    let mut sanitizer = HttpBodySanitizer::default();

    assert!(
        sanitizer
            .field_sanitizer()
            .policy()
            .sensitive_fields()
            .contains("password")
    );
    sanitizer
        .field_sanitizer_mut()
        .insert_sensitive_field("customer_id", SensitivityLevel::High);

    let content_type = HeaderValue::from_static("application/json");
    let sanitized = sanitizer.sanitize_body(
        br#"{"customerId":"C-001"}"#,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert_eq!(sanitized, r#"{"customerId":"****"}"#);
}

#[test]
fn test_http_body_sanitizer_sanitize_body_redacts_json_fields() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("application/json");

    let sanitized = sanitizer.sanitize_body(
        br#"{"user":"alice","password":"secret","nested":{"token":"abc"}}"#,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert_eq!(
        sanitized,
        r#"{"nested":{"token":"****"},"password":"<redacted>","user":"alice"}"#
    );
    assert!(!sanitized.contains("secret"));
    assert!(!sanitized.contains("abc"));
}

#[test]
fn test_http_body_sanitizer_fixed_policy_masks_non_string_json_values() {
    let mut policy = FieldSanitizePolicy::empty();
    policy.extend_sensitive_fields(
        ["numeric", "boolean", "array", "object", "nothing"],
        SensitivityLevel::High,
    );
    let sanitizer = HttpBodySanitizer::new(FieldSanitizer::new(policy));
    let content_type = HeaderValue::from_static("application/json");

    let sanitized = sanitizer
        .sanitize_body(
            br#"{"numeric":123,"boolean":true,"array":["leak"],"object":{"leak":"secret"},"nothing":null}"#,
            Some(&content_type),
            NameMatchMode::Exact,
        )
        .into_rendered();

    assert_eq!(
        sanitized,
        r#"{"array":"****","boolean":"****","nothing":"****","numeric":"****","object":"****"}"#,
    );
    assert!(!sanitized.contains("leak"));
    assert!(!sanitized.contains("secret"));
}

#[test]
fn test_http_body_sanitizer_empty_policy_masks_non_string_json_value() {
    let mut policy = FieldSanitizePolicy::empty();
    policy.insert_sensitive_field("payload", SensitivityLevel::High);
    policy
        .mask_policies_mut()
        .set(SensitivityLevel::High, MaskPolicy::empty());
    let sanitizer = HttpBodySanitizer::new(FieldSanitizer::new(policy));
    let content_type = HeaderValue::from_static("application/json");

    let sanitized = sanitizer
        .sanitize_body(
            br#"{"payload":{"leak":"secret"}}"#,
            Some(&content_type),
            NameMatchMode::Exact,
        )
        .into_rendered();

    assert_eq!(sanitized, r#"{"payload":""}"#);
}

#[test]
fn test_http_body_sanitizer_sanitize_body_redacts_json_arrays() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("application/json");

    let sanitized = sanitizer.sanitize_body(
        br#"[{"token":"abc"},{"nested":{"password":"secret"}}]"#,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert_eq!(
        sanitized,
        r#"[{"token":"****"},{"nested":{"password":"<redacted>"}}]"#
    );
    assert!(!sanitized.contains("abc"));
    assert!(!sanitized.contains("secret"));
}

#[test]
fn test_http_body_sanitizer_redacts_unkeyed_json_scalars_by_default() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("application/json");
    let marker = "<redacted: unkeyed JSON value>";
    let cases: &[(&[u8], &str)] = &[
        (br#""secret""#, r#""<redacted: unkeyed JSON value>""#),
        (b"42", r#""<redacted: unkeyed JSON value>""#),
        (b"true", r#""<redacted: unkeyed JSON value>""#),
        (b"null", r#""<redacted: unkeyed JSON value>""#),
        (
            br#"["secret",1,null]"#,
            r#"["<redacted: unkeyed JSON value>","<redacted: unkeyed JSON value>","<redacted: unkeyed JSON value>"]"#,
        ),
        (
            br#"[["secret"],{"token":"abc"}]"#,
            r#"[["<redacted: unkeyed JSON value>"],{"token":"****"}]"#,
        ),
    ];

    for (body, expected) in cases {
        let result = sanitizer.sanitize_body(
            body,
            Some(&content_type),
            NameMatchMode::ExactOrSuffix,
        );
        assert_eq!(result.content(), *expected);
        assert_eq!(result.status(), BodySanitizationStatus::Sanitized);
        assert!(!result.content().contains("secret"));
        assert!(result.content().contains(marker));
    }
}

#[test]
fn test_http_body_sanitizer_keeps_scalars_with_object_field_context() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("application/json");

    let result = sanitizer.sanitize_body(
        br#"{"items":["ok",1],"message":"visible"}"#,
        Some(&content_type),
        NameMatchMode::Exact,
    );

    assert_eq!(
        result.content(),
        r#"{"items":["ok",1],"message":"visible"}"#,
    );
    assert_eq!(result.status(), BodySanitizationStatus::Sanitized);
}

#[test]
fn test_http_body_sanitizer_reports_unkeyed_json_pass_through() {
    let sanitizer = HttpBodySanitizer::default()
        .with_unkeyed_json_value_policy(UnkeyedJsonValuePolicy::PassThrough);
    let content_type = HeaderValue::from_static("application/json");

    let result = sanitizer.sanitize_body(
        br#"["diagnostic",{"message":"visible"}]"#,
        Some(&content_type),
        NameMatchMode::Exact,
    );

    assert_eq!(result.content(), r#"["diagnostic",{"message":"visible"}]"#);
    assert_eq!(result.status(), BodySanitizationStatus::PassedThrough);
}

#[test]
fn test_http_body_sanitizer_exact_mode_keeps_prefixed_json_field() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("application/json");

    let sanitized = sanitizer.sanitize_body(
        br#"{"openaiApiKey":"secret-access","token":"abcdef"}"#,
        Some(&content_type),
        NameMatchMode::Exact,
    );
    let sanitized = sanitized.into_rendered();

    assert_eq!(
        sanitized,
        r#"{"openaiApiKey":"secret-access","token":"****"}"#,
    );
}

#[test]
fn test_http_body_sanitizer_sanitize_body_redacts_ndjson_fields() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("application/x-ndjson");

    let sanitized = sanitizer.sanitize_body(
        br#"{"token":"abc","id":1}

{"id":2}"#,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert_eq!(sanitized, "{\"id\":1,\"token\":\"****\"}\n\n{\"id\":2}");
    assert!(!sanitized.contains("abc"));
}

#[test]
fn test_http_body_sanitizer_redacts_unkeyed_ndjson_scalars_by_default() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("application/x-ndjson");

    let result = sanitizer.sanitize_body(
        b"\"secret\"\n[\"array-secret\"]\n{\"message\":\"visible\"}\n",
        Some(&content_type),
        NameMatchMode::Exact,
    );

    assert_eq!(
        result.content(),
        "\"<redacted: unkeyed JSON value>\"\n[\"<redacted: unkeyed JSON value>\"]\n{\"message\":\"visible\"}\n",
    );
    assert_eq!(result.status(), BodySanitizationStatus::Sanitized);
    assert!(!result.content().contains("secret"));
}

#[test]
fn test_http_body_sanitizer_sanitize_body_redacts_form_fields() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type =
        HeaderValue::from_static("application/x-www-form-urlencoded");

    let sanitized = sanitizer.sanitize_body(
        b"username=alice&password=secret&city=Shanghai",
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert_eq!(
        sanitized,
        "username=alice&password=%3Credacted%3E&city=Shanghai"
    );
    assert!(!sanitized.contains("secret"));
}

#[test]
fn test_http_body_sanitizer_sanitize_body_uses_custom_policy() {
    let mut policy = FieldSanitizePolicy::empty();
    policy.insert_sensitive_field("customer_id", SensitivityLevel::High);
    let sanitizer = HttpBodySanitizer::new(FieldSanitizer::new(policy));
    let content_type = HeaderValue::from_static("application/json");

    let sanitized = sanitizer.sanitize_body(
        br#"{"customer_id":"C-001","password":"kept"}"#,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert_eq!(sanitized, r#"{"customer_id":"****","password":"kept"}"#);
}

#[test]
fn test_http_body_sanitizer_sanitize_body_preview_adds_text_truncation_suffix()
{
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("text/plain");
    let body = b"hello world";
    let prefix = &body[..5];

    let sanitized = sanitizer.sanitize_body_preview(
        prefix,
        BodySourceLength::Known(body.len()),
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert_eq!(sanitized, "<redacted: text body>...<truncated 6 bytes>",);
}

#[test]
fn test_http_body_sanitizer_sanitize_body_renders_binary_body() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("application/octet-stream");

    let sanitized = sanitizer.sanitize_body(
        b"\xff\x00\x01",
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert_eq!(sanitized, "<binary 3 bytes>");
}

proptest! {
    #[test]
    fn test_http_body_sanitizer_proptest_never_leaks_structured_sensitive_value(
        secret in "[A-Za-z0-9]{8,64}",
    ) {
        let sanitizer = HttpBodySanitizer::default();
        let cases = [
            (
                format!(r#"{{"password":"{secret}"}}"#),
                HeaderValue::from_static("application/json"),
            ),
            (
                format!("{{\"password\":\"{secret}\"}}\n"),
                HeaderValue::from_static("application/x-ndjson"),
            ),
            (
                format!("password={secret}"),
                HeaderValue::from_static(
                    "application/x-www-form-urlencoded",
                ),
            ),
            (
                format!(
                    "--boundary\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n{secret}\r\n--boundary--\r\n",
                ),
                HeaderValue::from_static(
                    "multipart/form-data; boundary=boundary",
                ),
            ),
        ];

        for (body, content_type) in cases {
            let sanitized = sanitizer.sanitize_body(
                body.as_bytes(),
                Some(&content_type),
                NameMatchMode::ExactOrSuffix,
            );
            let sanitized = sanitized.into_rendered();
            prop_assert!(!sanitized.contains(&secret));
        }
    }

    #[test]
    fn test_http_body_sanitizer_proptest_handles_arbitrary_body(
        body in collection::vec(any::<u8>(), 0..512),
    ) {
        let sanitizer = HttpBodySanitizer::default();
        let content_types = [
            None,
            Some(HeaderValue::from_static("application/json")),
            Some(HeaderValue::from_static("application/x-ndjson")),
            Some(HeaderValue::from_static("application/x-www-form-urlencoded")),
            Some(HeaderValue::from_static("multipart/form-data; boundary=boundary")),
            Some(HeaderValue::from_static("text/plain")),
            Some(HeaderValue::from_static("application/octet-stream")),
        ];

        for content_type in &content_types {
            let _ = sanitizer.sanitize_body(
                &body,
                content_type.as_ref(),
                NameMatchMode::ExactOrSuffix,
            );
        }
    }
}

#[test]
fn test_http_body_sanitizer_sanitize_body_redacts_unsupported_utf8_body() {
    let sanitizer = HttpBodySanitizer::default();
    let content_type = HeaderValue::from_static("application/xml");

    let sanitized = sanitizer.sanitize_body(
        b"<password>secret</password>",
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert_eq!(sanitized, "<redacted: unsupported HTTP body>");
    assert!(!sanitized.contains("secret"));
}

#[test]
fn test_http_body_sanitizer_sanitize_body_redacts_utf8_body_without_content_type()
 {
    let sanitizer = HttpBodySanitizer::default();

    let sanitized = sanitizer.sanitize_body(
        b"password=secret",
        None,
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert_eq!(sanitized, "<redacted: unsupported HTTP body>");
    assert!(!sanitized.contains("secret"));
}

#[test]
fn test_http_body_sanitizer_constructed_from_field_sanitizer() {
    let sanitizer = HttpBodySanitizer::new(FieldSanitizer::default());
    let content_type = HeaderValue::from_static("application/json");

    let sanitized = sanitizer.sanitize_body(
        br#"{"token":"abcdef"}"#,
        Some(&content_type),
        NameMatchMode::ExactOrSuffix,
    );
    let sanitized = sanitized.into_rendered();

    assert_eq!(sanitized, r#"{"token":"****"}"#);
}
