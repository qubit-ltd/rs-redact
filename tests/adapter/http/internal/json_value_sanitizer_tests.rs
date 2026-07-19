// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for JSON value sanitization through the public API.

use http::HeaderValue;

use qubit_sanitize::{
    BodySanitizationStatus,
    FieldSanitizePolicy,
    FieldSanitizer,
    HttpBodySanitizer,
    NameMatchMode,
    SensitivityLevel,
    UnkeyedJsonValuePolicy,
};

#[test]
fn test_json_value_sanitizer_tracks_nested_field_context() {
    let content_type = HeaderValue::from_static("application/json");
    let sanitizer = HttpBodySanitizer::default();

    let result = sanitizer.sanitize_body(
        br#"[{"items":["visible"]},["secret"],{"token":"abc"}]"#,
        Some(&content_type),
        NameMatchMode::Exact,
    );

    assert_eq!(
        result.content(),
        r#"[{"items":["visible"]},["<redacted: unkeyed JSON value>"],{"token":"****"}]"#,
    );
    assert_eq!(result.status(), BodySanitizationStatus::Sanitized);
}

#[test]
fn test_json_value_sanitizer_reports_unkeyed_pass_through() {
    let content_type = HeaderValue::from_static("application/json");
    let sanitizer = HttpBodySanitizer::default()
        .with_unkeyed_json_value_policy(UnkeyedJsonValuePolicy::PassThrough);

    let result = sanitizer.sanitize_body(
        br#"["diagnostic",{"message":"visible"}]"#,
        Some(&content_type),
        NameMatchMode::Exact,
    );

    assert_eq!(result.status(), BodySanitizationStatus::PassedThrough);
}

#[test]
fn test_json_value_sanitizer_masks_non_string_with_value_dependent_policy() {
    let content_type = HeaderValue::from_static("application/json");
    let mut policy = FieldSanitizePolicy::empty();
    policy.insert_sensitive_field("numeric", SensitivityLevel::Low);
    let sanitizer = HttpBodySanitizer::new(FieldSanitizer::new(policy));

    let result = sanitizer.sanitize_body(
        br#"{"numeric":123456}"#,
        Some(&content_type),
        NameMatchMode::Exact,
    );

    assert_eq!(result.content(), r#"{"numeric":"12****56"}"#);
    assert_eq!(result.status(), BodySanitizationStatus::Sanitized);
}
