// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`FormUrlEncodedSanitizer`](qubit_redact::FormUrlEncodedSanitizer).

use qubit_redact::{
    FieldSanitizer,
    FormUrlEncodedSanitizer,
    NameMatchMode,
    SensitivityLevel,
};

#[test]
fn test_form_urlencoded_sanitizer_field_sanitizer_accessors() {
    let mut sanitizer = FormUrlEncodedSanitizer::default();

    assert!(
        sanitizer
            .field_sanitizer()
            .policy()
            .sensitive_fields()
            .contains("password")
    );
    sanitizer
        .field_sanitizer_mut()
        .insert_sensitive_field("custom_field", SensitivityLevel::High);
    assert_eq!(
        sanitizer.sanitize_str(
            "custom_field=abcdef&mode=debug",
            NameMatchMode::ExactOrSuffix
        ),
        "custom_field=****&mode=debug",
    );
}

#[test]
fn test_form_urlencoded_sanitizer_masks_sensitive_fields() {
    let sanitizer = FormUrlEncodedSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_str(
            "username=alice&password=secret&openai_api_key=abcdef&empty=",
            NameMatchMode::ExactOrSuffix
        ),
        "username=alice&password=%3Credacted%3E&openai_api_key=****&empty=",
    );
}

#[test]
fn test_form_urlencoded_sanitizer_exact_mode_keeps_prefixed_fields() {
    let sanitizer = FormUrlEncodedSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_str("openai_api_key=abcdef", NameMatchMode::Exact),
        "openai_api_key=abcdef",
    );
}

#[test]
fn test_form_urlencoded_sanitizer_constructed_from_field_sanitizer() {
    let sanitizer = FormUrlEncodedSanitizer::new(FieldSanitizer::default());

    assert_eq!(
        sanitizer.sanitize_str("password=secret", NameMatchMode::ExactOrSuffix),
        "password=%3Credacted%3E",
    );
}
