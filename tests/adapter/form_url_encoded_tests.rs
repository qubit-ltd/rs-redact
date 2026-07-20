// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for URL-encoded form sanitization behavior.

use proptest::prelude::{
    prop_assert,
    proptest,
};

use qubit_redact::{
    FormUrlEncodedSanitizer,
    NameMatchMode,
};

#[test]
fn test_form_urlencoded_sanitizer_preserves_duplicate_fields() {
    let sanitizer = FormUrlEncodedSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_str(
            "token=first&token=second&mode=debug",
            NameMatchMode::ExactOrSuffix
        ),
        "token=****&token=****&mode=debug",
    );
}

#[test]
fn test_form_urlencoded_sanitizer_sanitize_bytes() {
    let sanitizer = FormUrlEncodedSanitizer::default();

    assert_eq!(
        sanitizer.sanitize_bytes(
            b"password=secret&mode=debug",
            NameMatchMode::ExactOrSuffix
        ),
        "password=%3Credacted%3E&mode=debug",
    );
}

#[test]
fn test_form_urlencoded_sanitizer_redacts_malformed_percent_encoding() {
    let sanitizer = FormUrlEncodedSanitizer::default();

    for form in [
        b"%FFpassword=secret".as_slice(),
        b"%ZZpassword=secret",
        b"password=secret%",
    ] {
        let sanitized =
            sanitizer.sanitize_bytes(form, NameMatchMode::ExactOrSuffix);
        assert_eq!(sanitized, "<redacted: invalid URL-encoded form>");
        assert!(!sanitized.contains("secret"));
    }
}

proptest! {
    #[test]
    fn test_form_urlencoded_sanitizer_proptest_never_leaks_sensitive_value(
        secret in "[A-Za-z0-9]{8,64}",
    ) {
        let sanitizer = FormUrlEncodedSanitizer::default();
        let form = format!("password={secret}");
        let sanitized = sanitizer.sanitize_str(
            &form,
            NameMatchMode::ExactOrSuffix,
        );

        prop_assert!(!sanitized.contains(&secret));
    }
}
