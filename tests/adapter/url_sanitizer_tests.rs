// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`UrlSanitizer`](qubit_sanitize::UrlSanitizer).

use proptest::prelude::{
    prop_assert,
    proptest,
};

use qubit_sanitize::{
    FieldSanitizePolicy,
    FieldSanitizer,
    MaskPolicies,
    MaskPolicy,
    NameMatchMode,
    SensitivityLevel,
    UrlPathPolicy,
    UrlSanitizer,
};
use url::Url;

#[test]
fn test_url_sanitizer_field_sanitizer_accessors() {
    let mut sanitizer = UrlSanitizer::default();

    assert!(
        sanitizer
            .field_sanitizer()
            .policy()
            .sensitive_fields()
            .contains("access_token")
    );
    sanitizer.field_sanitizer_mut().insert_sensitive_field(
        "custom_query",
        qubit_sanitize::SensitivityLevel::High,
    );
    let url = Url::parse("https://example.com/?custom_query=abcdef&mode=debug")
        .expect("test URL should parse");

    assert_eq!(
        sanitizer.sanitize_url(&url, NameMatchMode::ExactOrSuffix),
        "https://example.com/?custom_query=****&mode=debug",
    );
}

#[test]
fn test_url_sanitizer_sanitize_url_masks_sensitive_components() {
    let sanitizer = UrlSanitizer::default();
    let url = Url::parse(
        "https://alice:secret@example.com/path?access_token=abcdef&mode=debug#session-fragment",
    )
    .expect("test URL should parse");

    assert_eq!(
        sanitizer.sanitize_url(&url, NameMatchMode::ExactOrSuffix),
        "https://****:%3Credacted%3E@example.com/path?access_token=****&mode=debug#****",
    );
}

#[test]
fn test_url_sanitizer_masks_signed_url_credentials() {
    let sanitizer = UrlSanitizer::default();
    let url = Url::parse(
        "https://example.com/object?X-Amz-Signature=aws-secret&X-Goog-Signature=google-secret&sig=azure-secret",
    )
    .expect("signed URL should parse");

    let sanitized = sanitizer.sanitize_url(&url, NameMatchMode::ExactOrSuffix);

    assert_eq!(
        sanitized,
        "https://example.com/object?X-Amz-Signature=%3Credacted%3E&X-Goog-Signature=%3Credacted%3E&sig=%3Credacted%3E",
    );
}

#[test]
fn test_url_sanitizer_uses_secret_policy_for_password() {
    let mut policies = MaskPolicies::default();
    policies.set(
        SensitivityLevel::High,
        MaskPolicy::preserve_edges(1, 1, "****", 0),
    );
    policies.set(SensitivityLevel::Secret, MaskPolicy::fixed("SECRET_MASK"));
    let sanitizer = UrlSanitizer::new(FieldSanitizer::new(
        FieldSanitizePolicy::default().with_mask_policies(policies),
    ));

    let sanitized = sanitizer
        .sanitize_url_str(
            "https://alice:password@example.test/path#fragment",
            NameMatchMode::Exact,
        )
        .expect("URL should parse");

    let sanitized = Url::parse(&sanitized).expect("sanitized URL should parse");
    assert_eq!(sanitized.username(), "a****e");
    assert_eq!(sanitized.password(), Some("SECRET_MASK"));
    assert_eq!(sanitized.fragment(), Some("f****t"));
    assert!(!sanitized.as_str().contains("password"));
}

#[test]
fn test_url_sanitizer_sanitize_url_str_parses_and_masks_prefixed_query_name() {
    let sanitizer = UrlSanitizer::default();

    assert_eq!(
        sanitizer
            .sanitize_url_str(
                "https://example.com/callback?openai_api_key=abcdef&state=ok",
                NameMatchMode::ExactOrSuffix
            )
            .expect("test URL should parse"),
        "https://example.com/callback?openai_api_key=****&state=ok",
    );
}

#[test]
fn test_url_sanitizer_sanitize_url_str_exact_mode_keeps_prefixed_query_name() {
    let sanitizer = UrlSanitizer::default();

    assert_eq!(
        sanitizer
            .sanitize_url_str(
                "https://example.com/callback?openai_api_key=abcdef&state=ok",
                NameMatchMode::Exact,
            )
            .expect("test URL should parse"),
        "https://example.com/callback?openai_api_key=abcdef&state=ok",
    );
}

#[test]
fn test_url_sanitizer_sanitize_url_str_reports_parse_error() {
    let sanitizer = UrlSanitizer::default();

    assert!(
        sanitizer
            .sanitize_url_str("not a url", NameMatchMode::ExactOrSuffix)
            .is_err()
    );
}

#[test]
fn test_url_sanitizer_sanitize_url_without_query() {
    let sanitizer = UrlSanitizer::default();
    let url =
        Url::parse("https://alice:secret@example.com/path#session-fragment")
            .expect("test URL should parse");

    assert_eq!(
        sanitizer.sanitize_url(&url, NameMatchMode::ExactOrSuffix),
        "https://****:%3Credacted%3E@example.com/path#****",
    );
}

#[test]
fn test_url_sanitizer_redacts_malformed_percent_encoded_query() {
    let sanitizer = UrlSanitizer::default();

    for query in [
        "%FFpassword=secret",
        "%ZZpassword=secret",
        "password=secret%",
    ] {
        let sanitized = sanitizer
            .sanitize_url_str(
                &format!("https://example.com/path?{query}"),
                NameMatchMode::ExactOrSuffix,
            )
            .expect("test URL should parse");
        assert_eq!(
            sanitized,
            "https://example.com/path?%3Credacted:%20invalid%20URL-encoded%20query%3E",
        );
        assert!(!sanitized.contains("secret"));
    }
}

#[test]
fn test_url_sanitizer_constructed_from_field_sanitizer() {
    let sanitizer = UrlSanitizer::new(FieldSanitizer::default());
    let url = Url::parse("https://example.com/?access_token=abcdef")
        .expect("test URL should parse");

    assert_eq!(
        sanitizer.sanitize_url(&url, NameMatchMode::ExactOrSuffix),
        "https://example.com/?access_token=****",
    );
}

#[test]
fn test_url_sanitizer_preserves_vendor_specific_secret_path() {
    let sanitizer = UrlSanitizer::default();
    let url = Url::parse(
        "https://hooks.example.com/services/T001/B001/path-secret?access_token=query-secret",
    )
    .expect("test URL should parse");

    assert_eq!(
        sanitizer.sanitize_url(&url, NameMatchMode::ExactOrSuffix),
        "https://hooks.example.com/services/T001/B001/path-secret?access_token=****",
    );
}

#[test]
fn test_url_sanitizer_redacts_path_and_masks_other_sensitive_components() {
    let sanitizer =
        UrlSanitizer::default().with_url_path_policy(UrlPathPolicy::Redact);
    let url = Url::parse(
        "https://alice:password@example.com/tenant/secret-id?access_token=query-secret#fragment-secret",
    )
    .expect("test URL should parse");

    assert_eq!(sanitizer.url_path_policy(), UrlPathPolicy::Redact);
    assert_eq!(
        sanitizer.sanitize_url(&url, NameMatchMode::ExactOrSuffix),
        "https://****:%3Credacted%3E@example.com/%3Credacted%3E?access_token=****#****",
    );
}

#[test]
fn test_url_sanitizer_url_path_policy_setter() {
    let mut sanitizer = UrlSanitizer::default();
    let url = Url::parse("https://example.com/tenant/secret-id")
        .expect("test URL should parse");

    sanitizer.set_url_path_policy(UrlPathPolicy::Redact);

    assert_eq!(sanitizer.url_path_policy(), UrlPathPolicy::Redact);
    assert_eq!(
        sanitizer.sanitize_url(&url, NameMatchMode::ExactOrSuffix),
        "https://example.com/%3Credacted%3E",
    );
}

proptest! {
    #[test]
    fn test_url_sanitizer_proptest_never_leaks_sensitive_query_value(
        secret in "[A-Za-z0-9]{8,64}",
    ) {
        let sanitizer = UrlSanitizer::default();
        let url = Url::parse(&format!(
            "https://example.com/callback?access_token={secret}",
        ))
        .expect("generated test URL should parse");
        let sanitized =
            sanitizer.sanitize_url(&url, NameMatchMode::ExactOrSuffix);

        prop_assert!(!sanitized.contains(&secret));
    }
}
