/*******************************************************************************
 *
 *    Copyright (c) 2026 Haixing Hu.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    Licensed under the Apache License, Version 2.0.
 *
 ******************************************************************************/
//! Tests for [`UrlSanitizer`](qubit_sanitize::UrlSanitizer).

use qubit_sanitize::{
    FieldSanitizer,
    NameMatchMode,
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
            .sensitive_fields
            .contains("access_token")
    );
    sanitizer
        .field_sanitizer_mut()
        .insert_sensitive_field("custom_query", qubit_sanitize::SensitivityLevel::High);
    let url = Url::parse("https://example.com/?custom_query=abcdef&mode=debug").expect("test URL should parse");

    assert_eq!(
        sanitizer.sanitize_url(&url, NameMatchMode::ExactOrSuffix),
        "https://example.com/?custom_query=****&mode=debug",
    );
}

#[test]
fn test_url_sanitizer_sanitize_url_masks_sensitive_components() {
    let sanitizer = UrlSanitizer::default();
    let url = Url::parse("https://alice:secret@example.com/path?access_token=abcdef&mode=debug#session-fragment")
        .expect("test URL should parse");

    assert_eq!(
        sanitizer.sanitize_url(&url, NameMatchMode::ExactOrSuffix),
        "https://****:****@example.com/path?access_token=****&mode=debug#****",
    );
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
    let url = Url::parse("https://alice:secret@example.com/path#session-fragment").expect("test URL should parse");

    assert_eq!(
        sanitizer.sanitize_url(&url, NameMatchMode::ExactOrSuffix),
        "https://****:****@example.com/path#****",
    );
}

#[test]
fn test_url_sanitizer_constructed_from_field_sanitizer() {
    let sanitizer = UrlSanitizer::new(FieldSanitizer::default());
    let url = Url::parse("https://example.com/?access_token=abcdef").expect("test URL should parse");

    assert_eq!(
        sanitizer.sanitize_url(&url, NameMatchMode::ExactOrSuffix),
        "https://example.com/?access_token=****",
    );
}
