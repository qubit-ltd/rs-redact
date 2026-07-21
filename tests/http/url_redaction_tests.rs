// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

use proptest::prelude::{
    prop_assert,
    prop_assert_eq,
    proptest,
};
use qubit_redact::{
    MaskPolicy,
    RedactionPolicy,
    Sensitivity,
    http::{
        HttpRedactionPolicy,
        HttpRedactor,
    },
};

#[test]
fn test_url_redaction_masks_components_and_query_values() {
    let result = HttpRedactor::default().redact_url_str(
        "https://alice:secret@example.test/private?openai_api_key=raw&mode=debug#secret-fragment",
    );

    assert!(!result.as_ref().contains("alice"));
    assert!(!result.as_ref().contains("secret"));
    assert!(!result.as_ref().contains("raw"));
    assert!(result.as_ref().contains("mode=debug"));
}

#[test]
fn test_url_and_form_redaction_fail_closed_on_malformed_input() {
    let redactor = HttpRedactor::default();

    assert_eq!(
        redactor.redact_url_str("not a URL").as_ref(),
        "<redacted: invalid URL>"
    );
    assert_eq!(
        redactor.redact_form("password=secret&bad=%").as_ref(),
        "<redacted: invalid URL-encoded form>",
    );
    let url = redactor
        .redact_url_str("https://example.test/private?password=secret&bad=%");
    assert!(!url.as_ref().contains("secret"));
    assert!(url.as_ref().contains("invalid%20URL-encoded%20query"));
}

#[test]
fn test_diagnostic_text_redaction_keeps_non_url_text() {
    let result = HttpRedactor::default()
        .redact_urls_in_text("opaque diagnostic message");

    assert_eq!(result.as_ref(), "opaque diagnostic message");
}

#[test]
fn test_diagnostic_text_redaction_masks_urls_and_preserves_punctuation() {
    let result = HttpRedactor::default().redact_urls_in_text(
        "failed near (https://alice:secret@example.test/private?password=raw), then HTTP://example.test/?access_token=query-secret!",
    );

    assert!(!result.as_ref().contains("alice"));
    assert!(!result.as_ref().contains("secret"));
    assert!(!result.as_ref().contains("raw"));
    assert!(!result.as_ref().contains("query-secret"));
    assert!(result.as_ref().contains("), then http://example.test/"));
    assert!(result.as_ref().ends_with('!'));
}

#[test]
fn test_diagnostic_text_redaction_masks_nested_url_in_same_token() {
    let result = HttpRedactor::default().redact_urls_in_text(
        "redirect=https://outer.test/?next=https://nested-user:nested-secret@inner.test/private",
    );

    assert!(!result.as_ref().contains("nested-user"));
    assert!(!result.as_ref().contains("nested-secret"));
    assert!(result.as_ref().contains("next=https://****:"));
}

#[test]
fn test_url_redaction_masks_percent_encoded_nested_url() {
    let result = HttpRedactor::default().redact_url_str(
        "https://outer.test/?next=https%3A%2F%2Fnested-user%3Anested-secret%40inner.test%2Fprivate",
    );

    assert!(!result.as_ref().contains("nested-user"));
    assert!(!result.as_ref().contains("nested-secret"));
    assert!(result.as_ref().contains("next=https%3A%2F%2F****%3A"));
}

#[test]
fn test_url_redaction_fails_closed_on_malformed_encoded_nested_url() {
    let result = HttpRedactor::default().redact_url_str(
        "https://outer.test/?next=https%253A%252F%252Fnested-user%253Anested-secret%2540inner.test%252Fprivate%25ZZ",
    );

    assert!(!result.as_ref().contains("nested-user"));
    assert!(!result.as_ref().contains("nested-secret"));
    assert!(result.as_ref().contains("invalid+URL"));
}

#[test]
fn test_url_redaction_preserves_non_url_percent_values() {
    let redactor = HttpRedactor::default();

    assert_eq!(
        redactor
            .redact_url_str("https://outer.test/?next=%25")
            .as_ref(),
        "https://outer.test/?next=%25",
    );
    assert_eq!(
        redactor
            .redact_url_str("https://outer.test/?next=h%25ZZ")
            .as_ref(),
        "https://outer.test/?next=h%25ZZ",
    );
}

#[test]
fn test_url_redaction_preserves_authoritative_mask_output() {
    let query_policy = RedactionPolicy::builder()
        .mask(
            Sensitivity::Secret,
            MaskPolicy::fixed("https://mask.invalid/private"),
        )
        .build()
        .expect("query policy should be valid");
    let policy = HttpRedactionPolicy::builder()
        .query_policy(query_policy)
        .build()
        .expect("HTTP policy should be valid");
    let result = HttpRedactor::new(policy)
        .redact_url_str("https://outer.test/?password=raw-secret");

    assert!(!result.as_ref().contains("raw-secret"));
    assert!(
        result
            .as_ref()
            .contains("password=https%3A%2F%2Fmask.invalid%2Fprivate"),
    );
}

#[test]
fn test_url_redaction_fails_closed_at_percent_decoding_limit() {
    let mut nested =
        "https://nested-user:nested-secret@inner.test/private".to_owned();
    for _ in 0..10 {
        nested = nested
            .replace('%', "%25")
            .replace(':', "%3A")
            .replace('/', "%2F")
            .replace('@', "%40");
    }
    let input = format!("https://outer.test/?next={nested}");
    let result = HttpRedactor::default().redact_url_str(&input);

    assert!(!result.as_ref().contains("nested-user"));
    assert!(!result.as_ref().contains("nested-secret"));
    assert!(
        result.as_ref().contains("nested+URL+limit+exceeded"),
        "unexpected redaction: {}",
        result.as_ref(),
    );
}

#[test]
fn test_url_redaction_fails_closed_at_nested_url_recursion_limit() {
    let mut nested =
        "https://deep-user:deep-secret@inner.test/private".to_owned();
    for layer in 0..10 {
        let encoded = nested
            .replace('%', "%25")
            .replace(':', "%3A")
            .replace('/', "%2F")
            .replace('@', "%40")
            .replace('?', "%3F")
            .replace('&', "%26")
            .replace('=', "%3D");
        nested = format!("https://layer-{layer}.test/?next={encoded}");
    }
    let result = HttpRedactor::default().redact_url_str(&nested);

    assert!(!result.as_ref().contains("deep-user"));
    assert!(!result.as_ref().contains("deep-secret"));
    assert!(
        result.as_ref().contains("nested")
            && result.as_ref().contains("limit")
            && result.as_ref().contains("exceeded"),
        "unexpected redaction: {}",
        result.as_ref(),
    );
}

#[test]
fn test_diagnostic_text_redaction_fails_closed_on_incomplete_url() {
    let result = HttpRedactor::default()
        .redact_urls_in_text("failed near https:// and plain text");

    assert_eq!(
        result.as_ref(),
        "failed near <redacted: invalid URL> and plain text",
    );
}

#[test]
fn test_diagnostic_text_redaction_keeps_balanced_ipv6_host_brackets() {
    let result =
        HttpRedactor::default().redact_urls_in_text("connect http://[::1]");

    assert_eq!(result.as_ref(), "connect http://[::1]/");
}

#[test]
fn test_diagnostic_text_redaction_preserves_long_unmatched_delimiter_suffix() {
    let suffix = ")".repeat(8_192);
    let input = format!("https://alice:secret@example.test/private{suffix}",);
    let result = HttpRedactor::default().redact_urls_in_text(&input);

    assert!(!result.as_ref().contains("alice"));
    assert!(!result.as_ref().contains("secret"));
    assert!(result.as_ref().ends_with(&suffix));
}

#[test]
fn test_diagnostic_text_redaction_escapes_log_controls_once() {
    let result = HttpRedactor::default().redact_urls_in_text(
        "first\tHTTP://alice:secret@example.test/path?password=raw\nsecond",
    );

    assert_eq!(
        result.as_ref(),
        "first\\thttp://****:%3Credacted%3E@example.test/%3Credacted%3E?password=%3Credacted%3E\\nsecond",
    );
}

proptest! {
    #[test]
    fn prop_url_redaction_never_leaks_sensitive_components(
        secret in "[A-Za-z0-9]{8,64}",
    ) {
        let input = format!(
            "https://{secret}:{secret}@example.test/{secret}?password={secret}#{secret}",
        );
        let result = HttpRedactor::default().redact_url_str(&input);

        prop_assert!(!result.as_ref().contains(&secret));
    }

    #[test]
    fn prop_url_and_form_redaction_are_deterministic(input in ".{0,128}") {
        let redactor = HttpRedactor::default();
        prop_assert_eq!(redactor.redact_form(&input), redactor.redact_form(&input));
        let url = format!("https://example.test/?{input}");
        prop_assert_eq!(redactor.redact_url_str(&url), redactor.redact_url_str(&url));
    }
}
