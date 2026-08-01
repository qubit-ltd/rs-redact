// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

use proptest::prelude::{prop_assert, prop_assert_eq, proptest};
use qubit_redact::{
    MaskPolicy, RedactionPolicy, Sensitivity,
    http::{DiagnosticBudget, HttpRedactionPolicy, HttpRedactor},
};
use url::Url;

/// Builds an HTTP redactor with explicit finite diagnostic limits.
fn redactor_with_diagnostic_budget(input: usize, output: usize) -> HttpRedactor {
    let budget = DiagnosticBudget::new(input, output)
        .expect("test diagnostic budgets satisfy the public lower bounds");
    let policy = HttpRedactionPolicy::empty_builder()
        .diagnostic_budget(budget)
        .build()
        .expect("HTTP redaction policy should be valid");
    HttpRedactor::new(policy)
}

/// Verifies every URL and form diagnostic entry rejects oversized input before
/// exposing any source prefix.
#[test]
fn test_url_and_form_diagnostics_fail_closed_at_input_limit() {
    let redactor = std::hint::black_box(redactor_with_diagnostic_budget(16, 128));
    let marker = "<redacted: diagnostic limit exceeded>";
    let url = Url::parse("https://example.test/?password=source-secret")
        .expect("the test URL should be valid");

    assert_eq!(redactor.redact_url(&url).as_ref(), marker);
    assert_eq!(
        redactor
            .redact_url_str("https://example.test/?password=source-secret",)
            .as_ref(),
        marker,
    );
    assert_eq!(
        redactor
            .redact_urls_in_text("failed at https://example.test/?password=source-secret",)
            .as_ref(),
        marker,
    );
    assert_eq!(
        redactor.redact_form("password=source-secret").as_ref(),
        marker,
    );
}

/// Verifies normal diagnostic text is escaped and truncated at a UTF-8
/// boundary under the configured output limit.
#[test]
fn test_diagnostic_output_budget_is_log_safe_and_utf8_bounded() {
    let output_limit = DiagnosticBudget::MIN_OUTPUT_BYTES + 5;
    let redactor = redactor_with_diagnostic_budget(128, output_limit);
    let result = redactor.redact_urls_in_text("你\n你你你你你你你你你你你你你你你");

    assert!(result.as_ref().len() <= output_limit);
    assert!(result.as_ref().ends_with("<truncated>"));
    assert!(!result.as_ref().contains('\n'));
    assert!(std::str::from_utf8(result.as_ref().as_bytes()).is_ok());
}

#[test]
/// Verifies that url redaction masks components and query values.
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
/// Verifies that url and form redaction fail closed on malformed input.
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
    let url = redactor.redact_url_str("https://example.test/private?password=secret&bad=%");
    assert!(!url.as_ref().contains("secret"));
    assert!(url.as_ref().contains("invalid%20URL-encoded%20query"));
}

#[test]
/// Verifies that diagnostic text redaction keeps non url text.
fn test_diagnostic_text_redaction_keeps_non_url_text() {
    let result = HttpRedactor::default().redact_urls_in_text("opaque diagnostic message");

    assert_eq!(result.as_ref(), "opaque diagnostic message");
}

#[test]
/// Verifies that diagnostic text redaction masks urls and preserves
/// punctuation.
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
/// Verifies that diagnostic text redaction handles overlapping schemes and
/// braces.
fn test_diagnostic_text_redaction_handles_overlapping_schemes_and_braces() {
    let result = HttpRedactor::default()
        .redact_urls_in_text("http://example.test/https://nested.test/{visible}}");

    assert!(result.as_ref().ends_with('}'));
    assert!(result.as_ref().contains("http://example.test/"));
}

#[test]
/// Verifies that diagnostic text redaction masks nested url in same token.
fn test_diagnostic_text_redaction_masks_nested_url_in_same_token() {
    let result = HttpRedactor::default().redact_urls_in_text(
        "redirect=https://outer.test/?next=https://nested-user:nested-secret@inner.test/private",
    );

    assert!(!result.as_ref().contains("nested-user"));
    assert!(!result.as_ref().contains("nested-secret"));
    assert!(result.as_ref().contains("next=https://****:"));
}

#[test]
/// Verifies that url redaction masks percent encoded nested url.
fn test_url_redaction_masks_percent_encoded_nested_url() {
    let result = HttpRedactor::default().redact_url_str(
        "https://outer.test/?next=https%3A%2F%2Fnested-user%3Anested-secret%40inner.test%2Fprivate",
    );

    assert!(!result.as_ref().contains("nested-user"));
    assert!(!result.as_ref().contains("nested-secret"));
    assert!(result.as_ref().contains("next=https%3A%2F%2F****%3A"));
}

#[test]
/// Verifies that url redaction fails closed on malformed encoded nested url.
fn test_url_redaction_fails_closed_on_malformed_encoded_nested_url() {
    let result = HttpRedactor::default().redact_url_str(
        "https://outer.test/?next=https%253A%252F%252Fnested-user%253Anested-secret%2540inner.test%252Fprivate%25ZZ",
    );

    assert!(!result.as_ref().contains("nested-user"));
    assert!(!result.as_ref().contains("nested-secret"));
    assert!(result.as_ref().contains("invalid+URL"));
}

#[test]
/// Verifies that url redaction preserves non url percent values.
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
/// Verifies that nested url detection covers malformed and bounded decoding.
fn test_nested_url_detection_covers_malformed_and_bounded_decoding() {
    let redactor = HttpRedactor::default();
    let inputs = [
        "https://outer.test/?next=http://",
        "https://outer.test/?next=http%253A%252F%25",
        "https://outer.test/?next=%25FF",
        "https://outer.test/?next=%25FF%25",
        "https://outer.test/?next=http%253a%252f%252finner.test",
    ];

    for input in inputs {
        let result = redactor.redact_url_str(input);
        assert!(!result.as_ref().is_empty());
    }

    let mut non_url = "%3A".to_owned();
    for _ in 0..7 {
        non_url = non_url.replace('%', "%25");
    }
    let result = redactor.redact_url_str(&format!("https://outer.test/?next={non_url}",));
    assert!(result.as_ref().contains("next="));
}

#[test]
/// Verifies that url redaction preserves authoritative mask output.
fn test_url_redaction_preserves_authoritative_mask_output() {
    let query_policy = RedactionPolicy::empty_builder()
        .disable_floor()
        .raise("password", Sensitivity::Secret)
        .mask(
            Sensitivity::Secret,
            MaskPolicy::fixed("https://mask.invalid/private"),
        )
        .build()
        .expect("query policy should be valid");
    let policy = HttpRedactionPolicy::empty_builder()
        .query_rules(query_policy.rules().clone())
        .disable_query_floor()
        .build()
        .expect("HTTP policy should be valid");
    let result =
        HttpRedactor::new(policy).redact_url_str("https://outer.test/?password=raw-secret");

    assert!(!result.as_ref().contains("raw-secret"));
    assert!(
        result
            .as_ref()
            .contains("password=https%3A%2F%2Fmask.invalid%2Fprivate"),
    );
}

#[test]
/// Verifies that url redaction fails closed at percent decoding limit.
fn test_url_redaction_fails_closed_at_percent_decoding_limit() {
    let mut nested = "https://nested-user:nested-secret@inner.test/private".to_owned();
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
/// Verifies that url redaction fails closed at nested url recursion limit.
fn test_url_redaction_fails_closed_at_nested_url_recursion_limit() {
    let mut nested = "https://deep-user:deep-secret@inner.test/private".to_owned();
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
/// Verifies that diagnostic text redaction fails closed on incomplete url.
fn test_diagnostic_text_redaction_fails_closed_on_incomplete_url() {
    let result = HttpRedactor::default().redact_urls_in_text("failed near https:// and plain text");

    assert_eq!(
        result.as_ref(),
        "failed near <redacted: invalid URL> and plain text",
    );
}

#[test]
/// Verifies that diagnostic text redaction keeps balanced ipv6 host brackets.
fn test_diagnostic_text_redaction_keeps_balanced_ipv6_host_brackets() {
    let result = HttpRedactor::default().redact_urls_in_text("connect http://[::1]");

    assert_eq!(result.as_ref(), "connect http://[::1]/");
}

#[test]
/// Verifies that diagnostic text redaction preserves long unmatched delimiter
/// suffix.
fn test_diagnostic_text_redaction_preserves_long_unmatched_delimiter_suffix() {
    let suffix = ")".repeat(8_192);
    let input = format!("https://alice:secret@example.test/private{suffix}",);
    let result = HttpRedactor::default().redact_urls_in_text(&input);

    assert!(!result.as_ref().contains("alice"));
    assert!(!result.as_ref().contains("secret"));
    assert!(result.as_ref().ends_with(&suffix));
}

#[test]
/// Verifies that diagnostic text redaction escapes log controls once.
fn test_diagnostic_text_redaction_escapes_log_controls_once() {
    let result = HttpRedactor::default()
        .redact_urls_in_text("first\tHTTP://alice:secret@example.test/path?password=raw\nsecond");

    assert_eq!(
        result.as_ref(),
        "first\\thttp://****:%3Credacted%3E@example.test/%3Credacted%3E?password=%3Credacted%3E\\nsecond",
    );
}

proptest! {
    #[test]
    /// Checks across generated inputs that url redaction never leaks sensitive components.
    fn test_url_redaction_never_leaks_sensitive_components(
        secret in "[A-Za-z0-9]{8,64}",
    ) {
        let input = format!(
            "https://{secret}:{secret}@example.test/{secret}?password={secret}#{secret}",
        );
        let result = HttpRedactor::default().redact_url_str(&input);

        prop_assert!(!result.as_ref().contains(&secret));
    }

    #[test]
    /// Checks across generated inputs that url and form redaction are deterministic.
    fn test_url_and_form_redaction_are_deterministic(input in ".{0,128}") {
        let redactor = HttpRedactor::default();
        prop_assert_eq!(redactor.redact_form(&input), redactor.redact_form(&input));
        let url = format!("https://example.test/?{input}");
        prop_assert_eq!(redactor.redact_url_str(&url), redactor.redact_url_str(&url));
    }
}
