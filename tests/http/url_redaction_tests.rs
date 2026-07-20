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
use qubit_redact::http::HttpRedactor;
use qubit_redact::{
    RedactionPolicy,
    http::{
        HttpRedactionPolicy,
        UrlPathPolicy,
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
fn test_url_redaction_can_preserve_path_and_handles_urls_without_query() {
    let policy = HttpRedactionPolicy::builder(RedactionPolicy::default())
        .url_path_policy(UrlPathPolicy::Preserve)
        .build();
    let redactor = HttpRedactor::new(policy);

    assert_eq!(
        redactor
            .redact_url_str("https://example.test/public/path")
            .as_ref(),
        "https://example.test/public/path",
    );
    assert_eq!(redactor.policy().url_path_policy(), UrlPathPolicy::Preserve);
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
