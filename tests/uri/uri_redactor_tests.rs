// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Integration tests for policy-driven URI redaction.

use qubit_redact::{
    InputOutputLimit,
    LogSafeText,
    MaskPolicy,
    RedactionPolicy,
    RedactionSession,
    Sensitivity,
    UriFragmentPolicy,
    UriPathPolicy,
    UriRedactionReason,
    UriRedactionStatus,
    UriRedactor,
};

/// Verifies repeated URI session fallbacks never exceed the cumulative output
/// limit, including when insufficient bytes remain for another complete marker.
#[test]
fn test_uri_session_fallbacks_respect_cumulative_output_limit() {
    let budget = InputOutputLimit::new(8, InputOutputLimit::MIN_OUTPUT_BYTES)
        .expect("the marker-sized diagnostic budget should be valid");
    let policy = RedactionPolicy::builder()
        .diagnostic_event(budget)
        .build()
        .expect("URI policy should be valid");
    let redactor = UriRedactor::new(policy);
    let session = RedactionSession::diagnostic(redactor.policy());

    let rendered: Vec<_> = (0..4)
        .map(|_| {
            redactor
                .redact_uri_str_with_session(
                    "https://example.test/?password=secret",
                    &session,
                )
                .into_log_safe_text()
                .into_owned()
        })
        .collect();

    assert_eq!(rendered[0], "<invalid URI>");
    assert_eq!(rendered[1], "<invalid URI>");
    assert!(rendered[2].is_empty());
    assert!(rendered[3].is_empty());
    assert!(
        rendered.iter().map(String::len).sum::<usize>()
            <= budget.max_output_bytes()
    );
}

/// Verifies that the default URI policy exposes usernames but masks passwords.
#[test]
fn test_uri_redactor_redacts_password_but_preserves_username() {
    let redactor = UriRedactor::default();
    assert_eq!(format!("{redactor}"), "UriRedactor");
    assert_eq!(redactor.policy(), &RedactionPolicy::default());
    let result = redactor.redact_uri_str(
        "https://alice:secret@example.test/private?password=raw#fragment",
    );

    assert_eq!(
        result.log_safe_text().as_str(),
        "https://alice:%3Credacted%3E@example.test/private?password=%3Credacted%3E#****",
    );
    assert_eq!(result.status(), UriRedactionStatus::Redacted);
    assert!(
        result.has_sensitive_component(qubit_redact::UriComponent::Password)
    );
    assert!(result.has_sensitive_component(qubit_redact::UriComponent::Query));
    assert!(
        result.has_sensitive_component(qubit_redact::UriComponent::Fragment)
    );
}

/// Verifies username and password use independent core field rules.
#[test]
fn test_uri_redactor_applies_username_policy_and_keeps_encoded_colon() {
    let core = RedactionPolicy::builder()
        .disable_floor()
        .raise("username", Sensitivity::Secret)
        .expect("username rule is valid")
        .raise("password", Sensitivity::Secret)
        .expect("password rule is valid")
        .allow_canonical_exact("username")
        .expect("username allow rule is valid")
        .build()
        .expect("core policy is valid");
    let policy = RedactionPolicy::builder_from(&core)
        .build()
        .expect("URI policy is valid");

    let result = UriRedactor::new(policy)
        .redact_uri_str("https://alice%3Ateam:secret@example.test/private");

    assert_eq!(
        result.log_safe_text().as_str(),
        "https://alice%3Ateam:%3Credacted%3E@example.test/private",
    );
    assert_eq!(result.status(), UriRedactionStatus::Redacted);
    assert!(
        result.has_sensitive_component(qubit_redact::UriComponent::Password)
    );
    assert!(
        !result.has_sensitive_component(qubit_redact::UriComponent::Username)
    );
}

/// Verifies query values are decoded before masking and raw order is retained.
#[test]
fn test_uri_redactor_masks_query_after_decoding_and_preserves_order() {
    let core = RedactionPolicy::builder()
        .disable_floor()
        .raise("token", Sensitivity::High)
        .expect("token rule is valid")
        .mask(Sensitivity::High, MaskPolicy::fixed("x y"))
        .expect("mask policy is valid")
        .build()
        .expect("core policy is valid");
    let policy = RedactionPolicy::builder_from(&core)
        .build()
        .expect("URI policy is valid");

    let result = UriRedactor::new(policy).redact_uri_str(
        "https://example.test/path?keep=a%2Fb&token=hello%20world&keep=last",
    );

    assert_eq!(
        result.log_safe_text().as_str(),
        "https://example.test/path?keep=a%2Fb&token=x%20y&keep=last",
    );
    assert_eq!(result.status(), UriRedactionStatus::Redacted);
    assert!(result.has_sensitive_component(qubit_redact::UriComponent::Query));
}

/// Verifies malformed syntax and undecodable query keys fail closed.
#[test]
fn test_uri_redactor_fails_closed_for_invalid_uri_and_query_key_utf8() {
    let redactor = UriRedactor::default();
    let malformed = redactor.redact_uri_str("https://[invalid");
    assert_eq!(malformed.log_safe_text().as_str(), "<invalid URI>");
    assert_eq!(malformed.status(), UriRedactionStatus::Invalid);
    assert!(malformed.has_reason(UriRedactionReason::InvalidUri));

    let invalid_key =
        redactor.redact_uri_str("https://example.test/?%FF=secret");
    assert_eq!(invalid_key.log_safe_text().as_str(), "<invalid URI>");
    assert_eq!(invalid_key.status(), UriRedactionStatus::Invalid);
    assert!(invalid_key.has_reason(UriRedactionReason::UndecodableQueryKey));
}

/// Verifies path and fragment visibility are independently configurable.
#[test]
fn test_uri_redaction_policy_configures_path_and_fragment_boundaries() {
    let policy = RedactionPolicy::builder()
        .path_policy(UriPathPolicy::Redact)
        .fragment_policy(UriFragmentPolicy::Preserve)
        .build()
        .expect("URI policy is valid");
    let result = UriRedactor::new(policy)
        .redact_uri_str("https://example.test/private/path#debug");

    assert_eq!(
        result.log_safe_text().as_str(),
        "https://example.test/%3Credacted%3E#debug",
    );
    assert!(result.has_sensitive_component(qubit_redact::UriComponent::Path));
    assert!(
        !result.has_sensitive_component(qubit_redact::UriComponent::Fragment)
    );
}

/// Verifies consuming a URI result preserves the typed log-safe boundary.
#[test]
fn test_uri_redaction_consuming_text_preserves_safe_type() {
    let text: LogSafeText<'static> = UriRedactor::default()
        .redact_uri_str("https://example.test/?password=secret")
        .into_log_safe_text();
    assert_eq!(
        text.as_str(),
        "https://example.test/?password=%3Credacted%3E"
    );
}

/// Verifies later malformed query fields are still validated after truncation.
#[test]
fn test_uri_redactor_validates_after_output_truncation() {
    let core = RedactionPolicy::default()
        .to_builder()
        .diagnostic_event(
            InputOutputLimit::new(4096, 64)
                .expect("the diagnostic budget is valid"),
        )
        .build()
        .expect("the core policy is valid");
    let policy = RedactionPolicy::builder_from(&core)
        .build()
        .expect("the URI policy is valid");
    let redactor = UriRedactor::new(policy);
    let input = format!(
        "https://example.test/?password={}&bad=%FF",
        "secret".repeat(32),
    );
    let result = redactor.redact_uri_str(&input);
    assert_eq!(result.status(), UriRedactionStatus::Invalid);
    assert!(result.has_reason(UriRedactionReason::UndecodableQueryValue));
    assert_eq!(result.log_safe_text().as_str(), "<invalid URI>");
}

/// Verifies URI component branches fail closed and continue validating safely.
#[test]
fn test_uri_redactor_covers_authority_query_and_input_boundaries() {
    let redactor = UriRedactor::default();
    assert_eq!(
        redactor.redact_uri_str("https://example.test/").status(),
        UriRedactionStatus::PassedThrough,
    );
    assert_eq!(
        redactor.redact_uri_str("urn:path").log_safe_text().as_str(),
        "urn:path",
    );
    let path_redacted = UriRedactor::new(
        RedactionPolicy::builder()
            .path_policy(UriPathPolicy::Redact)
            .build()
            .expect("the path policy is valid"),
    );
    assert_eq!(
        path_redacted
            .redact_uri_str("urn:path")
            .log_safe_text()
            .as_str(),
        "urn:%3Credacted%3E",
    );
    assert_eq!(
        redactor
            .redact_uri_str("https://alice@example.test/")
            .log_safe_text()
            .as_str(),
        "https://alice@example.test/",
    );
    assert_eq!(
        redactor
            .redact_uri_str("https://alice%2@example.test/")
            .status(),
        UriRedactionStatus::Invalid,
    );
    assert_eq!(
        redactor
            .redact_uri_str("https://example.test/?keep")
            .log_safe_text()
            .as_str(),
        "https://example.test/?keep",
    );
    for query in ["?%GG=value", "?keep=%", "?keep=%GG"] {
        let result =
            redactor.redact_uri_str(&format!("https://example.test/{query}"));
        assert_eq!(result.status(), UriRedactionStatus::Invalid);
    }

    let budget = InputOutputLimit::new(4096, 64)
        .expect("the diagnostic budget is valid");
    let core = RedactionPolicy::default()
        .to_builder()
        .diagnostic_event(budget)
        .build()
        .expect("the core policy is valid");
    let bounded = UriRedactor::new(
        RedactionPolicy::builder_from(&core)
            .build()
            .expect("the URI policy is valid"),
    );
    let long_path = format!(
        "https://example.test/{}?password=secret#fragment",
        "a".repeat(256),
    );
    let result = bounded.redact_uri_str(&long_path);
    assert!(result.is_truncated());
    assert!(!result.log_safe_text().as_str().contains("secret"));

    let input_limited = RedactionPolicy::default()
        .to_builder()
        .diagnostic_event(
            InputOutputLimit::new(4, 64)
                .expect("the input limit policy is valid"),
        )
        .build()
        .expect("the input limit core policy is valid");
    let limited = UriRedactor::new(
        RedactionPolicy::builder_from(&input_limited)
            .build()
            .expect("the limited URI policy is valid"),
    );
    let result = limited.redact_uri_str("https://example.test/");
    assert!(result.has_reason(UriRedactionReason::InputLimitExceeded));
}

/// Verifies an oversized final mask still reports output truncation.
#[test]
fn test_uri_redactor_marks_truncated_final_sensitive_value() {
    let replacement = "X".repeat(128);
    let core = RedactionPolicy::default()
        .to_builder()
        .mask(Sensitivity::Secret, MaskPolicy::fixed(&replacement))
        .expect("the mask policy is valid")
        .mask(Sensitivity::High, MaskPolicy::fixed(&replacement))
        .expect("the opaque mask policy is valid")
        .diagnostic_event(
            InputOutputLimit::new(4096, 37)
                .expect("the diagnostic budget is valid"),
        )
        .build()
        .expect("the core policy is valid");
    let policy = RedactionPolicy::builder_from(&core)
        .build()
        .expect("the URI policy is valid");
    let result = UriRedactor::new(policy)
        .redact_uri_str("https://example.test/?password=secret");

    assert!(result.is_truncated());
    assert!(result.has_reason(UriRedactionReason::OutputTruncated));
    assert!(result.log_safe_text().as_str().ends_with("<truncated>"));
    assert!(!result.log_safe_text().as_str().contains('X'));

    let fragment_result = UriRedactor::new(
        RedactionPolicy::builder_from(&core)
            .build()
            .expect("the URI policy is valid"),
    )
    .redact_uri_str("https://example.test/#fragment");
    assert!(fragment_result.is_truncated());
    assert!(
        fragment_result
            .log_safe_text()
            .as_str()
            .ends_with("<truncated>")
    );
}
