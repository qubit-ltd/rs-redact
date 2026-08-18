// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Integration tests for policy-driven URI redaction.

use qubit_redact::InputOutputLimit;
use qubit_redact::MaskPolicy;
use qubit_redact::RedactedText;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;
use qubit_redact::formats::uri::UriComponent;
use qubit_redact::formats::uri::UriFragmentPolicy;
use qubit_redact::formats::uri::UriPathPolicy;
use qubit_redact::formats::uri::UriRedactionReason;
use qubit_redact::formats::uri::UriRedactionStatus;
use qubit_redact::formats::uri::UriRedactor;
/// Verifies repeated URI session fallbacks never exceed the cumulative output
/// limit, including when insufficient bytes remain for another complete marker.
#[test]
fn test_uri_session_fallbacks_respect_cumulative_output_limit() {
    let budget = InputOutputLimit::builder()
        .max_input_bytes(8)
        .max_output_bytes(InputOutputLimit::MIN_OUTPUT_BYTES)
        .build()
        .expect("the marker-sized diagnostic budget should be valid");
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.limits().diagnostic_event(budget);
        builder
    })
    .build()
    .expect("URI policy should be valid");
    let redactor = UriRedactor::new(policy);
    let mut session = redactor.session();

    let rendered: Vec<_> = (0..4)
        .map(|_| {
            session
                .uri_with_mut(|uri| uri.redact_uri_str("https://example.test/?password=secret"))
                .into_log_safe_text()
                .into_owned()
        })
        .collect();

    assert_eq!(rendered[0], "<invalid URI>");
    assert_eq!(rendered[1], "<invalid URI>");
    assert!(rendered[2].is_empty());
    assert!(rendered[3].is_empty());
    assert!(rendered.iter().map(String::len).sum::<usize>() <= budget.max_output_bytes());
}

/// Verifies that the default URI policy exposes usernames but masks passwords.
#[test]
fn test_uri_redactor_redacts_password_but_preserves_username() {
    let redactor = UriRedactor::default();
    assert_eq!(format!("{redactor}"), "UriRedactor");
    assert_eq!(redactor.policy(), &RedactionPolicy::default());
    let result = redactor.redact_uri_str("https://alice:secret@example.test/private?password=raw#fragment");

    assert_eq!(
        result.log_safe_text().as_str(),
        "https://alice:%3Credacted%3E@example.test/private?password=%3Credacted%3E#****",
    );
    assert_eq!(result.status(), UriRedactionStatus::Redacted);
    assert!(result.has_sensitive_component(UriComponent::Password));
    assert!(result.has_sensitive_component(UriComponent::Query));
    assert!(result.has_sensitive_component(UriComponent::Fragment));
}

/// Verifies username and password use independent core field rules.
#[test]
fn test_uri_redactor_applies_username_policy_and_keeps_encoded_colon() {
    let core = ({
        let mut builder = RedactionPolicy::builder();
        builder.edit_fields().disable_floor();
        builder
            .edit_fields()
            .raise("username", Sensitivity::Secret)
            .expect("username rule is valid");
        builder
            .edit_fields()
            .raise("password", Sensitivity::Secret)
            .expect("password rule is valid");
        builder
            .edit_fields()
            .allow_exact("username")
            .expect("username allow rule is valid");
        builder
    })
    .build()
    .expect("core policy is valid");
    let policy = core.to_builder().build().expect("URI policy is valid");

    let result = UriRedactor::new(policy).redact_uri_str("https://alice%3Ateam:secret@example.test/private");

    assert_eq!(
        result.log_safe_text().as_str(),
        "https://alice%3Ateam:%3Credacted%3E@example.test/private",
    );
    assert_eq!(result.status(), UriRedactionStatus::Redacted);
    assert!(result.has_sensitive_component(UriComponent::Password));
    assert!(!result.has_sensitive_component(UriComponent::Username));
}

/// Verifies query values are decoded before masking and raw order is retained.
#[test]
fn test_uri_redactor_masks_query_after_decoding_and_preserves_order() {
    let core = ({
        let mut builder = RedactionPolicy::builder();
        builder.edit_fields().disable_floor();
        builder
            .edit_fields()
            .raise("token", Sensitivity::High)
            .expect("token rule is valid");
        builder
            .edit_fields()
            .mask(Sensitivity::High, MaskPolicy::fixed("x y"))
            .expect("mask policy is valid");
        builder
    })
    .build()
    .expect("core policy is valid");
    let policy = core.to_builder().build().expect("URI policy is valid");

    let result =
        UriRedactor::new(policy).redact_uri_str("https://example.test/path?keep=a%2Fb&token=hello%20world&keep=last");

    assert_eq!(
        result.log_safe_text().as_str(),
        "https://example.test/path?keep=a%2Fb&token=x%20y&keep=last",
    );
    assert_eq!(result.status(), UriRedactionStatus::Redacted);
    assert!(result.has_sensitive_component(UriComponent::Query));
}

/// Verifies malformed syntax and undecodable query keys fail closed.
#[test]
fn test_uri_redactor_fails_closed_for_invalid_uri_and_query_key_utf8() {
    let redactor = UriRedactor::default();
    let malformed = redactor.redact_uri_str("https://[invalid");
    assert_eq!(malformed.log_safe_text().as_str(), "<invalid URI>");
    assert_eq!(malformed.status(), UriRedactionStatus::Invalid);
    assert!(malformed.has_reason(UriRedactionReason::InvalidUri));

    let invalid_key = redactor.redact_uri_str("https://example.test/?%FF=secret");
    assert_eq!(invalid_key.log_safe_text().as_str(), "<invalid URI>");
    assert_eq!(invalid_key.status(), UriRedactionStatus::Invalid);
    assert!(invalid_key.has_reason(UriRedactionReason::UndecodableQueryKey));
}

/// Verifies path and fragment visibility are independently configurable.
#[test]
fn test_uri_redaction_policy_configures_path_and_fragment_boundaries() {
    let policy = ({
        let mut builder = RedactionPolicy::builder();
        builder.uri().path(UriPathPolicy::Redact);
        builder.uri().fragment(UriFragmentPolicy::Preserve);
        builder
    })
    .build()
    .expect("URI policy is valid");
    let result = UriRedactor::new(policy).redact_uri_str("https://example.test/private/path#debug");

    assert_eq!(
        result.log_safe_text().as_str(),
        "https://example.test/%3Credacted%3E#debug",
    );
    assert!(result.has_sensitive_component(UriComponent::Path));
    assert!(!result.has_sensitive_component(UriComponent::Fragment));
}

/// Verifies consuming a URI result preserves the typed log-safe boundary.
#[test]
fn test_uri_redaction_consuming_text_preserves_safe_type() {
    let text: RedactedText = UriRedactor::default()
        .redact_uri_str("https://example.test/?password=secret")
        .into_log_safe_text();
    assert_eq!(text.as_str(), "https://example.test/?password=%3Credacted%3E");
}

/// Verifies later malformed query fields are still validated after truncation.
#[test]
fn test_uri_redactor_validates_after_output_truncation() {
    let core = ({
        let mut builder = RedactionPolicy::default().to_builder();
        builder.limits().diagnostic_event(
            InputOutputLimit::builder()
                .max_input_bytes(4096)
                .max_output_bytes(64)
                .build()
                .expect("the diagnostic budget is valid"),
        );
        builder
    })
    .build()
    .expect("the core policy is valid");
    let policy = core.to_builder().build().expect("the URI policy is valid");
    let redactor = UriRedactor::new(policy);
    let input = format!("https://example.test/?password={}&bad=%FF", "secret".repeat(32),);
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
    assert_eq!(redactor.redact_uri_str("urn:path").log_safe_text().as_str(), "urn:path",);
    let path_redacted = UriRedactor::new(
        ({
            let mut builder = RedactionPolicy::builder();
            builder.uri().path(UriPathPolicy::Redact);
            builder
        })
        .build()
        .expect("the path policy is valid"),
    );
    assert_eq!(
        path_redacted.redact_uri_str("urn:path").log_safe_text().as_str(),
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
        redactor.redact_uri_str("https://alice%2@example.test/").status(),
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
        let result = redactor.redact_uri_str(&format!("https://example.test/{query}"));
        assert_eq!(result.status(), UriRedactionStatus::Invalid);
    }

    let budget = InputOutputLimit::builder()
        .max_input_bytes(4096)
        .max_output_bytes(64)
        .build()
        .expect("the diagnostic budget is valid");
    let core = ({
        let mut builder = RedactionPolicy::default().to_builder();
        builder.limits().diagnostic_event(budget);
        builder
    })
    .build()
    .expect("the core policy is valid");
    let bounded = UriRedactor::new(core.to_builder().build().expect("the URI policy is valid"));
    let long_path = format!("https://example.test/{}?password=secret#fragment", "a".repeat(256),);
    let result = bounded.redact_uri_str(&long_path);
    assert_eq!(result.completion(), RedactionCompletion::Truncated);
    assert!(result.has_reason(UriRedactionReason::OutputTruncated));
    assert!(!result.log_safe_text().as_str().contains("secret"));

    let input_limited = ({
        let mut builder = RedactionPolicy::default().to_builder();
        builder.limits().diagnostic_event(
            InputOutputLimit::builder()
                .max_input_bytes(4)
                .max_output_bytes(64)
                .build()
                .expect("the input limit policy is valid"),
        );
        builder
    })
    .build()
    .expect("the input limit core policy is valid");
    let limited = UriRedactor::new(
        input_limited
            .to_builder()
            .build()
            .expect("the limited URI policy is valid"),
    );
    let result = limited.redact_uri_str("https://example.test/");
    assert_eq!(result.completion(), RedactionCompletion::Truncated);
    assert_eq!(result.status(), UriRedactionStatus::Invalid);
    assert!(result.has_reason(UriRedactionReason::InputLimitExceeded));
}

/// Verifies an oversized final mask still reports output truncation.
#[test]
fn test_uri_redactor_marks_truncated_final_sensitive_value() {
    let replacement = "X".repeat(128);
    let core = ({
        let mut builder = RedactionPolicy::default().to_builder();
        builder
            .edit_fields()
            .mask(Sensitivity::Secret, MaskPolicy::fixed(&replacement))
            .expect("the mask policy is valid");
        builder
            .edit_fields()
            .mask(Sensitivity::High, MaskPolicy::fixed(&replacement))
            .expect("the opaque mask policy is valid");
        builder.limits().diagnostic_event(
            InputOutputLimit::builder()
                .max_input_bytes(4096)
                .max_output_bytes(37)
                .build()
                .expect("the diagnostic budget is valid"),
        );
        builder
    })
    .build()
    .expect("the core policy is valid");
    let policy = core.to_builder().build().expect("the URI policy is valid");
    let result = UriRedactor::new(policy).redact_uri_str("https://example.test/?password=secret");

    assert_eq!(result.completion(), RedactionCompletion::Truncated);
    assert!(result.has_reason(UriRedactionReason::OutputTruncated));
    assert!(result.log_safe_text().as_str().ends_with("<truncated>"));
    assert!(!result.log_safe_text().as_str().contains('X'));

    let fragment_result = UriRedactor::new(core.to_builder().build().expect("the URI policy is valid"))
        .redact_uri_str("https://example.test/#fragment");
    assert_eq!(fragment_result.completion(), RedactionCompletion::Truncated,);
    assert!(fragment_result.has_reason(UriRedactionReason::OutputTruncated));
    assert!(fragment_result.log_safe_text().as_str().ends_with("<truncated>"));
}
