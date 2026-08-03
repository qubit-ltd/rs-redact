// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Integration tests for policy-driven URI redaction.

use qubit_redact::{
    MaskPolicy,
    RedactionPolicy,
    Sensitivity,
    UriFragmentPolicy,
    UriPathPolicy,
    UriRedactionReason,
    UriRedactionStatus,
    UriRedactor,
};

use qubit_redact::uri::UriRedactionPolicy;

/// Verifies that the default URI policy exposes usernames but masks passwords.
#[test]
fn test_uri_redactor_redacts_password_but_preserves_username() {
    let result = UriRedactor::default().redact_uri_str(
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
    let policy = UriRedactionPolicy::builder_from(&core)
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
    let policy = UriRedactionPolicy::builder_from(&core)
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
    let policy = UriRedactionPolicy::builder()
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
