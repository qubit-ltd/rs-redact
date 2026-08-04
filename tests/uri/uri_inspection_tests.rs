// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Integration tests for metadata-only URI inspection.

use qubit_redact::{
    InputOutputLimit,
    RedactionPolicy,
    UriComponent,
    UriRedactionReason,
    UriRedactionStatus,
    UriRedactor,
};

/// Verifies inspection reports sensitive components without producing text.
#[test]
fn test_uri_redactor_inspect_uri_str_reports_metadata() {
    let inspection = UriRedactor::default().inspect_uri_str(
        "https://alice:secret@example.test/private?password=raw#fragment",
    );

    assert_eq!(inspection.status(), UriRedactionStatus::Redacted);
    assert!(inspection.has_sensitive_component(UriComponent::Password));
    assert!(inspection.has_sensitive_component(UriComponent::Query));
    assert!(inspection.has_sensitive_component(UriComponent::Fragment));
    assert!(!inspection.has_sensitive_component(UriComponent::Path));
    assert!(
        inspection.has_reason(UriRedactionReason::SensitiveComponent(
            UriComponent::Password,
        ))
    );
    assert!(!inspection.has_reason(UriRedactionReason::InvalidUri));
}

/// Verifies inspection preserves strict invalid-input classification.
#[test]
fn test_uri_redactor_inspect_uri_str_fails_closed() {
    let redactor = UriRedactor::default();
    let malformed = redactor.inspect_uri_str("https://[invalid");
    assert_eq!(malformed.status(), UriRedactionStatus::Invalid);
    assert!(malformed.has_reason(UriRedactionReason::InvalidUri));

    let invalid_value =
        redactor.inspect_uri_str("https://example.test/?keep=%FF");
    assert_eq!(invalid_value.status(), UriRedactionStatus::Invalid);
    assert!(
        invalid_value.has_reason(UriRedactionReason::UndecodableQueryValue)
    );
}

/// Verifies inspection is independent of the rendered output budget.
#[test]
fn test_uri_redactor_inspect_uri_str_ignores_output_budget() {
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
    let input =
        format!("https://example.test/{}?password=secret", "a".repeat(256),);

    let inspection = UriRedactor::new(policy).inspect_uri_str(&input);
    assert_eq!(inspection.status(), UriRedactionStatus::Redacted);
    assert!(inspection.has_sensitive_component(UriComponent::Query));
    assert!(!inspection.has_reason(UriRedactionReason::OutputTruncated));
}
