// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for structured URI redaction results.

use qubit_redact::RedactionCompletion;
use qubit_redact::formats::uri::UriComponent;
use qubit_redact::formats::uri::UriRedactionReason;
use qubit_redact::formats::uri::UriRedactionStatus;
use qubit_redact::formats::uri::UriRedactor;
/// Verifies results expose safe text and component metadata together.
#[test]
fn test_uri_redaction_result_exposes_safe_metadata() {
    let result = UriRedactor::default()
        .redact_uri_str("https://user:secret@example.test/");

    assert_eq!(UriRedactionStatus::Redacted, result.status());
    assert!(result.has_sensitive_component(UriComponent::Password));
    assert!(result.has_sensitive_components());
    assert!(result.has_reason(UriRedactionReason::SensitiveComponent(
        UriComponent::Password,
    )));
    assert!(!result.reasons().is_empty());
    assert_eq!(result.completion(), RedactionCompletion::Complete);
    assert!(format!("{result:?}").contains("UriRedaction"));
    assert!(!result.to_string().contains("secret"));
}
