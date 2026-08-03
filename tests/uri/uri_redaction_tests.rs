// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for structured URI redaction results.

use qubit_redact::{
    UriComponent,
    UriRedactionStatus,
    UriRedactor,
};

/// Verifies results expose safe text and component metadata together.
#[test]
fn test_uri_redaction_result_exposes_safe_metadata() {
    let result = UriRedactor::default()
        .redact_uri_str("https://user:secret@example.test/");

    assert_eq!(UriRedactionStatus::Redacted, result.status());
    assert!(result.has_sensitive_component(UriComponent::Password));
    assert!(!result.to_string().contains("secret"));
}
