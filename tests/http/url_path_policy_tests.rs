// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`UrlPathPolicy`](qubit_redact::http::UrlPathPolicy).

use qubit_redact::http::{
    HttpRedactionPolicy,
    HttpRedactor,
    UrlPathPolicy,
};

/// Verifies URL paths are redacted by default.
#[test]
fn test_url_path_policy_default_is_redact() {
    assert_eq!(UrlPathPolicy::default(), UrlPathPolicy::Redact);
    assert_eq!(
        HttpRedactionPolicy::default().url_path_policy(),
        UrlPathPolicy::Redact,
    );
}
/// Verifies the preserve opt-in retains a complete path without a query.
#[test]
fn test_url_path_policy_preserve_keeps_complete_path() {
    let policy = HttpRedactionPolicy::empty_builder()
        .url_path_policy(UrlPathPolicy::Preserve)
        .build()
        .expect("HTTP redaction policy should be valid");
    let redactor = HttpRedactor::new(policy);

    assert_eq!(
        redactor
            .redact_url_str("https://example.test/public/path")
            .as_ref(),
        "https://example.test/public/path",
    );
    assert_eq!(redactor.policy().url_path_policy(), UrlPathPolicy::Preserve);
}
