// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Isolated application-default tests for URI redaction policy construction.

#![cfg(feature = "uri")]

use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::formats::uri::UriFragmentPolicy;
use qubit_redact::formats::uri::UriPathPolicy;
/// Verifies application defaults publish a complete URI policy snapshot.
#[test]
fn test_uri_policy_defaults_preserve_application_snapshot() {
    let expected = {
        RedactionPolicy::standard()
            .to_builder()
            .uri(|uri| {
                uri.path(UriPathPolicy::Redact).fragment(UriFragmentPolicy::Preserve);
            })
            .expect("the URI draft should be valid")
            .build()
            .expect("the custom URI policy should be valid")
    };
    let before_replacement = Redactor::application_default();
    let previous = Redactor::replace_application_default(Redactor::new(expected));

    let installed = Redactor::application_default();
    let installed_output = installed.redact_uri("https://example.test/visible#fragment");
    let prior_output = before_replacement.redact_uri("https://example.test/visible#fragment");
    let _ = Redactor::replace_application_default(previous);

    assert!(installed_output.text().as_str().contains("%3Credacted%3E"));
    assert!(installed_output.text().as_str().ends_with("#fragment"));
    assert!(prior_output.text().as_str().contains("/visible"));
    assert!(!prior_output.text().as_str().contains("fragment"));
}
