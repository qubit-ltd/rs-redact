// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Isolated global-configuration tests for URI redaction policy construction.

#![cfg(feature = "uri")]

use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::formats::uri::UriFragmentPolicy;
use qubit_redact::formats::uri::UriPathPolicy;
use qubit_redact::formats::uri::UriRedactor;
/// Verifies URI defaults preserve the complete installed policy snapshot.
#[test]
fn test_uri_policy_defaults_preserve_global_snapshot() {
    let expected = {
        let mut builder = RedactionPolicy::standard().to_builder();
        builder
            .uri()
            .path(UriPathPolicy::Redact)
            .fragment(UriFragmentPolicy::Preserve);
        builder.build().expect("the custom URI policy should be valid")
    };
    let previous = Redactor::set_default(Redactor::new(expected.clone()));

    assert_eq!(UriRedactor::default().policy(), &expected);
    let _ = Redactor::set_default(previous);
}
