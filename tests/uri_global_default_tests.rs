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
use qubit_redact::uri::UriFragmentPolicy;
use qubit_redact::uri::UriPathPolicy;
use qubit_redact::uri::UriRedactor;
/// Verifies URI defaults preserve the complete installed policy snapshot.
#[test]
fn test_uri_policy_defaults_preserve_global_snapshot() {
    let expected = {
        let mut builder =
            RedactionPolicy::builder_from(&RedactionPolicy::standard());
        builder
            .uri()
            .path(UriPathPolicy::Redact)
            .fragment(UriFragmentPolicy::Preserve);
        builder
            .build()
            .expect("the custom URI policy should be valid")
    };
    RedactionPolicy::install_global(expected.clone())
        .expect("this isolated test process installs the global policy once");

    assert_eq!(RedactionPolicy::default(), expected);
    assert_eq!(UriRedactor::default().policy(), &expected);
}
