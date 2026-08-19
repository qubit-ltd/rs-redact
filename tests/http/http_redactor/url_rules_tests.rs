// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for nested URL redaction limits.

use qubit_redact::Redactor;

use crate::http::support::redaction::redact_url;
/// Verifies excessive nested URL recursion fails closed without exposing
/// secrets.
#[test]
fn test_url_rules_limit_nested_url_recursion() {
    let mut nested = "https://deep-user:deep-secret@inner.test/private".to_owned();
    for layer in 0..10 {
        let encoded = nested
            .replace('%', "%25")
            .replace(':', "%3A")
            .replace('/', "%2F")
            .replace('@', "%40")
            .replace('?', "%3F")
            .replace('&', "%26")
            .replace('=', "%3D");
        nested = format!("https://layer-{layer}.test/?next={encoded}");
    }

    let rendered = redact_url(&Redactor::standard(), &nested);

    assert!(!rendered.contains("deep-user"));
    assert!(!rendered.contains("deep-secret"));
    assert!(
        rendered.contains("nested") && rendered.contains("limit") && rendered.contains("exceeded"),
        "unexpected redaction: {}",
        rendered,
    );
}
