// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`TextBodyPolicy`](qubit_redact::formats::http::TextBodyPolicy).

use qubit_redact::RedactionPolicy;
use qubit_redact::formats::http::TextBodyPolicy;
/// Verifies opaque text is redacted by default.
#[test]
fn test_text_body_policy_default_is_redact() {
    assert_eq!(TextBodyPolicy::default(), TextBodyPolicy::Redact);
    assert_eq!(
        RedactionPolicy::default().http().text_body_policy(),
        TextBodyPolicy::Redact,
    );
}
/// Verifies the HTTP policy builder accepts the explicit pass-through opt-in.
#[test]
fn test_text_body_policy_builder_accepts_pass_through() {
    let policy = RedactionPolicy::builder()
        .http(|http| {
            http.text_body(TextBodyPolicy::PassThrough);
        })
        .expect("HTTP policy configuration should be valid")
        .build()
        .expect("HTTP redaction policy should be valid");

    assert_eq!(policy.http().text_body_policy(), TextBodyPolicy::PassThrough);
}
