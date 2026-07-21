// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`TextBodyPolicy`](qubit_redact::http::TextBodyPolicy).

use qubit_redact::http::{
    HttpRedactionPolicy,
    TextBodyPolicy,
};

/// Verifies opaque text is redacted by default.
#[test]
fn test_text_body_policy_default_is_redact() {
    assert_eq!(TextBodyPolicy::default(), TextBodyPolicy::Redact);
    assert_eq!(
        HttpRedactionPolicy::default().text_body_policy(),
        TextBodyPolicy::Redact,
    );
}

/// Verifies the HTTP policy builder accepts the explicit pass-through opt-in.
#[test]
fn test_text_body_policy_builder_accepts_pass_through() {
    let policy = HttpRedactionPolicy::builder()
        .text_body_policy(TextBodyPolicy::PassThrough)
        .build()
        .expect("HTTP redaction policy should be valid");

    assert_eq!(policy.text_body_policy(), TextBodyPolicy::PassThrough);
}
