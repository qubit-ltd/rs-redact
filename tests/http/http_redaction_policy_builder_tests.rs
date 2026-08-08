// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for HTTP policy builder behavior.

use qubit_redact::RedactionPolicy;
use qubit_redact::http::TextBodyPolicy;
use qubit_redact::http::UrlPathPolicy;
/// Verifies the HTTP builder updates its independently configured choices.
#[test]
fn test_http_policy_builder_updates_behavior_choices() {
    let mut builder = RedactionPolicy::default().to_builder();
    builder.http().url_path(UrlPathPolicy::Redact);
    builder.http().text_body(TextBodyPolicy::PassThrough);
    let policy = builder
        .build()
        .expect("the configured policy must be valid");

    assert_eq!(policy.http().url_path_policy(), UrlPathPolicy::Redact);
    assert_eq!(
        policy.http().text_body_policy(),
        TextBodyPolicy::PassThrough,
    );
}
