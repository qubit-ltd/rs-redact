// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for immutable HTTP policy accessors.

use qubit_redact::RedactionPolicy;
use qubit_redact::http::TextBodyPolicy;
use qubit_redact::http::UrlPathPolicy;
/// Verifies the HTTP snapshot exposes its default behavioral choices.
#[test]
fn test_http_policy_exposes_default_behavior() {
    let policy = RedactionPolicy::default();

    assert_eq!(policy.http().url_path_policy(), UrlPathPolicy::Preserve);
    assert_eq!(policy.http().text_body_policy(), TextBodyPolicy::Redact);
}
