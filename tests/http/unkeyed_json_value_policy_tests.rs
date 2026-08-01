// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`UnkeyedJsonValuePolicy`](qubit_redact::http::UnkeyedJsonValuePolicy).

use qubit_redact::http::{
    HttpRedactionPolicy,
    UnkeyedJsonValuePolicy,
};

/// Verifies unkeyed JSON scalar values are redacted by default.
#[test]
fn test_unkeyed_json_value_policy_default_is_redact() {
    assert_eq!(
        UnkeyedJsonValuePolicy::default(),
        UnkeyedJsonValuePolicy::Redact,
    );
    assert_eq!(
        HttpRedactionPolicy::default().unkeyed_json_value_policy(),
        UnkeyedJsonValuePolicy::Redact,
    );
}
/// Verifies the HTTP policy builder accepts the explicit pass-through opt-in.
#[test]
fn test_unkeyed_json_value_policy_builder_accepts_pass_through() {
    let policy = HttpRedactionPolicy::builder()
        .unkeyed_json_value_policy(UnkeyedJsonValuePolicy::PassThrough)
        .build()
        .expect("HTTP redaction policy should be valid");

    assert_eq!(
        policy.unkeyed_json_value_policy(),
        UnkeyedJsonValuePolicy::PassThrough,
    );
}
