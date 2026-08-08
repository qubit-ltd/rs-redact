// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`UnkeyedJsonValuePolicy`](qubit_redact::http::UnkeyedJsonValuePolicy).

use qubit_redact::RedactionPolicy;
use qubit_redact::http::UnkeyedJsonValuePolicy;
/// Verifies the standard policy preserves unkeyed JSON scalar values.
#[test]
fn test_unkeyed_json_value_policy_default_is_redact() {
    assert_eq!(
        UnkeyedJsonValuePolicy::default(),
        UnkeyedJsonValuePolicy::Redact,
    );
    assert_eq!(
        RedactionPolicy::default().unkeyed_json_value_policy(),
        UnkeyedJsonValuePolicy::PassThrough,
    );
}
/// Verifies the HTTP policy builder accepts the explicit pass-through opt-in.
#[test]
fn test_unkeyed_json_value_policy_builder_accepts_pass_through() {
    let policy = RedactionPolicy::builder()
        .unkeyed_json_value_policy(UnkeyedJsonValuePolicy::PassThrough)
        .build()
        .expect("HTTP redaction policy should be valid");

    assert_eq!(
        policy.unkeyed_json_value_policy(),
        UnkeyedJsonValuePolicy::PassThrough,
    );
}
