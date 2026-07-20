// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`UnkeyedJsonValuePolicy`](qubit_redact::UnkeyedJsonValuePolicy).

use qubit_redact::{
    HttpBodySanitizer,
    UnkeyedJsonValuePolicy,
};

#[test]
fn test_unkeyed_json_value_policy_default_is_redact() {
    assert_eq!(
        UnkeyedJsonValuePolicy::default(),
        UnkeyedJsonValuePolicy::Redact,
    );
}

#[test]
fn test_http_body_sanitizer_unkeyed_json_value_policy_accessors() {
    let mut sanitizer = HttpBodySanitizer::default();

    assert_eq!(
        sanitizer.unkeyed_json_value_policy(),
        UnkeyedJsonValuePolicy::Redact,
    );
    sanitizer
        .set_unkeyed_json_value_policy(UnkeyedJsonValuePolicy::PassThrough);
    assert_eq!(
        sanitizer.unkeyed_json_value_policy(),
        UnkeyedJsonValuePolicy::PassThrough,
    );

    let sanitizer = sanitizer
        .with_unkeyed_json_value_policy(UnkeyedJsonValuePolicy::Redact);
    assert_eq!(
        sanitizer.unkeyed_json_value_policy(),
        UnkeyedJsonValuePolicy::Redact,
    );
}
