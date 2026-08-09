// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for stateless JSON recursion-depth limits.

use qubit_redact::JsonDepthLimit;
use qubit_redact::JsonDepthLimitError;
use qubit_redact::RedactionPolicy;
/// Verifies JSON depth limits are positive and have a finite default.
#[test]
fn test_json_depth_limit_validates_positive_depth() {
    assert_eq!(JsonDepthLimit::new(0), Err(JsonDepthLimitError::ZeroDepth),);
    assert_eq!(
        JsonDepthLimitError::ZeroDepth.to_string(),
        "JSON depth limit must be greater than zero",
    );
    assert_eq!(
        JsonDepthLimit::default().maximum(),
        JsonDepthLimit::DEFAULT_MAX_DEPTH,
    );
}

/// Verifies policies retain custom JSON depth limits across immutable copies.
#[test]
fn test_redaction_policy_preserves_json_depth_limit() {
    let limit = JsonDepthLimit::new(3).expect("the depth limit is valid");
    let policy = RedactionPolicy::builder()
        .json_depth_limit(limit)
        .build()
        .expect("the policy should build");
    let copied = RedactionPolicy::builder_from(&policy)
        .build()
        .expect("the copied policy should build");

    assert_eq!(policy.json_depth_limit(), limit);
    assert_eq!(copied, policy);
}

/// Verifies depth observations do not consume or otherwise change the limit.
#[test]
fn test_json_depth_limit_is_stateless() {
    let limit = JsonDepthLimit::new(2).expect("positive depth is valid");

    assert_eq!(2, limit.maximum());
    assert!(limit.allows(2));
    assert!(!limit.allows(3));
    assert_eq!(2, limit.maximum());
}
