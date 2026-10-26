// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Admission contracts for scalar field inspection.

use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::Redactor;

fn limited_policy(max_nodes: usize, max_depth: usize, max_key_bytes: usize) -> RedactionPolicy {
    RedactionPolicy::builder()
        .limits(|limits| {
            limits
                .max_nodes(max_nodes)
                .max_depth(max_depth)
                .max_key_bytes(max_key_bytes);
        })
        .expect("limits should be valid")
        .build()
        .expect("policy should build")
}

#[test]
fn test_scalar_inspection_rejects_zero_node_depth_and_key_budgets() {
    for (policy, expected) in [
        (limited_policy(0, 8, 8), RedactionReason::TraversalLimitReached),
        (limited_policy(8, 0, 8), RedactionReason::DepthLimitReached),
        (limited_policy(8, 8, 0), RedactionReason::TraversalLimitReached),
    ] {
        let error = Redactor::new(policy)
            .inspect_field("label", "x")
            .expect_err("scalar inspection must enforce structural and key budgets");
        assert!(error.reasons().contains(expected));
    }
}

#[test]
fn test_scalar_inspection_admits_raw_utf8_key_bytes_and_tracks_structure() {
    let accepted = Redactor::new(limited_policy(1, 1, 3))
        .inspect_field("名", "x")
        .expect("three UTF-8 key bytes should fit exactly");
    assert_eq!(accepted.usage().visited_nodes(), 1);
    assert_eq!(accepted.usage().visited_collection_items(), 0);
    assert_eq!(accepted.usage().max_depth(), 1);
    assert_eq!(accepted.usage().output_bytes(), 0);

    let error = Redactor::new(limited_policy(1, 1, 2))
        .inspect_field("名", "x")
        .expect_err("two UTF-8 key bytes must reject a three-byte key");
    assert!(error.reasons().contains(RedactionReason::TraversalLimitReached));
}

#[test]
fn test_disabled_scalar_inspection_still_enforces_structural_admission() {
    let mut policy = limited_policy(0, 1, 8);
    let _ = policy.set_disabled(true);
    let error = Redactor::new(policy)
        .inspect_field("label", "x")
        .expect_err("disabled mode must still enforce structural limits");
    assert!(error.reasons().contains(RedactionReason::TraversalLimitReached));
}
