// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared structural rejection reasons for JSON admission.

#![cfg(feature = "json")]

use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::Redactor;
use serde_json::json;

fn reason_for_limit(limits: impl FnOnce(&mut qubit_redact::RedactionLimitsBuilder)) -> RedactionReason {
    let policy = RedactionPolicy::builder()
        .limits(limits)
        .expect("limits should be valid")
        .build()
        .expect("policy should build");
    let error = Redactor::new(policy)
        .inspect_json_value(&json!({"label": "x"}))
        .expect_err("configured structural limit should reject the JSON tree");
    if error.reasons().contains(RedactionReason::DepthLimitReached) {
        RedactionReason::DepthLimitReached
    } else {
        RedactionReason::TraversalLimitReached
    }
}

#[test]
fn test_json_admission_preserves_shared_depth_limit_reason() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_depth(1);
        })
        .expect("limits should be valid")
        .build()
        .expect("policy should build");
    let redactor = Redactor::new(policy);
    let input = r#"{"label":"x"}"#;
    let value = json!({"label": "x"});

    let text_inspection = redactor
        .inspect_json(input)
        .expect_err("text JSON should exceed shared depth limit");
    let value_inspection = redactor
        .inspect_json_value(&value)
        .expect_err("Value JSON should exceed shared depth limit");
    let text_output = redactor.redact_json(input);
    let value_output = redactor.redact_json_value(&value);

    assert!(text_inspection.reasons().contains(RedactionReason::DepthLimitReached));
    assert!(value_inspection.reasons().contains(RedactionReason::DepthLimitReached));
    assert!(
        text_output
            .summary()
            .reasons()
            .contains(RedactionReason::DepthLimitReached)
    );
    assert!(
        value_output
            .summary()
            .reasons()
            .contains(RedactionReason::DepthLimitReached)
    );
}

#[test]
fn test_json_specific_and_traversal_limits_keep_traversal_reason() {
    assert_eq!(
        reason_for_limit(|limits| {
            limits.max_nodes(1);
        }),
        RedactionReason::TraversalLimitReached
    );
    assert_eq!(
        reason_for_limit(|limits| {
            limits.max_collection_items(0);
        }),
        RedactionReason::TraversalLimitReached
    );
    assert_eq!(
        reason_for_limit(|limits| {
            limits.max_json_depth(1);
        }),
        RedactionReason::TraversalLimitReached
    );
}

#[test]
fn test_json_admission_succeeds_with_exact_shared_depth_budget() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits
                .max_nodes(2)
                .max_collection_items(1)
                .max_depth(2)
                .max_json_depth(2);
        })
        .expect("limits should be valid")
        .build()
        .expect("policy should build");
    let redactor = Redactor::new(policy);
    let value = json!({"label": "x"});

    let inspection = redactor
        .inspect_json_value(&value)
        .expect("the root and its only child fit the exact budget");
    assert_eq!(inspection.usage().visited_nodes(), 2);
    assert_eq!(inspection.usage().visited_collection_items(), 1);
    assert_eq!(inspection.usage().max_depth(), 2);
    assert_eq!(inspection.usage().output_bytes(), 0);
    assert_eq!(
        redactor.redact_json_value(&value).summary().completion(),
        qubit_redact::RedactionCompletion::Complete
    );
}

#[test]
fn test_json_text_fixed_materialization_depth_remains_invalid_json() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits
                .max_nodes(256)
                .max_collection_items(256)
                .max_depth(256)
                .max_json_depth(256);
        })
        .expect("limits should be valid")
        .build()
        .expect("policy should build");
    let input = format!("{}0{}", "[".repeat(128), "]".repeat(128));

    let output = Redactor::new(policy).redact_json(&input);

    assert!(output.summary().reasons().contains(RedactionReason::InvalidJson));
    assert!(!output.summary().reasons().contains(RedactionReason::DepthLimitReached));
    assert!(
        !output
            .summary()
            .reasons()
            .contains(RedactionReason::TraversalLimitReached)
    );
}

#[test]
fn test_json_batch_items_share_the_structural_budget() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(3);
        })
        .expect("limits should be valid")
        .build()
        .expect("policy should build");
    let output = Redactor::new(policy)
        .text_composer()
        .json(|writer| {
            writer.text(r#"{"first":"one"}"#);
            writer.text(r#"{"second":"two"}"#);
        })
        .finish();

    assert!(output.text().as_str().contains("first"));
    assert!(!output.text().as_str().contains("second"));
    assert!(
        output
            .summary()
            .reasons()
            .contains(RedactionReason::TraversalLimitReached)
    );
}
