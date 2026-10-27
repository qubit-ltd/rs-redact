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
use qubit_redact::RedactionReasons;
use qubit_redact::Redactor;
use serde_json::json;

fn reason_for_limit(limits: impl FnOnce(&mut qubit_redact::RedactionLimitsBuilder)) -> RedactionReasons {
    let policy = RedactionPolicy::builder()
        .limits(limits)
        .expect("limits should be valid")
        .build()
        .expect("policy should build");
    let error = Redactor::new(policy)
        .inspect_json_value(&json!({"label": "x"}))
        .expect_err("configured structural limit should reject the JSON tree");
    error.reasons()
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

    let expected = RedactionReasons::empty().with(RedactionReason::DepthLimitReached);
    assert_eq!(text_inspection.reasons(), expected);
    assert_eq!(value_inspection.reasons(), expected);
    assert_eq!(text_output.summary().reasons(), expected);
    assert_eq!(value_output.summary().reasons(), expected);

    let composed = redactor
        .text_composer()
        .literal("safe prefix")
        .json(|writer| {
            writer.text(input);
        })
        .finish();
    assert_eq!(composed.summary().reasons(), expected);
    assert!(composed.text().as_str().starts_with("safe prefix"));

    let mut batch = redactor.diagnostic_batch();
    let handle = batch.redact_json(input);
    let published = batch.finish_with_marker("<batch incomplete>");
    assert_eq!(published.summary().reasons(), expected);
    assert_eq!(published.text(handle).as_str(), "<batch incomplete>");
}

#[test]
fn test_json_admission_marker_output_limit_adds_only_real_output_reason() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_depth(1).max_output_bytes(5);
        })
        .expect("limits should be valid")
        .build()
        .expect("policy should build");
    let output = Redactor::new(policy).redact_json(r#"{"label":"x"}"#);

    assert!(output.text().as_str().is_empty());
    assert_eq!(
        output.summary().reasons(),
        RedactionReasons::empty()
            .with(RedactionReason::DepthLimitReached)
            .with(RedactionReason::OutputLimitReached)
    );
}

#[test]
fn test_json_batch_keeps_neighbor_reasons_separate_and_incomplete_marker() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_depth(1);
        })
        .expect("limits should be valid")
        .build()
        .expect("policy should build");
    let redactor = Redactor::new(policy);
    let mut batch = redactor.diagnostic_batch();
    let rejected = batch.redact_json(r#"{"label":"x"}"#);
    let invalid = batch.redact_json("{");
    let output = batch.finish_with_marker("<batch incomplete>");

    assert_eq!(output.text(rejected).as_str(), "<batch incomplete>");
    assert_eq!(output.text(invalid).as_str(), "<redacted>");
    assert_eq!(
        output.summary().reasons(),
        RedactionReasons::empty()
            .with(RedactionReason::DepthLimitReached)
            .with(RedactionReason::InvalidJson)
    );
}

#[test]
fn test_json_specific_and_traversal_limits_keep_traversal_reason() {
    assert_eq!(
        reason_for_limit(|limits| {
            limits.max_nodes(1);
        }),
        RedactionReasons::empty().with(RedactionReason::TraversalLimitReached)
    );
    assert_eq!(
        reason_for_limit(|limits| {
            limits.max_collection_items(0);
        }),
        RedactionReasons::empty().with(RedactionReason::TraversalLimitReached)
    );
    assert_eq!(
        reason_for_limit(|limits| {
            limits.max_json_depth(1);
        }),
        RedactionReasons::empty().with(RedactionReason::TraversalLimitReached)
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
fn test_json_text_json_depth_limit_reports_traversal_limit() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits
                .max_nodes(16)
                .max_collection_items(16)
                .max_depth(16)
                .max_json_depth(1);
        })
        .expect("limits should be valid")
        .build()
        .expect("policy should build");
    let input = r#"{"outer":{"value":0}}"#;

    let output = Redactor::new(policy).redact_json(input);

    assert!(
        output
            .summary()
            .reasons()
            .contains(RedactionReason::TraversalLimitReached)
    );
    assert!(!output.summary().reasons().contains(RedactionReason::InvalidJson));
    assert!(!output.summary().reasons().contains(RedactionReason::DepthLimitReached));
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
