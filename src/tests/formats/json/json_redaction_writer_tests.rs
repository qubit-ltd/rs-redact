// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Parser-entry accounting unavailable through the public API.

use crate::Redactor;
use crate::formats::json::parse_counter::json_materialization_count;
use crate::formats::json::parse_counter::json_parse_count;
use crate::formats::json::parse_counter::reset_json_materialization_count;
use crate::formats::json::parse_counter::reset_json_parse_count;

fn preflight_limited_redactor() -> Redactor {
    let policy = crate::RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(1).max_input_bytes(1_000_000);
        })
        .expect("limits")
        .build()
        .expect("policy");
    Redactor::new(policy)
}

fn large_array_text() -> String {
    format!("[{}]", "0,".repeat(10_000) + "0")
}

#[test]
fn test_enabled_json_text_is_parsed_exactly_once() {
    reset_json_parse_count();

    let output = Redactor::standard().redact_json(r#"{"token":"raw-secret"}"#);

    assert_eq!(json_parse_count(), 1);
    assert!(!output.text().as_str().contains("raw-secret"));
}

#[test]
fn test_preflight_stops_before_unique_decoder_when_nodes_are_exhausted() {
    let redactor = preflight_limited_redactor();
    let source = large_array_text();

    reset_json_materialization_count();
    let output = redactor.redact_json(&source);

    assert_eq!(json_materialization_count(), 0);
    assert!(
        output
            .summary()
            .reasons()
            .contains(crate::RedactionReason::TraversalLimitReached)
    );
    assert_eq!(output.summary().usage().visited_nodes(), 0);
}

#[test]
fn test_preflight_inspection_and_composer_stop_before_unique_decoder() {
    let redactor = preflight_limited_redactor();
    let source = large_array_text();

    reset_json_materialization_count();
    assert!(redactor.inspect_json(&source).is_err());
    assert_eq!(json_materialization_count(), 0);

    reset_json_materialization_count();
    let output = redactor
        .text_composer()
        .json(|json| {
            json.text(&source);
        })
        .finish();
    assert_eq!(json_materialization_count(), 0);
    assert_eq!(output.summary().usage().visited_nodes(), 0);
}

#[test]
fn test_preflight_batch_counts_only_prior_unique_decoder_entry() {
    let redactor = preflight_limited_redactor();
    let source = large_array_text();
    let mut batch = redactor.diagnostic_batch();
    reset_json_materialization_count();
    let _ = batch.redact_json("0");
    let _ = batch.redact_json(&source);

    assert_eq!(json_materialization_count(), 1);
}

#[test]
fn test_json_with_exact_nodes_and_collection_items_is_admitted() {
    let policy = crate::RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(3).max_collection_items(2);
        })
        .expect("limits")
        .build()
        .expect("policy");
    let redactor = Redactor::new(policy);

    reset_json_materialization_count();
    let output = redactor.redact_json(r#"{"a":[1]}"#);

    assert_eq!(json_materialization_count(), 1);
    assert_eq!(output.summary().usage().visited_nodes(), 3);
    assert_eq!(output.summary().usage().visited_collection_items(), 2);
    assert_eq!(output.summary().completion(), crate::RedactionCompletion::Complete);
}

#[test]
fn test_json_ledger_accumulates_across_values_and_rejects_before_next_decoder() {
    let policy = crate::RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(3).max_collection_items(2);
        })
        .expect("limits")
        .build()
        .expect("policy");
    let redactor = Redactor::new(policy);
    reset_json_materialization_count();

    let output = redactor
        .text_composer()
        .json(|json| {
            json.text(r#"{"a":0}"#);
            json.text(r#"{"b":0}"#);
        })
        .finish();

    assert_eq!(json_materialization_count(), 1);
    assert_eq!(output.summary().usage().visited_nodes(), 2);
    assert_eq!(output.summary().usage().visited_collection_items(), 1);
    assert!(
        output
            .summary()
            .reasons()
            .contains(crate::RedactionReason::TraversalLimitReached)
    );
}

#[test]
fn test_shared_depth_rejection_leaves_shallow_json_available() {
    let policy = crate::RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_depth(2);
        })
        .expect("limits")
        .build()
        .expect("policy");
    let redactor = Redactor::new(policy);
    reset_json_materialization_count();

    let output = redactor
        .text_composer()
        .json(|json| {
            json.text("[[0]]");
            json.text("0");
        })
        .finish();

    assert_eq!(json_materialization_count(), 1);
    assert_eq!(output.summary().usage().visited_nodes(), 1);
    assert!(
        output
            .summary()
            .reasons()
            .contains(crate::RedactionReason::DepthLimitReached)
    );
    assert!(output.text().as_str().ends_with('0'));
}
