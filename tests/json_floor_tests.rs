// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Floor sensitivity integration tests for JSON redaction.

#![cfg(feature = "json")]

use qubit_redact::MaskPolicy;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionFloor;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
use qubit_redact::UnkeyedJsonValuePolicy;

#[test]
fn test_json_uses_policy_mask_for_floor_matched_key() {
    let floor = RedactionFloor::builder()
        .raise("credential", Sensitivity::Low)
        .expect("the test builder input should be valid")
        .build()
        .expect("the floor should build");
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            let _ = fields.floor(floor).sensitive(Sensitivity::Secret, "credential");
            fields.mask(Sensitivity::Secret, MaskPolicy::fixed("[application]"));
        })
        .expect("the test field draft should build")
        .build()
        .expect("the policy should build");
    let value = r#"{"credential":"value"}"#;

    let output = Redactor::new(policy).redact_json(value);

    assert_eq!(output.text().as_str(), r#"{"credential":"[application]"}"#);
}

#[test]
fn test_json_documents_share_the_parent_structural_budget() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(3).max_collection_items(2);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let output = Redactor::new(policy)
        .text_composer()
        .json(|json| {
            json.text(r#"{"first":"one"}"#);
            json.text(r#"{"second":"must-not-be-traversed"}"#);
        })
        .finish();

    assert!(output.text().as_str().contains("first"));
    assert!(!output.text().as_str().contains("must-not-be-traversed"));
    assert_eq!(output.summary().usage().visited_nodes(), 3);
    assert_eq!(output.summary().usage().visited_collection_items(), 2);
    assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
}

/// JSON point and payload limits are transaction-owned and therefore carry
/// forward across JSON operations instead of restarting in each adapter.
#[test]
fn test_json_documents_share_the_transaction_json_payload_budget() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_json_payload_bytes(4);
        })
        .expect("test limits should build")
        .build()
        .expect("test policy should build");
    let mut batch = Redactor::new(policy).batch();
    let first = batch.redact_json(r#"{"a":"1"}"#);
    let second = batch.redact_json(r#"{"b":"22"}"#);
    let output = batch.finish_for_diagnostics("<truncated>");

    assert_eq!(output.text(first).as_str(), r#"{"a":"1"}"#);
    assert_eq!(output.text(second).as_str(), "<truncated>");
    assert!(
        output
            .summary()
            .reasons()
            .contains(RedactionReason::TraversalLimitReached)
    );
}

/// A document rejected by the JSON-specific budget never reaches structural
/// materialization and therefore leaves structural capacity for later items.
#[test]
fn test_json_budget_rejection_preserves_structural_capacity() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(2).max_json_payload_bytes(2);
        })
        .expect("test limits should build")
        .build()
        .expect("test policy should build");
    let mut batch = Redactor::new(policy).batch();
    let rejected = batch.redact_json(r#"{"oversized":"payload"}"#);
    let admitted = batch.redact_json(r#"{"a":"1"}"#);
    let output = batch.finish_for_diagnostics("<truncated>");

    assert_eq!(output.text(rejected).as_str(), "<truncated>");
    assert!(
        output
            .summary()
            .reasons()
            .contains(RedactionReason::TraversalLimitReached)
    );

    assert_eq!(output.text(admitted).as_str(), r#"{"a":"1"}"#);
    assert_eq!(output.summary().usage().visited_nodes(), 2);
    assert_eq!(output.summary().usage().visited_collection_items(), 1);
}

#[test]
fn test_json_masks_unkeyed_scalars_when_policy_requires_it() {
    let policy = RedactionPolicy::builder()
        .unkeyed_json_value_policy(UnkeyedJsonValuePolicy::Redact)
        .build()
        .expect("policy should build");

    let output = Redactor::new(policy).redact_json(r#"["root-secret", {"password": 7}]"#);

    assert!(!output.text().as_str().contains("root-secret"));
    assert!(!output.text().as_str().contains("7"));
    assert!(output.text().as_str().contains("password"));
}

#[test]
fn test_json_invalid_input_reports_safe_invalid_json_result() {
    let output = Redactor::strict().redact_json(r#"{"password":"raw""#);

    assert!(!output.text().as_str().contains("raw"));
    assert!(output.summary().reasons().contains(RedactionReason::InvalidJson));
}

/// JSON redaction shares qubit-json's signed/unsigned 64-bit number boundary.
#[test]
fn test_json_rejects_integer_outside_64_bit_range() {
    let output = Redactor::strict().redact_json("18446744073709551616");

    assert!(output.summary().reasons().contains(RedactionReason::InvalidJson));
    assert!(!output.text().as_str().contains("18446744073709551616"));
}

/// serde_json's former private number marker remains an ordinary object key.
#[test]
fn test_json_preserves_former_number_marker_object() {
    let input = r#"{"$serde_json::private::Number":"123"}"#;
    let output = Redactor::strict().redact_json(input);

    assert!(output.text().as_str().contains("$serde_json::private::Number"));
    assert!(output.text().as_str().starts_with('{'));
    assert!(!output.summary().reasons().contains(RedactionReason::InvalidJson));
}

/// Empty input is invalid JSON, so it must preserve parser provenance rather
/// than being mistaken for an input-budget admission failure.
#[test]
fn test_json_empty_input_reports_safe_invalid_json_result() {
    let output = Redactor::strict().redact_json("");

    assert!(output.summary().reasons().contains(RedactionReason::InvalidJson));
}

/// The composer path must retain invalid-JSON provenance for an empty
/// document instead of treating it as an omitted input prefix.
#[test]
fn test_json_composer_empty_input_reports_safe_invalid_json_result() {
    let output = Redactor::strict()
        .text_composer()
        .json(|json| {
            json.text("");
        })
        .finish();

    assert!(output.summary().reasons().contains(RedactionReason::InvalidJson));
}

/// The batch path must retain invalid-JSON provenance for an empty document.
#[test]
fn test_json_batch_empty_input_reports_safe_invalid_json_result() {
    let mut batch = Redactor::strict().batch();
    let handle = batch.redact_json("");
    let output = batch.finish_for_diagnostics("<redaction incomplete>");

    assert!(output.summary().reasons().contains(RedactionReason::InvalidJson));
    assert_eq!(output.text(handle).as_str(), "<redacted>");
}

/// The JSON handle path must preserve parser provenance and publish the
/// replacement only when its enclosing transaction finishes.
#[test]
fn test_json_handle_reports_invalid_input_without_exposing_source() {
    let mut batch = Redactor::strict().batch();
    let handle = batch.redact_json(r#"{"password":"raw""#);
    let output = batch.finish_for_diagnostics("<redaction incomplete>");

    assert!(!output.text(handle).as_str().contains("raw"));
    assert!(output.summary().reasons().contains(RedactionReason::InvalidJson));
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
}

/// JSON parsing must not receive a document once the shared structural
/// transaction ledger has rejected its root or a collection member.
#[test]
fn test_json_handle_uses_shared_structural_fallback() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(1);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let mut batch = Redactor::new(policy).batch();
    let handle = batch.redact_json(r#"{"password":"must-not-be-rendered"}"#);
    let output = batch.finish_for_diagnostics("<truncated>");

    assert_eq!(output.text(handle).as_str(), "<truncated>");
    assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
    assert!(!output.text(handle).as_str().contains("must-not-be-rendered"));
}

/// Verifies that a JSON fallback which cannot fit closes the transaction.
#[test]
fn test_json_tiny_output_budget_is_exhausted() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_output_bytes(1);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let aggregate = Redactor::new(policy)
        .text_composer()
        .json(|json| {
            json.text(r#"{"password":"must-not-fit"}"#);
        })
        .finish();

    assert_eq!(aggregate.text().as_str(), "");
    assert_eq!(aggregate.summary().completion(), RedactionCompletion::Exhausted);
    assert!(
        aggregate
            .summary()
            .reasons()
            .contains(RedactionReason::OutputLimitReached)
    );
}
