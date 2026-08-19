// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for URI redaction through completed transactions.

use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::Redactor;

/// Verifies the one-shot URI entry point publishes only final safe text.
#[test]
fn test_redactor_redact_uri_publishes_safe_completed_output() {
    let result = Redactor::standard().redact_uri("https://user:secret@example.test/");

    assert_eq!(result.summary().completion(), RedactionCompletion::Complete);
    assert!(!result.text().as_str().contains("secret"));
    assert!(result.text().as_str().contains("%3Credacted%3E"));
}

/// Verifies aggregate and individually resolvable URI operations share one
/// transaction and are inaccessible until that transaction finishes.
#[test]
fn test_uri_session_publishes_aggregate_and_handle_after_finish() {
    let mut session = Redactor::standard().session();
    let handle = session.redact_uri("https://user:secret@example.test/item");
    let output = session
        .literal("request=")
        .uri(|uri| {
            uri.value("https://example.test/path?token=secret");
        })
        .finish();

    let item = output
        .resolve(handle)
        .expect("a handle from the completed transaction must resolve");
    assert!(!item.text().as_str().contains("secret"));
    assert!(output.text().as_str().starts_with("request=https://"));
    assert!(!output.text().as_str().contains("secret"));
}

/// Verifies URI query pairs consume the same structural ledger as an earlier
/// URI in the transaction.
#[test]
fn test_uri_query_pairs_share_the_transaction_structural_budget() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(3).max_collection_items(1);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let mut session = Redactor::new(policy).session();

    session.uri(|uri| {
        uri.value("https://example.test/?first=one");
        uri.value("https://example.test/?second=must-not-be-rendered");
    });
    let output = session.finish();

    assert!(output.text().as_str().contains("first=one"));
    assert!(!output.text().as_str().contains("must-not-be-rendered"));
    assert_eq!(output.summary().usage().visited_nodes(), 3);
    assert_eq!(output.summary().usage().visited_collection_items(), 1);
    assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
}

/// Invalid URI input is replaced at the URI adapter boundary, including its
/// individual handle form; raw source must never become aggregate output.
#[test]
fn test_uri_handle_replaces_invalid_input_and_preserves_provenance() {
    let mut session = Redactor::standard().session();
    let handle = session.redact_uri("https://example.test/?token=%zz-secret");
    let output = session.finish();
    let item = output
        .resolve(handle)
        .expect("finished transaction publishes URI handle");

    assert_eq!(item.text().as_str(), "<invalid URI>");
    assert!(item.summary().reasons().contains(RedactionReason::InvalidUri));
    assert!(!item.text().as_str().contains("secret"));
}

/// Verifies percent-encoded sensitive query values are decoded for policy
/// classification but never preserved in the rendered URI.
#[test]
fn test_uri_redacts_percent_encoded_sensitive_query_values() {
    let output = Redactor::standard().redact_uri("https://example.test/?token=%53%65%63%72%65%74");

    assert!(output.text().as_str().contains("token="));
    assert!(!output.text().as_str().contains("Secret"));
    assert!(!output.text().as_str().contains("%53%65%63%72%65%74"));
}

/// A URI that cannot fit after earlier output must become an exhausted handle
/// and must not add unbudgeted text to the aggregate transaction.
#[test]
fn test_uri_handle_observes_exhausted_parent_output() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_output_bytes(3);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let mut session = Redactor::new(policy).session();
    let _ = session.literal("pre");
    let handle = session.redact_uri("https://example.test/?token=secret");
    let output = session.finish();
    let item = output.resolve(handle).expect("exhausted handle belongs to transaction");

    assert_eq!(output.text().as_str(), "pre");
    assert!(item.text().as_str().is_empty());
    assert_eq!(item.summary().completion(), RedactionCompletion::Exhausted);
}
