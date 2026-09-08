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

/// Input rejection must never let a URI prefix change password syntax into a
/// port and publish it as ordinary text.
#[test]
fn test_uri_input_limit_never_reinterprets_userinfo_password_as_port() {
    let policy = RedactionPolicy::standard()
        .to_builder()
        .limits(|limits| {
            limits.max_input_bytes("https://alice:1234".len());
        })
        .expect("valid limits")
        .build()
        .expect("valid policy");
    let uri = "https://alice:1234@example.test/";
    let output = Redactor::new(policy).redact_uri(uri);
    assert!(!output.text().as_str().contains("1234"));
    assert!(output.summary().reasons().contains(RedactionReason::InputLimitReached));
}

/// Strict URI rendering and inspection both protect non-root paths.
#[test]
fn test_strict_uri_path_protection_matches_http() {
    let redactor = Redactor::strict();
    for uri in [
        "https://example.test/reset/raw-secret",
        "file:///private/raw-secret",
        "custom:raw-secret",
    ] {
        let output = redactor.redact_uri(uri);
        assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
        assert!(!output.text().as_str().contains("raw-secret"), "{uri}");
        assert!(redactor.inspect_uri(uri).expect("valid URI").contains_sensitive());
        let mut batch = redactor.diagnostic_batch();
        let handle = batch.redact_uri(uri);
        let output = batch.finish_with_marker("incomplete");
        assert!(!output.text(handle).as_str().contains("raw-secret"));
        let output = redactor
            .text_composer()
            .uri(|writer| {
                writer.value(uri);
            })
            .finish();
        assert!(!output.text().as_str().contains("raw-secret"));
        #[cfg(feature = "http")]
        if uri.starts_with("https:") {
            assert!(!redactor.redact_http_url(uri).text().as_str().contains("raw-secret"));
        }
    }
}

/// Strict protection permits roots; standard and explicit overrides retain
/// paths.
#[test]
fn test_strict_uri_path_roots_and_explicit_overrides() {
    use qubit_redact::formats::uri::UriPathPolicy;
    for uri in ["https://example.test", "https://example.test/"] {
        let redactor = Redactor::strict();
        assert_eq!(redactor.redact_uri(uri).text().as_str(), uri);
        assert!(!redactor.inspect_uri(uri).expect("valid root URI").contains_sensitive());
    }
    let uri = "https://example.test/raw-secret";
    let policy = RedactionPolicy::strict()
        .to_builder()
        .uri(|uri| {
            uri.path(UriPathPolicy::Preserve);
        })
        .expect("valid URI policy")
        .build()
        .expect("valid policy");
    let mut disabled = RedactionPolicy::strict();
    let _ = disabled.set_disabled(true);
    for redactor in [Redactor::standard(), Redactor::new(policy), Redactor::new(disabled)] {
        assert_eq!(redactor.redact_uri(uri).text().as_str(), uri);
    }
}

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
fn test_uri_composer_and_batch_publish_separate_results() {
    let output = Redactor::standard()
        .text_composer()
        .literal("request=")
        .uri(|uri| {
            uri.value("https://example.test/path?token=secret");
        })
        .finish();

    let mut batch = Redactor::standard().diagnostic_batch();
    let handle = batch.redact_uri("https://user:secret@example.test/item");
    let batch_output = batch.finish_with_marker("<redaction incomplete>");
    assert!(!batch_output.text(handle).as_str().contains("secret"));
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
    let output = Redactor::new(policy)
        .text_composer()
        .uri(|uri| {
            uri.value("https://example.test/?first=one");
            uri.value("https://example.test/?second=must-not-be-rendered");
        })
        .finish();

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
    let mut batch = Redactor::standard().diagnostic_batch();
    let handle = batch.redact_uri("https://example.test/?token=%zz-secret");
    let output = batch.finish_with_marker("<redaction incomplete>");

    assert_eq!(output.text(handle).as_str(), "<invalid URI>");
    assert!(output.summary().reasons().contains(RedactionReason::InvalidUri));
    assert!(!output.text(handle).as_str().contains("secret"));
}

/// An empty URI is syntactically invalid in every public URI entry point; it
/// must not be mistaken for an input-budget omission.
#[test]
fn test_empty_uri_reports_invalid_uri_for_one_shot_composer_and_batch() {
    let one_shot = Redactor::strict().redact_uri("");
    let aggregate = Redactor::strict()
        .text_composer()
        .uri(|uri| {
            uri.value("");
        })
        .finish();
    let mut batch = Redactor::strict().diagnostic_batch();
    let handle = batch.redact_uri("");
    let batch_output = batch.finish_with_marker("<redaction incomplete>");

    for output in [&one_shot, &aggregate] {
        assert_eq!(output.text().as_str(), "<invalid URI>");
        assert!(output.summary().reasons().contains(RedactionReason::InvalidUri));
        assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
    }
    assert_eq!(batch_output.text(handle).as_str(), "<invalid URI>");
    assert!(batch_output.summary().reasons().contains(RedactionReason::InvalidUri));
    assert_eq!(batch_output.summary().completion(), RedactionCompletion::Complete);
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
    let mut batch = Redactor::new(policy).diagnostic_batch();
    let handle = batch.redact_uri("https://example.test/?token=secret");
    let output = batch.finish_with_marker("");

    assert!(output.text(handle).as_str().is_empty());
    assert_eq!(output.summary().completion(), RedactionCompletion::Exhausted);
}
