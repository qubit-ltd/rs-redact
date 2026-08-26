// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Regression coverage for the post-redesign public transaction API.

use std::borrow::Cow;
use std::ffi::OsStr;

use qubit_redact::Redact;
use qubit_redact::RedactionBatchHandleError;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::RedactionReasons;
use qubit_redact::RedactionUsage;
use qubit_redact::RedactionWriter;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;

struct Account {
    name: String,
    _password: String,
}

impl Redact for Account {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("Account", |fields| {
            fields
                .unredacted("name", || self.name.clone())
                .sensitive(Sensitivity::Secret, "password", || {
                    panic!("a secret accessor must not run")
                });
        });
    }
}

fn secret_policy(field: &str) -> RedactionPolicy {
    RedactionPolicy::builder()
        .fields(|fields| {
            let _ = fields.secret_sensitive(field);
        })
        .expect("field configuration should be valid")
        .build()
        .expect("policy should build")
}

#[test]
fn composer_and_batch_publish_separate_models() {
    let redactor = Redactor::new(secret_policy("request_token"));
    let text = redactor
        .text_composer()
        .literal("request failed: ")
        .field("request_token", "raw-token")
        .literal("; account=")
        .value(&Account {
            name: "Ada".to_owned(),
            _password: "raw-password".to_owned(),
        })
        .finish();
    let mut batch = redactor.batch();
    let name = batch.redact_field("name", "Ada");
    let output = batch.finish();
    let name = output
        .resolve(name)
        .expect("a handle from this transaction resolves after finish");
    assert_eq!(name.text().as_str(), "Ada");
    assert_eq!(name.summary().completion(), RedactionCompletion::Complete);
    assert!(text.text().as_str().contains("request failed: "));
    assert!(text.text().as_str().contains("<redacted>"));
    assert!(text.text().as_str().contains("Account"));
    assert!(!text.text().as_str().contains("raw-token"));
    assert!(!text.text().as_str().contains("raw-password"));
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
    assert_eq!(output.summary().usage().output_bytes(), name.text().as_str().len());
}

#[test]
fn batch_handles_cannot_cross_batches() {
    let mut first_batch = Redactor::standard().batch();
    let first_handle = first_batch.redact_field("name", "Ada");
    let first = first_batch.finish();
    assert_eq!(first.resolve(first_handle).unwrap().text().as_str(), "Ada");

    let second = Redactor::standard().batch().finish();
    assert!(matches!(
        second.resolve(first_handle),
        Err(RedactionBatchHandleError::DifferentBatch),
    ));
    assert_eq!(second.summary().completion(), RedactionCompletion::Complete);
}

#[test]
fn batch_diagnostics_resolves_complete_text_or_the_selected_marker() {
    let mut complete_batch = Redactor::standard().batch();
    let complete_handle = complete_batch.redact_field("name", "Ada");
    let complete_output = complete_batch.finish_for_diagnostics("<redaction incomplete>");
    assert_eq!(complete_output.text(complete_handle).as_str(), "Ada");

    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_output_bytes(1);
        })
        .expect("limit configuration should be valid")
        .build()
        .expect("policy should build");
    let mut incomplete_batch = Redactor::new(policy).batch();
    let incomplete_handle = incomplete_batch.redact_field("password", "raw-password");
    let incomplete_output = incomplete_batch.finish_for_diagnostics("<redaction\nincomplete>");
    assert_eq!(
        incomplete_output.text(incomplete_handle).as_str(),
        "<redaction\\nincomplete>",
    );
    assert_eq!(incomplete_output.summary().completion(), RedactionCompletion::Exhausted,);
}

#[test]
fn batch_diagnostics_maps_truncated_text_to_the_selected_marker() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_collection_items(1);
        })
        .expect("limit configuration should be valid")
        .build()
        .expect("policy should build");
    let mut batch = Redactor::new(policy).batch();
    let handle = batch.redact_env_pairs([
        (OsStr::new("FIRST"), OsStr::new("visible")),
        (OsStr::new("PASSWORD"), OsStr::new("raw-password")),
    ]);
    let diagnostics = batch.finish_for_diagnostics("<redaction incomplete>");

    assert_eq!(diagnostics.text(handle).as_str(), "<redaction incomplete>",);
    assert_eq!(diagnostics.summary().completion(), RedactionCompletion::Truncated,);
}

#[test]
fn batch_diagnostics_maps_a_foreign_handle_to_the_selected_marker() {
    let mut first_batch = Redactor::standard().batch();
    let first_handle = first_batch.redact_field("name", "Ada");
    let _ = first_batch.finish();

    let second_output = Redactor::standard()
        .batch()
        .finish_for_diagnostics("<redaction incomplete>");
    assert_eq!(second_output.text(first_handle).as_str(), "<redaction incomplete>",);
}

#[test]
fn application_default_replacement_affects_new_trait_entries_only() {
    let original = Redactor::application_default();
    let replacement = Redactor::new(secret_policy("token"));
    let previous = Redactor::replace_application_default(replacement.clone());
    assert_eq!(previous, original);

    let value = Account {
        name: "Ada".to_owned(),
        _password: "raw-password".to_owned(),
    };
    let output = Redactor::application_default().redact(&value);
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
    assert!(!output.text().as_str().contains("raw-password"));

    let restored = Redactor::replace_application_default(original);
    assert_eq!(restored, replacement);
}

#[test]
fn summaries_keep_completion_reason_and_usage_machine_readable() {
    let output = Redactor::standard().redact(&Account {
        name: "Ada".to_owned(),
        _password: "raw-password".to_owned(),
    });
    let (text, summary) = output.into_parts();
    assert!(!text.as_str().contains("raw-password"));
    assert_eq!(summary.completion(), RedactionCompletion::Complete);
    assert_eq!(summary.usage().output_bytes(), text.as_str().len());
}

/// Verifies the one-item facade exposes the same final text and summary
/// through borrowing and consuming output accessors.
#[test]
fn redaction_output_preserves_parts_across_all_public_accessors() {
    let output = Redactor::standard().redact_field("password", "raw-password");

    assert_eq!(output.text().as_str(), "<redacted>");
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
    assert_eq!(
        output.complete_text().expect("field output must be complete").as_str(),
        "<redacted>",
    );
    assert!(matches!(
        output.text_or_marker("<redaction incomplete>"),
        Cow::Borrowed("<redacted>"),
    ));

    let text = output.into_complete_text().expect("field output must be complete");
    assert_eq!(text.into_string(), "<redacted>");
}

/// Verifies incomplete output requires an explicit fallback presentation.
#[test]
fn redaction_output_rejects_incomplete_text_and_uses_the_selected_marker() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_output_bytes(1);
        })
        .expect("limit configuration should be valid")
        .build()
        .expect("policy should build");
    let output = Redactor::new(policy).redact_field("password", "raw-password");

    assert!(output.complete_text().is_err());
    assert_eq!(
        output.text_or_marker("<redaction\nincomplete>"),
        "<redaction\\nincomplete>",
    );
    assert!(output.clone().into_complete_text().is_err());
    assert_eq!(
        output.into_text_or_marker("<redaction incomplete>").as_str(),
        "<redaction incomplete>",
    );
}

/// Verifies the owned-text alias consumes the same safe final representation.
#[test]
fn redacted_text_into_string_returns_the_final_safe_text() {
    let text = Redactor::standard()
        .redact_field("password", "raw-password")
        .into_complete_text()
        .expect("field output must be complete");

    assert_eq!(text.into_string(), "<redacted>");
}

/// Verifies reason sets remain directly inspectable without requiring callers
/// to parse rendered diagnostic text.
#[test]
fn summary_completion_reason_and_empty_usage_values_are_publicly_observable() {
    let reasons = RedactionReasons::empty()
        .with(RedactionReason::DepthLimitReached)
        .union(RedactionReasons::empty().with(RedactionReason::InvalidJson));
    assert!(reasons.contains(RedactionReason::DepthLimitReached));
    assert!(reasons.contains(RedactionReason::InvalidJson));
    assert!(!reasons.contains(RedactionReason::OutputLimitReached));
}

/// Verifies every currently published reason has an independent set bit.
#[test]
fn every_redaction_reason_round_trips_through_the_reason_set() {
    let reasons = [
        RedactionReason::InputLimitReached,
        RedactionReason::OutputLimitReached,
        RedactionReason::TraversalLimitReached,
        RedactionReason::DepthLimitReached,
        RedactionReason::SourceTruncated,
        RedactionReason::InvalidJson,
        RedactionReason::InvalidUri,
        RedactionReason::InvalidContentType,
        RedactionReason::UnsupportedContentType,
        RedactionReason::InvalidForm,
        RedactionReason::InvalidMultipart,
    ];

    for reason in reasons {
        let set = RedactionReasons::empty().with(reason);
        assert!(set.contains(reason), "{reason:?} should round-trip");
    }
}

/// Verifies the default usage value preserves the public empty-usage contract.
#[test]
fn test_redaction_usage_default_matches_empty_usage() {
    assert_eq!(RedactionUsage::default(), RedactionUsage::empty());
    assert_eq!(RedactionUsage::default().omitted_input_bytes(), Some(0));
}

#[cfg(feature = "http")]
#[test]
fn http_batch_handle_publishes_independent_result() {
    let mut batch = Redactor::standard().batch();
    let url = batch.redact_http_url("https://example.test/?token=raw-token");
    let output = batch.finish();
    let url = output.resolve(url).expect("HTTP batch handle resolves");
    assert!(url.text().as_str().contains("example.test"));
    assert!(!url.text().as_str().contains("raw-token"));
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
}
