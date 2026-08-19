// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Regression coverage for the post-redesign public transaction API.

use qubit_redact::Redact;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::RedactionReasons;
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
fn transaction_aggregates_literal_field_and_value_and_publishes_handles_on_finish() {
    let redactor = Redactor::new(secret_policy("request_token"));
    let mut session = redactor.session();

    let name = session.redact_field("name", "Ada");
    let _ = session
        .literal("request failed: ")
        .field("request_token", "raw-token")
        .literal("; account=")
        .value(&Account {
            name: "Ada".to_owned(),
            _password: "raw-password".to_owned(),
        });

    let output = session.finish();
    let name = output
        .resolve(name)
        .expect("a handle from this transaction resolves after finish");
    assert_eq!(name.text().as_str(), "Ada");
    assert_eq!(name.summary().completion(), RedactionCompletion::Complete);
    assert!(output.text().as_str().contains("request failed: "));
    assert!(output.text().as_str().contains("<redacted>"));
    assert!(output.text().as_str().contains("Account"));
    assert!(!output.text().as_str().contains("raw-token"));
    assert!(!output.text().as_str().contains("raw-password"));
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
    assert_eq!(
        output.summary().usage().output_bytes(),
        output.text().as_str().len() + name.text().as_str().len()
    );
}

#[test]
fn finished_session_resets_and_old_handles_cannot_cross_transactions() {
    let mut session = Redactor::standard().session();
    let first_handle = session.redact_field("name", "Ada");
    let first = session.finish();
    assert_eq!(first.resolve(first_handle).unwrap().text().as_str(), "Ada");

    let _ = session.literal("next transaction");
    let second = session.finish();
    assert_eq!(second.text().as_str(), "next transaction");
    assert!(second.resolve(first_handle).is_err());
    assert_eq!(second.summary().completion(), RedactionCompletion::Complete);
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
    let output = value.redacted();
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

    let text = output.into_text();
    assert_eq!(text.into_string(), "<redacted>");
}

/// Verifies the owned-text alias consumes the same safe final representation.
#[test]
fn redacted_text_into_string_returns_the_final_safe_text() {
    let text = Redactor::standard()
        .redact_field("password", "raw-password")
        .into_text();

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

#[cfg(feature = "http")]
#[test]
fn http_handle_uses_the_same_single_transaction_publication_boundary() {
    let mut session = Redactor::standard().session();
    let url = session.redact_http_url("https://example.test/?token=raw-token");
    let _ = session.literal(" request completed");

    let output = session.finish();
    let url = output.resolve(url).expect("HTTP handle resolves after finish");
    assert!(url.text().as_str().contains("example.test"));
    assert!(!url.text().as_str().contains("raw-token"));
    assert!(output.text().as_str().contains("request completed"));
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
}
