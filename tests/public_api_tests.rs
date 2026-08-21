// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Public transactional API surface checks.

use qubit_redact::Redact;
use qubit_redact::RedactMapValueMut;
use qubit_redact::RedactMut;
use qubit_redact::RedactValueMut;
use qubit_redact::RedactedText;
use qubit_redact::RedactedTextComposer;
use qubit_redact::RedactionBatch;
use qubit_redact::RedactionBatchHandle;
use qubit_redact::RedactionBatchHandleError;
use qubit_redact::RedactionBatchOutput;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionEntries;
use qubit_redact::RedactionFields;
use qubit_redact::RedactionItems;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionSummary;
use qubit_redact::RedactionTextOutput;
use qubit_redact::RedactionUsage;
use qubit_redact::RedactionWriter;
use qubit_redact::Redactor;

/// Proves the target public types are available through the crate root.
#[test]
fn target_transactional_types_are_public() {
    fn assert_redact<T: Redact + ?Sized>() {}
    fn assert_redact_mut<T: RedactMut>() {}
    fn assert_redact_value_mut<T: RedactValueMut>() {}
    fn assert_redact_map_value_mut<T: RedactMapValueMut<String, String>>() {}

    let _ = assert_redact::<PublicApiValue>;
    let _ = assert_redact_mut::<PublicApiMutableValue>;
    let _ = assert_redact_value_mut::<String>;
    let _ = assert_redact_map_value_mut::<std::collections::BTreeMap<String, String>>;
    let _: Option<RedactionFields<'_, '_>> = None;
    let _: Option<RedactionItems<'_, '_>> = None;
    let _: Option<RedactionEntries<'_, '_>> = None;
    let _: Option<RedactedText> = None;
    let _: Option<RedactedTextComposer> = None;
    let _: Option<RedactionBatch> = None;
    let _: Option<RedactionBatchHandle> = None;
    let _: Option<RedactionBatchHandleError> = None;
    let _: Option<RedactionBatchOutput> = None;
    let _: Option<RedactionCompletion> = None;
    let _: Option<RedactionTextOutput> = None;
    let _: Option<RedactionPolicy> = None;
    let _: Option<RedactionSummary> = None;
    let _: Option<RedactionUsage> = None;
    let _: Option<Redactor> = None;
}

#[test]
fn batch_resolves_independent_items_without_aggregate_text() {
    let mut batch = Redactor::strict().batch();
    let handle = batch.redact_field("password", "raw-secret");
    let output = batch.finish();

    assert_eq!(
        output.resolve(handle).expect("batch handle resolves").text().as_str(),
        "<redacted>"
    );
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
}

#[test]
fn batch_redacts_one_domain_value() {
    let mut batch = Redactor::strict().batch();
    let handle = batch.redact_value(&PublicApiValue);
    let output = batch.finish();

    assert_eq!(
        output.resolve(handle).expect("domain handle resolves").text().as_str(),
        "PublicApiValue"
    );
}

#[test]
fn text_composer_builds_one_ordered_text() {
    let output = Redactor::strict()
        .text_composer()
        .literal("password=")
        .field("password", "raw-secret")
        .finish();

    assert_eq!(output.text().as_str(), "password=<redacted>");
}

/// Minimal type used only to prove the public trait is implementable.
struct PublicApiValue;

/// Minimal mutable type used only to prove the root trait is implementable.
struct PublicApiMutableValue;

impl RedactMut for PublicApiMutableValue {
    fn redact_in_place_with(&mut self, _policy: &RedactionPolicy) {}
}

impl Redact for PublicApiValue {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.literal("PublicApiValue");
    }
}
