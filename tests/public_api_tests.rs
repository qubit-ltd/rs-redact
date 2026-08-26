// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Public transactional API surface checks.

use qubit_redact::Redact;
use qubit_redact::RedactedText;
use qubit_redact::RedactedTextComposer;
use qubit_redact::RedactionBatch;
use qubit_redact::RedactionBatchDiagnostics;
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
    let _ = assert_redact::<PublicApiValue>;
    let _: Option<RedactionFields<'_, '_>> = None;
    let _: Option<RedactionItems<'_, '_>> = None;
    let _: Option<RedactionEntries<'_, '_>> = None;
    let _: Option<RedactedText> = None;
    let _: Option<RedactedTextComposer> = None;
    let _: Option<RedactionBatch> = None;
    let _: Option<RedactionBatchDiagnostics> = None;
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

impl Redact for PublicApiValue {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.literal("PublicApiValue");
    }
}
