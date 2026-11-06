// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Public transactional API surface checks.

#[cfg(all(feature = "http", feature = "uri", feature = "json"))]
use std::ffi::OsStr;

#[cfg(all(feature = "http", feature = "uri", feature = "json"))]
use http::HeaderMap;
#[cfg(all(feature = "http", feature = "uri", feature = "json"))]
use http::HeaderValue;
use qubit_redact::DiagnosticRedactionBatch;
use qubit_redact::DiagnosticRedactionHandle;
use qubit_redact::DiagnosticRedactionOutput;
use qubit_redact::Redact;
use qubit_redact::RedactedText;
use qubit_redact::RedactedTextComposer;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionSummary;
use qubit_redact::RedactionTextOutput;
use qubit_redact::RedactionUsage;
use qubit_redact::RedactionWriter;
use qubit_redact::Redactor;
use qubit_redact::domain::RedactionEntries;
use qubit_redact::domain::RedactionFields;
use qubit_redact::domain::RedactionItems;
#[cfg(all(feature = "http", feature = "uri", feature = "json"))]
use qubit_redact::formats::argv::ArgvItem;
#[cfg(all(feature = "http", feature = "uri", feature = "json"))]
use qubit_redact::formats::http::BodyCapture;
#[cfg(all(feature = "http", feature = "uri", feature = "json"))]
use serde_json::json;

/// Proves the target public types are available through the crate root.
#[test]
fn test_target_transactional_types_are_public() {
    fn assert_redact<T: Redact + ?Sized>() {}
    let _ = assert_redact::<PublicApiValue>;
    let _: Option<RedactionFields<'_, '_>> = None;
    let _: Option<RedactionItems<'_, '_>> = None;
    let _: Option<RedactionEntries<'_, '_>> = None;
    let _: Option<RedactedText> = None;
    let _: Option<RedactedTextComposer> = None;
    let _: Option<DiagnosticRedactionBatch> = None;
    let _: Option<DiagnosticRedactionOutput> = None;
    let _: Option<DiagnosticRedactionHandle> = None;
    let _: Option<RedactionCompletion> = None;
    let _: Option<RedactionTextOutput> = None;
    let _: Option<RedactionPolicy> = None;
    let _: Option<RedactionSummary> = None;
    let _: Option<RedactionUsage> = None;
    let _: Option<Redactor> = None;
}

#[test]
fn test_batch_resolves_independent_items_without_aggregate_text() {
    let mut batch = Redactor::strict().diagnostic_batch();
    let handle = batch.redact_field("password", "raw-secret");
    let output = batch.finish_with_marker("<redaction incomplete>");

    assert_eq!(
        output.text(handle).as_str(),
        "<redacted>",
        "the password item must be redacted"
    );
    assert_eq!(
        output.summary().completion(),
        RedactionCompletion::Complete,
        "the batch must complete"
    );
}

#[test]
fn test_batch_redacts_one_domain_value() {
    let mut batch = Redactor::strict().diagnostic_batch();
    let handle = batch.redact_value(&PublicApiValue);
    let output = batch.finish_with_marker("<redaction incomplete>");

    assert_eq!(
        output.text(handle).as_str(),
        "PublicApiValue",
        "the batch must use the public Redact implementation"
    );
}

#[test]
fn test_text_composer_builds_one_ordered_text() {
    let output = Redactor::strict()
        .text_composer()
        .literal("password=")
        .field("password", "raw-secret")
        .finish();

    assert_eq!(
        output.text().as_str(),
        "password=<redacted>",
        "the composer must preserve literal and field order"
    );
}

/// Exercises each all-format batch entry point in one shared transaction.
#[cfg(all(feature = "http", feature = "uri", feature = "json"))]
#[test]
fn test_batch_redacts_each_supported_format_as_an_independent_item() {
    let mut batch = Redactor::strict().diagnostic_batch();
    let mut handles = vec![batch.redact_env("TOKEN", "raw-env-token")];
    handles.push(batch.redact_env_pairs([(OsStr::new("TOKEN"), OsStr::new("raw-pair-token"))]));
    handles.push(batch.redact_argv([ArgvItem::plain(OsStr::new("--password=raw-argv"))]));
    handles.push(batch.redact_heuristic_argv([ArgvItem::plain(OsStr::new("--password=raw-heuristic"))]));
    handles.push(batch.redact_process(
        OsStr::new("service"),
        [ArgvItem::plain(OsStr::new("--password=raw-process"))],
        [(OsStr::new("TOKEN"), OsStr::new("raw-process-token"))],
    ));
    handles.push(batch.redact_json(r#"{"password":"raw-json"}"#));
    handles.push(batch.redact_json_value(&json!({"password": "raw-value"})));
    handles.push(batch.redact_uri("https://example.test/?token=raw-uri"));
    handles.push(batch.redact_http_url("https://example.test/?token=raw-url"));

    let mut headers = HeaderMap::new();
    headers.insert("authorization", HeaderValue::from_static("Bearer raw-header"));
    handles.push(batch.redact_http_headers(&headers));
    let content_type = HeaderValue::from_static("text/plain");
    handles.push(batch.redact_http_body(BodyCapture::complete(b"raw body"), Some(&content_type)));
    handles.push(
        batch.redact_http_body_with_content_type_text(BodyCapture::complete(b"raw body text"), Some("text/plain")),
    );

    assert!(
        !batch.is_output_exhausted(),
        "the format batch must remain within its output budget"
    );
    let output = batch.finish_with_marker("<incomplete>");
    for handle in handles {
        assert_ne!(
            output.text(handle).as_str(),
            "<incomplete>",
            "each format item must finish without the fallback marker"
        );
    }
    let mut default_finish_batch = Redactor::strict().diagnostic_batch();
    let default_finish_handle = default_finish_batch.redact_env("TOKEN", "raw-default-finish");
    let default_finish_output = default_finish_batch.finish();
    assert_ne!(
        default_finish_output.text(default_finish_handle).as_str(),
        "<redaction incomplete>",
        "the default finish path must complete the environment item"
    );
}

/// Minimal type used only to prove the public trait is implementable.
struct PublicApiValue;

impl Redact for PublicApiValue {
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.literal("PublicApiValue");
    }
}
