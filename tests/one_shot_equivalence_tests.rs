// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Behavioral equivalence between one-shot and one-item batch redaction.

use std::ffi::OsStr;

use qubit_redact::Redact;
use qubit_redact::RedactionBatchDiagnostics;
use qubit_redact::RedactionBatchHandle;
use qubit_redact::RedactionTextOutput;
use qubit_redact::RedactionWriter;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
use qubit_redact::formats::argv::ArgvItem;

/// Small structured value shared by the domain equivalence test.
struct Credentials;

impl Redact for Credentials {
    /// Writes one public and one secret field through the domain API.
    fn write_redacted(&self, writer: &mut RedactionWriter<'_>) {
        writer.record("Credentials", |fields| {
            fields
                .unredacted("account", || "account-42")
                .sensitive(Sensitivity::Secret, "password", || "raw-secret");
        });
    }
}

/// Asserts two independently published operations have identical safe output
/// and accounting metadata.
fn assert_equivalent(one_shot: &RedactionTextOutput, batch: &RedactionBatchDiagnostics, handle: RedactionBatchHandle) {
    assert_eq!(one_shot.text(), batch.text(handle));
    assert_eq!(one_shot.summary(), batch.summary());
}

/// Domain and scalar one-shot calls preserve their one-item batch semantics.
#[test]
fn test_one_shot_domain_and_field_match_single_batch_items() {
    let redactor = Redactor::strict();

    let domain = redactor.redact(&Credentials);
    let mut batch = redactor.batch();
    let handle = batch.redact_value(&Credentials);
    let output = batch.finish_for_diagnostics("<redaction incomplete>");
    assert_equivalent(&domain, &output, handle);

    let field = redactor.redact_field("password", "raw-secret");
    let mut batch = redactor.batch();
    let handle = batch.redact_field("password", "raw-secret");
    let output = batch.finish_for_diagnostics("<redaction incomplete>");
    assert_equivalent(&field, &output, handle);
}

/// Argv, environment, and process one-shot calls preserve their one-item batch
/// semantics.
#[test]
fn test_one_shot_process_formats_match_single_batch_items() {
    let redactor = Redactor::strict();
    let argv = [
        ArgvItem::plain(OsStr::new("client")),
        ArgvItem::sensitive(OsStr::new("raw-secret"), Sensitivity::Secret),
    ];

    let direct = redactor.redact_argv(argv);
    let mut batch = redactor.batch();
    let handle = batch.redact_argv(argv);
    let output = batch.finish_for_diagnostics("<redaction incomplete>");
    assert_equivalent(&direct, &output, handle);

    let direct = redactor.redact_heuristic_argv(argv);
    let mut batch = redactor.batch();
    let handle = batch.redact_heuristic_argv(argv);
    let output = batch.finish_for_diagnostics("<redaction incomplete>");
    assert_equivalent(&direct, &output, handle);

    let direct = redactor.redact_env("PASSWORD", "raw-secret");
    let mut batch = redactor.batch();
    let handle = batch.redact_env("PASSWORD", "raw-secret");
    let output = batch.finish_for_diagnostics("<redaction incomplete>");
    assert_equivalent(&direct, &output, handle);

    let pairs = [(OsStr::new("PASSWORD"), OsStr::new("raw-secret"))];
    let direct = redactor.redact_env_pairs(pairs);
    let mut batch = redactor.batch();
    let handle = batch.redact_env_pairs(pairs);
    let output = batch.finish_for_diagnostics("<redaction incomplete>");
    assert_equivalent(&direct, &output, handle);

    let arguments = [ArgvItem::plain(OsStr::new("--password=raw-secret"))];
    let direct = redactor.redact_process(OsStr::new("client"), arguments, pairs);
    let mut batch = redactor.batch();
    let handle = batch.redact_process(OsStr::new("client"), arguments, pairs);
    let output = batch.finish_for_diagnostics("<redaction incomplete>");
    assert_equivalent(&direct, &output, handle);
}

/// JSON text and borrowed values preserve their one-item batch semantics.
#[cfg(feature = "json")]
#[test]
fn test_one_shot_json_formats_match_single_batch_items() {
    let redactor = Redactor::strict();
    let text = r#"{"account":"account-42","password":"raw-secret"}"#;

    let direct = redactor.redact_json(text);
    let mut batch = redactor.batch();
    let handle = batch.redact_json(text);
    let output = batch.finish_for_diagnostics("<redaction incomplete>");
    assert_equivalent(&direct, &output, handle);

    let value = serde_json::from_str(text).expect("the test JSON should parse");
    let direct = redactor.redact_json_value(&value);
    let mut batch = redactor.batch();
    let handle = batch.redact_json_value(&value);
    let output = batch.finish_for_diagnostics("<redaction incomplete>");
    assert_equivalent(&direct, &output, handle);
}

/// HTTP URL, headers, and body operations preserve their one-item batch
/// semantics.
#[cfg(feature = "http")]
#[test]
fn test_one_shot_http_formats_match_single_batch_items() {
    use http::HeaderMap;
    use http::HeaderValue;
    use qubit_redact::formats::http::BodyCapture;

    let redactor = Redactor::strict();
    let url = "https://example.test/private?token=raw-secret";
    let direct = redactor.redact_http_url(url);
    let mut batch = redactor.batch();
    let handle = batch.redact_http_url(url);
    let output = batch.finish_for_diagnostics("<redaction incomplete>");
    assert_equivalent(&direct, &output, handle);

    let mut headers = HeaderMap::new();
    headers.insert("authorization", HeaderValue::from_static("Bearer raw-secret"));
    let direct = redactor.redact_http_headers(&headers);
    let mut batch = redactor.batch();
    let handle = batch.redact_http_headers(&headers);
    let output = batch.finish_for_diagnostics("<redaction incomplete>");
    assert_equivalent(&direct, &output, handle);

    let capture = BodyCapture::complete(br#"{"password":"raw-secret"}"#);
    let content_type = HeaderValue::from_static("application/json");
    let direct = redactor.redact_http_body(capture, Some(&content_type));
    let mut batch = redactor.batch();
    let handle = batch.redact_http_body(capture, Some(&content_type));
    let output = batch.finish_for_diagnostics("<redaction incomplete>");
    assert_equivalent(&direct, &output, handle);

    let direct = redactor.redact_http_body_with_content_type_text(capture, Some("application/json"));
    let mut batch = redactor.batch();
    let handle = batch.redact_http_body_with_content_type_text(capture, Some("application/json"));
    let output = batch.finish_for_diagnostics("<redaction incomplete>");
    assert_equivalent(&direct, &output, handle);
}

/// URI one-shot calls preserve their one-item batch semantics.
#[cfg(feature = "uri")]
#[test]
fn test_one_shot_uri_format_matches_single_batch_item() {
    let redactor = Redactor::strict();
    let uri = "scheme://user:password@example.test/private?token=raw-secret";
    let direct = redactor.redact_uri(uri);
    let mut batch = redactor.batch();
    let handle = batch.redact_uri(uri);
    let output = batch.finish_for_diagnostics("<redaction incomplete>");

    assert_equivalent(&direct, &output, handle);
}
