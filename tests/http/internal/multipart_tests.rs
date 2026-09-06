// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for multipart body redaction.

use http::HeaderValue;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::formats::http::BodyCapture;
use qubit_redact::formats::http::TextBodyPolicy;

use crate::http::support::redaction::redact_body;
/// Verifies multipart file contents are not included in diagnostics.
#[test]
fn test_multipart_hides_file_content() {
    let body = b"--boundary\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"secret.txt\"\r\n\r\nfile-secret\r\n--boundary--\r\n";
    let rendered = redact_body(
        &Redactor::standard(),
        BodyCapture::complete(body),
        Some(&HeaderValue::from_static("multipart/form-data; boundary=boundary")),
    );

    assert!(!rendered.contains("file-secret"));
}

/// Verifies LF-only multipart framing and text-part policy dispatch remain
/// observable through the public HTTP-body entry point.
#[test]
fn test_multipart_lf_framing_passes_non_sensitive_text_when_policy_allows_it() {
    let body = b"--boundary\nContent-Disposition: form-data; name=note\nContent-Type: text/plain\n\nvisible note\n--boundary--\n";
    let policy = RedactionPolicy::builder()
        .http(|http| {
            http.text_body(TextBodyPolicy::PassThrough);
        })
        .expect("HTTP policy setup must be valid")
        .build()
        .expect("test policy must be valid");
    let rendered = redact_body(
        &Redactor::new(policy),
        BodyCapture::complete(body),
        Some(&HeaderValue::from_static("multipart/form-data; boundary=boundary")),
    );

    assert!(rendered.contains("<multipart>"));
    assert!(rendered.contains("note=visible note"));
    assert!(rendered.contains("</multipart>"));
}

/// Verifies a non-sensitive form part receives the ordinary form redaction
/// path instead of being treated as an opaque multipart payload.
#[test]
fn test_multipart_form_part_redacts_nested_sensitive_values() {
    let body = b"--boundary\r\nContent-Disposition: form-data; name=payload\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nlabel=visible&token=form-secret\r\n--boundary--\r\n";
    let rendered = redact_body(
        &Redactor::standard(),
        BodyCapture::complete(body),
        Some(&HeaderValue::from_static("multipart/form-data; boundary=boundary")),
    );

    assert!(rendered.contains("payload="));
    assert!(rendered.contains("label=visible"));
    assert!(!rendered.contains("form-secret"));
}
