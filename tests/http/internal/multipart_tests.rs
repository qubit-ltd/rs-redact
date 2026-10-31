// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for multipart body redaction.

use http::HeaderValue;
use qubit_redact::MaskPolicy;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::RedactionReasons;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
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

/// A binary opaque part does not prevent a sibling text field from being
/// inspected and rendered.
#[test]
fn test_multipart_binary_sensitive_part_keeps_text_sibling_visible() {
    let body = b"--boundary\r\nContent-Disposition: form-data; name=payload\r\nContent-Type: application/octet-stream\r\n\r\n\xff\r\n--boundary\r\nContent-Disposition: form-data; name=note\r\nContent-Type: text/plain\r\n\r\nvisible note\r\n--boundary--\r\n";
    let output_limit = 256;
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.secret_sensitive("payload");
        })
        .expect("field policy setup must be valid")
        .http(|http| {
            http.text_body(TextBodyPolicy::PassThrough);
        })
        .expect("HTTP policy setup must be valid")
        .limits(|limits| {
            limits.max_output_bytes(output_limit);
        })
        .expect("output limit setup must be valid")
        .build()
        .expect("test policy must be valid");
    let redactor = Redactor::new(policy);
    let content_type = Some(&HeaderValue::from_static("multipart/form-data; boundary=boundary"));

    let inspection = redactor
        .inspect_http_body(BodyCapture::complete(body), content_type)
        .expect("binary application/octet-stream part is opaque, not invalid multipart");
    assert!(inspection.contains_sensitive());

    let output = redactor.redact_http_body(BodyCapture::complete(body), content_type);
    assert!(output.text().as_str().contains("note=visible note"));
    assert!(output.text().as_str().contains("payload=<redacted>"));
    assert!(!output.summary().reasons().contains(RedactionReason::InvalidMultipart));
    assert!(output.summary().usage().output_bytes() <= output_limit);

    let mut batch = redactor.diagnostic_batch();
    let handle = batch.redact_http_body(BodyCapture::complete(body), content_type);
    let published = batch.finish();
    let diagnostic = published.text(handle).as_str();
    assert!(diagnostic.contains("note=visible note"));
    assert!(diagnostic.contains("payload=<redacted>"));
    assert!(
        !published
            .summary()
            .reasons()
            .contains(RedactionReason::InvalidMultipart)
    );
}

/// A non-sensitive binary part uses the opaque marker without invalidating its
/// neighboring text part.
#[test]
fn test_multipart_binary_non_sensitive_part_keeps_text_sibling_visible() {
    let body = b"--boundary\r\nContent-Disposition: form-data; name=blob\r\nContent-Type: application/octet-stream\r\n\r\n\xff\r\n--boundary\r\nContent-Disposition: form-data; name=note\r\nContent-Type: text/plain\r\n\r\nvisible note\r\n--boundary--\r\n";
    let output_limit = 256;
    let policy = RedactionPolicy::builder()
        .http(|http| {
            http.text_body(TextBodyPolicy::PassThrough);
        })
        .expect("HTTP policy setup must be valid")
        .limits(|limits| {
            limits.max_output_bytes(output_limit);
        })
        .expect("output limit setup must be valid")
        .build()
        .expect("test policy must be valid");
    let redactor = Redactor::new(policy);
    let content_type = Some(&HeaderValue::from_static("multipart/form-data; boundary=boundary"));

    let inspection = redactor
        .inspect_http_body(BodyCapture::complete(body), content_type)
        .expect("binary application/octet-stream part is opaque, not invalid multipart");
    assert!(inspection.contains_sensitive());

    let output = redactor.redact_http_body(BodyCapture::complete(body), content_type);
    assert!(output.text().as_str().contains("blob=<redacted: multipart part>"));
    assert!(output.text().as_str().contains("note=visible note"));
    assert!(!output.summary().reasons().contains(RedactionReason::InvalidMultipart));
    assert!(output.summary().usage().output_bytes() <= output_limit);
}

/// Opaque binary values use the configured complete replacement at low and
/// medium sensitivity levels.
#[test]
fn test_multipart_binary_sensitive_part_uses_custom_opaque_masks() {
    let body = b"--boundary\r\nContent-Disposition: form-data; name=low_value\r\nContent-Type: application/octet-stream\r\n\r\n\xff\r\n--boundary\r\nContent-Disposition: form-data; name=medium_value\r\nContent-Type: application/octet-stream\r\n\r\n\xfe\r\n--boundary--\r\n";
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields
                .low_sensitive("low_value")
                .medium_sensitive("medium_value")
                .mask(Sensitivity::Low, MaskPolicy::preserve_edges(1, 1, "[low]", 1))
                .mask(Sensitivity::Medium, MaskPolicy::fixed("[medium]"));
        })
        .expect("field policy setup must be valid")
        .build()
        .expect("test policy must be valid");
    let rendered = redact_body(
        &Redactor::new(policy),
        BodyCapture::complete(body),
        Some(&HeaderValue::from_static("multipart/form-data; boundary=boundary")),
    );

    assert!(rendered.contains("low_value=[low]"));
    assert!(rendered.contains("medium_value=[medium]"));
    assert!(!rendered.contains('\u{fffd}'));
}

/// A complete UTF-8 opaque mask is emitted only when the entire escaped part
/// line fits in the remaining output allowance.
#[test]
fn test_multipart_binary_mask_keeps_complete_line_and_escaped_name_semantics() {
    let body = b"--boundary\r\nContent-Disposition: form-data; name=\"pass\\\\word\"\r\n\r\n\xff\r\n--boundary--\r\n";
    let make_redactor = |max_output_bytes| {
        let policy = RedactionPolicy::builder()
            .fields(|fields| {
                fields
                    .secret_sensitive("pass\\word")
                    .mask(Sensitivity::Secret, MaskPolicy::fixed("界"));
            })
            .expect("field policy setup must be valid")
            .limits(|limits| {
                limits.max_output_bytes(max_output_bytes);
            })
            .expect("output limit setup must be valid")
            .build()
            .expect("test policy must be valid");
        Redactor::new(policy)
    };
    let content_type = Some(&HeaderValue::from_static("multipart/form-data; boundary=boundary"));
    let complete = make_redactor(128).redact_http_body(BodyCapture::complete(body), content_type);
    let expected = r"<multipart>\npass\\word=界\n</multipart>";
    assert_eq!(complete.text().as_str(), expected);
    assert_eq!(complete.summary().completion(), RedactionCompletion::Complete);
    assert_eq!(complete.summary().reasons(), RedactionReasons::empty());

    let exact = make_redactor(expected.len()).redact_http_body(BodyCapture::complete(body), content_type);
    assert_eq!(exact.text().as_str(), expected);
    assert_eq!(exact.summary().completion(), RedactionCompletion::Complete);
    assert_eq!(exact.summary().reasons(), RedactionReasons::empty());

    let short = make_redactor(expected.len() - 1).redact_http_body(BodyCapture::complete(body), content_type);
    assert!(short.text().as_str().len() < expected.len());
    assert_ne!(short.summary().completion(), RedactionCompletion::Complete);
    assert!(short.summary().reasons().contains(RedactionReason::OutputLimitReached));
}

/// Invalid UTF-8 remains an error for a part declared as text.
#[test]
fn test_multipart_invalid_utf8_text_part_remains_invalid() {
    let body = b"--boundary\r\nContent-Disposition: form-data; name=note\r\nContent-Type: text/plain\r\n\r\n\xff\r\n--boundary--\r\n";
    let redactor = Redactor::standard();
    let content_type = Some(&HeaderValue::from_static("multipart/form-data; boundary=boundary"));

    let error = redactor
        .inspect_http_body(BodyCapture::complete(body), content_type)
        .expect_err("invalid UTF-8 text must remain inconclusive");
    assert!(error.reasons().contains(RedactionReason::InvalidMultipart));
    let output = redactor.redact_http_body(BodyCapture::complete(body), content_type);
    assert!(output.summary().reasons().contains(RedactionReason::InvalidMultipart));
}

/// Malformed multipart framing remains an invalid-multipart failure.
#[test]
fn test_multipart_malformed_framing_remains_invalid() {
    let body =
        b"--boundary\r\nContent-Disposition: form-data; name=note\r\nContent-Type: text/plain\r\n\r\nvisible note\r\n";
    let error = Redactor::standard()
        .inspect_http_body(
            BodyCapture::complete(body),
            Some(&HeaderValue::from_static("multipart/form-data; boundary=boundary")),
        )
        .expect_err("missing closing boundary must remain inconclusive");

    assert!(error.reasons().contains(RedactionReason::InvalidMultipart));
}

/// A tiny output budget keeps opaque masks within the transaction limit and
/// reports the incomplete rendering.
#[test]
fn test_multipart_binary_opaque_mask_obeys_small_output_limit() {
    let body = b"--boundary\r\nContent-Disposition: form-data; name=payload\r\nContent-Type: application/octet-stream\r\n\r\n\xff\r\n--boundary--\r\n";
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.secret_sensitive("payload");
        })
        .expect("field policy setup must be valid")
        .limits(|limits| {
            limits.max_output_bytes(1);
        })
        .expect("output limit setup must be valid")
        .build()
        .expect("test policy must be valid");
    let output = Redactor::new(policy).redact_http_body(
        BodyCapture::complete(body),
        Some(&HeaderValue::from_static("multipart/form-data; boundary=boundary")),
    );

    assert_ne!(output.summary().completion(), RedactionCompletion::Complete);
    assert!(!output.text().as_str().contains('\u{fffd}'));
    assert!(output.summary().usage().output_bytes() <= 1);
}
