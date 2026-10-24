// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! HTTP parsing and output-omission contracts across bounded diagnostics.

#![cfg(feature = "http")]

use http::HeaderMap;
use http::HeaderValue;
use qubit_redact::MaskPolicy;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
use qubit_redact::formats::http::BodyCapture;

#[test]
fn test_real_ndjson_separator_preserves_visible_field() {
    let redactor = Redactor::standard();
    let valid = "{\"noise\":\"427b93\"}\n{\"password\":\"raw-secret\"}";
    let output = redactor
        .redact_http_body_with_content_type_text(BodyCapture::complete(valid.as_bytes()), Some("application/x-ndjson"));
    assert!(!output.summary().reasons().contains(RedactionReason::InvalidJson));
    assert!(output.text().as_str().contains("427b93"));
    assert!(!output.text().as_str().contains("raw-secret"));
    let invalid = valid.replace('\n', "\\n");
    let output = redactor.redact_http_body_with_content_type_text(
        BodyCapture::complete(invalid.as_bytes()),
        Some("application/x-ndjson"),
    );
    assert!(output.summary().reasons().contains(RedactionReason::InvalidJson));
    assert!(!output.text().as_str().contains("raw-secret"));
}

#[test]
fn test_ndjson_blank_records_agree_between_inspection_and_rendering() {
    let redactor = Redactor::standard();
    for body in ["{}\n  \n{}\n", "\r\n{}\r\n\t\r\n{}\r\n", " \n\t\n", "{}\n\n{}", "{}"] {
        let capture = BodyCapture::complete(body.as_bytes());
        let inspection = redactor
            .inspect_http_body_with_content_type_text(capture, Some("application/x-ndjson"))
            .expect("blank lines are not JSON records");
        let output = redactor.redact_http_body_with_content_type_text(capture, Some("application/x-ndjson"));
        assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
        assert!(!output.summary().reasons().contains(RedactionReason::InvalidJson));
        assert_eq!(inspection.usage().output_bytes(), 0);
    }
    for body in [b"not-json\n".as_slice(), b"{}\n\xff"] {
        let error = redactor
            .inspect_http_body_with_content_type_text(BodyCapture::complete(body), Some("application/x-ndjson"))
            .expect_err("invalid non-blank records and invalid UTF-8 must fail closed");
        assert!(error.reasons().contains(RedactionReason::InvalidJson));
    }
}

#[test]
fn test_multipart_ndjson_blank_records_agree_between_inspection_and_rendering() {
    let body = concat!(
        "--boundary\r\n",
        "Content-Disposition: form-data; name=\"events\"\r\n",
        "Content-Type: application/x-ndjson\r\n\r\n",
        "{}\r\n \r\n\t\r\n{}\r\n",
        "--boundary--\r\n",
    );
    let redactor = Redactor::standard();
    let capture = BodyCapture::complete(body.as_bytes());
    let inspection = redactor
        .inspect_http_body_with_content_type_text(capture, Some("multipart/form-data; boundary=boundary"))
        .expect("multipart blank lines are not JSON records");
    let output =
        redactor.redact_http_body_with_content_type_text(capture, Some("multipart/form-data; boundary=boundary"));
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
    assert!(!output.summary().reasons().contains(RedactionReason::InvalidJson));
    assert_eq!(inspection.usage().output_bytes(), 0);

    let blank_body = concat!(
        "--boundary\r\n",
        "Content-Disposition: form-data; name=\"events\"\r\n",
        "Content-Type: application/x-ndjson\r\n\r\n",
        " \r\n\t\r\n",
        "--boundary--\r\n",
    );
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(2).max_depth(2);
        })
        .expect("valid limits")
        .build()
        .expect("valid policy");
    let admitted = Redactor::new(policy)
        .inspect_http_body_with_content_type_text(
            BodyCapture::complete(blank_body.as_bytes()),
            Some("multipart/form-data; boundary=boundary"),
        )
        .expect("blank nested records must not charge a depth-three JSON node");
    assert_eq!(admitted.usage().visited_nodes(), 2);
    assert_eq!(admitted.usage().max_depth(), 2);

    let invalid_body = concat!(
        "--boundary\r\n",
        "Content-Disposition: form-data; name=\"events\"\r\n",
        "Content-Type: application/x-ndjson\r\n\r\n",
        " \r\nnot-json\r\n",
        "--boundary--\r\n",
    );
    let error = redactor
        .inspect_http_body_with_content_type_text(
            BodyCapture::complete(invalid_body.as_bytes()),
            Some("multipart/form-data; boundary=boundary"),
        )
        .expect_err("non-blank invalid multipart record must still fail closed");
    assert!(error.reasons().contains(RedactionReason::InvalidJson));

    let invalid_utf8_body = [
        b"--boundary\r\nContent-Disposition: form-data; name=\"events\"\r\nContent-Type: application/x-ndjson\r\n\r\n".as_slice(),
        b"{}\r\n\xff\r\n",
        b"--boundary--\r\n",
    ]
    .concat();
    let error = redactor
        .inspect_http_body_with_content_type_text(
            BodyCapture::complete(&invalid_utf8_body),
            Some("multipart/form-data; boundary=boundary"),
        )
        .expect_err("multipart NDJSON must reject invalid UTF-8");
    assert!(error.reasons().contains(RedactionReason::InvalidJson));
}

#[test]
fn test_nested_http_output_rejection_closes_later_batch_items() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_output_bytes(64);
        })
        .expect("limits")
        .build()
        .expect("policy");
    let redactor = Redactor::new(policy);
    let body = serde_json::to_string(&vec!["visible"; 16]).expect("array JSON");
    let admitted = redactor
        .redact_http_body_with_content_type_text(BodyCapture::complete(body.as_bytes()), Some("application/json"))
        .summary()
        .usage()
        .inspected_input_bytes();
    let mut batch = redactor.diagnostic_batch();
    let first =
        batch.redact_http_body_with_content_type_text(BodyCapture::complete(body.as_bytes()), Some("application/json"));
    let second = batch.redact_field("id", "should-not-appear");
    let output = batch.finish_with_marker("<incomplete>");
    assert_eq!(output.text(first).as_str(), "<incomplete>");
    assert_eq!(output.text(second).as_str(), "<incomplete>");
    assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
    assert_eq!(output.summary().usage().inspected_input_bytes(), admitted);
}

#[test]
fn test_source_truncation_keeps_its_reason_without_closing_remaining_output() {
    let mut batch = Redactor::standard().diagnostic_batch();
    let first = batch.redact_http_body_with_content_type_text(
        BodyCapture::truncated(b"prefix", 20).expect("source metadata"),
        Some("text/plain"),
    );
    let second = batch.redact_field("id", "visible");
    let output = batch.finish_with_marker("<incomplete>");
    assert_eq!(output.text(first).as_str(), "<incomplete>");
    assert_eq!(output.text(second).as_str(), "visible");
    assert!(output.summary().reasons().contains(RedactionReason::SourceTruncated));
    assert!(!output.summary().reasons().contains(RedactionReason::OutputLimitReached));
}

#[test]
fn test_http_url_output_omission_always_records_output_limit() {
    for source in [
        "https://example.test/?first=abcdefghijk&second=lmnopqrstuvwxyz",
        "https://example.test/#private-fragment",
    ] {
        let complete = Redactor::standard().redact_http_url(source);
        for maximum in 1..complete.text().as_str().len() {
            let policy = RedactionPolicy::builder()
                .limits(|limits| {
                    limits.max_output_bytes(maximum);
                })
                .expect("limits")
                .build()
                .expect("policy");
            let output = Redactor::new(policy).redact_http_url(source);
            assert!(output.text().as_str().len() <= maximum);
            assert!(
                output.summary().reasons().contains(RedactionReason::OutputLimitReached),
                "omitted URL output must be recorded at limit {maximum}: {output:?}"
            );
        }
    }
}

#[test]
fn test_http_header_utf8_mask_omission_records_output_limit() {
    let mut headers = HeaderMap::new();
    headers.insert("authorization", HeaderValue::from_static("raw-secret"));
    for maximum in 1..23 {
        let policy = RedactionPolicy::builder()
            .fields(|fields| {
                fields.mask(Sensitivity::High, MaskPolicy::fixed("界界"));
                fields.mask(Sensitivity::Secret, MaskPolicy::fixed("界界"));
            })
            .expect("mask")
            .limits(|limits| {
                limits.max_output_bytes(maximum);
            })
            .expect("limits")
            .build()
            .expect("policy");
        let output = Redactor::new(policy).redact_http_headers(&headers);
        assert!(output.text().as_str().len() <= maximum);
        assert!(
            output.summary().reasons().contains(RedactionReason::OutputLimitReached),
            "omitted mask must be recorded at limit {maximum}: {output:?}"
        );
    }
}
