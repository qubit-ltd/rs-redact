// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! HTTP output and source completeness regression tests.

#![cfg(feature = "http")]

use qubit_redact::MaskPolicy;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;
use qubit_redact::formats::http::BodyCapture;

fn bounded_policy(field: &str, mask: &str, max_output_bytes: usize) -> Redactor {
    let policy = RedactionPolicy::builder()
        .fields(|fields| {
            fields.raise(field, Sensitivity::Secret);
            fields.mask(Sensitivity::Secret, MaskPolicy::fixed(mask));
        })
        .expect("field policy")
        .limits(|limits| {
            limits.max_output_bytes(max_output_bytes);
        })
        .expect("output limit")
        .build()
        .expect("policy");
    Redactor::new(policy)
}

fn assert_incomplete_redaction(output: &qubit_redact::RedactionTextOutput, secret: &str) {
    assert_ne!(output.summary().completion(), RedactionCompletion::Complete);
    assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
    assert!(output.complete_text().is_err());
    assert!(!output.text().as_str().contains(secret));
}

#[test]
fn test_form_empty_segments_do_not_consume_structure_budget() {
    let policy = RedactionPolicy::standard()
        .to_builder()
        .limits(|limits| {
            limits.max_nodes(1).max_collection_items(0);
        })
        .expect("valid limits")
        .build()
        .expect("valid policy");
    let redactor = Redactor::new(policy);
    let content_type = Some("application/x-www-form-urlencoded");
    for bytes in [b"".as_slice(), b"&".as_slice(), b"&&".as_slice()] {
        assert!(
            redactor
                .inspect_http_body_with_content_type_text(BodyCapture::complete(bytes), content_type)
                .is_ok()
        );
        let output = redactor.redact_http_body_with_content_type_text(BodyCapture::complete(bytes), content_type);
        assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
        assert_eq!(output.summary().usage().visited_nodes(), 1);
        assert_eq!(output.summary().usage().visited_collection_items(), 0);
        assert_eq!(output.text().as_str(), "");
    }
}

#[test]
fn test_form_empty_segments_match_one_field_across_public_entries() {
    let policy = RedactionPolicy::standard()
        .to_builder()
        .limits(|limits| {
            limits.max_nodes(16).max_collection_items(2);
        })
        .expect("valid limits")
        .build()
        .expect("valid policy");
    let redactor = Redactor::new(policy);
    let content_type = "application/x-www-form-urlencoded";
    let baseline = redactor.redact_http_body_with_content_type_text(BodyCapture::complete(b"a=1"), Some(content_type));
    for bytes in [b"&a=1".as_slice(), b"a=1&".as_slice(), b"&a=1&&".as_slice()] {
        let direct = redactor.redact_http_body_with_content_type_text(BodyCapture::complete(bytes), Some(content_type));
        assert_eq!(direct.summary().completion(), RedactionCompletion::Complete);
        assert_eq!(
            direct.summary().usage().visited_nodes(),
            baseline.summary().usage().visited_nodes()
        );
        assert_eq!(
            direct.summary().usage().visited_collection_items(),
            baseline.summary().usage().visited_collection_items()
        );
        assert_eq!(direct.text().as_str(), baseline.text().as_str());

        let inspection = redactor
            .inspect_http_body_with_content_type_text(BodyCapture::complete(bytes), Some(content_type))
            .expect("empty form segments are inspectable");
        assert_eq!(
            inspection.usage().visited_nodes(),
            direct.summary().usage().visited_nodes()
        );
        assert_eq!(
            inspection.usage().visited_collection_items(),
            direct.summary().usage().visited_collection_items()
        );
    }
}

#[test]
fn test_form_empty_segments_still_consume_raw_input_budget() {
    let content_type = "application/x-www-form-urlencoded";
    let policy = RedactionPolicy::standard()
        .to_builder()
        .limits(|limits| {
            limits
                .max_nodes(1)
                .max_collection_items(0)
                .max_input_bytes(content_type.len());
        })
        .expect("valid limits")
        .build()
        .expect("valid policy");
    let output =
        Redactor::new(policy).redact_http_body_with_content_type_text(BodyCapture::complete(b"&"), Some(content_type));
    assert_ne!(output.summary().completion(), RedactionCompletion::Complete);
    assert!(output.summary().reasons().contains(RedactionReason::InputLimitReached));
    assert_eq!(output.summary().usage().presented_input_bytes(), content_type.len() + 1);
    assert_eq!(output.summary().usage().inspected_input_bytes(), 0);
}

#[test]
fn test_form_empty_keys_and_values_are_real_fields() {
    let policy = RedactionPolicy::standard()
        .to_builder()
        .limits(|limits| {
            limits.max_nodes(8).max_collection_items(0);
        })
        .expect("valid limits")
        .build()
        .expect("valid policy");
    let redactor = Redactor::new(policy);
    for bytes in [b"=".as_slice(), b"=v".as_slice(), b"k=".as_slice(), b"%26".as_slice()] {
        let output = redactor.redact_http_body_with_content_type_text(
            BodyCapture::complete(bytes),
            Some("application/x-www-form-urlencoded"),
        );
        assert_ne!(
            output.summary().completion(),
            RedactionCompletion::Complete,
            "{bytes:?}"
        );
        assert!(
            output
                .summary()
                .reasons()
                .contains(RedactionReason::TraversalLimitReached),
            "{bytes:?}: {:?}",
            output.summary().reasons()
        );
    }
}

#[test]
fn test_form_invalid_percent_encoding_keeps_invalid_form_reason() {
    let output = Redactor::standard().redact_http_body_with_content_type_text(
        BodyCapture::complete(b"a=%ZZ"),
        Some("application/x-www-form-urlencoded"),
    );
    assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
    assert!(output.summary().reasons().contains(RedactionReason::InvalidForm));
}

#[test]
fn test_form_empty_segments_share_composer_and_batch_structure_budget() {
    let policy = RedactionPolicy::standard()
        .to_builder()
        .limits(|limits| {
            limits.max_nodes(32).max_collection_items(2);
        })
        .expect("valid limits")
        .build()
        .expect("valid policy");
    let redactor = Redactor::new(policy);
    let content_type = "application/x-www-form-urlencoded";
    let composed = redactor
        .text_composer()
        .http(|http| {
            http.body_with_content_type_text(BodyCapture::complete(b"a=1&&"), Some(content_type));
            http.body_with_content_type_text(BodyCapture::complete(b"b=2"), Some(content_type));
        })
        .finish();
    assert_eq!(composed.summary().completion(), RedactionCompletion::Complete);
    assert_eq!(composed.summary().usage().visited_collection_items(), 2);

    let mut batch = redactor.diagnostic_batch();
    let first = batch.redact_http_body_with_content_type_text(BodyCapture::complete(b"a=1&&"), Some(content_type));
    let second = batch.redact_http_body_with_content_type_text(BodyCapture::complete(b"b=2"), Some(content_type));
    let third = batch.redact_http_body_with_content_type_text(BodyCapture::complete(b"c=3"), Some(content_type));
    let finished = batch.finish_with_marker("<incomplete>");
    assert_eq!(finished.text(first).as_str(), "a=1");
    assert_eq!(finished.text(second).as_str(), "b=2");
    assert_eq!(finished.text(third).as_str(), "<incomplete>");
    assert!(
        finished
            .summary()
            .reasons()
            .contains(RedactionReason::TraversalLimitReached)
    );
    assert_eq!(finished.summary().usage().visited_collection_items(), 2);
}

#[test]
fn test_multipart_form_empty_segments_do_not_consume_nested_structure_budget() {
    let policy = RedactionPolicy::standard()
        .to_builder()
        .limits(|limits| {
            limits.max_nodes(32).max_collection_items(32);
        })
        .expect("valid limits")
        .build()
        .expect("valid policy");
    let redactor = Redactor::new(policy);
    let content_type = Some("multipart/form-data; boundary=boundary");
    let body = |field| {
        format!(
            "--boundary\r\nContent-Disposition: form-data; name=\"fields\"\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n{field}\r\n--boundary--\r\n"
        )
    };
    let baseline_body = body("a=1");
    let with_empty_segments = body("a=1&&");
    let baseline =
        redactor.redact_http_body_with_content_type_text(BodyCapture::complete(baseline_body.as_bytes()), content_type);
    let actual = redactor
        .redact_http_body_with_content_type_text(BodyCapture::complete(with_empty_segments.as_bytes()), content_type);
    assert_eq!(actual.summary().completion(), RedactionCompletion::Complete);
    assert_eq!(
        actual.summary().usage().visited_nodes(),
        baseline.summary().usage().visited_nodes()
    );
    assert_eq!(
        actual.summary().usage().visited_collection_items(),
        baseline.summary().usage().visited_collection_items()
    );
    assert_eq!(actual.text().as_str(), baseline.text().as_str());
}

fn userinfo_redactor(high_mask: &str, secret_mask: &str, max_output_bytes: usize) -> Redactor {
    let policy = RedactionPolicy::standard()
        .to_builder()
        .fields(|fields| {
            fields.raise("username", Sensitivity::High);
            fields.mask(Sensitivity::High, MaskPolicy::fixed(high_mask));
            fields.mask(Sensitivity::Secret, MaskPolicy::fixed(secret_mask));
        })
        .expect("field policy")
        .limits(|limits| {
            limits.max_output_bytes(max_output_bytes);
        })
        .expect("output limit")
        .build()
        .expect("policy");
    Redactor::new(policy)
}

#[test]
fn test_url_username_unicode_mask_truncation_is_reported_and_uses_batch_marker() {
    let redactor = userinfo_redactor("😀", "😀", 11);
    let url = "https://raw@a/";

    let direct = redactor.redact_http_url(url);
    assert_incomplete_redaction(&direct, "raw");
    assert!(direct.text().as_str().len() <= 11);
    assert!(direct.text().as_str().is_char_boundary(direct.text().as_str().len()));

    let mut batch = redactor.diagnostic_batch();
    let handle = batch.redact_http_url(url);
    let diagnostics = batch.finish_with_marker("<incomplete>");
    assert_eq!(diagnostics.text(handle).as_str(), "<incomplete>");
    assert!(
        diagnostics
            .summary()
            .reasons()
            .contains(RedactionReason::OutputLimitReached)
    );
}

#[test]
fn test_url_password_unicode_mask_truncation_and_complete_ascii_controls() {
    let truncated = userinfo_redactor("😀", "😀", 12);
    let direct = truncated.redact_http_url("https://:raw@a/");
    assert_incomplete_redaction(&direct, "raw");
    assert!(direct.text().as_str().len() <= 12);

    let sufficient = userinfo_redactor("😀", "😀", 64);
    let complete = sufficient.redact_http_url("https://raw:secret@a/");
    assert_eq!(complete.summary().completion(), RedactionCompletion::Complete);
    assert!(
        !complete
            .summary()
            .reasons()
            .contains(RedactionReason::OutputLimitReached)
    );
    assert!(!complete.text().as_str().contains("raw"));
    assert!(!complete.text().as_str().contains("secret"));

    let ascii = userinfo_redactor("U", "P", 64).redact_http_url("https://raw:secret@a/");
    assert_eq!(ascii.summary().completion(), RedactionCompletion::Complete);
    assert!(!ascii.summary().reasons().contains(RedactionReason::OutputLimitReached));
    assert_eq!(ascii.text().as_str(), "https://U:P@a/");
}

#[test]
fn test_query_mask_truncation_is_reported_for_one_shot_and_batch() {
    let redactor = bounded_policy("x", "界", 24);
    let url = "https://example.test/?x=raw";

    let direct = redactor.redact_http_url(url);
    assert_incomplete_redaction(&direct, "raw");

    let mut batch = redactor.diagnostic_batch();
    let handle = batch.redact_http_url(url);
    let diagnostics = batch.finish_with_marker("<incomplete>");
    assert_eq!(diagnostics.text(handle).as_str(), "<incomplete>");
    assert_ne!(diagnostics.summary().completion(), RedactionCompletion::Complete);
    assert!(
        diagnostics
            .summary()
            .reasons()
            .contains(RedactionReason::OutputLimitReached)
    );
}

#[test]
fn test_form_mask_truncation_is_reported_for_one_shot_and_batch() {
    let redactor = bounded_policy("a", "😀", 2);
    let capture = || BodyCapture::complete(b"a=secret");

    let direct = redactor.redact_http_body_with_content_type_text(capture(), Some("application/x-www-form-urlencoded"));
    assert_incomplete_redaction(&direct, "secret");

    let mut batch = redactor.diagnostic_batch();
    let handle = batch.redact_http_body_with_content_type_text(capture(), Some("application/x-www-form-urlencoded"));
    let diagnostics = batch.finish_with_marker("<incomplete>");
    assert_eq!(diagnostics.text(handle).as_str(), "<incomplete>");
    assert_ne!(diagnostics.summary().completion(), RedactionCompletion::Complete);
    assert!(
        diagnostics
            .summary()
            .reasons()
            .contains(RedactionReason::OutputLimitReached)
    );
}

#[test]
fn test_disabled_body_preserves_source_and_output_truncation_facts() {
    let sufficient = Redactor::new(RedactionPolicy::disabled());
    let capture = || BodyCapture::truncated(b"prefix", 20).expect("source metadata");
    let source_truncated = sufficient.redact_http_body_with_content_type_text(capture(), Some("text/plain"));
    assert_ne!(source_truncated.summary().completion(), RedactionCompletion::Complete);
    assert!(
        source_truncated
            .summary()
            .reasons()
            .contains(RedactionReason::SourceTruncated)
    );
    assert!(source_truncated.summary().is_redaction_disabled());
    assert_eq!(source_truncated.summary().usage().inspected_input_bytes(), 16);

    let tight_policy = RedactionPolicy::disabled()
        .to_builder()
        .limits(|limits| {
            limits.max_output_bytes(3);
        })
        .expect("output limit")
        .build()
        .expect("policy");
    let both = Redactor::new(tight_policy).redact_http_body_with_content_type_text(capture(), Some("text/plain"));
    assert_ne!(both.summary().completion(), RedactionCompletion::Complete);
    assert!(both.summary().reasons().contains(RedactionReason::SourceTruncated));
    assert!(both.summary().reasons().contains(RedactionReason::OutputLimitReached));
    assert!(both.summary().is_redaction_disabled());
    assert_eq!(both.summary().usage().inspected_input_bytes(), 16);

    let complete =
        sufficient.redact_http_body_with_content_type_text(BodyCapture::complete(b"prefix"), Some("text/plain"));
    assert_eq!(complete.summary().completion(), RedactionCompletion::Complete);
    assert!(complete.summary().is_redaction_disabled());
    assert_eq!(complete.text().as_str(), "prefix");
}
