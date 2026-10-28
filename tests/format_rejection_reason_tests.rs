// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Structural rejection reasons retained by format writers.

#![cfg(all(feature = "http", feature = "uri"))]

use http::HeaderValue;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason as R;
use qubit_redact::RedactionReasons;
use qubit_redact::Redactor;
use qubit_redact::formats::http::BodyCapture;

fn redactor_with(limits: impl FnOnce(&mut qubit_redact::RedactionLimitsBuilder)) -> Redactor {
    let policy = RedactionPolicy::builder()
        .limits(limits)
        .expect("limits should be valid")
        .build()
        .expect("policy should build");
    Redactor::new(policy)
}

fn depth_reason() -> RedactionReasons {
    RedactionReasons::empty().with(R::DepthLimitReached)
}

fn traversal_reason() -> RedactionReasons {
    RedactionReasons::empty().with(R::TraversalLimitReached)
}

fn assert_uri_reasons(redactor: &Redactor, input: &str, expected: RedactionReasons) {
    let direct = redactor.redact_uri(input);
    let composed = redactor
        .text_composer()
        .uri(|uri| {
            uri.value(input);
        })
        .finish();
    let mut batch = redactor.diagnostic_batch();
    let handle = batch.redact_uri(input);
    let published = batch.finish_with_marker("FALLBACK");
    let inspection = redactor.inspect_uri(input).expect_err("structure should be rejected");

    assert_eq!(inspection.reasons(), expected);
    assert_eq!(direct.summary().reasons(), expected);
    assert_eq!(composed.summary().reasons(), expected);
    assert_eq!(published.summary().reasons(), expected);
    assert_eq!(direct.summary().completion(), RedactionCompletion::Truncated);
    assert_eq!(composed.summary().completion(), RedactionCompletion::Truncated);
    assert_eq!(published.summary().completion(), RedactionCompletion::Truncated);
    assert_eq!(published.text(handle).as_str(), "FALLBACK");
}

fn assert_http_url_reasons(redactor: &Redactor, input: &str, expected: RedactionReasons) {
    let direct = redactor.redact_http_url(input);
    let composed = redactor
        .text_composer()
        .http(|http| {
            http.url(input);
        })
        .finish();
    let mut batch = redactor.diagnostic_batch();
    let handle = batch.redact_http_url(input);
    let published = batch.finish_with_marker("FALLBACK");
    let inspection = redactor
        .inspect_http_url(input)
        .expect_err("structure should be rejected");

    assert_eq!(inspection.reasons(), expected);
    assert_eq!(direct.summary().reasons(), expected);
    assert_eq!(composed.summary().reasons(), expected);
    assert_eq!(published.summary().reasons(), expected);
    assert_eq!(direct.summary().completion(), RedactionCompletion::Truncated);
    assert_eq!(composed.summary().completion(), RedactionCompletion::Truncated);
    assert_eq!(published.summary().completion(), RedactionCompletion::Truncated);
    assert_eq!(published.text(handle).as_str(), "FALLBACK");
}

#[test]
fn test_uri_depth_rejection_has_only_depth_reason() {
    let at_root = redactor_with(|limits| {
        limits.max_depth(0);
    });
    assert_uri_reasons(&at_root, "https://example.test/?public=x", depth_reason());

    let at_query = redactor_with(|limits| {
        limits.max_depth(1);
    });
    assert_uri_reasons(&at_query, "https://example.test/?public=x", depth_reason());
}

#[test]
fn test_http_url_depth_rejection_has_only_depth_reason() {
    let at_root = redactor_with(|limits| {
        limits.max_depth(0);
    });
    assert_http_url_reasons(&at_root, "https://example.test/?public=x", depth_reason());

    let at_query = redactor_with(|limits| {
        limits.max_depth(1);
    });
    assert_http_url_reasons(&at_query, "https://example.test/?public=x", depth_reason());
}

#[test]
fn test_uri_traversal_rejections_have_only_traversal_reason() {
    for redactor in [
        redactor_with(|limits| {
            limits.max_nodes(0);
        }),
        redactor_with(|limits| {
            limits.max_collection_items(0);
        }),
        redactor_with(|limits| {
            limits.max_key_bytes(1);
        }),
    ] {
        assert_uri_reasons(&redactor, "https://example.test/?public=x", traversal_reason());
    }
}

#[test]
fn test_http_url_traversal_rejections_have_only_traversal_reason() {
    for redactor in [
        redactor_with(|limits| {
            limits.max_nodes(0);
        }),
        redactor_with(|limits| {
            limits.max_collection_items(0);
        }),
        redactor_with(|limits| {
            limits.max_key_bytes(1);
        }),
    ] {
        assert_http_url_reasons(&redactor, "https://example.test/?public=x", traversal_reason());
    }
}

#[test]
fn test_http_json_body_depth_reason_matches_all_entry_points() {
    let redactor = redactor_with(|limits| {
        limits.max_depth(1);
    });
    let body = BodyCapture::complete(br#"{"public":{"child":1}}"#);
    let native_type = HeaderValue::from_static("application/json");

    let direct = redactor.redact_http_body(body, Some(&native_type));
    let composed = redactor
        .text_composer()
        .http(|http| {
            http.body(body, Some(&native_type));
        })
        .finish();
    let mut batch = redactor.diagnostic_batch();
    let handle = batch.redact_http_body(body, Some(&native_type));
    let published = batch.finish_with_marker("FALLBACK");
    let inspection = redactor
        .inspect_http_body(body, Some(&native_type))
        .expect_err("nested body should exceed depth");
    let expected = depth_reason();

    assert_eq!(inspection.reasons(), expected);
    assert_eq!(direct.summary().reasons(), expected);
    assert_eq!(composed.summary().reasons(), expected);
    assert_eq!(published.summary().reasons(), expected);
    assert_eq!(direct.summary().completion(), RedactionCompletion::Truncated);
    assert_eq!(composed.summary().completion(), RedactionCompletion::Truncated);
    assert_eq!(published.summary().completion(), RedactionCompletion::Truncated);
    assert_eq!(published.text(handle).as_str(), "FALLBACK");

    let text_direct = redactor.redact_http_body_with_content_type_text(body, Some("application/json"));
    let text_composed = redactor
        .text_composer()
        .http(|http| {
            http.body_with_content_type_text(body, Some("application/json"));
        })
        .finish();
    let text_inspection = redactor
        .inspect_http_body_with_content_type_text(body, Some("application/json"))
        .expect_err("nested body should exceed depth");
    let mut text_batch = redactor.diagnostic_batch();
    let text_handle = text_batch.redact_http_body_with_content_type_text(body, Some("application/json"));
    let text_published = text_batch.finish_with_marker("FALLBACK");

    assert_eq!(text_inspection.reasons(), expected);
    assert_eq!(text_direct.summary().reasons(), expected);
    assert_eq!(text_composed.summary().reasons(), expected);
    assert_eq!(text_published.summary().reasons(), expected);
    assert_eq!(text_direct.summary().completion(), RedactionCompletion::Truncated);
    assert_eq!(text_composed.summary().completion(), RedactionCompletion::Truncated);
    assert_eq!(text_published.summary().completion(), RedactionCompletion::Truncated);
    assert_eq!(text_published.text(text_handle).as_str(), "FALLBACK");
}

#[test]
fn test_depth_rejection_adds_output_reason_only_when_carrier_does_not_fit() {
    let redactor = redactor_with(|limits| {
        limits.max_depth(1).max_output_bytes(1);
    });
    let output = redactor.redact_uri("https://example.test/?public=x");
    assert_eq!(
        output.summary().reasons(),
        RedactionReasons::empty()
            .with(R::DepthLimitReached)
            .with(R::OutputLimitReached)
    );
    assert_eq!(output.summary().completion(), RedactionCompletion::Exhausted);
    assert!(!output.summary().reasons().contains(R::TraversalLimitReached));
}

#[test]
fn test_composer_depth_rejection_keeps_safe_prefix_and_reports_output_limit() {
    let redactor = redactor_with(|limits| {
        limits.max_depth(1).max_output_bytes(8);
    });
    let output = redactor
        .text_composer()
        .literal("safe")
        .uri(|uri| {
            uri.value("https://example.test/?public=x");
        })
        .finish();

    assert_eq!(output.text().as_str(), "safe");
    assert_eq!(
        output.summary().reasons(),
        RedactionReasons::empty()
            .with(R::DepthLimitReached)
            .with(R::OutputLimitReached)
    );
    assert_eq!(output.summary().completion(), RedactionCompletion::Exhausted);
    assert!(!output.summary().reasons().contains(R::TraversalLimitReached));
}
