// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! HTTP reuse of admitted JSON trees, observed through existing parser
//! counters.

use http::HeaderValue;

use crate::Redactor;
use crate::formats::http::BodyCapture;
use crate::formats::json::parse_counter::json_materialization_count;
use crate::formats::json::parse_counter::json_parse_count;
use crate::formats::json::parse_counter::reset_json_materialization_count;
use crate::formats::json::parse_counter::reset_json_parse_count;

/// Verifies HTTP JSON admission and rendering share one parsed tree.
#[test]
fn test_enabled_http_json_body_is_parsed_exactly_once() {
    reset_json_parse_count();

    let output = Redactor::standard().redact_http_body(
        BodyCapture::complete(br#"{"token":"raw-secret"}"#),
        Some(&HeaderValue::from_static("application/json")),
    );

    assert_eq!(json_parse_count(), 1);
    assert!(!output.text().as_str().contains("raw-secret"));
}

/// Verifies each non-empty NDJSON line is parsed exactly once.
#[test]
fn test_enabled_http_ndjson_lines_are_parsed_exactly_once() {
    reset_json_parse_count();

    let output = Redactor::standard().redact_http_body(
        BodyCapture::complete(b"{\"token\":\"one\"}\n{\"token\":\"two\"}\n"),
        Some(&HeaderValue::from_static("application/x-ndjson")),
    );

    assert_eq!(json_parse_count(), 2);
    assert!(!output.text().as_str().contains("one"));
    assert!(!output.text().as_str().contains("two"));
}

/// Verifies multipart JSON admission and rendering reuse one parsed tree.
#[test]
fn test_enabled_multipart_json_part_is_parsed_exactly_once() {
    reset_json_parse_count();

    let body = concat!(
        "--b\r\n",
        "Content-Disposition: form-data; name=\"payload\"\r\n",
        "Content-Type: application/json\r\n\r\n",
        "{\"token\":\"raw-secret\"}\r\n",
        "--b--\r\n",
    );
    let output = Redactor::standard().redact_http_body(
        BodyCapture::complete(body.as_bytes()),
        Some(&HeaderValue::from_static("multipart/form-data; boundary=b")),
    );

    assert_eq!(json_parse_count(), 1);
    assert!(!output.text().as_str().contains("raw-secret"));
}

/// Verifies multipart NDJSON records are each parsed once and reused.
#[test]
fn test_enabled_multipart_ndjson_records_are_parsed_exactly_once() {
    reset_json_parse_count();

    let body = concat!(
        "--b\r\n",
        "Content-Disposition: form-data; name=\"payload\"\r\n",
        "Content-Type: application/x-ndjson\r\n\r\n",
        "{\"token\":\"first-secret\"}\n{\"token\":\"second-secret\"}\n\r\n",
        "--b--\r\n",
    );
    let output = Redactor::standard().redact_http_body(
        BodyCapture::complete(body.as_bytes()),
        Some(&HeaderValue::from_static("multipart/form-data; boundary=b")),
    );

    assert_eq!(json_parse_count(), 2);
    assert!(!output.text().as_str().contains("first-secret"));
    assert!(!output.text().as_str().contains("second-secret"));
}

#[test]
fn test_http_json_preflight_stops_before_unique_decoder_for_shared_depth_excess() {
    let policy = crate::RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_depth(1).max_input_bytes(1_000_000);
        })
        .expect("limits")
        .build()
        .expect("policy");
    let redactor = Redactor::new(policy);
    let body = format!("[{}]", "0,".repeat(10_000) + "0");

    reset_json_materialization_count();
    let output = redactor.redact_http_body(
        BodyCapture::complete(body.as_bytes()),
        Some(&HeaderValue::from_static("application/json")),
    );

    assert_eq!(json_materialization_count(), 0);
    assert!(
        output
            .summary()
            .reasons()
            .contains(crate::RedactionReason::DepthLimitReached)
    );
}

#[test]
fn test_http_ndjson_preflight_stops_before_unique_decoder_for_shared_node_excess() {
    let policy = crate::RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(1).max_input_bytes(1_000_000);
        })
        .expect("limits")
        .build()
        .expect("policy");
    let redactor = Redactor::new(policy);

    reset_json_materialization_count();
    let output = redactor.redact_http_body(
        BodyCapture::complete(b"0\n[1]\n"),
        Some(&HeaderValue::from_static("application/x-ndjson")),
    );

    assert_eq!(json_materialization_count(), 1);
    assert!(
        output
            .summary()
            .reasons()
            .contains(crate::RedactionReason::TraversalLimitReached)
    );
}

#[test]
fn test_multipart_json_preflight_stops_before_unique_decoder_for_shared_node_excess() {
    let policy = crate::RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(1).max_input_bytes(1_000_000);
        })
        .expect("limits")
        .build()
        .expect("policy");
    let redactor = Redactor::new(policy);
    let body = concat!(
        "--b\r\n",
        "Content-Disposition: form-data; name=\"payload\"\r\n",
        "Content-Type: application/json\r\n\r\n",
        "[1]\r\n",
        "--b--\r\n",
    );

    reset_json_materialization_count();
    let output = redactor.redact_http_body(
        BodyCapture::complete(body.as_bytes()),
        Some(&HeaderValue::from_static("multipart/form-data; boundary=b")),
    );

    assert_eq!(json_materialization_count(), 0);
    assert!(
        output
            .summary()
            .reasons()
            .contains(crate::RedactionReason::TraversalLimitReached)
    );
}
