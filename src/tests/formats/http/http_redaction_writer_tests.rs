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
use crate::formats::json::parse_counter::json_parse_count;
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
