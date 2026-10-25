// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! HTTP adapter transaction contract tests.

#![cfg(feature = "http")]

use http::HeaderMap;
use http::HeaderValue;
use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::Redactor;
use qubit_redact::formats::http::BodyCapture;

/// Verifies every HTTP aggregate operation appends to the parent transaction.
#[test]
fn test_http_aggregate_operations_share_the_parent_transaction_output() {
    let mut headers = HeaderMap::new();
    headers.insert("x-request-id", HeaderValue::from_static("request-42"));

    let output = Redactor::standard()
        .text_composer()
        .literal("http=")
        .http(|http| {
            let _ = http
                .url("https://example.test/path?token=raw")
                .headers(&headers)
                .body(BodyCapture::complete(br#"{"name":"Ada"}"#), None);
        })
        .finish();

    assert!(output.text().as_str().starts_with("http=https://example.test"));
    assert!(output.text().as_str().contains("x-request-id: [request-42]"));
    assert!(output.text().as_str().contains("{\"name\":\"Ada\"}"));
    assert_eq!(output.summary().usage().output_bytes(), output.text().as_str().len());
}

/// Verifies URL, header, and body handles are published only by `finish`.
#[test]
fn test_http_handle_operations_publish_from_the_parent_transaction() {
    let mut headers = HeaderMap::new();
    headers.insert("x-request-id", HeaderValue::from_static("request-42"));

    let mut batch = Redactor::standard().diagnostic_batch();
    let url = batch.redact_http_url("https://example.test/path?token=raw");
    let header = batch.redact_http_headers(&headers);
    let body = batch.redact_http_body(BodyCapture::complete(br#"{"name":"Ada"}"#), None);
    let output = batch.finish_with_marker("<redaction incomplete>");
    assert!(output.text(url).as_str().contains("example.test"));
    assert!(output.text(header).as_str().contains("x-request-id: [request-42]"));
    assert_eq!(output.text(body).as_str(), "{\"name\":\"Ada\"}");
}

/// Verifies direct HTTP handles and one-shot conveniences use the same
/// completed transaction path as the borrowed HTTP facade.
#[test]
fn test_http_direct_handle_and_redactor_convenience_operations() {
    let redactor = Redactor::strict();

    let url = redactor.redact_http_url("https://example.test/path?token=raw");
    assert!(url.text().as_str().contains("example.test"));
    assert!(!url.text().as_str().contains("token=raw"));

    let body = redactor.redact_http_body(BodyCapture::complete(br#"{"password":"raw"}"#), None);
    assert!(!body.text().as_str().contains("raw"));

    let mut batch = redactor.diagnostic_batch();
    let handle = batch.redact_http_url("https://example.test/path?token=raw");
    let output = batch.finish_with_marker("<redaction incomplete>");
    assert!(output.text(handle).as_str().contains("example.test"));

    let mut headers = HeaderMap::new();
    headers.insert("authorization", HeaderValue::from_static("Bearer raw-secret"));

    let headers_output = redactor.redact_http_headers(&headers);
    assert!(!headers_output.text().as_str().contains("raw-secret"));

    let mut batch = redactor.diagnostic_batch();
    let handle = batch.redact_http_headers(&headers);
    let output = batch.finish_with_marker("<redaction incomplete>");
    assert!(!output.text(handle).as_str().contains("raw-secret"));
    assert!(output.text(handle).as_str().contains("authorization"));
}

/// Empty input is not a valid absolute URL and must retain the parser's safe
/// invalid-URI provenance on the public one-shot path.
#[test]
fn test_http_empty_url_reports_safe_invalid_uri_result() {
    let output = Redactor::strict().redact_http_url("");

    assert!(output.summary().reasons().contains(RedactionReason::InvalidUri));
}

/// The composer path must retain invalid-URI provenance for an empty URL.
#[test]
fn test_http_composer_empty_url_reports_safe_invalid_uri_result() {
    let output = Redactor::strict()
        .text_composer()
        .http(|http| {
            http.url("");
        })
        .finish();

    assert!(output.summary().reasons().contains(RedactionReason::InvalidUri));
}

/// The batch path must retain invalid-URI provenance for an empty URL.
#[test]
fn test_http_batch_empty_url_reports_safe_invalid_uri_result() {
    let mut batch = Redactor::strict().diagnostic_batch();
    let handle = batch.redact_http_url("");
    let output = batch.finish_with_marker("<redaction incomplete>");

    assert!(output.summary().reasons().contains(RedactionReason::InvalidUri));
    assert_eq!(output.text(handle).as_str(), "<redacted: invalid URL>");
}

/// Verifies URL rendering receives only the output capacity still available
/// to its parent transaction rather than an independent unbounded ceiling.
#[test]
fn test_http_url_uses_the_session_remaining_output_budget() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_output_bytes(32);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let mut batch = Redactor::new(policy).diagnostic_batch();
    let handle =
        batch.redact_http_url("https://example.test/a-very-long-path?token=raw-secret-token&visible=long-value");
    let output = batch.finish_with_marker("<truncated>");

    assert!(output.text(handle).as_str().len() <= 32);
    assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
    assert!(output.summary().reasons().contains(RedactionReason::OutputLimitReached));
    assert!(output.summary().usage().output_bytes() <= 32);
}

/// Verifies URL, headers, and JSON body traversal all charge the enclosing
/// transaction's structural ledger.
#[test]
fn test_http_formats_share_the_transaction_structural_budget() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(3).max_collection_items(1);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let mut headers = HeaderMap::new();
    headers.insert("x-request-id", HeaderValue::from_static("request-42"));
    let output = Redactor::new(policy)
        .text_composer()
        .http(|http| {
            http.url("https://example.test/");
            http.headers(&headers);
            let _ = http.body(BodyCapture::complete(br#"{"password":"must-not-be-traversed"}"#), None);
        })
        .finish();

    assert!(output.text().as_str().contains("x-request-id"));
    assert!(!output.text().as_str().contains("must-not-be-traversed"));
    assert_eq!(output.summary().usage().visited_nodes(), 3);
    assert_eq!(output.summary().usage().visited_collection_items(), 1);
    assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
}

/// Verifies URL query-pair and embedded-URL traversal are admitted before the
/// HTTP renderer runs. A rejected nested URL must therefore publish only the
/// transaction fallback on both aggregate and handle paths.
#[test]
fn test_http_url_nested_traversal_uses_shared_structural_budget() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(2);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let nested = "https://outer.test/?next=https%3A%2F%2Finner.test%2F%3Ftoken%3Draw-secret";

    let aggregate = Redactor::new(policy.clone())
        .text_composer()
        .http(|http| {
            http.url(nested);
        })
        .finish();
    assert_eq!(aggregate.text().as_str(), "<truncated>");
    assert!(
        aggregate
            .summary()
            .reasons()
            .contains(RedactionReason::TraversalLimitReached)
    );
    assert!(!aggregate.text().as_str().contains("raw-secret"));

    let mut batch = Redactor::new(policy).diagnostic_batch();
    let handle = batch.redact_http_url(nested);
    let output = batch.finish_with_marker("<truncated>");
    assert_eq!(output.text(handle).as_str(), "<truncated>");
    assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
    assert!(!output.text(handle).as_str().contains("raw-secret"));
}

/// Verifies a URL query collection closes at the shared collection limit
/// before the renderer can inspect a later pair.
#[test]
fn test_http_url_query_collection_limit_stops_before_later_pair() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(32).max_collection_items(1);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let output = Redactor::new(policy)
        .text_composer()
        .http(|http| {
            http.url("https://example.test/?first=ok&later=raw-secret");
        })
        .finish();

    assert_eq!(output.text().as_str(), "<truncated>");
    assert_eq!(output.summary().usage().visited_collection_items(), 1);
    assert!(!output.text().as_str().contains("raw-secret"));
}

/// Verifies nested URL query traversal observes the transaction-wide depth
/// ceiling rather than only HTTP's fixed recursion ceiling.
#[test]
fn test_http_nested_url_uses_shared_depth_limit() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(32).max_collection_items(32).max_depth(2);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let output = Redactor::new(policy)
        .text_composer()
        .http(|http| {
            http.url("https://outer.test/?next=https%3A%2F%2Finner.test%2F%3Ftoken%3Draw-secret");
        })
        .finish();

    assert_eq!(output.text().as_str(), "<truncated>");
    assert!(output.summary().reasons().contains(RedactionReason::DepthLimitReached));
    assert!(!output.text().as_str().contains("raw-secret"));
}

/// Verifies text content types use the same session body transaction path as
/// native header values, including individually published body handles.
#[test]
fn test_http_text_content_type_body_operations_publish_safe_results() {
    let aggregate = Redactor::standard()
        .text_composer()
        .http(|http| {
            let _ = http.body_with_content_type_text(
                BodyCapture::complete(br#"{"password":"aggregate-secret"}"#),
                Some("application/json; charset=utf-8"),
            );
        })
        .finish();
    let mut batch = Redactor::standard().diagnostic_batch();
    let handle = batch.redact_http_body_with_content_type_text(
        BodyCapture::complete(br#"{"token":"handle-secret"}"#),
        Some("application/json"),
    );
    let output = batch.finish_with_marker("<redaction incomplete>");

    assert!(!aggregate.text().as_str().contains("aggregate-secret"));
    assert!(!output.text(handle).as_str().contains("handle-secret"));
    assert!(output.text(handle).as_str().contains("token"));
}

/// Invalid URL input must retain the HTTP parser provenance on a staged item
/// while replacing every untrusted source byte with the safe marker.
#[test]
fn test_http_invalid_url_handle_is_safe_and_keeps_reason() {
    let mut batch = Redactor::standard().diagnostic_batch();
    let handle = batch.redact_http_url("https://[not-an-ipv6");
    let output = batch.finish_with_marker("<redaction incomplete>");

    assert!(!output.text(handle).as_str().contains("not-an-ipv6"));
    assert!(output.summary().reasons().contains(RedactionReason::InvalidUri));
}

/// Headers are admitted as one structural collection. Once its shared
/// collection allowance rejects the list, the renderer must not see a later
/// confidential header and the handle reports structural truncation.
#[test]
fn test_http_header_handle_stops_before_later_header_at_collection_limit() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_collection_items(1);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let mut headers = HeaderMap::new();
    headers.insert("x-first", HeaderValue::from_static("visible"));
    headers.insert("authorization", HeaderValue::from_static("Bearer must-not-be-rendered"));
    let mut batch = Redactor::new(policy).diagnostic_batch();
    let handle = batch.redact_http_headers(&headers);
    let output = batch.finish_with_marker("");

    assert!(output.text(handle).as_str().is_empty());
    assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
    assert!(
        output
            .summary()
            .reasons()
            .contains(RedactionReason::TraversalLimitReached)
    );
    assert!(!output.text(handle).as_str().contains("must-not-be-rendered"));
}

/// JSON-looking bodies without an explicit content type still use the parent
/// structural ledger before HTTP body parsing can inspect a later field.
#[test]
fn test_http_inferred_json_body_uses_shared_structural_fallback() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(1);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let mut batch = Redactor::new(policy).diagnostic_batch();
    let handle = batch.redact_http_body(BodyCapture::complete(br#"{"password":"must-not-be-rendered"}"#), None);
    let output = batch.finish_with_marker("<truncated>");

    assert_eq!(output.text(handle).as_str(), "<truncated>");
    assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
    assert!(!output.text(handle).as_str().contains("must-not-be-rendered"));
}

/// URL-encoded form fields are one transaction-owned collection. A later
/// field must not reach the renderer after the shared collection limit closes.
#[test]
fn test_http_form_body_uses_shared_collection_budget() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(32).max_collection_items(1);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let content_type = HeaderValue::from_static("application/x-www-form-urlencoded");

    let output = Redactor::new(policy).redact_http_body(
        BodyCapture::complete(b"first=ok&password=must-not-be-rendered"),
        Some(&content_type),
    );

    assert_eq!(output.text().as_str(), "<truncated>");
    assert_eq!(output.summary().usage().visited_collection_items(), 1);
    assert!(
        output
            .summary()
            .reasons()
            .contains(RedactionReason::TraversalLimitReached)
    );
    assert!(!output.text().as_str().contains("must-not-be-rendered"));
}

/// Multipart parts and their nested JSON values remain in the enclosing
/// transaction's collection and depth ledgers.
#[test]
fn test_http_multipart_body_uses_shared_structural_budget() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(32).max_collection_items(8).max_depth(2);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let content_type = HeaderValue::from_static("multipart/form-data; boundary=boundary");
    let body = b"--boundary\r\nContent-Disposition: form-data; name=\"metadata\"\r\nContent-Type: application/json\r\n\r\n{\"password\":\"must-not-be-rendered\"}\r\n--boundary--\r\n";

    let output = Redactor::new(policy).redact_http_body(BodyCapture::complete(body), Some(&content_type));

    assert_eq!(output.text().as_str(), "<truncated>");
    assert_eq!(output.summary().usage().max_depth(), 2);
    assert!(output.summary().reasons().contains(RedactionReason::DepthLimitReached));
    assert!(!output.text().as_str().contains("must-not-be-rendered"));
}

/// Multipart part admission stops before a later part once the transaction's
/// shared collection allowance is consumed.
#[test]
fn test_http_multipart_parts_use_shared_collection_budget() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(32).max_collection_items(1);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let content_type = HeaderValue::from_static("multipart/form-data; boundary=boundary");
    let body = b"--boundary\r\nContent-Disposition: form-data; name=\"first\"\r\n\r\nok\r\n--boundary\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nmust-not-be-rendered\r\n--boundary--\r\n";

    let output = Redactor::new(policy).redact_http_body(BodyCapture::complete(body), Some(&content_type));

    assert_eq!(output.text().as_str(), "<truncated>");
    assert_eq!(output.summary().usage().visited_collection_items(), 1);
    assert!(
        output
            .summary()
            .reasons()
            .contains(RedactionReason::TraversalLimitReached)
    );
    assert!(!output.text().as_str().contains("must-not-be-rendered"));
}

/// Invalid nested JSON retains parser provenance; only resource rejection is a
/// traversal limit.
#[test]
fn test_http_multipart_nested_json_preserves_invalid_and_limit_reasons() {
    let content_type = HeaderValue::from_static("multipart/form-data; boundary=boundary");
    let invalid_bodies: [&[u8]; 2] = [
        b"--boundary\r\nContent-Disposition: form-data; name=\"metadata\"\r\nContent-Type: application/json\r\n\r\nnot-json-secret\r\n--boundary--\r\n",
        b"--boundary\r\nContent-Disposition: form-data; name=\"metadata\"\r\nContent-Type: application/x-ndjson\r\n\r\n{}\nnot-json-secret\r\n--boundary--\r\n",
    ];
    for body in invalid_bodies {
        let output = Redactor::standard().redact_http_body(BodyCapture::complete(body), Some(&content_type));

        assert!(output.summary().reasons().contains(RedactionReason::InvalidJson));
        assert!(
            !output
                .summary()
                .reasons()
                .contains(RedactionReason::TraversalLimitReached)
        );
        assert!(!output.text().as_str().contains("not-json-secret"));
    }

    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(2).max_collection_items(4);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let valid_json = b"--boundary\r\nContent-Disposition: form-data; name=\"metadata\"\r\nContent-Type: application/json\r\n\r\n{\"safe\":\"ok\"}\r\n--boundary--\r\n";
    let limited = Redactor::new(policy).redact_http_body(BodyCapture::complete(valid_json), Some(&content_type));

    assert!(
        limited
            .summary()
            .reasons()
            .contains(RedactionReason::TraversalLimitReached)
    );
    assert!(!limited.summary().reasons().contains(RedactionReason::InvalidJson));
    assert!(!limited.text().as_str().contains("ok"));
}

/// Builds a URL chain with an exact number of nested layers and query pairs at
/// its leaf.
fn nested_url_with_query_count(layers: usize, query_count: usize) -> String {
    let mut url = url::Url::parse("https://leaf.test/").expect("leaf URL should parse");
    {
        let mut query = url.query_pairs_mut();
        for _ in 0..query_count {
            query.append_pair("password", "raw-secret");
        }
    }
    for _ in 0..layers {
        let mut parent = url::Url::parse("https://redirect.test/").expect("parent URL should parse");
        parent.query_pairs_mut().append_pair("next", url.as_str());
        url = parent;
    }
    url.into()
}

#[test]
fn test_nested_url_node_budget_matches_inspection() {
    let input = "https://outer.test/?next=https%3A%2F%2Finner.test%2F%3Fx%3D1";
    for maximum in [3, 4] {
        let policy = RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_nodes(maximum).max_depth(32).max_output_bytes(4096);
            })
            .expect("valid limits")
            .build()
            .expect("valid policy");
        let redactor = Redactor::new(policy);
        let output = redactor.redact_http_url(input);
        let inspected = redactor.inspect_http_url(input);
        if maximum == 3 {
            assert!(output.summary().reasons().contains(RedactionReason::TraversalLimitReached));
            let error = inspected.expect_err("nested URL root must consume a node");
            assert!(error.reasons().contains(RedactionReason::TraversalLimitReached));
        } else {
            assert!(output.complete_text().is_ok());
            let inspected = inspected.expect("four nodes fit");
            assert_eq!(output.summary().usage().visited_nodes(), 4);
            assert_eq!(inspected.usage().visited_nodes(), 4);
            assert_eq!(inspected.usage().visited_collection_items(), 2);
            assert_eq!(inspected.usage().max_depth(), 3);
        }
    }
}

/// Nested URL boundaries retain the same depth cause across HTTP entry points.
#[test]
fn test_http_nested_url_depth_boundaries_match_render_and_inspection() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits
                .max_depth(32)
                .max_nodes(256)
                .max_collection_items(256)
                .max_output_bytes(65_536);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let redactor = Redactor::new(policy);
    for (layers, query_count) in [(7, 1), (8, 3), (9, 1), (9, 3)] {
        let input = nested_url_with_query_count(layers, query_count);
        let expected_depth = layers >= 9;

        let direct = redactor.redact_http_url(&input);
        assert_eq!(
            direct.summary().reasons().contains(RedactionReason::DepthLimitReached),
            expected_depth,
            "direct URL: layers={layers}, leaf_queries={query_count}, usage={:?}, reasons={:?}",
            direct.summary().usage(),
            direct.summary().reasons(),
        );
        assert!(direct.summary().usage().max_depth() <= 32);
        assert!(direct.summary().usage().output_bytes() <= 65_536);

        let aggregate = redactor
            .text_composer()
            .http(|http| {
                http.url(&input);
            })
            .finish();
        assert_eq!(
            aggregate
                .summary()
                .reasons()
                .contains(RedactionReason::DepthLimitReached),
            expected_depth,
            "composer URL: layers={layers}, leaf_queries={query_count}, usage={:?}, reasons={:?}",
            aggregate.summary().usage(),
            aggregate.summary().reasons(),
        );
        assert!(aggregate.summary().usage().output_bytes() <= 65_536);

        let mut batch = redactor.diagnostic_batch();
        let handle = batch.redact_http_url(&input);
        let output = batch.finish_with_marker("<truncated>");
        assert_eq!(
            output.summary().reasons().contains(RedactionReason::DepthLimitReached),
            expected_depth,
            "batch URL: layers={layers}, leaf_queries={query_count}, usage={:?}, reasons={:?}",
            output.summary().usage(),
            output.summary().reasons(),
        );
        assert!(output.summary().usage().output_bytes() <= 65_536);
        assert!(!output.text(handle).as_str().contains("raw-secret"));

        let inspected = redactor.inspect_http_url(&input);
        assert_eq!(
            inspected
                .as_ref()
                .err()
                .is_some_and(|error| error.reasons().contains(RedactionReason::DepthLimitReached)),
            expected_depth,
            "inspection URL: layers={layers}, leaf_queries={query_count}, usage={:?}, reasons={:?}",
            inspected.as_ref().err().map(|error| error.usage()),
            inspected.as_ref().err().map(|error| error.reasons()),
        );
        assert!(
            inspected.as_ref().map_or_else(
                |error| error.usage().output_bytes(),
                |value| value.usage().output_bytes()
            ) <= 65_536
        );
        let inspected_usage = inspected
            .as_ref()
            .map_or_else(|error| error.usage(), |value| value.usage());
        let direct_usage = direct.summary().usage();
        let aggregate_usage = aggregate.summary().usage();
        let batch_usage = output.summary().usage();
        for usage in [aggregate_usage, batch_usage, inspected_usage] {
            assert_eq!(direct_usage.visited_nodes(), usage.visited_nodes());
            assert_eq!(direct_usage.visited_collection_items(), usage.visited_collection_items());
            assert_eq!(direct_usage.max_depth(), usage.max_depth());
        }
        let expected_nodes = if expected_depth { 18 } else { 1 + layers * 2 + query_count };
        let expected_collection_items = if expected_depth { 9 } else { layers + query_count };
        let expected_max_depth = if expected_depth { 10 } else { layers + 2 };
        assert_eq!(direct_usage.visited_nodes(), expected_nodes);
        assert_eq!(direct_usage.visited_collection_items(), expected_collection_items);
        assert_eq!(direct_usage.max_depth(), expected_max_depth);
    }
}

#[test]
fn test_http_nested_url_structure_budget_boundaries_and_sensitive_values() {
    let input = "https://outer.test/?next=https%3A%2F%2Finner.test%2F%3Fx%3D1";
    for (maximum_nodes, maximum_items, expected_complete) in [(4, 2, true), (3, 2, false), (4, 1, false)] {
        let policy = RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_nodes(maximum_nodes).max_collection_items(maximum_items).max_depth(32);
            })
            .expect("valid limits")
            .build()
            .expect("valid policy");
        let redactor = Redactor::new(policy);
        let output = redactor.redact_http_url(input);
        let inspection = redactor.inspect_http_url(input);
        assert_eq!(output.complete_text().is_ok(), expected_complete);
        assert_eq!(inspection.is_ok(), expected_complete);
        if expected_complete {
            let usage = output.summary().usage();
            let inspected = inspection.expect("exact structural budget should fit").usage();
            assert_eq!(usage.visited_nodes(), 4);
            assert_eq!(usage.visited_collection_items(), 2);
            assert_eq!(usage.max_depth(), 3);
            assert_eq!(usage.visited_nodes(), inspected.visited_nodes());
            assert_eq!(usage.visited_collection_items(), inspected.visited_collection_items());
            assert_eq!(usage.max_depth(), inspected.max_depth());
        } else {
            assert!(output.summary().reasons().contains(RedactionReason::TraversalLimitReached));
            assert!(inspection.unwrap_err().reasons().contains(RedactionReason::TraversalLimitReached));
        }
    }

    let no_query = "https://outer.test/?next=https%3A%2F%2Finner.test%2F";
    let output = Redactor::standard().redact_http_url(no_query);
    let inspection = Redactor::standard()
        .inspect_http_url(no_query)
        .expect("nested URL without query should be inspectable");
    assert_eq!(output.summary().usage().visited_nodes(), 3);
    assert_eq!(output.summary().usage().visited_collection_items(), 1);
    assert_eq!(output.summary().usage().visited_nodes(), inspection.usage().visited_nodes());
    assert_eq!(output.summary().usage().visited_collection_items(), inspection.usage().visited_collection_items());

    let sensitive = "https://outer.test/?password=https%3A%2F%2Finner.test%2F%3Fx%3Draw-secret";
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_nodes(2).max_collection_items(1).max_depth(32);
        })
        .expect("valid limits")
        .build()
        .expect("valid policy");
    let redactor = Redactor::new(policy);
    let output = redactor.redact_http_url(sensitive);
    let inspection = redactor.inspect_http_url(sensitive).expect("masked nested value is not traversed");
    assert!(output.complete_text().is_ok());
    assert!(!output.text().as_str().contains("raw-secret"));
    assert_eq!(output.summary().usage().visited_nodes(), 2);
    assert_eq!(output.summary().usage().visited_nodes(), inspection.usage().visited_nodes());
}

#[test]
fn test_http_nested_url_structural_depth_boundaries() {
    let input = "https://outer.test/?next=https%3A%2F%2Finner.test%2F%3Fx%3D1";
    for maximum_depth in [0, 1, 2] {
        let policy = RedactionPolicy::builder()
            .limits(|limits| {
                limits.max_nodes(16).max_collection_items(16).max_depth(maximum_depth);
            })
            .expect("valid limits")
            .build()
            .expect("policy should build");
        let redactor = Redactor::new(policy);
        let output = redactor.redact_http_url(input);
        let inspection = redactor.inspect_http_url(input).expect_err("query structure exceeds depth");
        assert!(
            output.summary().reasons().contains(RedactionReason::DepthLimitReached),
            "depth={maximum_depth}, reasons={:?}, usage={:?}",
            output.summary().reasons(),
            output.summary().usage(),
        );
        assert!(
            inspection.reasons().contains(RedactionReason::DepthLimitReached),
            "depth={maximum_depth}, reasons={:?}, usage={:?}",
            inspection.reasons(),
            inspection.usage(),
        );
    }
}

/// A malformed embedded URL keeps InvalidUri provenance across render and
/// inspection paths.
#[test]
fn test_http_nested_invalid_url_reason_matches_all_entry_points() {
    let mut url = url::Url::parse("https://outer.test/").expect("outer URL should parse");
    url.query_pairs_mut().append_pair("next", "https://[bad");
    let input = url.as_str();
    let redactor = Redactor::standard();

    let direct = redactor.redact_http_url(input);
    assert!(direct.summary().reasons().contains(RedactionReason::InvalidUri));
    assert!(!direct.text().as_str().contains("https://[bad"));

    let composer = redactor
        .text_composer()
        .http(|http| {
            http.url(input);
        })
        .finish();
    assert!(composer.summary().reasons().contains(RedactionReason::InvalidUri));

    let mut batch = redactor.diagnostic_batch();
    let handle = batch.redact_http_url(input);
    let output = batch.finish_with_marker("<truncated>");
    assert!(output.summary().reasons().contains(RedactionReason::InvalidUri));
    assert!(!output.text(handle).as_str().contains("https://[bad"));

    let inspection = redactor
        .inspect_http_url(input)
        .expect_err("nested invalid URL must fail inspection");
    assert!(inspection.reasons().contains(RedactionReason::InvalidUri));
    assert!(inspection.usage().inspected_input_bytes() > 0);
}

/// Query and form rules classify the same key through their own HTTP contexts.
#[test]
fn test_http_custom_form_payload_uses_query_and_body_contexts() {
    let query_only = RedactionPolicy::builder()
        .http(|http| {
            http.query()
                .raise("custom_form_payload", qubit_redact::Sensitivity::Secret)
                .expect("query rule should be valid");
        })
        .expect("HTTP rules should build")
        .build()
        .expect("policy should build");
    let query_redactor = Redactor::new(query_only);
    let url = "https://example.test/?custom_form_payload=raw-secret";
    let query_output = query_redactor.redact_http_url(url);
    let body_type = HeaderValue::from_static("application/x-www-form-urlencoded");
    let form_output = query_redactor.redact_http_body(
        BodyCapture::complete(b"custom_form_payload=raw-secret"),
        Some(&body_type),
    );
    assert!(!query_output.text().as_str().contains("raw-secret"));
    assert!(form_output.text().as_str().contains("raw-secret"));
    assert_eq!(
        query_redactor
            .inspect_http_url(url)
            .expect("URL inspection should complete")
            .max_sensitivity(),
        Some(qubit_redact::Sensitivity::Secret)
    );
    assert_eq!(
        query_redactor
            .inspect_http_body(
                BodyCapture::complete(b"custom_form_payload=raw-secret"),
                Some(&body_type)
            )
            .expect("form inspection should complete")
            .max_sensitivity(),
        None
    );

    let body_only = RedactionPolicy::builder()
        .http(|http| {
            http.body()
                .raise("custom_form_payload", qubit_redact::Sensitivity::Secret)
                .expect("body rule should be valid");
        })
        .expect("HTTP rules should build")
        .build()
        .expect("policy should build");
    let body_redactor = Redactor::new(body_only);
    let body_output = body_redactor.redact_http_body(
        BodyCapture::complete(b"custom_form_payload=raw-secret"),
        Some(&body_type),
    );
    let query_output = body_redactor.redact_http_url(url);
    assert!(!body_output.text().as_str().contains("raw-secret"));
    assert!(query_output.text().as_str().contains("raw-secret"));
    assert_eq!(
        body_redactor
            .inspect_http_url(url)
            .expect("URL inspection should complete")
            .max_sensitivity(),
        None
    );
    assert_eq!(
        body_redactor
            .inspect_http_body(
                BodyCapture::complete(b"custom_form_payload=raw-secret"),
                Some(&body_type)
            )
            .expect("form inspection should complete")
            .max_sensitivity(),
        Some(qubit_redact::Sensitivity::Secret)
    );

    let global_floor = RedactionPolicy::builder()
        .fields(|fields| {
            fields.raise("custom_form_payload", qubit_redact::Sensitivity::Secret);
        })
        .expect("global rules should build")
        .http(|http| {
            http.body()
                .raise("custom_form_payload", qubit_redact::Sensitivity::Low)
                .expect("context rule should be valid");
        })
        .expect("HTTP rules should build")
        .build()
        .expect("policy should build");
    let global_output = Redactor::new(global_floor).redact_http_body(
        BodyCapture::complete(b"custom_form_payload=raw-secret"),
        Some(&body_type),
    );
    assert!(!global_output.text().as_str().contains("raw-secret"));
}

/// A source-truncated capture reports source provenance and known omitted
/// bytes without claiming that the transaction output limit was reached.
#[test]
fn test_http_known_source_truncation_has_truthful_summary_and_usage() {
    let capture = BodyCapture::truncated(b"visible", 12).expect("total length exceeds capture");
    let content_type = HeaderValue::from_static("text/plain");

    let output = Redactor::standard().redact_http_body(capture, Some(&content_type));

    assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
    assert!(output.summary().reasons().contains(RedactionReason::SourceTruncated));
    assert!(!output.summary().reasons().contains(RedactionReason::OutputLimitReached));
    assert_eq!(output.summary().usage().presented_input_bytes(), 22);
    assert_eq!(output.summary().usage().inspected_input_bytes(), 17);
    assert_eq!(output.summary().usage().omitted_input_bytes(), Some(5));
}

/// Unknown source length keeps omitted-byte accounting unknown while still
/// recording the captured prefix inspected by the HTTP adapter.
#[test]
fn test_http_unknown_source_truncation_keeps_omitted_usage_unknown() {
    let capture = BodyCapture::truncated_unknown(b"visible");

    let output = Redactor::standard().redact_http_body(capture, None);

    assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
    assert!(output.summary().reasons().contains(RedactionReason::SourceTruncated));
    assert!(!output.summary().reasons().contains(RedactionReason::OutputLimitReached));
    assert_eq!(output.summary().usage().presented_input_bytes(), 7);
    assert_eq!(output.summary().usage().inspected_input_bytes(), 7);
    assert_eq!(output.summary().usage().omitted_input_bytes(), None);
}

/// A URL handle created inside an aggregate HTTP namespace records the complete
/// input rejection before parser inspection.
#[test]
fn test_http_namespace_handle_tracks_its_own_input_rejection() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(1);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let mut batch = Redactor::new(policy).diagnostic_batch();
    let handle = batch.redact_http_url("https://example.test/");
    let output = batch.finish_with_marker("");

    assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
    assert!(output.summary().reasons().contains(RedactionReason::InputLimitReached));
    assert!(!output.summary().reasons().contains(RedactionReason::OutputLimitReached));
    assert_eq!(output.summary().usage().presented_input_bytes(), 21);
    assert_eq!(output.summary().usage().inspected_input_bytes(), 0);
    assert!(output.text(handle).as_str().is_empty());
}
