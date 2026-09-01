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

    assert!(
        output
            .text()
            .as_str()
            .starts_with("http=https://example.test")
    );
    assert!(
        output
            .text()
            .as_str()
            .contains("x-request-id: [request-42]")
    );
    assert!(output.text().as_str().contains("{\"name\":\"Ada\"}"));
    assert_eq!(
        output.summary().usage().output_bytes(),
        output.text().as_str().len()
    );
}

/// Verifies URL, header, and body handles are published only by `finish`.
#[test]
fn test_http_handle_operations_publish_from_the_parent_transaction() {
    let mut headers = HeaderMap::new();
    headers.insert("x-request-id", HeaderValue::from_static("request-42"));

    let mut batch = Redactor::standard().batch();
    let url = batch.redact_http_url("https://example.test/path?token=raw");
    let header = batch.redact_http_headers(&headers);
    let body = batch.redact_http_body(BodyCapture::complete(br#"{"name":"Ada"}"#), None);
    let output = batch.finish();
    assert!(
        output
            .resolve(url)
            .expect("URL handle should publish")
            .text()
            .as_str()
            .contains("example.test")
    );
    assert!(
        output
            .resolve(header)
            .expect("header handle should publish")
            .text()
            .as_str()
            .contains("x-request-id: [request-42]")
    );
    assert_eq!(
        output
            .resolve(body)
            .expect("body handle should publish")
            .text()
            .as_str(),
        "{\"name\":\"Ada\"}"
    );
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

    let mut batch = redactor.batch();
    let handle = batch.redact_http_url("https://example.test/path?token=raw");
    let output = batch.finish();
    assert!(
        output
            .resolve(handle)
            .expect("HTTP handle must resolve")
            .text()
            .as_str()
            .contains("example.test")
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_static("Bearer raw-secret"),
    );

    let headers_output = redactor.redact_http_headers(&headers);
    assert!(!headers_output.text().as_str().contains("raw-secret"));

    let mut batch = redactor.batch();
    let handle = batch.redact_http_headers(&headers);
    let output = batch.finish();
    let headers_output = output
        .resolve(handle)
        .expect("HTTP header handle must resolve");
    assert!(!headers_output.text().as_str().contains("raw-secret"));
    assert!(headers_output.text().as_str().contains("authorization"));
}

/// Empty input is not a valid absolute URL and must retain the parser's safe
/// invalid-URI provenance on the public one-shot path.
#[test]
fn test_http_empty_url_reports_safe_invalid_uri_result() {
    let output = Redactor::strict().redact_http_url("");

    assert!(
        output
            .summary()
            .reasons()
            .contains(RedactionReason::InvalidUri)
    );
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

    assert!(
        output
            .summary()
            .reasons()
            .contains(RedactionReason::InvalidUri)
    );
}

/// The batch path must retain invalid-URI provenance for an empty URL.
#[test]
fn test_http_batch_empty_url_reports_safe_invalid_uri_result() {
    let mut batch = Redactor::strict().batch();
    let handle = batch.redact_http_url("");
    let output = batch.finish();
    let item = output
        .resolve(handle)
        .expect("the completed batch resolves its handle");

    assert!(
        item.summary()
            .reasons()
            .contains(RedactionReason::InvalidUri)
    );
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
    let mut batch = Redactor::new(policy).batch();
    let handle = batch.redact_http_url(
        "https://example.test/a-very-long-path?token=raw-secret-token&visible=long-value",
    );
    let output = batch.finish();
    let url = output
        .resolve(handle)
        .expect("URL handle should publish from the completed transaction");

    assert!(url.text().as_str().len() <= 32);
    assert_eq!(url.summary().completion(), RedactionCompletion::Truncated);
    assert!(
        url.summary()
            .reasons()
            .contains(RedactionReason::OutputLimitReached)
    );
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
            let _ = http.body(
                BodyCapture::complete(br#"{"password":"must-not-be-traversed"}"#),
                None,
            );
        })
        .finish();

    assert!(output.text().as_str().contains("x-request-id"));
    assert!(!output.text().as_str().contains("must-not-be-traversed"));
    assert_eq!(output.summary().usage().visited_nodes(), 3);
    assert_eq!(output.summary().usage().visited_collection_items(), 1);
    assert_eq!(
        output.summary().completion(),
        RedactionCompletion::Truncated
    );
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

    let mut batch = Redactor::new(policy).batch();
    let handle = batch.redact_http_url(nested);
    let output = batch.finish();
    let item = output
        .resolve(handle)
        .expect("truncated URL handle should still publish");
    assert_eq!(item.text().as_str(), "<truncated>");
    assert_eq!(item.summary().completion(), RedactionCompletion::Truncated);
    assert!(!item.text().as_str().contains("raw-secret"));
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
    assert!(
        output
            .summary()
            .reasons()
            .contains(RedactionReason::DepthLimitReached)
    );
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
    let mut batch = Redactor::standard().batch();
    let handle = batch.redact_http_body_with_content_type_text(
        BodyCapture::complete(br#"{"token":"handle-secret"}"#),
        Some("application/json"),
    );
    let output = batch.finish();

    assert!(!aggregate.text().as_str().contains("aggregate-secret"));
    let item = output.resolve(handle).expect("body handle should publish");
    assert!(!item.text().as_str().contains("handle-secret"));
    assert!(item.text().as_str().contains("token"));
}

/// Invalid URL input must retain the HTTP parser provenance on a staged item
/// while replacing every untrusted source byte with the safe marker.
#[test]
fn test_http_invalid_url_handle_is_safe_and_keeps_reason() {
    let mut batch = Redactor::standard().batch();
    let handle = batch.redact_http_url("https://[not-an-ipv6");
    let output = batch.finish();
    let item = output
        .resolve(handle)
        .expect("finished transaction publishes URL handle");

    assert!(!item.text().as_str().contains("not-an-ipv6"));
    assert!(
        item.summary()
            .reasons()
            .contains(RedactionReason::InvalidUri)
    );
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
    headers.insert(
        "authorization",
        HeaderValue::from_static("Bearer must-not-be-rendered"),
    );
    let mut batch = Redactor::new(policy).batch();
    let handle = batch.redact_http_headers(&headers);
    let output = batch.finish();
    let item = output
        .resolve(handle)
        .expect("truncated header handle publishes");

    assert!(item.text().as_str().is_empty());
    assert_eq!(item.summary().completion(), RedactionCompletion::Truncated);
    assert!(
        item.summary()
            .reasons()
            .contains(RedactionReason::TraversalLimitReached)
    );
    assert!(!item.text().as_str().contains("must-not-be-rendered"));
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
    let mut batch = Redactor::new(policy).batch();
    let handle = batch.redact_http_body(
        BodyCapture::complete(br#"{"password":"must-not-be-rendered"}"#),
        None,
    );
    let output = batch.finish();
    let item = output
        .resolve(handle)
        .expect("truncated body handle publishes");

    assert_eq!(item.text().as_str(), "<truncated>");
    assert_eq!(item.summary().completion(), RedactionCompletion::Truncated);
    assert!(!item.text().as_str().contains("must-not-be-rendered"));
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

    let output =
        Redactor::new(policy).redact_http_body(BodyCapture::complete(body), Some(&content_type));

    assert_eq!(output.text().as_str(), "<truncated>");
    assert_eq!(output.summary().usage().max_depth(), 2);
    assert!(
        output
            .summary()
            .reasons()
            .contains(RedactionReason::DepthLimitReached)
    );
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

    let output =
        Redactor::new(policy).redact_http_body(BodyCapture::complete(body), Some(&content_type));

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

/// A source-truncated capture reports source provenance and known omitted
/// bytes without claiming that the transaction output limit was reached.
#[test]
fn test_http_known_source_truncation_has_truthful_summary_and_usage() {
    let capture = BodyCapture::truncated(b"visible", 12).expect("total length exceeds capture");
    let content_type = HeaderValue::from_static("text/plain");

    let output = Redactor::standard().redact_http_body(capture, Some(&content_type));

    assert_eq!(
        output.summary().completion(),
        RedactionCompletion::Truncated
    );
    assert!(
        output
            .summary()
            .reasons()
            .contains(RedactionReason::SourceTruncated)
    );
    assert!(
        !output
            .summary()
            .reasons()
            .contains(RedactionReason::OutputLimitReached)
    );
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

    assert_eq!(
        output.summary().completion(),
        RedactionCompletion::Truncated
    );
    assert!(
        output
            .summary()
            .reasons()
            .contains(RedactionReason::SourceTruncated)
    );
    assert!(
        !output
            .summary()
            .reasons()
            .contains(RedactionReason::OutputLimitReached)
    );
    assert_eq!(output.summary().usage().presented_input_bytes(), 7);
    assert_eq!(output.summary().usage().inspected_input_bytes(), 7);
    assert_eq!(output.summary().usage().omitted_input_bytes(), None);
}

/// A URL handle created inside an aggregate HTTP namespace records only its
/// admitted parser prefix and its own input-limit reason.
#[test]
fn test_http_namespace_handle_tracks_its_own_input_rejection() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits.max_input_bytes(1);
        })
        .expect("limit draft should build")
        .build()
        .expect("policy should build");
    let mut batch = Redactor::new(policy).batch();
    let handle = batch.redact_http_url("https://example.test/");
    let output = batch.finish();
    let item = output.resolve(handle).expect("handle should resolve");

    assert_eq!(item.summary().completion(), RedactionCompletion::Truncated);
    assert!(
        item.summary()
            .reasons()
            .contains(RedactionReason::InputLimitReached)
    );
    assert!(
        !item
            .summary()
            .reasons()
            .contains(RedactionReason::OutputLimitReached)
    );
    assert_eq!(item.summary().usage().presented_input_bytes(), 21);
    assert_eq!(item.summary().usage().inspected_input_bytes(), 1);
}
