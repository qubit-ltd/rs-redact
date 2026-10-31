// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
#![cfg(feature = "http")]

use std::ffi::OsStr;

use qubit_redact::RedactionPolicy;
use qubit_redact::RedactionReason;
use qubit_redact::Redactor;
use qubit_redact::formats::http::BodyCapture;

const BODY: &[u8] = concat!(
    "--b\r\n",
    "Content-Disposition: form-data; name=\"payload\"\r\n",
    "Content-Type: application/json\r\n\r\n",
    "{\"password\":\"multipart-json-secret\",\"visible\":\"json-public\"}\r\n",
    "--b\r\n",
    "Content-Disposition: form-data; name=\"details\"\r\n",
    "Content-Type: application/x-www-form-urlencoded\r\n\r\n",
    "password=multipart-form-secret&visible=form-public\r\n",
    "--b\r\n",
    "Content-Disposition: form-data; name=\"note\"\r\n\r\n",
    "multipart-public\r\n",
    "--b--\r\n",
)
.as_bytes();
const SIMPLE_FORM_BODY: &[u8] = concat!(
    "--b\r\n",
    "Content-Disposition: form-data; name=\"payload\"\r\n",
    "Content-Type: application/x-www-form-urlencoded\r\n\r\n",
    "x=1\r\n--b--\r\n",
)
.as_bytes();

const CONTENT_TYPE: &str = "multipart/form-data; boundary=b";
const SECRETS: [&str; 2] = ["multipart-json-secret", "multipart-form-secret"];

fn redactor(output: usize, depth: usize, nodes: usize, items: usize) -> Redactor {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits
                .max_input_bytes(65_536)
                .max_output_bytes(output)
                .max_depth(depth)
                .max_nodes(nodes)
                .max_collection_items(items);
        })
        .expect("limits should be valid")
        .build()
        .expect("policy should build");
    Redactor::new(policy)
}

fn assert_safe_output(text: &str) {
    for secret in SECRETS {
        assert!(!text.contains(secret), "output leaked {secret}");
    }
    assert!(!text.chars().any(char::is_control));
}

#[test]
fn test_multipart_nested_json_and_form_respect_small_budgets() {
    let sufficient = redactor(65_536, 8, 256, 256);
    let output = sufficient
        .redact_http_body_with_content_type_text(BodyCapture::complete(BODY), Some(CONTENT_TYPE));
    assert_safe_output(output.text().as_str());
    assert!(output.text().as_str().contains("json-public"));
    assert!(output.text().as_str().contains("form-public"));
    assert!(
        output
            .text()
            .as_str()
            .contains("note=<redacted: multipart text part>")
    );
    let exact_output = output.summary().usage().output_bytes();
    assert!(exact_output > 1);

    for output_limit in [0, 1, 8, 9, 10, 16, 32, 64, 256] {
        let output = redactor(output_limit, 8, 256, 256).redact_http_body_with_content_type_text(
            BodyCapture::complete(BODY),
            Some(CONTENT_TYPE),
        );
        assert!(output.summary().usage().output_bytes() <= output_limit);
        assert_safe_output(output.text().as_str());
    }

    for (depth, nodes, items) in [(2, 256, 256), (3, 256, 256), (8, 2, 256), (8, 256, 2)] {
        let output = redactor(65_536, depth, nodes, items).redact_http_body_with_content_type_text(
            BodyCapture::complete(BODY),
            Some(CONTENT_TYPE),
        );
        assert_safe_output(output.text().as_str());
        assert!(output.summary().usage().visited_nodes() <= nodes);
        assert!(output.summary().usage().visited_collection_items() <= items);
        assert!(output.summary().usage().max_depth() <= depth);
        if nodes == 2 || items == 2 {
            assert!(
                output
                    .summary()
                    .reasons()
                    .contains(RedactionReason::TraversalLimitReached)
            );
        }
    }

    let shallow = redactor(65_536, 2, 256, 256).redact_http_body_with_content_type_text(
        BodyCapture::complete(SIMPLE_FORM_BODY),
        Some(CONTENT_TYPE),
    );
    assert!(
        shallow
            .summary()
            .reasons()
            .contains(RedactionReason::DepthLimitReached)
    );
    let boundary = redactor(65_536, 3, 256, 256).redact_http_body_with_content_type_text(
        BodyCapture::complete(SIMPLE_FORM_BODY),
        Some(CONTENT_TYPE),
    );
    assert!(
        !boundary
            .summary()
            .reasons()
            .contains(RedactionReason::DepthLimitReached)
    );
    assert_eq!(boundary.summary().usage().max_depth(), 3);

    let exact = sufficient
        .redact_http_body_with_content_type_text(BodyCapture::complete(BODY), Some(CONTENT_TYPE));
    let exact_size = exact.summary().usage().output_bytes();
    for limit in [exact_size, exact_size.saturating_sub(1)] {
        let output = redactor(limit, 8, 256, 256).redact_http_body_with_content_type_text(
            BodyCapture::complete(BODY),
            Some(CONTENT_TYPE),
        );
        assert!(output.summary().usage().output_bytes() <= limit);
        assert_safe_output(output.text().as_str());
    }
}

#[test]
fn test_multipart_truncation_and_batch_share_budget() {
    let sufficient = redactor(65_536, 8, 256, 256);
    let truncated = BodyCapture::prefix(BODY, BODY.len() - 2);
    let output = sufficient.redact_http_body_with_content_type_text(truncated, Some(CONTENT_TYPE));
    assert!(
        output
            .summary()
            .reasons()
            .contains(RedactionReason::SourceTruncated)
    );
    assert_safe_output(output.text().as_str());

    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            limits
                .max_input_bytes(65_536)
                .max_output_bytes(256)
                .max_depth(8)
                .max_nodes(256)
                .max_collection_items(256);
        })
        .expect("limits should be valid")
        .build()
        .expect("policy should build");
    let redactor = Redactor::new(policy);
    let mut batch = redactor.diagnostic_batch();
    let ordinary = batch.redact_field("ordinary", &"visible-before-multipart");
    let multipart = batch
        .redact_http_body_with_content_type_text(BodyCapture::complete(BODY), Some(CONTENT_TYPE));
    let output = batch.finish_with_marker("");
    assert_safe_output(output.text(ordinary).as_str());
    assert_safe_output(output.text(multipart).as_str());
    assert!(output.summary().usage().output_bytes() <= 256);
    assert!(output.summary().usage().presented_input_bytes() >= BODY.len());
}

#[test]
fn test_exhausted_batch_does_not_advance_later_env_pairs() {
    let redactor = redactor(1, 8, 256, 256);
    let mut batch = redactor.diagnostic_batch();
    let _ordinary = batch.redact_field("ordinary", &"a value longer than one byte");
    assert!(batch.is_output_exhausted());

    let mut visits = 0;
    let pairs = std::iter::from_fn(|| {
        visits += 1;
        Some((OsStr::new("TOKEN"), OsStr::new("multipart-batch-secret")))
    });
    let environment = batch.redact_env_pairs(pairs);
    assert_eq!(visits, 0);

    let output = batch.finish_with_marker("fallback-marker");
    assert!(output.summary().usage().output_bytes() <= 1);
    assert_safe_output(output.text(environment).as_str());
}
