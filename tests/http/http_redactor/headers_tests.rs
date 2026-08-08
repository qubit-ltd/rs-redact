// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for deterministic header grouping.

use http::HeaderMap;
use http::HeaderValue;
use qubit_redact::http::HttpRedactor;
/// Verifies repeated values remain grouped beneath their sorted header name.
#[test]
fn test_headers_group_repeated_values_in_insertion_order() {
    let mut headers = HeaderMap::new();
    headers.insert("z-last", HeaderValue::from_static("z"));
    headers.append("x-visible", HeaderValue::from_static("first"));
    headers.append("x-visible", HeaderValue::from_static("second"));

    let rendered = HttpRedactor::default().redact_headers(&headers).to_string();

    assert_eq!(rendered, "x-visible: [first, second]\\nz-last: [z]");
}
