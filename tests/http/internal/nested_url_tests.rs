// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for nested URL redaction in structured bodies.

use qubit_redact::formats::http::HttpRedactor;
/// Verifies a nested URL does not expose query secrets.
#[test]
fn test_nested_url_masks_query_secret() {
    let rendered = HttpRedactor::default()
        .redact_url_str(
            "https://outer.test/?next=https%3A%2F%2Fexample.test%2Fpath%3Fapi_key%3Draw",
        )
        .to_string();

    assert!(!rendered.contains("raw"));
}
