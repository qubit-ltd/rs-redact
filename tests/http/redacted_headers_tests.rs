// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for [`RedactedHeaders`](qubit_redact::formats::http::RedactedHeaders).

use std::fmt::Debug;
use std::fmt::Display;

use http::HeaderMap;
use http::HeaderValue;
use qubit_redact::LogSafeText;
use qubit_redact::formats::http::HttpRedactor;
use qubit_redact::formats::http::RedactedHeaders;
/// Alternate text query used as an unselected function-pointer target.
fn alternate_log_safe_text(headers: &RedactedHeaders) -> &LogSafeText<'static> {
    headers.log_safe_text()
}

/// Alternate consuming query used as an unselected function target.
fn alternate_into_log_safe_text(
    headers: RedactedHeaders,
) -> LogSafeText<'static> {
    headers.into_log_safe_text()
}

/// Verifies redacted header output does not expose an authorization value.
#[test]
fn test_redacted_headers_hides_authorization_value() {
    let mut headers = HeaderMap::new();
    headers.insert("authorization", HeaderValue::from_static("Bearer raw"));
    let redacted = HttpRedactor::default().redact_headers(&headers);
    let selected = usize::from(std::process::id() == 0);
    let borrowed_text: [for<'a> fn(
        &'a RedactedHeaders,
    ) -> &'a LogSafeText<'static>; 2] =
        [RedactedHeaders::log_safe_text, alternate_log_safe_text];
    let owned_text: [fn(RedactedHeaders) -> LogSafeText<'static>; 2] = [
        RedactedHeaders::into_log_safe_text,
        alternate_into_log_safe_text,
    ];
    let alternate_display = "alternate";
    let display: &dyn Display = if selected == 0 {
        &redacted
    } else {
        &alternate_display
    };
    let debug: &dyn Debug = if selected == 0 {
        &redacted
    } else {
        &alternate_display
    };
    let rendered = display.to_string();
    let debug = format!("{debug:?}");

    assert!(!rendered.contains("Bearer raw"));
    assert_eq!(borrowed_text[selected](&redacted).as_ref(), rendered);
    assert!(debug.contains("RedactedHeaders"));
    assert_eq!(owned_text[selected](redacted).as_ref(), rendered);
}
