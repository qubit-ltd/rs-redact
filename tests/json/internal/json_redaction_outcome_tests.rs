// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for public effects of JSON redaction outcomes.

use http::HeaderValue;
#[cfg(feature = "http")]
use qubit_redact::RedactionPolicy;
use qubit_redact::http::BodyCapture;
use qubit_redact::http::BodyRedactionStatus;
use qubit_redact::http::HttpRedactor;
use qubit_redact::http::UnkeyedJsonValuePolicy;
/// Verifies an explicit unkeyed pass-through reports the matching body status.
#[cfg(feature = "http")]
#[test]
fn test_json_redaction_outcome_reports_unkeyed_pass_through() {
    let policy = RedactionPolicy::builder()
        .unkeyed_json_value_policy(UnkeyedJsonValuePolicy::PassThrough)
        .build()
        .expect("the HTTP policy should build");
    let content_type = HeaderValue::from_static("application/json");
    let body = HttpRedactor::new(policy)
        .redact_body(BodyCapture::complete(br#""visible""#), Some(&content_type));

    assert_eq!(body.status(), BodyRedactionStatus::PassedThrough);
    assert_eq!(body.to_string(), "\"visible\"");
}
