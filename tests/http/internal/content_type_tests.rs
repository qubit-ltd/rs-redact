//! Tests for content-type dispatch.

use http::HeaderValue;
use qubit_redact::http::{
    BodyCapture,
    BodyRedactionStatus,
    HttpRedactor,
};

/// Verifies JSON content types select structured redaction.
#[test]
fn test_content_type_json_selects_structured_redaction() {
    let result = HttpRedactor::default().redact_body(
        BodyCapture::complete(br#"{"password":"raw"}"#),
        Some(&HeaderValue::from_static("application/json")),
    );

    assert_eq!(result.status(), BodyRedactionStatus::Structured);
}
