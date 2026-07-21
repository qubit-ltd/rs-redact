//! Tests for [`RedactedHeaders`](qubit_redact::http::RedactedHeaders).

use http::{
    HeaderMap,
    HeaderValue,
};
use qubit_redact::http::HttpRedactor;

/// Verifies redacted header output does not expose an authorization value.
#[test]
fn test_redacted_headers_hides_authorization_value() {
    let mut headers = HeaderMap::new();
    headers.insert("authorization", HeaderValue::from_static("Bearer raw"));
    let rendered = HttpRedactor::default().redact_headers(&headers).to_string();

    assert!(!rendered.contains("Bearer raw"));
}
