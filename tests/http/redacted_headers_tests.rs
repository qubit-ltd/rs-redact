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
    let redacted = HttpRedactor::default().redact_headers(&headers);
    let rendered = redacted.to_string();

    assert!(!rendered.contains("Bearer raw"));
    assert_eq!(redacted.log_safe_text().as_ref(), rendered);
    assert!(format!("{redacted:?}").contains("RedactedHeaders"));
    assert_eq!(redacted.into_log_safe_text().as_ref(), rendered);
}
