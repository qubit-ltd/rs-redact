//! Tests for multipart header parameter parsing.

use http::HeaderValue;
use qubit_redact::http::{
    BodyCapture,
    HttpRedactor,
};

/// Verifies malformed multipart parameters fail closed.
#[test]
fn test_header_parameter_malformed_multipart_hides_body() {
    let result = HttpRedactor::default().redact_body(
        BodyCapture::complete(b"--x\r\ncontent\r\n--x--\r\n"),
        Some(&HeaderValue::from_static("multipart/form-data; boundary=x")),
    );

    assert!(!result.to_string().contains("content"));
}
