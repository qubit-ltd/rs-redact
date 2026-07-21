//! Tests for multipart part metadata redaction.

use http::HeaderValue;
use qubit_redact::http::{
    BodyCapture,
    HttpRedactor,
};

/// Verifies multipart filenames are removed from rendered diagnostics.
#[test]
fn test_multipart_part_metadata_hides_filename() {
    let body = b"--boundary\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"secret.txt\"\r\n\r\ncontent\r\n--boundary--\r\n";
    let rendered = HttpRedactor::default()
        .redact_body(
            BodyCapture::complete(body),
            Some(&HeaderValue::from_static(
                "multipart/form-data; boundary=boundary",
            )),
        )
        .to_string();

    assert!(!rendered.contains("secret.txt"));
}
