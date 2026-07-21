//! Tests for JSON body redaction.

use http::HeaderValue;
use qubit_redact::http::{
    BodyCapture,
    HttpRedactor,
};

/// Verifies JSON redaction does not expose a secret field value.
#[test]
fn test_json_masks_secret_field_value() {
    let rendered = HttpRedactor::default()
        .redact_body(
            BodyCapture::complete(br#"{"password":"raw"}"#),
            Some(&HeaderValue::from_static("application/json")),
        )
        .to_string();

    assert!(!rendered.contains("raw"));
}
