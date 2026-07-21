//! Tests for bounded-body truncation markers.

use http::HeaderValue;
use qubit_redact::http::{
    BodyBudget,
    BodyCapture,
    HttpRedactionPolicy,
    HttpRedactor,
    TextBodyPolicy,
};

/// Verifies output truncation appends the complete marker.
#[test]
fn test_markers_append_truncation_marker() {
    let budget = BodyBudget::new(64, BodyBudget::MIN_OUTPUT_BYTES)
        .expect("the minimum output budget should be valid");
    let policy = HttpRedactionPolicy::builder()
        .body_budget(budget)
        .text_body_policy(TextBodyPolicy::PassThrough)
        .build()
        .expect("the HTTP policy should be valid");
    let rendered = HttpRedactor::new(policy)
        .redact_body(
            BodyCapture::complete(b"payload larger than marker"),
            Some(&HeaderValue::from_static("text/plain")),
        )
        .to_string();

    assert_eq!(rendered, "<truncated>");
}
