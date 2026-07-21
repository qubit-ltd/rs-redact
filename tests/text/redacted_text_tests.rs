//! Tests for [`RedactedText`](qubit_redact::RedactedText).

use qubit_redact::Redactor;

/// Verifies redacted text exposes the masked scalar value.
#[test]
fn test_redacted_text_exposes_masked_value() {
    let text = Redactor::default().redact("password", "raw");

    assert_eq!(text.as_str(), "<redacted>");
}
