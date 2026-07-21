//! Tests for [`BodyRedactionReason`](qubit_redact::http::BodyRedactionReason).

use qubit_redact::http::BodyRedactionReason;

/// Verifies the opaque-text reason is available to callers.
#[test]
fn test_body_redaction_reason_exposes_opaque_text_variant() {
    assert_eq!(
        BodyRedactionReason::OpaqueText,
        BodyRedactionReason::OpaqueText,
    );
}
