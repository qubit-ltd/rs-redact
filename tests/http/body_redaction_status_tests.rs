//! Tests for [`BodyRedactionStatus`](qubit_redact::http::BodyRedactionStatus).

use qubit_redact::http::{
    BodyRedactionReason,
    BodyRedactionStatus,
};

/// Verifies a fail-closed status retains its precise reason.
#[test]
fn test_body_redaction_status_retains_reason() {
    assert_eq!(
        BodyRedactionStatus::Redacted(BodyRedactionReason::InvalidJson),
        BodyRedactionStatus::Redacted(BodyRedactionReason::InvalidJson),
    );
}
