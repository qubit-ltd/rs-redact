//! Tests for [`HttpRedactionPolicyBuilder`](qubit_redact::http::HttpRedactionPolicyBuilder).

use qubit_redact::http::HttpRedactionPolicy;

/// Verifies the HTTP policy builder creates the default policy snapshot.
#[test]
fn test_http_redaction_policy_builder_builds_default_snapshot() {
    let policy = HttpRedactionPolicy::builder()
        .build()
        .expect("the default HTTP policy should be valid");

    assert_eq!(policy, HttpRedactionPolicy::default());
}
