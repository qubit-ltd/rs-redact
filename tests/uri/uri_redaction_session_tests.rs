// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared-session URI regression tests.

use qubit_redact::InputOutputLimit;
use qubit_redact::RedactionPolicy;
use qubit_redact::UriRedactor;

/// Verifies output exhaustion short-circuits later URI input admission.
#[test]
fn test_uri_session_does_not_charge_input_after_output_exhaustion() {
    let budget = InputOutputLimit::new(8, InputOutputLimit::MIN_OUTPUT_BYTES)
        .expect("the marker-sized diagnostic budget should be valid");
    let policy = RedactionPolicy::builder()
        .diagnostic_event(budget)
        .build()
        .expect("the URI policy should build");
    let redactor = UriRedactor::new(policy);
    let mut session = redactor.session();
    let _ = session.uri().redact_uri_str(
        "scheme://user:secret@example.test/private?token=secret#fragment",
    );
    let input_before = session.remaining_input_bytes();
    let second = session.uri().redact_uri_str("scheme://unread-secret");
    assert_eq!(second.log_safe_text().as_str(), "<invalid URI>");
    assert_eq!(session.remaining_input_bytes(), input_before);
    let third = session.uri().redact_uri_str("https://must-not-be-read");
    assert_eq!(third.log_safe_text().as_str(), "");
    assert_eq!(session.remaining_input_bytes(), input_before);
}
