// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! URI rendering shares the enclosing composer output allowance.

use qubit_redact::RedactionCompletion;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;

/// Verifies a URI adapter receives the output allowance left after earlier
/// aggregate writes in its enclosing transaction.
#[test]
fn test_uri_session_uses_the_transaction_remaining_output_allowance() {
    let policy = RedactionPolicy::builder()
        .limits(|limits| {
            let _ = limits.max_output_bytes(20);
        })
        .expect("the test limit draft should build")
        .build()
        .expect("the test policy should build");
    let output = Redactor::new(policy)
        .text_composer()
        .literal("prefix")
        .uri(|uri| {
            uri.value("https://example.test/a/very/long/path?token=secret");
        })
        .finish();

    assert_eq!(output.text().as_str(), "prefixhtt<truncated>");
    assert_eq!(output.summary().completion(), RedactionCompletion::Truncated);
    assert_eq!(output.summary().usage().output_bytes(), 20);
}
