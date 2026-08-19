// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for application-default redactor replacement.

use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
/// Verifies replacement returns the previous application-default snapshot.
#[test]
fn test_application_default_replacement_returns_previous_snapshot() {
    let replacement_policy = RedactionPolicy::builder()
        .fields(|fields| {
            let _ = fields.secret_sensitive("replacement_only_secret");
        })
        .expect("the replacement builder input must be valid")
        .build()
        .expect("the replacement policy must be valid");
    let original = Redactor::application_default();
    let replacement = Redactor::new(replacement_policy);
    let previous = Redactor::replace_application_default(replacement.clone());

    assert_eq!(previous.policy(), original.policy());
    assert_eq!(Redactor::application_default(), replacement);

    let _ = Redactor::replace_application_default(original);
}
