// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for application-default redactor replacement.

use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
/// Verifies replacement changes only future application-default snapshots.
#[test]
fn test_application_default_replacement_keeps_explicit_snapshots() {
    let before_application_default = Redactor::application_default();
    let before_standard = Redactor::default();
    let before_builder = RedactionPolicy::builder();
    let custom = RedactionPolicy::builder()
        .fields(|fields| {
            let _ = fields.secret_sensitive("tenant_protected_blob");
        })
        .expect("the test builder input should be valid")
        .build()
        .expect("the custom policy should be valid");

    let replacement = Redactor::new(custom.clone());
    let previous = Redactor::replace_application_default(replacement.clone());

    assert_eq!(previous, before_application_default);
    assert_eq!(Redactor::application_default(), replacement);
    assert_eq!(
        before_application_default
            .policy()
            .sensitivity_for("tenant_protected_blob"),
        None
    );
    assert_eq!(Redactor::default(), before_standard);
    assert_eq!(
        RedactionPolicy::builder()
            .build()
            .expect("the deterministic builder should remain valid")
            .sensitivity_for("tenant_protected_blob"),
        None,
    );
    assert_eq!(
        before_builder
            .build()
            .expect("the pre-install builder should remain valid")
            .sensitivity_for("tenant_protected_blob"),
        None,
    );
    assert_eq!(
        RedactionPolicy::standard().sensitivity_for("tenant_protected_blob"),
        None
    );
    let _ = Redactor::replace_application_default(previous);
}
