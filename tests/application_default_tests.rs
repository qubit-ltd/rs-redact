// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Application-default redactor contract tests.

use std::sync::Mutex;

use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
use qubit_redact::Sensitivity;

static APPLICATION_DEFAULT_LOCK: Mutex<()> = Mutex::new(());

/// Verifies that the Rust `Default` implementation is deterministic and does
/// not read mutable application state.
#[test]
fn test_default_remains_standard_after_application_default_replacement() {
    let _guard = APPLICATION_DEFAULT_LOCK
        .lock()
        .expect("application-default test lock must not be poisoned");
    let replacement_policy = RedactionPolicy::builder()
        .fields(|fields| {
            let _ = fields.secret_sensitive("tenant_only_secret");
        })
        .expect("replacement policy should be valid")
        .build()
        .expect("replacement policy should build");
    let replacement = Redactor::new(replacement_policy);
    let previous = Redactor::replace_application_default(replacement);

    assert_eq!(
        Redactor::application_default()
            .policy()
            .sensitivity_for("tenant_only_secret"),
        Some(Sensitivity::Secret)
    );
    assert_eq!(Redactor::default(), Redactor::standard());

    let _ = Redactor::replace_application_default(previous);
}

/// Sessions retain the application-default snapshot that existed when they
/// were created, even when a later setup phase replaces that default.
#[test]
fn test_session_keeps_application_default_snapshot() {
    let _guard = APPLICATION_DEFAULT_LOCK
        .lock()
        .expect("application-default test lock must not be poisoned");
    let before = Redactor::application_default();
    let mut session = before.session();
    let replacement = Redactor::strict();
    let previous = Redactor::replace_application_default(replacement.clone());

    assert_eq!(before.policy(), previous.policy());
    assert_eq!(session.policy(), before.policy());
    assert_eq!(Redactor::application_default(), replacement);

    let _ = session.finish();
    let _ = Redactor::replace_application_default(previous);
}
