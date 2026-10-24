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
fn test_composer_keeps_application_default_snapshot() {
    let _guard = APPLICATION_DEFAULT_LOCK
        .lock()
        .expect("application-default test lock must not be poisoned");
    let before = Redactor::application_default();
    let composer = before.text_composer();
    let replacement = Redactor::strict();
    let previous = Redactor::replace_application_default(replacement.clone());

    assert_eq!(before.policy(), previous.policy());
    assert_eq!(Redactor::application_default(), replacement);

    let _ = composer.finish();
    let _ = Redactor::replace_application_default(previous);
}

/// Existing composers keep their captured policy while later composers use a replacement.
#[test]
fn test_composer_uses_the_application_default_snapshot_at_creation() {
    let _guard = APPLICATION_DEFAULT_LOCK
        .lock()
        .expect("application-default test lock must not be poisoned");
    let before = Redactor::application_default();
    let original_policy = RedactionPolicy::builder()
        .fields(|fields| {
            let _ = fields.secret_sensitive("custom_probe");
        })
        .expect("initial policy should be valid")
        .build()
        .expect("initial policy should build");
    let previous = Redactor::replace_application_default(Redactor::new(original_policy));
    let old_composer = Redactor::application_default()
        .text_composer()
        .field("custom_probe", "visible");

    let replacement = Redactor::new(RedactionPolicy::standard());
    let _ = Redactor::replace_application_default(replacement);
    let new_composer = Redactor::application_default()
        .text_composer()
        .field("custom_probe", "visible");
    let old_output = old_composer.finish();
    let new_output = new_composer.finish();

    assert_eq!(
        old_output.summary().completion(),
        qubit_redact::RedactionCompletion::Complete
    );
    assert_eq!(
        new_output.summary().completion(),
        qubit_redact::RedactionCompletion::Complete
    );
    assert!(old_output.text().as_str().contains("<redacted>"));
    assert!(new_output.text().as_str().contains("visible"));
    let _ = Redactor::replace_application_default(previous);
    assert_eq!(Redactor::application_default(), before);
}

/// Verifies replacement returns the previous application-default snapshot.
#[test]
fn test_application_default_replacement_returns_previous_snapshot() {
    let _guard = APPLICATION_DEFAULT_LOCK
        .lock()
        .expect("application-default test lock must not be poisoned");
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
