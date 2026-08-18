// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Regression test for reading the fallback global configuration before setup.

use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
/// Verifies a fallback read does not prevent the application from installing
/// its policy during later setup.
#[test]
fn test_default_redactor_replacement_keeps_existing_snapshots() {
    let before_default = Redactor::default();
    let before_builder = RedactionPolicy::default().to_builder();

    let previous = Redactor::set_default(Redactor::strict());

    assert_eq!(before_default.policy(), &RedactionPolicy::standard());
    assert_eq!(
        before_builder
            .build()
            .expect("the pre-install default builder should remain valid"),
        RedactionPolicy::standard(),
    );
    assert_eq!(Redactor::default().policy(), &RedactionPolicy::strict());
    let _ = Redactor::set_default(previous);
}
