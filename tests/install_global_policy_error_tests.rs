// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for global-policy installation errors.

use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;
/// Verifies replacing the default redactor returns the previous snapshot.
#[test]
fn test_default_redactor_replacement_returns_previous_snapshot() {
    let rejected = ({
        let mut builder = RedactionPolicy::default().to_builder();
        builder.edit_fields().disable_floor();
        builder
    })
    .build()
    .expect("the rejected policy must be valid");
    let original = Redactor::default();
    let previous = Redactor::set_default(Redactor::new(rejected));
    assert_eq!(previous.policy(), original.policy());
    let _ = Redactor::set_default(original);
}
