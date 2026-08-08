// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for the public domain module boundary.

use qubit_redact::RedactValue;
use qubit_redact::RedactionPolicy;
use qubit_redact::Sensitivity;
/// Verifies reexported domain traits and values compose.
#[test]
fn test_domain_module_reexports_compose() {
    let policy = RedactionPolicy::standard();
    let value = String::from("raw-secret");
    let redacted = value.redact_value(Sensitivity::Secret, policy.masking());

    assert!(!redacted.to_string().contains("raw-secret"));
}
