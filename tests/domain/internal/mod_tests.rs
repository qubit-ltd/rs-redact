// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for internal domain support through generated behavior.

use qubit_redact::Redact;
use qubit_redact_derive::Redact;

/// Nested value used to exercise internal recursive adapters.
#[derive(Redact)]
struct NestedValue {
    /// Sensitive payload.
    #[redact(level = "secret")]
    secret: String,
}

/// Outer value whose derive uses the internal nested adapter.
#[derive(Redact)]
struct OuterValue {
    /// Nested payload.
    #[redact(nested)]
    nested: NestedValue,
}

/// Verifies generated internal adapters preserve the outer policy.
#[test]
fn test_domain_internal_adapters_preserve_redaction() {
    let value = OuterValue {
        nested: NestedValue {
            secret: String::from("raw-secret"),
        },
    };

    assert!(!format!("{:?}", value.redacted()).contains("raw-secret"));
}
