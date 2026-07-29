// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for redacted field carriers and serialization conditions.

use qubit_redact::Redact as _;
use qubit_redact_derive::Redact;

/// Record with redacted, conditional, and always-skipped carriers.
#[derive(Redact)]
#[redact(serde)]
struct ConditionalRecord {
    /// Secret carrier.
    #[redact(level = "secret")]
    secret: String,
    /// Carrier omitted only when empty.
    #[serde(skip_serializing_if = "String::is_empty")]
    optional: String,
    /// Carrier always omitted by Serde policy.
    #[serde(skip)]
    serde_skipped: String,
}

/// Verifies carrier redaction and conditional omission use the raw field value.
#[test]
fn test_serde_field_serialization_applies_carriers_and_conditions() {
    let empty = ConditionalRecord {
        secret: String::from("raw-secret"),
        optional: String::new(),
        serde_skipped: String::from("raw-skipped"),
    };
    let populated = ConditionalRecord {
        secret: String::from("raw-secret"),
        optional: String::from("shown"),
        serde_skipped: String::from("raw-skipped"),
    };

    assert_eq!(
        serde_json::to_value(empty.redacted()).expect("conditional empty record serializes"),
        serde_json::json!({"secret": "<redacted>"}),
    );
    assert_eq!(
        serde_json::to_value(populated.redacted())
            .expect("conditional populated record serializes"),
        serde_json::json!({
            "secret": "<redacted>",
            "optional": "shown",
        }),
    );
}
