// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for enum field patterns and serialized carrier ordering.

use qubit_redact::Redact as _;
use qubit_redact_derive::Redact;

/// Enum mixing retained and omitted named and tuple carriers.
#[derive(Redact)]
#[redact(serde)]
enum CarrierEvent {
    /// Named carriers.
    Named {
        /// First visible carrier.
        first: &'static str,
        /// Omitted middle carrier.
        #[redact(skip)]
        omitted: String,
        /// Last secret carrier with an explicit wire name.
        #[serde(rename = "wire_secret")]
        #[redact(level = "secret")]
        secret: String,
    },
    /// Tuple carriers.
    Tuple(
        &'static str,
        #[redact(skip)] String,
        #[redact(level = "secret")] String,
    ),
}

/// Verifies skipped fields do not disturb retained names or tuple order.
#[test]
fn test_serde_variant_fields_preserve_retained_carrier_order() {
    assert_eq!(
        serde_json::to_value(
            CarrierEvent::Named {
                first: "shown",
                omitted: String::from("raw-omitted"),
                secret: String::from("raw-secret"),
            }
            .redacted(),
        )
        .expect("named carrier variant serializes"),
        serde_json::json!({
            "Named": {
                "first": "shown",
                "wire_secret": "<redacted>",
            },
        }),
    );
    assert_eq!(
        serde_json::to_value(
            CarrierEvent::Tuple(
                "shown",
                String::from("raw-omitted"),
                String::from("raw-secret"),
            )
            .redacted(),
        )
        .expect("tuple carrier variant serializes"),
        serde_json::json!({"Tuple": ["shown", "<redacted>"]}),
    );
}
