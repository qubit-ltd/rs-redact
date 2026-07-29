// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for externally tagged redacted enum serialization.

use qubit_redact::Redact as _;
use qubit_redact_derive::Redact;

/// Externally tagged enum covering every field shape.
#[derive(Redact)]
#[redact(serde)]
#[serde(rename_all = "snake_case")]
enum ExternalEvent {
    /// Named payload.
    Named {
        /// Explicitly renamed visible field.
        #[serde(rename = "public")]
        visible: &'static str,
        /// Secret payload.
        #[redact(level = "secret")]
        secret: String,
        /// Omitted payload.
        #[redact(skip)]
        omitted: String,
    },
    /// Newtype payload.
    Newtype(#[redact(level = "secret")] String),
    /// Tuple payload.
    Tuple(#[redact(level = "secret")] String, &'static str),
    /// Empty named payload.
    Empty {
        /// Omitted carrier.
        #[redact(skip)]
        omitted: String,
    },
    /// Unit payload.
    Ready,
}

/// Verifies externally tagged names, carriers, and empty shapes exactly.
#[test]
fn test_serde_external_enum_preserves_wire_shapes() {
    let named = ExternalEvent::Named {
        visible: "shown",
        secret: String::from("raw-secret"),
        omitted: String::from("raw-omitted"),
    };

    assert_eq!(
        serde_json::to_value(named.redacted())
            .expect("external named variant serializes"),
        serde_json::json!({
            "named": {
                "public": "shown",
                "secret": "<redacted>",
            },
        }),
    );
    assert_eq!(
        serde_json::to_value(
            ExternalEvent::Newtype(String::from("raw-secret")).redacted()
        )
        .expect("external newtype variant serializes"),
        serde_json::json!({"newtype": "<redacted>"}),
    );
    assert_eq!(
        serde_json::to_value(
            ExternalEvent::Tuple(String::from("raw-secret"), "shown").redacted()
        )
        .expect("external tuple variant serializes"),
        serde_json::json!({"tuple": ["<redacted>", "shown"]}),
    );
    assert_eq!(
        serde_json::to_value(
            ExternalEvent::Empty {
                omitted: String::from("raw-omitted"),
            }
            .redacted(),
        )
        .expect("external empty variant serializes"),
        serde_json::json!({"empty": {}}),
    );
    assert_eq!(
        serde_json::to_value(ExternalEvent::Ready.redacted())
            .expect("external unit variant serializes"),
        serde_json::json!("ready"),
    );
}
