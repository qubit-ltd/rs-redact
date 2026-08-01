// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for adjacently tagged redacted enum serialization.

use qubit_redact::Redact as _;
use qubit_redact_derive::Redact;

/// Adjacently tagged enum covering content-bearing and empty variants.
#[derive(Redact)]
#[redact(serde)]
#[serde(tag = "kind", content = "payload")]
enum AdjacentEvent {
    /// Named content.
    Named {
        /// Secret payload.
        #[redact(level = "secret")]
        secret: String,
    },
    /// Tuple content.
    Tuple(#[redact(level = "secret")] String, &'static str),
    /// Newtype content.
    Newtype(#[redact(level = "secret")] String),
    /// Named content without a carrier.
    EmptyNamed {
        /// Omitted payload.
        #[redact(skip)]
        omitted: String,
    },
    /// Tuple content without a carrier.
    EmptyTuple(#[redact(skip)] String),
    /// Unit content.
    Ready,
}

/// Verifies adjacent tags and optional content members exactly.
#[test]
fn test_serde_adjacent_enum_emits_exact_tag_and_content() {
    assert_eq!(
        serde_json::to_value(
            AdjacentEvent::Named {
                secret: String::from("raw-secret"),
            }
            .redacted(),
        )
        .expect("adjacent named variant serializes"),
        serde_json::json!({
            "kind": "Named",
            "payload": {"secret": "<redacted>"},
        }),
    );
    assert_eq!(
        serde_json::to_value(AdjacentEvent::Tuple(String::from("raw-secret"), "shown").redacted(),)
            .expect("adjacent tuple variant serializes"),
        serde_json::json!({
            "kind": "Tuple",
            "payload": ["<redacted>", "shown"],
        }),
    );
    assert_eq!(
        serde_json::to_value(AdjacentEvent::Newtype(String::from("raw-secret")).redacted())
            .expect("adjacent newtype variant serializes"),
        serde_json::json!({
            "kind": "Newtype",
            "payload": "<redacted>",
        }),
    );
    assert_eq!(
        serde_json::to_value(
            AdjacentEvent::EmptyNamed {
                omitted: String::from("raw-omitted"),
            }
            .redacted(),
        )
        .expect("adjacent empty named variant serializes"),
        serde_json::json!({"kind": "EmptyNamed", "payload": {}}),
    );
    assert_eq!(
        serde_json::to_value(AdjacentEvent::EmptyTuple(String::from("raw-omitted")).redacted())
            .expect("adjacent empty tuple variant serializes"),
        serde_json::json!({"kind": "EmptyTuple"}),
    );
    assert_eq!(
        serde_json::to_value(AdjacentEvent::Ready.redacted())
            .expect("adjacent unit variant serializes"),
        serde_json::json!({"kind": "Ready"}),
    );
}
