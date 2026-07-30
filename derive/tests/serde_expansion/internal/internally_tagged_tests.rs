// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for internally tagged redacted enum serialization.

use qubit_redact::Redact as _;
use qubit_redact_derive::Redact;

/// Nested object merged into an internally tagged newtype variant.
#[derive(Redact)]
#[redact(serde)]
struct InternalPayload {
    /// Visible payload.
    value: &'static str,
}

/// Internally tagged enum with named, newtype, empty, and unit content.
#[derive(Redact)]
#[redact(serde)]
#[serde(tag = "kind")]
enum InternalEvent {
    /// Named content with an explicit wire name.
    #[serde(rename = "renamed")]
    Named {
        /// Visible payload.
        visible: &'static str,
        /// Secret payload.
        #[redact(level = "secret")]
        secret: String,
    },
    /// Nested newtype content.
    Nested(#[redact(nested)] InternalPayload),
    /// Newtype without a serializable carrier.
    Empty(#[redact(skip)] String),
    /// Unit content.
    Ready,
}

/// Verifies internally tagged variants merge content beside the exact tag.
#[test]
fn test_serde_internal_enum_merges_content_beside_tag() {
    assert_eq!(
        serde_json::to_value(
            InternalEvent::Named {
                visible: "shown",
                secret: String::from("raw-secret"),
            }
            .redacted(),
        )
        .expect("internal named variant serializes"),
        serde_json::json!({
            "kind": "renamed",
            "visible": "shown",
            "secret": "<redacted>",
        }),
    );
    assert_eq!(
        serde_json::to_value(
            InternalEvent::Nested(InternalPayload { value: "shown" })
                .redacted(),
        )
        .expect("internal nested variant serializes"),
        serde_json::json!({"kind": "Nested", "value": "shown"}),
    );
    assert_eq!(
        serde_json::to_value(
            InternalEvent::Empty(String::from("raw-omitted")).redacted()
        )
        .expect("internal empty variant serializes"),
        serde_json::json!({"kind": "Empty"}),
    );
    assert_eq!(
        serde_json::to_value(InternalEvent::Ready.redacted())
            .expect("internal unit variant serializes"),
        serde_json::json!({"kind": "Ready"}),
    );
}
