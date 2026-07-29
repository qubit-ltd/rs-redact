// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for untagged redacted enum serialization.

use qubit_redact::Redact as _;
use qubit_redact_derive::Redact;

/// Untagged enum covering named, tuple, newtype, empty, and unit content.
#[derive(Redact)]
#[redact(serde)]
#[serde(untagged)]
enum UntaggedEvent {
    /// Named content.
    Named {
        /// Visible payload.
        visible: &'static str,
        /// Secret payload.
        #[redact(level = "secret")]
        secret: String,
    },
    /// Tuple content.
    Tuple(#[redact(level = "secret")] String, &'static str),
    /// Newtype content.
    Newtype(#[redact(level = "secret")] String),
    /// Empty content.
    Empty(#[redact(skip)] String),
    /// Unit content.
    Ready,
}

/// Verifies untagged variants serialize only their redacted content.
#[test]
fn test_serde_untagged_enum_serializes_exact_content() {
    assert_eq!(
        serde_json::to_value(
            UntaggedEvent::Named {
                visible: "shown",
                secret: String::from("raw-secret"),
            }
            .redacted(),
        )
        .expect("untagged named variant serializes"),
        serde_json::json!({
            "visible": "shown",
            "secret": "<redacted>",
        }),
    );
    assert_eq!(
        serde_json::to_value(
            UntaggedEvent::Tuple(String::from("raw-secret"), "shown")
                .redacted(),
        )
        .expect("untagged tuple variant serializes"),
        serde_json::json!(["<redacted>", "shown"]),
    );
    assert_eq!(
        serde_json::to_value(
            UntaggedEvent::Newtype(String::from("raw-secret")).redacted()
        )
        .expect("untagged newtype variant serializes"),
        serde_json::json!("<redacted>"),
    );
    assert_eq!(
        serde_json::to_value(
            UntaggedEvent::Empty(String::from("raw-omitted")).redacted()
        )
        .expect("untagged empty variant serializes"),
        serde_json::Value::Null,
    );
    assert_eq!(
        serde_json::to_value(UntaggedEvent::Ready.redacted())
            .expect("untagged unit variant serializes"),
        serde_json::Value::Null,
    );
}
