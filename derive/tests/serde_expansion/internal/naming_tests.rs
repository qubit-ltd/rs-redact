// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for Serde container, variant, and field naming precedence.

use qubit_redact::Redact as _;
use qubit_redact_derive::Redact;

/// Enum using container rules plus explicit variant and field overrides.
#[derive(Redact)]
#[redact(serde)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", rename_all_fields = "camelCase")]
enum NamedEvent {
    /// Variant renamed by the container rule.
    SomeValue {
        /// Field renamed by the container field rule.
        visible_value: &'static str,
        /// Field with an explicit name that wins over the container rule.
        #[serde(rename = "explicit_secret")]
        #[redact(level = "secret")]
        secret_value: String,
    },
    /// Variant with an explicit name that wins over the container rule.
    #[serde(rename = "custom")]
    Explicit {
        /// Visible field.
        another_value: &'static str,
    },
}

/// Verifies explicit names override applicable container rename rules.
#[test]
fn test_serde_naming_applies_exact_precedence() {
    assert_eq!(
        serde_json::to_value(
            NamedEvent::SomeValue {
                visible_value: "shown",
                secret_value: String::from("raw-secret"),
            }
            .redacted(),
        )
        .expect("container-renamed variant serializes"),
        serde_json::json!({
            "SOME_VALUE": {
                "visibleValue": "shown",
                "explicit_secret": "<redacted>",
            },
        }),
    );
    assert_eq!(
        serde_json::to_value(
            NamedEvent::Explicit {
                another_value: "shown",
            }
            .redacted(),
        )
        .expect("explicitly renamed variant serializes"),
        serde_json::json!({"custom": {"anotherValue": "shown"}}),
    );
}
