// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for redacted Serde expansion across struct shapes.

use qubit_redact::Redact as _;
use qubit_redact_derive::Redact;

/// Named struct with visible, secret, and omitted fields.
#[derive(Redact)]
#[redact(serde)]
#[serde(rename_all = "camelCase")]
struct NamedShape {
    /// Visible field renamed by the container rule.
    visible_value: &'static str,
    /// Secret field renamed by the container rule.
    #[redact(level = "secret")]
    secret_value: String,
    /// Field omitted from the redacted representation.
    #[redact(skip)]
    omitted_value: String,
}

/// Secret newtype struct.
#[derive(Redact)]
#[redact(serde)]
struct SecretNewtype(#[redact(level = "secret")] String);

/// Newtype whose only carrier is omitted.
#[derive(Redact)]
#[redact(serde)]
struct EmptyNewtype(#[redact(skip)] String);

/// Tuple struct with one omitted carrier.
#[derive(Redact)]
#[redact(serde)]
struct TupleShape(
    #[redact(level = "secret")] String,
    #[redact(skip)] String,
    &'static str,
);

/// Unit struct.
#[derive(Redact)]
#[redact(serde)]
struct Ready;

/// Verifies named, newtype, tuple, unit, and empty-carrier struct output.
#[test]
fn test_serde_struct_expansion_preserves_each_shape() {
    let named = NamedShape {
        visible_value: "shown",
        secret_value: String::from("raw-secret"),
        omitted_value: String::from("raw-omitted"),
    };
    let _ = &named.omitted_value;

    assert_eq!(
        serde_json::to_value(named.redacted())
            .expect("named redacted struct serializes"),
        serde_json::json!({
            "visibleValue": "shown",
            "secretValue": "<redacted>",
        }),
    );
    assert_eq!(
        serde_json::to_value(
            SecretNewtype(String::from("raw-secret")).redacted()
        )
        .expect("redacted newtype serializes"),
        serde_json::json!("<redacted>"),
    );
    assert_eq!(
        serde_json::to_value(
            EmptyNewtype(String::from("raw-omitted")).redacted()
        )
        .expect("empty redacted newtype serializes"),
        serde_json::Value::Null,
    );
    assert_eq!(
        serde_json::to_value(
            TupleShape(
                String::from("raw-secret"),
                String::from("raw-omitted"),
                "shown",
            )
            .redacted(),
        )
        .expect("redacted tuple struct serializes"),
        serde_json::json!(["<redacted>", "shown"]),
    );
    assert_eq!(
        serde_json::to_value(Ready.redacted())
            .expect("redacted unit struct serializes"),
        serde_json::Value::Null,
    );
}
