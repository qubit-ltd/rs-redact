// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Integration tests for derived JSON text fields.

use qubit_redact::{
    Redact as _,
    RedactMut as _,
};
use qubit_redact_derive::{
    Redact,
    RedactMut,
};

/// Immutable record storing JSON in a string field.
#[derive(Redact)]
struct JsonRecord {
    /// JSON document whose sensitive object values are masked.
    #[redact(json)]
    payload: String,
}

/// Tuple record storing a recursively redacted JSON text field.
#[derive(Redact)]
struct JsonTupleRecord(#[redact(json)] String);

/// Enum covering recursively redacted JSON text in both field shapes.
#[derive(Redact)]
enum JsonEvent {
    /// Named JSON payload.
    Named {
        /// JSON text whose keyed secret values are masked.
        #[redact(json)]
        payload: String,
    },
    /// Tuple JSON payload.
    Tuple(#[redact(json)] String),
}

/// Mutable record storing JSON in a string field.
#[derive(RedactMut)]
struct MutableJsonRecord {
    /// JSON document rewritten to a compact redacted string.
    #[redact(json)]
    payload: String,
}

#[test]
fn test_derived_json_field_redacts_debug_output() {
    let value = JsonRecord {
        payload: r#"{"password":"raw-password","id":7}"#.to_owned(),
    };

    let output = format!("{:?}", value.redacted());

    assert!(!output.contains("raw-password"));
    assert!(output.contains("\"password\":"));
}

/// Verifies JSON field expansion handles tuple structs and both enum field
/// shapes without leaking a keyed secret.
#[test]
fn test_derived_json_tuple_and_enum_fields_redact_debug_output() {
    let payload = r#"{"password":"raw-secret","name":"Ada"}"#.to_owned();
    let tuple = JsonTupleRecord(payload.clone());
    let named = JsonEvent::Named {
        payload: payload.clone(),
    };
    let enum_tuple = JsonEvent::Tuple(payload);

    for output in [
        format!("{:?}", tuple.redacted()),
        format!("{:?}", named.redacted()),
        format!("{:?}", enum_tuple.redacted()),
    ] {
        assert!(!output.contains("raw-secret"), "{output}");
        assert!(output.contains("Ada"), "{output}");
    }
}

#[test]
fn test_derived_json_field_rewrites_compact_json_in_place() {
    let mut value = MutableJsonRecord {
        payload: r#"{ "password": "raw-password", "id": 7 }"#.to_owned(),
    };

    value.redact_in_place();

    assert!(!value.payload.contains("raw-password"));
    assert!(value.payload.starts_with('{'));
    assert!(!value.payload.contains(' '));
}

#[cfg(feature = "serde")]
mod serde {
    use qubit_redact::Redact as _;
    use qubit_redact_derive::Redact;
    use serde::Serialize;

    /// Serializable record containing a JSON text string.
    #[derive(Redact, Serialize)]
    #[redact(serde)]
    struct SerializableJsonRecord {
        /// Serialized as a redacted JSON string, not an embedded object.
        #[redact(json)]
        payload: String,
    }

    #[test]
    fn test_derived_json_field_serde_preserves_outer_string_shape() {
        let value = SerializableJsonRecord {
            payload: r#"{"token":"raw-token"}"#.to_owned(),
        };

        let output = serde_json::to_string(&value.redacted()).unwrap();

        assert!(!output.contains("raw-token"));
        assert!(output.starts_with(r#"{"payload":"{"#));
    }
}
