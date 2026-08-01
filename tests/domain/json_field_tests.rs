// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Integration tests for derived JSON text fields.

use qubit_redact::{Redact as _, RedactMut as _};
use qubit_redact_derive::{Redact, RedactMut};

/// Immutable record storing JSON in a string field.
#[derive(Redact)]
struct JsonRecord {
    /// JSON document whose sensitive object values are masked.
    #[redact(json)]
    payload: String,
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
