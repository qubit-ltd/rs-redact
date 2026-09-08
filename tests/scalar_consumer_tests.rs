// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Scalar newtypes preserve their underlying representation without trait
//! takeover.
#![cfg(feature = "derive")]

use qubit_redact::Redact;
use qubit_redact::RedactScalar;
use qubit_redact::RedactionPolicy;
use qubit_redact::Redactor;

#[derive(RedactScalar)]
struct Id(u64);

#[derive(RedactScalar)]
struct UserId {
    value: String,
}

#[derive(RedactScalar)]
struct Wrapped<T>(T);

#[derive(RedactScalar)]
struct NamedGeneric<__QuibitScalarSerializer> {
    inner: __QuibitScalarSerializer,
}

#[derive(Redact)]
#[cfg_attr(feature = "serde", redact(serde))]
struct Record {
    #[redact(level = "secret")]
    id: Id,
    #[redact(level = "secret")]
    user: Wrapped<UserId>,
    #[redact(level = "secret")]
    ids: Option<Vec<Id>>,
}

/// Scalar wrappers retain native disabled values and mask without ordinary
/// trait derives.
#[test]
fn test_scalar_newtypes_do_not_require_debug_or_serialize() {
    let _generic = NamedGeneric { inner: Id(8) };
    let value = Record {
        id: Id(42),
        user: Wrapped(UserId {
            value: "raw-user".into(),
        }),
        ids: Some(vec![Id(7)]),
    };
    let output = Redactor::standard().redact_text(&value);
    assert!(!output.text().as_str().contains("raw-user"));
    assert!(!output.text().as_str().contains("42"));
    let disabled = Redactor::new(RedactionPolicy::disabled());
    let text = disabled.redact_text(&value);
    assert!(text.text().as_str().contains("raw-user"));
    assert!(text.text().as_str().contains("42"));
    #[cfg(feature = "serde")]
    {
        let json = serde_json::to_value(disabled.redact_view(&value)).expect("disabled scalar serialization");
        assert_eq!(json, serde_json::json!({"id":42,"user":"raw-user","ids":[7]}));
        let masked =
            serde_json::to_value(Redactor::standard().redact_view(&value)).expect("masked scalar serialization");
        assert_eq!(
            masked,
            serde_json::json!({"id":"<redacted>","user":"<redacted>","ids":["<redacted>"]})
        );
    }
}
