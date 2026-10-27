// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================

#![cfg(all(feature = "derive", feature = "serde"))]

use std::any::type_name;

use qubit_redact::Redact;
use qubit_redact::Redactor;
use qubit_redact::domain::internal::RedactSerializeSource;

#[derive(Debug)]
struct PrivateTextOnly;

#[derive(Debug, Redact)]
pub struct PublicTextOnly {
    inner: PrivateTextOnly,
}

#[derive(Debug, serde::Serialize)]
struct PrivateSerializable(u8);

#[derive(Debug, Redact)]
pub struct PublicSerializable {
    inner: PrivateSerializable,
}

#[derive(Debug, Redact)]
#[allow(private_interfaces)]
pub enum PublicChoiceWithPrivatePayload {
    Hidden(PrivateTextOnly),
}

#[derive(Debug, Redact)]
pub(crate) struct CrateTextOnly {
    inner: PrivateTextOnly,
}

fn accepts_projection<T: RedactSerializeSource>() {
    let _ = type_name::<T>();
}

mod api {
    use qubit_redact_derive::Redact;

    #[derive(Redact)]
    #[redact(serde)]
    pub struct PublicRecord {
        pub name: String,
    }

    #[derive(Redact)]
    #[redact(serde)]
    pub enum PublicChoice {
        Empty,
        Text(String),
    }

    #[derive(Redact)]
    #[redact(serde)]
    pub struct PublicGeneric<T> {
        pub value: T,
    }

    #[derive(Redact)]
    #[redact(serde)]
    pub(crate) struct CrateRecord {
        value: String,
    }

    #[derive(Redact)]
    #[redact(serde)]
    struct PrivateRecord {
        value: String,
    }

    pub(super) fn assert_non_public_projections_compile() {
        super::accepts_projection::<CrateRecord>();
        super::accepts_projection::<PrivateRecord>();
    }
}

#[test]
fn test_projection_visibility_matches_derived_type_visibility() {
    let _ = api::PublicChoice::Empty;
    let _ = api::PublicChoice::Text(String::new());
    accepts_projection::<api::PublicRecord>();
    accepts_projection::<api::PublicChoice>();
    accepts_projection::<api::PublicGeneric<String>>();
    api::assert_non_public_projections_compile();
}

#[test]
fn test_private_source_field_types_remain_hidden_without_serialize() {
    let redactor = Redactor::standard();
    let text_only = PublicTextOnly { inner: PrivateTextOnly };
    let rendered = redactor.redact_text(&text_only);
    assert!(rendered.complete_text().is_ok());
    assert!(rendered.text().as_str().contains("PrivateTextOnly"));

    let enum_payload = PublicChoiceWithPrivatePayload::Hidden(PrivateTextOnly);
    let rendered = redactor.redact_text(&enum_payload);
    assert!(rendered.complete_text().is_ok());

    let crate_only = CrateTextOnly { inner: PrivateTextOnly };
    assert!(redactor.redact_text(&crate_only).complete_text().is_ok());
}

#[test]
fn test_private_serializable_payload_supports_borrowed_view() {
    let value = PublicSerializable {
        inner: PrivateSerializable(7),
    };
    let encoded = serde_json::to_value(Redactor::standard().redact_view(&value))
        .expect("private serializable payload should support a borrowed view");
    assert_eq!(encoded["inner"], 7);
}
