// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for parsing derive attributes.

use syn::Data;
use syn::DeriveInput;
use syn::Fields;
use syn::parse_quote;

use crate::attributes::ContainerAttributes;
use crate::attributes::FieldAttributes;
use crate::model::FieldMode;

#[test]
fn test_container_attributes_parse_supported_options() {
    let input: DeriveInput = parse_quote! {
        #[redact(debug, display, serde)]
        struct Record { value: String }
    };

    let attributes = ContainerAttributes::parse(&input).expect("supported options parse");
    assert!(attributes.debug_enabled());
    assert!(attributes.display_enabled());
    assert!(attributes.serde_enabled());
}

#[test]
fn test_container_attributes_reject_removed_options() {
    let input: DeriveInput = parse_quote! {
        #[redact(no_mut)]
        struct Record { value: String }
    };

    let error = match ContainerAttributes::parse(&input) {
        Ok(_) => panic!("removed options must fail"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("unknown container attribute"));

    let input: DeriveInput = parse_quote! {
        #[redact(require_explicit)]
        struct Record { value: String }
    };
    let error = match ContainerAttributes::parse(&input) {
        Ok(_) => panic!("removed options must fail"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("unknown container attribute"));
}

#[test]
fn test_field_attributes_parse_every_supported_mode() {
    let input: DeriveInput = parse_quote! {
        struct Record {
            plain: String,
            #[redact(level = "high")]
            level: String,
            #[redact(nested)]
            nested: String,
            #[redact(map)]
            map: String,
            #[redact(keyed_by = unmarked)]
            keyed: String,
            #[redact(json)]
            json: String,
            #[redact(skip)]
            skip: String,
        }
    };
    let Data::Struct(data) = &input.data else {
        panic!("fixture is a struct");
    };
    let Fields::Named(fields) = &data.fields else {
        panic!("fixture has named fields");
    };
    let modes = fields
        .named
        .iter()
        .map(|field| {
            let name = field.ident.as_ref().expect("named field");
            let attributes =
                FieldAttributes::parse(field, &input.ident, &name.to_string()).expect("supported field mode parses");
            match attributes.mode() {
                FieldMode::Unmarked => "unmarked",
                FieldMode::Level(_) => "level",
                FieldMode::DisplayLevel(_) => "display_level",
                FieldMode::Nested => "nested",
                FieldMode::Map => "map",
                FieldMode::MapLevels { .. } => "map_levels",
                FieldMode::KeyedBy(_) => "keyed_by",
                FieldMode::Json => "json",
                FieldMode::Skip => "skip",
            }
        })
        .collect::<Vec<_>>();

    assert_eq!(
        modes,
        ["unmarked", "level", "nested", "map", "keyed_by", "json", "skip"]
    );
}

#[test]
fn test_field_attributes_reject_removed_plain_mode() {
    let input: DeriveInput = parse_quote! {
        struct Record {
            #[redact(plain)]
            value: String,
        }
    };
    let Data::Struct(data) = &input.data else {
        panic!("fixture is a struct");
    };
    let Fields::Named(fields) = &data.fields else {
        panic!("fixture has named fields");
    };
    let field = fields.named.first().expect("fixture has one field");
    let error = match FieldAttributes::parse(field, &input.ident, "value") {
        Ok(_) => panic!("removed plain mode must fail"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("unknown attribute `plain`"));
}
