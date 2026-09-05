// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Unit tests for the derive parser, model, and expansion pipeline.

use syn::Data;
use syn::DeriveInput;
use syn::Fields;
use syn::parse_quote;

use crate::attributes::ContainerAttributes;
use crate::attributes::FieldAttributes;
use crate::expand;
use crate::model;
use crate::model::ContainerData;
use crate::model::FieldMode;
use crate::model::FieldsData;

#[test]
fn container_attributes_parse_supported_options() {
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
fn container_attributes_reject_removed_options() {
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
fn field_attributes_parse_every_supported_mode() {
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
fn field_attributes_reject_removed_plain_mode() {
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

#[test]
fn input_model_preserves_struct_tuple_unit_and_enum_shapes() {
    let named: DeriveInput = parse_quote!(
        struct Named {
            value: String,
        }
    );
    let tuple: DeriveInput = parse_quote!(
        struct Tuple(String);
    );
    let unit: DeriveInput = parse_quote!(
        struct Unit;
    );
    let enumeration: DeriveInput = parse_quote!(
        enum Event {
            Named { value: String },
            Tuple(String),
            Unit,
        }
    );

    assert!(matches!(
        model::parse(&named, "Redact", false).expect("named model"),
        ContainerData::Struct(FieldsData::Named(_))
    ));
    assert!(matches!(
        model::parse(&tuple, "Redact", false).expect("tuple model"),
        ContainerData::Struct(FieldsData::Unnamed(_))
    ));
    assert!(matches!(
        model::parse(&unit, "Redact", false).expect("unit model"),
        ContainerData::Struct(FieldsData::Unit)
    ));
    assert!(matches!(
        model::parse(&enumeration, "Redact", false).expect("enum model"),
        ContainerData::Enum(variants) if variants.len() == 3
    ));
}

#[test]
fn expansion_generates_only_the_requested_public_contracts() {
    let input: DeriveInput = parse_quote! {
        #[redact(crate = crate, debug, display)]
        struct Record {
            #[redact(level = "secret")]
            value: String,
        }
    };

    let rendered = expand::expand(&input).expect("valid input expands").to_string();
    for expected in ["Redact", "Debug", "Display"] {
        assert!(rendered.contains(expected), "missing {expected}: {rendered}");
    }
    for removed in ["RedactMut", "redacted_with", "expand_with_options"] {
        assert!(
            !rendered.contains(removed),
            "retained removed contract {removed}: {rendered}"
        );
    }
}
