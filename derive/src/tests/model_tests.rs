// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Tests for constructing the derive input model.

use syn::DeriveInput;
use syn::parse_quote;

use crate::model;
use crate::model::ContainerData;
use crate::model::FieldsData;

#[test]
fn test_input_model_preserves_struct_tuple_unit_and_enum_shapes() {
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
