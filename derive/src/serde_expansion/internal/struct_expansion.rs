// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Redacted serialization expansion for struct shapes.

use proc_macro2::TokenStream;
use quote::{format_ident, quote, quote_spanned};
use syn::{Path, spanned::Spanned};

use crate::{
    internal::{FieldsData, NamedField, UnnamedField},
    serde_container_attributes::SerdeContainerAttributes,
};

use super::field_serialization::{
    field_context, field_is_skipped, raw_identifier, serialization_condition, serialized_carrier,
};

/// Generates redacted serialization for one struct shape.
pub(super) fn struct_body(
    type_name: &syn::Ident,
    fields: &FieldsData<'_>,
    runtime: &Path,
    serde: &Path,
    container_attributes: &SerdeContainerAttributes,
) -> TokenStream {
    match fields {
        FieldsData::Named(fields) => {
            named_struct_body(type_name, fields, runtime, serde, container_attributes)
        }
        FieldsData::Unnamed(fields) if fields.len() == 1 => {
            newtype_struct_body(type_name, &fields[0], runtime, serde, container_attributes)
        }
        FieldsData::Unnamed(fields) => {
            tuple_struct_body(type_name, fields, runtime, serde, container_attributes)
        }
        FieldsData::Unit => {
            let serialized_name = container_attributes.name();
            quote! {
                #serde::Serializer::serialize_unit_struct(
                    serializer,
                    #serialized_name,
                )
            }
        }
    }
}

/// Generates named-struct serialization.
fn named_struct_body(
    type_name: &syn::Ident,
    fields: &[NamedField<'_>],
    runtime: &Path,
    serde: &Path,
    container_attributes: &SerdeContainerAttributes,
) -> TokenStream {
    let mut setups = Vec::new();
    let mut conditions = Vec::new();
    let mut serialized_names = Vec::new();
    let mut carriers = Vec::new();

    for (position, parsed) in fields.iter().enumerate() {
        if field_is_skipped(parsed.attributes().mode(), parsed.serde_attributes()) {
            continue;
        }
        let field = parsed.field();
        let identifier = parsed.identifier();
        let raw_name = raw_identifier(identifier);
        let serialized_name = parsed.serde_attributes().rename().map_or_else(
            || container_attributes.rename_struct_field(&raw_name),
            str::to_owned,
        );
        let raw = quote_spanned!(field.span()=> &self.#identifier);
        let context = field_context(None, &raw_name);
        let carrier = format_ident!("__qubit_redact_serialized_{position}");
        let value = serialized_carrier(
            type_name,
            field,
            &context,
            parsed.attributes().mode(),
            runtime,
            raw.clone(),
        );
        let condition = serialization_condition(parsed.serde_attributes(), raw);
        setups.push(quote_spanned! {field.span()=>
            let #carrier = if #condition {
                ::core::option::Option::Some(#value)
            } else {
                ::core::option::Option::None
            };
        });
        conditions.push(quote!(#carrier.is_some()));
        serialized_names.push(serialized_name);
        carriers.push(carrier);
    }

    let count_conditions = &conditions;
    let serialized_name = container_attributes.name();
    let calls = conditions.iter().zip(&serialized_names).zip(&carriers).map(
        |((_condition, field_name), carrier)| {
            quote! {
                if let ::core::option::Option::Some(carrier) = #carrier.as_ref() {
                    #serde::ser::SerializeStruct::serialize_field(
                        &mut state,
                        #field_name,
                        carrier,
                    )?;
                }
            }
        },
    );
    quote! {
        #(#setups)*
        let mut field_count = 0usize;
        #(
            if #count_conditions {
                field_count += 1;
            }
        )*
        let mut state = #serde::Serializer::serialize_struct(
            serializer,
            #serialized_name,
            field_count,
        )?;
        #(#calls)*
        #serde::ser::SerializeStruct::end(state)
    }
}

/// Generates newtype-struct serialization.
fn newtype_struct_body(
    type_name: &syn::Ident,
    parsed: &UnnamedField<'_>,
    runtime: &Path,
    serde: &Path,
    container_attributes: &SerdeContainerAttributes,
) -> TokenStream {
    let serialized_name = container_attributes.name();
    if field_is_skipped(parsed.attributes().mode(), parsed.serde_attributes()) {
        return quote! {
            #serde::Serializer::serialize_unit_struct(serializer, #serialized_name)
        };
    }
    let field = parsed.field();
    let index = parsed.index();
    let raw = quote_spanned!(field.span()=> &self.#index);
    let context = field_context(None, &index.index.to_string());
    let value = serialized_carrier(
        type_name,
        field,
        &context,
        parsed.attributes().mode(),
        runtime,
        raw.clone(),
    );
    let condition = serialization_condition(parsed.serde_attributes(), raw);
    quote! {
        if #condition {
            let __qubit_redact_serialized_0 = #value;
            #serde::Serializer::serialize_newtype_struct(
                serializer,
                #serialized_name,
                &__qubit_redact_serialized_0,
            )
        } else {
            #serde::Serializer::serialize_unit_struct(serializer, #serialized_name)
        }
    }
}

/// Generates tuple-struct serialization.
fn tuple_struct_body(
    type_name: &syn::Ident,
    fields: &[UnnamedField<'_>],
    runtime: &Path,
    serde: &Path,
    container_attributes: &SerdeContainerAttributes,
) -> TokenStream {
    let mut setups = Vec::new();
    let mut conditions = Vec::new();
    let mut carriers = Vec::new();
    for (position, parsed) in fields.iter().enumerate() {
        if field_is_skipped(parsed.attributes().mode(), parsed.serde_attributes()) {
            continue;
        }
        let field = parsed.field();
        let index = parsed.index();
        let raw = quote_spanned!(field.span()=> &self.#index);
        let context = field_context(None, &index.index.to_string());
        let carrier = format_ident!("__qubit_redact_serialized_{position}");
        let value = serialized_carrier(
            type_name,
            field,
            &context,
            parsed.attributes().mode(),
            runtime,
            raw.clone(),
        );
        let condition = serialization_condition(parsed.serde_attributes(), raw);
        setups.push(quote_spanned! {field.span()=>
            let #carrier = if #condition {
                ::core::option::Option::Some(#value)
            } else {
                ::core::option::Option::None
            };
        });
        conditions.push(quote!(#carrier.is_some()));
        carriers.push(carrier);
    }
    let count_conditions = &conditions;
    let serialized_name = container_attributes.name();
    let calls = conditions
        .iter()
        .zip(&carriers)
        .map(|(_condition, carrier)| {
            quote! {
                if let ::core::option::Option::Some(carrier) = #carrier.as_ref() {
                    #serde::ser::SerializeTupleStruct::serialize_field(
                        &mut state,
                        carrier,
                    )?;
                }
            }
        });
    quote! {
        #(#setups)*
        let mut field_count = 0usize;
        #(
            if #count_conditions {
                field_count += 1;
            }
        )*
        let mut state = #serde::Serializer::serialize_tuple_struct(
            serializer,
            #serialized_name,
            field_count,
        )?;
        #(#calls)*
        #serde::ser::SerializeTupleStruct::end(state)
    }
}
