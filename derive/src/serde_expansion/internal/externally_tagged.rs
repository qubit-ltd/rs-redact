// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Externally tagged enum serialization expansion.

use proc_macro2::TokenStream;
use quote::quote;
use syn::Path;

use crate::{
    internal::{
        FieldsData,
        VariantData,
    },
    serde_container_attributes::SerdeContainerAttributes,
};

use super::{
    naming::serialized_variant_name,
    variant_fields::{
        enum_named_parts,
        enum_unnamed_parts,
    },
};

/// Generates one externally tagged variant arm.
pub(super) fn external_variant_arm(
    type_name: &syn::Ident,
    variant: &VariantData<'_>,
    runtime: &Path,
    serde: &Path,
    container_attributes: &SerdeContainerAttributes,
) -> syn::Result<TokenStream> {
    let rust_name = &variant.variant().ident;
    let variant_name = serialized_variant_name(variant, container_attributes);
    let enum_name = container_attributes.name();
    let variant_index = variant.index();
    let arm = match variant.fields() {
        FieldsData::Named(fields) => {
            let (pattern, setups, conditions, names, carriers) =
                enum_named_parts(
                    type_name,
                    rust_name,
                    fields,
                    runtime,
                    container_attributes,
                    variant,
                );
            let count_conditions = &conditions;
            let calls = conditions.iter().zip(&names).zip(&carriers).map(
                |((_condition, field_name), carrier)| {
                    quote! {
                        if let ::core::option::Option::Some(carrier) = #carrier.as_ref() {
                            #serde::ser::SerializeStructVariant::serialize_field(
                                &mut state,
                                #field_name,
                                carrier,
                            )?;
                        }
                    }
                },
            );
            quote! {
                Self::#rust_name #pattern => {
                    #(#setups)*
                    let mut field_count = 0usize;
                    #(
                        if #count_conditions {
                            field_count += 1;
                        }
                    )*
                    let mut state = #serde::Serializer::serialize_struct_variant(
                        serializer,
                        #enum_name,
                        #variant_index,
                        #variant_name,
                        field_count,
                    )?;
                    #(#calls)*
                    #serde::ser::SerializeStructVariant::end(state)
                }
            }
        }
        FieldsData::Unnamed(fields) if fields.len() == 1 => {
            let (pattern, setups, _conditions, carriers) =
                enum_unnamed_parts(type_name, rust_name, fields, runtime);
            if carriers.is_empty() {
                quote! {
                    Self::#rust_name #pattern => #serde::Serializer::serialize_unit_variant(
                        serializer,
                        #enum_name,
                        #variant_index,
                        #variant_name,
                    )
                }
            } else {
                let carrier = &carriers[0];
                quote! {
                    Self::#rust_name #pattern => {
                        #(#setups)*
                        if let ::core::option::Option::Some(carrier) = #carrier.as_ref() {
                            #serde::Serializer::serialize_newtype_variant(
                                serializer,
                                #enum_name,
                                #variant_index,
                                #variant_name,
                                carrier,
                            )
                        } else {
                            #serde::Serializer::serialize_unit_variant(
                                serializer,
                                #enum_name,
                                #variant_index,
                                #variant_name,
                            )
                        }
                    }
                }
            }
        }
        FieldsData::Unnamed(fields) => {
            let (pattern, setups, conditions, carriers) =
                enum_unnamed_parts(type_name, rust_name, fields, runtime);
            let count_conditions = &conditions;
            let calls = conditions
                .iter()
                .zip(&carriers)
                .map(|(_condition, carrier)| {
                    quote! {
                        if let ::core::option::Option::Some(carrier) = #carrier.as_ref() {
                            #serde::ser::SerializeTupleVariant::serialize_field(
                                &mut state,
                                carrier,
                            )?;
                        }
                    }
                });
            quote! {
                Self::#rust_name #pattern => {
                    #(#setups)*
                    let mut field_count = 0usize;
                    #(
                        if #count_conditions {
                            field_count += 1;
                        }
                    )*
                    let mut state = #serde::Serializer::serialize_tuple_variant(
                        serializer,
                        #enum_name,
                        #variant_index,
                        #variant_name,
                        field_count,
                    )?;
                    #(#calls)*
                    #serde::ser::SerializeTupleVariant::end(state)
                }
            }
        }
        FieldsData::Unit => quote! {
            Self::#rust_name => #serde::Serializer::serialize_unit_variant(
                serializer,
                #enum_name,
                #variant_index,
                #variant_name,
            )
        },
    };
    Ok(arm)
}
