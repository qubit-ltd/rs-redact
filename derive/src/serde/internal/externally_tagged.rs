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
use syn::Ident;
use syn::Path;
use syn::Result;

use super::variant_fields::enum_named_parts;
use super::variant_fields::enum_unnamed_parts;
use crate::attributes::SerdeContainerAttributes;
use crate::model::FieldsData;
use crate::model::VariantData;
use crate::serde::naming::serialized_variant_name;
/// Generates one externally tagged variant arm.
///
/// # Parameters
///
/// * `type_name` - Enum receiving the generated serialization implementation.
/// * `variant` - Parsed variant being expanded.
/// * `runtime` - Resolved path to the runtime crate.
/// * `serde` - Resolved path to Serde.
/// * `container_attributes` - Validated container naming controls.
///
/// # Returns
///
/// A match arm that serializes the variant with external tagging.
///
/// # Errors
///
/// This function currently produces no direct error; the result type matches
/// the representation-dispatch interface.
pub(in crate::serde) fn external_variant_arm(
    type_name: &Ident,
    variant: &VariantData<'_>,
    runtime: &Path,
    serde: &Path,
    container_attributes: &SerdeContainerAttributes,
) -> Result<TokenStream> {
    let rust_name = &variant.variant().ident;
    let variant_name = serialized_variant_name(variant, container_attributes);
    let enum_name = container_attributes.name();
    let variant_index = variant.index();
    let arm = match variant.fields() {
        FieldsData::Named(fields) => {
            let (pattern, setups, conditions, names, carriers) =
                enum_named_parts(type_name, rust_name, fields, runtime, container_attributes, variant);
            let count_conditions = &conditions;
            let calls = conditions
                .iter()
                .zip(&names)
                .zip(&carriers)
                .map(|((_condition, field_name), carrier)| {
                    quote! {
                        if let ::core::option::Option::Some(carrier) = #carrier.as_ref() {
                            #serde::ser::SerializeStructVariant::serialize_field(
                                &mut state,
                                #field_name,
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
                    #runtime::domain::internal::admit_serializer_items(&serializer, field_count)?;
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
                enum_unnamed_parts(type_name, rust_name, variant.index(), fields, runtime);
            if carriers.is_empty() {
                quote! {
                    Self::#rust_name #pattern => #runtime::domain::internal::serialize_unit_variant(
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
                            #runtime::domain::internal::serialize_unit_variant(
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
                enum_unnamed_parts(type_name, rust_name, variant.index(), fields, runtime);
            let count_conditions = &conditions;
            let calls = conditions.iter().zip(&carriers).map(|(_condition, carrier)| {
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
                    #runtime::domain::internal::admit_serializer_items(&serializer, field_count)?;
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
            Self::#rust_name => #runtime::domain::internal::serialize_unit_variant(
                serializer,
                #enum_name,
                #variant_index,
                #variant_name,
            )
        },
    };
    Ok(arm)
}
