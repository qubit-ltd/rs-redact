// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Adjacently tagged enum serialization expansion.

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
use crate::serde::naming::named_content_proxy;
use crate::serde::naming::serialized_variant_name;
use crate::serde::naming::tuple_content_proxy;
/// Generates one adjacently tagged variant arm.
///
/// # Parameters
///
/// * `type_name` - Enum receiving the generated serialization implementation.
/// * `variant` - Parsed variant being expanded.
/// * `runtime` - Resolved path to the runtime crate.
/// * `serde` - Resolved path to Serde.
/// * `container_attributes` - Validated container naming controls.
/// * `tag` - Serialized key containing the variant name.
/// * `content` - Serialized key containing the variant payload.
///
/// # Returns
///
/// A match arm that serializes the variant with adjacent tagging.
///
/// # Errors
///
/// This function currently produces no direct error; the result type matches
/// the representation-dispatch interface.
pub(in crate::serde) fn adjacent_variant_arm(
    type_name: &Ident,
    variant: &VariantData<'_>,
    runtime: &Path,
    serde: &Path,
    container_attributes: &SerdeContainerAttributes,
    tag: &str,
    content: &str,
) -> Result<TokenStream> {
    let rust_name = &variant.variant().ident;
    let variant_name = serialized_variant_name(variant, container_attributes);
    let enum_name = container_attributes.name();
    let arm = match variant.fields() {
        FieldsData::Named(fields) => {
            let (pattern, setups, _conditions, names, carriers) =
                enum_named_parts(type_name, rust_name, fields, runtime, container_attributes, variant);
            let (proxy_definition, proxy_value) = named_content_proxy(rust_name, serde, &names, &carriers);
            quote! {
                Self::#rust_name #pattern => {
                    #(#setups)*
                    #proxy_definition
                    let content_value = #proxy_value;
                    let mut state = #serde::Serializer::serialize_struct(
                        serializer,
                        #enum_name,
                        2,
                    )?;
                    #serde::ser::SerializeStruct::serialize_field(
                        &mut state,
                        #tag,
                        #variant_name,
                    )?;
                    #serde::ser::SerializeStruct::serialize_field(
                        &mut state,
                        #content,
                        &content_value,
                    )?;
                    #serde::ser::SerializeStruct::end(state)
                }
            }
        }
        FieldsData::Unnamed(fields) if fields.len() == 1 => {
            let (pattern, setups, _conditions, carriers) =
                enum_unnamed_parts(type_name, rust_name, variant.index(), fields, runtime);
            if carriers.is_empty() {
                quote! {
                    Self::#rust_name #pattern => {
                        let mut state = #serde::Serializer::serialize_struct(
                            serializer,
                            #enum_name,
                            1,
                        )?;
                        #serde::ser::SerializeStruct::serialize_field(
                            &mut state,
                            #tag,
                            #variant_name,
                        )?;
                        #serde::ser::SerializeStruct::end(state)
                    }
                }
            } else {
                let carrier = &carriers[0];
                quote! {
                    Self::#rust_name #pattern => {
                        #(#setups)*
                        let has_content = #carrier.is_some();
                        let mut state = #serde::Serializer::serialize_struct(
                            serializer,
                            #enum_name,
                            if has_content { 2 } else { 1 },
                        )?;
                        #serde::ser::SerializeStruct::serialize_field(
                            &mut state,
                            #tag,
                            #variant_name,
                        )?;
                        if let ::core::option::Option::Some(carrier) = #carrier.as_ref() {
                            #serde::ser::SerializeStruct::serialize_field(
                                &mut state,
                                #content,
                                carrier,
                            )?;
                        }
                        #serde::ser::SerializeStruct::end(state)
                    }
                }
            }
        }
        FieldsData::Unnamed(fields) => {
            let (pattern, setups, _conditions, carriers) =
                enum_unnamed_parts(type_name, rust_name, variant.index(), fields, runtime);
            let (proxy_definition, proxy_value) = tuple_content_proxy(rust_name, serde, &carriers);
            quote! {
                Self::#rust_name #pattern => {
                    #(#setups)*
                    #proxy_definition
                    let content_value = #proxy_value;
                    let mut state = #serde::Serializer::serialize_struct(
                        serializer,
                        #enum_name,
                        2,
                    )?;
                    #serde::ser::SerializeStruct::serialize_field(
                        &mut state,
                        #tag,
                        #variant_name,
                    )?;
                    #serde::ser::SerializeStruct::serialize_field(
                        &mut state,
                        #content,
                        &content_value,
                    )?;
                    #serde::ser::SerializeStruct::end(state)
                }
            }
        }
        FieldsData::Unit => quote! {
            Self::#rust_name => {
                let mut state = #serde::Serializer::serialize_struct(
                    serializer,
                    #enum_name,
                    1,
                )?;
                #serde::ser::SerializeStruct::serialize_field(
                    &mut state,
                    #tag,
                    #variant_name,
                )?;
                #serde::ser::SerializeStruct::end(state)
            }
        },
    };
    Ok(arm)
}
