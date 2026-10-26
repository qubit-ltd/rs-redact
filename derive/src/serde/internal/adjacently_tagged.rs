// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Adjacently tagged enum serialization expansion.

use proc_macro2::TokenStream;
use quote::format_ident;
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
#[allow(clippy::too_many_arguments)]
pub(in crate::serde) fn adjacent_variant_arm(
    type_name: &Ident,
    recursive_target: &str,
    variant: &VariantData<'_>,
    runtime: &Path,
    serde: &Path,
    container_attributes: &SerdeContainerAttributes,
    tag: &str,
    content: &str,
    legacy_nested: bool,
) -> Result<TokenStream> {
    let rust_name = &variant.variant().ident;
    let variant_name = serialized_variant_name(variant, container_attributes);
    let enum_name = container_attributes.name();
    let tag_serializer = adjacent_tag_serializer(serde, enum_name, variant.index(), &variant_name);
    let arm = match variant.fields() {
        FieldsData::Named(fields) => {
            let (pattern, setups, _conditions, names, carriers) = enum_named_parts(
                type_name,
                recursive_target,
                rust_name,
                fields,
                runtime,
                container_attributes,
                variant,
                legacy_nested,
            );
            let (proxy_definition, proxy_value) =
                named_content_proxy(rust_name, &variant_name, runtime, serde, &names, &carriers);
            quote! {
                Self::#rust_name #pattern => {
                    #tag_serializer
                    #(#setups)*
                    #proxy_definition
                    let content_value = #proxy_value;
                    #runtime::domain::internal::admit_serializer_items(&serializer, 2)?;
                    let mut state = #serde::Serializer::serialize_struct(
                        serializer,
                        #enum_name,
                        2,
                    )?;
                    #serde::ser::SerializeStruct::serialize_field(
                        &mut state,
                        #tag,
                        &#runtime::domain::internal::BudgetSerialize::new(__QubitRedactAdjacentTag),
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
            let (pattern, setups, _conditions, carriers) = enum_unnamed_parts(
                type_name,
                recursive_target,
                rust_name,
                variant.index(),
                fields,
                runtime,
                legacy_nested,
            );
            if carriers.is_empty() {
                quote! {
                    Self::#rust_name #pattern => {
                        #tag_serializer
                        #runtime::domain::internal::admit_serializer_items(&serializer, 1)?;
                        let mut state = #serde::Serializer::serialize_struct(
                            serializer,
                            #enum_name,
                            1,
                        )?;
                        #serde::ser::SerializeStruct::serialize_field(
                            &mut state,
                            #tag,
                            &#runtime::domain::internal::BudgetSerialize::new(__QubitRedactAdjacentTag),
                        )?;
                        #serde::ser::SerializeStruct::end(state)
                    }
                }
            } else {
                let carrier = &carriers[0];
                quote! {
                    Self::#rust_name #pattern => {
                        #tag_serializer
                        #(#setups)*
                        let has_content = #carrier.is_some();
                        #runtime::domain::internal::admit_serializer_items(&serializer, if has_content { 2 } else { 1 })?;
                        let mut state = #serde::Serializer::serialize_struct(
                            serializer,
                            #enum_name,
                            if has_content { 2 } else { 1 },
                        )?;
                        #serde::ser::SerializeStruct::serialize_field(
                            &mut state,
                            #tag,
                            &#runtime::domain::internal::BudgetSerialize::new(__QubitRedactAdjacentTag),
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
            let (pattern, setups, _conditions, carriers) = enum_unnamed_parts(
                type_name,
                recursive_target,
                rust_name,
                variant.index(),
                fields,
                runtime,
                legacy_nested,
            );
            let (proxy_definition, proxy_value) = tuple_content_proxy(rust_name, runtime, serde, &carriers);
            quote! {
                Self::#rust_name #pattern => {
                    #tag_serializer
                    #(#setups)*
                    #proxy_definition
                    let content_value = #proxy_value;
                    #runtime::domain::internal::admit_serializer_items(&serializer, 2)?;
                    let mut state = #serde::Serializer::serialize_struct(
                        serializer,
                        #enum_name,
                        2,
                    )?;
                    #serde::ser::SerializeStruct::serialize_field(
                        &mut state,
                        #tag,
                        &#runtime::domain::internal::BudgetSerialize::new(__QubitRedactAdjacentTag),
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
                #tag_serializer
                #runtime::domain::internal::admit_serializer_items(&serializer, 1)?;
                let mut state = #serde::Serializer::serialize_struct(
                    serializer,
                    #enum_name,
                    1,
                )?;
                #serde::ser::SerializeStruct::serialize_field(
                    &mut state,
                    #tag,
                    &#runtime::domain::internal::BudgetSerialize::new(__QubitRedactAdjacentTag),
                )?;
                #serde::ser::SerializeStruct::end(state)
            }
        },
    };
    Ok(arm)
}

/// Generates a local Serde adapter that preserves an adjacent enum's event
/// identity.
///
/// # Parameters
///
/// * `serde` - Resolved Serde path used by the generated implementation.
/// * `enum_name` - Effective serialized name of the enum.
/// * `variant_index` - Zero-based declaration index of the variant.
/// * `variant_name` - Effective serialized name of the variant.
///
/// # Returns
///
/// A local unit type whose serializer emits the corresponding unit-variant
/// event.
fn adjacent_tag_serializer(serde: &Path, enum_name: &str, variant_index: u32, variant_name: &str) -> TokenStream {
    let enum_name = syn::LitStr::new(enum_name, proc_macro2::Span::call_site());
    let variant_name = syn::LitStr::new(variant_name, proc_macro2::Span::call_site());
    let variant_index = syn::Index::from(variant_index as usize);
    let tag_type = format_ident!("__QubitRedactAdjacentTag", span = proc_macro2::Span::mixed_site());
    quote! {
        struct #tag_type;
        impl #serde::Serialize for #tag_type {
            fn serialize<__Serializer>(
                &self,
                serializer: __Serializer,
            ) -> ::core::result::Result<__Serializer::Ok, __Serializer::Error>
            where
                __Serializer: #serde::Serializer,
            {
                serializer.serialize_unit_variant(
                    #enum_name,
                    #variant_index,
                    #variant_name,
                )
            }
        }
    }
}
