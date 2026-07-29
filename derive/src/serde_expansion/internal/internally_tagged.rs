// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Internally tagged enum serialization expansion.

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

/// Generates one internally tagged variant arm.
///
/// # Parameters
///
/// * `type_name` - Enum receiving the generated serialization implementation.
/// * `variant` - Parsed variant being expanded.
/// * `runtime` - Resolved path to the runtime crate.
/// * `serde` - Resolved path to Serde.
/// * `container_attributes` - Validated container naming controls.
/// * `tag` - Serialized key containing the variant name.
///
/// # Returns
///
/// A match arm that serializes the variant with internal tagging.
///
/// # Errors
///
/// Returns an error when a named field conflicts with `tag` or when an
/// internally tagged variant has more than one unnamed field.
pub(super) fn internal_variant_arm(
    type_name: &syn::Ident,
    variant: &VariantData<'_>,
    runtime: &Path,
    serde: &Path,
    container_attributes: &SerdeContainerAttributes,
    tag: &str,
) -> syn::Result<TokenStream> {
    let rust_name = &variant.variant().ident;
    let variant_name = serialized_variant_name(variant, container_attributes);
    let enum_name = container_attributes.name();
    match variant.fields() {
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
            if let Some((field, _)) =
                fields.iter().zip(&names).find(|(_, name)| *name == tag)
            {
                return Err(syn::Error::new_spanned(
                    field.field(),
                    format!(
                        "Redact serde for `{type_name}` variant `{rust_name}` has field `{tag}` conflicting with the internal tag",
                    ),
                ));
            }
            let count_conditions = &conditions;
            let calls = conditions.iter().zip(&names).zip(&carriers).map(
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
            Ok(quote! {
                Self::#rust_name #pattern => {
                    #(#setups)*
                    let mut field_count = 1usize;
                    #(
                        if #count_conditions {
                            field_count += 1;
                        }
                    )*
                    let mut state = #serde::Serializer::serialize_struct(
                        serializer,
                        #enum_name,
                        field_count,
                    )?;
                    #serde::ser::SerializeStruct::serialize_field(
                        &mut state,
                        #tag,
                        #variant_name,
                    )?;
                    #(#calls)*
                    #serde::ser::SerializeStruct::end(state)
                }
            })
        }
        FieldsData::Unnamed(fields) if fields.len() == 1 => {
            let (pattern, setups, _conditions, carriers) =
                enum_unnamed_parts(type_name, rust_name, fields, runtime);
            if carriers.is_empty() {
                Ok(quote! {
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
                })
            } else {
                let carrier = &carriers[0];
                Ok(quote! {
                    Self::#rust_name #pattern => {
                        #(#setups)*
                        if let ::core::option::Option::Some(carrier) = #carrier.as_ref() {
                            #runtime::__private::serialize_internally_tagged(
                                serializer,
                                #enum_name,
                                stringify!(#rust_name),
                                #tag,
                                #variant_name,
                                carrier,
                            )
                        } else {
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
                })
            }
        }
        FieldsData::Unnamed(_) => Err(syn::Error::new_spanned(
            variant.variant(),
            format!(
                "Redact serde for internally tagged `{type_name}` does not allow tuple variants",
            ),
        )),
        FieldsData::Unit => Ok(quote! {
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
        }),
    }
}
