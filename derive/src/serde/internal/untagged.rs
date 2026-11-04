// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Untagged enum serialization expansion.

use proc_macro2::TokenStream;
use quote::quote;
use syn::Path;
use syn::Result;

use super::super::source_function_path::SourceTypeContext;
use super::field_events::field_count;
use super::field_events::named_field_event;
use super::field_events::positional_field_event;
use super::variant_fields::enum_named_plan;
use super::variant_fields::enum_unnamed_parts;
use crate::attributes::SerdeContainerAttributes;
use crate::model::FieldsData;
use crate::model::VariantData;
/// Generates one untagged variant arm.
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
/// A match arm that serializes the variant without a tag.
///
/// # Errors
///
/// This function currently produces no direct error; the result type matches
/// the representation-dispatch interface.
pub(in crate::serde) fn untagged_variant_arm(
    source_context: &SourceTypeContext<'_>,
    recursive_target: &str,
    variant: &VariantData<'_>,
    runtime: &Path,
    serde: &Path,
    container_attributes: &SerdeContainerAttributes,
    legacy_nested: bool,
) -> Result<TokenStream> {
    let rust_name = &variant.variant().ident;
    let enum_name = container_attributes.name();
    let arm = match variant.fields() {
        FieldsData::Named(fields) => {
            let (pattern, plans) = enum_named_plan(
                source_context,
                recursive_target,
                rust_name,
                fields,
                runtime,
                container_attributes,
                variant,
                legacy_nested,
            );
            let setups = plans.iter().map(|plan| &plan.setup);
            let count_conditions = plans
                .iter()
                .map(|plan| plan.included.clone())
                .collect::<Vec<_>>();
            let count_setup = field_count(&count_conditions, 0);
            let trait_path: syn::Path = syn::parse_quote!(#serde::ser::SerializeStruct);
            let state = quote!(&mut state);
            let calls = plans.iter().map(|plan| {
                let carrier = &plan.carrier;
                let carrier = quote!(#carrier);
                named_field_event(
                    &trait_path,
                    &state,
                    &carrier,
                    plan.serialized_name
                        .as_deref()
                        .expect("named field has a name"),
                    plan.skip_event.as_ref(),
                )
            });
            quote! {
                Self::#rust_name #pattern => {
                    #(#setups)*
                    #count_setup
                    #runtime::domain::internal::admit_serializer_items(&serializer, field_count)?;
                    let mut state = #serde::Serializer::serialize_struct(
                        serializer,
                        #enum_name,
                        field_count,
                    )?;
                    #(#calls)*
                    #serde::ser::SerializeStruct::end(state)
                }
            }
        }
        FieldsData::Unnamed(fields) if fields.len() == 1 => {
            let (pattern, setups, _conditions, carriers) = enum_unnamed_parts(
                source_context,
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
                        #serde::Serializer::serialize_unit(serializer)
                    }
                }
            } else {
                let carrier = &carriers[0];
                quote! {
                    Self::#rust_name #pattern => {
                        #(#setups)*
                        if let ::core::option::Option::Some(carrier) = #carrier.as_ref() {
                            #serde::Serialize::serialize(carrier, serializer)
                        } else {
                            #serde::Serializer::serialize_unit(serializer)
                        }
                    }
                }
            }
        }
        FieldsData::Unnamed(fields) => {
            let (pattern, setups, conditions, carriers) = enum_unnamed_parts(
                source_context,
                recursive_target,
                rust_name,
                variant.index(),
                fields,
                runtime,
                legacy_nested,
            );
            let count_setup = field_count(&conditions, 0);
            let trait_path: syn::Path = syn::parse_quote!(#serde::ser::SerializeTuple);
            let method: syn::Ident = syn::parse_quote!(serialize_element);
            let state = quote!(&mut state);
            let calls = carriers.iter().map(|carrier| {
                let carrier = quote!(#carrier);
                positional_field_event(&trait_path, &method, &state, &carrier)
            });
            quote! {
                Self::#rust_name #pattern => {
                    #(#setups)*
                    #count_setup
                    #runtime::domain::internal::admit_serializer_items(&serializer, field_count)?;
                    let mut state = #serde::Serializer::serialize_tuple(
                        serializer,
                        field_count,
                    )?;
                    #(#calls)*
                    #serde::ser::SerializeTuple::end(state)
                }
            }
        }
        FieldsData::Unit => quote! {
            Self::#rust_name => #serde::Serializer::serialize_unit(serializer)
        },
    };
    Ok(arm)
}
