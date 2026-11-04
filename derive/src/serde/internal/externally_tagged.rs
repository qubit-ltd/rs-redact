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
use syn::Result;

use super::super::source_function_path::SourceTypeContext;
use super::field_events::field_count;
use super::field_events::named_field_event;
use super::field_events::positional_field_event;
use super::variant_fields::enum_named_plan;
use super::variant_fields::enum_unnamed_plan;
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
    source_context: &SourceTypeContext<'_>,
    recursive_target: &str,
    variant: &VariantData<'_>,
    runtime: &Path,
    serde: &Path,
    container_attributes: &SerdeContainerAttributes,
    legacy_nested: bool,
) -> Result<TokenStream> {
    let rust_name = &variant.variant().ident;
    let variant_name = serialized_variant_name(variant, container_attributes);
    let enum_name = container_attributes.name();
    let variant_index = variant.index();
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
            let count_conditions = plans.iter().map(|plan| plan.included.clone()).collect::<Vec<_>>();
            let count_setup = field_count(&count_conditions, 0);
            let trait_path: syn::Path = syn::parse_quote!(#serde::ser::SerializeStructVariant);
            let state = quote!(&mut state);
            let calls = plans.iter().map(|plan| {
                let carrier = &plan.carrier;
                let carrier = quote!(#carrier);
                named_field_event(
                    &trait_path,
                    &state,
                    &carrier,
                    plan.serialized_name.as_deref().expect("named field has a name"),
                    plan.skip_event.as_ref(),
                )
            });
            quote! {
                Self::#rust_name #pattern => {
                    #(#setups)*
                    #count_setup
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
            let (pattern, plans) = enum_unnamed_plan(
                source_context,
                recursive_target,
                rust_name,
                variant.index(),
                fields,
                runtime,
                legacy_nested,
            );
            let setups = plans.iter().map(|plan| &plan.setup);
            let carriers = plans.iter().map(|plan| &plan.carrier).collect::<Vec<_>>();
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
            let (pattern, plans) = enum_unnamed_plan(
                source_context,
                recursive_target,
                rust_name,
                variant.index(),
                fields,
                runtime,
                legacy_nested,
            );
            let setups = plans.iter().map(|plan| &plan.setup);
            let conditions = plans.iter().map(|plan| plan.included.clone()).collect::<Vec<_>>();
            let carriers = plans.iter().map(|plan| plan.carrier.clone()).collect::<Vec<_>>();
            let count_setup = field_count(&conditions, 0);
            let trait_path: syn::Path = syn::parse_quote!(#serde::ser::SerializeTupleVariant);
            let method: syn::Ident = syn::parse_quote!(serialize_field);
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
