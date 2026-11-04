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
use syn::Error;
use syn::Path;
use syn::Result;

use super::super::source_function_path::SourceTypeContext;
use super::field_events::field_count;
use super::field_events::named_field_event;
use super::variant_fields::enum_named_plan;
use super::variant_fields::enum_unnamed_plan;
use crate::attributes::SerdeContainerAttributes;
use crate::model::FieldsData;
use crate::model::VariantData;
use crate::serde::field::field_is_skipped;
use crate::serde::naming::serialized_variant_name;
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
/// internally tagged tuple variant does not contain exactly one field.
#[allow(clippy::too_many_arguments)]
pub(in crate::serde) fn internal_variant_arm(
    source_context: &SourceTypeContext<'_>,
    recursive_target: &str,
    variant: &VariantData<'_>,
    runtime: &Path,
    serde: &Path,
    container_attributes: &SerdeContainerAttributes,
    tag: &str,
    legacy_nested: bool,
) -> Result<TokenStream> {
    let type_name = source_context.ident;
    let rust_name = &variant.variant().ident;
    let variant_name = serialized_variant_name(variant, container_attributes);
    let enum_name = container_attributes.name();
    match variant.fields() {
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
            let conditions = plans.iter().map(|plan| plan.included.clone()).collect::<Vec<_>>();
            if let Some((field, _)) = fields
                .iter()
                .filter(|field| !field_is_skipped(field.serde_attributes()))
                .zip(plans.iter())
                .find(|(_, plan)| plan.serialized_name.as_deref() == Some(tag))
            {
                return Err(Error::new_spanned(
                    field.field(),
                    format!(
                        "Redact serde for `{type_name}` variant `{rust_name}` has field `{tag}` conflicting with the internal tag",
                    ),
                ));
            }
            let count_setup = field_count(&conditions, 1);
            let trait_path: syn::Path = syn::parse_quote!(#serde::ser::SerializeStruct);
            let state = quote!(&mut state);
            let calls = plans.iter().map(|plan| {
                let carrier = {
                    let carrier = &plan.carrier;
                    quote!(#carrier)
                };
                named_field_event(
                    &trait_path,
                    &state,
                    &carrier,
                    plan.serialized_name.as_deref().expect("named field has a name"),
                    plan.skip_event.as_ref(),
                )
            });
            Ok(quote! {
                Self::#rust_name #pattern => {
                    #(#setups)*
                    #count_setup
                    #runtime::domain::internal::admit_serializer_items(&serializer, field_count)?;
                    let mut state = #serde::Serializer::serialize_struct(
                        serializer,
                        #enum_name,
                        field_count,
                    )?;
                    #serde::ser::SerializeStruct::serialize_field(
                        &mut state,
                        #tag,
                        &#runtime::domain::internal::BudgetSerialize::new(#variant_name),
                    )?;
                    #(#calls)*
                    #serde::ser::SerializeStruct::end(state)
                }
            })
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
            let carriers = plans.iter().map(|plan| plan.carrier.clone()).collect::<Vec<_>>();
            if carriers.is_empty() {
                Ok(quote! {
                    Self::#rust_name #pattern => {
                        #runtime::domain::internal::admit_serializer_items(&serializer, 1)?;
                        let mut state = #serde::Serializer::serialize_struct(
                            serializer,
                            #enum_name,
                            1,
                        )?;
                        #serde::ser::SerializeStruct::serialize_field(
                            &mut state,
                            #tag,
                            &#runtime::domain::internal::BudgetSerialize::new(#variant_name),
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
                            #runtime::domain::internal::serialize_internally_tagged(
                                serializer,
                                #enum_name,
                                stringify!(#rust_name),
                                #tag,
                                #variant_name,
                                carrier,
                            )
                        } else {
                            #runtime::domain::internal::admit_serializer_items(&serializer, 1)?;
                            let mut state = #serde::Serializer::serialize_struct(
                                serializer,
                                #enum_name,
                                1,
                            )?;
                            #serde::ser::SerializeStruct::serialize_field(
                                &mut state,
                                #tag,
                                &#runtime::domain::internal::BudgetSerialize::new(#variant_name),
                            )?;
                            #serde::ser::SerializeStruct::end(state)
                        }
                    }
                })
            }
        }
        FieldsData::Unnamed(_) => Err(Error::new_spanned(
            variant.variant(),
            format!("Redact serde for internally tagged `{type_name}` does not allow tuple variants",),
        )),
        FieldsData::Unit => Ok(quote! {
            Self::#rust_name => {
                #runtime::domain::internal::admit_serializer_items(&serializer, 1)?;
                let mut state = #serde::Serializer::serialize_struct(
                    serializer,
                    #enum_name,
                    1,
                )?;
                #serde::ser::SerializeStruct::serialize_field(
                    &mut state,
                    #tag,
                    &#runtime::domain::internal::BudgetSerialize::new(#variant_name),
                )?;
                #serde::ser::SerializeStruct::end(state)
            }
        }),
    }
}
