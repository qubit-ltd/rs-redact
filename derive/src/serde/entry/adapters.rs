// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Local carriers used by custom Serde serialization adapters.

use proc_macro2::TokenStream;
use quote::format_ident;
use quote::quote;
use quote::quote_spanned;
use syn::Field;
use syn::GenericParam;
use syn::Generics;
use syn::LifetimeParam;
use syn::Path;
use syn::spanned::Spanned;

use super::super::field::adapter_helper_name;
use super::super::field::field_context;
use super::super::source_function_path::SourceTypeContext;
use super::super::source_function_path::path_has_self_type_argument;
use super::super::source_function_path::source_function_path;
use crate::expand::assertions;
use crate::model::ContainerData;
use crate::model::FieldsData;
use crate::model::VariantData;

/// Collects local Serde carriers for custom field adapters.
///
/// # Parameters
///
/// * `source_context` - Source type identity used to resolve `Self` in adapter
///   paths.
/// * `source_generics` - Rebound source generic parameters and bounds.
/// * `projection_generics` - Projection parameters used to select helper
///   dependencies and avoid generated-name collisions.
/// * `model` - Validated source fields and adapter controls.
/// * `serde` - Resolved Serde path.
///
/// # Returns
///
/// Local helper declarations for fields with custom serialization adapters.
#[must_use]
pub(super) fn serialization_adapter_helpers(
    source_context: &SourceTypeContext<'_>,
    source_generics: &Generics,
    projection_generics: &Generics,
    model: &ContainerData<'_>,
    serde: &Path,
) -> Vec<TokenStream> {
    match model {
        ContainerData::Struct(fields) => helpers_for_group(
            source_context,
            source_generics,
            projection_generics,
            fields,
            None,
            serde,
        ),
        ContainerData::Enum(variants) => variants
            .iter()
            .filter(|variant| !variant.serde_attributes().skip())
            .flat_map(|variant| {
                helpers_for_group(
                    source_context,
                    source_generics,
                    projection_generics,
                    variant.fields(),
                    Some(variant),
                    serde,
                )
            })
            .collect(),
    }
}

/// Builds custom serialization helpers for one field group.
///
/// # Parameters
///
/// * `source_context` - Source type identity used to resolve `Self` in adapter
///   paths.
/// * `source_generics` - Rebound source generic parameters and bounds.
/// * `projection_generics` - Projection parameters used to select helper
///   dependencies and avoid generated-name collisions.
/// * `fields` - Fields whose optional adapters are inspected.
/// * `variant` - Owning enum variant, or None for struct fields.
/// * `serde` - Resolved Serde path.
///
/// # Returns
///
/// Helper declarations only for fields with a serialization adapter.
#[must_use]
fn helpers_for_group(
    source_context: &SourceTypeContext<'_>,
    source_generics: &Generics,
    projection_generics: &Generics,
    fields: &FieldsData<'_>,
    variant: Option<&VariantData<'_>>,
    serde: &Path,
) -> Vec<TokenStream> {
    match fields {
        FieldsData::Named(fields) => fields
            .iter()
            .filter(|field| !field.serde_attributes().skip())
            .filter_map(|field| {
                adapter_helper(
                    source_context,
                    source_generics,
                    projection_generics,
                    field.field(),
                    &field_context(
                        variant.map(|item| &item.variant().ident),
                        variant.map(VariantData::index),
                        &field.identifier().to_string(),
                    ),
                    field.serde_attributes().serialize_with(),
                    serde,
                )
            })
            .collect(),
        FieldsData::Unnamed(fields) => fields
            .iter()
            .filter(|field| !field.serde_attributes().skip())
            .filter_map(|field| {
                adapter_helper(
                    source_context,
                    source_generics,
                    projection_generics,
                    field.field(),
                    &field_context(
                        variant.map(|item| &item.variant().ident),
                        variant.map(VariantData::index),
                        &field.index().index.to_string(),
                    ),
                    field.serde_attributes().serialize_with(),
                    serde,
                )
            })
            .collect(),
        FieldsData::Unit => Vec::new(),
    }
}

/// Builds a local borrowing carrier for one custom adapter.
///
/// # Parameters
///
/// * `source_context` - Source type identity used to resolve `Self` in adapter
///   paths.
/// * `source_generics` - Rebound source generic parameters and bounds.
/// * `projection_generics` - Projection parameters used to select field
///   dependencies and avoid generated-name collisions.
/// * `field` - Source field supplying its type and diagnostic span.
/// * `context` - Stable field context used in helper names.
/// * `adapter` - Custom serialization function, or None to use ordinary Serde.
/// * `serde` - Resolved Serde path.
///
/// # Returns
///
/// Some carrier and helper declarations when an adapter exists, otherwise None.
#[must_use]
fn adapter_helper(
    source_context: &SourceTypeContext<'_>,
    source_generics: &Generics,
    projection_generics: &Generics,
    field: &Field,
    context: &str,
    adapter: Option<&Path>,
    serde: &Path,
) -> Option<TokenStream> {
    let adapter = adapter?;
    let helper = adapter_helper_name(source_context.ident, field, context);
    let wrapper = format_ident!("{helper}_carrier", span = field.span());
    let field_type = &field.ty;
    let lifetime = assertions::fresh_lifetime(projection_generics);
    let adapter_tokens = source_function_path(source_context, adapter);
    let mut helper_generics = if adapter.segments.first().is_some_and(|segment| segment.ident == "Self")
        || path_has_self_type_argument(adapter)
    {
        source_generics.clone()
    } else {
        assertions::generics_for_field_and_adapter(projection_generics, field_type, adapter)
    };
    helper_generics
        .params
        .insert(0, GenericParam::Lifetime(LifetimeParam::new(lifetime.clone())));
    let serializer = assertions::fresh_identifier(&helper_generics, "__QubitRedactSerializer");
    let marker_types = helper_generics.params.iter().filter_map(|parameter| match parameter {
        GenericParam::Lifetime(parameter) => {
            let lifetime = &parameter.lifetime;
            Some(quote!(&#lifetime ()))
        }
        GenericParam::Type(parameter) => {
            let name = &parameter.ident;
            Some(quote!(*const #name))
        }
        GenericParam::Const(_) => None,
    });
    let params = &helper_generics.params;
    let (impl_generics, type_generics, where_clause) = helper_generics.split_for_impl();
    let carrier_arguments = helper_generics.params.iter().map(|parameter| match parameter {
        GenericParam::Lifetime(parameter) if parameter.lifetime == lifetime => {
            quote!(#lifetime)
        }
        GenericParam::Lifetime(parameter) => {
            let name = &parameter.lifetime;
            quote!(#name)
        }
        GenericParam::Type(parameter) => {
            let name = &parameter.ident;
            quote!(#name)
        }
        GenericParam::Const(parameter) => {
            let name = &parameter.ident;
            quote!(#name)
        }
    });
    Some(quote_spanned! {field.span()=>
        #[allow(non_camel_case_types)] struct #wrapper<#params>(&#lifetime #field_type, ::core::marker::PhantomData<(#(#marker_types,)*)>) #where_clause;
        impl #impl_generics #serde::Serialize for #wrapper #type_generics #where_clause { fn serialize<#serializer>(&self, serializer: #serializer) -> ::core::result::Result<#serializer::Ok, #serializer::Error> where #serializer: #serde::Serializer { #adapter_tokens(self.0, serializer) } }
        #[allow(non_snake_case)] let #helper: for<#lifetime> fn(&#lifetime #field_type) -> #wrapper<#(#carrier_arguments),*> = |value| #wrapper(value, ::core::marker::PhantomData);
    })
}
