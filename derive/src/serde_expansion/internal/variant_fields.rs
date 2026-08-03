// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Bindings and carriers shared by enum representation expansions.

use proc_macro2::TokenStream;
use quote::{
    format_ident,
    quote,
    quote_spanned,
};
use syn::{
    Path,
    spanned::Spanned,
};

use crate::{
    internal::{
        NamedField,
        UnnamedField,
        VariantData,
    },
    serde_container_attributes::SerdeContainerAttributes,
};

use super::field_serialization::{
    field_context,
    field_is_skipped,
    raw_identifier,
    serialization_condition,
    serialized_carrier,
};

/// Builds bindings, carriers, names, and conditions for named enum fields.
///
/// # Parameters
///
/// * `type_name` - Enum receiving the generated serialization implementation.
/// * `variant_name` - Variant owning the fields.
/// * `fields` - Parsed named fields in declaration order.
/// * `runtime` - Resolved path to the runtime crate.
/// * `container_attributes` - Validated container naming controls.
/// * `variant` - Parsed variant-local naming controls.
///
/// # Returns
///
/// The match pattern, carrier setup statements, inclusion conditions,
/// serialized field names, and carrier identifiers.
pub(super) fn enum_named_parts(
    type_name: &syn::Ident,
    variant_name: &syn::Ident,
    fields: &[NamedField<'_>],
    runtime: &Path,
    container_attributes: &SerdeContainerAttributes,
    variant: &VariantData<'_>,
) -> (
    TokenStream,
    Vec<TokenStream>,
    Vec<TokenStream>,
    Vec<String>,
    Vec<syn::Ident>,
) {
    let patterns = fields.iter().map(|parsed| {
        let identifier = parsed.identifier();
        if field_is_skipped(
            parsed.attributes().mode(),
            parsed.serde_attributes(),
        ) {
            quote!(#identifier: _)
        } else {
            quote!(#identifier)
        }
    });
    let mut setups = Vec::new();
    let mut conditions = Vec::new();
    let mut names = Vec::new();
    let mut carriers = Vec::new();
    for (position, parsed) in fields.iter().enumerate() {
        if field_is_skipped(
            parsed.attributes().mode(),
            parsed.serde_attributes(),
        ) {
            continue;
        }
        let field = parsed.field();
        let identifier = parsed.identifier();
        let raw_name = raw_identifier(identifier);
        let container_name =
            container_attributes.rename_variant_field(&raw_name);
        let default_name = variant
            .serde_attributes()
            .rename_field(&raw_name, container_name);
        let serialized_name = parsed
            .serde_attributes()
            .rename()
            .map_or(default_name, str::to_owned);
        let raw = quote_spanned!(field.span()=> #identifier);
        let context = field_context(
            Some(variant_name),
            Some(variant.index()),
            &raw_name,
        );
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
        names.push(serialized_name);
        carriers.push(carrier);
    }
    (
        quote!({ #(#patterns),* }),
        setups,
        conditions,
        names,
        carriers,
    )
}

/// Builds bindings, carriers, and conditions for tuple enum fields.
///
/// # Parameters
///
/// * `type_name` - Enum receiving the generated serialization implementation.
/// * `variant_name` - Variant owning the fields.
/// * `variant_index` - Zero-based declaration index of the owning variant.
/// * `fields` - Parsed positional fields in declaration order.
/// * `runtime` - Resolved path to the runtime crate.
///
/// # Returns
///
/// The match pattern, carrier setup statements, inclusion conditions, and
/// carrier identifiers.
pub(super) fn enum_unnamed_parts(
    type_name: &syn::Ident,
    variant_name: &syn::Ident,
    variant_index: u32,
    fields: &[UnnamedField<'_>],
    runtime: &Path,
) -> (
    TokenStream,
    Vec<TokenStream>,
    Vec<TokenStream>,
    Vec<syn::Ident>,
) {
    let bindings = fields
        .iter()
        .map(|parsed| {
            format_ident!(
                "__qubit_redact_field_{}",
                parsed.index().index,
                span = parsed.field().span(),
            )
        })
        .collect::<Vec<_>>();
    let patterns = fields.iter().zip(&bindings).map(|(parsed, binding)| {
        if field_is_skipped(
            parsed.attributes().mode(),
            parsed.serde_attributes(),
        ) {
            quote!(_)
        } else {
            quote!(#binding)
        }
    });
    let mut setups = Vec::new();
    let mut conditions = Vec::new();
    let mut carriers = Vec::new();
    for (position, (parsed, binding)) in
        fields.iter().zip(&bindings).enumerate()
    {
        if field_is_skipped(
            parsed.attributes().mode(),
            parsed.serde_attributes(),
        ) {
            continue;
        }
        let field = parsed.field();
        let field_name = parsed.index().index.to_string();
        let context = field_context(
            Some(variant_name),
            Some(variant_index),
            &field_name,
        );
        let carrier = format_ident!("__qubit_redact_serialized_{position}");
        let raw = quote_spanned!(field.span()=> #binding);
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
    (quote!((#(#patterns),*)), setups, conditions, carriers)
}
