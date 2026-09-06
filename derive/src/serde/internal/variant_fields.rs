// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Bindings and carriers shared by enum representation expansions.

use proc_macro2::TokenStream;
use quote::format_ident;
use quote::quote;
use quote::quote_spanned;
use syn::Ident;
use syn::Path;
use syn::spanned::Spanned;

use crate::attributes::SerdeContainerAttributes;
use crate::model::FieldMode;
use crate::model::NamedField;
use crate::model::UnnamedField;
use crate::model::VariantData;
use crate::serde::field::field_context;
use crate::serde::field::field_is_skipped;
use crate::serde::field::raw_identifier;
use crate::serde::field::serialization_condition;
use crate::serde::field::serialized_carrier;
use crate::serde::field_access::FieldAccess;
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
    type_name: &Ident,
    variant_name: &Ident,
    fields: &[NamedField<'_>],
    runtime: &Path,
    container_attributes: &SerdeContainerAttributes,
    variant: &VariantData<'_>,
) -> (TokenStream, Vec<TokenStream>, Vec<TokenStream>, Vec<String>, Vec<Ident>) {
    let bindings = fields
        .iter()
        .enumerate()
        .map(|(position, parsed)| format_ident!("__qubit_redact_field_{position}", span = parsed.field().span()))
        .collect::<Vec<_>>();
    let patterns = fields.iter().zip(&bindings).map(|(parsed, binding)| {
        let identifier = parsed.identifier();
        let used_as_key = fields.iter().any(|field| {
            !field_is_skipped(field.attributes().mode(), field.serde_attributes())
                && matches!(field.attributes().mode(), FieldMode::KeyedBy(key) if key == identifier)
        });
        if field_is_skipped(parsed.attributes().mode(), parsed.serde_attributes()) && !used_as_key {
            quote!(#identifier: _)
        } else {
            quote!(#identifier: #binding)
        }
    });
    let mut setups = Vec::new();
    let mut conditions = Vec::new();
    let mut names = Vec::new();
    let mut carriers = Vec::new();
    for (position, (parsed, binding)) in fields.iter().zip(&bindings).enumerate() {
        if field_is_skipped(parsed.attributes().mode(), parsed.serde_attributes()) {
            continue;
        }
        let field = parsed.field();
        let identifier = parsed.identifier();
        let raw_name = raw_identifier(identifier);
        let container_name = container_attributes.rename_variant_field(&raw_name);
        let default_name = variant.serde_attributes().rename_field(&raw_name, container_name);
        let serialized_name = parsed.serde_attributes().rename().map_or(default_name, str::to_owned);
        let raw = quote_spanned!(field.span()=> #binding);
        let key_raw = match parsed.attributes().mode() {
            FieldMode::KeyedBy(key) => {
                let position = fields
                    .iter()
                    .position(|candidate| candidate.identifier() == key)
                    .expect("keyed_by sibling was validated");
                let key_binding = &bindings[position];
                Some(quote_spanned!(field.span()=> #key_binding))
            }
            _ => None,
        };
        let context = field_context(Some(variant_name), Some(variant.index()), &raw_name);
        let carrier = format_ident!("__qubit_redact_serialized_{position}");
        let value = serialized_carrier(
            type_name,
            field,
            &context,
            parsed.attributes().mode(),
            runtime,
            parsed.serde_attributes().serialize_with(),
            FieldAccess {
                raw: raw.clone(),
                key_raw,
            },
        );
        let condition = serialization_condition(parsed.serde_attributes(), parsed.attributes().mode(), raw);
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
    (quote!({ #(#patterns),* }), setups, conditions, names, carriers)
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
    type_name: &Ident,
    variant_name: &Ident,
    variant_index: u32,
    fields: &[UnnamedField<'_>],
    runtime: &Path,
) -> (TokenStream, Vec<TokenStream>, Vec<TokenStream>, Vec<Ident>) {
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
        if field_is_skipped(parsed.attributes().mode(), parsed.serde_attributes()) {
            quote!(_)
        } else {
            quote!(#binding)
        }
    });
    let mut setups = Vec::new();
    let mut conditions = Vec::new();
    let mut carriers = Vec::new();
    for (position, (parsed, binding)) in fields.iter().zip(&bindings).enumerate() {
        if field_is_skipped(parsed.attributes().mode(), parsed.serde_attributes()) {
            continue;
        }
        let field = parsed.field();
        let field_name = parsed.index().index.to_string();
        let context = field_context(Some(variant_name), Some(variant_index), &field_name);
        let carrier = format_ident!("__qubit_redact_serialized_{position}");
        let raw = quote_spanned!(field.span()=> #binding);
        let value = serialized_carrier(
            type_name,
            field,
            &context,
            parsed.attributes().mode(),
            runtime,
            parsed.serde_attributes().serialize_with(),
            FieldAccess {
                raw: raw.clone(),
                key_raw: None,
            },
        );
        let condition = serialization_condition(parsed.serde_attributes(), parsed.attributes().mode(), raw);
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
