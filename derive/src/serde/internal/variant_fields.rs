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
use crate::serde::field::projected_predicate;
use crate::serde::field::projected_raw;
use crate::serde::field::raw_identifier;
use crate::serde::field::serialization_condition;
use crate::serde::field::serialized_carrier;
use crate::serde::field_access::FieldAccess;
use crate::serde::source_function_path::SourceTypeContext;
/// Builds bindings, carriers, names, and conditions for named enum fields.
///
/// # Parameters
///
/// * `source_context` - Source type identity and generic context used to
///   resolve source paths and helpers.
/// * `recursive_target` - Source type name used to recognize self-recursive
///   field projections.
/// * `variant_name` - Variant owning the fields.
/// * `fields` - Parsed named fields in declaration order.
/// * `runtime` - Resolved path to the runtime crate.
/// * `container_attributes` - Validated container naming controls.
/// * `variant` - Parsed variant-local naming controls.
/// * `legacy_nested` - Whether nested fields use the source serialization
///   bridge rather than borrowed view projections, affecting field access and
///   nested carrier selection.
///
/// # Returns
///
/// The match pattern, carrier setup statements, inclusion conditions,
/// serialized field names, and carrier identifiers.
///
/// # Panics
///
/// Panics if validated keyed mode has no sibling field or map-level mode has
/// no key sensitivity.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub(super) fn enum_named_parts(
    source_context: &SourceTypeContext<'_>,
    recursive_target: &str,
    variant_name: &Ident,
    fields: &[NamedField<'_>],
    runtime: &Path,
    container_attributes: &SerdeContainerAttributes,
    variant: &VariantData<'_>,
    legacy_nested: bool,
) -> (TokenStream, Vec<TokenStream>, Vec<TokenStream>, Vec<String>, Vec<Ident>) {
    let type_name = source_context.ident;
    let bindings = fields
        .iter()
        .enumerate()
        .map(|(position, parsed)| format_ident!("__qubit_redact_field_{position}", span = parsed.field().span()))
        .collect::<Vec<_>>();
    let patterns = fields.iter().zip(&bindings).map(|(parsed, binding)| {
        let identifier = parsed.identifier();
        let used_as_key = fields.iter().any(|field| {
            !field_is_skipped(field.serde_attributes())
                && matches!(field.attributes().mode(), FieldMode::KeyedBy(key) if key == identifier)
        });
        if field_is_skipped(parsed.serde_attributes()) && !used_as_key {
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
        if field_is_skipped(parsed.serde_attributes()) {
            continue;
        }
        let field = parsed.field();
        let identifier = parsed.identifier();
        let raw_name = raw_identifier(identifier);
        let container_name = container_attributes.rename_variant_field(&raw_name);
        let default_name = variant.serde_attributes().rename_field(&raw_name, container_name);
        let serialized_name = parsed.serde_attributes().rename().map_or(default_name, str::to_owned);
        let raw_member = quote_spanned!(field.span()=> #binding);
        let predicate = projected_predicate(raw_member.clone(), parsed.serde_attributes(), legacy_nested);
        let raw = projected_raw(raw_member, parsed.serde_attributes(), legacy_nested);
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
        let key_raw = key_raw.map(|raw| {
            let FieldMode::KeyedBy(key) = parsed.attributes().mode() else {
                unreachable!()
            };
            let key_field = fields
                .iter()
                .find(|candidate| candidate.identifier() == key)
                .expect("keyed_by sibling was validated");
            projected_raw(raw, key_field.serde_attributes(), legacy_nested)
        });
        let context = field_context(Some(variant_name), Some(variant.index()), &raw_name);
        let carrier = format_ident!("__qubit_redact_serialized_{position}");
        let value = serialized_carrier(
            type_name,
            recursive_target,
            field,
            &context,
            parsed.attributes().mode(),
            runtime,
            parsed.serde_attributes().serialize_with(),
            FieldAccess {
                raw: raw.clone(),
                key_raw,
            },
            legacy_nested,
        );
        let condition = serialization_condition(
            source_context,
            parsed.serde_attributes(),
            parsed.attributes().mode(),
            raw,
            predicate,
        );
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
/// * `source_context` - Source type identity and generic context used to
///   resolve source paths and helpers.
/// * `recursive_target` - Source type name used to recognize self-recursive
///   field projections.
/// * `variant_name` - Variant owning the fields.
/// * `variant_index` - Zero-based declaration index of the owning variant.
/// * `fields` - Parsed positional fields in declaration order.
/// * `runtime` - Resolved path to the runtime crate.
/// * `legacy_nested` - Whether nested fields use the source serialization
///   bridge rather than borrowed view projections, affecting field access and
///   nested carrier selection.
///
/// # Returns
///
/// The match pattern, carrier setup statements, inclusion conditions, and
/// carrier identifiers.
///
/// # Panics
///
/// Panics if validation admitted keyed mode on a tuple field or map-level
/// mode without a key sensitivity.
#[must_use]
pub(super) fn enum_unnamed_parts(
    source_context: &SourceTypeContext<'_>,
    recursive_target: &str,
    variant_name: &Ident,
    variant_index: u32,
    fields: &[UnnamedField<'_>],
    runtime: &Path,
    legacy_nested: bool,
) -> (TokenStream, Vec<TokenStream>, Vec<TokenStream>, Vec<Ident>) {
    let type_name = source_context.ident;
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
        if field_is_skipped(parsed.serde_attributes()) {
            quote!(_)
        } else {
            quote!(#binding)
        }
    });
    let mut setups = Vec::new();
    let mut conditions = Vec::new();
    let mut carriers = Vec::new();
    for (position, (parsed, binding)) in fields.iter().zip(&bindings).enumerate() {
        if field_is_skipped(parsed.serde_attributes()) {
            continue;
        }
        let field = parsed.field();
        let field_name = parsed.index().index.to_string();
        let context = field_context(Some(variant_name), Some(variant_index), &field_name);
        let carrier = format_ident!("__qubit_redact_serialized_{position}");
        let raw_member = quote_spanned!(field.span()=> #binding);
        let predicate = projected_predicate(raw_member.clone(), parsed.serde_attributes(), legacy_nested);
        let raw = projected_raw(raw_member, parsed.serde_attributes(), legacy_nested);
        let value = serialized_carrier(
            type_name,
            recursive_target,
            field,
            &context,
            parsed.attributes().mode(),
            runtime,
            parsed.serde_attributes().serialize_with(),
            FieldAccess {
                raw: raw.clone(),
                key_raw: None,
            },
            legacy_nested,
        );
        let condition = serialization_condition(
            source_context,
            parsed.serde_attributes(),
            parsed.attributes().mode(),
            raw,
            predicate,
        );
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
