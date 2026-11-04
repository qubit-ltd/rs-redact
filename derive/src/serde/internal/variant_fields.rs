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
use crate::serde::field::projected_raw;
use crate::serde::field::raw_identifier;
use crate::serde::field_access::FieldAccess;
use crate::serde::source_function_path::SourceTypeContext;
/// Builds a field plan for each serializable named enum field.
///
/// The pattern and source access expressions retain the enum representation's
/// field binding and keyed-field rules; carrier preparation is delegated to the
/// shared field planner.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub(super) fn enum_named_plan(
    source_context: &SourceTypeContext<'_>,
    recursive_target: &str,
    variant_name: &Ident,
    fields: &[NamedField<'_>],
    runtime: &Path,
    container_attributes: &SerdeContainerAttributes,
    variant: &VariantData<'_>,
    legacy_nested: bool,
) -> (TokenStream, Vec<super::serialized_field_plan::SerializedFieldPlan>) {
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
    let mut plans = Vec::new();
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
        let key_raw = match parsed.attributes().mode() {
            FieldMode::KeyedBy(key) => {
                let key_position = fields
                    .iter()
                    .position(|candidate| candidate.identifier() == key)
                    .expect("keyed_by sibling was validated");
                let key_binding = &bindings[key_position];
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
        if let Some(plan) = super::field_plan::prepare_field_plan(
            source_context,
            recursive_target,
            field,
            &context,
            parsed.attributes().mode(),
            parsed.serde_attributes(),
            runtime,
            FieldAccess {
                raw: raw_member,
                key_raw,
            },
            legacy_nested,
            position,
            Some(serialized_name),
            None,
        ) {
            plans.push(plan);
        }
    }
    (quote!({ #(#patterns),* }), plans)
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
pub(super) fn enum_unnamed_plan(
    source_context: &SourceTypeContext<'_>,
    recursive_target: &str,
    variant_name: &Ident,
    variant_index: u32,
    fields: &[UnnamedField<'_>],
    runtime: &Path,
    legacy_nested: bool,
) -> (TokenStream, Vec<super::serialized_field_plan::SerializedFieldPlan>) {
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
    let mut plans = Vec::new();
    for (position, (parsed, binding)) in fields.iter().zip(&bindings).enumerate() {
        if field_is_skipped(parsed.serde_attributes()) {
            continue;
        }
        let field = parsed.field();
        let field_name = parsed.index().index.to_string();
        let context = field_context(Some(variant_name), Some(variant_index), &field_name);
        let raw_member = quote_spanned!(field.span()=> #binding);
        let condition_override = if fields.len() == 1 {
            if matches!(parsed.attributes().mode(), FieldMode::Skip) {
                Some(quote!(policy.is_disabled()))
            } else {
                Some(quote!(true))
            }
        } else {
            None
        };
        if let Some(plan) = super::field_plan::prepare_field_plan(
            source_context,
            recursive_target,
            field,
            &context,
            parsed.attributes().mode(),
            parsed.serde_attributes(),
            runtime,
            FieldAccess {
                raw: raw_member,
                key_raw: None,
            },
            legacy_nested,
            position,
            None,
            condition_override,
        ) {
            plans.push(plan);
        }
    }
    (quote!((#(#patterns),*)), plans)
}
