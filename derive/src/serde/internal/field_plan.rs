// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0 (the "License");
// =============================================================================
//! Shared macro-time preparation for serialized fields.

use proc_macro2::TokenStream;
use quote::format_ident;
use quote::quote;
use quote::quote_spanned;
use syn::spanned::Spanned;

use crate::attributes::SerdeAttributes;
use crate::model::FieldMode;
use crate::serde::field::conditional_skip_event_allowed;
use crate::serde::field::field_is_skipped;
use crate::serde::field::projected_predicate;
use crate::serde::field::projected_raw;
use crate::serde::field::serialization_condition;
use crate::serde::field::serialized_carrier;
use crate::serde::field_access::FieldAccess;
use crate::serde::source_function_path::SourceTypeContext;

/// Prepares the carrier setup and event metadata for one field.
///
/// # Parameters
///
/// - `source_context`: Source type and projection context.
/// - `recursive_target`: Type name used for recursive projection.
/// - `field`: Source field metadata.
/// - `context`: Field context passed to generated projection code.
/// - `mode`: Redaction mode for the field.
/// - `attributes`: Parsed Serde field attributes.
/// - `runtime`: Resolved runtime crate path.
/// - `access`: Raw field and optional key access expressions.
/// - `legacy_nested`: Whether legacy nested projection is active.
/// - `position`: Field position used to name generated locals.
/// - `serialized_name`: Serde-visible name for named fields.
/// - `condition_override`: Optional representation-specific inclusion condition.
///
/// # Returns
///
/// A prepared plan for included fields, or `None` for skipped fields.
#[allow(clippy::too_many_arguments)]
pub(in crate::serde) fn prepare_field_plan(
    source_context: &SourceTypeContext<'_>,
    recursive_target: &str,
    field: &syn::Field,
    context: &str,
    mode: &FieldMode,
    attributes: &SerdeAttributes,
    runtime: &syn::Path,
    access: FieldAccess,
    legacy_nested: bool,
    position: usize,
    serialized_name: Option<String>,
    condition_override: Option<TokenStream>,
) -> Option<super::serialized_field_plan::SerializedFieldPlan> {
    if field_is_skipped(attributes) {
        return None;
    }
    let carrier = format_ident!("__qubit_redact_serialized_{position}");
    let predicate = projected_predicate(access.raw.clone(), attributes, legacy_nested);
    let raw = projected_raw(access.raw, attributes, legacy_nested);
    let value = serialized_carrier(
        source_context.ident,
        recursive_target,
        field,
        context,
        mode,
        runtime,
        attributes.serialize_with(),
        FieldAccess {
            raw: raw.clone(),
            key_raw: access.key_raw,
        },
        legacy_nested,
    );
    let condition =
        condition_override.unwrap_or_else(|| serialization_condition(source_context, attributes, mode, raw, predicate));
    let skip_event = conditional_skip_event_allowed(attributes, mode);
    let setup = quote_spanned! {field.span()=>
        let #carrier = if #condition {
            ::core::option::Option::Some(#value)
        } else {
            ::core::option::Option::None
        };
    };
    let included = quote!(#carrier.is_some());
    Some(super::serialized_field_plan::SerializedFieldPlan {
        setup,
        carrier,
        included,
        serialized_name,
        skip_event,
    })
}
