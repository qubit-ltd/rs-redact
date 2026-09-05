// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared field-level serialization expressions and naming context.

use proc_macro2::TokenStream;
use quote::format_ident;
use quote::quote;
use quote::quote_spanned;
use syn::Field;
use syn::Ident;
use syn::Path;
use syn::spanned::Spanned;

use crate::attributes::SerdeAttributes;
use crate::model::FieldMode;
use crate::serde::field_access::FieldAccess;

/// Returns whether a field is omitted by redaction or Serde controls.
///
/// # Parameters
///
/// * `mode` - Validated redaction mode.
/// * `serde_attributes` - Validated Serde field controls.
///
/// # Returns
///
/// `true` when either control set omits the field.
#[must_use]
#[inline(always)]
pub(super) fn field_is_skipped(mode: &FieldMode, serde_attributes: &SerdeAttributes) -> bool {
    let _ = mode;
    serde_attributes.skip()
}

/// Generates the condition deciding whether one field is serialized.
///
/// # Parameters
///
/// * `serde_attributes` - Validated Serde field controls.
/// * `raw` - Expression accessing the unredacted field value.
///
/// # Returns
///
/// A predicate expression honoring `skip_serializing_if`, or unconditional
/// `true` when no predicate is configured.
#[inline]
pub(super) fn serialization_condition(
    serde_attributes: &SerdeAttributes,
    mode: &FieldMode,
    raw: TokenStream,
) -> TokenStream {
    let predicate = serde_attributes
        .skip_serializing_if()
        .map_or_else(|| quote!(true), |predicate| quote!(!(#predicate)(#raw)));
    if matches!(mode, FieldMode::Skip) {
        quote!(policy.is_disabled() && #predicate)
    } else {
        predicate
    }
}

/// Generates one serializable raw or redacted carrier expression.
///
/// # Parameters
///
/// * `type_name` - Type receiving the generated implementation.
/// * `field` - Source field supplying type information and diagnostic span.
/// * `context` - Stable field context used in generated helper names.
/// * `mode` - Validated redaction mode.
/// * `runtime` - Resolved path to the runtime crate.
/// * `serialize_with` - Optional adapter used by an unmarked field.
/// * `access` - Expressions accessing the value and optional sibling key.
///
/// # Returns
///
/// The raw value, a redacted carrier, or an empty stream for an omitted field.
pub(super) fn serialized_carrier(
    type_name: &Ident,
    field: &Field,
    context: &str,
    mode: &FieldMode,
    runtime: &Path,
    serialize_with: Option<&Path>,
    access: FieldAccess,
) -> TokenStream {
    match mode {
        FieldMode::Unmarked | FieldMode::Skip => match serialize_with {
            Some(_) => {
                let helper = adapter_helper_name(type_name, field, context);
                let raw = access.raw;
                quote_spanned!(field.span()=> #runtime::domain::internal::BudgetSerialize::new(#helper(#raw)))
            }
            None => {
                let raw = access.raw;
                quote_spanned!(field.span()=> #runtime::domain::internal::BudgetSerialize::new(#raw))
            }
        },
        FieldMode::Level(sensitivity) => {
            let level = sensitivity.runtime_tokens(runtime);
            let raw = access.raw;
            quote_spanned! {field.span()=>
                #runtime::domain::internal::RedactedLevelSerializeRef::new(#raw, policy, #level)
            }
        }
        FieldMode::Nested => {
            let raw = access.raw;
            quote_spanned!(field.span()=>
                #runtime::domain::internal::RedactedSerializeRef::new(#raw, policy)
            )
        }
        FieldMode::Map => {
            let raw = access.raw;
            quote_spanned!(field.span()=>
                #runtime::domain::internal::RedactedMapSerializeRef::new(#raw, policy)
            )
        }
        FieldMode::MapLevels { key, value } => {
            let key = key.as_ref().expect("map key level is required").runtime_tokens(runtime);
            let value = value
                .as_ref()
                .map(|level| {
                    let level = level.runtime_tokens(runtime);
                    quote!(Some(#level))
                })
                .unwrap_or_else(|| quote!(None));
            let raw = access.raw;
            quote_spanned!(field.span()=>
                #runtime::domain::internal::RedactedMapKeySerializeRef::new(#raw, policy, #key, #value)
            )
        }
        FieldMode::KeyedBy(_) => {
            let raw = access.raw;
            let key = access.key_raw.expect("keyed_by is available only for named fields");
            quote_spanned!(field.span()=>
                #runtime::domain::internal::RedactedKeyedSerializeRef::new(#raw, #key, policy)
            )
        }
        FieldMode::Json => {
            let raw = access.raw;
            quote_spanned!(field.span()=>
                #runtime::domain::internal::RedactedJsonSerializeRef::new(#raw, policy)
            )
        }
    }
}

/// Creates the stable helper identifier for one Serde field adapter.
#[inline]
pub(super) fn adapter_helper_name(type_name: &Ident, field: &Field, context: &str) -> Ident {
    let type_fragment = type_name.to_string().replace("r#", "");
    let field_fragment = context.replace("r#", "");
    format_ident!(
        "__qubit_redact_{}_{}_serialize_with",
        type_fragment,
        field_fragment,
        span = field.span(),
    )
}

/// Returns an identifier without Rust's raw prefix.
///
/// # Parameters
///
/// * `identifier` - Rust field or variant identifier.
///
/// # Returns
///
/// The identifier text without a leading `r#`.
#[inline]
pub(super) fn raw_identifier(identifier: &Ident) -> String {
    identifier
        .to_string()
        .strip_prefix("r#")
        .map_or_else(|| identifier.to_string(), str::to_owned)
}

/// Creates a helper-name context unique within an enum.
///
/// # Parameters
///
/// * `variant_name` - Owning variant, or `None` for a struct field.
/// * `variant_index` - Zero-based declaration index of the owning variant.
/// * `field_name` - Field identifier or positional index.
///
/// # Returns
///
/// A field name optionally prefixed by its owning variant.
#[inline]
pub(super) fn field_context(variant_name: Option<&Ident>, variant_index: Option<u32>, field_name: &str) -> String {
    variant_name.map_or_else(
        || field_name.to_owned(),
        |variant| {
            let index = variant_index.expect("enum variant field contexts require a declaration index");
            format!("{variant}_{index}_{field_name}")
        },
    )
}
