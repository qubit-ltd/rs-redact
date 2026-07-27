// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared field-level serialization expressions and naming context.

use proc_macro2::TokenStream;
use quote::{quote, quote_spanned};
use syn::{Path, spanned::Spanned};

use crate::{field_assertion, field_mode::FieldMode};

/// Returns whether a field is omitted by redaction or Serde controls.
pub(super) fn field_is_skipped(
    mode: &FieldMode,
    serde_attributes: &crate::serde_attributes::SerdeAttributes,
) -> bool {
    matches!(mode, FieldMode::Skip) || serde_attributes.skip()
}

/// Generates the condition deciding whether one field is serialized.
pub(super) fn serialization_condition(
    serde_attributes: &crate::serde_attributes::SerdeAttributes,
    raw: TokenStream,
) -> TokenStream {
    serde_attributes
        .skip_serializing_if()
        .map_or_else(|| quote!(true), |predicate| quote!(!(#predicate)(#raw)))
}

/// Generates one serializable raw or redacted carrier expression.
pub(super) fn serialized_carrier(
    type_name: &syn::Ident,
    field: &syn::Field,
    context: &str,
    mode: &FieldMode,
    runtime: &Path,
    raw: TokenStream,
) -> TokenStream {
    match mode {
        FieldMode::Plain => raw,
        FieldMode::Level(sensitivity) => {
            let level = sensitivity.runtime_tokens(runtime);
            quote_spanned! {field.span()=>
                #runtime::RedactValue::redact_value(
                    #raw,
                    #level,
                    policy.masking(),
                )
            }
        }
        FieldMode::Nested => {
            let helper = field_assertion::helper_name(type_name, field, context, "RedactSerialize");
            quote_spanned!(field.span()=> #helper(#raw, policy))
        }
        FieldMode::Map => {
            let helper =
                field_assertion::helper_name(type_name, field, context, "RedactMapSerialize");
            quote_spanned!(field.span()=> #helper(#raw, policy))
        }
        FieldMode::Skip => TokenStream::new(),
    }
}

/// Returns an identifier without Rust's raw prefix.
pub(super) fn raw_identifier(identifier: &syn::Ident) -> String {
    identifier
        .to_string()
        .strip_prefix("r#")
        .map_or_else(|| identifier.to_string(), str::to_owned)
}

/// Creates a helper-name context unique within an enum.
pub(super) fn field_context(variant_name: Option<&syn::Ident>, field_name: &str) -> String {
    variant_name.map_or_else(
        || field_name.to_owned(),
        |variant| format!("{variant}_{field_name}"),
    )
}
