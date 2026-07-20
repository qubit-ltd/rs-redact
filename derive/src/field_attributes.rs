// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Strict field-level `redact` attribute parsing.

use quote::ToTokens;
use syn::{
    Field,
    Ident,
    LitStr,
    Meta,
    Token,
};

use crate::{
    field_mode::FieldMode,
    sensitivity::Sensitivity,
};

/// Parsed attributes selecting exactly one mode for a named field.
pub(crate) struct FieldAttributes {
    /// Unique mode selected by the field's attributes.
    mode: FieldMode,
}

impl FieldAttributes {
    /// Parses the strict field attribute grammar.
    ///
    /// # Parameters
    ///
    /// * `field` - Named field whose attributes are parsed.
    /// * `type_name` - Derived type used in targeted diagnostics.
    /// * `field_name` - Field identifier used in targeted diagnostics.
    ///
    /// # Returns
    ///
    /// A unique plain, level, skip, nested, or map mode.
    ///
    /// # Errors
    ///
    /// Returns an error at the offending attribute for empty attributes,
    /// duplicate or conflicting modes, unknown keys, invalid arguments, or an
    /// unsupported sensitivity spelling.
    pub(crate) fn parse(
        field: &Field,
        type_name: &Ident,
        field_name: &Ident,
    ) -> syn::Result<Self> {
        let mut selected = None;
        for attribute in &field.attrs {
            if !attribute.path().is_ident("redact") {
                continue;
            }
            let Meta::List(list) = &attribute.meta else {
                return Err(field_error(
                    attribute,
                    type_name,
                    field_name,
                    "expected `#[redact(level = \"...\")]`, `#[redact(skip)]`, \
                     `#[redact(nested)]`, or `#[redact(map)]`",
                ));
            };
            if list.tokens.is_empty() {
                return Err(field_error(
                    attribute,
                    type_name,
                    field_name,
                    "empty `#[redact()]` is not allowed; choose `level = \"...\"`, `skip`, \
                     `nested`, or `map`",
                ));
            }
            attribute.parse_nested_meta(|meta| {
                let mode = if meta.path.is_ident("level") {
                    if !meta.input.peek(Token![=]) {
                        return Err(meta.error(format!(
                            "Redact derive for `{type_name}` field `{field_name}` requires \
                             `level = \"low|medium|high|secret\"`",
                        )));
                    }
                    let literal: LitStr = meta.value()?.parse()?;
                    FieldMode::Level(Sensitivity::parse(&literal, type_name, field_name)?)
                } else if meta.path.is_ident("skip") {
                    if !meta.input.is_empty() {
                        return Err(meta.error(format!(
                            "Redact derive for `{type_name}` field `{field_name}` requires bare \
                             `skip` without arguments",
                        )));
                    }
                    FieldMode::Skip
                } else if meta.path.is_ident("nested") {
                    if !meta.input.is_empty() {
                        return Err(meta.error(format!(
                            "Redact derive for `{type_name}` field `{field_name}` requires bare \
                             `nested` without arguments",
                        )));
                    }
                    FieldMode::Nested
                } else if meta.path.is_ident("map") {
                    if !meta.input.is_empty() {
                        return Err(meta.error(format!(
                            "Redact derive for `{type_name}` field `{field_name}` requires bare \
                             `map` without arguments; map values are classified by runtime key \
                             and the complete policy",
                        )));
                    }
                    FieldMode::Map
                } else {
                    let key = meta.path.to_token_stream().to_string();
                    return Err(meta.error(format!(
                        "Redact derive for `{type_name}` field `{field_name}` has unknown \
                         attribute `{key}`; use `level = \"...\"`, `skip`, `nested`, or `map`",
                    )));
                };
                if selected.is_some() {
                    return Err(meta.error(format!(
                        "Redact derive for `{type_name}` field `{field_name}` has conflicting or \
                         repeated modes; choose exactly one of `level = \"...\"`, `skip`, \
                         `nested`, or `map`; map values are classified by runtime key and the \
                         complete policy",
                    )));
                }
                selected = Some(mode);
                Ok(())
            })?;
        }
        Ok(Self {
            mode: selected.unwrap_or(FieldMode::Plain),
        })
    }

    /// Returns the unique formatting mode selected for the field.
    ///
    /// # Returns
    ///
    /// The parsed plain, explicit-level, skip, nested, or map mode.
    #[inline(always)]
    pub(crate) const fn mode(&self) -> &FieldMode {
        &self.mode
    }
}

/// Creates a field-scoped syntax error with consistent type context.
///
/// # Parameters
///
/// * `tokens` - Syntax node identifying the diagnostic span.
/// * `type_name` - Derived type containing the field.
/// * `field_name` - Field whose attribute is invalid.
/// * `message` - Actionable error detail and correction direction.
///
/// # Returns
///
/// A syntax error located at `tokens`.
fn field_error(
    tokens: impl ToTokens,
    type_name: &Ident,
    field_name: &Ident,
    message: &str,
) -> syn::Error {
    syn::Error::new_spanned(
        tokens,
        format!(
            "Redact derive for `{type_name}` field `{field_name}`: {message}"
        ),
    )
}
