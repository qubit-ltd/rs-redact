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
#[must_use]
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
    /// A unique plain, level, skip, nested, map, or JSON mode.
    ///
    /// # Errors
    ///
    /// Returns an error at the offending attribute for empty attributes,
    /// duplicate or conflicting modes, unknown keys, invalid arguments, or an
    /// unsupported sensitivity spelling.
    pub(crate) fn parse(
        field: &Field,
        type_name: &Ident,
        field_name: &str,
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
                let mode = parse_mode(&meta, type_name, field_name)?;
                select_mode(&meta, type_name, field_name, &mut selected, mode)
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
    /// The parsed plain, explicit-level, skip, nested, map, or JSON mode.
    #[inline(always)]
    pub(crate) const fn mode(&self) -> &FieldMode {
        &self.mode
    }
}

/// Parses one nested field mode.
///
/// # Parameters
///
/// * `meta` - Nested attribute item to parse.
/// * `type_name` - Derived type containing the field.
/// * `field_name` - Field whose mode is being parsed.
///
/// # Returns
///
/// The mode represented by the nested attribute item.
///
/// # Errors
///
/// Returns an error for unknown modes, missing level values, invalid
/// sensitivity values, or arguments supplied to a bare mode.
fn parse_mode(
    meta: &syn::meta::ParseNestedMeta<'_>,
    type_name: &Ident,
    field_name: &str,
) -> syn::Result<FieldMode> {
    if meta.path.is_ident("level") {
        if !meta.input.peek(Token![=]) {
            return Err(meta.error(format!(
                "Redact derive for `{type_name}` field `{field_name}` requires \
                 `level = \"low|medium|high|secret\"`",
            )));
        }
        let literal: LitStr = meta.value()?.parse()?;
        Ok(FieldMode::Level(Sensitivity::parse(
            &literal, type_name, field_name,
        )?))
    } else if meta.path.is_ident("skip") {
        require_bare(
            meta,
            type_name,
            field_name,
            "bare `skip` without arguments",
        )?;
        Ok(FieldMode::Skip)
    } else if meta.path.is_ident("nested") {
        require_bare(
            meta,
            type_name,
            field_name,
            "bare `nested` without arguments",
        )?;
        Ok(FieldMode::Nested)
    } else if meta.path.is_ident("map") {
        require_bare(
            meta,
            type_name,
            field_name,
            "bare `map` without arguments; map values are classified by runtime key \
             and the complete policy",
        )?;
        Ok(FieldMode::Map)
    } else if meta.path.is_ident("json") {
        require_bare(
            meta,
            type_name,
            field_name,
            "bare `json` without arguments; JSON text is parsed and redacted by field key",
        )?;
        Ok(FieldMode::Json)
    } else {
        let key = meta.path.to_token_stream().to_string();
        Err(meta.error(format!(
            "Redact derive for `{type_name}` field `{field_name}` has unknown \
             attribute `{key}`; use `level = \"...\"`, `skip`, `nested`, `map`, or `json`",
        )))
    }
}

/// Requires a nested field mode to have no value or argument list.
///
/// # Parameters
///
/// * `meta` - Nested attribute item to validate.
/// * `type_name` - Derived type containing the field.
/// * `field_name` - Field whose mode is being parsed.
/// * `requirement` - Exact grammar requirement used in diagnostics.
///
/// # Errors
///
/// Returns an error when the nested item has a value or parenthesized
/// arguments.
#[inline]
fn require_bare(
    meta: &syn::meta::ParseNestedMeta<'_>,
    type_name: &Ident,
    field_name: &str,
    requirement: &str,
) -> syn::Result<()> {
    if meta.input.peek(Token![=]) || meta.input.peek(syn::token::Paren) {
        Err(meta.error(format!(
            "Redact derive for `{type_name}` field `{field_name}` requires {requirement}",
        )))
    } else {
        Ok(())
    }
}

/// Selects one field mode and rejects a repeated or conflicting choice.
///
/// # Parameters
///
/// * `meta` - Nested item used as the conflict diagnostic span.
/// * `type_name` - Derived type containing the field.
/// * `field_name` - Field whose mode is being selected.
/// * `selected` - Previously selected mode, if any.
/// * `mode` - Newly parsed mode.
///
/// # Errors
///
/// Returns an error when another mode was already selected.
#[inline]
fn select_mode(
    meta: &syn::meta::ParseNestedMeta<'_>,
    type_name: &Ident,
    field_name: &str,
    selected: &mut Option<FieldMode>,
    mode: FieldMode,
) -> syn::Result<()> {
    if selected.is_some() {
        return Err(meta.error(format!(
            "Redact derive for `{type_name}` field `{field_name}` has conflicting or \
             repeated modes; choose exactly one of `level = \"...\"`, `skip`, \
             `nested`, `map`, or `json`; map values are classified by runtime key and the \
             complete policy",
        )));
    }
    *selected = Some(mode);
    Ok(())
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
#[inline]
fn field_error(
    tokens: impl ToTokens,
    type_name: &Ident,
    field_name: &str,
    message: &str,
) -> syn::Error {
    syn::Error::new_spanned(
        tokens,
        format!(
            "Redact derive for `{type_name}` field `{field_name}`: {message}"
        ),
    )
}
