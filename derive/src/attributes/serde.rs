// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Whitelisted serde field attributes for redacted serialization.
// qubit-style: allow type-file-name

use syn::Error;
use syn::Field;
use syn::Ident;
use syn::LitStr;
use syn::Meta;
use syn::Path;
use syn::Result;
use syn::Token;
use syn::meta::ParseNestedMeta;
use syn::parse_quote;
use syn::token::Paren;

use super::parse_serialize_name;
use crate::model::FieldMode;
/// Serde controls that preserve the generated redacted structure.
#[must_use]
pub(crate) struct SerdeAttributes {
    /// Explicit serialized field name.
    rename: Option<String>,
    /// Whether any serialization or deserialization rename was declared.
    rename_seen: bool,
    /// Whether the field is always omitted.
    skip: bool,
    /// Predicate deciding whether the raw field is omitted.
    skip_serializing_if: Option<Path>,
    /// Function used to serialize an explicitly unmarked field.
    serialize_with: Option<Path>,
}

impl SerdeAttributes {
    /// Parses supported serde field attributes when integration is enabled.
    ///
    /// # Parameters
    ///
    /// * `field` - Field whose helper attributes are read.
    /// * `type_name` - Derived type used in diagnostics.
    /// * `field_name` - Field identifier used in diagnostics.
    /// * `enabled` - Whether the container declared `#[redact(serde)]`.
    ///
    /// # Returns
    ///
    /// Parsed rename, skip, and serialization-adapter controls, or empty
    /// controls when disabled.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, repeated, or unsupported serde controls.
    ///
    /// # Panics
    ///
    /// Panics only if `syn` supplies a nested metadata path without any
    /// segments, which violates the `ParseNestedMeta` path invariant.
    pub(crate) fn parse(field: &Field, type_name: &Ident, field_name: &str, enabled: bool) -> Result<Self> {
        let mut parsed = Self {
            rename: None,
            rename_seen: false,
            skip: false,
            skip_serializing_if: None,
            serialize_with: None,
        };
        if !enabled {
            return Ok(parsed);
        }
        for attribute in &field.attrs {
            if !attribute.path().is_ident("serde") {
                continue;
            }
            let Meta::List(_) = &attribute.meta else {
                return Err(Error::new_spanned(
                    attribute,
                    format!(
                        "Redact serde for `{type_name}` field `{field_name}` expects \
                         `#[serde(...)]`",
                    ),
                ));
            };
            attribute.parse_nested_meta(|meta| {
                if meta.path.is_ident("rename") {
                    if parsed.rename_seen {
                        return Err(meta.error(format!(
                            "Redact serde for `{type_name}` field `{field_name}` repeats `rename`",
                        )));
                    }
                    parsed.rename = parse_serialize_name(&meta, "rename")?.map(|literal| literal.value());
                    parsed.rename_seen = true;
                } else if meta.path.is_ident("skip") || meta.path.is_ident("skip_serializing") {
                    if !meta.input.is_empty() {
                        return Err(meta.error(format!(
                            "Redact serde for `{type_name}` field `{field_name}` requires a bare \
                             skip attribute",
                        )));
                    }
                    if parsed.skip {
                        return Err(meta.error(format!(
                            "Redact serde for `{type_name}` field `{field_name}` repeats a skip \
                             attribute",
                        )));
                    }
                    parsed.skip = true;
                } else if meta.path.is_ident("skip_serializing_if") {
                    if parsed.skip_serializing_if.is_some() {
                        return Err(meta.error(format!(
                            "Redact serde for `{type_name}` field `{field_name}` repeats \
                             `skip_serializing_if`",
                        )));
                    }
                    let literal: LitStr = meta.value()?.parse()?;
                    parsed.skip_serializing_if = Some(literal.parse()?);
                } else if meta.path.is_ident("with") || meta.path.is_ident("serialize_with") {
                    if parsed.serialize_with.is_some() {
                        return Err(meta.error(format!(
                            "Redact serde for `{type_name}` field `{field_name}` repeats a serialization adapter",
                        )));
                    }
                    if !meta.input.peek(Token![=]) {
                        return Err(meta.error("Redact serde expects a string path for a serialization adapter"));
                    }
                    let literal: LitStr = meta.value()?.parse()?;
                    let path: Path = literal.parse()?;
                    parsed.serialize_with = if meta.path.is_ident("with") {
                        Some(parse_quote!(#path::serialize))
                    } else {
                        Some(path)
                    };
                } else if is_deserialize_only_control(&meta) {
                    parse_deserialize_only_control(&meta)?;
                } else {
                    let key = meta
                        .path
                        .segments
                        .last()
                        .expect("syn nested meta paths always contain a segment")
                        .ident
                        .to_string();
                    return Err(meta.error(format!(
                        "Redact serde for `{type_name}` field `{field_name}` does not support \
                         `{key}` because it can change structure or bypass redaction; use only \
                         `rename`, `skip`, `skip_serializing`, `skip_serializing_if`, \
                         `with`, `serialize_with`, or \
                         deserialization-only controls such as `default`, `alias`, and \
                         `skip_deserializing`",
                    )));
                }
                Ok(())
            })?;
        }
        Ok(parsed)
    }

    /// Validates serialization adapters against the selected redaction mode.
    ///
    /// # Parameters
    ///
    /// * `field` - Field carrying the relevant Serde attributes.
    /// * `type_name` - Derived type used in the diagnostic.
    /// * `field_name` - Field identifier used in the diagnostic.
    /// * `mode` - Redaction mode selected for the field.
    ///
    /// # Errors
    ///
    /// `skip_serializing_if` is valid for every mode and always observes the
    /// raw field before any carrier is built. Serialization adapters remain
    /// limited to plain and skipped fields.
    pub(crate) fn validate_redaction_mode(
        &self,
        field: &Field,
        type_name: &Ident,
        field_name: &str,
        mode: &FieldMode,
    ) -> Result<()> {
        if self.serialize_with.is_some() && !matches!(mode, FieldMode::Unmarked | FieldMode::Skip) {
            return Err(Error::new_spanned(
                field,
                format!(
                    "Redact serde for `{type_name}` field `{field_name}` cannot use a serialization adapter with a redaction mode that observes raw field state; use it only with `skip`",
                ),
            ));
        }
        Ok(())
    }

    /// Returns the explicit serialized name, when present.
    ///
    /// # Returns
    ///
    /// `Some(name)` for an explicit field rename, or `None` to use the
    /// applicable container or variant rename rule.
    #[must_use]
    #[inline(always)]
    pub(crate) fn rename(&self) -> Option<&str> {
        self.rename.as_deref()
    }

    /// Returns whether the field is always omitted by serde.
    ///
    /// # Returns
    ///
    /// `true` when either `skip` or `skip_serializing` was present.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn skip(&self) -> bool {
        self.skip
    }

    /// Returns the optional raw-value skip predicate.
    ///
    /// # Returns
    ///
    /// `Some(path)` for `skip_serializing_if`, or `None` when serialization is
    /// unconditional.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn skip_serializing_if(&self) -> Option<&Path> {
        self.skip_serializing_if.as_ref()
    }

    /// Returns the optional unmarked-field serialization adapter.
    ///
    /// # Returns
    ///
    /// `Some(path)` for `with` or `serialize_with`, or `None` when the field
    /// uses ordinary Serde serialization.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn serialize_with(&self) -> Option<&Path> {
        self.serialize_with.as_ref()
    }
}

/// Returns whether one field control affects deserialization only.
///
/// # Parameters
///
/// * `meta` - Nested Serde metadata item to classify.
///
/// # Returns
///
/// `true` for a supported deserialization-only control.
fn is_deserialize_only_control(meta: &ParseNestedMeta<'_>) -> bool {
    meta.path.is_ident("default")
        || meta.path.is_ident("alias")
        || meta.path.is_ident("skip_deserializing")
        || meta.path.is_ident("deserialize_with")
        || meta.path.is_ident("deserialize_in_place")
        || meta.path.is_ident("borrow")
}

/// Consumes one supported deserialization-only field control.
///
/// # Parameters
///
/// * `meta` - Nested Serde metadata item to validate and consume.
///
/// # Errors
///
/// Returns an error when the control uses the wrong shape or a non-string
/// value.
fn parse_deserialize_only_control(meta: &ParseNestedMeta<'_>) -> Result<()> {
    if meta.path.is_ident("skip_deserializing") || meta.path.is_ident("deserialize_in_place") {
        if meta.input.peek(Token![=]) || meta.input.peek(Paren) {
            return Err(meta.error("Redact serde expects a bare deserialization-only field control"));
        }
        return Ok(());
    }
    if meta.path.is_ident("default") && !meta.input.peek(Token![=]) {
        return Ok(());
    }
    if meta.path.is_ident("borrow") && !meta.input.peek(Token![=]) {
        return Ok(());
    }
    if !meta.input.peek(Token![=]) {
        return Err(meta.error("Redact serde expects a string value for this deserialization-only field control"));
    }
    let _: LitStr = meta.value()?.parse()?;
    Ok(())
}
