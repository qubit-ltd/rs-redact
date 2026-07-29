// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Whitelisted serde field attributes for redacted serialization.

use syn::{Field, Ident, LitStr, Meta, Path};

/// Serde controls that preserve the generated redacted structure.
#[must_use]
pub(crate) struct SerdeAttributes {
    /// Explicit serialized field name.
    rename: Option<String>,
    /// Whether the field is always omitted.
    skip: bool,
    /// Predicate deciding whether the raw field is omitted.
    skip_serializing_if: Option<Path>,
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
    /// Parsed rename and skip controls, or empty controls when disabled.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, repeated, or unsupported serde controls.
    ///
    /// # Panics
    ///
    /// Panics only if `syn` supplies a nested metadata path without any
    /// segments, which violates the `ParseNestedMeta` path invariant.
    pub(crate) fn parse(
        field: &Field,
        type_name: &Ident,
        field_name: &str,
        enabled: bool,
    ) -> syn::Result<Self> {
        let mut parsed = Self {
            rename: None,
            skip: false,
            skip_serializing_if: None,
        };
        if !enabled {
            return Ok(parsed);
        }
        for attribute in &field.attrs {
            if !attribute.path().is_ident("serde") {
                continue;
            }
            let Meta::List(_) = &attribute.meta else {
                return Err(syn::Error::new_spanned(
                    attribute,
                    format!(
                        "Redact serde for `{type_name}` field `{field_name}` expects \
                         `#[serde(...)]`",
                    ),
                ));
            };
            attribute.parse_nested_meta(|meta| {
                if meta.path.is_ident("rename") {
                    if parsed.rename.is_some() {
                        return Err(meta.error(format!(
                            "Redact serde for `{type_name}` field `{field_name}` repeats `rename`",
                        )));
                    }
                    let literal: LitStr = meta.value()?.parse()?;
                    parsed.rename = Some(literal.value());
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
                         `rename`, `skip`, `skip_serializing`, or `skip_serializing_if`",
                    )));
                }
                Ok(())
            })?;
        }
        Ok(parsed)
    }

    /// Returns the explicit serialized name, when present.
    ///
    /// # Returns
    ///
    /// `Some(name)` for an explicit field rename, or `None` to use the
    /// applicable container or variant rename rule.
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
    #[inline(always)]
    pub(crate) const fn skip_serializing_if(&self) -> Option<&Path> {
        self.skip_serializing_if.as_ref()
    }
}
