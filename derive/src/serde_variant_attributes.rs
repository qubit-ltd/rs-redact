// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Whitelisted Serde variant attributes for redacted serialization.

use syn::{
    LitStr,
    Meta,
    Token,
    Variant,
};

use crate::serde_rename_rule::SerdeRenameRule;

/// Validated variant name, field rename rule, and skip state.
#[must_use]
pub(crate) struct SerdeVariantAttributes {
    /// Explicit serialized variant name.
    rename: Option<String>,
    /// Variant-local named-field rename rule.
    rename_all: Option<SerdeRenameRule>,
    /// Whether serialization of this variant is forbidden.
    skip: bool,
}

impl SerdeVariantAttributes {
    /// Parses the safe serialization-only Serde variant allowlist.
    ///
    /// # Parameters
    ///
    /// * `variant` - Enum variant carrying helper attributes.
    /// * `type_name` - Owning enum used in diagnostics.
    /// * `enabled` - Whether `#[redact(serde)]` requested parsing.
    ///
    /// # Returns
    ///
    /// Validated rename and skip controls.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, repeated, or unsupported controls.
    ///
    /// # Panics
    ///
    /// Panics only if `syn` supplies a nested metadata path without any
    /// segments, which violates the `ParseNestedMeta` path invariant.
    pub(crate) fn parse(
        variant: &Variant,
        type_name: &syn::Ident,
        enabled: bool,
    ) -> syn::Result<Self> {
        let mut parsed = Self {
            rename: None,
            rename_all: None,
            skip: false,
        };
        if !enabled {
            return Ok(parsed);
        }
        for attribute in &variant.attrs {
            if !attribute.path().is_ident("serde") {
                continue;
            }
            let Meta::List(_) = &attribute.meta else {
                return Err(syn::Error::new_spanned(
                    attribute,
                    format!(
                        "Redact serde for `{type_name}` variant `{}` expects `#[serde(...)]`",
                        variant.ident,
                    ),
                ));
            };
            attribute.parse_nested_meta(|meta| {
                if meta.path.is_ident("rename") {
                    if parsed.rename.is_some() {
                        return Err(meta.error(format!(
                            "Redact serde for `{type_name}` variant `{}` repeats `rename`",
                            variant.ident,
                        )));
                    }
                    let literal: LitStr = meta.value()?.parse()?;
                    parsed.rename = Some(literal.value());
                } else if meta.path.is_ident("rename_all") {
                    if parsed.rename_all.is_some() {
                        return Err(meta.error(format!(
                            "Redact serde for `{type_name}` variant `{}` repeats `rename_all`",
                            variant.ident,
                        )));
                    }
                    let literal: LitStr = meta.value()?.parse()?;
                    parsed.rename_all = Some(SerdeRenameRule::parse(&literal)?);
                } else if meta.path.is_ident("skip")
                    || meta.path.is_ident("skip_serializing")
                {
                    if meta.input.peek(Token![=])
                        || meta.input.peek(syn::token::Paren)
                    {
                        return Err(meta.error(format!(
                            "Redact serde for `{type_name}` variant `{}` requires a bare skip attribute",
                            variant.ident,
                        )));
                    }
                    if parsed.skip {
                        return Err(meta.error(format!(
                            "Redact serde for `{type_name}` variant `{}` repeats a skip attribute",
                            variant.ident,
                        )));
                    }
                    parsed.skip = true;
                } else {
                    let key = meta
                        .path
                        .segments
                        .last()
                        .expect("syn nested meta paths always contain a segment")
                        .ident
                        .to_string();
                    return Err(meta.error(format!(
                        "Redact serde for `{type_name}` variant `{}` does not support `{key}` because it can change value paths or bypass redaction; use only `rename`, `rename_all`, `skip`, or `skip_serializing`",
                        variant.ident,
                    )));
                }
                Ok(())
            })?;
        }
        Ok(parsed)
    }

    /// Selects the serialized variant name.
    ///
    /// # Parameters
    ///
    /// * `default_name` - Name produced by the container rule.
    ///
    /// # Returns
    ///
    /// The explicit rename when present, otherwise `default_name`.
    #[inline(always)]
    pub(crate) fn rename_variant(&self, default_name: String) -> String {
        self.rename.clone().unwrap_or(default_name)
    }

    /// Applies the variant-local field rule before a container fallback.
    ///
    /// # Parameters
    ///
    /// * `field_name` - Rust field identifier without a raw prefix.
    /// * `container_name` - Name produced by `rename_all_fields`.
    ///
    /// # Returns
    ///
    /// The serialized field name.
    #[inline]
    pub(crate) fn rename_field(
        &self,
        field_name: &str,
        container_name: String,
    ) -> String {
        self.rename_all
            .as_ref()
            .map_or(container_name, |rule| rule.apply_to_field(field_name))
    }

    /// Returns whether selecting this variant must fail serialization.
    ///
    /// # Returns
    ///
    /// `true` for `skip` or `skip_serializing`.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn skip(&self) -> bool {
        self.skip
    }
}
