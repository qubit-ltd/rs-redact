// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Strict parsing boundary for container-level `redact` attributes.

use syn::{
    DeriveInput,
    LitStr,
    Meta,
};

use crate::serde_rename_rule::SerdeRenameRule;

/// Parsed container controls for optional redacted serde integration.
pub(crate) struct ContainerAttributes {
    /// Whether redacted serde integration was requested.
    serde: bool,
    /// Container-wide serialized field rename rule.
    rename_all: Option<SerdeRenameRule>,
}

impl ContainerAttributes {
    /// Parses and validates container-level attributes on `input`.
    ///
    /// # Parameters
    ///
    /// * `input` - Complete derive input whose container attributes are read.
    ///
    /// # Returns
    ///
    /// Validated serde enablement and optional rename rule.
    ///
    /// # Errors
    ///
    /// Returns a targeted error for malformed, repeated, or unsupported
    /// container controls.
    pub(crate) fn parse(input: &DeriveInput) -> syn::Result<Self> {
        let mut serde = false;
        for attribute in &input.attrs {
            if !attribute.path().is_ident("redact") {
                continue;
            }
            let Meta::List(list) = &attribute.meta else {
                return Err(syn::Error::new_spanned(
                    attribute,
                    format!(
                        "Redact derive for `{}` expects `#[redact(serde)]` on the container",
                        input.ident,
                    ),
                ));
            };
            if list.tokens.is_empty() {
                return Err(syn::Error::new_spanned(
                    attribute,
                    format!(
                        "Redact derive for `{}` does not allow an empty container attribute; use \
                         `#[redact(serde)]`",
                        input.ident,
                    ),
                ));
            }
            attribute.parse_nested_meta(|meta| {
                if !meta.path.is_ident("serde") {
                    return Err(meta.error(format!(
                        "Redact derive for `{}` has unknown container attribute; use \
                         `#[redact(serde)]`",
                        input.ident,
                    )));
                }
                if !meta.input.is_empty() {
                    return Err(meta.error(format!(
                        "Redact derive for `{}` requires bare `serde` without arguments",
                        input.ident,
                    )));
                }
                if serde {
                    return Err(meta.error(format!(
                        "Redact derive for `{}` repeats the `serde` container option",
                        input.ident,
                    )));
                }
                serde = true;
                Ok(())
            })?;
        }
        let mut rename_all = None;
        if serde {
            for attribute in &input.attrs {
                if !attribute.path().is_ident("serde") {
                    continue;
                }
                let Meta::List(_) = &attribute.meta else {
                    return Err(syn::Error::new_spanned(
                        attribute,
                        format!(
                            "Redact serde for `{}` expects `#[serde(rename_all = \"...\")]`",
                            input.ident,
                        ),
                    ));
                };
                attribute.parse_nested_meta(|meta| {
                    if !meta.path.is_ident("rename_all") {
                        return Err(meta.error(format!(
                            "Redact serde for `{}` supports only container `rename_all`; remove \
                             structure-changing serde options",
                            input.ident,
                        )));
                    }
                    if rename_all.is_some() {
                        return Err(meta.error(format!(
                            "Redact serde for `{}` repeats `rename_all`",
                            input.ident,
                        )));
                    }
                    let literal: LitStr = meta.value()?.parse()?;
                    rename_all = Some(SerdeRenameRule::parse(&literal)?);
                    Ok(())
                })?;
            }
        }
        Ok(Self { serde, rename_all })
    }

    /// Returns whether this struct requested redacted serialization.
    #[inline(always)]
    pub(crate) const fn serde_enabled(&self) -> bool {
        self.serde
    }

    /// Applies the optional container rename rule to `field_name`.
    pub(crate) fn rename_field(&self, field_name: &str) -> String {
        self.rename_all.as_ref().map_or_else(
            || field_name.to_owned(),
            |rule| rule.apply(field_name),
        )
    }
}
