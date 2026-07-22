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
    Token,
};

use crate::serde_rename_rule::SerdeRenameRule;

/// Parsed container controls for optional redacted serde integration.
pub(crate) struct ContainerAttributes {
    /// Whether the original type should receive a redacted `Debug` impl.
    debug: bool,
    /// Whether the original type should receive a redacted `Display` impl.
    display: bool,
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
        let mut debug = false;
        let mut display = false;
        let mut serde = false;
        for attribute in &input.attrs {
            if !attribute.path().is_ident("redact") {
                continue;
            }
            let Meta::List(list) = &attribute.meta else {
                return Err(syn::Error::new_spanned(
                    attribute,
                    format!(
                        "Redact derive for `{}` expects `#[redact(debug, display, serde)]` on the container",
                        input.ident,
                    ),
                ));
            };
            if list.tokens.is_empty() {
                return Err(syn::Error::new_spanned(
                    attribute,
                    format!(
                        "Redact derive for `{}` does not allow an empty container attribute; use \
                         `#[redact(debug)]`, `#[redact(display)]`, or `#[redact(serde)]`",
                        input.ident,
                    ),
                ));
            }
            attribute.parse_nested_meta(|meta| {
                let option = if meta.path.is_ident("debug") {
                    &mut debug
                } else if meta.path.is_ident("display") {
                    &mut display
                } else if meta.path.is_ident("serde") {
                    &mut serde
                } else {
                    return Err(meta.error(format!(
                        "Redact derive for `{}` has unknown container attribute; use \
                         `debug`, `display`, or `serde`",
                        input.ident,
                    )));
                };
                if meta.input.peek(Token![=]) || meta.input.peek(syn::token::Paren) {
                    let name = meta
                        .path
                        .segments
                        .last()
                        .map_or("option".to_owned(), |segment| segment.ident.to_string());
                    return Err(meta.error(format!(
                        "Redact derive for `{}` requires bare `{name}` without arguments",
                        input.ident
                    )));
                }
                if *option {
                    let name = meta
                        .path
                        .segments
                        .last()
                        .map_or("option".to_owned(), |segment| segment.ident.to_string());
                    return Err(meta.error(format!(
                        "Redact derive for `{}` repeats the `{name}` container option",
                        input.ident
                    )));
                }
                *option = true;
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
        Ok(Self {
            debug,
            display,
            serde,
            rename_all,
        })
    }

    /// Returns whether this struct requested a redacted `Debug` impl.
    ///
    /// # Returns
    ///
    /// `true` when the `debug` container option was present.
    #[inline(always)]
    pub(crate) const fn debug_enabled(&self) -> bool {
        self.debug
    }

    /// Returns whether this struct requested a redacted `Display` impl.
    ///
    /// # Returns
    ///
    /// `true` when the `display` container option was present.
    #[inline(always)]
    pub(crate) const fn display_enabled(&self) -> bool {
        self.display
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
