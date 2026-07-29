// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Strict derive-side representation of supported sensitivity spellings.

use proc_macro2::TokenStream;
use quote::{
    format_ident,
    quote,
};
use syn::{
    Ident,
    LitStr,
    Path,
};

/// Validated sensitivity level used to generate a runtime variant path.
#[must_use]
pub(crate) struct Sensitivity {
    /// Runtime `Sensitivity` variant identifier.
    runtime_variant: &'static str,
}

impl Sensitivity {
    /// Parses one case-sensitive sensitivity string.
    ///
    /// # Parameters
    ///
    /// * `literal` - String literal supplied to `level`.
    /// * `type_name` - Derived type used to contextualize diagnostics.
    /// * `field_name` - Field used to contextualize diagnostics.
    ///
    /// # Returns
    ///
    /// The corresponding derive-side sensitivity variant.
    ///
    /// # Errors
    ///
    /// Returns an error at `literal` when its value is not exactly `low`,
    /// `medium`, `high`, or `secret`.
    pub(crate) fn parse(
        literal: &LitStr,
        type_name: &Ident,
        field_name: &str,
    ) -> syn::Result<Self> {
        match literal.value().as_str() {
            "low" => Ok(Self {
                runtime_variant: "Low",
            }),
            "medium" => Ok(Self {
                runtime_variant: "Medium",
            }),
            "high" => Ok(Self {
                runtime_variant: "High",
            }),
            "secret" => Ok(Self {
                runtime_variant: "Secret",
            }),
            value => Err(syn::Error::new_spanned(
                literal,
                format!(
                    "Redact derive for `{type_name}` field `{field_name}` has unknown level \
                     `{value}`; use one of `low`, `medium`, `high`, or `secret`",
                ),
            )),
        }
    }

    /// Generates the matching runtime sensitivity path.
    ///
    /// # Parameters
    ///
    /// * `runtime` - Resolved path to the `qubit-redact` runtime crate.
    ///
    /// # Returns
    ///
    /// Tokens naming the corresponding runtime `Sensitivity` variant.
    #[inline]
    pub(crate) fn runtime_tokens(&self, runtime: &Path) -> TokenStream {
        let variant = format_ident!("{}", self.runtime_variant);
        quote!(#runtime::Sensitivity::#variant)
    }
}
