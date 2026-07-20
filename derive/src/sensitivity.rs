// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Strict derive-side representation of supported sensitivity spellings.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{
    Ident,
    LitStr,
    Path,
};

/// Sensitivity level parsed from a field attribute.
pub(crate) enum Sensitivity {
    /// Low-sensitivity text.
    Low,
    /// Medium-sensitivity text.
    Medium,
    /// High-sensitivity text.
    High,
    /// Secret text.
    Secret,
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
        field_name: &Ident,
    ) -> syn::Result<Self> {
        match literal.value().as_str() {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "secret" => Ok(Self::Secret),
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
    pub(crate) fn runtime_tokens(&self, runtime: &Path) -> TokenStream {
        match self {
            Self::Low => quote!(#runtime::Sensitivity::Low),
            Self::Medium => quote!(#runtime::Sensitivity::Medium),
            Self::High => quote!(#runtime::Sensitivity::High),
            Self::Secret => quote!(#runtime::Sensitivity::Secret),
        }
    }
}
