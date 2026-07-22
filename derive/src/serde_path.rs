// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Serde-crate path resolution for generated implementations.

use proc_macro_crate::{
    FoundCrate,
    crate_name,
};
use proc_macro2::Span;
use quote::format_ident;
use syn::{
    DeriveInput,
    Path,
    parse_quote,
};

/// Resolves the serde path visible from the derive call site.
///
/// # Parameters
///
/// * `input` - Derive input used as the diagnostic span on lookup failure.
///
/// # Returns
///
/// An absolute path using serde's local dependency name.
///
/// # Errors
///
/// Returns a targeted syntax error when serde is not a direct dependency.
pub(crate) fn resolve(input: &DeriveInput) -> syn::Result<Path> {
    match crate_name("serde") {
        Ok(FoundCrate::Itself) => Ok(parse_quote!(::serde)),
        Ok(FoundCrate::Name(name)) => {
            let identifier = format_ident!(
                "{}",
                name.replace('-', "_"),
                span = Span::call_site()
            );
            Ok(parse_quote!(::#identifier))
        }
        Err(error) => Err(syn::Error::new_spanned(
            input,
            format!(
                "unable to resolve serde; add `serde` as a direct dependency: {error}"
            ),
        )),
    }
}
