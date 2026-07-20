// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Runtime-crate path resolution for generated implementations.

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

/// Resolves the runtime path visible from the derive call site.
///
/// # Parameters
///
/// * `input` - Derive input used as the diagnostic span on lookup failure.
///
/// # Returns
///
/// `crate` when deriving inside the runtime crate, or an absolute path using
/// the dependency's local name when invoked by a downstream crate.
///
/// # Errors
///
/// Returns a syntax error attached to `input` when Cargo metadata does not
/// expose the `qubit-redact` runtime dependency.
pub(crate) fn resolve(input: &DeriveInput) -> syn::Result<Path> {
    match crate_name("qubit-redact") {
        Ok(FoundCrate::Itself) => Ok(parse_quote!(crate)),
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
                "unable to resolve the qubit-redact runtime crate: {error}"
            ),
        )),
    }
}
