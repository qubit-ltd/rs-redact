// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Runtime-crate path resolution for generated implementations.

pub(crate) mod internal;

use proc_macro_crate::crate_name;
use quote::quote;
use syn::DeriveInput;
use syn::Meta;
use syn::Path;
use syn::Result;
use syn::Token;
use syn::parse_quote;
use syn::parse2;
use syn::punctuated::Punctuated;

/// Resolves the runtime path visible from the derive call site.
///
/// # Parameters
///
/// * `input` - Derive input used as the diagnostic span on lookup failure.
///
/// # Returns
///
/// The explicit `redact(crate = ...)` path when supplied, otherwise `crate`
/// inside the runtime or an absolute path using the downstream dependency name.
///
/// # Errors
///
/// Returns a syntax error attached to `input` when Cargo metadata does not
/// expose the `qubit-redact` runtime dependency, or when an explicit override
/// cannot be parsed as a Rust path.
pub(crate) fn resolve(input: &DeriveInput) -> Result<Path> {
    for attribute in input
        .attrs
        .iter()
        .filter(|attribute| attribute.path().is_ident("redact"))
    {
        if !matches!(attribute.meta, Meta::List(_)) {
            continue;
        }
        let Ok(items) = attribute.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated) else {
            continue;
        };
        for item in items {
            if let Meta::NameValue(value) = item
                && value.path.is_ident("crate")
            {
                let expression = value.value;
                return parse2(quote!(#expression));
            }
        }
    }
    internal::resolve(
        input,
        crate_name("qubit-redact"),
        parse_quote!(crate),
        "unable to resolve the qubit-redact runtime crate",
    )
}
