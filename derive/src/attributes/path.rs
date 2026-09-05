// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Serde-crate path resolution for generated implementations.

use proc_macro_crate::crate_name;
use syn::DeriveInput;
use syn::Expr;
use syn::Lit;
use syn::Meta;
use syn::Path;
use syn::Result;
use syn::Token;
use syn::parse_quote;
use syn::punctuated::Punctuated;

use crate::runtime_path::internal;
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
#[inline(always)]
pub(crate) fn resolve(input: &DeriveInput) -> Result<Path> {
    for attribute in input
        .attrs
        .iter()
        .filter(|attribute| attribute.path().is_ident("serde"))
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
                let Expr::Lit(expression) = value.value else {
                    continue;
                };
                let Lit::Str(literal) = expression.lit else {
                    continue;
                };
                return literal.parse();
            }
        }
    }
    internal::resolve(
        input,
        crate_name("serde"),
        parse_quote!(crate),
        "unable to resolve serde; add `serde` as a direct dependency",
    )
}
