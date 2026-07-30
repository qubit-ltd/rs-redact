// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Serde-crate path resolution for generated implementations.

use proc_macro_crate::crate_name;
use syn::{
    DeriveInput,
    Path,
    parse_quote,
};

use crate::internal::crate_path;

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
pub(crate) fn resolve(input: &DeriveInput) -> syn::Result<Path> {
    crate_path::resolve(
        input,
        crate_name("serde"),
        parse_quote!(::serde),
        "unable to resolve serde; add `serde` as a direct dependency",
    )
}
