// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Runtime-crate path resolution for generated implementations.

use proc_macro_crate::crate_name;
use syn::{DeriveInput, Path, parse_quote};

use crate::internal::crate_path;

/// Resolves the runtime path visible from the derive call site.
///
/// # Parameters
///
/// * `input` - Derive input used as the diagnostic span on lookup failure.
///
/// # Returns
///
/// `::qubit_redact` when deriving inside the runtime crate, or an absolute path
/// using the dependency's local name when invoked by a downstream crate.
///
/// # Errors
///
/// Returns a syntax error attached to `input` when Cargo metadata does not
/// expose the `qubit-redact` runtime dependency.
#[inline(always)]
pub(crate) fn resolve(input: &DeriveInput) -> syn::Result<Path> {
    crate_path::resolve(
        input,
        crate_name("qubit-redact"),
        parse_quote!(::qubit_redact),
        "unable to resolve the qubit-redact runtime crate",
    )
}
