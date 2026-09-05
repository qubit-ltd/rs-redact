// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Public entry point for redaction derive expansion.

use proc_macro2::TokenStream;
use syn::DeriveInput;
use syn::Result;

use crate::runtime_path;

/// Generates the standard Redact derive expansion.
///
/// # Errors
///
/// Returns a targeted syntax error when the runtime crate, input shape, or
/// redaction attributes cannot be resolved.
pub(crate) fn expand(input: &DeriveInput) -> Result<TokenStream> {
    let runtime = runtime_path::resolve(input)?;
    super::redact::expand(input, &runtime)
}
