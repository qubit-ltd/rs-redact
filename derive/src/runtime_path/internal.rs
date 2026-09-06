// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared Cargo-aware crate-path mapping for generated derive code.

use std::result::Result as CrateResult;

use proc_macro_crate::Error as CrateError;
use proc_macro_crate::FoundCrate;
use proc_macro2::Span;
use quote::format_ident;
use syn::DeriveInput;
use syn::Error;
use syn::Path;
use syn::Result;
use syn::parse_quote;

/// Converts a Cargo crate lookup into an absolute generated-code path.
///
/// # Parameters
///
/// * `input` - Derive input used as the diagnostic span on lookup failure.
/// * `result` - Cargo-aware crate lookup result.
/// * `itself` - Absolute path used when the requested crate is the consumer.
/// * `error_context` - Stable diagnostic prefix for lookup failures.
///
/// # Returns
///
/// The absolute path visible from the derive call site.
///
/// # Errors
///
/// Returns a syntax error attached to `input` when the Cargo lookup failed.
pub(crate) fn resolve(
    input: &DeriveInput,
    result: CrateResult<FoundCrate, CrateError>,
    itself: Path,
    error_context: &str,
) -> Result<Path> {
    match result {
        Ok(FoundCrate::Itself) => Ok(itself),
        Ok(FoundCrate::Name(name)) => {
            let identifier = format_ident!("{}", name.replace('-', "_"), span = Span::call_site());
            Ok(parse_quote!(::#identifier))
        }
        Err(error) => Err(Error::new_spanned(input, format!("{error_context}: {error}"))),
    }
}
