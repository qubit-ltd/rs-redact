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
use quote::quote;
use syn::DeriveInput;
use syn::Error;
use syn::Path;
use syn::Result;

/// Converts a Cargo crate lookup into a generated-code path.
///
/// # Parameters
///
/// * `input` - Derive input used as the diagnostic span on lookup failure.
/// * `result` - Cargo-aware crate lookup result.
/// * `itself` - Caller-provided path used when the requested crate is the
///   consumer.
/// * `error_context` - Stable diagnostic prefix for lookup failures.
///
/// # Returns
///
/// The supplied self path or an absolute path naming the dependency.
///
/// # Errors
///
/// Returns a syntax error attached to `input` when the Cargo lookup failed or
/// the resolved dependency name is not a valid Rust identifier.
pub(crate) fn resolve(
    input: &DeriveInput,
    result: CrateResult<FoundCrate, CrateError>,
    itself: Path,
    error_context: &str,
) -> Result<Path> {
    match result {
        Ok(FoundCrate::Itself) => Ok(itself),
        Ok(FoundCrate::Name(name)) => {
            let name = name.replace('-', "_");
            let invalid_name = || {
                Error::new_spanned(
                    input,
                    format!("{error_context}: invalid runtime crate name `{name}`"),
                )
            };
            let identifier = if name == "gen" {
                syn::parse_str::<syn::Ident>(&format!("r#{name}"))
            } else {
                syn::parse_str::<syn::Ident>(&name)
                    .or_else(|_| syn::parse_str::<syn::Ident>(&format!("r#{name}")))
            }
            .map_err(|_| invalid_name())?;
            syn::parse2(quote!(::#identifier)).map_err(|_| invalid_name())
        }
        Err(error) => Err(Error::new_spanned(input, format!("{error_context}: {error}"))),
    }
}
