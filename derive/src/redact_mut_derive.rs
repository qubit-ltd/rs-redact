// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Entry-point orchestration for the `RedactMut` derive.

use proc_macro::TokenStream;
use syn::DeriveInput;

use crate::{redact_mut_expansion, runtime_path};

/// Parses and expands one `RedactMut` derive invocation.
///
/// # Parameters
///
/// * `input` - Tokens for the annotated Rust item.
///
/// # Returns
///
/// Generated implementation tokens or targeted `compile_error!` tokens.
#[inline]
pub(crate) fn derive(input: TokenStream) -> TokenStream {
    syn::parse::<DeriveInput>(input)
        .and_then(|input| {
            runtime_path::resolve(&input)
                .and_then(|runtime| redact_mut_expansion::expand(&input, &runtime))
        })
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
