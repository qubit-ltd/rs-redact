// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Derive macros for `qubit-redact` domain objects.

mod derive_input;
mod redact_derive;
mod runtime_path;

use proc_macro::TokenStream;

/// Derives immutable redacted formatting for a named-field struct.
///
/// In this initial form, every field is formatted unchanged. Redaction
/// attributes are introduced separately so that recursion and masking remain
/// explicit choices.
///
/// # Parameters
///
/// * `input` - Rust item annotated with `#[derive(Redact)]`.
///
/// # Returns
///
/// An implementation of `qubit_redact::Redact`, or a targeted compile error
/// when the input is not a named-field struct or the runtime crate cannot be
/// resolved.
#[proc_macro_derive(Redact)]
#[inline(always)]
pub fn derive_redact(input: TokenStream) -> TokenStream {
    redact_derive::derive(input)
}
