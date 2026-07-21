// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Derive macros for `qubit-redact` domain objects.

mod container_attributes;
mod field_assertion;
mod field_attributes;
mod field_mode;
mod internal;
mod named_fields;
mod redact_derive;
mod redact_expansion;
mod redact_mut_derive;
mod redact_mut_expansion;
mod runtime_path;
mod sensitivity;
mod serde_attributes;
mod serde_expansion;
mod serde_rename_rule;

use proc_macro::TokenStream;

/// Derives immutable redacted formatting for a named-field struct.
///
/// Unmarked fields use ordinary `Debug`; masking, recursion, map processing,
/// and omission require explicit field attributes.
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
#[proc_macro_derive(Redact, attributes(redact, serde))]
#[inline(always)]
pub fn derive_redact(input: TokenStream) -> TokenStream {
    redact_derive::derive(input)
}

/// Derives explicit destructive redaction for owned fields of a named struct.
///
/// # Parameters
///
/// * `input` - Rust item annotated with `#[derive(RedactMut)]`.
///
/// # Returns
///
/// An implementation of `qubit_redact::RedactMut`, or a targeted compile
/// error for unsupported input or field capabilities.
#[proc_macro_derive(RedactMut, attributes(redact, serde))]
#[inline(always)]
pub fn derive_redact_mut(input: TokenStream) -> TokenStream {
    redact_mut_derive::derive(input)
}
