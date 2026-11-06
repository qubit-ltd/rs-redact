// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Source declaration identity shared by Serde expansion helpers.

use syn::Generics;
use syn::Ident;

/// Borrows source declaration identity while emitting Serde attribute paths.
///
/// # Type Parameters
///
/// - `'a`: Lifetime of the source declaration borrowed by both fields.
pub(in crate::serde) struct SourceTypeContext<'a> {
    /// Identifier that names the source declaration.
    pub(in crate::serde) ident: &'a Ident,
    /// Lifetime, type, and const parameters declared by the source.
    pub(in crate::serde) generics: &'a Generics,
}
