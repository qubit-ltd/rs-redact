// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Parsed field shape shared by container and variant data.

use super::NamedField;
use super::UnnamedField;

/// Validated named, unnamed, or unit fields in source order.
///
/// # Type Parameters
///
/// * `'a` - Lifetime of the borrowed field syntax.
#[must_use]
pub(crate) enum FieldsData<'a> {
    /// Brace-delimited fields carrying identifiers.
    Named(
        /// Parsed named fields retained in their original declaration order.
        Vec<NamedField<'a>>,
    ),
    /// Tuple fields addressed by stable declaration indexes.
    Unnamed(
        /// Parsed tuple fields with their original positional indexes.
        Vec<UnnamedField<'a>>,
    ),
    /// A container or variant without fields.
    Unit,
}
