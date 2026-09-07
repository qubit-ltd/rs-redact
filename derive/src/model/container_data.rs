// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Parsed container shape shared by every derive backend.

use super::FieldsData;
use super::VariantData;

/// Validated struct or enum data in source order.
///
/// # Type Parameters
///
/// * `'a` - Lifetime of the borrowed derive input syntax.
#[must_use]
pub(crate) enum ContainerData<'a> {
    /// One struct with named, unnamed, or unit fields.
    Struct(
        /// Parsed fields belonging to the source struct.
        FieldsData<'a>,
    ),
    /// One enum with variants retained in declaration order.
    Enum(
        /// Parsed variants with their own source field shapes and attributes.
        Vec<VariantData<'a>>,
    ),
}
