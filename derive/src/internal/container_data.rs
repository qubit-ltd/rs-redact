// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Parsed container shape shared by every derive backend.

use crate::internal::{FieldsData, VariantData};

/// Validated struct or enum data in source order.
#[must_use]
pub(crate) enum ContainerData<'a> {
    /// One struct with named, unnamed, or unit fields.
    Struct(FieldsData<'a>),
    /// One enum with variants retained in declaration order.
    Enum(Vec<VariantData<'a>>),
}
