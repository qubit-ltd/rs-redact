// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Unique formatting mode selected for one derived field.

use crate::sensitivity::Sensitivity;

/// Formatting behavior generated for one named field.
#[must_use]
pub(crate) enum FieldMode {
    /// Formats the original field with its ordinary `Debug` implementation.
    Plain,
    /// Masks a supported textual value at an explicit sensitivity level.
    Level(Sensitivity),
    /// Omits the field name and value without imposing formatting bounds.
    Skip,
    /// Recursively formats the field through its `Redact` implementation.
    Nested,
    /// Classifies string map values by their runtime keys and active policy.
    Map,
    /// Redacts JSON text stored in a string field.
    Json,
}
