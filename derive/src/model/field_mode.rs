// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Unique formatting mode selected for one derived field.

use syn::Ident;

use super::Sensitivity;
/// Formatting behavior generated for one named or tuple field.
#[must_use]
pub(crate) enum FieldMode {
    /// Formats the original field with its ordinary `Debug` implementation.
    Unmarked,
    /// Masks supported scalar leaves at an explicit level, preserving container
    /// shape.
    Level(
        /// Fixed sensitivity applied independently to each supported scalar
        /// leaf.
        Sensitivity,
    ),
    /// Masks the explicitly selected Display string representation.
    DisplayLevel(
        /// Fixed sensitivity applied after bounded Display capture.
        Sensitivity,
    ),
    /// Omits the field name and value without imposing formatting bounds.
    Skip,
    /// Recursively formats the field through its `Redact` implementation.
    Nested,
    /// Classifies text-keyed map values by their runtime keys and active
    /// policy.
    Map,
    /// Masks map keys and, optionally, map values at fixed levels.
    MapLevels {
        /// Sensitivity applied to every map key; validated modes always
        /// contain `Some`.
        key: Option<Sensitivity>,
        /// Fixed value sensitivity, or `None` to preserve ordinary value
        /// output.
        value: Option<Sensitivity>,
    },
    /// Classifies a field value by a sibling text key and active policy.
    KeyedBy(
        /// Source identifier of the sibling field supplying the runtime key.
        Ident,
    ),
    /// Redacts supported JSON text or a parsed JSON value.
    Json,
}
