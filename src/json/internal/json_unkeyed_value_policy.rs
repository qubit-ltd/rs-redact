// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Internal treatment for JSON scalars without an object-key context.

/// Selects handling for a scalar with no enclosing object key.
#[cfg_attr(not(feature = "http"), allow(dead_code))]
#[derive(Debug, Clone, Copy)]
pub(crate) enum JsonUnkeyedValuePolicy<'a> {
    /// Leaves the scalar visible and reports the pass-through.
    PassThrough,
    /// Replaces the scalar with a bounded diagnostic marker.
    Redact {
        /// Preferred marker when it fits the remaining mask budget.
        marker: &'a str,
        /// Shorter marker used when the preferred marker does not fit.
        truncated_marker: &'a str,
    },
}
