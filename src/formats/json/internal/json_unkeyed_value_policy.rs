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
    /// Emits the selected diagnostic marker in place of the scalar.
    Redact {
        /// Marker selected by the enclosing format policy.
        marker: &'a str,
    },
}
