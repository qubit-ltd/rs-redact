// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Value-free rejection reasons for JSON structural preflight.

/// Value-free failure from shared JSON structural validation.
///
/// `Invalid` represents malformed JSON, `DepthLimit` represents relative
/// depth rejection, and `TraversalLimit` represents a closed traversal or a
/// node/item budget rejection.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JsonStructurePreflightError {
    /// The text is malformed JSON.
    Invalid,
    /// The text exceeds the available relative nesting depth.
    DepthLimit,
    /// Traversal is closed or the shared node/item capacity is exceeded.
    TraversalLimit,
}
