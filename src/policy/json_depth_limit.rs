// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Stateless recursion-depth limits for JSON redaction.

use super::JsonDepthLimitError;

/// Stateless maximum recursive container depth inspected during JSON redaction.
///
/// This is a point limit: each observed container depth is checked
/// independently against the immutable maximum. It does not track
/// recursion-stack occupancy, traversal history, or a resource lifecycle, so
/// entering a container never requires a later release. Use it for JSON nesting
/// depth; use a [`qubit_budget::ResourceBudget`] for cumulative input or output
/// bytes. Failed checks leave this value unchanged.
#[must_use = "use the validated limit to bound JSON redaction"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonDepthLimit {
    /// Immutable point limit for recursive container depth.
    limit: usize,
}

impl JsonDepthLimit {
    /// Default maximum depth, aligned with serde_json's parser limit.
    pub const DEFAULT_MAX_DEPTH: usize = 128;

    /// Creates a checked JSON recursion-depth limit.
    ///
    /// The root value has depth zero. A budget of one permits the root
    /// container and its scalar children, while replacing nested containers
    /// with the policy's opaque Secret mask.
    ///
    /// # Parameters
    ///
    /// * `max_depth` - Maximum recursive container descents from the root.
    ///
    /// # Returns
    ///
    /// A validated positive depth limit.
    ///
    /// # Errors
    ///
    /// Returns [`JsonDepthLimitError::ZeroDepth`] when `max_depth` is zero.
    #[must_use]
    #[inline]
    pub const fn new(max_depth: usize) -> Result<Self, JsonDepthLimitError> {
        if max_depth == 0 {
            Err(JsonDepthLimitError::ZeroDepth)
        } else {
            Ok(Self { limit: max_depth })
        }
    }

    /// Returns the maximum recursive container depth.
    ///
    /// # Returns
    ///
    /// The positive depth limit measured from a root depth of zero.
    #[inline(always)]
    pub fn maximum(self) -> usize {
        self.limit
    }

    /// Checks whether one observed recursive container depth is permitted.
    ///
    /// # Parameters
    ///
    /// * `depth` - Container depth measured from the root.
    ///
    /// # Returns
    ///
    /// `true` when `depth` is at most [`Self::maximum`]; this point check does
    /// not record the observation or change future checks.
    #[must_use]
    #[inline(always)]
    pub fn allows(&self, depth: usize) -> bool {
        depth <= self.limit
    }
}

impl Default for JsonDepthLimit {
    /// Returns the conservative default recursion-depth budget.
    ///
    /// # Returns
    ///
    /// A budget allowing at most 128 recursive container descents.
    #[inline(always)]
    fn default() -> Self {
        Self {
            limit: Self::DEFAULT_MAX_DEPTH,
        }
    }
}
