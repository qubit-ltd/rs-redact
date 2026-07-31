// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Validated recursion-depth limits for JSON redaction.

use super::JsonDepthBudgetError;

/// Maximum recursive container depth inspected during JSON redaction.
#[must_use = "use the validated budget to bound JSON redaction"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonDepthBudget {
    /// Maximum number of recursive container descents from the root.
    max_depth: usize,
}

impl JsonDepthBudget {
    /// Default maximum depth, aligned with serde_json's parser limit.
    pub const DEFAULT_MAX_DEPTH: usize = 128;

    /// Creates a checked JSON recursion-depth budget.
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
    /// A validated positive depth budget.
    ///
    /// # Errors
    ///
    /// Returns [`JsonDepthBudgetError::ZeroDepth`] when `max_depth` is zero.
    #[inline]
    pub const fn new(max_depth: usize) -> Result<Self, JsonDepthBudgetError> {
        if max_depth == 0 {
            Err(JsonDepthBudgetError::ZeroDepth)
        } else {
            Ok(Self { max_depth })
        }
    }

    /// Returns the maximum recursive container depth.
    ///
    /// # Returns
    ///
    /// The positive depth limit measured from a root depth of zero.
    #[inline(always)]
    pub const fn max_depth(self) -> usize {
        self.max_depth
    }
}

impl Default for JsonDepthBudget {
    /// Returns the conservative default recursion-depth budget.
    ///
    /// # Returns
    ///
    /// A budget allowing at most 128 recursive container descents.
    #[inline(always)]
    fn default() -> Self {
        Self {
            max_depth: Self::DEFAULT_MAX_DEPTH,
        }
    }
}
