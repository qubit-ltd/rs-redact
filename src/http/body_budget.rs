// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Hard input and output limits for HTTP body redaction.

use super::BodyBudgetError;

/// Bounds both inspected body bytes and produced log-safe bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyBudget {
    /// Maximum number of captured source bytes a parser may inspect.
    max_input_bytes: usize,
    /// Maximum number of bytes in the final log-safe rendering.
    max_output_bytes: usize,
}

impl BodyBudget {
    /// Smallest output limit that can contain the truncation marker.
    pub const MIN_OUTPUT_BYTES: usize = "<truncated>".len();

    /// Creates checked hard limits for body processing.
    ///
    /// # Parameters
    ///
    /// * `max_input_bytes` - Maximum source bytes available to body parsers.
    /// * `max_output_bytes` - Maximum bytes in the final log-safe result,
    ///   including a complete truncation marker when required.
    ///
    /// # Returns
    ///
    /// A checked finite body budget.
    ///
    /// # Errors
    ///
    /// Returns [`BodyBudgetError::ZeroInput`] when `max_input_bytes` is zero,
    /// or [`BodyBudgetError::OutputTooSmall`] when the output limit cannot
    /// contain the complete truncation marker.
    #[inline]
    pub const fn new(
        max_input_bytes: usize,
        max_output_bytes: usize,
    ) -> Result<Self, BodyBudgetError> {
        if max_input_bytes == 0 {
            return Err(BodyBudgetError::ZeroInput);
        }
        if max_output_bytes < Self::MIN_OUTPUT_BYTES {
            return Err(BodyBudgetError::OutputTooSmall {
                minimum: Self::MIN_OUTPUT_BYTES,
                actual: max_output_bytes,
            });
        }
        Ok(Self {
            max_input_bytes,
            max_output_bytes,
        })
    }

    /// Returns the maximum number of source bytes parsers may inspect.
    ///
    /// # Returns
    ///
    /// The positive input limit in bytes.
    #[must_use]
    #[inline(always)]
    pub const fn max_input_bytes(self) -> usize {
        self.max_input_bytes
    }

    /// Returns the maximum final log-safe output size.
    ///
    /// # Returns
    ///
    /// The output limit in bytes, including any truncation marker.
    #[must_use]
    #[inline(always)]
    pub const fn max_output_bytes(self) -> usize {
        self.max_output_bytes
    }
}

impl Default for BodyBudget {
    /// Returns the conservative 16 KiB input and 64 KiB output limits.
    ///
    /// # Returns
    ///
    /// The default finite HTTP body budget.
    #[inline(always)]

    fn default() -> Self {
        Self {
            max_input_bytes: 16 * 1024,
            max_output_bytes: 64 * 1024,
        }
    }
}
