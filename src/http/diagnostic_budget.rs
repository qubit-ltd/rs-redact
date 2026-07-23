// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Hard input and output limits for HTTP diagnostic redaction.

use super::DiagnosticBudgetError;

/// Bounds both inspected diagnostic bytes and produced log-safe bytes.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiagnosticBudget {
    /// Maximum number of source bytes a diagnostic redactor may inspect.
    max_input_bytes: usize,
    /// Maximum number of bytes in the final log-safe rendering.
    max_output_bytes: usize,
}

impl DiagnosticBudget {
    /// Smallest output limit that can contain the diagnostic-limit marker.
    pub const MIN_OUTPUT_BYTES: usize =
        "<redacted: diagnostic limit exceeded>".len();

    /// Creates checked hard limits for HTTP diagnostic processing.
    ///
    /// # Parameters
    ///
    /// * `max_input_bytes` - Maximum source bytes available to a diagnostic
    ///   redactor.
    /// * `max_output_bytes` - Maximum bytes in the final log-safe result,
    ///   including a complete limit or truncation marker when required.
    ///
    /// # Returns
    ///
    /// A checked finite diagnostic budget.
    ///
    /// # Errors
    ///
    /// Returns [`DiagnosticBudgetError::ZeroInput`] when `max_input_bytes` is
    /// zero, or [`DiagnosticBudgetError::OutputTooSmall`] when the output limit
    /// cannot contain the complete diagnostic-limit marker.
    #[inline]
    pub const fn new(
        max_input_bytes: usize,
        max_output_bytes: usize,
    ) -> Result<Self, DiagnosticBudgetError> {
        if max_input_bytes == 0 {
            return Err(DiagnosticBudgetError::ZeroInput);
        }
        if max_output_bytes < Self::MIN_OUTPUT_BYTES {
            return Err(DiagnosticBudgetError::OutputTooSmall {
                minimum: Self::MIN_OUTPUT_BYTES,
                actual: max_output_bytes,
            });
        }
        Ok(Self {
            max_input_bytes,
            max_output_bytes,
        })
    }

    /// Returns the maximum number of source bytes a diagnostic may inspect.
    ///
    /// # Returns
    ///
    /// The positive input limit in bytes.
    #[must_use]
    #[inline(always)]
    pub const fn max_input_bytes(self) -> usize {
        self.max_input_bytes
    }

    /// Returns the maximum final log-safe diagnostic size.
    ///
    /// # Returns
    ///
    /// The output limit in bytes, including any complete marker.
    #[must_use]
    #[inline(always)]
    pub const fn max_output_bytes(self) -> usize {
        self.max_output_bytes
    }
}

impl Default for DiagnosticBudget {
    /// Returns the conservative 16 KiB input and 64 KiB output limits.
    ///
    /// # Returns
    ///
    /// The default finite HTTP diagnostic budget.
    #[inline(always)]
    fn default() -> Self {
        Self {
            max_input_bytes: 16 * 1024,
            max_output_bytes: 64 * 1024,
        }
    }
}
