// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Hard input and output limits for redacted diagnostics.

use super::{DiagnosticBudgetError, DiagnosticInputBudget};

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
    pub const MIN_OUTPUT_BYTES: usize = "<redacted: diagnostic limit exceeded>".len();

    /// Creates checked hard limits for diagnostic processing.
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
    #[must_use]
    #[inline(always)]
    pub const fn max_input_bytes(self) -> usize {
        self.max_input_bytes
    }

    /// Returns the maximum final log-safe diagnostic size.
    #[must_use]
    #[inline(always)]
    pub const fn max_output_bytes(self) -> usize {
        self.max_output_bytes
    }

    /// Creates independent input accounting for one diagnostic rendering.
    ///
    /// # Returns
    ///
    /// A mutable budget initialized from this diagnostic's input limit.
    #[inline(always)]
    pub const fn input_budget(self) -> DiagnosticInputBudget {
        DiagnosticInputBudget::new(self.max_input_bytes)
    }
}

impl Default for DiagnosticBudget {
    /// Returns conservative 16 KiB input and 64 KiB output limits.
    #[inline(always)]
    fn default() -> Self {
        Self {
            max_input_bytes: 16 * 1024,
            max_output_bytes: 64 * 1024,
        }
    }
}
