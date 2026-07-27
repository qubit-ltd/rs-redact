// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Validated byte limits for bounded log output.

use crate::{
    DiagnosticBudget,
    LogOutputLimitError,
};

/// Marker appended when bounded log output is truncated.
pub(crate) const TRUNCATION_MARKER: &str = "<truncated>";

/// Maximum byte count for one bounded redacted log representation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[must_use = "use the validated limit to bound redacted display output"]
pub struct LogOutputLimit {
    /// Maximum rendered bytes, including any truncation marker.
    max_bytes: usize,
}

impl LogOutputLimit {
    /// Smallest valid limit, equal to the byte length of the truncation marker.
    pub const MINIMUM: usize = TRUNCATION_MARKER.len();

    /// Validates a maximum output byte count.
    ///
    /// # Parameters
    ///
    /// * `max_bytes` - Maximum rendered bytes, including any truncation marker.
    ///
    /// # Returns
    ///
    /// A validated output limit.
    ///
    /// # Errors
    ///
    /// Returns [`LogOutputLimitError`] when `max_bytes` cannot contain the
    /// complete truncation marker.
    #[inline]
    pub const fn new(max_bytes: usize) -> Result<Self, LogOutputLimitError> {
        if max_bytes < Self::MINIMUM {
            Err(LogOutputLimitError::new(max_bytes))
        } else {
            Ok(Self { max_bytes })
        }
    }

    /// Returns the maximum rendered byte count.
    ///
    /// # Returns
    ///
    /// The byte budget, including any truncation marker.
    #[inline(always)]
    pub const fn max_bytes(self) -> usize {
        self.max_bytes
    }
}

impl From<DiagnosticBudget> for LogOutputLimit {
    /// Converts a diagnostic budget into its compatible log-output limit.
    ///
    /// [`DiagnosticBudget`] guarantees an output bound large enough for every
    /// [`LogOutputLimit`].
    #[inline(always)]
    fn from(budget: DiagnosticBudget) -> Self {
        Self {
            max_bytes: budget.max_output_bytes(),
        }
    }
}
