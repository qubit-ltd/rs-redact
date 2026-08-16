// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Validated byte limits for bounded log output.
// qubit-style: allow multiple-public-types

use crate::InputOutputLimit;
use crate::LogOutputLimitError;

/// Marker appended when bounded log output is truncated.
pub(crate) const TRUNCATION_MARKER: &str = "<truncated>";

/// Mutable construction state for a [`LogOutputLimit`].
#[derive(Clone, Copy, Debug)]
pub struct LogOutputLimitBuilder {
    max_bytes: usize,
}

/// Maximum byte count for one bounded redacted log representation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LogOutputLimit {
    /// Maximum rendered bytes, including any truncation marker.
    max_bytes: usize,
}

impl LogOutputLimit {
    /// Smallest valid limit, equal to the byte length of the truncation marker.
    pub const MINIMUM: usize = TRUNCATION_MARKER.len();

    /// Creates a builder initialized with the minimum valid output size.
    #[must_use]
    #[inline]
    pub const fn builder() -> LogOutputLimitBuilder {
        LogOutputLimitBuilder {
            max_bytes: Self::MINIMUM,
        }
    }

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
    const fn from_builder(
        max_bytes: usize,
    ) -> Result<Self, LogOutputLimitError> {
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
    #[must_use]
    pub const fn max_bytes(self) -> usize {
        self.max_bytes
    }
}

impl LogOutputLimitBuilder {
    /// Sets the maximum rendered byte count.
    #[inline]
    pub const fn max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// Builds a validated log-output limit.
    #[inline]
    pub const fn build(self) -> Result<LogOutputLimit, LogOutputLimitError> {
        LogOutputLimit::from_builder(self.max_bytes)
    }
}

impl From<InputOutputLimit> for LogOutputLimit {
    /// Converts a diagnostic budget into its compatible log-output limit.
    ///
    /// [`InputOutputLimit`] guarantees an output bound large enough for every
    /// [`LogOutputLimit`].
    ///
    /// # Parameters
    ///
    /// * `budget` - Diagnostic budget whose output limit is converted.
    ///
    /// # Returns
    ///
    /// A compatible validated log-output limit.
    #[inline(always)]
    fn from(budget: InputOutputLimit) -> Self {
        Self {
            max_bytes: budget.max_output_bytes(),
        }
    }
}
