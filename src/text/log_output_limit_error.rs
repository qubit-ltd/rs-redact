// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Error returned for an undersized bounded log-output limit.

use std::{
    error::Error,
    fmt::{self, Display, Formatter},
};

use crate::LogOutputLimit;

/// Indicates that a byte budget cannot contain the truncation marker.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LogOutputLimitError {
    /// Invalid requested byte count.
    requested: usize,
}

impl LogOutputLimitError {
    /// Creates an error for an invalid requested byte count.
    ///
    /// # Parameters
    ///
    /// * `requested` - Invalid maximum output byte count.
    ///
    /// # Returns
    ///
    /// An error retaining the invalid request.
    #[inline(always)]
    pub(crate) const fn new(requested: usize) -> Self {
        Self { requested }
    }

    /// Returns the invalid requested byte count.
    ///
    /// # Returns
    ///
    /// The caller-provided byte count.
    #[inline(always)]
    pub const fn requested(self) -> usize {
        self.requested
    }

    /// Returns the smallest valid byte count.
    ///
    /// # Returns
    ///
    /// The byte length required for the complete truncation marker.
    #[inline(always)]
    pub const fn minimum(self) -> usize {
        LogOutputLimit::MINIMUM
    }
}

impl Display for LogOutputLimitError {
    /// Describes the invalid and minimum byte counts.
    ///
    /// # Parameters
    ///
    /// * `formatter` - Destination formatting context.
    ///
    /// # Returns
    ///
    /// The formatter result.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the destination formatter rejects output.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "log output limit {} bytes is smaller than the minimum {} bytes",
            self.requested,
            LogOutputLimit::MINIMUM,
        )
    }
}

impl Error for LogOutputLimitError {}
