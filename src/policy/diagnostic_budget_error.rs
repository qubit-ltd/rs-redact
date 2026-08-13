// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Validation errors for diagnostic budgets.

use std::error::Error;
use std::fmt;
use std::fmt::Display;
use std::fmt::Formatter;

/// Reports which hard diagnostic-budget invariant was violated.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticBudgetError {
    /// The input byte limit was zero.
    ZeroInput,
    /// The output limit cannot contain the complete diagnostic-limit marker.
    OutputTooSmall {
        /// Smallest accepted output limit in bytes.
        minimum: usize,
        /// Rejected output limit in bytes.
        actual: usize,
    },
}

impl Display for DiagnosticBudgetError {
    /// Writes a concise description of the violated budget invariant.
    ///
    /// # Parameters
    ///
    /// * `formatter` - Destination formatting context.
    ///
    /// # Returns
    ///
    /// The formatter result after writing the error description.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the destination formatter rejects output.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroInput => {
                formatter.write_str("diagnostic input budget must be greater than zero")
            }
            Self::OutputTooSmall { minimum, actual } => write!(
                formatter,
                "diagnostic output budget must be at least {minimum} bytes, got {actual}",
            ),
        }
    }
}

impl Error for DiagnosticBudgetError {}
