// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Errors reported while building a redaction policy.

use std::error::Error;
use std::fmt;

use super::PolicyLocation;
use super::Sensitivity;

/// Error returned when a redaction policy contains an invalid rule.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// A supplied field name is empty after canonicalization.
    EmptyFieldName {
        /// Location where the invalid field was configured.
        location: PolicyLocation,
    },
    /// A fixed mask has an empty replacement at the indicated level.
    EmptyFixedReplacement {
        /// Location where the fixed mask was configured.
        location: PolicyLocation,
        /// Sensitivity level containing the invalid fixed mask.
        level: Sensitivity,
    },
}

impl fmt::Display for PolicyError {
    /// Formats a concise description of the invalid policy configuration.
    ///
    /// # Parameters
    ///
    /// * `formatter` - Destination formatting context.
    ///
    /// # Returns
    ///
    /// The formatter result from writing the error description.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the destination rejects a write.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyFieldName { location } => write!(
                formatter,
                "field name is empty after canonicalization in {location}",
            ),
            Self::EmptyFixedReplacement { location, level } => write!(
                formatter,
                "fixed mask replacement for {level:?} sensitivity is empty in {location}",
            ),
        }
    }
}

impl Error for PolicyError {}
