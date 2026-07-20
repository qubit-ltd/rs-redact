// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Errors reported while building a redaction policy.

use std::{
    error::Error,
    fmt,
};

use super::Sensitivity;

/// Error returned when a redaction policy contains an invalid rule.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// A supplied field name is empty after canonicalization.
    EmptyFieldName,
    /// A fixed mask has an empty replacement at the indicated level.
    EmptyFixedReplacement {
        /// Sensitivity level containing the invalid fixed mask.
        level: Sensitivity,
    },
}

impl fmt::Display for PolicyError {
    /// Formats a concise description of the invalid policy configuration.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyFieldName => formatter
                .write_str("field name is empty after canonicalization"),
            Self::EmptyFixedReplacement { level } => write!(
                formatter,
                "fixed mask replacement for {level:?} sensitivity is empty",
            ),
        }
    }
}

impl Error for PolicyError {}
