// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Validation errors for JSON recursion-depth budgets.

use std::{
    error::Error,
    fmt::{
        self,
        Display,
        Formatter,
    },
};

/// Reports which JSON recursion-depth invariant was violated.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonDepthBudgetError {
    /// The recursive container depth limit was zero.
    ZeroDepth,
}

impl Display for JsonDepthBudgetError {
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
    /// Returns [`fmt::Error`] when the destination rejects output.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroDepth => formatter
                .write_str("JSON depth budget must be greater than zero"),
        }
    }
}

impl Error for JsonDepthBudgetError {}
