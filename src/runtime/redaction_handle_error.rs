// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Resolution failures for unpublished runtime batch handles.

use std::fmt;

/// Explains why a private batch publication cannot resolve a handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum RedactionHandleError {
    /// The handle was created by a different redaction transaction.
    DifferentTransaction,
    /// The handle points outside the transaction's published item range.
    MissingItem,
}

impl fmt::Display for RedactionHandleError {
    /// Writes a stable diagnostic without including item contents.
    ///
    /// # Parameters
    ///
    /// - `formatter`: Destination for a diagnostic containing no item data.
    ///
    /// # Errors
    ///
    /// Propagates a write failure from the destination formatter.
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DifferentTransaction => formatter.write_str("the handle belongs to a different transaction"),
            Self::MissingItem => formatter.write_str("the handle does not identify a published item"),
        }
    }
}

impl std::error::Error for RedactionHandleError {}
