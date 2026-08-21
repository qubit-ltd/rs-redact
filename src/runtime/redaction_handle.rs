// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Opaque references to one item published by a completed transaction.
// qubit-style: allow multiple-public-types

use std::fmt;

/// Private reference to one redacted item produced during a batch transaction.
///
/// A handle intentionally has no text formatting implementation. Call
/// The public [`crate::RedactionBatchHandle`] is created from this private
/// token before an operation returns to the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RedactionHandle {
    pub(super) transaction_id: u64,
    pub(super) item_index: usize,
}

impl RedactionHandle {
    /// Creates a handle for one transaction-owned item.
    #[must_use]
    pub(crate) const fn new(transaction_id: u64, item_index: usize) -> Self {
        Self {
            transaction_id,
            item_index,
        }
    }

    pub(crate) const fn parts(self) -> (u64, usize) {
        (self.transaction_id, self.item_index)
    }
}

/// Explains why a private batch publication cannot resolve a handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionHandleError {
    /// The handle was created by a different redaction transaction.
    DifferentTransaction,
    /// The handle points outside the transaction's published item range.
    MissingItem,
}

impl fmt::Display for RedactionHandleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DifferentTransaction => formatter.write_str("the handle belongs to a different transaction"),
            Self::MissingItem => formatter.write_str("the handle does not identify a published item"),
        }
    }
}

impl std::error::Error for RedactionHandleError {}
