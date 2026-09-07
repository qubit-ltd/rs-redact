// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Atomically published output from one redaction batch.

use crate::RedactionHandle;
use crate::RedactionHandleError;
use crate::RedactionSummary;
use crate::RedactionTextOutput;

/// Final output published after a batch commits successfully.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BatchPublication {
    /// Identity shared by every handle created before publication.
    transaction_id: u64,
    /// Independently resolvable final item outputs.
    items: Vec<RedactionTextOutput>,
    /// Aggregate accounting for the complete batch.
    summary: RedactionSummary,
}

impl BatchPublication {
    /// Creates output for the completed batch identity and staged items.
    ///
    /// # Parameters
    ///
    /// - `transaction_id`: Identity shared by this publication's handles.
    /// - `items`: Final items in handle-index order.
    /// - `summary`: Aggregate accounting for the completed batch.
    ///
    /// # Returns
    ///
    /// An immutable publication retaining all supplied items and accounting.
    #[must_use]
    #[inline(always)]
    pub(crate) fn new(transaction_id: u64, items: Vec<RedactionTextOutput>, summary: RedactionSummary) -> Self {
        Self {
            transaction_id,
            items,
            summary,
        }
    }

    /// Returns aggregate accounting across all published batch items.
    ///
    /// # Returns
    ///
    /// Aggregate accounting across the whole published batch.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn summary(&self) -> &RedactionSummary {
        &self.summary
    }

    /// Borrows the item selected by `handle` without cloning its final text.
    ///
    /// # Errors
    ///
    /// Returns [`RedactionHandleError::DifferentTransaction`] for another
    /// batch identity and [`RedactionHandleError::MissingItem`] for an invalid
    /// index in this batch.
    ///
    /// # Parameters
    ///
    /// - `handle`: Runtime token issued for this batch.
    ///
    /// # Returns
    ///
    /// The matching published item borrowed from this output.
    #[inline]
    pub(crate) fn resolve(&self, handle: RedactionHandle) -> Result<&RedactionTextOutput, RedactionHandleError> {
        if handle.transaction_id != self.transaction_id {
            return Err(RedactionHandleError::DifferentTransaction);
        }
        self.items
            .get(handle.item_index)
            .ok_or(RedactionHandleError::MissingItem)
    }
}
