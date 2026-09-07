// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Opaque references to one item published by a completed transaction.

/// Private reference to one redacted item produced during a batch transaction.
///
/// Debug output contains only transaction metadata, never item text. The public
/// [`crate::RedactionBatchHandle`] is created from this private token before
/// an operation returns to the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RedactionHandle {
    /// Identity of the batch transaction that created this handle.
    pub(super) transaction_id: u64,
    /// Position of the referenced item inside that batch.
    pub(super) item_index: usize,
}

impl RedactionHandle {
    /// Creates a handle for one transaction-owned item.
    ///
    /// # Parameters
    ///
    /// - `transaction_id`: Identity of the issuing batch.
    /// - `item_index`: Insertion index in that batch.
    ///
    /// # Returns
    ///
    /// An opaque runtime token carrying no item text.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn new(transaction_id: u64, item_index: usize) -> Self {
        Self {
            transaction_id,
            item_index,
        }
    }

    /// Returns the transaction identity and item position for facade wrapping.
    ///
    /// # Returns
    ///
    /// The transaction identity followed by the item index.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn parts(self) -> (u64, usize) {
        (self.transaction_id, self.item_index)
    }
}
