// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Unpublished independently resolvable text owned by the batch path.

use crate::RedactionTextOutput;

/// Accumulates unpublished text outputs for one batch transaction.
pub(super) struct BatchOutputBuffer {
    /// Items in their caller-observed publication order.
    items: Vec<RedactionTextOutput>,
    /// First item whose output capacity was exhausted, if one exists.
    exhausted_item: Option<usize>,
}

impl BatchOutputBuffer {
    /// Creates an empty unpublished batch buffer.
    ///
    /// # Returns
    ///
    /// An empty buffer with no exhausted-item sentinel.
    #[must_use]
    #[inline(always)]
    pub(super) const fn new() -> Self {
        Self {
            items: Vec::new(),
            exhausted_item: None,
        }
    }

    /// Returns the number of buffered items.
    ///
    /// # Returns
    ///
    /// The number of staged items, including an exhausted sentinel if present.
    #[must_use]
    #[inline(always)]
    pub(super) const fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns the first exhausted item index, if recorded.
    ///
    /// # Returns
    ///
    /// `Some(index)` identifies the first stored exhausted sentinel; `None`
    /// means no such sentinel has been recorded.
    #[must_use]
    #[inline(always)]
    pub(super) const fn exhausted_item(&self) -> Option<usize> {
        self.exhausted_item
    }

    /// Appends one rendered item and returns its stable batch index.
    ///
    /// # Parameters
    ///
    /// - `text`: Already escaped text for one admitted operation.
    /// - `summary`: Accounting and completion for that operation.
    ///
    /// # Returns
    ///
    /// The stable insertion index of the new item.
    #[inline]
    pub(super) fn push(&mut self, text: String, summary: crate::RedactionSummary) -> usize {
        let index = self.items.len();
        self.items.push(RedactionTextOutput::new(
            crate::RedactedText::from_escaped(text),
            summary,
        ));
        index
    }

    /// Records the first item index that exhausted shared output capacity.
    ///
    /// # Parameters
    ///
    /// - `index`: Index of the first exhausted sentinel, recorded once by the
    ///   caller.
    #[inline(always)]
    pub(super) fn set_exhausted_item(&mut self, index: usize) {
        self.exhausted_item = Some(index);
    }

    /// Consumes the buffer into the ordered published item collection.
    ///
    /// # Returns
    ///
    /// The staged items in insertion order, consuming the unpublished buffer.
    #[must_use]
    #[inline(always)]
    pub(super) fn publish(self) -> Vec<RedactionTextOutput> {
        self.items
    }
}
