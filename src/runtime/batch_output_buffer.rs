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
    #[must_use]
    pub(super) const fn new() -> Self {
        Self {
            items: Vec::new(),
            exhausted_item: None,
        }
    }

    /// Appends one rendered item and returns its stable batch index.
    pub(super) fn push(&mut self, text: String, summary: crate::RedactionSummary) -> usize {
        let index = self.items.len();
        self.items.push(RedactionTextOutput::new(
            crate::RedactedText::from_escaped(text),
            summary,
        ));
        index
    }

    /// Returns the number of buffered items.
    #[must_use]
    #[inline(always)]
    pub(super) const fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns the first exhausted item index, if recorded.
    #[must_use]
    #[inline(always)]
    pub(super) const fn exhausted_item(&self) -> Option<usize> {
        self.exhausted_item
    }

    /// Records the first item index that exhausted shared output capacity.
    pub(super) fn set_exhausted_item(&mut self, index: usize) {
        self.exhausted_item = Some(index);
    }

    /// Consumes the buffer into the ordered published item collection.
    #[must_use]
    pub(super) fn publish(self) -> Vec<RedactionTextOutput> {
        self.items
    }
}
