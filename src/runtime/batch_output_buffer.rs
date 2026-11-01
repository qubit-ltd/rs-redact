// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Unpublished independently resolvable text owned by the batch path.

use crate::RedactedText;
use crate::RedactionCompletion;
use crate::RedactionReasons;
use crate::RedactionSummary;
use crate::RedactionTextOutput;
use crate::RedactionUsage;

/// Accumulates unpublished text outputs for one batch transaction.
pub(super) struct BatchOutputBuffer {
    /// Items in their caller-observed publication order.
    items: Vec<RedactionTextOutput>,
    /// First item whose output capacity was exhausted, if one exists.
    exhausted_item: Option<usize>,
    /// First equivalent successful empty item with no recorded usage.
    zero_usage_complete_item: Option<usize>,
}

impl BatchOutputBuffer {
    /// Creates an empty unpublished batch buffer.
    ///
    /// # Returns
    ///
    /// An empty buffer with no exhausted-item sentinel or reusable empty item.
    #[must_use]
    #[inline(always)]
    pub(super) const fn new() -> Self {
        Self {
            items: Vec::new(),
            exhausted_item: None,
            zero_usage_complete_item: None,
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
    #[inline(always)]
    pub(super) const fn exhausted_item(&self) -> Option<usize> {
        self.exhausted_item
    }

    /// Appends one rendered item and returns its batch index.
    ///
    /// Equivalent successful empty items with zero usage share one stored
    /// item. Their summaries must match completely, including disabled state.
    ///
    /// # Parameters
    ///
    /// - `text`: Already escaped text for one admitted operation.
    /// - `summary`: Accounting and completion for that operation.
    ///
    /// # Returns
    ///
    /// The insertion index of the new item, or the shared index for an
    /// equivalent successful empty item with zero usage.
    #[inline]
    pub(super) fn push(&mut self, text: String, summary: RedactionSummary) -> usize {
        let reusable = text.is_empty()
            && summary.completion() == RedactionCompletion::Complete
            && summary.reasons() == RedactionReasons::empty()
            && summary.usage() == RedactionUsage::empty();
        if reusable
            && let Some(index) = self.zero_usage_complete_item
            && self.items[index].summary() == &summary
        {
            return index;
        }
        let index = self.items.len();
        self.items
            .push(RedactionTextOutput::new(RedactedText::from_escaped(text), summary));
        if reusable {
            self.zero_usage_complete_item = Some(index);
        }
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

#[cfg(test)]
mod tests {
    use super::BatchOutputBuffer;
    use crate::RedactionCompletion;
    use crate::RedactionReason;
    use crate::RedactionReasons;
    use crate::RedactionSummary;
    use crate::RedactionUsage;

    fn summary(disabled: bool, reasons: RedactionReasons, usage: RedactionUsage) -> RedactionSummary {
        RedactionSummary::from_parts(disabled, RedactionCompletion::Complete, reasons, usage)
    }

    #[test]
    fn test_only_equivalent_zero_usage_successful_empty_items_share_a_slot() {
        let neutral = summary(false, RedactionReasons::empty(), RedactionUsage::empty());
        let charged = summary(
            false,
            RedactionReasons::empty(),
            RedactionUsage::empty().with_domain_node(1),
        );
        let with_reason = summary(
            false,
            RedactionReasons::empty().with(RedactionReason::InvalidUri),
            RedactionUsage::empty(),
        );
        let disabled = summary(true, RedactionReasons::empty(), RedactionUsage::empty());
        let mut buffer = BatchOutputBuffer::new();

        let neutral_index = buffer.push(String::new(), neutral);
        assert_eq!(buffer.push(String::new(), neutral), neutral_index);
        let nonempty_index = buffer.push("text".to_owned(), neutral);
        assert_ne!(nonempty_index, neutral_index);
        assert_eq!(buffer.push(String::new(), neutral), neutral_index);

        let charged_index = buffer.push(String::new(), charged);
        assert_ne!(charged_index, neutral_index);
        let charged_again_index = buffer.push(String::new(), charged);
        assert_ne!(charged_again_index, charged_index);
        let reason_index = buffer.push(String::new(), with_reason);
        assert_ne!(reason_index, neutral_index);
        let reason_again_index = buffer.push(String::new(), with_reason);
        assert_ne!(reason_again_index, reason_index);
        let disabled_index = buffer.push(String::new(), disabled);
        assert_ne!(disabled_index, neutral_index);
        assert_eq!(buffer.push(String::new(), disabled), disabled_index);
        assert_eq!(buffer.len(), 7);

        let items = buffer.publish();
        assert_eq!(items[charged_index].summary(), &charged);
        assert_eq!(items[charged_again_index].summary(), &charged);
        assert_eq!(items[reason_index].summary(), &with_reason);
        assert_eq!(items[reason_again_index].summary(), &with_reason);
    }
}
