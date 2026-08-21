// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Unpublished independently resolvable text owned by the batch path.

use super::item_range::ItemRange;
use crate::RedactedText;
use crate::RedactionTextOutput;

pub(super) struct BatchOutputBuffer {
    storage: String,
    items: Vec<ItemRange>,
    exhausted_item: Option<usize>,
}

impl BatchOutputBuffer {
    #[must_use]
    pub(super) const fn new() -> Self {
        Self {
            storage: String::new(),
            items: Vec::new(),
            exhausted_item: None,
        }
    }

    pub(super) fn push(&mut self, text: &str, summary: crate::RedactionSummary) -> usize {
        let start = self.storage.len();
        self.storage.push_str(text);
        let index = self.items.len();
        self.items
            .push(ItemRange::new(start..self.storage.len(), summary));
        index
    }

    pub(super) const fn len(&self) -> usize {
        self.items.len()
    }

    pub(super) const fn exhausted_item(&self) -> Option<usize> {
        self.exhausted_item
    }

    pub(super) fn set_exhausted_item(&mut self, index: usize) {
        self.exhausted_item = Some(index);
    }

    #[must_use]
    pub(super) fn publish(self) -> Vec<RedactionTextOutput> {
        self.items
            .into_iter()
            .map(|item| {
                RedactionTextOutput::new(
                    RedactedText::from_escaped(self.storage[item.range].to_owned()),
                    item.summary,
                )
            })
            .collect()
    }
}
