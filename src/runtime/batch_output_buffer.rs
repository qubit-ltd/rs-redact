// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Unpublished independently resolvable text owned by the batch path.

use crate::RedactionTextOutput;

pub(super) struct BatchOutputBuffer {
    items: Vec<RedactionTextOutput>,
    exhausted_item: Option<usize>,
}

impl BatchOutputBuffer {
    #[must_use]
    pub(super) const fn new() -> Self {
        Self {
            items: Vec::new(),
            exhausted_item: None,
        }
    }

    pub(super) fn push(&mut self, text: String, summary: crate::RedactionSummary) -> usize {
        let index = self.items.len();
        self.items.push(RedactionTextOutput::new(
            crate::RedactedText::from_escaped(text),
            summary,
        ));
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
    }
}
