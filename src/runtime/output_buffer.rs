// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Transaction-owned storage for unpublished aggregate and item text.

use std::ops::Range;

use super::item_range::ItemRange;
use crate::RedactedText;
use crate::RedactionOutput;

/// Stores every committed text fragment in one arena until publication.
pub(super) struct OutputBuffer {
    storage: String,
    aggregate_ranges: Vec<Range<usize>>,
    pub(super) domain_frame: String,
    pub(super) domain_frame_output_bytes: usize,
    pub(super) domain_frame_truncated: bool,
    pub(super) domain_frame_output_limit_reached: bool,
}

impl OutputBuffer {
    /// Creates an empty unpublished output arena.
    #[must_use]
    pub(super) const fn new() -> Self {
        Self {
            storage: String::new(),
            aggregate_ranges: Vec::new(),
            domain_frame: String::new(),
            domain_frame_output_bytes: 0,
            domain_frame_truncated: false,
            domain_frame_output_limit_reached: false,
        }
    }

    /// Stores one aggregate fragment and records its arena range.
    pub(super) fn push_aggregate(&mut self, text: &str) {
        let range = self.push(text);
        self.aggregate_ranges.push(range);
    }

    /// Stores one item and returns its arena range.
    pub(super) fn push_item(&mut self, text: &str) -> Range<usize> {
        self.push(text)
    }

    /// Publishes aggregate and item text without charging either again.
    #[must_use]
    pub(super) fn publish(self, items: Vec<ItemRange>) -> (RedactedText, Vec<RedactionOutput>) {
        let aggregate_len = self.aggregate_ranges.iter().map(Range::len).sum();
        let mut aggregate = String::with_capacity(aggregate_len);
        for range in self.aggregate_ranges {
            aggregate.push_str(&self.storage[range]);
        }
        let items = items
            .into_iter()
            .map(|item| {
                let text = self.storage[item.range].to_owned();
                RedactionOutput::new(RedactedText::from_escaped(text), item.summary)
            })
            .collect();
        (RedactedText::from_escaped(aggregate), items)
    }

    /// Appends text to the shared arena and returns the retained byte range.
    fn push(&mut self, text: &str) -> Range<usize> {
        let start = self.storage.len();
        self.storage.push_str(text);
        start..self.storage.len()
    }
}
