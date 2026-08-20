// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared-session argument-vector redaction.

use super::ArgvItem;
use super::redaction::redact_heuristically_with_policy;
use super::redaction::redact_items_with_policy;
use crate::RedactionHandle;
use crate::RedactionSession;

/// A borrowed argv façade over one mutable diagnostic session.
pub struct ArgvRedactionWriter<'session> {
    /// Shared policy and accounting owned by the parent session.
    session: &'session mut RedactionSession,
}

impl<'session> ArgvRedactionWriter<'session> {
    /// Creates a façade from a mutable diagnostic session.
    #[inline(always)]
    #[must_use]
    pub(crate) const fn new(session: &'session mut RedactionSession) -> Self {
        Self { session }
    }

    /// Redacts items into the parent session's aggregate output.
    pub fn items<'items, I>(&mut self, items: I) -> &mut Self
    where
        I: IntoIterator<Item = ArgvItem<'items>>,
        I::IntoIter: ExactSizeIterator,
    {
        if self.session.is_output_exhausted() {
            return self;
        }
        let Some(items) = self.collect_admitted_items(items) else {
            return self;
        };
        let result = redact_items_with_policy(self.session.policy(), items, self.session.remaining_output_bytes());
        self.session.append_format_output(&result);
        self
    }

    /// Redacts heuristic items into the parent session's aggregate output.
    pub fn heuristic_items<'items, I>(&mut self, items: I) -> &mut Self
    where
        I: IntoIterator<Item = ArgvItem<'items>>,
        I::IntoIter: ExactSizeIterator,
    {
        if self.session.is_output_exhausted() {
            return self;
        }
        let Some(items) = self.collect_admitted_items(items) else {
            return self;
        };
        let result =
            redact_heuristically_with_policy(self.session.policy(), items, self.session.remaining_output_bytes());
        self.session.append_format_output(&result);
        self
    }

    /// Redacts items as one individually resolvable transaction item.
    #[must_use]
    pub fn redact_items<'items, I>(&mut self, items: I) -> RedactionHandle
    where
        I: IntoIterator<Item = ArgvItem<'items>>,
        I::IntoIter: ExactSizeIterator,
    {
        let owns_item_summary = self.session.begin_item_summary();
        let handle = (|| {
            if self.session.is_output_exhausted() {
                return self.session.stage_format_text(
                    crate::RedactedText::from_escaped(String::new()),
                    crate::RedactionCompletion::Exhausted,
                );
            }
            let Some(items) = self.collect_admitted_items(items) else {
                return self
                    .session
                    .stage_accounted_text(crate::RedactedText::from_escaped(String::new()));
            };
            let result = redact_items_with_policy(self.session.policy(), items, self.session.remaining_output_bytes());
            if result.text().as_str().is_empty()
                && result.summary().completion() == crate::RedactionCompletion::Truncated
            {
                return self.session.stage_format_text(
                    crate::RedactedText::from_escaped(String::new()),
                    crate::RedactionCompletion::Exhausted,
                );
            }
            self.session.stage_item(result)
        })();
        self.session.end_item_summary(owns_item_summary);
        handle
    }

    /// Redacts heuristic items as one individually resolvable transaction item.
    #[must_use]
    pub fn redact_heuristic_items<'items, I>(&mut self, items: I) -> RedactionHandle
    where
        I: IntoIterator<Item = ArgvItem<'items>>,
        I::IntoIter: ExactSizeIterator,
    {
        let owns_item_summary = self.session.begin_item_summary();
        let handle = (|| {
            if self.session.is_output_exhausted() {
                return self.session.stage_format_text(
                    crate::RedactedText::from_escaped(String::new()),
                    crate::RedactionCompletion::Exhausted,
                );
            }
            let Some(items) = self.collect_admitted_items(items) else {
                return self
                    .session
                    .stage_accounted_text(crate::RedactedText::from_escaped(String::new()));
            };
            let result =
                redact_heuristically_with_policy(self.session.policy(), items, self.session.remaining_output_bytes());
            if result.text().as_str().is_empty()
                && result.summary().completion() == crate::RedactionCompletion::Truncated
            {
                return self.session.stage_format_text(
                    crate::RedactedText::from_escaped(String::new()),
                    crate::RedactionCompletion::Exhausted,
                );
            }
            self.session.stage_item(result)
        })();
        self.session.end_item_summary(owns_item_summary);
        handle
    }

    /// Collects only items admitted by the parent transaction. Structural and
    /// input exhaustion stop the source iterator before later values can be
    /// observed by the argv renderer.
    fn collect_admitted_items<'items, I>(&mut self, items: I) -> Option<Vec<ArgvItem<'items>>>
    where
        I: IntoIterator<Item = ArgvItem<'items>>,
        I::IntoIter: ExactSizeIterator,
    {
        if !self.session.admit_format_node(1) {
            return None;
        }
        let mut iterator = items.into_iter();
        // Iterator length is caller-controlled metadata. Allocate only after
        // an item has passed the transaction's shared admission checks.
        let mut admitted = Vec::new();
        while iterator.len() > 0 {
            if !self.session.admit_format_collection_item() || !self.session.admit_format_node(2) {
                return None;
            }
            let item = iterator.next().expect("exact-size iterator reported an item");
            if !self.session.admit_input(item.value().as_encoded_bytes().len()) {
                return None;
            }
            admitted.push(item);
        }
        Some(admitted)
    }
}
