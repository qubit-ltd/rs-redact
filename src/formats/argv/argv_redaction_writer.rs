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
use crate::runtime::TextSession;
use crate::runtime::runtime_session::RuntimeSession;

/// A borrowed argv façade over one mutable diagnostic session.
pub struct ArgvRedactionWriter<'session> {
    /// Shared policy and accounting owned by the parent session.
    session: &'session mut TextSession,
}

impl<'session> ArgvRedactionWriter<'session> {
    /// Creates a façade from a mutable diagnostic session.
    #[inline(always)]
    #[must_use]
    pub(crate) const fn new(session: &'session mut TextSession) -> Self {
        Self { session }
    }

    /// Redacts items into the parent session's aggregate output.
    pub fn items<'items, I>(&mut self, items: I) -> &mut Self
    where
        I: IntoIterator<Item = ArgvItem<'items>>,
    {
        if self.session.skip_aggregate_for_exhausted_output() {
            return self;
        }
        let Some(items) = self.collect_admitted_items(items) else {
            return self;
        };
        let result = redact_items_with_policy(self.session.policy(), items, self.session.remaining_output_bytes());
        self.session.append_rendered_operation(result);
        self
    }

    /// Redacts heuristic items into the parent session's aggregate output.
    pub fn heuristic_items<'items, I>(&mut self, items: I) -> &mut Self
    where
        I: IntoIterator<Item = ArgvItem<'items>>,
    {
        if self.session.skip_aggregate_for_exhausted_output() {
            return self;
        }
        let Some(items) = self.collect_admitted_items(items) else {
            return self;
        };
        let result =
            redact_heuristically_with_policy(self.session.policy(), items, self.session.remaining_output_bytes());
        self.session.append_rendered_operation(result);
        self
    }

    /// Collects only items admitted by the parent transaction. Structural and
    /// input exhaustion stop the source iterator before later values can be
    /// observed by the argv renderer.
    fn collect_admitted_items<'items, I>(&mut self, items: I) -> Option<Vec<ArgvItem<'items>>>
    where
        I: IntoIterator<Item = ArgvItem<'items>>,
    {
        if !self.session.admit_format_node(1) {
            return None;
        }
        let iterator = items.into_iter();
        // Iterator length is caller-controlled metadata. Allocate only after
        // an item has passed the transaction's shared admission checks.
        let mut admitted = Vec::new();
        let mut iterator = iterator;
        loop {
            if iterator.size_hint().1 == Some(0) {
                break;
            }
            if !self.session.preflight_format_item(2) {
                return None;
            }
            let Some(item) = iterator.next() else {
                break;
            };
            if !self.session.admit_format_collection_item() || !self.session.admit_format_node(2) {
                return None;
            }
            if !self.session.admit_input(item.value().as_encoded_bytes().len()) {
                return None;
            }
            admitted.push(item);
        }
        Some(admitted)
    }
}
