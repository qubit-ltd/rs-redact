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
use crate::runtime::collect_flat_format_items;
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
        let Some(items) = collect_flat_format_items(self.session, items, |item| item.value().as_encoded_bytes().len())
        else {
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
        let Some(items) = collect_flat_format_items(self.session, items, |item| item.value().as_encoded_bytes().len())
        else {
            return self;
        };
        let result =
            redact_heuristically_with_policy(self.session.policy(), items, self.session.remaining_output_bytes());
        self.session.append_rendered_operation(result);
        self
    }
}
