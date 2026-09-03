// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared-session environment redaction.

use std::ffi::OsStr;

use super::redaction::redact_os_pairs_with_policy;
use super::redaction::redact_pair_with_policy;
use crate::runtime::TextSession;
use crate::runtime::admit_flat_format_item;
use crate::runtime::collect_flat_format_items;
use crate::runtime::runtime_session::RuntimeSession;

/// A borrowed environment façade over one mutable diagnostic session.
pub struct EnvRedactionWriter<'session> {
    /// Shared policy and accounting owned by the parent session.
    session: &'session mut TextSession,
}

impl<'session> EnvRedactionWriter<'session> {
    /// Creates a façade from a mutable diagnostic session.
    #[inline(always)]
    #[must_use]
    pub(crate) const fn new(session: &'session mut TextSession) -> Self {
        Self { session }
    }

    /// Redacts one pair into the parent session's aggregate output.
    pub fn pair(&mut self, name: &str, value: &str) -> &mut Self {
        if self.session.skip_aggregate_for_exhausted_output() {
            return self;
        }
        if !admit_flat_format_item(self.session, name.len().saturating_add(value.len())) {
            return self;
        }
        let result = redact_pair_with_policy(
            self.session.policy(),
            name,
            value,
            self.session.remaining_output_bytes(),
        );
        self.session.append_rendered_operation(result);
        self
    }

    /// Redacts an environment list into the parent session's aggregate output.
    pub fn os_pairs<'items, I>(&mut self, pairs: I) -> &mut Self
    where
        I: IntoIterator<Item = (&'items OsStr, &'items OsStr)>,
    {
        if self.session.skip_aggregate_for_exhausted_output() {
            return self;
        }
        let Some(pairs) = collect_flat_format_items(self.session, pairs, |(name, value)| {
            name.as_encoded_bytes()
                .len()
                .saturating_add(value.as_encoded_bytes().len())
        }) else {
            return self;
        };
        let result = redact_os_pairs_with_policy(self.session.policy(), pairs, self.session.remaining_output_bytes());
        self.session.append_rendered_operation(result);
        self
    }
}
