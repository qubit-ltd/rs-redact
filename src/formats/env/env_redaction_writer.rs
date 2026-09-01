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
        if !self.session.admit_format_node(1)
            || !self.session.admit_format_collection_item()
            || !self.session.admit_format_node(2)
            || !self
                .session
                .admit_input(name.len().saturating_add(value.len()))
        {
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
        let Some(pairs) = self.collect_admitted_pairs(pairs) else {
            return self;
        };
        let result = redact_os_pairs_with_policy(
            self.session.policy(),
            pairs,
            self.session.remaining_output_bytes(),
        );
        self.session.append_rendered_operation(result);
        self
    }

    /// Collects pairs only while their individual structural and input
    /// admissions succeed. This deliberately avoids materializing or
    /// rendering the suffix after a shared transaction limit is reached.
    fn collect_admitted_pairs<'items, I>(
        &mut self,
        pairs: I,
    ) -> Option<Vec<(&'items OsStr, &'items OsStr)>>
    where
        I: IntoIterator<Item = (&'items OsStr, &'items OsStr)>,
    {
        if !self.session.admit_format_node(1) {
            return None;
        }
        let iterator = pairs.into_iter();
        // Iterator length is caller-controlled metadata. Allocate only after
        // an entry has passed the transaction's shared admission checks.
        let mut admitted = Vec::new();
        let mut iterator = iterator;
        loop {
            if iterator.size_hint().1 == Some(0) {
                break;
            }
            if !self.session.preflight_format_item(2) {
                return None;
            }
            let Some((name, value)) = iterator.next() else {
                break;
            };
            if !self.session.admit_format_collection_item() || !self.session.admit_format_node(2) {
                return None;
            }
            if !self.session.admit_input(
                name.as_encoded_bytes()
                    .len()
                    .saturating_add(value.as_encoded_bytes().len()),
            ) {
                return None;
            }
            admitted.push((name, value));
        }
        Some(admitted)
    }
}
