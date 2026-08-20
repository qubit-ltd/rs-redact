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
use crate::RedactionHandle;
use crate::RedactionSession;

/// A borrowed environment façade over one mutable diagnostic session.
pub struct EnvRedactionWriter<'session> {
    /// Shared policy and accounting owned by the parent session.
    session: &'session mut RedactionSession,
}

impl<'session> EnvRedactionWriter<'session> {
    /// Creates a façade from a mutable diagnostic session.
    #[inline(always)]
    #[must_use]
    pub(crate) const fn new(session: &'session mut RedactionSession) -> Self {
        Self { session }
    }

    /// Redacts one pair into the parent session's aggregate output.
    pub fn pair(&mut self, name: &str, value: &str) -> &mut Self {
        if self.session.is_output_exhausted() {
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
        self.session.append_format_output(&result);
        self
    }

    /// Redacts an environment list into the parent session's aggregate output.
    pub fn os_pairs<'items, I>(&mut self, pairs: I) -> &mut Self
    where
        I: IntoIterator<Item = (&'items OsStr, &'items OsStr)>,
        I::IntoIter: ExactSizeIterator,
    {
        if self.session.is_output_exhausted() {
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
        self.session.append_format_output(&result);
        self
    }

    /// Redacts one pair as an individually resolvable transaction item.
    #[must_use]
    pub fn redact_pair(&mut self, name: &str, value: &str) -> RedactionHandle {
        let owns_item_summary = self.session.begin_item_summary();
        let handle = (|| {
            if self.session.is_output_exhausted() {
                return self.exhausted_handle();
            }
            if !self.session.admit_format_node(1)
                || !self.session.admit_format_collection_item()
                || !self.session.admit_format_node(2)
                || !self
                    .session
                    .admit_input(name.len().saturating_add(value.len()))
            {
                return self
                    .session
                    .stage_accounted_text(crate::RedactedText::from_escaped(String::new()));
            }
            let result = redact_pair_with_policy(
                self.session.policy(),
                name,
                value,
                self.session.remaining_output_bytes(),
            );
            if result.text().as_str().is_empty()
                && result.summary().completion() == crate::RedactionCompletion::Truncated
            {
                return self.exhausted_handle();
            }
            self.session.stage_item(result)
        })();
        self.session.end_item_summary(owns_item_summary);
        handle
    }

    /// Redacts an environment list as one individually resolvable transaction
    /// item.
    #[must_use]
    pub fn redact_os_pairs<'items, I>(&mut self, pairs: I) -> RedactionHandle
    where
        I: IntoIterator<Item = (&'items OsStr, &'items OsStr)>,
        I::IntoIter: ExactSizeIterator,
    {
        let owns_item_summary = self.session.begin_item_summary();
        let handle = (|| {
            if self.session.is_output_exhausted() {
                return self.exhausted_handle();
            }
            let Some(pairs) = self.collect_admitted_pairs(pairs) else {
                return self
                    .session
                    .stage_accounted_text(crate::RedactedText::from_escaped(String::new()));
            };
            let result = redact_os_pairs_with_policy(
                self.session.policy(),
                pairs,
                self.session.remaining_output_bytes(),
            );
            if result.text().as_str().is_empty()
                && result.summary().completion() == crate::RedactionCompletion::Truncated
            {
                return self.exhausted_handle();
            }
            self.session.stage_item(result)
        })();
        self.session.end_item_summary(owns_item_summary);
        handle
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
        I::IntoIter: ExactSizeIterator,
    {
        if !self.session.admit_format_node(1) {
            return None;
        }
        let mut iterator = pairs.into_iter();
        // Iterator length is caller-controlled metadata. Allocate only after
        // an entry has passed the transaction's shared admission checks.
        let mut admitted = Vec::new();
        while iterator.len() > 0 {
            if !self.session.admit_format_collection_item() || !self.session.admit_format_node(2) {
                return None;
            }
            let (name, value) = iterator
                .next()
                .expect("exact-size iterator reported an item");
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

    /// Stages the standard empty output after shared output exhaustion.
    #[must_use]
    fn exhausted_handle(&mut self) -> RedactionHandle {
        self.session.stage_format_text(
            crate::RedactedText::from_escaped(String::new()),
            crate::RedactionCompletion::Exhausted,
        )
    }
}
