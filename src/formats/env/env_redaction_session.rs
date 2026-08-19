// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared-session environment redaction.

use std::ffi::OsStr;

use super::env_redactor::redact_os_pairs_with_policy;
use super::env_redactor::redact_pair_with_policy;
use crate::RedactionHandle;
use crate::RedactionSession;

/// A borrowed environment façade over one mutable diagnostic session.
pub struct EnvRedactionSession<'session> {
    /// Shared policy and accounting owned by the parent session.
    session: &'session mut RedactionSession,
}

impl<'session> EnvRedactionSession<'session> {
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
            || !self.session.admit_input(name.len().saturating_add(value.len()))
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
        let result = redact_os_pairs_with_policy(self.session.policy(), pairs, self.session.remaining_output_bytes());
        self.session.append_format_output(&result);
        self
    }

    /// Redacts one pair as an individually resolvable transaction item.
    #[must_use]
    pub fn redact_pair(&mut self, name: &str, value: &str) -> RedactionHandle {
        if self.session.is_output_exhausted() {
            return self.session.stage_format_text(
                crate::RedactedText::from_escaped(String::new()),
                crate::RedactionCompletion::Exhausted,
            );
        }
        if !self.session.admit_format_node(1)
            || !self.session.admit_format_collection_item()
            || !self.session.admit_format_node(2)
            || !self.session.admit_input(name.len().saturating_add(value.len()))
        {
            return self.session.stage_format_text(
                crate::RedactedText::from_escaped(String::new()),
                crate::RedactionCompletion::Truncated,
            );
        }
        let result = redact_pair_with_policy(
            self.session.policy(),
            name,
            value,
            self.session.remaining_output_bytes(),
        );
        if result.text().as_str().is_empty() && result.summary().completion() == crate::RedactionCompletion::Truncated {
            return self.session.stage_format_text(
                crate::RedactedText::from_escaped(String::new()),
                crate::RedactionCompletion::Exhausted,
            );
        }
        self.session.stage_item(result)
    }

    /// Redacts an environment list as one individually resolvable transaction
    /// item.
    #[must_use]
    pub fn redact_os_pairs<'items, I>(&mut self, pairs: I) -> RedactionHandle
    where
        I: IntoIterator<Item = (&'items OsStr, &'items OsStr)>,
        I::IntoIter: ExactSizeIterator,
    {
        if self.session.is_output_exhausted() {
            return self.session.stage_format_text(
                crate::RedactedText::from_escaped(String::new()),
                crate::RedactionCompletion::Exhausted,
            );
        }
        let Some(pairs) = self.collect_admitted_pairs(pairs) else {
            return self.session.stage_format_text(
                crate::RedactedText::from_escaped(String::new()),
                crate::RedactionCompletion::Truncated,
            );
        };
        let result = redact_os_pairs_with_policy(self.session.policy(), pairs, self.session.remaining_output_bytes());
        if result.text().as_str().is_empty() && result.summary().completion() == crate::RedactionCompletion::Truncated {
            return self.session.stage_format_text(
                crate::RedactedText::from_escaped(String::new()),
                crate::RedactionCompletion::Exhausted,
            );
        }
        self.session.stage_item(result)
    }

    /// Collects pairs only while their individual structural and input
    /// admissions succeed. This deliberately avoids materializing or
    /// rendering the suffix after a shared transaction limit is reached.
    fn collect_admitted_pairs<'items, I>(&mut self, pairs: I) -> Option<Vec<(&'items OsStr, &'items OsStr)>>
    where
        I: IntoIterator<Item = (&'items OsStr, &'items OsStr)>,
        I::IntoIter: ExactSizeIterator,
    {
        if !self.session.admit_format_node(1) {
            return None;
        }
        let mut iterator = pairs.into_iter();
        let mut admitted = Vec::with_capacity(iterator.len());
        while iterator.len() > 0 {
            if !self.session.admit_format_collection_item() || !self.session.admit_format_node(2) {
                return None;
            }
            let (name, value) = iterator.next().expect("exact-size iterator reported an item");
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
