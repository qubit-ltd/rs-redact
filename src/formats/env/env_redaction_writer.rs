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
///
/// # Type Parameters
///
/// * `'session` - Borrow of the parent composer's unpublished transaction.
///
/// # Examples
///
/// ```
/// use qubit_redact::Redactor;
///
/// let output = Redactor::standard().text_composer().env(|env| {
///     env.pair("PASSWORD", "raw-password");
/// }).finish();
/// assert!(!output.text().as_str().contains("raw-password"));
/// ```
pub struct EnvRedactionWriter<'session> {
    /// Shared policy and accounting owned by the parent session.
    session: &'session mut TextSession,
}

impl<'session> EnvRedactionWriter<'session> {
    /// Creates a façade from a mutable diagnostic session.
    ///
    /// # Parameters
    ///
    /// * `session` - Parent transaction receiving admitted environment pairs.
    ///
    /// # Returns
    ///
    /// A writer borrowing the transaction's existing policy and budget.
    #[inline(always)]
    #[must_use]
    pub(crate) const fn new(session: &'session mut TextSession) -> Self {
        Self { session }
    }

    /// Redacts one pair into the parent session's aggregate output.
    ///
    /// The name selects field policy; both name and value bytes consume the
    /// parent's input allowance before rendering the assignment.
    ///
    /// # Parameters
    ///
    /// * `name` - Environment variable name used for classification.
    /// * `value` - Borrowed value to redact or preserve under that policy.
    ///
    /// # Returns
    ///
    /// This writer for further operations in the same transaction.
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
    ///
    /// Iterator advancement is guarded by shared structural admission.
    /// Non-Unicode pairs use the format's bounded fallback policy.
    ///
    /// # Type Parameters
    ///
    /// * `'items` - Lifetime of borrowed operating-system names and values.
    /// * `I` - Finite source of environment pairs.
    ///
    /// # Parameters
    ///
    /// * `pairs` - Name/value pairs in the desired diagnostic order.
    ///
    /// # Returns
    ///
    /// This writer for further operations in the same transaction.
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
