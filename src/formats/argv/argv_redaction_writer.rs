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
///
/// # Type Parameters
///
/// * `'session` - Borrow of the parent composer's unpublished transaction.
///
/// # Examples
///
/// ```
/// use std::ffi::OsStr;
/// use qubit_redact::{Redactor, Sensitivity};
/// use qubit_redact::formats::argv::ArgvItem;
///
/// let output = Redactor::standard().text_composer().argv(|argv| {
///     argv.items([ArgvItem::sensitive(OsStr::new("raw-token"), Sensitivity::Secret)]);
/// }).finish();
/// assert!(!output.text().as_str().contains("raw-token"));
/// ```
pub struct ArgvRedactionWriter<'session> {
    /// Shared policy and accounting owned by the parent session.
    session: &'session mut TextSession,
}

impl<'session> ArgvRedactionWriter<'session> {
    /// Creates a façade from a mutable diagnostic session.
    ///
    /// # Parameters
    ///
    /// * `session` - Parent transaction receiving all admitted arguments.
    ///
    /// # Returns
    ///
    /// A writer borrowing the transaction's existing policy and budget.
    #[inline(always)]
    #[must_use]
    pub(crate) const fn new(session: &'session mut TextSession) -> Self {
        Self { session }
    }

    /// Redacts items into the parent session's aggregate output.
    ///
    /// Plain items retain their values; use [`Self::heuristic_items`] to infer
    /// sensitivity from supported option syntax. Iterator advancement stops
    /// when shared structural admission fails or output is already closed.
    ///
    /// # Type Parameters
    ///
    /// * `'items` - Lifetime of borrowed argument values.
    /// * `I` - Finite source of explicitly classified argument items.
    ///
    /// # Parameters
    ///
    /// * `items` - Arguments in their original command-line order.
    ///
    /// # Returns
    ///
    /// This writer for further operations in the same transaction.
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
    ///
    /// Supported option syntax is interpreted only for plain items; explicit
    /// sensitivity is authoritative. This operation does not parse shell code.
    ///
    /// # Type Parameters
    ///
    /// * `'items` - Lifetime of borrowed argument values.
    /// * `I` - Finite source of arguments to classify and render.
    ///
    /// # Parameters
    ///
    /// * `items` - Arguments in their original command-line order.
    ///
    /// # Returns
    ///
    /// This writer for further operations in the same transaction.
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
