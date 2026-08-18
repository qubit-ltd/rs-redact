// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared-session argument-vector redaction.

use super::ArgvItem;
use super::ArgvRedactor;
use super::RedactedArgv;
use crate::RedactionSession;
use crate::Redactor;

/// A borrowed argv façade over one mutable diagnostic session.
pub struct ArgvRedactionSession<'session, 'policy> {
    /// Shared policy and accounting owned by the parent session.
    session: &'session mut RedactionSession<'policy>,
}

impl<'session, 'policy> ArgvRedactionSession<'session, 'policy> {
    /// Creates a façade from a mutable diagnostic session.
    #[inline(always)]
    #[must_use]
    pub(crate) const fn new(session: &'session mut RedactionSession<'policy>) -> Self {
        Self { session }
    }

    /// Redacts items and stages the committed result under `key`.
    pub fn redact_items_as<'items, I>(&mut self, key: &str, items: I) -> &mut Self
    where
        I: IntoIterator<Item = ArgvItem<'items>>,
        I::IntoIter: ExactSizeIterator,
    {
        if !self.session.prepare_key(key) {
            return self;
        }
        let result = self.redact_items(items);
        let completion = result.completion();
        self.session.stage_text(key, result.into_log_safe_text(), completion);
        self
    }

    /// Redacts heuristic items and stages the committed result under `key`.
    pub fn redact_heuristically_as<'items, I>(&mut self, key: &str, items: I) -> &mut Self
    where
        I: IntoIterator<Item = ArgvItem<'items>>,
        I::IntoIter: ExactSizeIterator,
    {
        if !self.session.prepare_key(key) {
            return self;
        }
        let result = self.redact_heuristically(items);
        let completion = result.completion();
        self.session.stage_text(key, result.into_log_safe_text(), completion);
        self
    }

    /// Redacts explicitly classified argument items.
    ///
    /// Input is pulled lazily. Once the shared input or output budget is
    /// exhausted, the iterator is not advanced again and only a safe marker
    /// or empty value is returned. The result reports `Complete` only after
    /// observing iterator exhaustion, `Truncated` for non-empty safe output
    /// with any omission, and `Exhausted` for empty output.
    #[must_use]
    pub fn redact_items<'items, I>(&mut self, items: I) -> RedactedArgv
    where
        I: IntoIterator<Item = ArgvItem<'items>>,
        I::IntoIter: ExactSizeIterator,
    {
        ArgvRedactor::new(Redactor::new(self.session.policy().clone())).redact_items(items)
    }

    /// Redacts explicit items and heuristically classifies plain items.
    ///
    /// Input is pulled lazily and never inspected after the shared session has
    /// reached its terminal output or input boundary. The result reports
    /// `Complete` only after observing iterator exhaustion, `Truncated` for
    /// non-empty safe output with any omission, and `Exhausted` for empty
    /// output.
    #[must_use]
    pub fn redact_heuristically<'items, I>(&mut self, items: I) -> RedactedArgv
    where
        I: IntoIterator<Item = ArgvItem<'items>>,
        I::IntoIter: ExactSizeIterator,
    {
        ArgvRedactor::new(Redactor::new(self.session.policy().clone())).redact_heuristically(items)
    }
}
