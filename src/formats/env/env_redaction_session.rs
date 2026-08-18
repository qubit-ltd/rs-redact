// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared-session environment redaction.

use std::ffi::OsStr;

use super::EnvRedactor;
use super::RedactedEnv;
use super::RedactedEnvPair;
use crate::RedactionSession;
use crate::Redactor;

/// A borrowed environment façade over one mutable diagnostic session.
pub struct EnvRedactionSession<'session, 'policy> {
    /// Shared policy and accounting owned by the parent session.
    session: &'session mut RedactionSession<'policy>,
}

impl<'session, 'policy> EnvRedactionSession<'session, 'policy> {
    /// Creates a façade from a mutable diagnostic session.
    #[inline(always)]
    #[must_use]
    pub(crate) const fn new(session: &'session mut RedactionSession<'policy>) -> Self {
        Self { session }
    }

    /// Redacts one pair and stages the committed result under `key`.
    pub fn redact_pair_as(&mut self, key: &str, name: &str, value: &str) -> &mut Self {
        if !self.session.prepare_key(key) {
            return self;
        }
        let result = self.redact_pair(name, value);
        let completion = result.completion();
        self.session.stage_text(key, result.into_log_safe_text(), completion);
        self
    }

    /// Redacts an environment list and stages it under `key`.
    pub fn redact_os_pairs_as<'items, I>(&mut self, key: &str, pairs: I) -> &mut Self
    where
        I: IntoIterator<Item = (&'items OsStr, &'items OsStr)>,
        I::IntoIter: ExactSizeIterator,
    {
        if !self.session.prepare_key(key) {
            return self;
        }
        let result = self.redact_os_pairs(pairs);
        let completion = result.completion();
        self.session.stage_text(key, result.into_log_safe_text(), completion);
        self
    }

    /// Redacts one UTF-8 environment pair.
    #[must_use]
    pub fn redact_pair(&mut self, name: &str, value: &str) -> RedactedEnvPair {
        self.redact_os_pair(OsStr::new(name), OsStr::new(value))
    }

    /// Redacts one possibly non-UTF-8 environment pair.
    #[must_use]
    pub fn redact_os_pair(&mut self, name: &OsStr, value: &OsStr) -> RedactedEnvPair {
        EnvRedactor::new(Redactor::new(self.session.policy().clone())).redact_os_pair(name, value)
    }

    /// Redacts a lazily supplied list of environment pairs.
    ///
    /// Pairs are admitted and pulled one at a time. A complete batch preserves
    /// its debug-style list, a truncated batch contains non-empty safe
    /// substitute text, and exhaustion returns empty safe text without
    /// advancing `pairs` again.
    ///
    /// # Type Parameters
    ///
    /// * `'items` - Lifetime of names and values yielded by `pairs`.
    /// * `I` - Iterator source yielding borrowed environment pairs.
    ///
    /// # Parameters
    ///
    /// * `pairs` - Lazily supplied environment names and values.
    ///
    /// # Returns
    ///
    /// A [`RedactedEnv`] carrying the batch text and exact completion state.
    #[must_use]
    pub fn redact_os_pairs<'items, I>(&mut self, pairs: I) -> RedactedEnv
    where
        I: IntoIterator<Item = (&'items OsStr, &'items OsStr)>,
        I::IntoIter: ExactSizeIterator,
    {
        EnvRedactor::new(Redactor::new(self.session.policy().clone())).redact_os_pairs(pairs)
    }
}
