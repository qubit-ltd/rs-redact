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
    pub fn redact_pair(&mut self, key: &str, name: &str, value: &str) -> &mut Self {
        if !self.session.prepare_key(key) {
            return self;
        }
        let result = EnvRedactor::new(Redactor::new(self.session.policy().clone())).redact_pair(name, value);
        let completion = result.completion();
        self.session.stage_text(key, result.into_log_safe_text(), completion);
        self
    }

    /// Redacts an environment list and stages it under `key`.
    pub fn redact_os_pairs<'items, I>(&mut self, key: &str, pairs: I) -> &mut Self
    where
        I: IntoIterator<Item = (&'items OsStr, &'items OsStr)>,
        I::IntoIter: ExactSizeIterator,
    {
        if !self.session.prepare_key(key) {
            return self;
        }
        let result = EnvRedactor::new(Redactor::new(self.session.policy().clone())).redact_os_pairs(pairs);
        let completion = result.completion();
        self.session.stage_text(key, result.into_log_safe_text(), completion);
        self
    }
}
