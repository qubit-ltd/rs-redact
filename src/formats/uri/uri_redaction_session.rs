// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! URI operations backed by one mutable diagnostic session.

use super::UriRedaction;
use super::uri_redactor::redact_uri_str_bounded;
use crate::RedactionSession;

/// URI facade borrowing one diagnostic session.
pub struct UriRedactionSession<'session, 'policy> {
    session: &'session mut RedactionSession<'policy>,
}

impl<'session, 'policy> UriRedactionSession<'session, 'policy> {
    /// Creates a URI facade borrowing a parent session.
    pub(crate) const fn new(session: &'session mut RedactionSession<'policy>) -> Self {
        Self { session }
    }

    /// Redacts a URI and stages it under `key`.
    pub fn redact_uri(&mut self, key: &str, value: &str) -> &mut Self {
        if !self.session.prepare_key(key) {
            return self;
        }
        let result = self.redact_uri_direct(value);
        let completion = result.completion();
        self.session.stage_text(key, result.into_log_safe_text(), completion);
        self
    }
}

impl UriRedactionSession<'_, '_> {
    /// Redacts one URI while charging the shared input and output budgets.
    ///
    /// Input is admitted before parsing. If the session has no output left,
    /// this method returns an empty fail-closed result without inspecting the
    /// URI. A component-level output limit can truncate this result while the
    /// session remains usable; exhaustion of the shared output budget closes
    /// the session for later operations. The returned completion is `Complete`
    /// for a full safe rewrite, `Truncated` for non-empty fallback or omitted
    /// output, and `Exhausted` only when the safe text is empty. Existing URI
    /// status and reason metadata keep their independent meanings.
    #[must_use]
    pub(crate) fn redact_uri_direct(&mut self, input: &str) -> UriRedaction {
        let policy = self.session.policy();
        let (result, _) = redact_uri_str_bounded(policy, input, usize::MAX, false);
        result
    }
}
