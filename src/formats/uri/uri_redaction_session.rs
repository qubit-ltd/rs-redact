// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! URI operations backed by one mutable diagnostic session.

use super::UriRedaction;
use super::UriRedactionReason;
use super::uri_redactor::empty_invalid_result;
use super::uri_redactor::invalid_result;
use super::uri_redactor::redact_uri_str_bounded;
use crate::RedactionSession;
use crate::policy::RedactionAdmission;

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
    pub fn redact_uri_as(&mut self, key: &str, value: &str) -> &mut Self {
        let result = self.redact_uri_str(value);
        let completion = result.completion();
        self.session.stage_text(key, result.into_log_safe_text(), completion);
        self
    }
}

impl<'policy> RedactionSession<'policy> {
    /// Configures the URI adapter inside a chainable session.
    #[must_use]
    pub fn uri_with<F>(mut self, configure: F) -> Self
    where
        F: for<'session> FnOnce(&mut UriRedactionSession<'session, 'policy>),
    {
        let mut adapter = UriRedactionSession { session: &mut self };
        configure(&mut adapter);
        self
    }

    /// Runs one URI operation through a borrowed closure adapter.
    #[must_use]
    #[inline(always)]
    pub fn uri_with_mut<F, R>(&mut self, configure: F) -> R
    where
        F: for<'session> FnOnce(&mut UriRedactionSession<'session, 'policy>) -> R,
    {
        let mut adapter = UriRedactionSession { session: self };
        configure(&mut adapter)
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
    pub fn redact_uri_str(&mut self, input: &str) -> UriRedaction {
        let domain_output_limit = self.session.policy().limits().diagnostic_event().max_output_bytes();
        let admission = self
            .session
            .admit(input.len(), domain_output_limit, "<invalid URI>".len());
        match admission {
            RedactionAdmission::Fallback => invalid_result(UriRedactionReason::InputLimitExceeded),
            RedactionAdmission::Exhausted => empty_invalid_result(UriRedactionReason::OutputTruncated),
            RedactionAdmission::Render { max_output_bytes } => {
                let session_limited = max_output_bytes < domain_output_limit;
                let policy = self.session.policy();
                let (result, completion) = redact_uri_str_bounded(policy, input, max_output_bytes, session_limited);
                self.session
                    .commit_output(result.log_safe_text().as_str().len(), completion);
                result
            }
        }
    }
}
