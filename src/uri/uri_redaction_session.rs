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
use super::uri_redactor::redact_uri_str_bounded;
use super::uri_redactor::{empty_invalid_result, invalid_result};
use crate::RedactionSession;
use crate::policy::RedactionAdmission;

/// URI facade borrowing one diagnostic session.
pub struct UriRedactionSession<'session, 'policy> {
    session: &'session mut RedactionSession<'policy>,
}

impl<'policy> RedactionSession<'policy> {
    /// Creates a URI facade backed by this session's policy and budgets.
    #[must_use = "use the URI facade to redact input"]
    #[inline]
    pub fn uri(&mut self) -> UriRedactionSession<'_, 'policy> {
        UriRedactionSession { session: self }
    }
}

impl UriRedactionSession<'_, '_> {
    /// Redacts one URI while charging the shared input and output budgets.
    ///
    /// Input is admitted before parsing. If the session has no output left,
    /// this method returns an empty fail-closed result without inspecting the
    /// URI. A component-level output limit can truncate this result while the
    /// session remains usable; exhaustion of the shared output budget closes
    /// the session for later operations.
    #[must_use = "use the structured URI redaction result"]
    pub fn redact_uri_str(&mut self, input: &str) -> UriRedaction {
        let domain_output_limit = self
            .session
            .policy()
            .limits()
            .diagnostic_event()
            .max_output_bytes();
        let admission = self
            .session
            .admit(input.len(), domain_output_limit, "<invalid URI>".len());
        match admission {
            RedactionAdmission::Fallback => invalid_result(UriRedactionReason::InputLimitExceeded),
            RedactionAdmission::Exhausted => {
                empty_invalid_result(UriRedactionReason::OutputTruncated)
            }
            RedactionAdmission::Render { max_output_bytes } => {
                let session_limited = max_output_bytes < domain_output_limit;
                let policy = self.session.policy();
                let (result, completion) =
                    redact_uri_str_bounded(policy, input, max_output_bytes, session_limited);
                self.session
                    .commit_output(result.log_safe_text().as_str().len(), completion);
                result
            }
        }
    }
}
