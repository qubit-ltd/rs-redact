// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable accounting for one bounded diagnostic redaction event.

use std::collections::BTreeMap;

use super::DomainRedactionContext;
use super::DomainTruncation;
use super::DomainTruncationCheckpoint;
use super::redaction_session_error::RedactionSessionError;
use super::redaction_session_output::RedactionSessionOutput;
use crate::FieldRedaction;
use crate::RedactionCompletion;
use crate::Sensitivity;
use crate::domain::Redact;
use crate::facade::redactor::redact_field_unbudgeted;
use crate::facade::redactor::redaction_output;
use crate::formats::argv::ArgvRedactionSession;
use crate::formats::env::EnvRedactionSession;
#[cfg(feature = "http")]
use crate::formats::http::HttpRedactionSession;
#[cfg(feature = "json")]
use crate::formats::json::JsonRedactionSession;
use crate::output::MaskedValue;
use crate::facade::RedactionOutput;
use crate::policy::DomainTraversalAdmission;
use crate::policy::DomainValueAdmission;
use crate::policy::DomainValueScope;
use crate::policy::RedactionPolicy;
use crate::runtime::DomainValueBudgetAdmission;

/// Carries one immutable policy and one mutable budget through a diagnostic
/// event.
#[derive(Debug)]
pub struct RedactionSession<'policy> {
    policy: &'policy RedactionPolicy,
    pub(super) domain_context: DomainRedactionContext,
    pub(super) fragments: String,
    staged: BTreeMap<String, crate::RedactionOutput>,
    summary: crate::RedactionSummary,
    session_error: Option<RedactionSessionError>,
}

impl<'policy> RedactionSession<'policy> {
    /// Creates diagnostic accounting from `policy`.
    #[must_use]
    #[inline]
    pub(crate) fn new(policy: &'policy RedactionPolicy) -> Self {
        Self {
            policy,
            domain_context: DomainRedactionContext::new(policy.limits().domain()),
            fragments: String::new(),
            staged: BTreeMap::new(),
            summary: crate::RedactionSummary::complete(),
            session_error: None,
        }
    }

    /// Returns the immutable policy snapshot used by this session.
    #[inline(always)]
    #[must_use]
    pub const fn policy(&self) -> &'policy RedactionPolicy {
        self.policy
    }

    /// Appends trusted program-authored context text.
    #[must_use]
    pub fn text(&mut self, text: &'static str) -> &mut Self {
        if self.session_error.is_some() {
            return self;
        }
        self.reset_fragment_budget();
        self.append_chain_fragment(text);
        self
    }

    /// Redacts and appends one scalar field in chain order.
    #[must_use]
    pub fn field(&mut self, field: &str, value: &str) -> &mut Self {
        if !self.prepare_key(field) {
            return self;
        }
        self.reset_fragment_budget();
        let rendered = self.redact_field_output(field, value);
        let text = rendered.log_safe_text().as_str().to_owned();
        self.fragments.push_str(&text);
        let summary = match rendered.completion() {
            crate::RedactionCompletion::Complete => crate::RedactionSummary::complete(),
            crate::RedactionCompletion::Truncated => {
                crate::RedactionSummary::truncated(crate::RedactionReason::TraversalLimitReached)
            }
        };
        self.stage(
            field,
            crate::RedactionOutput::new(crate::RedactedText::from_escaped(text), summary),
        );
        self
    }

    /// Redacts and appends one structured domain value in chain order.
    #[must_use]
    pub fn value<T>(&mut self, name: &str, value: &T) -> &mut Self
    where
        T: Redact,
    {
        if !self.prepare_key(name) {
            return self;
        }
        self.reset_fragment_budget();
        let mut writer = crate::domain::RedactionWriter::new_root(self);
        value.write_redacted(&mut writer);
        let rendered = writer.finish();
        self.append_committed_output(&rendered);
        self.stage(
            name,
            crate::RedactionOutput::new(crate::RedactedText::from_escaped(rendered), crate::RedactionSummary::complete()),
        );
        self
    }

    /// Runs an argv adapter while retaining the session borrow.
    pub fn argv<F>(&mut self, configure: F) -> &mut Self
    where
        F: for<'session> FnOnce(&mut ArgvRedactionSession<'session, 'policy>),
    {
        if self.session_error.is_some() {
            return self;
        }
        self.reset_fragment_budget();
        let mut adapter = ArgvRedactionSession::new(self);
        configure(&mut adapter);
        self
    }

    /// Runs an environment adapter while retaining the session borrow.
    pub fn env<F>(&mut self, configure: F) -> &mut Self
    where
        F: for<'session> FnOnce(&mut EnvRedactionSession<'session, 'policy>),
    {
        if self.session_error.is_some() {
            return self;
        }
        self.reset_fragment_budget();
        let mut adapter = EnvRedactionSession::new(self);
        configure(&mut adapter);
        self
    }

    /// Runs an HTTP adapter while retaining the session borrow.
    #[cfg(feature = "http")]
    pub fn http<F>(&mut self, configure: F) -> &mut Self
    where
        F: for<'session> FnOnce(&mut HttpRedactionSession<'session, 'policy>),
    {
        if self.session_error.is_some() {
            return self;
        }
        self.reset_fragment_budget();
        let mut adapter = HttpRedactionSession::new(self);
        configure(&mut adapter);
        self
    }

    /// Runs a JSON adapter while retaining the session borrow.
    #[cfg(feature = "json")]
    pub fn json<F>(&mut self, configure: F) -> &mut Self
    where
        F: for<'session> FnOnce(&mut JsonRedactionSession<'session, 'policy>),
    {
        if self.session_error.is_some() {
            return self;
        }
        self.reset_fragment_budget();
        let mut adapter = JsonRedactionSession::new(self);
        configure(&mut adapter);
        self
    }

    /// Runs a URI adapter while retaining the session borrow.
    #[cfg(feature = "uri")]
    pub fn uri<F>(&mut self, configure: F) -> &mut Self
    where
        F: for<'session> FnOnce(&mut crate::formats::uri::UriRedactionSession<'session, 'policy>),
    {
        if self.session_error.is_some() {
            return self;
        }
        self.reset_fragment_budget();
        let mut adapter = crate::formats::uri::UriRedactionSession::new(self);
        configure(&mut adapter);
        self
    }

    /// Charges and enters one domain value under the shared structure budget.
    ///
    /// Admission first honors permanent traversal closure, then checks active
    /// depth, and finally consumes one cumulative node. An entered value
    /// returns an RAII [`DomainValueScope`] that restores only active depth on
    /// drop. [`DomainValueAdmission::DepthLimitReached`] rejects just the
    /// current branch, while [`DomainValueAdmission::TraversalLimitReached`]
    /// means no later domain value may be accessed in this session.
    #[must_use]
    pub fn enter_domain_value<'session>(&'session mut self) -> DomainValueAdmission<'session, 'policy> {
        let checkpoint = self.domain_truncation_checkpoint();
        let admission = self.domain_context.enter_value();
        debug_assert!(match admission {
            DomainValueBudgetAdmission::Entered => {
                self.domain_truncation_since(checkpoint) == DomainTruncation::None
            }
            DomainValueBudgetAdmission::DepthLimitReached => {
                self.domain_truncation_since(checkpoint) == DomainTruncation::Depth
            }
            DomainValueBudgetAdmission::TraversalLimitReached => true,
        });
        match admission {
            DomainValueBudgetAdmission::Entered => DomainValueAdmission::Entered(DomainValueScope::new(self)),
            DomainValueBudgetAdmission::DepthLimitReached => DomainValueAdmission::DepthLimitReached,
            DomainValueBudgetAdmission::TraversalLimitReached => DomainValueAdmission::TraversalLimitReached,
        }
    }

    /// Begins a domain value for the structured writer without exposing an
    /// RAII scope to generated implementations.
    #[must_use]
    pub(crate) fn begin_domain_value(&mut self) -> bool {
        match self.domain_context.enter_value() {
            DomainValueBudgetAdmission::Entered => true,
            DomainValueBudgetAdmission::DepthLimitReached => false,
            DomainValueBudgetAdmission::TraversalLimitReached => false,
        }
    }

    /// Finishes a chain session and returns final text with its summary.
    pub fn finish(&mut self) -> Result<RedactionSessionOutput, RedactionSessionError> {
        let error = self.session_error.take();
        let text = std::mem::take(&mut self.fragments);
        let staged = std::mem::take(&mut self.staged);
        let summary = self.summary;
        self.domain_context = DomainRedactionContext::new(self.policy.limits().domain());
        self.summary = crate::RedactionSummary::complete();
        if let Some(error) = error {
            return Err(error);
        }
        let escaped =
            crate::output::log_escape::escape_log_control_characters(std::borrow::Cow::Owned(text)).into_owned();
        Ok(RedactionSessionOutput::new(
            crate::RedactedText::from_escaped(escaped),
            staged,
            summary,
        ))
    }

    /// Stages one already redacted result under a caller-owned string key.
    pub(crate) fn stage(&mut self, key: &str, output: crate::RedactionOutput) {
        if self.session_error.is_some() {
            return;
        }
        if key.is_empty() {
            self.session_error = Some(RedactionSessionError::EmptyKey);
        } else if self.staged.contains_key(key) {
            self.session_error = Some(RedactionSessionError::DuplicateKey { key: key.to_owned() });
        } else {
            self.summary = self.summary.merge(output.summary());
            self.staged.insert(key.to_owned(), output);
        }
    }

    /// Validates a result key before any caller-owned input is inspected.
    ///
    /// Session failures are sticky until `finish` resets the transaction. A
    /// failed key therefore prevents adapter closures and redactors from
    /// touching their source values.
    #[inline]
    pub(crate) fn prepare_key(&mut self, key: &str) -> bool {
        if self.session_error.is_some() {
            return false;
        }
        if key.is_empty() {
            self.session_error = Some(RedactionSessionError::EmptyKey);
            return false;
        }
        if self.staged.contains_key(key) {
            self.session_error = Some(RedactionSessionError::DuplicateKey { key: key.to_owned() });
            return false;
        }
        true
    }

    /// Stages safe text and its completion under a key.
    pub(crate) fn stage_text(&mut self, key: &str, text: crate::RedactedText, completion: crate::RedactionCompletion) {
        let summary = match completion {
            crate::RedactionCompletion::Complete => crate::RedactionSummary::complete(),
            crate::RedactionCompletion::Truncated => {
                crate::RedactionSummary::truncated(crate::RedactionReason::TraversalLimitReached)
            }
        };
        if self.session_error.is_none() {
            self.fragments.push_str(text.as_str());
        }
        self.stage(key, crate::RedactionOutput::new(text, summary));
    }

    /// Resets only the per-operation legacy accounting retained by transitional
    /// facades.
    fn reset_fragment_budget(&mut self) {
    }

    /// Appends a chain fragment at a UTF-8 boundary within remaining output.
    fn append_chain_fragment(&mut self, fragment: &str) {
        self.fragments.push_str(fragment);
    }

    /// Returns a checkpoint for detecting later domain traversal truncation.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn domain_truncation_checkpoint(&self) -> DomainTruncationCheckpoint {
        self.domain_context.truncation_checkpoint()
    }

    /// Classifies domain truncation recorded after `checkpoint`.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn domain_truncation_since(&self, checkpoint: DomainTruncationCheckpoint) -> DomainTruncation {
        self.domain_context.truncation_since(checkpoint)
    }

    /// Charges one domain field before its value is accessed.
    #[must_use]
    #[inline(always)]
    pub(crate) fn admit_domain_field(&mut self) -> DomainTraversalAdmission {
        self.domain_context.admit_field()
    }

    /// Charges one domain collection item before its iterator advances.
    #[must_use]
    #[inline(always)]
    pub(crate) fn admit_domain_collection_item(&mut self) -> DomainTraversalAdmission {
        self.domain_context.admit_collection_item()
    }

    /// Releases one active domain-value depth while preserving cumulative
    /// charges.
    #[inline(always)]
    pub(crate) fn leave_domain_value(&mut self) {
        self.domain_context.leave_value();
    }

    /// Appends output whose bytes were already committed by a structured
    /// writer frame.
    #[inline(always)]
    pub(crate) fn append_committed_output(&mut self, output: &str) {
        self.fragments.push_str(output);
    }

}

impl RedactionSession<'_> {
    /// Redacts one field through this diagnostic event's shared budget.
    #[must_use]
    pub fn redact_field<'value>(&mut self, field: &str, value: &'value str) -> FieldRedaction<'value> {
        let (redacted, _) = self.redact_field_with_completion(field, value);
        redacted
    }

    /// Redacts one field into owned safe text with its fragment completion.
    pub(crate) fn redact_field_output(&mut self, field: &str, value: &str) -> RedactionOutput {
        let (redacted, completion) = self.redact_field_with_completion(field, value);
        redaction_output(redacted.escape_for_log(), completion)
    }

    fn redact_field_with_completion<'value>(
        &mut self,
        field: &str,
        value: &'value str,
    ) -> (FieldRedaction<'value>, RedactionCompletion) {
        let policy = self.policy();
        let (redacted, _) = redact_field_unbudgeted(policy, field, value, usize::MAX);
        (redacted, RedactionCompletion::Complete)
    }

    /// Redacts one explicitly sensitive value through this diagnostic event.
    #[must_use]
    pub fn redact_at<'value>(&mut self, level: Sensitivity, value: &'value str) -> MaskedValue<'value> {
        let (redacted, _) = self.redact_at_with_completion(level, value);
        redacted
    }

    /// Redacts one sensitive value into owned safe text with its completion.
    pub(crate) fn redact_at_output(&mut self, level: Sensitivity, value: &str) -> RedactionOutput {
        let (redacted, completion) = self.redact_at_with_completion(level, value);
        redaction_output(redacted.escape_for_log(), completion)
    }

    fn redact_at_with_completion<'value>(
        &mut self,
        level: Sensitivity,
        value: &'value str,
    ) -> (MaskedValue<'value>, RedactionCompletion) {
        let policy = self.policy();
        let masked = policy.masking().mask(level, value);
        (MaskedValue::new(masked), RedactionCompletion::Complete)
    }
}
