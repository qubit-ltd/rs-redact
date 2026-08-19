// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable accounting for one bounded diagnostic redaction event.

use std::ffi::OsStr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use super::DomainEntry;
use super::redaction_session_output::RedactionSessionOutput;
use super::transaction_guard::TransactionGuard;
use super::transaction_state::TransactionState;
use crate::RedactionCompletion;
use crate::RedactionHandle;
use crate::domain::Redact;
use crate::facade::RedactionOutput;
use crate::facade::redactor::redact_field_text_for_output;
use crate::facade::redactor::redaction_output;
use crate::formats::argv::ArgvRedactionSession;
use crate::formats::env::EnvRedactionSession;
#[cfg(feature = "http")]
use crate::formats::http::HttpRedactionSession;
#[cfg(feature = "json")]
use crate::formats::json::JsonRedactionSession;
use crate::formats::process::ProcessRedactionSession;
use crate::policy::RedactionPolicy;

/// Allocates transaction identities across every session in this process.
///
/// A handle is valid only for the exact transaction that published it, so a
/// per-session counter would allow two independent sessions to collide.
static NEXT_TRANSACTION_ID: AtomicU64 = AtomicU64::new(1);

#[inline(always)]
fn next_transaction_id() -> u64 {
    NEXT_TRANSACTION_ID.fetch_add(1, Ordering::Relaxed)
}

/// Carries one immutable policy and one mutable budget through a diagnostic
/// event.
#[derive(Debug)]
pub struct RedactionSession {
    policy: Arc<RedactionPolicy>,
    transaction: TransactionState,
}

impl std::ops::Deref for RedactionSession {
    type Target = TransactionState;

    fn deref(&self) -> &Self::Target {
        &self.transaction
    }
}

impl std::ops::DerefMut for RedactionSession {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.transaction
    }
}

impl RedactionSession {
    /// Creates a session that owns a policy snapshot shared with its redactor.
    #[must_use]
    pub(crate) fn from_snapshot(policy: Arc<RedactionPolicy>) -> RedactionSession {
        RedactionSession {
            transaction: TransactionState::new(policy.as_ref(), next_transaction_id()),
            policy,
        }
    }

    /// Returns the immutable policy snapshot used by this session.
    #[inline(always)]
    #[must_use]
    pub fn policy(&self) -> &RedactionPolicy {
        self.policy.as_ref()
    }

    /// Appends trusted program-authored literal text to the aggregate output.
    #[must_use]
    #[inline(always)]
    pub fn literal(&mut self, text: &'static str) -> &mut Self {
        self.append_output_fragment(text);
        self
    }

    /// Redacts and appends one scalar field in chain order.
    #[must_use]
    pub fn field(&mut self, field: &str, value: &str) -> &mut Self {
        if self.is_output_exhausted() {
            return self;
        }
        if !self.admit_input(field.len().saturating_add(value.len())) {
            return self;
        }
        let rendered = self.redact_field_output(field, value);
        self.append_format_output(&rendered);
        self
    }

    /// Redacts and appends one structured domain value in chain order.
    ///
    /// If user-provided redaction code panics, this method discards the entire
    /// active transaction, installs a fresh transaction, and resumes unwinding.
    #[must_use]
    pub fn value<T>(&mut self, value: &T) -> &mut Self
    where
        T: Redact + ?Sized,
    {
        if self.is_output_exhausted() {
            return self;
        }
        let mut guard = TransactionGuard::new(self);
        let rendered = {
            let session = guard.session();
            let mut writer = crate::domain::RedactionWriter::new_root(session);
            value.write_redacted(&mut writer);
            writer.finish_with_completion()
        };
        guard.commit();
        self.append_domain_output(&rendered.0, rendered.2);
        self
    }

    /// Redacts one structured domain value as an individually resolvable item.
    ///
    /// A panic from user-provided redaction code rolls back the complete active
    /// transaction before this method resumes unwinding.
    #[must_use]
    pub fn redact_value<T>(&mut self, value: &T) -> RedactionHandle
    where
        T: Redact + ?Sized,
    {
        if self.is_output_exhausted() {
            return self.stage_exhausted_handle();
        }
        self.run_handle(|session| {
            let mut writer = crate::domain::RedactionWriter::new_root(session);
            value.write_redacted(&mut writer);
            let rendered = writer.finish_with_completion();
            let escaped = crate::output::log_escape::escape_log_control_characters(std::borrow::Cow::Owned(rendered.0))
                .into_owned();
            if rendered.2 {
                session.record_summary(crate::RedactionSummary::truncated(
                    crate::RedactionReason::OutputLimitReached,
                ));
            }
            session.stage_domain_item(crate::RedactedText::from_escaped(escaped))
        })
    }

    /// Runs an argv adapter while retaining the session borrow.
    pub fn argv<F>(&mut self, configure: F) -> &mut Self
    where
        F: for<'session> FnOnce(&mut ArgvRedactionSession<'session>),
    {
        if self.is_output_exhausted() {
            return self;
        }
        self.run_adapter(|session| {
            let mut adapter = ArgvRedactionSession::new(session);
            configure(&mut adapter);
        });
        self
    }

    /// Redacts explicit argv items as one individually resolvable item.
    #[must_use]
    pub fn redact_argv<'items, I>(&mut self, items: I) -> RedactionHandle
    where
        I: IntoIterator<Item = crate::formats::argv::ArgvItem<'items>>,
        I::IntoIter: ExactSizeIterator,
    {
        if self.is_output_exhausted() {
            return self.stage_exhausted_handle();
        }
        self.run_handle(|session| ArgvRedactionSession::new(session).redact_items(items))
    }

    /// Runs an environment adapter while retaining the session borrow.
    pub fn env<F>(&mut self, configure: F) -> &mut Self
    where
        F: for<'session> FnOnce(&mut EnvRedactionSession<'session>),
    {
        if self.is_output_exhausted() {
            return self;
        }
        self.run_adapter(|session| {
            let mut adapter = EnvRedactionSession::new(session);
            configure(&mut adapter);
        });
        self
    }

    /// Redacts one environment assignment as an individually resolvable item.
    #[must_use]
    pub fn redact_env(&mut self, name: &str, value: &str) -> RedactionHandle {
        if self.is_output_exhausted() {
            return self.stage_exhausted_handle();
        }
        self.run_handle(|session| EnvRedactionSession::new(session).redact_pair(name, value))
    }

    /// Redacts environment assignments as one individually resolvable item.
    #[must_use]
    pub fn redact_env_pairs<'items, I>(&mut self, pairs: I) -> RedactionHandle
    where
        I: IntoIterator<Item = (&'items OsStr, &'items OsStr)>,
        I::IntoIter: ExactSizeIterator,
    {
        if self.is_output_exhausted() {
            return self.stage_exhausted_handle();
        }
        self.run_handle(|session| EnvRedactionSession::new(session).redact_os_pairs(pairs))
    }

    /// Runs a process-command adapter while retaining the session borrow.
    #[must_use]
    pub fn process<F>(&mut self, configure: F) -> &mut Self
    where
        F: for<'session> FnOnce(&mut ProcessRedactionSession<'session>),
    {
        if self.is_output_exhausted() {
            return self;
        }
        self.run_adapter(|session| {
            let mut adapter = ProcessRedactionSession::new(session);
            configure(&mut adapter);
        });
        self
    }

    /// Redacts one process command as an individually resolvable item.
    #[must_use]
    pub fn redact_process<'arguments, 'variables, A, E>(
        &mut self,
        program: &'arguments OsStr,
        arguments: A,
        variables: E,
    ) -> RedactionHandle
    where
        A: IntoIterator<Item = crate::formats::argv::ArgvItem<'arguments>>,
        A::IntoIter: ExactSizeIterator,
        E: IntoIterator<Item = (&'variables OsStr, &'variables OsStr)>,
        E::IntoIter: ExactSizeIterator,
    {
        if self.is_output_exhausted() {
            return self.stage_exhausted_handle();
        }
        self.run_handle(|session| ProcessRedactionSession::new(session).redact_command(program, arguments, variables))
    }

    /// Runs an HTTP adapter while retaining the session borrow.
    #[cfg(feature = "http")]
    pub fn http<F>(&mut self, configure: F) -> &mut Self
    where
        F: for<'session> FnOnce(&mut HttpRedactionSession<'session>),
    {
        if self.is_output_exhausted() {
            return self;
        }
        self.run_adapter(|session| {
            let mut adapter = HttpRedactionSession::new(session);
            configure(&mut adapter);
        });
        self
    }

    /// Redacts one HTTP URL as an individually resolvable item.
    #[cfg(feature = "http")]
    #[must_use]
    pub fn redact_http_url(&mut self, value: &str) -> RedactionHandle {
        if self.is_output_exhausted() {
            return self.stage_exhausted_handle();
        }
        self.run_handle(|session| HttpRedactionSession::new(session).redact_url(value))
    }

    /// Redacts an HTTP header collection as an individually resolvable item.
    #[cfg(feature = "http")]
    #[must_use]
    pub fn redact_http_headers(&mut self, headers: &http::HeaderMap) -> RedactionHandle {
        if self.is_output_exhausted() {
            return self.stage_exhausted_handle();
        }
        self.run_handle(|session| HttpRedactionSession::new(session).redact_headers(headers))
    }

    /// Redacts one captured HTTP body as an individually resolvable item.
    #[cfg(feature = "http")]
    #[must_use]
    pub fn redact_http_body(
        &mut self,
        capture: crate::formats::http::BodyCapture<'_>,
        content_type: Option<&http::HeaderValue>,
    ) -> RedactionHandle {
        if self.is_output_exhausted() {
            return self.stage_exhausted_handle();
        }
        self.run_handle(|session| HttpRedactionSession::new(session).redact_body(capture, content_type))
    }

    /// Runs a JSON adapter while retaining the session borrow.
    #[cfg(feature = "json")]
    pub fn json<F>(&mut self, configure: F) -> &mut Self
    where
        F: for<'session> FnOnce(&mut JsonRedactionSession<'session>),
    {
        if self.is_output_exhausted() {
            return self;
        }
        self.run_adapter(|session| {
            let mut adapter = JsonRedactionSession::new(session);
            configure(&mut adapter);
        });
        self
    }

    /// Redacts JSON text as one individually resolvable transaction item.
    #[cfg(feature = "json")]
    #[must_use]
    pub fn redact_json(&mut self, text: &str) -> RedactionHandle {
        if self.is_output_exhausted() {
            return self.stage_exhausted_handle();
        }
        self.run_handle(|session| crate::formats::json::JsonRedactionSession::new(session).redact_text(text))
    }

    /// Runs a URI adapter while retaining the session borrow.
    #[cfg(feature = "uri")]
    pub fn uri<F>(&mut self, configure: F) -> &mut Self
    where
        F: for<'session> FnOnce(&mut crate::formats::uri::UriRedactionSession<'session>),
    {
        if self.is_output_exhausted() {
            return self;
        }
        self.run_adapter(|session| {
            let mut adapter = crate::formats::uri::UriRedactionSession::new(session);
            configure(&mut adapter);
        });
        self
    }

    /// Redacts a URI as one individually resolvable transaction item.
    #[cfg(feature = "uri")]
    #[must_use]
    pub fn redact_uri(&mut self, input: &str) -> RedactionHandle {
        if self.is_output_exhausted() {
            return self.stage_exhausted_handle();
        }
        self.run_handle(|session| crate::formats::uri::UriRedactionSession::new(session).redact_uri(input))
    }

    /// Begins a domain value for the structured writer without exposing an
    /// RAII scope to generated implementations.
    #[must_use]
    pub(crate) fn begin_domain_value(&mut self) -> bool {
        match self.domain_context.enter_value() {
            DomainEntry::Entered => {
                let depth = self.domain_context.current_depth();
                self.summary = self.summary.with_domain_node(depth);
                if let Some(item_summary) = self.item_summary {
                    self.item_summary = Some(item_summary.with_domain_node(depth));
                }
                true
            }
            DomainEntry::DepthLimitReached => {
                self.record_summary(crate::RedactionSummary::truncated(
                    crate::RedactionReason::DepthLimitReached,
                ));
                false
            }
            DomainEntry::TraversalLimitReached => {
                self.record_summary(crate::RedactionSummary::truncated(
                    crate::RedactionReason::TraversalLimitReached,
                ));
                false
            }
        }
    }

    /// Publishes the current transaction and immediately resets this session.
    #[must_use]
    pub fn finish(&mut self) -> RedactionSessionOutput {
        let fresh = TransactionState::new(self.policy.as_ref(), next_transaction_id());
        let completed = std::mem::replace(&mut self.transaction, fresh);
        RedactionSessionOutput::new(
            completed.id,
            crate::RedactedText::from_escaped(completed.fragments),
            completed.items,
            completed.summary,
        )
    }

    /// Replaces all state owned by the active transaction with a fresh state.
    pub(super) fn reset_transaction(&mut self) {
        self.transaction = TransactionState::new(self.policy.as_ref(), next_transaction_id());
    }

    /// Appends a chain fragment at a UTF-8 boundary within remaining output.
    fn append_output_fragment(&mut self, fragment: &str) {
        if self.output_exhausted {
            // An exact earlier write is still complete. A later aggregate
            // literal, however, is an attempted write after the shared
            // budget closed and must make that exhaustion observable.
            self.summary = self.summary.merge(crate::RedactionSummary::exhausted(
                crate::RedactionReason::OutputLimitReached,
            ));
            return;
        }
        let escaped = crate::output::log_escape::escape_log_control_characters(std::borrow::Cow::Borrowed(fragment));
        let used = self.summary.usage().output_bytes();
        let remaining = self.budget.output_limit().saturating_sub(used);
        if escaped.len() > remaining {
            self.output_exhausted = true;
            self.summary = self.summary.merge(crate::RedactionSummary::exhausted(
                crate::RedactionReason::OutputLimitReached,
            ));
            return;
        }
        self.fragments.push_str(&escaped);
        self.summary = self.summary.with_added_output_bytes(escaped.len());
        if self.summary.usage().output_bytes() == self.budget.output_limit() {
            // Exact consumption remains a complete result, but no later
            // adapter may inspect input after the transaction has no output
            // capacity left.
            self.output_exhausted = true;
        }
    }

    /// Executes a user-supplied adapter closure under transaction panic
    /// rollback semantics.
    fn run_adapter(&mut self, configure: impl FnOnce(&mut Self)) {
        let mut guard = TransactionGuard::new(self);
        configure(guard.session());
        guard.commit();
    }

    /// Runs an individually resolved operation with the same panic rollback
    /// contract as aggregate adapter closures.
    fn run_handle(&mut self, operation: impl FnOnce(&mut Self) -> RedactionHandle) -> RedactionHandle {
        let mut guard = TransactionGuard::new(self);
        let owns_item_summary = guard.session().begin_item_summary();
        let handle = operation(guard.session());
        guard.session().end_item_summary(owns_item_summary);
        guard.commit();
        handle
    }

    /// Starts per-item accounting unless an outer handle entry already did so.
    #[must_use]
    pub(crate) fn begin_item_summary(&mut self) -> bool {
        if self.item_summary.is_some() {
            return false;
        }
        self.item_summary = Some(crate::RedactionSummary::complete());
        true
    }

    /// Ends per-item accounting when the caller created the active scope.
    pub(crate) fn end_item_summary(&mut self, owns_item_summary: bool) {
        if owns_item_summary {
            self.item_summary = None;
        }
    }

    /// Merges one accounting delta into the transaction and active item.
    fn record_summary(&mut self, delta: crate::RedactionSummary) {
        self.summary = self.summary.merge(delta);
        if let Some(item_summary) = self.item_summary {
            self.item_summary = Some(item_summary.merge(delta));
        }
    }

    /// Adds retained output bytes to the transaction and active item.
    fn record_output_bytes(&mut self, bytes: usize) {
        self.summary = self.summary.with_added_output_bytes(bytes);
        if let Some(item_summary) = self.item_summary {
            self.item_summary = Some(item_summary.with_added_output_bytes(bytes));
        }
    }

    /// Charges one domain field before its value is accessed.
    #[must_use]
    #[inline(always)]
    pub(crate) fn admit_domain_field(&mut self) -> bool {
        let admission = self.domain_context.admit_field();
        if admission {
            let depth = self.domain_context.current_depth();
            self.summary = self.summary.with_domain_node(depth);
            if let Some(item_summary) = self.item_summary {
                self.item_summary = Some(item_summary.with_domain_node(depth));
            }
        } else {
            self.record_summary(crate::RedactionSummary::truncated(
                crate::RedactionReason::TraversalLimitReached,
            ));
        }
        admission
    }

    /// Charges one domain collection item before its iterator advances.
    #[must_use]
    #[inline(always)]
    pub(crate) fn admit_domain_collection_item(&mut self) -> bool {
        let admission = self.domain_context.admit_collection_item();
        if admission {
            self.summary = self.summary.with_collection_item();
            if let Some(item_summary) = self.item_summary {
                self.item_summary = Some(item_summary.with_collection_item());
            }
        } else {
            self.record_summary(crate::RedactionSummary::truncated(
                crate::RedactionReason::TraversalLimitReached,
            ));
        }
        admission
    }

    /// Admits one format node through the same structural ledger used by
    /// domain values. Format adapters must call this before inspecting a
    /// structured component.
    #[must_use]
    pub(crate) fn admit_format_node(&mut self, depth: usize) -> bool {
        match self.domain_context.admit_format_node(depth) {
            DomainEntry::Entered => {
                self.summary = self.summary.with_domain_node(depth);
                if let Some(item_summary) = self.item_summary {
                    self.item_summary = Some(item_summary.with_domain_node(depth));
                }
                true
            }
            DomainEntry::DepthLimitReached => {
                self.record_summary(crate::RedactionSummary::truncated(
                    crate::RedactionReason::DepthLimitReached,
                ));
                false
            }
            DomainEntry::TraversalLimitReached => {
                self.record_summary(crate::RedactionSummary::truncated(
                    crate::RedactionReason::TraversalLimitReached,
                ));
                false
            }
        }
    }

    /// Admits one format collection item through the transaction-wide
    /// collection ledger. A failed admission closes subsequent traversal.
    #[must_use]
    #[inline(always)]
    pub(crate) fn admit_format_collection_item(&mut self) -> bool {
        self.admit_domain_collection_item()
    }

    /// Admits JSON-specific key, scalar, payload, and local structural limits
    /// through the ledger stored in the active transaction.
    #[cfg(feature = "json")]
    #[must_use]
    pub(crate) fn admit_json_value(&mut self, value: &serde_json::Value) -> bool {
        if self.transaction.admit_json_value(value) {
            true
        } else {
            self.record_summary(crate::RedactionSummary::truncated(
                crate::RedactionReason::TraversalLimitReached,
            ));
            false
        }
    }

    /// Releases one active domain-value depth while preserving cumulative
    /// charges.
    #[inline(always)]
    pub(crate) fn leave_domain_value(&mut self) {
        self.domain_context.leave_value();
    }

    /// Appends output rendered by the domain writer, retaining genuine output
    /// exhaustion alongside any earlier input or structural provenance.
    pub(crate) fn append_domain_output(&mut self, output: &str, output_limit_reached: bool) {
        if output_limit_reached {
            self.record_summary(crate::RedactionSummary::truncated(
                crate::RedactionReason::OutputLimitReached,
            ));
        }
        self.append_output_fragment(output);
    }

    /// Appends one completed format result through the sole transaction budget.
    pub(crate) fn append_format_output(&mut self, output: &crate::RedactionOutput) {
        self.record_summary(*output.summary());
        if output.summary().completion() == RedactionCompletion::Exhausted {
            self.output_exhausted = true;
            return;
        }
        self.append_output_fragment(output.text().as_str());
    }

    /// Appends a format's completed safe text without creating a second result
    /// model or budget.
    #[cfg(any(feature = "json", feature = "http", feature = "uri"))]
    pub(crate) fn append_format_text(&mut self, text: crate::RedactedText, completion: crate::RedactionCompletion) {
        let summary = match completion {
            crate::RedactionCompletion::Complete => crate::RedactionSummary::complete(),
            crate::RedactionCompletion::Truncated => {
                crate::RedactionSummary::truncated(crate::RedactionReason::TraversalLimitReached)
            }
            crate::RedactionCompletion::Exhausted => {
                crate::RedactionSummary::exhausted(crate::RedactionReason::OutputLimitReached)
            }
        };
        self.append_format_output(&crate::RedactionOutput::new(text, summary));
    }

    /// Records a format result rendered inside a domain writer.
    ///
    /// The writer retains the text until its enclosing domain value closes, so
    /// its bytes must not be charged here. Completion and provenance still
    /// belong to the one active transaction and are recorded immediately.
    #[cfg(feature = "json")]
    pub(crate) fn record_format_provenance(&mut self, summary: crate::RedactionSummary) {
        use crate::RedactionReason;

        // The JSON text is embedded in a domain frame, whose bytes are
        // charged when that frame is appended. Retain only completion and
        // reasons here; merging helper usage would double-charge the session.
        for reason in [
            RedactionReason::InputLimitReached,
            RedactionReason::OutputLimitReached,
            RedactionReason::TraversalLimitReached,
            RedactionReason::DepthLimitReached,
            RedactionReason::SourceTruncated,
            RedactionReason::InvalidJson,
            RedactionReason::InvalidUri,
            RedactionReason::InvalidContentType,
            RedactionReason::UnsupportedContentType,
        ] {
            if !summary.reasons().contains(reason) {
                continue;
            }
            let provenance = match summary.completion() {
                RedactionCompletion::Complete => crate::RedactionSummary::complete_with_reason(reason),
                RedactionCompletion::Truncated => crate::RedactionSummary::truncated(reason),
                RedactionCompletion::Exhausted => crate::RedactionSummary::exhausted(reason),
            };
            self.record_summary(provenance);
        }
    }

    /// Reports whether the active transaction has exhausted its output budget.
    #[must_use]
    #[inline(always)]
    pub(crate) fn is_output_exhausted(&self) -> bool {
        self.output_exhausted || self.remaining_output_bytes() == 0
    }

    /// Returns output capacity still available to one renderer.
    #[must_use]
    #[inline(always)]
    pub(crate) fn remaining_output_bytes(&self) -> usize {
        self.budget
            .output_limit()
            .saturating_sub(self.summary.usage().output_bytes())
    }

    /// Admits one encoded format input before its parser or renderer can
    /// inspect it.
    ///
    /// Rejected input is recorded as presented but uninspected and degrades
    /// the transaction without opening a second input budget.
    pub(crate) fn admit_input(&mut self, bytes: usize) -> bool {
        let inspected = self.summary.usage().inspected_input_bytes();
        let limit = self.policy.limits().max_input_bytes();
        if bytes > limit.saturating_sub(inspected) {
            self.summary = self.summary.with_input(bytes, 0);
            if let Some(item_summary) = self.item_summary {
                self.item_summary = Some(item_summary.with_input(bytes, 0));
            }
            self.record_summary(crate::RedactionSummary::truncated(
                crate::RedactionReason::InputLimitReached,
            ));
            return false;
        }
        self.summary = self.summary.with_input(bytes, bytes);
        if let Some(item_summary) = self.item_summary {
            self.item_summary = Some(item_summary.with_input(bytes, bytes));
        }
        true
    }

    /// Admits a captured source whose complete length may be unknown.
    #[cfg(feature = "http")]
    pub(crate) fn admit_source_input(&mut self, total: Option<usize>, inspectable: usize) -> bool {
        let already_inspected = self.summary.usage().inspected_input_bytes();
        let limit = self.policy.limits().max_input_bytes();
        let admitted = inspectable <= limit.saturating_sub(already_inspected);
        let inspected = if admitted { inspectable } else { 0 };
        let presented = total.unwrap_or(inspectable);
        let omitted = total.map(|length| length.saturating_sub(inspected));

        self.summary = self.summary.with_source_input(presented, inspected, omitted);
        if let Some(item_summary) = self.item_summary {
            self.item_summary = Some(item_summary.with_source_input(presented, inspected, omitted));
        }
        if !admitted {
            self.record_summary(crate::RedactionSummary::truncated(
                crate::RedactionReason::InputLimitReached,
            ));
        }
        admitted
    }
}

impl RedactionSession {
    /// Redacts one field as an individually resolvable transaction item.
    ///
    /// The returned handle does not expose text before [`Self::finish`]
    /// publishes the transaction.
    #[must_use]
    pub fn redact_field(&mut self, field: &str, value: &str) -> RedactionHandle {
        if self.is_output_exhausted() {
            return self.stage_exhausted_handle();
        }
        self.run_handle(|session| {
            if !session.admit_input(field.len().saturating_add(value.len())) {
                return session.stage_item(crate::RedactionOutput::new(
                    crate::RedactedText::from_escaped(String::new()),
                    crate::RedactionSummary::complete(),
                ));
            }
            let output = session.redact_field_output(field, value);
            session.stage_item(output)
        })
    }

    /// Stores one individually resolvable output after charging the shared
    /// budget.
    pub(crate) fn stage_item(&mut self, output: crate::RedactionOutput) -> RedactionHandle {
        let item_index = self.items.len();
        let used = self.summary.usage().output_bytes();
        let remaining = self.budget.output_limit().saturating_sub(used);
        let output = if self.output_exhausted
            || output.summary().completion() == RedactionCompletion::Exhausted
            || output.text().as_str().len() > remaining
        {
            self.output_exhausted = true;
            let summary = crate::RedactionSummary::exhausted(crate::RedactionReason::OutputLimitReached);
            self.record_summary(*output.summary());
            self.record_summary(summary);
            let item_summary = self.item_summary.unwrap_or(summary);
            crate::RedactionOutput::new(
                crate::RedactedText::from_escaped(std::borrow::Cow::Borrowed("")),
                item_summary,
            )
        } else {
            let summary = output.summary().with_added_output_bytes(output.text().as_str().len());
            self.record_summary(summary);
            let item_summary = self.item_summary.unwrap_or(summary);
            if self.summary.usage().output_bytes() == self.budget.output_limit() {
                // An exactly fitting handle is valid and complete; it simply
                // closes this transaction to all subsequent work.
                self.output_exhausted = true;
            }
            crate::RedactionOutput::new(output.into_text(), item_summary)
        };
        self.items.push(output);
        RedactionHandle::new(self.id, item_index)
    }

    /// Stages a domain value whose writer has already charged traversal state
    /// to the shared transaction. This records that operation's delta without
    /// merging its domain charges a second time.
    fn stage_domain_item(&mut self, text: crate::RedactedText) -> RedactionHandle {
        let item_index = self.items.len();
        if text.as_str().len() > self.remaining_output_bytes() {
            self.output_exhausted = true;
            let summary = crate::RedactionSummary::exhausted(crate::RedactionReason::OutputLimitReached);
            self.record_summary(summary);
            let item_summary = self.item_summary.unwrap_or(summary);
            self.items.push(crate::RedactionOutput::new(
                crate::RedactedText::from_escaped(String::new()),
                item_summary,
            ));
        } else {
            self.record_output_bytes(text.as_str().len());
            let summary = self
                .item_summary
                .expect("domain handles are staged inside an item-accounting scope");
            self.items.push(crate::RedactionOutput::new(text, summary));
        }
        RedactionHandle::new(self.id, item_index)
    }

    /// Redacts one field into owned safe text with its fragment completion.
    pub(crate) fn redact_field_output(&mut self, field: &str, value: &str) -> RedactionOutput {
        let (redacted, completion) = self.redact_field_with_completion(field, value);
        redaction_output(redacted, completion)
    }

    /// Stages a completed format result as one individually resolvable item.
    pub(crate) fn stage_format_text(
        &mut self,
        text: crate::RedactedText,
        completion: crate::RedactionCompletion,
    ) -> RedactionHandle {
        let summary = match completion {
            crate::RedactionCompletion::Complete => crate::RedactionSummary::complete(),
            crate::RedactionCompletion::Truncated => {
                crate::RedactionSummary::truncated(crate::RedactionReason::TraversalLimitReached)
            }
            crate::RedactionCompletion::Exhausted => {
                crate::RedactionSummary::exhausted(crate::RedactionReason::OutputLimitReached)
            }
        };
        self.stage_item(crate::RedactionOutput::new(text, summary))
    }

    /// Stages text after the active item scope has already recorded its
    /// completion, reasons, and usage.
    pub(crate) fn stage_accounted_text(&mut self, text: crate::RedactedText) -> RedactionHandle {
        self.stage_item(crate::RedactionOutput::new(text, crate::RedactionSummary::complete()))
    }

    /// Stages the standard empty result without inspecting a later input once
    /// the transaction's output budget has closed.
    #[must_use]
    fn stage_exhausted_handle(&mut self) -> RedactionHandle {
        self.output_exhausted = true;
        self.stage_format_text(
            crate::RedactedText::from_escaped(String::new()),
            RedactionCompletion::Exhausted,
        )
    }

    fn redact_field_with_completion(&mut self, field: &str, value: &str) -> (crate::RedactedText, RedactionCompletion) {
        let policy = self.policy();
        let (redacted, completion) = redact_field_text_for_output(policy, field, value, self.remaining_output_bytes());
        (redacted, completion)
    }
}
