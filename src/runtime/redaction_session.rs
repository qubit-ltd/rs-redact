// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable accounting for one bounded diagnostic redaction event.

use std::ffi::OsStr;
use std::fmt::Write;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use super::OperationSink;
use super::RenderedOperation;
use super::batch_publication::BatchPublication;
use super::bounded_field_writer::BoundedFieldWriter;
use super::summary_builder::SummaryBuilder;
use super::transaction_guard::TransactionGuard;
use super::transaction_phase::TransactionPhase;
use super::transaction_state::TransactionState;
use crate::RedactionCompletion;
use crate::RedactionHandle;
use crate::domain::Redact;
use crate::formats::argv::ArgvRedactionWriter;
use crate::formats::env::EnvRedactionWriter;
#[cfg(feature = "http")]
use crate::formats::http::HttpRedactionWriter;
#[cfg(feature = "json")]
use crate::formats::json::JsonRedactionWriter;
use crate::formats::process::ProcessRedactionWriter;
use crate::policy::RedactionPolicy;
use crate::policy::ResolvedField;

/// Allocates transaction identities across every session in this process.
///
/// A handle is valid only for the exact transaction that published it, so a
/// per-session counter would allow two independent sessions to collide.
static NEXT_TRANSACTION_ID: AtomicU64 = AtomicU64::new(1);

#[inline(always)]
fn next_transaction_id() -> u64 {
    NEXT_TRANSACTION_ID.fetch_add(1, Ordering::Relaxed)
}

/// A mutable, unpublished redaction transaction.
///
/// ```compile_fail
/// use qubit_redact::Redactor;
///
/// let composer = Redactor::standard().text_composer();
/// let _ = format!("{composer:?}");
/// ```
pub struct RedactionSession {
    transaction: TransactionState,
}

impl RedactionSession {
    /// Creates a session that owns a policy snapshot shared with its redactor.
    #[must_use]
    pub(crate) fn from_text_snapshot(policy: Arc<RedactionPolicy>) -> RedactionSession {
        RedactionSession {
            transaction: TransactionState::new_text(policy, next_transaction_id()),
        }
    }

    /// Creates runtime state whose only publication model is a batch of items.
    #[must_use]
    pub(crate) fn from_batch_snapshot(policy: Arc<RedactionPolicy>) -> RedactionSession {
        RedactionSession {
            transaction: TransactionState::new_batch(policy, next_transaction_id()),
        }
    }

    /// Returns the immutable policy snapshot used by this session.
    #[inline(always)]
    #[must_use]
    pub fn policy(&self) -> &RedactionPolicy {
        self.transaction.runtime.policy()
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
        if self.skip_aggregate_for_exhausted_output() {
            return self;
        }
        if !self.admit_input(field.len().saturating_add(value.len())) {
            return self;
        }
        let rendered = self.redact_field_output(field, value);
        self.append_rendered_operation(rendered);
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
        if self.skip_aggregate_for_exhausted_output() {
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
        if self.skip_aggregate_for_exhausted_output() {
            return self.stage_exhausted_handle();
        }
        self.run_handle(|session| {
            let mut writer = crate::domain::RedactionWriter::new_root(session);
            value.write_redacted(&mut writer);
            let rendered = writer.finish_with_completion();
            let escaped = crate::output::log_escape::escape_log_control_characters(std::borrow::Cow::Owned(rendered.0))
                .into_owned();
            if rendered.2 && escaped.is_empty() {
                return session.stage_exhausted_handle();
            }
            if rendered.2 {
                session.record_summary(crate::RedactionSummary::truncated(
                    crate::RedactionReason::OutputLimitReached,
                ));
            }
            session.stage_domain_item(escaped)
        })
    }

    /// Runs an argv adapter while retaining the session borrow.
    pub fn argv<F>(&mut self, configure: F) -> &mut Self
    where
        F: for<'session> FnOnce(&mut ArgvRedactionWriter<'session>),
    {
        if self.skip_aggregate_for_exhausted_output() {
            return self;
        }
        self.run_adapter(|session| {
            let mut adapter = ArgvRedactionWriter::new(session);
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
        if self.skip_aggregate_for_exhausted_output() {
            return self.stage_exhausted_handle();
        }
        self.run_handle(|session| ArgvRedactionWriter::new(session).redact_items(items))
    }

    /// Redacts heuristic argv items as one individually resolvable item.
    #[must_use]
    pub fn redact_heuristic_argv<'items, I>(&mut self, items: I) -> RedactionHandle
    where
        I: IntoIterator<Item = crate::formats::argv::ArgvItem<'items>>,
        I::IntoIter: ExactSizeIterator,
    {
        if self.skip_aggregate_for_exhausted_output() {
            return self.stage_exhausted_handle();
        }
        self.run_handle(|session| ArgvRedactionWriter::new(session).redact_heuristic_items(items))
    }

    /// Runs an environment adapter while retaining the session borrow.
    pub fn env<F>(&mut self, configure: F) -> &mut Self
    where
        F: for<'session> FnOnce(&mut EnvRedactionWriter<'session>),
    {
        if self.skip_aggregate_for_exhausted_output() {
            return self;
        }
        self.run_adapter(|session| {
            let mut adapter = EnvRedactionWriter::new(session);
            configure(&mut adapter);
        });
        self
    }

    /// Redacts one environment assignment as an individually resolvable item.
    #[must_use]
    pub fn redact_env(&mut self, name: &str, value: &str) -> RedactionHandle {
        if self.skip_aggregate_for_exhausted_output() {
            return self.stage_exhausted_handle();
        }
        self.run_handle(|session| EnvRedactionWriter::new(session).redact_pair(name, value))
    }

    /// Redacts environment assignments as one individually resolvable item.
    #[must_use]
    pub fn redact_env_pairs<'items, I>(&mut self, pairs: I) -> RedactionHandle
    where
        I: IntoIterator<Item = (&'items OsStr, &'items OsStr)>,
        I::IntoIter: ExactSizeIterator,
    {
        if self.skip_aggregate_for_exhausted_output() {
            return self.stage_exhausted_handle();
        }
        self.run_handle(|session| EnvRedactionWriter::new(session).redact_os_pairs(pairs))
    }

    /// Runs a process-command adapter while retaining the session borrow.
    #[must_use]
    pub fn process<F>(&mut self, configure: F) -> &mut Self
    where
        F: for<'session> FnOnce(&mut ProcessRedactionWriter<'session>),
    {
        if self.skip_aggregate_for_exhausted_output() {
            return self;
        }
        self.run_adapter(|session| {
            let mut adapter = ProcessRedactionWriter::new(session);
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
        if self.skip_aggregate_for_exhausted_output() {
            return self.stage_exhausted_handle();
        }
        self.run_handle(|session| ProcessRedactionWriter::new(session).redact_command(program, arguments, variables))
    }

    /// Runs an HTTP adapter while retaining the session borrow.
    ///
    /// This aggregate operation returns the session for chaining. Use one of
    /// the explicit `redact_http_*` methods when a separately resolvable item
    /// is required.
    ///
    /// ```compile_fail
    /// use qubit_redact::RedactionBatchHandle;
    /// use qubit_redact::Redactor;
    ///
    /// let composer = Redactor::standard().text_composer();
    /// let _: RedactionBatchHandle = composer.http(|_| {});
    /// ```
    #[cfg(feature = "http")]
    pub fn http<F>(&mut self, configure: F) -> &mut Self
    where
        F: for<'session> FnOnce(&mut HttpRedactionWriter<'session>),
    {
        if self.skip_aggregate_for_exhausted_output() {
            return self;
        }
        self.run_adapter(|session| {
            let mut adapter = HttpRedactionWriter::new(session);
            configure(&mut adapter);
        });
        self
    }

    /// Redacts one HTTP URL as an individually resolvable item.
    #[cfg(feature = "http")]
    #[must_use]
    pub fn redact_http_url(&mut self, value: &str) -> RedactionHandle {
        if self.skip_aggregate_for_exhausted_output() {
            return self.stage_exhausted_handle();
        }
        self.run_handle(|session| HttpRedactionWriter::new(session).redact_url(value))
    }

    /// Redacts an HTTP header collection as an individually resolvable item.
    #[cfg(feature = "http")]
    #[must_use]
    pub fn redact_http_headers(&mut self, headers: &http::HeaderMap) -> RedactionHandle {
        if self.skip_aggregate_for_exhausted_output() {
            return self.stage_exhausted_handle();
        }
        self.run_handle(|session| HttpRedactionWriter::new(session).redact_headers(headers))
    }

    /// Redacts one captured HTTP body as an individually resolvable item.
    #[cfg(feature = "http")]
    #[must_use]
    pub fn redact_http_body(
        &mut self,
        capture: crate::formats::http::BodyCapture<'_>,
        content_type: Option<&http::HeaderValue>,
    ) -> RedactionHandle {
        if self.skip_aggregate_for_exhausted_output() {
            return self.stage_exhausted_handle();
        }
        self.run_handle(|session| HttpRedactionWriter::new(session).redact_body(capture, content_type))
    }

    /// Redacts one captured HTTP body with textual content-type metadata as an
    /// individually resolvable item.
    #[cfg(feature = "http")]
    #[must_use]
    pub fn redact_http_body_with_content_type_text(
        &mut self,
        capture: crate::formats::http::BodyCapture<'_>,
        content_type: Option<&str>,
    ) -> RedactionHandle {
        if self.skip_aggregate_for_exhausted_output() {
            return self.stage_exhausted_handle();
        }
        self.run_handle(|session| {
            HttpRedactionWriter::new(session).redact_body_with_content_type_text(capture, content_type)
        })
    }

    /// Runs a JSON adapter while retaining the session borrow.
    #[cfg(feature = "json")]
    pub fn json<F>(&mut self, configure: F) -> &mut Self
    where
        F: for<'session> FnOnce(&mut JsonRedactionWriter<'session>),
    {
        if self.skip_aggregate_for_exhausted_output() {
            return self;
        }
        self.run_adapter(|session| {
            let mut adapter = JsonRedactionWriter::new(session);
            configure(&mut adapter);
        });
        self
    }

    /// Redacts JSON text as one individually resolvable transaction item.
    #[cfg(feature = "json")]
    #[must_use]
    pub fn redact_json(&mut self, text: &str) -> RedactionHandle {
        if self.skip_aggregate_for_exhausted_output() {
            return self.stage_exhausted_handle();
        }
        self.run_handle(|session| crate::formats::json::JsonRedactionWriter::new(session).redact_text(text))
    }

    /// Runs a URI adapter while retaining the session borrow.
    #[cfg(feature = "uri")]
    pub fn uri<F>(&mut self, configure: F) -> &mut Self
    where
        F: for<'session> FnOnce(&mut crate::formats::uri::UriRedactionWriter<'session>),
    {
        if self.skip_aggregate_for_exhausted_output() {
            return self;
        }
        self.run_adapter(|session| {
            let mut adapter = crate::formats::uri::UriRedactionWriter::new(session);
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
        self.run_handle(|session| crate::formats::uri::UriRedactionWriter::new(session).redact_uri(input))
    }

    /// Begins a domain value for the structured writer without exposing an
    /// RAII scope to generated implementations.
    #[must_use]
    pub(crate) fn begin_domain_value(&mut self) -> bool {
        self.transaction.runtime.begin_domain_value()
    }

    /// Publishes the current composer transaction.
    #[must_use]
    pub(crate) fn finish_text(self) -> crate::RedactionTextOutput {
        let TransactionState {
            runtime, publication, ..
        } = self.transaction;
        crate::RedactionTextOutput::new(publication.into_text(), runtime.into_summary())
    }

    /// Publishes the current batch transaction.
    #[must_use]
    pub(crate) fn finish_batch(self) -> BatchPublication {
        let TransactionState {
            id,
            runtime,
            publication,
        } = self.transaction;
        BatchPublication::new(id, publication.into_batch(), runtime.into_summary())
    }

    /// Replaces all state owned by the active transaction with a fresh state.
    pub(super) fn reset_transaction(&mut self) {
        let policy = self.transaction.runtime.policy.clone();
        self.transaction = if self.transaction.publication.is_text() {
            TransactionState::new_text(policy, next_transaction_id())
        } else {
            TransactionState::new_batch(policy, next_transaction_id())
        };
    }

    /// Appends a chain fragment at a UTF-8 boundary within remaining output.
    fn append_output_fragment(&mut self, fragment: &str) {
        if self.transaction.runtime.phase == TransactionPhase::OutputExhausted {
            // An exact earlier write is still complete. A later aggregate
            // literal, however, is an attempted write after the shared
            // budget closed and must make that exhaustion observable.
            self.transaction.runtime.summary =
                self.transaction
                    .runtime
                    .summary
                    .merge(crate::RedactionSummary::exhausted(
                        crate::RedactionReason::OutputLimitReached,
                    ));
            return;
        }
        let escaped = crate::output::log_escape::escape_log_control_characters(std::borrow::Cow::Borrowed(fragment));
        let used = self.transaction.runtime.budget.usage().output_bytes();
        let remaining = self.transaction.runtime.budget.output_limit().saturating_sub(used);
        if escaped.len() > remaining {
            self.transaction.runtime.phase = TransactionPhase::OutputExhausted;
            self.transaction.runtime.summary =
                self.transaction
                    .runtime
                    .summary
                    .merge(crate::RedactionSummary::exhausted(
                        crate::RedactionReason::OutputLimitReached,
                    ));
            return;
        }
        self.transaction.publication.text_mut().push(&escaped);
        self.transaction.runtime.budget.record_output_bytes(escaped.len());
        if self.transaction.runtime.budget.usage().output_bytes() == self.transaction.runtime.budget.output_limit() {
            // Exact consumption remains a complete result, but no later
            // adapter may inspect input after the transaction has no output
            // capacity left.
            self.transaction.runtime.phase = TransactionPhase::OutputExhausted;
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
        self.transaction.runtime.begin_item_summary()
    }

    /// Ends per-item accounting when the caller created the active scope.
    pub(crate) fn end_item_summary(&mut self, owns_item_summary: bool) {
        self.transaction.runtime.end_item_summary(owns_item_summary);
    }

    /// Merges one accounting delta into the transaction and active item.
    fn record_summary(&mut self, delta: crate::RedactionSummary) {
        self.transaction.runtime.record_summary(delta);
    }

    /// Adds retained output bytes to the transaction and active item.
    fn record_output_bytes(&mut self, bytes: usize) {
        self.transaction.runtime.record_output_bytes(bytes);
    }

    /// Charges one domain field before its value is accessed.
    #[must_use]
    #[inline(always)]
    pub(crate) fn admit_domain_field(&mut self) -> bool {
        self.transaction.runtime.admit_domain_field()
    }

    /// Charges one domain collection item before its iterator advances.
    #[must_use]
    #[inline(always)]
    pub(crate) fn admit_domain_collection_item(&mut self) -> bool {
        self.transaction.runtime.admit_domain_collection_item()
    }

    /// Admits one format node through the same structural ledger used by
    /// domain values. Format adapters must call this before inspecting a
    /// structured component.
    #[must_use]
    pub(crate) fn admit_format_node(&mut self, depth: usize) -> bool {
        self.transaction.runtime.admit_format_node(depth)
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
        self.transaction.runtime.admit_json_value(value)
    }

    /// Releases one active domain-value depth while preserving cumulative
    /// charges.
    #[inline(always)]
    pub(crate) fn leave_domain_value(&mut self) {
        self.transaction.runtime.leave_domain_value();
    }

    /// Returns whether the transaction-owned domain frame has stopped writing.
    #[must_use]
    #[inline(always)]
    pub(crate) fn domain_frame_is_truncated(&self) -> bool {
        self.transaction.runtime.domain_frame_truncated
    }

    /// Returns output capacity still available to the active domain frame.
    #[must_use]
    #[inline(always)]
    pub(crate) fn remaining_domain_frame_output_bytes(&self) -> usize {
        self.remaining_output_bytes()
            .saturating_sub(self.transaction.runtime.domain_frame_output_bytes)
    }

    /// Appends one complete raw fragment to the transaction-owned domain frame.
    pub(crate) fn append_domain_frame_fragment(&mut self, text: &str) {
        for character in text.chars() {
            self.transaction.runtime.domain_frame.push(character);
            self.transaction.runtime.domain_frame_output_bytes += encoded_log_safe_len(character);
        }
    }

    /// Appends a fragment while enforcing the shared transaction output limit.
    pub(crate) fn write_domain_fragment(&mut self, text: &str) -> bool {
        if self.transaction.runtime.domain_frame_truncated {
            return false;
        }
        for character in text.chars() {
            if encoded_log_safe_len(character) > self.remaining_domain_frame_output_bytes() {
                self.mark_domain_frame_output_limit_reached();
                self.truncate_domain_frame_without_output_limit();
                return false;
            }
            self.transaction.runtime.domain_frame.push(character);
            self.transaction.runtime.domain_frame_output_bytes += encoded_log_safe_len(character);
        }
        true
    }

    /// Marks the active domain frame as having reached the shared output limit.
    pub(crate) fn mark_domain_frame_output_limit_reached(&mut self) {
        self.transaction.runtime.domain_frame_output_limit_reached = true;
    }

    /// Marks the active domain frame as closed to later field access.
    pub(crate) fn mark_domain_frame_truncated(&mut self) {
        self.transaction.runtime.domain_frame_truncated = true;
    }

    /// Removes raw characters until the frame's encoded representation fits
    /// `limit`.
    pub(crate) fn truncate_domain_frame_to(&mut self, limit: usize) {
        while self.transaction.runtime.domain_frame_output_bytes > limit {
            let Some(character) = self.transaction.runtime.domain_frame.pop() else {
                self.transaction.runtime.domain_frame_output_bytes = 0;
                return;
            };
            self.transaction.runtime.domain_frame_output_bytes = self
                .transaction
                .runtime
                .domain_frame_output_bytes
                .saturating_sub(encoded_log_safe_len(character));
        }
    }

    /// Appends the standard marker after structural or input truncation.
    pub(crate) fn truncate_domain_frame_without_output_limit(&mut self) {
        if self.transaction.runtime.domain_frame_truncated {
            return;
        }
        const MARKER: &str = "<truncated>";
        if MARKER.len() > self.remaining_output_bytes() {
            self.truncate_domain_frame_to(0);
            self.mark_domain_frame_output_limit_reached();
            self.transaction.runtime.phase = TransactionPhase::OutputExhausted;
        } else {
            self.truncate_domain_frame_to(self.remaining_output_bytes().saturating_sub(MARKER.len()));
            self.append_domain_frame_fragment(MARKER);
        }
        self.mark_domain_frame_truncated();
    }

    /// Removes a final separator from the transaction-owned domain frame.
    pub(crate) fn trim_domain_frame_separator(&mut self) {
        if self.transaction.runtime.domain_frame.ends_with(", ") {
            self.transaction
                .runtime
                .domain_frame
                .truncate(self.transaction.runtime.domain_frame.len() - 2);
            self.transaction.runtime.domain_frame_output_bytes =
                self.transaction.runtime.domain_frame_output_bytes.saturating_sub(2);
        }
    }

    /// Takes the completed domain frame and resets its transaction-local state.
    #[must_use]
    pub(crate) fn finish_domain_frame(&mut self) -> (String, bool, bool) {
        let output = std::mem::take(&mut self.transaction.runtime.domain_frame);
        let truncated = std::mem::take(&mut self.transaction.runtime.domain_frame_truncated);
        let output_limit_reached = std::mem::take(&mut self.transaction.runtime.domain_frame_output_limit_reached);
        self.transaction.runtime.domain_frame_output_bytes = 0;
        (output, truncated, output_limit_reached)
    }

    /// Appends output rendered by the domain writer, retaining genuine output
    /// exhaustion alongside any earlier input or structural provenance.
    pub(crate) fn append_domain_output(&mut self, output: &str, output_limit_reached: bool) {
        if output_limit_reached {
            let summary = if output.is_empty() || self.transaction.runtime.phase == TransactionPhase::OutputExhausted {
                crate::RedactionSummary::exhausted(crate::RedactionReason::OutputLimitReached)
            } else {
                crate::RedactionSummary::truncated(crate::RedactionReason::OutputLimitReached)
            };
            self.record_summary(summary);
        }
        self.append_output_fragment(output);
    }

    /// Commits unpublished adapter text through the sole transaction budget.
    pub(crate) fn append_rendered_operation(&mut self, operation: RenderedOperation) {
        let (text, completion, reasons) = operation.into_parts();
        let summary = rendered_summary(completion, reasons);
        self.record_summary(summary);
        let replacement_could_not_fit = text.is_empty() && reasons.contains(crate::RedactionReason::OutputLimitReached);
        if completion == RedactionCompletion::Exhausted || replacement_could_not_fit {
            self.transaction.runtime.phase = TransactionPhase::OutputExhausted;
            self.record_summary(crate::RedactionSummary::exhausted(
                crate::RedactionReason::OutputLimitReached,
            ));
            return;
        }
        self.append_output_fragment(&text);
    }

    /// Records a format result rendered inside a domain writer.
    ///
    /// The writer retains the text until its enclosing domain value closes, so
    /// its bytes must not be charged here. Completion and provenance still
    /// belong to the one active transaction and are recorded immediately.
    #[cfg(feature = "json")]
    pub(crate) fn record_rendered_provenance(&mut self, operation: &RenderedOperation) {
        use crate::RedactionReason;

        let summary = rendered_summary(operation.completion(), operation.reasons());

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
        self.transaction.runtime.is_output_exhausted()
    }

    /// Stops an aggregate operation before it can observe caller input.
    ///
    /// An exact prior write remains complete until a later operation is
    /// attempted. A zero-sized transaction has no such prior write, so its
    /// first skipped operation must still publish the output-limit failure.
    #[must_use]
    #[inline(always)]
    pub(crate) fn skip_aggregate_for_exhausted_output(&mut self) -> bool {
        self.transaction.runtime.skip_aggregate_for_exhausted_output()
    }

    /// Returns output capacity still available to one renderer.
    #[must_use]
    #[inline(always)]
    pub(crate) fn remaining_output_bytes(&self) -> usize {
        self.transaction.runtime.remaining_output_bytes()
    }

    /// Admits one encoded format input before its parser or renderer can
    /// inspect it.
    ///
    /// Rejected input is recorded as presented but uninspected and degrades
    /// the transaction without opening a second input budget.
    pub(crate) fn admit_input(&mut self, bytes: usize) -> bool {
        self.transaction.runtime.admit_input(bytes)
    }

    /// Admits the UTF-8 prefix of one parser input that fits the shared input
    /// budget and records the whole source as presented.
    ///
    /// The returned slice always ends on a character boundary. When it is
    /// shorter than `text`, the transaction records `InputLimitReached` while
    /// still allowing the parser to inspect the admitted prefix.
    #[cfg(any(feature = "json", feature = "http", feature = "uri"))]
    #[must_use]
    pub(crate) fn admit_input_prefix<'text>(&mut self, text: &'text str) -> &'text str {
        self.transaction.runtime.admit_input_prefix(text)
    }

    /// Admits a captured source whose complete length may be unknown.
    #[cfg(feature = "http")]
    pub(crate) fn admit_source_input(&mut self, total: Option<usize>, inspectable: usize) -> bool {
        self.transaction.runtime.admit_source_input(total, inspectable)
    }
}

impl RedactionSession {
    /// Redacts one field as an individually resolvable transaction item.
    ///
    /// The returned handle does not expose text before [`Self::finish_batch`]
    /// publishes the transaction.
    #[must_use]
    pub fn redact_field(&mut self, field: &str, value: &str) -> RedactionHandle {
        if self.is_output_exhausted() {
            return self.stage_exhausted_handle();
        }
        self.run_handle(|session| {
            if !session.admit_input(field.len().saturating_add(value.len())) {
                return session.stage_accounted_text(String::new());
            }
            let output = session.redact_field_output(field, value);
            session.stage_rendered_operation(output)
        })
    }

    /// Stages a domain value whose writer has already charged traversal state
    /// to the shared transaction. This records that operation's delta without
    /// merging its domain charges a second time.
    fn stage_domain_item(&mut self, text: String) -> RedactionHandle {
        let item_index = self.transaction.publication.batch_mut().len();
        if text.len() > self.remaining_output_bytes() {
            self.transaction.runtime.phase = TransactionPhase::OutputExhausted;
            let summary = crate::RedactionSummary::exhausted(crate::RedactionReason::OutputLimitReached);
            self.record_summary(summary);
            let item_summary = self
                .transaction
                .runtime
                .active_operation_summary
                .unwrap_or(SummaryBuilder::from_summary(summary));
            self.transaction.publication.batch_mut().push(
                String::new(),
                item_summary.build(
                    self.transaction
                        .runtime
                        .budget
                        .active_operation_usage()
                        .unwrap_or_else(crate::RedactionUsage::empty),
                ),
            );
        } else {
            self.record_output_bytes(text.len());
            let summary = self
                .transaction
                .runtime
                .active_operation_summary
                .expect("domain handles are staged inside an item-accounting scope");
            let usage = self
                .transaction
                .runtime
                .budget
                .active_operation_usage()
                .expect("domain handles are staged inside an item-accounting scope");
            self.transaction
                .publication
                .batch_mut()
                .push(text, summary.build(usage));
        }
        RedactionHandle::new(self.transaction.id, item_index)
    }

    /// Redacts one field into owned safe text with its fragment completion.
    pub(crate) fn redact_field_output(&mut self, field: &str, value: &str) -> RenderedOperation {
        let (redacted, completion) = self.redact_field_with_completion(field, value);
        match completion {
            RedactionCompletion::Complete => OperationSink::complete(redacted).finish(),
            RedactionCompletion::Truncated => {
                OperationSink::truncated(redacted, crate::RedactionReason::OutputLimitReached).finish()
            }
            RedactionCompletion::Exhausted => {
                OperationSink::exhausted(redacted, crate::RedactionReason::OutputLimitReached).finish()
            }
        }
    }

    /// Stages one unpublished adapter result as an individually resolvable
    /// item.
    pub(crate) fn stage_rendered_operation(&mut self, operation: RenderedOperation) -> RedactionHandle {
        let (text, completion, reasons) = operation.into_parts();
        let operation_summary = rendered_summary(completion, reasons);
        let item_index = self.transaction.publication.batch_mut().len();
        let remaining = self.remaining_output_bytes();
        let replacement_could_not_fit = text.is_empty() && reasons.contains(crate::RedactionReason::OutputLimitReached);
        let (retained, item_summary) = if self.transaction.runtime.phase == TransactionPhase::OutputExhausted
            || completion == RedactionCompletion::Exhausted
            || replacement_could_not_fit
            || text.len() > remaining
        {
            self.transaction.runtime.phase = TransactionPhase::OutputExhausted;
            let exhausted = crate::RedactionSummary::exhausted(crate::RedactionReason::OutputLimitReached);
            self.record_summary(operation_summary);
            self.record_summary(exhausted);
            let item_summary = self
                .transaction
                .runtime
                .active_operation_summary
                .unwrap_or(SummaryBuilder::from_summary(exhausted));
            (
                String::new(),
                item_summary.build(
                    self.transaction
                        .runtime
                        .budget
                        .active_operation_usage()
                        .unwrap_or_else(crate::RedactionUsage::empty),
                ),
            )
        } else {
            self.record_summary(operation_summary);
            self.record_output_bytes(text.len());
            let item_summary = self
                .transaction
                .runtime
                .active_operation_summary
                .unwrap_or(SummaryBuilder::from_summary(operation_summary));
            if self.remaining_output_bytes() == 0 {
                // An exactly fitting handle is valid and complete; it simply
                // closes this transaction to all subsequent work.
                self.transaction.runtime.phase = TransactionPhase::OutputExhausted;
            }
            (
                text,
                item_summary.build(
                    self.transaction
                        .runtime
                        .budget
                        .active_operation_usage()
                        .unwrap_or_else(crate::RedactionUsage::empty),
                ),
            )
        };
        self.transaction.publication.batch_mut().push(retained, item_summary);
        RedactionHandle::new(self.transaction.id, item_index)
    }

    /// Stages text after the active item scope has already recorded its
    /// completion, reasons, and usage.
    pub(crate) fn stage_accounted_text(&mut self, text: impl Into<String>) -> RedactionHandle {
        self.stage_rendered_operation(OperationSink::complete(text).finish())
    }

    /// Stages the standard empty result without inspecting a later input once
    /// the transaction's output budget has closed.
    #[must_use]
    pub(crate) fn stage_exhausted_handle(&mut self) -> RedactionHandle {
        self.transaction.runtime.phase = TransactionPhase::OutputExhausted;
        if let Some(item_index) = self.transaction.publication.batch_mut().exhausted_item() {
            return RedactionHandle::new(self.transaction.id, item_index);
        }
        let summary = crate::RedactionSummary::exhausted(crate::RedactionReason::OutputLimitReached);
        self.record_summary(summary);
        let item_summary = self
            .transaction
            .runtime
            .active_operation_summary
            .unwrap_or(SummaryBuilder::from_summary(summary))
            .build(
                self.transaction
                    .runtime
                    .budget
                    .active_operation_usage()
                    .unwrap_or_else(crate::RedactionUsage::empty),
            );
        let item_index = self.transaction.publication.batch_mut().len();
        self.transaction
            .publication
            .batch_mut()
            .push(String::new(), item_summary);
        self.transaction.publication.batch_mut().set_exhausted_item(item_index);
        RedactionHandle::new(self.transaction.id, item_index)
    }

    fn redact_field_with_completion(&mut self, field: &str, value: &str) -> (String, RedactionCompletion) {
        let policy = self.policy();
        let (redacted, completion) = redact_field_text_for_output(policy, field, value, self.remaining_output_bytes());
        (redacted, completion)
    }
}

/// Converts unpublished renderer provenance into the runtime's summary model.
fn rendered_summary(completion: RedactionCompletion, reasons: crate::RedactionReasons) -> crate::RedactionSummary {
    let mut summary = crate::RedactionSummary::complete();
    let mut found_reason = false;
    for reason in [
        crate::RedactionReason::InputLimitReached,
        crate::RedactionReason::OutputLimitReached,
        crate::RedactionReason::TraversalLimitReached,
        crate::RedactionReason::DepthLimitReached,
        crate::RedactionReason::SourceTruncated,
        crate::RedactionReason::InvalidJson,
        crate::RedactionReason::InvalidUri,
        crate::RedactionReason::InvalidContentType,
        crate::RedactionReason::UnsupportedContentType,
    ] {
        if reasons.contains(reason) {
            found_reason = true;
            summary = summary.merge(match completion {
                RedactionCompletion::Complete => crate::RedactionSummary::complete_with_reason(reason),
                RedactionCompletion::Truncated => crate::RedactionSummary::truncated(reason),
                RedactionCompletion::Exhausted => crate::RedactionSummary::exhausted(reason),
            });
        }
    }
    if found_reason || completion == RedactionCompletion::Complete {
        return summary;
    }
    match completion {
        RedactionCompletion::Complete => summary,
        RedactionCompletion::Truncated => {
            crate::RedactionSummary::truncated(crate::RedactionReason::TraversalLimitReached)
        }
        RedactionCompletion::Exhausted => {
            crate::RedactionSummary::exhausted(crate::RedactionReason::OutputLimitReached)
        }
    }
}

/// Returns the final log-safe byte count of one source character.
fn encoded_log_safe_len(character: char) -> usize {
    let mut buffer = [0_u8; 12];
    crate::output::log_escape::encode_log_safe_character(character, &mut buffer)
        .expect("the log-safe character encoder always produces UTF-8")
        .len()
}

/// Resolves and renders one admitted field through the transaction's final
/// escaped-output ceiling.
fn redact_field_text_for_output(
    policy: &RedactionPolicy,
    field: &str,
    value: &str,
    max_output_bytes: usize,
) -> (String, RedactionCompletion) {
    let mut writer = BoundedFieldWriter::new(max_output_bytes);
    let result = match policy.resolve_field(field) {
        ResolvedField::Sensitive { sensitivity } => {
            policy.masking().for_level(sensitivity).write_masked(value, &mut writer)
        }
        ResolvedField::PassThrough => writer.write_str(value),
    };
    if result.is_err() || writer.overflowed() {
        return (String::new(), RedactionCompletion::Exhausted);
    }
    (writer.finish(), RedactionCompletion::Complete)
}
