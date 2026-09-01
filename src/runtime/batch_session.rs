// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Independently resolvable batch transaction with typed publication storage.

use std::sync::Arc;

use super::batch_output_buffer::BatchOutputBuffer;
use super::batch_publication::BatchPublication;
use super::field_rendering;
use super::operation_sink::OperationSink;
use super::redaction_handle::RedactionHandle;
use super::render_runtime::RenderRuntime;
use super::rendered_operation::RenderedOperation;
use super::rendered_summary::rendered_summary;
use super::resettable_session::ResettableSession;
use super::runtime_core::RuntimeCore;
use super::runtime_session::RuntimeSession;
use super::summary_builder::SummaryBuilder;
use super::transaction_guard::TransactionGuard;
use super::transaction_phase::TransactionPhase;
use crate::Redact;
use crate::RedactionCompletion;
use crate::RedactionPolicy;
use crate::Sensitivity;

/// Owns one rendering runtime and its independently resolvable item buffer.
pub(crate) struct BatchSession {
    /// Identity embedded in every handle produced by this transaction.
    id: u64,
    /// Shared rendering policy and accounting.
    runtime: RenderRuntime,
    /// Item text and summaries retained until publication.
    output: BatchOutputBuffer,
}

impl BatchSession {
    /// Redacts one field as an individually resolvable transaction item.
    ///
    /// The returned handle does not expose text before [`Self::finish`]
    /// publishes the transaction.
    #[must_use]
    pub fn redact_field<T>(&mut self, field: &str, value: &T) -> RedactionHandle
    where
        T: std::fmt::Display + ?Sized,
    {
        if self.is_output_exhausted() {
            return self.stage_exhausted_handle();
        }
        self.run_handle(|session| {
            let output = session.redact_field_display_output(field, value);
            session.stage_rendered_operation(output)
        })
    }

    /// Stages a domain value whose writer has already charged traversal state
    /// to the shared transaction. This records that operation's delta without
    /// merging its domain charges a second time.
    fn stage_domain_item(&mut self, text: String) -> RedactionHandle {
        let item_index = self.output.len();
        if text.len() > self.remaining_output_bytes() {
            self.runtime.core.phase = TransactionPhase::OutputExhausted;
            let summary = crate::RedactionSummary::exhausted(crate::RedactionReason::OutputLimitReached);
            self.record_summary(summary);
            let item_summary = self
                .runtime
                .core
                .active_operation_summary
                .unwrap_or(SummaryBuilder::from_summary(summary));
            self.output.push(
                String::new(),
                item_summary.build(
                    self.runtime
                        .core
                        .budget
                        .active_operation_usage()
                        .unwrap_or_else(crate::RedactionUsage::empty),
                ),
            );
        } else {
            self.record_output_bytes(text.len());
            let summary = self
                .runtime
                .core
                .active_operation_summary
                .unwrap_or_else(|| SummaryBuilder::new(self.policy().is_disabled()));
            let usage = self
                .runtime
                .core
                .budget
                .active_operation_usage()
                .unwrap_or_else(crate::RedactionUsage::empty);
            self.output.push(text, summary.build(usage));
        }
        RedactionHandle::new(self.id, item_index)
    }

    /// Redacts one field into owned safe text with its fragment completion.
    #[allow(dead_code)]
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

    /// Redacts one display value under the remaining batch output allowance.
    pub(crate) fn redact_field_display_output<T>(&mut self, field: &str, value: &T) -> RenderedOperation
    where
        T: std::fmt::Display + ?Sized,
    {
        let (redacted, completion) = field_rendering::redact_field_display_for_output(
            self.policy(),
            field,
            value,
            self.remaining_output_bytes(),
        );
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
        let item_index = self.output.len();
        let remaining = self.remaining_output_bytes();
        let replacement_could_not_fit = text.is_empty() && reasons.contains(crate::RedactionReason::OutputLimitReached);
        let (retained, item_summary) = if self.runtime.core.phase == TransactionPhase::OutputExhausted
            || completion == RedactionCompletion::Exhausted
            || replacement_could_not_fit
            || text.len() > remaining
        {
            self.runtime.core.phase = TransactionPhase::OutputExhausted;
            let exhausted = crate::RedactionSummary::exhausted(crate::RedactionReason::OutputLimitReached);
            self.record_summary(operation_summary);
            self.record_summary(exhausted);
            let item_summary = self
                .runtime
                .core
                .active_operation_summary
                .unwrap_or(SummaryBuilder::from_summary(exhausted));
            (
                String::new(),
                item_summary.build(
                    self.runtime
                        .core
                        .budget
                        .active_operation_usage()
                        .unwrap_or_else(crate::RedactionUsage::empty),
                ),
            )
        } else {
            self.record_summary(operation_summary);
            self.record_output_bytes(text.len());
            let item_summary = self
                .runtime
                .core
                .active_operation_summary
                .unwrap_or(SummaryBuilder::from_summary(operation_summary));
            if self.remaining_output_bytes() == 0 {
                // An exactly fitting handle is valid and complete; it simply
                // closes this transaction to all subsequent work.
                self.runtime.core.phase = TransactionPhase::OutputExhausted;
            }
            (
                text,
                item_summary.build(
                    self.runtime
                        .core
                        .budget
                        .active_operation_usage()
                        .unwrap_or_else(crate::RedactionUsage::empty),
                ),
            )
        };
        self.output.push(retained, item_summary);
        RedactionHandle::new(self.id, item_index)
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
        self.runtime.core.phase = TransactionPhase::OutputExhausted;
        if let Some(item_index) = self.output.exhausted_item() {
            return RedactionHandle::new(self.id, item_index);
        }
        let summary = crate::RedactionSummary::exhausted(crate::RedactionReason::OutputLimitReached);
        self.record_summary(summary);
        let item_summary = self
            .runtime
            .core
            .active_operation_summary
            .unwrap_or(SummaryBuilder::from_summary(summary))
            .build(
                self.runtime
                    .core
                    .budget
                    .active_operation_usage()
                    .unwrap_or_else(crate::RedactionUsage::empty),
            );
        let item_index = self.output.len();
        self.output.push(String::new(), item_summary);
        self.output.set_exhausted_item(item_index);
        RedactionHandle::new(self.id, item_index)
    }

    /// Returns bounded field text with the completion caused by its allowance.
    #[allow(dead_code)]
    fn redact_field_with_completion(&mut self, field: &str, value: &str) -> (String, RedactionCompletion) {
        let policy = self.policy();
        let (redacted, completion) =
            field_rendering::redact_field_text_for_output(policy, field, value, self.remaining_output_bytes());
        (redacted, completion)
    }
}

impl BatchSession {
    /// Creates a batch transaction from one immutable policy snapshot.
    #[must_use]
    pub(crate) fn new(policy: Arc<RedactionPolicy>) -> Self {
        Self {
            id: super::transaction_id::next_transaction_id(),
            runtime: RenderRuntime::new(policy),
            output: BatchOutputBuffer::new(),
        }
    }

    /// Consumes the transaction into independently resolvable items.
    #[must_use]
    pub(crate) fn finish(self) -> BatchPublication {
        BatchPublication::new(self.id, self.output.publish(), self.runtime.core.into_summary())
    }

    /// Runs one item operation under panic rollback semantics.
    fn run_handle(&mut self, operation: impl FnOnce(&mut Self) -> RedactionHandle) -> RedactionHandle {
        let mut guard = TransactionGuard::new(self);
        let owns_item_summary = guard.session().begin_item_summary();
        let handle = operation(guard.session());
        guard.session().end_item_summary(owns_item_summary);
        guard.commit();
        handle
    }

    /// Redacts one structured domain value as an independently resolvable item.
    #[must_use]
    pub(crate) fn redact_value<T>(&mut self, value: &T) -> RedactionHandle
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

    /// Redacts explicitly classified arguments as one batch item.
    pub(crate) fn redact_argv<'items, I>(&mut self, items: I) -> RedactionHandle
    where
        I: IntoIterator<Item = crate::formats::argv::ArgvItem<'items>>,
    {
        self.run_handle(|session| crate::formats::argv::batch_redaction::redact_items(session, items))
    }

    /// Redacts heuristically classified arguments as one batch item.
    pub(crate) fn redact_heuristic_argv<'items, I>(&mut self, items: I) -> RedactionHandle
    where
        I: IntoIterator<Item = crate::formats::argv::ArgvItem<'items>>,
    {
        self.run_handle(|session| crate::formats::argv::batch_redaction::redact_heuristic_items(session, items))
    }

    /// Redacts one environment pair as a batch item.
    pub(crate) fn redact_env(&mut self, name: &str, value: &str) -> RedactionHandle {
        self.run_handle(|session| crate::formats::env::batch_redaction::redact_pair(session, name, value))
    }

    /// Redacts environment pairs as one batch item.
    pub(crate) fn redact_env_pairs<'items, I>(&mut self, pairs: I) -> RedactionHandle
    where
        I: IntoIterator<Item = (&'items std::ffi::OsStr, &'items std::ffi::OsStr)>,
    {
        self.run_handle(|session| crate::formats::env::batch_redaction::redact_os_pairs(session, pairs))
    }

    /// Redacts one process command as a batch item.
    pub(crate) fn redact_process<'arguments, 'variables, A, E>(
        &mut self,
        program: &'arguments std::ffi::OsStr,
        arguments: A,
        variables: E,
    ) -> RedactionHandle
    where
        A: IntoIterator<Item = crate::formats::argv::ArgvItem<'arguments>>,
        E: IntoIterator<Item = (&'variables std::ffi::OsStr, &'variables std::ffi::OsStr)>,
    {
        self.run_handle(|session| {
            crate::formats::process::batch_redaction::redact_command(session, program, arguments, variables)
        })
    }

    /// Redacts JSON text as one batch item.
    #[cfg(feature = "json")]
    pub(crate) fn redact_json(&mut self, text: &str) -> RedactionHandle {
        self.run_handle(|session| crate::formats::json::batch_redaction::redact_text(session, text))
    }

    /// Redacts a parsed JSON value as one batch item.
    #[cfg(feature = "json")]
    pub(crate) fn redact_json_value(&mut self, value: &serde_json::Value) -> RedactionHandle {
        self.run_handle(|session| crate::formats::json::batch_redaction::redact_value(session, value))
    }

    /// Redacts one URI as a batch item.
    #[cfg(feature = "uri")]
    pub(crate) fn redact_uri(&mut self, value: &str) -> RedactionHandle {
        self.run_handle(|session| crate::formats::uri::batch_redaction::redact_uri(session, value))
    }

    /// Redacts an HTTP URL as one batch item.
    #[cfg(feature = "http")]
    pub(crate) fn redact_http_url(&mut self, value: &str) -> RedactionHandle {
        self.run_handle(|session| crate::formats::http::batch_redaction::redact_url(session, value))
    }

    /// Redacts HTTP headers as one batch item.
    #[cfg(feature = "http")]
    pub(crate) fn redact_http_headers(&mut self, headers: &http::HeaderMap) -> RedactionHandle {
        self.run_handle(|session| crate::formats::http::batch_redaction::redact_headers(session, headers))
    }

    /// Redacts a captured HTTP body as one batch item.
    #[cfg(feature = "http")]
    pub(crate) fn redact_http_body(
        &mut self,
        capture: crate::formats::http::BodyCapture<'_>,
        content_type: Option<&http::HeaderValue>,
    ) -> RedactionHandle {
        self.run_handle(|session| crate::formats::http::batch_redaction::redact_body(session, capture, content_type))
    }

    /// Redacts a captured HTTP body with textual Content-Type.
    #[cfg(feature = "http")]
    pub(crate) fn redact_http_body_with_content_type_text(
        &mut self,
        capture: crate::formats::http::BodyCapture<'_>,
        content_type: Option<&str>,
    ) -> RedactionHandle {
        self.run_handle(|session| {
            crate::formats::http::batch_redaction::redact_body_with_content_type_text(session, capture, content_type)
        })
    }
}

impl RuntimeSession for BatchSession {
    /// Borrows the publication-independent batch accounting core.
    #[inline(always)]
    fn runtime(&self) -> &RuntimeCore {
        &self.runtime.core
    }

    /// Mutably borrows the publication-independent batch accounting core.
    #[inline(always)]
    fn runtime_mut(&mut self) -> &mut RuntimeCore {
        &mut self.runtime.core
    }

    /// Identifies this session as rendering state.
    #[inline(always)]
    fn is_inspection(&self) -> bool {
        false
    }

    /// Ignores inspection-only observations in batch mode.
    #[inline(always)]
    fn observe_sensitivity(&mut self, _sensitivity: Sensitivity) {
        // Batch transactions render decisions into independently published
        // items instead of accumulating inspection results.
    }
}

impl ResettableSession for BatchSession {
    /// Replaces a panicked transaction and invalidates its unpublished handles.
    fn reset_transaction(&mut self) {
        let policy = Arc::clone(&self.runtime.core.policy);
        *self = Self::new(policy);
    }
}
