// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Independently resolvable batch transaction with typed publication storage.

use std::borrow::Cow;
use std::ffi::OsStr;
use std::fmt::Display;
use std::sync::Arc;

#[cfg(feature = "http")]
use http::HeaderMap;
#[cfg(feature = "http")]
use http::HeaderValue;
#[cfg(feature = "json")]
use serde_json::Value;

use super::batch_output_buffer::BatchOutputBuffer;
use super::batch_publication::BatchPublication;
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
use crate::RedactionPolicy;
use crate::Sensitivity;
#[cfg(feature = "http")]
use crate::formats::http::BodyCapture;
#[cfg(feature = "http")]
use crate::formats::http::batch_redaction as http_batch_redaction;

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
    ///
    /// # Type Parameters
    ///
    /// - `T`: Possibly unsized scalar implementing `Display`.
    ///
    /// # Parameters
    ///
    /// - `field`: Raw field key admitted before classification.
    /// - `value`: Borrowed scalar formatted only when the selected policy needs
    ///   it.
    ///
    /// # Returns
    ///
    /// A handle to the staged safe item; no text is published before finish.
    #[must_use]
    pub fn redact_field<T>(&mut self, field: &str, value: &T) -> RedactionHandle
    where
        T: Display + ?Sized,
    {
        if self.is_output_exhausted() {
            return self.stage_exhausted_handle();
        }
        self.run_handle(|session| {
            let output = super::scalar_operation::redact_field(session, field, value);
            session.stage_rendered_operation(output)
        })
    }

    /// Reports whether no later batch item may inspect input.
    ///
    /// # Returns
    ///
    /// Whether later batch operations must skip input access and output work.
    #[must_use]
    #[inline(always)]
    pub(crate) fn is_output_exhausted(&self) -> bool {
        RuntimeSession::is_output_exhausted(self)
    }

    /// Stages one unpublished adapter result as an individually resolvable
    /// item.
    ///
    /// # Parameters
    ///
    /// - `operation`: Already escaped, bounded rendering with completion facts.
    ///
    /// # Returns
    ///
    /// A stable handle for the staged item, retaining operation-local
    /// accounting.
    pub(crate) fn stage_rendered_operation(&mut self, operation: RenderedOperation) -> RedactionHandle {
        let output_closed = operation.output_closed();
        let (text, completion, reasons) = operation.into_parts();
        let operation_summary = rendered_summary(completion, reasons);
        let item_index = self.output.len();
        let remaining = self.remaining_output_bytes();
        let (retained, item_summary) =
            if self.runtime.core.phase == TransactionPhase::OutputExhausted || text.len() > remaining {
                self.runtime.core.phase = TransactionPhase::OutputExhausted;
                let exhausted = crate::RedactionSummary::exhausted();
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
                if output_closed || self.remaining_output_bytes() == 0 {
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
    ///
    /// # Parameters
    ///
    /// - `text`: Already escaped text whose active item scope owns its
    ///   accounting.
    ///
    /// # Returns
    ///
    /// A handle to the item staged from the accounted text.
    #[inline(always)]
    pub(crate) fn stage_accounted_text(&mut self, text: impl Into<String>) -> RedactionHandle {
        self.stage_rendered_operation(OperationSink::complete(text).finish())
    }

    /// Stages the standard empty result without inspecting a later input once
    /// the transaction's output budget has closed.
    ///
    /// # Returns
    ///
    /// The batch's shared exhausted sentinel handle, creating it only once.
    #[must_use]
    pub(crate) fn stage_exhausted_handle(&mut self) -> RedactionHandle {
        self.runtime.core.phase = TransactionPhase::OutputExhausted;
        if let Some(item_index) = self.output.exhausted_item() {
            return RedactionHandle::new(self.id, item_index);
        }
        let summary = crate::RedactionSummary::exhausted();
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

    /// Stages a domain value whose writer has already charged traversal state
    /// to the shared transaction. This records that operation's delta without
    /// merging its domain charges a second time.
    ///
    /// # Parameters
    ///
    /// - `text`: Already escaped domain output; traversal was charged by its
    ///   writer.
    ///
    /// # Returns
    ///
    /// A handle to this item without charging domain traversal a second time.
    fn stage_domain_item(&mut self, text: String) -> RedactionHandle {
        let item_index = self.output.len();
        if text.len() > self.remaining_output_bytes() {
            self.runtime.core.phase = TransactionPhase::OutputExhausted;
            let summary = crate::RedactionSummary::exhausted();
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
}

impl BatchSession {
    /// Creates a batch transaction from one immutable policy snapshot.
    ///
    /// # Parameters
    ///
    /// - `policy`: Immutable snapshot governing the new batch.
    ///
    /// # Returns
    ///
    /// A fresh batch with its own identity and empty unpublished item storage.
    #[must_use]
    pub(crate) fn new(policy: Arc<RedactionPolicy>) -> Self {
        Self {
            id: super::transaction_id::next_transaction_id(),
            runtime: RenderRuntime::new(policy),
            output: BatchOutputBuffer::new(),
        }
    }

    /// Consumes the transaction into independently resolvable items.
    ///
    /// # Returns
    ///
    /// The immutable item publication and aggregate transaction summary.
    #[must_use]
    #[inline(always)]
    pub(crate) fn finish(self) -> BatchPublication {
        BatchPublication::new(self.id, self.output.publish(), self.runtime.core.into_summary())
    }

    /// Redacts one structured domain value as an independently resolvable item.
    ///
    /// # Type Parameters
    ///
    /// - `T`: Possibly unsized domain value implementing `Redact`.
    ///
    /// # Parameters
    ///
    /// - `value`: Domain value traversed only while output admission remains
    ///   open.
    ///
    /// # Returns
    ///
    /// A stable handle for the staged domain result.
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
            let escaped = crate::output::log_escape::escape_log_control_characters(Cow::Owned(rendered.0)).into_owned();
            if rendered.2 && escaped.is_empty() {
                return session.stage_exhausted_handle();
            }
            if rendered.2 {
                session.record_summary(crate::RedactionSummary::truncated(
                    crate::RedactionReason::OutputLimitReached,
                ));
            }
            let handle = session.stage_domain_item(escaped);
            if rendered.2 {
                session.runtime.core.phase = TransactionPhase::OutputExhausted;
            }
            handle
        })
    }

    /// Redacts explicitly classified arguments as one batch item.
    ///
    /// # Type Parameters
    ///
    /// - `'items`: Borrow shared by argument values.
    /// - `I`: Source converted into an iterator of classified argument items.
    ///
    /// # Parameters
    ///
    /// - `items`: Finite borrowed arguments; rejected suffixes are not pulled.
    ///
    /// # Returns
    ///
    /// A handle to the combined argument item.
    #[inline(always)]
    pub(crate) fn redact_argv<'items, I>(&mut self, items: I) -> RedactionHandle
    where
        I: IntoIterator<Item = crate::formats::argv::ArgvItem<'items>>,
    {
        self.run_handle(|session| crate::formats::argv::batch_redaction::redact_items(session, items))
    }

    /// Redacts heuristically classified arguments as one batch item.
    ///
    /// # Type Parameters
    ///
    /// - `'items`: Borrow shared by argument values.
    /// - `I`: Source converted into an iterator of classified argument items.
    ///
    /// # Parameters
    ///
    /// - `items`: Finite borrowed arguments; rejected suffixes are not pulled.
    ///
    /// # Returns
    ///
    /// A handle to the combined argument item.
    #[inline(always)]
    pub(crate) fn redact_heuristic_argv<'items, I>(&mut self, items: I) -> RedactionHandle
    where
        I: IntoIterator<Item = crate::formats::argv::ArgvItem<'items>>,
    {
        self.run_handle(|session| crate::formats::argv::batch_redaction::redact_heuristic_items(session, items))
    }

    /// Redacts one environment pair as a batch item.
    ///
    /// # Parameters
    ///
    /// - `name`: Environment variable name used for classification.
    /// - `value`: Borrowed environment value.
    ///
    /// # Returns
    ///
    /// A handle to the redacted name/value item.
    #[inline(always)]
    pub(crate) fn redact_env(&mut self, name: &str, value: &str) -> RedactionHandle {
        self.run_handle(|session| crate::formats::env::batch_redaction::redact_pair(session, name, value))
    }

    /// Redacts environment pairs as one batch item.
    ///
    /// # Type Parameters
    ///
    /// - `'items`: Borrow shared by environment names and values.
    /// - `I`: Source converted into an iterator of OS-string pairs.
    ///
    /// # Parameters
    ///
    /// - `pairs`: Finite borrowed environment pairs admitted in order.
    ///
    /// # Returns
    ///
    /// A handle to the combined environment item.
    #[inline(always)]
    pub(crate) fn redact_env_pairs<'items, I>(&mut self, pairs: I) -> RedactionHandle
    where
        I: IntoIterator<Item = (&'items OsStr, &'items OsStr)>,
    {
        self.run_handle(|session| crate::formats::env::batch_redaction::redact_os_pairs(session, pairs))
    }

    /// Redacts one process command as a batch item.
    ///
    /// # Type Parameters
    ///
    /// - `'arguments`: Borrow of program and argument values.
    /// - `'variables`: Borrow of environment names and values.
    /// - `A`: Source converted into an argument iterator.
    /// - `E`: Source converted into an environment-pair iterator.
    ///
    /// # Parameters
    ///
    /// - `program`: Borrowed executable name.
    /// - `arguments`: Finite classified arguments appended after the program.
    /// - `variables`: Finite environment pairs processed only while admission
    ///   remains open.
    ///
    /// # Returns
    ///
    /// A handle to the combined process rendering.
    #[inline(always)]
    pub(crate) fn redact_process<'arguments, 'variables, A, E>(
        &mut self,
        program: &'arguments OsStr,
        arguments: A,
        variables: E,
    ) -> RedactionHandle
    where
        A: IntoIterator<Item = crate::formats::argv::ArgvItem<'arguments>>,
        E: IntoIterator<Item = (&'variables OsStr, &'variables OsStr)>,
    {
        self.run_handle(|session| {
            crate::formats::process::batch_redaction::redact_command(session, program, arguments, variables)
        })
    }

    /// Redacts JSON text as one batch item.
    ///
    /// # Parameters
    ///
    /// - `text`: Raw JSON text admitted before parsing.
    ///
    /// # Returns
    ///
    /// A handle to the staged format item and its operation-local summary.
    #[cfg(feature = "json")]
    #[inline(always)]
    pub(crate) fn redact_json(&mut self, text: &str) -> RedactionHandle {
        self.run_handle(|session| crate::formats::json::batch_redaction::redact_text(session, text))
    }

    /// Redacts a parsed JSON value as one batch item.
    ///
    /// # Parameters
    ///
    /// - `value`: Borrowed parsed tree sharing structural and payload
    ///   admission.
    ///
    /// # Returns
    ///
    /// A handle to the staged format item and its operation-local summary.
    #[cfg(feature = "json")]
    #[inline(always)]
    pub(crate) fn redact_json_value(&mut self, value: &Value) -> RedactionHandle {
        self.run_handle(|session| crate::formats::json::batch_redaction::redact_value(session, value))
    }

    /// Redacts one URI as a batch item.
    ///
    /// # Parameters
    ///
    /// - `value`: Raw URI text admitted before parsing.
    ///
    /// # Returns
    ///
    /// A handle to the staged format item and its operation-local summary.
    #[cfg(feature = "uri")]
    #[inline(always)]
    pub(crate) fn redact_uri(&mut self, value: &str) -> RedactionHandle {
        self.run_handle(|session| crate::formats::uri::batch_redaction::redact_uri(session, value))
    }

    /// Redacts an HTTP URL as one batch item.
    ///
    /// # Parameters
    ///
    /// - `value`: Raw HTTP URL admitted before parsing.
    ///
    /// # Returns
    ///
    /// A handle to the staged format item and its operation-local summary.
    #[cfg(feature = "http")]
    #[inline(always)]
    pub(crate) fn redact_http_url(&mut self, value: &str) -> RedactionHandle {
        self.run_handle(|session| http_batch_redaction::redact_url(session, value))
    }

    /// Redacts HTTP headers as one batch item.
    ///
    /// # Parameters
    ///
    /// - `headers`: Borrowed headers preserving native sensitivity metadata.
    ///
    /// # Returns
    ///
    /// A handle to the staged format item and its operation-local summary.
    #[cfg(feature = "http")]
    #[inline(always)]
    pub(crate) fn redact_http_headers(&mut self, headers: &HeaderMap) -> RedactionHandle {
        self.run_handle(|session| http_batch_redaction::redact_headers(session, headers))
    }

    /// Redacts a captured HTTP body as one batch item.
    ///
    /// # Parameters
    ///
    /// - `capture`: Captured body bytes and original-source truncation
    ///   metadata.
    /// - `content_type`: `Some(value)` selects a declared media type; `None`
    ///   selects the policy's missing-content-type handling.
    ///
    /// # Returns
    ///
    /// A handle to the staged body item and its source-aware accounting.
    #[cfg(feature = "http")]
    #[inline(always)]
    pub(crate) fn redact_http_body(
        &mut self,
        capture: BodyCapture<'_>,
        content_type: Option<&HeaderValue>,
    ) -> RedactionHandle {
        self.run_handle(|session| http_batch_redaction::redact_body(session, capture, content_type))
    }

    /// Redacts a captured HTTP body with textual Content-Type.
    ///
    /// # Parameters
    ///
    /// - `capture`: Captured body bytes and original-source truncation
    ///   metadata.
    /// - `content_type`: `Some(value)` selects a declared media type; `None`
    ///   selects the policy's missing-content-type handling.
    ///
    /// # Returns
    ///
    /// A handle to the staged body item and its source-aware accounting.
    #[cfg(feature = "http")]
    #[inline(always)]
    pub(crate) fn redact_http_body_with_content_type_text(
        &mut self,
        capture: BodyCapture<'_>,
        content_type: Option<&str>,
    ) -> RedactionHandle {
        self.run_handle(|session| {
            http_batch_redaction::redact_body_with_content_type_text(session, capture, content_type)
        })
    }

    /// Runs one item operation under panic rollback semantics.
    ///
    /// # Parameters
    ///
    /// - `operation`: One item operation using this transaction and its nested
    ///   scopes.
    ///
    /// # Returns
    ///
    /// The issued handle after committing successful operation state.
    ///
    /// # Panics
    ///
    /// Propagates a panic from the operation after the guard resets the batch
    /// and invalidates its previous unpublished handles.
    #[inline]
    fn run_handle(&mut self, operation: impl FnOnce(&mut Self) -> RedactionHandle) -> RedactionHandle {
        let mut guard = TransactionGuard::new(self);
        let owns_item_summary = guard.session().begin_item_summary();
        let handle = operation(guard.session());
        guard.session().end_item_summary(owns_item_summary);
        guard.commit();
        handle
    }
}

impl RuntimeSession for BatchSession {
    /// Borrows the publication-independent batch accounting core.
    ///
    /// # Returns
    ///
    /// The accounting core borrowed without changing transaction state.
    #[inline(always)]
    fn runtime(&self) -> &RuntimeCore {
        &self.runtime.core
    }

    /// Mutably borrows the publication-independent batch accounting core.
    ///
    /// # Returns
    ///
    /// An exclusive borrow of the transaction accounting core.
    #[inline(always)]
    fn runtime_mut(&mut self) -> &mut RuntimeCore {
        &mut self.runtime.core
    }

    /// Identifies this session as rendering state.
    ///
    /// # Returns
    ///
    /// Whether this implementation observes sensitivity without rendering
    /// output.
    #[inline(always)]
    fn is_inspection(&self) -> bool {
        false
    }

    /// Ignores inspection-only observations in batch mode.
    ///
    /// # Parameters
    ///
    /// - `_sensitivity`: Classification ignored by this rendering mode.
    #[inline(always)]
    fn observe_sensitivity(&mut self, _sensitivity: Sensitivity) {
        // Batch transactions render decisions into independently published
        // items instead of accumulating inspection results.
    }
}

impl ResettableSession for BatchSession {
    /// Replaces a panicked transaction and invalidates its unpublished handles.
    #[inline]
    fn reset_transaction(&mut self) {
        let policy = Arc::clone(&self.runtime.core.policy);
        *self = Self::new(policy);
    }
}
