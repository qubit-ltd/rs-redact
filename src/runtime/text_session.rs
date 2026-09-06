// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Ordered-text transaction with compile-time publication ownership.

use std::sync::Arc;

use super::field_rendering::redact_field_display_for_output;
use super::render_runtime::RenderRuntime;
use super::rendered_operation::RenderedOperation;
use super::rendered_summary::rendered_summary;
use super::resettable_session::ResettableSession;
use super::runtime_session::RuntimeSession;
use super::text_output_buffer::TextOutputBuffer;
use super::transaction_guard::TransactionGuard;
use super::transaction_phase::TransactionPhase;
use crate::Redact;
use crate::RedactionCompletion;
use crate::RedactionPolicy;
use crate::RedactionReason;
use crate::RedactionSummary;
use crate::RedactionTextOutput;
use crate::Sensitivity;
use crate::formats::argv::ArgvRedactionWriter;
use crate::formats::env::EnvRedactionWriter;
#[cfg(feature = "http")]
use crate::formats::http::HttpRedactionWriter;
#[cfg(feature = "json")]
use crate::formats::json::JsonRedactionWriter;
use crate::formats::process::ProcessRedactionWriter;
#[cfg(feature = "uri")]
use crate::formats::uri::UriRedactionWriter;

/// Owns one rendering runtime and its ordered text publication buffer.
pub(crate) struct TextSession {
    /// Shared rendering policy and accounting.
    runtime: RenderRuntime,
    /// Ordered text retained until `finish` publishes the transaction.
    output: TextOutputBuffer,
}

impl TextSession {
    /// Creates a text transaction from one immutable policy snapshot.
    #[must_use]
    pub(crate) fn new(policy: Arc<RedactionPolicy>) -> Self {
        Self {
            runtime: RenderRuntime::new(policy),
            output: TextOutputBuffer::new(),
        }
    }

    /// Appends trusted program-authored literal text.
    #[must_use]
    #[inline(always)]
    pub(crate) fn literal(&mut self, text: &'static str) -> &mut Self {
        self.append_output_fragment(text);
        self
    }

    /// Redacts and appends one scalar field in chain order.
    #[must_use]
    pub(crate) fn field<T>(&mut self, field: &str, value: &T) -> &mut Self
    where
        T: std::fmt::Display + ?Sized,
    {
        if self.skip_aggregate_for_exhausted_output() {
            return self;
        }
        let rendered = self.redact_field_display_output(field, value);
        self.append_rendered_operation(rendered);
        self
    }

    /// Redacts and appends one structured domain value in chain order.
    #[must_use]
    pub(crate) fn value<T>(&mut self, value: &T) -> &mut Self
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

    /// Runs an argv adapter under panic rollback semantics.
    pub(crate) fn argv<F>(&mut self, configure: F) -> &mut Self
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

    /// Runs an environment adapter under panic rollback semantics.
    pub(crate) fn env<F>(&mut self, configure: F) -> &mut Self
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

    /// Runs a process adapter under panic rollback semantics.
    #[must_use]
    pub(crate) fn process<F>(&mut self, configure: F) -> &mut Self
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

    /// Runs an HTTP adapter under panic rollback semantics.
    #[cfg(feature = "http")]
    pub(crate) fn http<F>(&mut self, configure: F) -> &mut Self
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

    /// Runs a JSON adapter under panic rollback semantics.
    #[cfg(feature = "json")]
    pub(crate) fn json<F>(&mut self, configure: F) -> &mut Self
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

    /// Runs a URI adapter under panic rollback semantics.
    #[cfg(feature = "uri")]
    pub(crate) fn uri<F>(&mut self, configure: F) -> &mut Self
    where
        F: for<'session> FnOnce(&mut UriRedactionWriter<'session>),
    {
        if self.skip_aggregate_for_exhausted_output() {
            return self;
        }
        self.run_adapter(|session| {
            let mut adapter = UriRedactionWriter::new(session);
            configure(&mut adapter);
        });
        self
    }

    /// Consumes this transaction into its ordered text and summary.
    #[must_use]
    pub(crate) fn finish(self) -> RedactionTextOutput {
        RedactionTextOutput::new(self.output.publish(), self.runtime.core.into_summary())
    }

    /// Appends a chain fragment if its escaped form fits the output budget.
    fn append_output_fragment(&mut self, fragment: &str) {
        if self.runtime.core.phase == TransactionPhase::OutputExhausted {
            self.runtime.core.summary = self.runtime.core.summary.merge(
                RedactionSummary::exhausted(RedactionReason::OutputLimitReached),
            );
            return;
        }
        let escaped = crate::output::log_escape::escape_log_control_characters(
            std::borrow::Cow::Borrowed(fragment),
        );
        let used = self.runtime.core.budget.usage().output_bytes();
        let remaining = self.runtime.core.budget.output_limit().saturating_sub(used);
        if escaped.len() > remaining {
            self.runtime.core.phase = TransactionPhase::OutputExhausted;
            self.runtime.core.summary = self.runtime.core.summary.merge(
                RedactionSummary::exhausted(RedactionReason::OutputLimitReached),
            );
            return;
        }
        self.output.push(&escaped);
        self.runtime.core.budget.record_output_bytes(escaped.len());
        if self.runtime.core.budget.usage().output_bytes()
            == self.runtime.core.budget.output_limit()
        {
            self.runtime.core.phase = TransactionPhase::OutputExhausted;
        }
    }

    /// Executes one user adapter under panic rollback semantics.
    fn run_adapter(&mut self, configure: impl FnOnce(&mut Self)) {
        let mut guard = TransactionGuard::new(self);
        configure(guard.session());
        guard.commit();
    }

    /// Appends output rendered by a structured domain writer.
    fn append_domain_output(&mut self, output: &str, output_limit_reached: bool) {
        if output_limit_reached {
            let summary = if output.is_empty()
                || self.runtime.core.phase == TransactionPhase::OutputExhausted
            {
                RedactionSummary::exhausted(RedactionReason::OutputLimitReached)
            } else {
                RedactionSummary::truncated(RedactionReason::OutputLimitReached)
            };
            self.record_summary(summary);
        }
        self.append_output_fragment(output);
    }

    /// Commits one renderer result to the ordered publication buffer.
    pub(crate) fn append_rendered_operation(&mut self, operation: RenderedOperation) {
        let (text, completion, reasons) = operation.into_parts();
        self.record_summary(rendered_summary(completion, reasons));
        let replacement_could_not_fit =
            text.is_empty() && reasons.contains(RedactionReason::OutputLimitReached);
        if completion == RedactionCompletion::Exhausted || replacement_could_not_fit {
            self.runtime.core.phase = TransactionPhase::OutputExhausted;
            self.record_summary(RedactionSummary::exhausted(
                RedactionReason::OutputLimitReached,
            ));
            return;
        }
        self.append_output_fragment(&text);
    }

    /// Renders one scalar field without publishing it.
    fn redact_field_display_output<T>(&mut self, field: &str, value: &T) -> RenderedOperation
    where
        T: std::fmt::Display + ?Sized,
    {
        let (redacted, completion) = redact_field_display_for_output(
            self.policy(),
            field,
            value,
            self.remaining_output_bytes(),
        );
        match completion {
            RedactionCompletion::Complete => {
                super::operation_sink::OperationSink::complete(redacted).finish()
            }
            RedactionCompletion::Truncated => super::operation_sink::OperationSink::truncated(
                redacted,
                RedactionReason::OutputLimitReached,
            )
            .finish(),
            RedactionCompletion::Exhausted => super::operation_sink::OperationSink::exhausted(
                redacted,
                RedactionReason::OutputLimitReached,
            )
            .finish(),
        }
    }
}

impl RuntimeSession for TextSession {
    /// Borrows the publication-independent text accounting core.
    #[inline(always)]
    fn runtime(&self) -> &super::runtime_core::RuntimeCore {
        &self.runtime.core
    }

    /// Mutably borrows the publication-independent text accounting core.
    #[inline(always)]
    fn runtime_mut(&mut self) -> &mut super::runtime_core::RuntimeCore {
        &mut self.runtime.core
    }

    /// Identifies this session as rendering state.
    #[inline(always)]
    fn is_inspection(&self) -> bool {
        false
    }

    /// Ignores inspection-only observations in text mode.
    #[inline(always)]
    fn observe_sensitivity(&mut self, _sensitivity: Sensitivity) {
        // Text transactions render policy decisions instead of accumulating
        // inspection results.
    }
}

impl ResettableSession for TextSession {
    /// Replaces a panicked transaction with a fresh text transaction.
    fn reset_transaction(&mut self) {
        let policy = Arc::clone(&self.runtime.core.policy);
        *self = Self::new(policy);
    }
}
