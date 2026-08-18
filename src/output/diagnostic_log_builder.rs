// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared bounded construction of log-safe diagnostic text.

use std::borrow::Cow;
use std::fmt;
use std::fmt::Write as _;

use super::RedactedText;
use super::RedactionCompletion;
use super::internal::BoundedLogEscapeWriter;
use crate::RedactionOutput;
use crate::InputOutputLimit;
use crate::LogOutputLimit;
use crate::RedactionSession;
use crate::Sensitivity;

/// Builds one log-safe diagnostic under a final output budget.
///
/// This type guarantees log-structure escaping and a bounded final rendering.
/// Callers can append already-safe values or redact scalar fields through a
/// shared [`RedactionSession`].
pub struct DiagnosticLogBuilder {
    writer: BoundedLogEscapeWriter,
}

impl DiagnosticLogBuilder {
    /// Creates a builder from one diagnostic output budget.
    ///
    /// # Parameters
    ///
    /// * `budget` - Policy limit whose output bound applies to this rendering.
    ///
    /// # Returns
    ///
    /// An empty builder with bounded output.
    #[must_use]
    #[inline]
    pub fn new(budget: InputOutputLimit) -> Self {
        Self {
            writer: BoundedLogEscapeWriter::new(LogOutputLimit::from(budget)),
        }
    }

    /// Appends a formatted fragment after streaming log-control escaping.
    ///
    /// The formatting arguments are not evaluated after this builder has
    /// already truncated its output.
    ///
    /// # Parameters
    ///
    /// * `arguments` - Raw or already-redacted formatting arguments.
    ///
    /// # Returns
    ///
    /// [`RedactionCompletion::Complete`] when the fragment fit,
    /// [`RedactionCompletion::Truncated`] after a complete marker was emitted,
    /// or [`RedactionCompletion::Exhausted`] when no safe output fit.
    ///
    /// # Errors
    ///
    /// Returns a formatter error from an argument that failed independently of
    /// output truncation.
    pub fn push_fmt(&mut self, arguments: fmt::Arguments<'_>) -> Result<RedactionCompletion, fmt::Error> {
        if self.writer.is_truncated() {
            return Ok(self.truncation_completion());
        }
        match fmt::write(&mut self.writer, arguments) {
            Ok(()) => Ok(RedactionCompletion::Complete),
            Err(_) if self.writer.is_truncated() => Ok(self.truncation_completion()),
            Err(error) => Err(error),
        }
    }

    /// Appends an already log-safe fragment under the shared output budget.
    ///
    /// # Parameters
    ///
    /// * `text` - Escaped text that cannot contain raw log controls.
    ///
    /// # Returns
    ///
    /// [`RedactionCompletion::Complete`] when the fragment fit,
    /// [`RedactionCompletion::Truncated`] after a complete marker was emitted,
    /// or [`RedactionCompletion::Exhausted`] when no safe output fit.
    #[inline]
    pub fn push_safe(&mut self, text: &RedactedText) -> RedactionCompletion {
        if self.writer.is_truncated() {
            return self.truncation_completion();
        }
        let _ = self.writer.write_str(text.as_str());
        if self.writer.is_truncated() {
            self.truncation_completion()
        } else {
            RedactionCompletion::Complete
        }
    }

    /// Redacts and appends one field through a shared diagnostic session.
    ///
    /// The field and value are not inspected after this builder has truncated.
    /// The session supplies the policy and accumulates input and generated-mask
    /// output across every redacted fragment in the enclosing event.
    pub fn push_redacted_field(
        &mut self,
        session: &mut RedactionSession<'_>,
        field: &str,
        value: &str,
    ) -> RedactionCompletion {
        if self.writer.is_truncated() {
            return self.truncation_completion();
        }
        let output = session.redact_field_output(field, value);
        self.push_redaction_output(output)
    }

    /// Redacts and appends one explicitly sensitive value through a shared
    /// diagnostic session.
    ///
    /// The value is not inspected after this builder has truncated. The
    /// explicit sensitivity bypasses field-name classification while retaining
    /// the session's cumulative resource accounting.
    pub fn push_redacted_at(
        &mut self,
        session: &mut RedactionSession<'_>,
        level: Sensitivity,
        value: &str,
    ) -> RedactionCompletion {
        if self.writer.is_truncated() {
            return self.truncation_completion();
        }
        let output = session.redact_at_output(level, value);
        self.push_redaction_output(output)
    }

    /// Reports whether the final output has been truncated.
    ///
    /// # Returns
    ///
    /// True after the complete truncation marker has been emitted.
    #[must_use]
    #[inline]
    pub const fn is_truncated(&self) -> bool {
        self.writer.is_truncated()
    }

    /// Classifies a writer that has stopped because its output budget ended.
    ///
    /// # Returns
    ///
    /// [`RedactionCompletion::Truncated`] when non-empty safe substitute text
    /// was emitted, or [`RedactionCompletion::Exhausted`] when the writer could
    /// not emit any safe text.
    #[inline]
    fn truncation_completion(&self) -> RedactionCompletion {
        if self.writer.len() == 0 {
            RedactionCompletion::Truncated
        } else {
            RedactionCompletion::Truncated
        }
    }

    /// Appends one session-produced output while preserving source completion.
    ///
    /// # Parameters
    ///
    /// * `output` - Owned safe text and completion from one redacted fragment.
    ///
    /// # Returns
    ///
    /// Source completion when the append fits, or the more terminal builder
    /// completion when this output budget truncates or emits no text.
    fn push_redaction_output(&mut self, output: RedactionOutput) -> RedactionCompletion {
        let source_completion = output.completion();
        let text = output.into_log_safe_text();
        let write_completion = self.push_safe(&text);
        match write_completion {
            RedactionCompletion::Complete => source_completion,
            RedactionCompletion::Truncated => RedactionCompletion::Truncated,
            RedactionCompletion::Truncated => RedactionCompletion::Truncated,
        }
    }

    /// Finishes the builder as an owned log-safe text value.
    ///
    /// # Returns
    ///
    /// A typed log-safe value containing the bounded escaped output.
    #[inline]
    #[must_use]
    pub fn finish(self) -> RedactedText {
        RedactedText::from_escaped(Cow::Owned(self.writer.finish()))
    }
}
