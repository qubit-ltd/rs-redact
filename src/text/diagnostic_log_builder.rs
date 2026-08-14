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

use super::DiagnosticWriteStatus;
use super::LogSafeText;
use super::internal::BoundedLogEscapeWriter;
use crate::InputOutputLimit;
use crate::LogOutputLimit;
use crate::RedactionSession;
use crate::Sensitivity;

/// Builds one log-safe diagnostic under a final output budget.
///
/// This type guarantees log-structure escaping and a bounded final rendering.
/// Callers can append already-safe values or redact scalar fields through a
/// shared [`RedactionSession`].
#[must_use = "finish the diagnostic into log-safe text"]
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
    /// `Complete` when the fragment fit, or `Truncated` after the marker was
    /// emitted.
    ///
    /// # Errors
    ///
    /// Returns a formatter error from an argument that failed independently of
    /// output truncation.
    pub fn push_fmt(
        &mut self,
        arguments: fmt::Arguments<'_>,
    ) -> Result<DiagnosticWriteStatus, fmt::Error> {
        if self.writer.is_truncated() {
            return Ok(DiagnosticWriteStatus::Truncated);
        }
        match fmt::write(&mut self.writer, arguments) {
            Ok(()) => Ok(DiagnosticWriteStatus::Complete),
            Err(_) if self.writer.is_truncated() => Ok(DiagnosticWriteStatus::Truncated),
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
    /// `Complete` when the fragment fit, or `Truncated` after the marker was
    /// emitted.
    #[inline]
    pub fn push_safe(&mut self, text: &LogSafeText<'_>) -> DiagnosticWriteStatus {
        if self.writer.is_truncated() {
            return DiagnosticWriteStatus::Truncated;
        }
        let _ = self.writer.write_str(text.as_str());
        if self.writer.is_truncated() {
            DiagnosticWriteStatus::Truncated
        } else {
            DiagnosticWriteStatus::Complete
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
    ) -> DiagnosticWriteStatus {
        if self.writer.is_truncated() {
            return DiagnosticWriteStatus::Truncated;
        }
        let text = session.redact_field(field, value).escape_for_log();
        self.push_safe(&text)
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
    ) -> DiagnosticWriteStatus {
        if self.writer.is_truncated() {
            return DiagnosticWriteStatus::Truncated;
        }
        let text = session.redact_at(level, value).escape_for_log();
        self.push_safe(&text)
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

    /// Finishes the builder as an owned log-safe text value.
    ///
    /// # Returns
    ///
    /// A typed log-safe value containing the bounded escaped output.
    #[inline]
    pub fn finish(self) -> LogSafeText<'static> {
        LogSafeText::from_escaped(Cow::Owned(self.writer.finish()))
    }
}
