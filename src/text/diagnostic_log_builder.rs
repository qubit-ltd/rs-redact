// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared bounded construction of log-safe diagnostic text.

use std::{borrow::Cow, fmt, fmt::Write as _};

use crate::{DiagnosticBudget, DiagnosticInputBudget, LogOutputLimit};

use super::{DiagnosticWriteStatus, LogSafeText, internal::BoundedLogEscapeWriter};

/// Builds one log-safe diagnostic while sharing input and output budgets.
///
/// This type guarantees log-structure escaping and a bounded final rendering;
/// it does not perform redaction. Callers must append already-redacted values
/// or redacted formatting views when constructing a diagnostic.
#[must_use = "finish the diagnostic into log-safe text"]
pub struct DiagnosticLogBuilder {
    input_budget: DiagnosticInputBudget,
    writer: BoundedLogEscapeWriter,
}

impl DiagnosticLogBuilder {
    /// Creates a builder from one complete diagnostic budget.
    ///
    /// # Parameters
    ///
    /// * `budget` - Shared source-input and final-output limits.
    ///
    /// # Returns
    ///
    /// An empty builder with independent input accounting and bounded output.
    #[inline]
    pub fn new(budget: DiagnosticBudget) -> Self {
        Self {
            input_budget: budget.input_budget(),
            writer: BoundedLogEscapeWriter::new(LogOutputLimit::from(budget)),
        }
    }

    /// Borrows the shared source-input budget.
    ///
    /// Reserve bytes before inspecting each untrusted diagnostic segment. A
    /// failed reservation permanently exhausts the input budget.
    ///
    /// # Returns
    ///
    /// The mutable input accounting shared by this diagnostic.
    #[inline(always)]
    pub fn input_budget(&mut self) -> &mut DiagnosticInputBudget {
        &mut self.input_budget
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

    /// Reports whether the final output has been truncated.
    ///
    /// # Returns
    ///
    /// True after the complete truncation marker has been emitted.
    #[must_use]
    #[inline(always)]
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
