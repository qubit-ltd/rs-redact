// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Log-safe rendering of a redacted argument vector.

use std::fmt;
use std::fmt::Display;
use std::fmt::Formatter;

use super::redacted_argv_builder::RedactedArgvBuilder;
use crate::InputOutputLimit;
use crate::LogSafeText;
use crate::RedactionCompletion;
use crate::output::redaction_output::RedactionOutput;

/// A redacted argv rendering that is safe for a single-line text log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedArgv {
    /// Escaped rendering paired with its exact completion state.
    output: RedactionOutput,
}

impl RedactedArgv {
    /// Creates a bounded argv rendering builder for one diagnostic budget.
    ///
    /// # Parameters
    ///
    /// * `budget` - Input and output limits for the diagnostic rendering.
    ///
    /// # Returns
    ///
    /// An empty byte-bounded argv rendering builder.
    #[must_use]
    #[inline]
    pub(super) fn builder(budget: InputOutputLimit) -> RedactedArgvBuilder {
        RedactedArgvBuilder::new(budget)
    }

    /// Creates a complete argv value from already escaped bounded output.
    ///
    /// # Parameters
    ///
    /// * `rendered` - Escaped debug-style argv rendering.
    ///
    /// # Returns
    ///
    /// A displayable argv value.
    #[inline(always)]
    #[must_use]
    pub(super) fn complete(rendered: LogSafeText<'static>) -> Self {
        Self {
            output: RedactionOutput::complete(rendered),
        }
    }

    /// Creates a truncated argv value from non-empty safe substitute output.
    ///
    /// # Parameters
    ///
    /// * `rendered` - Non-empty escaped substitute or truncation marker.
    ///
    /// # Returns
    ///
    /// A truncated result when `rendered` is non-empty; otherwise the sole
    /// valid exhausted result.
    #[inline(always)]
    #[must_use]
    pub(super) fn truncated(rendered: LogSafeText<'static>) -> Self {
        Self {
            output: RedactionOutput::truncated(rendered).unwrap_or_else(RedactionOutput::exhausted),
        }
    }

    /// Creates an exhausted argv value without safe substitute text.
    ///
    /// # Returns
    ///
    /// Empty safe text paired with [`RedactionCompletion::Exhausted`].
    #[inline(always)]
    #[must_use]
    pub(super) fn exhausted() -> Self {
        Self {
            output: RedactionOutput::exhausted(),
        }
    }

    /// Borrows the already escaped diagnostic representation.
    ///
    /// The returned text is safe to append through
    /// [`crate::DiagnosticLogBuilder::push_safe`]. Callers remain responsible
    /// for applying any enclosing output budget.
    #[must_use]
    #[inline(always)]
    pub const fn log_safe_text(&self) -> &LogSafeText<'static> {
        self.output.log_safe_text()
    }

    /// Reports whether argv processing completed, substituted, or exhausted.
    ///
    /// # Returns
    ///
    /// [`RedactionCompletion::Complete`] after full rendering,
    /// [`RedactionCompletion::Truncated`] when non-empty safe substitute text
    /// represents omitted input or output, or
    /// [`RedactionCompletion::Exhausted`] when the result is empty and the
    /// input iterator was not advanced after exhaustion.
    #[inline(always)]
    pub const fn completion(&self) -> RedactionCompletion {
        self.output.completion()
    }

    /// Consumes the result and returns its log-safe diagnostic text.
    ///
    /// # Returns
    ///
    /// Complete or substitute safe text, or an empty value when
    /// [`Self::completion`] was [`RedactionCompletion::Exhausted`].
    #[must_use]
    #[inline(always)]
    pub fn into_log_safe_text(self) -> LogSafeText<'static> {
        self.output.into_log_safe_text()
    }
}

impl Display for RedactedArgv {
    /// Writes the escaped argv result text.
    ///
    /// # Parameters
    ///
    /// * `formatter` - Destination formatting context.
    ///
    /// # Returns
    ///
    /// The formatter result from writing complete, truncated, or empty
    /// exhausted output.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the destination formatter rejects output.
    #[inline(always)]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(self.output.log_safe_text(), formatter)
    }
}
