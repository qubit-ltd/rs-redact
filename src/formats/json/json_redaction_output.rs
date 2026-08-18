// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Structured output from shared-session JSON redaction.

use std::fmt;
use std::fmt::Display;
use std::fmt::Formatter;

use crate::RedactedText;
use crate::RedactionCompletion;
use crate::output::redaction_output::RedactionOutput;

/// Holds log-safe JSON text together with its completion state.
///
/// [`RedactionCompletion::Complete`] means the complete safe JSON rendering,
/// including an ordinary sensitivity mask, fit the budget.
/// [`RedactionCompletion::Truncated`] means input or output was omitted but a
/// non-empty safe substitute was emitted. [`RedactionCompletion::Exhausted`]
/// is the only state with empty output and means no safe substitute fit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonRedactionOutput {
    /// Invariant-preserving safe text and completion state.
    output: RedactionOutput,
}

impl JsonRedactionOutput {
    /// Creates a public JSON result from the shared internal carrier.
    ///
    /// # Parameters
    ///
    /// * `output` - Safe JSON text paired with its invariant completion state.
    ///
    /// # Returns
    ///
    /// A structured JSON redaction result.
    #[must_use]
    #[inline]
    pub(crate) const fn new(output: RedactionOutput) -> Self {
        Self { output }
    }

    /// Returns the escaped and output-bounded JSON text.
    ///
    /// # Returns
    ///
    /// Complete safe JSON, a non-empty safe substitute, or empty text after
    /// exhaustion, according to [`Self::completion`].
    #[must_use]
    #[inline(always)]
    pub const fn log_safe_text(&self) -> &RedactedText {
        self.output.log_safe_text()
    }

    /// Returns how the JSON redaction operation completed.
    ///
    /// # Returns
    ///
    /// The state paired with the safe output by the three-state invariant.
    #[inline(always)]
    pub const fn completion(&self) -> RedactionCompletion {
        self.output.completion()
    }

    /// Returns the safe JSON text as a string slice.
    ///
    /// # Returns
    ///
    /// The same text exposed by [`Self::log_safe_text`].
    #[must_use]
    #[inline(always)]
    pub fn as_str(&self) -> &str {
        self.log_safe_text().as_str()
    }

    /// Consumes this result and returns its safe JSON text.
    ///
    /// # Returns
    ///
    /// Complete safe JSON, a non-empty safe substitute, or empty exhausted
    /// output.
    #[must_use]
    #[inline(always)]
    pub fn into_log_safe_text(self) -> RedactedText {
        self.output.into_log_safe_text()
    }
}

impl Display for JsonRedactionOutput {
    /// Formats only the log-safe JSON text.
    #[inline]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(self.log_safe_text(), formatter)
    }
}
