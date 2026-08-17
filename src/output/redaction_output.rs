// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Invariant-preserving redaction output shared by diagnostic adapters.

use std::borrow::Cow;

use super::LogSafeText;
use super::RedactionCompletion;

/// Log-safe redaction text paired with its invariant completion state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RedactionOutput {
    /// Safe text produced by the redaction operation.
    text: LogSafeText<'static>,
    /// Whether the operation completed, substituted, or emitted no text.
    completion: RedactionCompletion,
}

impl RedactionOutput {
    /// Creates the output of a fully processed redaction operation.
    ///
    /// A complete result may contain any safe text, including an ordinary
    /// sensitivity mask or an intentionally empty value. Normal masking is
    /// successful redaction and does not make the result truncated.
    ///
    /// # Parameters
    ///
    /// * `text` - Complete log-safe output from the operation.
    ///
    /// # Returns
    ///
    /// The text paired with [`RedactionCompletion::Complete`].
    #[inline]
    pub(crate) fn complete(text: LogSafeText<'static>) -> Self {
        Self {
            text,
            completion: RedactionCompletion::Complete,
        }
    }

    /// Creates output that safely represents omitted input or output.
    ///
    /// # Parameters
    ///
    /// * `text` - Non-empty safe replacement text or a complete truncation
    ///   marker.
    ///
    /// # Returns
    ///
    /// `Some` paired with [`RedactionCompletion::Truncated`] when `text` is
    /// non-empty, or `None` when no safe substitute was emitted and the caller
    /// must use [`Self::exhausted`].
    #[inline]
    pub(crate) fn truncated(text: LogSafeText<'static>) -> Option<Self> {
        if text.as_str().is_empty() {
            None
        } else {
            Some(Self {
                text,
                completion: RedactionCompletion::Truncated,
            })
        }
    }

    /// Creates the sole valid result for a fully exhausted output budget.
    ///
    /// An exhausted operation emitted no safe replacement text and must not
    /// continue reading input.
    ///
    /// # Returns
    ///
    /// Empty log-safe text paired with [`RedactionCompletion::Exhausted`].
    #[inline]
    pub(crate) fn exhausted() -> Self {
        Self {
            text: LogSafeText::from_escaped(Cow::Borrowed("")),
            completion: RedactionCompletion::Exhausted,
        }
    }

    /// Borrows the safe output text.
    ///
    /// # Returns
    ///
    /// The complete, substitute, or empty text established by the constructor.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn log_safe_text(&self) -> &LogSafeText<'static> {
        &self.text
    }

    /// Reports how the redaction operation completed.
    ///
    /// # Returns
    ///
    /// The state paired with the output by its invariant constructor.
    #[inline(always)]
    pub(crate) const fn completion(&self) -> RedactionCompletion {
        self.completion
    }

    /// Consumes the result and returns its safe output text.
    ///
    /// # Returns
    ///
    /// The complete, substitute, or empty text established by the constructor.
    #[must_use]
    #[inline(always)]
    pub(crate) fn into_log_safe_text(self) -> LogSafeText<'static> {
        self.text
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::RedactionOutput;
    use crate::LogSafeText;
    use crate::RedactionCompletion;

    /// Creates an owned log-safe value for output invariant tests.
    #[must_use]
    fn safe(value: &str) -> LogSafeText<'static> {
        LogSafeText::from_escaped(Cow::Owned(value.to_owned()))
    }

    /// Verifies each constructor establishes its completion-state invariant.
    #[test]
    fn test_redaction_output_constructors_preserve_state_invariants() {
        let complete = RedactionOutput::complete(safe("done"));
        let truncated = RedactionOutput::truncated(safe("<truncated>"))
            .expect("non-empty truncated text is valid");
        let exhausted = RedactionOutput::exhausted();

        assert!(RedactionOutput::truncated(safe("")).is_none());
        assert_eq!(complete.completion(), RedactionCompletion::Complete);
        assert_eq!(truncated.completion(), RedactionCompletion::Truncated);
        assert!(!truncated.log_safe_text().as_str().is_empty());
        assert_eq!(exhausted.completion(), RedactionCompletion::Exhausted);
        assert!(exhausted.log_safe_text().as_str().is_empty());
        assert_eq!(complete.into_log_safe_text().as_str(), "done");
    }
}
