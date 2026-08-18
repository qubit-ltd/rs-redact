// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Final output paired with its execution summary.

use super::RedactedText;
use super::RedactionSummary;

/// Complete result of one redaction operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionOutput {
    text: RedactedText,
    summary: RedactionSummary,
}

impl RedactionOutput {
    /// Creates a complete output.
    #[must_use]
    pub(crate) fn new(text: RedactedText, summary: RedactionSummary) -> Self {
        Self { text, summary }
    }

    #[doc(hidden)]
    pub(crate) fn complete(text: RedactedText) -> Self {
        Self::new(text, RedactionSummary::complete())
    }

    #[doc(hidden)]
    pub(crate) fn truncated(text: RedactedText) -> Option<Self> {
        if text.as_str().is_empty() {
            None
        } else {
            Some(Self::new(text, RedactionSummary::truncated(crate::RedactionReason::OutputLimitReached)))
        }
    }

    #[doc(hidden)]
    pub(crate) fn exhausted() -> Self {
        Self::new(RedactedText::from_escaped(std::borrow::Cow::Borrowed("")), RedactionSummary::exhausted())
    }

    #[doc(hidden)]
    pub(crate) const fn log_safe_text(&self) -> &RedactedText { self.text() }

    #[doc(hidden)]
    pub(crate) const fn completion(&self) -> crate::RedactionCompletion { self.summary.completion() }

    #[doc(hidden)]
    pub(crate) fn into_log_safe_text(self) -> RedactedText { self.into_text() }

    /// Borrows the final text.
    #[must_use]
    pub const fn text(&self) -> &RedactedText {
        &self.text
    }

    /// Borrows the execution summary.
    #[must_use]
    pub const fn summary(&self) -> RedactionSummary {
        self.summary
    }

    /// Consumes the output and returns its final text.
    #[must_use]
    pub fn into_text(self) -> RedactedText {
        self.text
    }

    /// Consumes the output and returns both parts.
    #[must_use]
    pub fn into_parts(self) -> (RedactedText, RedactionSummary) {
        (self.text, self.summary)
    }
}
