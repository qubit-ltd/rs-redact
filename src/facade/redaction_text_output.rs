// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Final output paired with its execution summary.

use std::borrow::Cow;

use super::RedactedText;
use super::RedactionSummary;
use crate::RedactionCompletion;

/// Published safe text and completion metadata from one redaction operation.
///
/// When redaction is enabled, [`Self::text`] remains confidentiality-safe for
/// every completion state. `Truncated` and `Exhausted` describe incomplete
/// diagnostics, not unsafe text. Callers need to reject or replace such text
/// only when their own contract requires completeness.
///
/// # Examples
///
/// ```
/// use qubit_redact::RedactionCompletion;
/// use qubit_redact::Redactor;
///
/// let output = Redactor::strict().redact_field("password", "raw-secret");
/// assert_eq!(output.summary().completion(), RedactionCompletion::Complete);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionTextOutput {
    /// Final log-safe text owned by this completed transaction.
    text: RedactedText,
    /// Completion, provenance, and resource use for the same transaction.
    summary: RedactionSummary,
}

impl RedactionTextOutput {
    /// Creates a complete output.
    #[must_use]
    pub(crate) fn new(text: RedactedText, summary: RedactionSummary) -> Self {
        Self { text, summary }
    }

    /// Borrows the final text.
    #[must_use]
    #[inline(always)]
    pub const fn text(&self) -> &RedactedText {
        &self.text
    }

    /// Borrows the execution summary.
    #[must_use]
    #[inline(always)]
    pub const fn summary(&self) -> &RedactionSummary {
        &self.summary
    }

    /// Borrows the final text when the operation completed without truncation
    /// or exhaustion.
    ///
    /// # Errors
    ///
    /// Returns the execution summary when the safe output was truncated or
    /// exhausted. The error reports completeness; it does not imply that the
    /// published text is unsafe for diagnostics.
    pub fn complete_text(&self) -> Result<&RedactedText, &RedactionSummary> {
        if self.summary.completion() == RedactionCompletion::Complete {
            Ok(&self.text)
        } else {
            Err(&self.summary)
        }
    }

    /// Borrows the final text or returns an escaped caller-selected marker
    /// when the operation was incomplete.
    ///
    /// The complete path does not allocate. An incomplete marker is escaped
    /// before publication so control characters cannot forge diagnostic log
    /// structure. The marker is selected after the transaction and therefore
    /// does not consume its resource budget.
    #[must_use]
    pub fn text_or_marker(&self, marker: &str) -> Cow<'_, str> {
        self.complete_text().map_or_else(
            |_| {
                Cow::Owned(crate::output::log_escape::escape_log_control_characters(Cow::Borrowed(marker)).into_owned())
            },
            |text| Cow::Borrowed(text.as_str()),
        )
    }

    /// Consumes a complete output and returns its final text.
    ///
    /// # Errors
    ///
    /// Returns the execution summary when the safe output was truncated or
    /// exhausted. The error reports completeness; it does not imply that the
    /// published text is unsafe for diagnostics.
    pub fn into_complete_text(self) -> Result<RedactedText, RedactionSummary> {
        if self.summary.completion() == RedactionCompletion::Complete {
            Ok(self.text)
        } else {
            Err(self.summary)
        }
    }

    /// Consumes the output and returns a caller-selected marker when it is
    /// incomplete.
    ///
    /// The marker is escaped before becoming [`RedactedText`], so it remains
    /// safe for diagnostic presentation.
    #[must_use]
    pub fn into_text_or_marker(self, marker: &str) -> RedactedText {
        self.into_complete_text().unwrap_or_else(|_| {
            RedactedText::from_escaped(
                crate::output::log_escape::escape_log_control_characters(std::borrow::Cow::Borrowed(marker))
                    .into_owned(),
            )
        })
    }

    /// Consumes the output and returns both parts.
    #[must_use]
    #[inline(always)]
    pub fn into_parts(self) -> (RedactedText, RedactionSummary) {
        (self.text, self.summary)
    }
}
