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

/// Published policy-transformed text and completion metadata from one
/// operation.
///
/// Incomplete output retains the selected policy's confidentiality guarantees.
/// `Truncated` and `Exhausted` describe incomplete diagnostics; they do not
/// authorize disclosure of fields protected by that policy. As with
/// [`RedactedText`], disabled policies and explicitly unredacted operations can
/// deliberately preserve source content. Callers can reject or replace
/// incomplete text when their own contract requires completeness.
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
    /// Pairs published text with its actual completion and accounting summary.
    ///
    /// # Parameters
    ///
    /// - `text`: Final policy-transformed and escaped text.
    /// - `summary`: Accounting and completion from the same operation.
    ///
    /// # Returns
    ///
    /// An output pairing the text with its actual execution metadata.
    #[must_use]
    #[inline(always)]
    pub(crate) fn new(text: RedactedText, summary: RedactionSummary) -> Self {
        Self { text, summary }
    }

    /// Borrows the final text.
    ///
    /// # Returns
    ///
    /// Borrowed final text, including safe incomplete representations.
    #[must_use]
    #[inline(always)]
    pub const fn text(&self) -> &RedactedText {
        &self.text
    }

    /// Borrows the execution summary.
    ///
    /// # Returns
    ///
    /// Borrowed completion, reasons, and resource use for this output.
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
    ///
    /// # Returns
    ///
    /// Borrowed text only for Complete; otherwise the borrowed execution
    /// summary.
    #[inline]
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
    ///
    /// # Parameters
    ///
    /// - `marker`: Fallback escaped outside the completed operation’s byte
    ///   budget.
    ///
    /// # Returns
    ///
    /// Borrowed complete text, or an owned escaped marker for incomplete
    /// output.
    #[must_use]
    #[inline]
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
    ///
    /// # Returns
    ///
    /// Owned text only for Complete; otherwise the owned execution summary.
    #[inline]
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
    ///
    /// # Parameters
    ///
    /// - `marker`: Fallback escaped outside the completed operation’s byte
    ///   budget.
    ///
    /// # Returns
    ///
    /// Owned complete text, or a wrapper around the escaped fallback marker.
    #[must_use]
    #[inline]
    pub fn into_text_or_marker(self, marker: &str) -> RedactedText {
        self.into_complete_text().unwrap_or_else(|_| {
            RedactedText::from_escaped(
                crate::output::log_escape::escape_log_control_characters(Cow::Borrowed(marker)).into_owned(),
            )
        })
    }

    /// Consumes the output and returns both parts.
    ///
    /// # Returns
    ///
    /// The owned text and summary, in that order, without checking
    /// completeness.
    #[must_use]
    #[inline(always)]
    pub fn into_parts(self) -> (RedactedText, RedactionSummary) {
        (self.text, self.summary)
    }
}
