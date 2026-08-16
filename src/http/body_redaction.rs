// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Log-safe bounded result of HTTP body redaction.

use std::borrow::Cow;
use std::fmt;
use std::fmt::Display;
use std::fmt::Formatter;

use super::BodyRedactionStatus;
use crate::LogSafeText;
use crate::RedactionCompletion;
use crate::text::redaction_output::RedactionOutput;

/// Holds only escaped, bounded body text plus read-only source metadata.
#[must_use = "inspect or render the redacted body instead of discarding it"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyRedaction {
    /// Escaped output paired with its invariant completion state.
    output: RedactionOutput,
    /// How the diagnostic representation was produced.
    status: BodyRedactionStatus,
    /// Number of source bytes inspected after applying the input budget.
    captured_len: usize,
    /// Exact complete source length when known.
    source_len: Option<usize>,
    /// Exact number of source bytes omitted when known.
    omitted_len: Option<usize>,
}

impl BodyRedaction {
    /// Creates a completed safe body result.
    ///
    /// # Parameters
    ///
    /// * `text` - Escaped and bounded output text.
    /// * `status` - Classification of the redaction outcome.
    /// * `captured_len` - Number of source bytes inspected.
    /// * `source_len` - Exact source length when known.
    /// * `omitted_len` - Exact number of uninspected source bytes when known.
    /// * `completion` - Whether rendering completed, emitted a safe substitute,
    ///   or exhausted the output budget.
    ///
    /// # Returns
    ///
    /// A body result exposing only log-safe text.
    #[inline(always)]
    pub(super) fn new(
        text: String,
        status: BodyRedactionStatus,
        captured_len: usize,
        source_len: Option<usize>,
        omitted_len: Option<usize>,
        completion: RedactionCompletion,
    ) -> Self {
        let text = LogSafeText::from_escaped(Cow::Owned(text));
        let output = match completion {
            RedactionCompletion::Complete => RedactionOutput::complete(text),
            RedactionCompletion::Truncated => RedactionOutput::truncated(text)
                .unwrap_or_else(RedactionOutput::exhausted),
            RedactionCompletion::Exhausted => RedactionOutput::exhausted(),
        };
        Self {
            output,
            status,
            captured_len,
            source_len,
            omitted_len,
        }
    }

    /// Returns the escaped and output-bounded diagnostic text.
    ///
    /// # Returns
    ///
    /// A borrowed log-safe body representation. A `Truncated` result contains
    /// non-empty safe substitute text; an `Exhausted` result is empty and does
    /// not promise that a truncation marker still fit.
    #[must_use]
    #[inline]
    pub const fn log_safe_text(&self) -> &LogSafeText<'static> {
        self.output.log_safe_text()
    }

    /// Consumes this result and returns its escaped diagnostic text.
    ///
    /// # Returns
    ///
    /// Owned log-safe body text including any truncation marker.
    #[must_use]
    #[inline(always)]
    pub fn into_log_safe_text(self) -> LogSafeText<'static> {
        self.output.into_log_safe_text()
    }

    /// Returns how the body representation was produced.
    ///
    /// # Returns
    ///
    /// The immutable redaction status.
    #[inline(always)]
    pub const fn status(&self) -> BodyRedactionStatus {
        self.status
    }

    /// Returns the number of source bytes inspected.
    ///
    /// # Returns
    ///
    /// The byte count after applying the hard input budget.
    #[must_use]
    #[inline]
    pub const fn captured_len(&self) -> usize {
        self.captured_len
    }

    /// Returns the complete source length when known.
    ///
    /// # Returns
    ///
    /// `Some(total)` for known source size, or `None` when a truncated source
    /// had no exact total length.
    #[inline(always)]
    pub const fn source_len(&self) -> Option<usize> {
        self.source_len
    }

    /// Returns the exact number of omitted source bytes when known.
    ///
    /// # Returns
    ///
    /// `Some(count)` when the source length is known, or `None` otherwise.
    #[inline]
    pub const fn omitted_len(&self) -> Option<usize> {
        self.omitted_len
    }

    /// Returns how body redaction completed under the shared output budget.
    ///
    /// # Returns
    ///
    /// [`RedactionCompletion::Complete`] when the full safe representation fit,
    /// including ordinary masking; [`RedactionCompletion::Truncated`] when a
    /// non-empty safe substitute represents omitted source or output; or
    /// [`RedactionCompletion::Exhausted`] when no safe substitute fit and the
    /// result is empty.
    #[inline]
    pub const fn completion(&self) -> RedactionCompletion {
        self.output.completion()
    }
}

impl Display for BodyRedaction {
    /// Writes the bounded log-safe body representation.
    ///
    /// # Parameters
    ///
    /// * `formatter` - Destination formatting context.
    ///
    /// # Returns
    ///
    /// The formatter result from writing the complete safe text.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the destination rejects a write.
    #[inline(always)]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(self.log_safe_text(), formatter)
    }
}
