// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Log-safe bounded result of HTTP body redaction.

use std::fmt::{
    self,
    Display,
    Formatter,
};

use crate::LogSafeText;

use super::BodyRedactionStatus;

/// Holds only escaped, bounded body text plus read-only source metadata.
#[must_use = "inspect or render the redacted body instead of discarding it"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyRedaction {
    /// Escaped and output-bounded diagnostic representation.
    text: LogSafeText<'static>,
    /// How the diagnostic representation was produced.
    status: BodyRedactionStatus,
    /// Number of source bytes inspected after applying the input budget.
    captured_len: usize,
    /// Exact complete source length when known.
    source_len: Option<usize>,
    /// Exact number of source bytes omitted when known.
    omitted_len: Option<usize>,
    /// Whether capture, input budget, or output budget omitted data.
    truncated: bool,
}

impl BodyRedaction {
    /// Returns the escaped and output-bounded diagnostic text.
    ///
    /// # Returns
    ///
    /// A borrowed log-safe body representation including a complete
    /// truncation marker whenever [`Self::is_truncated`] is `true`.
    #[inline(always)]
    pub const fn log_safe_text(&self) -> &LogSafeText<'static> {
        &self.text
    }

    /// Consumes this result and returns its escaped diagnostic text.
    ///
    /// # Returns
    ///
    /// Owned log-safe body text including any truncation marker.
    #[inline(always)]
    pub fn into_log_safe_text(self) -> LogSafeText<'static> {
        self.text
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
    #[inline(always)]
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
    #[inline(always)]
    pub const fn omitted_len(&self) -> Option<usize> {
        self.omitted_len
    }

    /// Reports whether any source or rendered data was omitted.
    ///
    /// # Returns
    ///
    /// `true` for source capture, input-budget, or output-budget truncation.
    #[inline(always)]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
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
        Display::fmt(&self.text, formatter)
    }
}
