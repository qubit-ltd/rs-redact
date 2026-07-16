// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Structured result of sanitizing an HTTP body.

use std::fmt::{self, Display, Formatter, Write};

use super::BodySanitizationStatus;

/// Stores sanitized diagnostic content and source-length metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodySanitization {
    /// Diagnostic content without the standard truncation suffix.
    content: String,
    /// How the diagnostic content was produced.
    status: BodySanitizationStatus,
    /// Number of source bytes available to the sanitizer.
    captured_len: usize,
    /// Total source byte length, clamped to at least `captured_len`.
    source_len: usize,
}

impl BodySanitization {
    /// Creates a structured HTTP body sanitization result.
    ///
    /// # Parameters
    ///
    /// * `content` - Diagnostic content without a truncation suffix.
    /// * `status` - How the diagnostic content was produced.
    /// * `captured_len` - Number of source bytes inspected.
    /// * `source_len` - Total source length when known.
    ///
    /// # Returns
    ///
    /// A structured sanitization result. `source_len` is clamped to at least
    /// `captured_len`.
    #[inline(always)]
    pub(super) fn new(
        content: String,
        status: BodySanitizationStatus,
        captured_len: usize,
        source_len: usize,
    ) -> Self {
        Self {
            content,
            status,
            captured_len,
            source_len: source_len.max(captured_len),
        }
    }

    /// Returns diagnostic content without the standard truncation suffix.
    ///
    /// # Returns
    ///
    /// Borrowed diagnostic content.
    #[inline(always)]
    pub fn content(&self) -> &str {
        &self.content
    }

    /// Consumes this result and returns content without the truncation suffix.
    ///
    /// # Returns
    ///
    /// Owned diagnostic content.
    #[inline(always)]
    pub fn into_content(self) -> String {
        self.content
    }

    /// Returns how the diagnostic content was produced.
    ///
    /// # Returns
    ///
    /// Sanitization status.
    #[inline(always)]
    pub const fn status(&self) -> BodySanitizationStatus {
        self.status
    }

    /// Returns the number of source bytes inspected by the sanitizer.
    ///
    /// # Returns
    ///
    /// Captured source byte count.
    #[inline(always)]
    pub const fn captured_len(&self) -> usize {
        self.captured_len
    }

    /// Returns the total source byte length when known.
    ///
    /// # Returns
    ///
    /// Total source byte count, always at least [`Self::captured_len`].
    #[inline(always)]
    pub const fn source_len(&self) -> usize {
        self.source_len
    }

    /// Returns the number of source bytes not inspected by the sanitizer.
    ///
    /// # Returns
    ///
    /// Truncated source byte count.
    #[inline(always)]
    pub const fn truncated_bytes(&self) -> usize {
        self.source_len.saturating_sub(self.captured_len)
    }

    /// Returns whether source bytes were omitted from the captured body.
    ///
    /// # Returns
    ///
    /// `true` when [`Self::source_len`] exceeds [`Self::captured_len`].
    #[inline(always)]
    pub const fn is_truncated(&self) -> bool {
        self.source_len > self.captured_len
    }

    /// Renders diagnostic content with the standard truncation suffix.
    ///
    /// # Returns
    ///
    /// Owned diagnostic rendering.
    pub fn rendered(&self) -> String {
        self.to_string()
    }

    /// Consumes this result and renders its diagnostic content.
    ///
    /// # Returns
    ///
    /// Owned diagnostic rendering with a truncation suffix when needed.
    pub fn into_rendered(self) -> String {
        let truncated_bytes = self.truncated_bytes();
        let mut content = self.content;
        if truncated_bytes > 0 {
            let _ = write!(content, "...<truncated {truncated_bytes} bytes>",);
        }
        content
    }
}

impl Display for BodySanitization {
    /// Renders diagnostic content with a truncation suffix when needed.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.content)?;
        let truncated_bytes = self.truncated_bytes();
        if truncated_bytes > 0 {
            write!(formatter, "...<truncated {truncated_bytes} bytes>",)?;
        }
        Ok(())
    }
}
