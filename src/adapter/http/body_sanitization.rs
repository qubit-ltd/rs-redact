// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Structured result of sanitizing an HTTP body.

use std::{
    borrow::Cow,
    fmt::{
        self,
        Display,
        Formatter,
        Write,
    },
};

use crate::escape_log_control_characters;

use super::{
    BodySanitizationStatus,
    BodySourceLength,
};

/// Stores sanitized diagnostic content and source-length metadata.
///
/// ```compile_fail
/// #![deny(unused_must_use)]
/// use qubit_redact::{HttpBodySanitizer, NameMatchMode};
///
/// let sanitizer = HttpBodySanitizer::default();
/// sanitizer.sanitize_body(b"secret", None, NameMatchMode::Exact);
/// ```
#[must_use = "inspect or render the sanitized body instead of discarding it"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodySanitization {
    /// Diagnostic content without the standard truncation suffix.
    content: String,
    /// How the diagnostic content was produced.
    status: BodySanitizationStatus,
    /// Number of source bytes available to the sanitizer.
    captured_len: usize,
    /// Exact total source byte length, clamped to at least `captured_len`.
    source_len: Option<usize>,
    /// Whether source bytes were omitted from the capture.
    truncated: bool,
}

impl BodySanitization {
    /// Creates a structured HTTP body sanitization result.
    ///
    /// # Parameters
    ///
    /// * `content` - Diagnostic content without a truncation suffix.
    /// * `status` - How the diagnostic content was produced.
    /// * `captured_len` - Number of source bytes inspected.
    /// * `source_length` - Exact or unknown-truncated source length metadata.
    ///
    /// # Returns
    ///
    /// A structured sanitization result. Known source lengths are clamped to
    /// at least `captured_len`.
    #[inline(always)]
    pub(super) fn new(
        content: String,
        status: BodySanitizationStatus,
        captured_len: usize,
        source_length: BodySourceLength,
    ) -> Self {
        let (source_len, truncated) = source_length.resolve(captured_len);
        Self {
            content,
            status,
            captured_len,
            source_len,
            truncated,
        }
    }

    /// Returns raw sanitized content without the standard truncation suffix.
    ///
    /// Log-unsafe characters are not escaped. Use [`Self::escaped_content`],
    /// [`Self::rendered`], or [`Display`] when inserting the result into
    /// untrusted log text.
    ///
    /// # Returns
    ///
    /// Borrowed diagnostic content.
    #[must_use]
    #[inline(always)]
    pub fn raw_content(&self) -> &str {
        &self.content
    }

    /// Consumes this result and returns raw sanitized content without the
    /// truncation suffix.
    ///
    /// Log-unsafe characters are not escaped. Use
    /// [`Self::into_escaped_content`] or [`Self::into_rendered`] when inserting
    /// the result into untrusted log text.
    ///
    /// # Returns
    ///
    /// Owned diagnostic content.
    #[must_use = "use the sanitized content instead of discarding it"]
    #[inline(always)]
    pub fn into_raw_content(self) -> String {
        self.content
    }

    /// Returns diagnostic content with log-unsafe characters escaped and no
    /// standard truncation suffix.
    ///
    /// This method is intended for callers that need to append their own
    /// trusted, context-specific suffix. Use [`Self::rendered`] when the
    /// standard truncation suffix is appropriate.
    ///
    /// # Returns
    ///
    /// Owned, log-safe diagnostic content without a truncation suffix.
    #[must_use = "use the sanitized rendering instead of discarding it"]
    #[inline(always)]
    pub fn escaped_content(&self) -> String {
        escape_log_control_characters(&self.content).into_owned()
    }

    /// Consumes this result and returns diagnostic content with log-unsafe
    /// characters escaped and no standard truncation suffix.
    ///
    /// This method is intended for callers that need to append their own
    /// trusted, context-specific suffix. Use [`Self::into_rendered`] when the
    /// standard truncation suffix is appropriate.
    ///
    /// # Returns
    ///
    /// Owned, log-safe diagnostic content without a truncation suffix.
    #[must_use = "use the sanitized rendering instead of discarding it"]
    #[inline(always)]
    pub fn into_escaped_content(mut self) -> String {
        if let Cow::Owned(escaped) =
            escape_log_control_characters(&self.content)
        {
            self.content = escaped;
        }
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
    #[must_use]
    #[inline(always)]
    pub const fn captured_len(&self) -> usize {
        self.captured_len
    }

    /// Returns the total source byte length when known.
    ///
    /// # Returns
    ///
    /// Exact total source byte count, always at least
    /// [`Self::captured_len`], or `None` when the source is known to be
    /// truncated but its total length is unknown.
    #[must_use]
    #[inline(always)]
    pub const fn source_len(&self) -> Option<usize> {
        self.source_len
    }

    /// Returns the number of source bytes not inspected by the sanitizer.
    ///
    /// # Returns
    ///
    /// Exact truncated source byte count, or `None` when the total source
    /// length is unknown.
    #[must_use]
    #[inline(always)]
    pub const fn truncated_bytes(&self) -> Option<usize> {
        match self.source_len {
            Some(source_len) => {
                Some(source_len.saturating_sub(self.captured_len))
            }
            None => None,
        }
    }

    /// Returns whether source bytes were omitted from the captured body.
    ///
    /// # Returns
    ///
    /// `true` when the exact source length exceeds [`Self::captured_len`] or
    /// the caller reported an unknown truncated source.
    #[must_use]
    #[inline(always)]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Renders diagnostic content with escaped log-unsafe characters and the
    /// standard truncation suffix.
    ///
    /// # Returns
    ///
    /// Owned diagnostic rendering.
    #[must_use = "use the sanitized rendering instead of discarding it"]
    #[inline(always)]
    pub fn rendered(&self) -> String {
        self.to_string()
    }

    /// Consumes this result and renders its diagnostic content with escaped
    /// log-unsafe characters.
    ///
    /// # Returns
    ///
    /// Owned diagnostic rendering with a truncation suffix when needed.
    #[must_use = "use the sanitized rendering instead of discarding it"]
    pub fn into_rendered(self) -> String {
        let truncated_bytes = self.truncated_bytes();
        let truncated = self.truncated;
        let mut content = self.into_escaped_content();
        match truncated_bytes {
            Some(truncated_bytes) if truncated_bytes > 0 => {
                let _ =
                    write!(content, "...<truncated {truncated_bytes} bytes>",);
            }
            None if truncated => content.push_str("...<truncated>"),
            Some(_) | None => {}
        }
        content
    }
}

impl Display for BodySanitization {
    /// Renders diagnostic content with escaped log-unsafe characters and a
    /// truncation suffix when needed.
    ///
    /// # Parameters
    ///
    /// * `formatter` - Destination formatter.
    ///
    /// # Returns
    ///
    /// Formatting result after writing sanitized diagnostic content.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the formatter rejects a write.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&escape_log_control_characters(&self.content))?;
        match self.truncated_bytes() {
            Some(truncated_bytes) if truncated_bytes > 0 => {
                write!(formatter, "...<truncated {truncated_bytes} bytes>",)?;
            }
            None if self.truncated => formatter.write_str("...<truncated>")?,
            Some(_) | None => {}
        }
        Ok(())
    }
}
