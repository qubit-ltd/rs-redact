// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Internal multipart sanitization result.

/// Sanitized multipart content and its opaque-text exposure state.
pub(in crate::adapter::http) struct MultipartSanitization {
    /// Sanitized diagnostic content.
    content: String,
    /// Whether policy allowed opaque text to remain unchanged.
    contains_passed_through_text: bool,
}

impl MultipartSanitization {
    /// Creates a multipart sanitization result.
    ///
    /// # Parameters
    ///
    /// * `content` - Sanitized diagnostic content.
    /// * `contains_passed_through_text` - Whether opaque text remains
    ///   unchanged.
    ///
    /// # Returns
    ///
    /// A result containing the supplied content and exposure state.
    #[inline]
    pub(in crate::adapter::http) fn new(
        content: String,
        contains_passed_through_text: bool,
    ) -> Self {
        Self {
            content,
            contains_passed_through_text,
        }
    }

    /// Returns the sanitized diagnostic content.
    ///
    /// # Returns
    ///
    /// Borrowed sanitized content.
    #[inline(always)]
    pub(in crate::adapter::http) fn content(&self) -> &str {
        &self.content
    }

    /// Consumes the result and returns its sanitized diagnostic content.
    ///
    /// # Returns
    ///
    /// Owned sanitized content.
    #[inline(always)]
    pub(in crate::adapter::http) fn into_content(self) -> String {
        self.content
    }

    /// Reports whether opaque text remains unchanged in the content.
    ///
    /// # Returns
    ///
    /// `true` when at least one opaque text body was passed through.
    #[inline(always)]
    pub(in crate::adapter::http) const fn contains_passed_through_text(
        &self,
    ) -> bool {
        self.contains_passed_through_text
    }
}
