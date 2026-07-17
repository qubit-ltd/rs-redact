// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Internal multipart sanitization result.

/// Sanitized multipart content and its passed-through value state.
#[must_use = "inspect the multipart sanitization result instead of discarding it"]
pub(in crate::adapter::http) struct MultipartSanitization {
    /// Sanitized diagnostic content.
    content: String,
    /// Whether policy allowed at least one value to remain unchanged.
    contains_passed_through_value: bool,
}

impl MultipartSanitization {
    /// Creates a multipart sanitization result.
    ///
    /// # Parameters
    ///
    /// * `content` - Sanitized diagnostic content.
    /// * `contains_passed_through_value` - Whether policy allowed at least one
    ///   value to remain unchanged.
    ///
    /// # Returns
    ///
    /// A result containing the supplied content and exposure state.
    #[inline(always)]
    pub(in crate::adapter::http) fn new(
        content: String,
        contains_passed_through_value: bool,
    ) -> Self {
        Self {
            content,
            contains_passed_through_value,
        }
    }

    /// Returns the sanitized diagnostic content.
    ///
    /// # Returns
    ///
    /// Borrowed sanitized content.
    #[must_use]
    #[inline(always)]
    pub(in crate::adapter::http) fn content(&self) -> &str {
        &self.content
    }

    /// Consumes the result and returns its sanitized diagnostic content.
    ///
    /// # Returns
    ///
    /// Owned sanitized content.
    #[must_use = "use the sanitized multipart content instead of discarding it"]
    #[inline(always)]
    pub(in crate::adapter::http) fn into_content(self) -> String {
        self.content
    }

    /// Reports whether policy left at least one value unchanged.
    ///
    /// # Returns
    ///
    /// `true` when at least one value was passed through.
    #[must_use]
    #[inline(always)]
    pub(in crate::adapter::http) const fn contains_passed_through_value(
        &self,
    ) -> bool {
        self.contains_passed_through_value
    }
}
