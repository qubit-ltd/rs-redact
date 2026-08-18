// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Parser output shared by HTTP body redaction helpers.

use crate::formats::http::BodyRedactionStatus;

/// Unescaped parser output paired with its body-redaction status.
pub(in crate::formats::http) struct ParsedBody {
    /// Redacted text before final log escaping.
    text: String,
    /// How the parser processed the body.
    status: BodyRedactionStatus,
    /// Whether bounded structured rendering omitted output.
    rendered_truncated: bool,
}

impl ParsedBody {
    /// Creates parser output with its final rendering-truncation state.
    ///
    /// # Parameters
    ///
    /// * `text` - Redacted text before final log escaping.
    /// * `status` - How the parser processed the body.
    /// * `rendered_truncated` - Whether structured rendering omitted output.
    ///
    /// # Returns
    ///
    /// One complete parser result.
    #[inline(always)]
    #[must_use]
    pub(in crate::formats::http) const fn new(
        text: String,
        status: BodyRedactionStatus,
        rendered_truncated: bool,
    ) -> Self {
        Self {
            text,
            status,
            rendered_truncated,
        }
    }

    /// Separates the parser result into its rendering components.
    ///
    /// # Returns
    ///
    /// The redacted text, body-redaction status, and rendering-truncation flag,
    /// in that order.
    #[must_use]
    #[inline(always)]
    pub(in crate::formats::http) fn into_parts(self) -> (String, BodyRedactionStatus, bool) {
        (self.text, self.status, self.rendered_truncated)
    }
}
