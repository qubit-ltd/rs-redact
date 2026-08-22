// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Final output paired with its execution summary.

use super::RedactedText;
use super::RedactionSummary;

/// Complete result of one redaction operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionTextOutput {
    text: RedactedText,
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
    pub const fn text(&self) -> &RedactedText {
        &self.text
    }

    /// Borrows the execution summary.
    #[must_use]
    pub const fn summary(&self) -> &RedactionSummary {
        &self.summary
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

#[cfg(feature = "serde")]
impl serde::Serialize for RedactionTextOutput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.text.as_str())
    }
}
