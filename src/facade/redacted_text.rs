// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Final text produced by one redaction operation.

use std::fmt;

/// Final UTF-8 text produced by a redaction operation.
///
/// The value has crossed the plain-text safety boundary. It is owned, bounded
/// by the operation that produced it, and safe to render with
/// [`std::fmt::Display`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RedactedText(String);

impl RedactedText {
    /// Creates final text from an already escaped representation.
    #[must_use]
    #[inline]
    pub(crate) fn from_escaped(value: String) -> Self {
        Self(value)
    }

    /// Borrows the final redacted text.
    #[must_use]
    #[inline(always)]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the wrapper and returns its owned text.
    #[must_use]
    #[inline]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl AsRef<str> for RedactedText {
    #[inline(always)]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for RedactedText {
    #[inline(always)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}
