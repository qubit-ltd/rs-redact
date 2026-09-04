// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Final text produced by one redaction operation.

use std::borrow::Cow;
use std::fmt;

/// Final UTF-8 text produced by a redaction operation under its selected
/// policy.
///
/// The value has crossed the runtime's plain-text presentation boundary. It is
/// owned and can be rendered with [`std::fmt::Display`] without running another
/// redaction pass. This guarantee is policy-relative: a disabled policy or an
/// explicitly unredacted writer operation may deliberately preserve source
/// content. Callers must not treat this type as proof that the text is
/// confidential in every policy configuration. Any additional length
/// restriction belongs to the caller's final logging or presentation sink.
///
/// # Examples
///
/// ```
/// use qubit_redact::Redactor;
///
/// let output = Redactor::strict().redact_field("password", "raw-secret");
/// assert_eq!(output.text().as_str(), "<redacted>");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RedactedText(
    /// Owned text that has already crossed the redaction safety boundary.
    String,
);

impl RedactedText {
    /// Creates final text from an already escaped representation.
    #[must_use]
    #[inline]
    pub(crate) fn from_escaped(value: impl Into<Cow<'static, str>>) -> Self {
        Self(value.into().into_owned())
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
    /// Borrows the safe text through the standard string-reference contract.
    #[inline(always)]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for RedactedText {
    /// Writes only the finalized safe text to the destination formatter.
    #[inline(always)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}
