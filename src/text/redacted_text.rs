// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Text that has passed through a redaction policy.

use std::borrow::Cow;

use super::{LogSafeText, log_escape::escape_log_control_characters};

/// A value that has passed through field-sensitive redaction.
///
/// This type deliberately does not implement [`std::fmt::Display`]. Plain-text
/// log sinks must first call [`Self::escape_for_log`] so that controls and
/// bidirectional formatting characters cannot manipulate rendered log output.
///
/// ```compile_fail
/// use qubit_redact::Redactor;
///
/// let value = Redactor::default().redact("message", "hello");
/// let _ = format!("{value}");
/// ```
#[must_use = "use the redacted value instead of the original value"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedText<'a>(
    /// Borrowed input or an owned masked value.
    Cow<'a, str>,
);

impl<'a> RedactedText<'a> {
    /// Creates typed redacted text from a borrowed or owned value.
    ///
    /// # Parameters
    ///
    /// * `value` - Value already processed by a redaction policy.
    ///
    /// # Returns
    ///
    /// Typed redacted text retaining the input ownership form.
    #[inline(always)]
    pub(crate) const fn new(value: Cow<'a, str>) -> Self {
        Self(value)
    }

    /// Borrows the redacted contents.
    ///
    /// # Returns
    ///
    /// The redacted text as a string slice.
    #[must_use = "use the redacted value instead of the original value"]
    #[inline(always)]
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }

    /// Converts the redacted contents into an owned string.
    ///
    /// # Returns
    ///
    /// The redacted text, allocating only when the value is borrowed.
    #[must_use = "use the redacted value instead of the original value"]
    #[inline(always)]
    pub fn into_owned(self) -> String {
        self.0.into_owned()
    }

    /// Escapes the redacted contents for a plain-text log boundary.
    ///
    /// All control characters, Unicode line and paragraph separators, and
    /// Unicode bidirectional formatting controls are rendered with debug
    /// escapes. Safe borrowed input remains borrowed.
    ///
    /// # Returns
    ///
    /// Typed text that is safe to render with [`std::fmt::Display`].
    #[inline]
    pub fn escape_for_log(self) -> LogSafeText<'a> {
        LogSafeText::from_escaped(escape_log_control_characters(self.0))
    }

    /// Returns the underlying borrowed or owned value to crate internals.
    ///
    /// # Returns
    ///
    /// The redacted text with its ownership form preserved.
    #[cfg(feature = "http")]
    #[must_use = "use the redacted value instead of the original value"]
    #[inline(always)]
    pub(crate) fn into_inner(self) -> Cow<'a, str> {
        self.0
    }
}
