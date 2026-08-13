// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Text that is safe to render at a plain-text log boundary.

use std::borrow::Cow;
use std::fmt;
use std::fmt::Display;
use std::fmt::Formatter;

use super::BoundedLogSafeDisplay;
use super::LogOutputLimit;

/// Redacted text whose log-structure and bidirectional controls are escaped.
///
/// Values can only be constructed inside this crate after escaping, preventing
/// arbitrary untrusted text from being labeled log-safe.
///
/// # Type Parameters
///
/// * `'a` - Lifetime of any borrowed escaped text stored by the value.
#[must_use = "render or otherwise consume the log-safe value"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSafeText<'a>(
    /// Borrowed safe input or an owned escaped value.
    Cow<'a, str>,
);

impl<'a> LogSafeText<'a> {
    /// Creates log-safe text from contents that have already been escaped.
    ///
    /// # Parameters
    ///
    /// * `value` - Escaped text with its ownership form preserved.
    ///
    /// # Returns
    ///
    /// Typed log-safe text.
    #[inline(always)]
    pub(crate) const fn from_escaped(value: Cow<'a, str>) -> Self {
        Self(value)
    }

    /// Borrows the escaped log-safe contents.
    ///
    /// # Returns
    ///
    /// The escaped text without allocating or formatting it.
    #[inline(always)]
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }

    /// Converts this value into an owned escaped string.
    ///
    /// # Returns
    ///
    /// The existing string allocation when this value already owns its
    /// contents, or a copied string for borrowed contents.
    #[inline(always)]
    pub fn into_owned(self) -> String {
        self.0.into_owned()
    }

    /// Creates a display adapter bounded by one final log-output limit.
    ///
    /// # Parameters
    ///
    /// * `limit` - Validated final output-byte limit.
    ///
    /// # Returns
    ///
    /// A bounded adapter borrowing this escaped text.
    #[must_use = "format the bounded log-safe text"]
    #[inline(always)]
    pub const fn with_output_limit(
        &self,
        limit: LogOutputLimit,
    ) -> BoundedLogSafeDisplay<'_> {
        BoundedLogSafeDisplay::new(self, limit)
    }
}

impl AsRef<str> for LogSafeText<'_> {
    /// Borrows the escaped log-safe contents.
    ///
    /// # Returns
    ///
    /// The escaped text as a string slice.
    #[inline(always)]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Display for LogSafeText<'_> {
    /// Writes the already escaped contents without surrounding quotes.
    ///
    /// # Parameters
    ///
    /// * `formatter` - Destination formatting context.
    ///
    /// # Returns
    ///
    /// The formatter result from writing the complete escaped string.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the destination formatter cannot accept the
    /// complete escaped string.
    #[inline(always)]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}
