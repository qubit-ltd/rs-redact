// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Text that is safe to render at a plain-text log boundary.

use std::{
    borrow::Cow,
    fmt::{
        self,
        Display,
        Formatter,
    },
};

/// Redacted text whose log-structure and bidirectional controls are escaped.
///
/// Values can only be constructed inside this crate after escaping, preventing
/// arbitrary untrusted text from being labeled log-safe.
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
}

impl AsRef<str> for LogSafeText<'_> {
    /// Borrows the escaped log-safe contents.
    ///
    /// # Returns
    ///
    /// The escaped text as a string slice.
    #[inline(always)]
    fn as_ref(&self) -> &str {
        self.0.as_ref()
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
        formatter.write_str(self.0.as_ref())
    }
}
