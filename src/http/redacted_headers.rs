// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Safe rendered HTTP header values.

use std::fmt::{
    self,
    Debug,
    Display,
    Formatter,
};

use crate::LogSafeText;

/// Owns a deterministic log-safe rendering of an HTTP header map.
#[must_use = "render or otherwise consume the redacted headers"]
#[derive(Clone, PartialEq, Eq)]
pub struct RedactedHeaders {
    /// Sorted, escaped representation containing no unprocessed values.
    text: LogSafeText<'static>,
}

impl RedactedHeaders {
    /// Creates redacted headers from already escaped text.
    ///
    /// # Parameters
    ///
    /// * `text` - Complete log-safe rendering.
    ///
    /// # Returns
    ///
    /// An opaque safe header result.
    #[inline(always)]
    pub(super) const fn new(text: LogSafeText<'static>) -> Self {
        Self { text }
    }

    /// Returns the complete safe rendering.
    ///
    /// # Returns
    ///
    /// A borrowed log-safe header representation.
    #[inline]
    pub const fn log_safe_text(&self) -> &LogSafeText<'static> {
        &self.text
    }

    /// Consumes the result and returns its safe rendering.
    ///
    /// # Returns
    ///
    /// Owned log-safe header text.
    #[inline]
    pub fn into_log_safe_text(self) -> LogSafeText<'static> {
        self.text
    }
}

impl Display for RedactedHeaders {
    /// Writes the safe header representation.
    ///
    /// # Parameters
    ///
    /// * `formatter` - Destination formatting context.
    ///
    /// # Returns
    ///
    /// The formatter result.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the destination rejects a write.
    #[inline]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.text, formatter)
    }
}

impl Debug for RedactedHeaders {
    /// Writes only the safe header representation.
    ///
    /// # Parameters
    ///
    /// * `formatter` - Destination formatting context.
    ///
    /// # Returns
    ///
    /// The formatter result.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the destination rejects a write.
    #[inline]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("RedactedHeaders")
            .field(&self.text)
            .finish()
    }
}
