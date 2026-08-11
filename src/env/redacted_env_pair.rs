// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Log-safe rendering of one redacted environment pair.

use std::borrow::Cow;
use std::fmt;
use std::fmt::Display;
use std::fmt::Formatter;

use crate::LogSafeText;

/// One escaped environment-variable name and its redacted, escaped value.
#[must_use = "render the redacted pair instead of the original environment value"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedEnvPair {
    /// Complete escaped `NAME=VALUE` representation.
    rendered: LogSafeText<'static>,
}

impl RedactedEnvPair {
    /// Creates a redacted pair from log-safe owned components.
    ///
    /// # Parameters
    ///
    /// * `name` - Escaped environment-variable name.
    /// * `value` - Redacted and escaped environment-variable value.
    ///
    /// # Returns
    ///
    /// A pair that renders in `NAME=VALUE` form.
    #[inline(always)]
    pub(super) fn new(name: LogSafeText<'static>, value: LogSafeText<'static>) -> Self {
        Self::from_rendered(format!("{}={}", name.as_str(), value.as_str()))
    }

    /// Creates a pair from a complete, already escaped representation.
    #[inline(always)]
    pub(super) fn from_rendered(rendered: String) -> Self {
        Self {
            rendered: LogSafeText::from_escaped(Cow::Owned(rendered)),
        }
    }
}

impl Display for RedactedEnvPair {
    /// Writes the escaped pair in `NAME=VALUE` form.
    ///
    /// # Parameters
    ///
    /// * `formatter` - Destination formatting context.
    ///
    /// # Returns
    ///
    /// The formatter result from writing the complete pair.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the destination formatter rejects output.
    #[inline]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.rendered, formatter)
    }
}
