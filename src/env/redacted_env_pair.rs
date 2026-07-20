// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Log-safe rendering of one redacted environment pair.

use std::fmt::{
    self,
    Display,
    Formatter,
};

use crate::LogSafeText;

/// One escaped environment-variable name and its redacted, escaped value.
#[must_use = "render the redacted pair instead of the original environment value"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedEnvPair {
    /// Escaped environment-variable name.
    name: LogSafeText<'static>,
    /// Redacted and escaped environment-variable value.
    value: LogSafeText<'static>,
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
    pub(super) const fn new(
        name: LogSafeText<'static>,
        value: LogSafeText<'static>,
    ) -> Self {
        Self { name, value }
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
        write!(formatter, "{}={}", self.name, self.value)
    }
}
