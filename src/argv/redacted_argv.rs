// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Log-safe rendering of a redacted argument vector.

use std::{
    borrow::Cow,
    fmt::{
        self,
        Display,
        Formatter,
    },
};

use crate::{
    LogSafeText,
    RedactedText,
};

/// A redacted argv rendering that is safe for a single-line text log.
#[must_use = "render the redacted argv instead of the original arguments"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedArgv {
    /// Escaped debug-style rendering of all argument tokens.
    rendered: LogSafeText<'static>,
}

impl RedactedArgv {
    /// Creates a log-safe argv rendering from already redacted tokens.
    ///
    /// # Parameters
    ///
    /// * `items` - Redacted argument tokens in their original order.
    ///
    /// # Returns
    ///
    /// An escaped debug-style one-line rendering.
    #[inline]
    pub(super) fn new(items: Vec<String>) -> Self {
        let rendered = format!("{items:?}");
        let rendered = RedactedText::new(Cow::Owned(rendered)).escape_for_log();
        Self { rendered }
    }
}

impl Display for RedactedArgv {
    /// Writes the complete escaped argv rendering.
    ///
    /// # Parameters
    ///
    /// * `formatter` - Destination formatting context.
    ///
    /// # Returns
    ///
    /// The formatter result from writing the complete rendering.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the destination formatter rejects output.
    #[inline(always)]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.rendered, formatter)
    }
}
