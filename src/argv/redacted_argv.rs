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
    DiagnosticBudget,
    LogSafeText,
};

use super::redacted_argv_builder::RedactedArgvBuilder;

/// A redacted argv rendering that is safe for a single-line text log.
#[must_use = "render the redacted argv instead of the original arguments"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedArgv {
    /// Escaped debug-style rendering of all argument tokens.
    rendered: LogSafeText<'static>,
}

impl RedactedArgv {
    /// Creates a bounded argv rendering builder for one diagnostic budget.
    ///
    /// # Parameters
    ///
    /// * `budget` - Input and output limits for the diagnostic rendering.
    ///
    /// # Returns
    ///
    /// An empty byte-bounded argv rendering builder.
    #[inline]
    pub(super) fn builder(budget: DiagnosticBudget) -> RedactedArgvBuilder {
        RedactedArgvBuilder::new(budget)
    }

    /// Creates an argv value from already escaped bounded output.
    ///
    /// # Parameters
    ///
    /// * `rendered` - Escaped debug-style argv rendering.
    ///
    /// # Returns
    ///
    /// A displayable argv value.
    #[inline(always)]
    pub(super) fn from_rendered(rendered: String) -> Self {
        Self {
            rendered: LogSafeText::from_escaped(Cow::Owned(rendered)),
        }
    }

    /// Borrows the already escaped diagnostic representation.
    ///
    /// The returned text is safe to append through
    /// [`crate::DiagnosticLogBuilder::push_safe`]. Callers remain responsible
    /// for applying any enclosing output budget.
    #[inline(always)]
    pub const fn as_log_safe_text(&self) -> &LogSafeText<'static> {
        &self.rendered
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
