// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Log-safe rendering of one redacted environment pair.

use std::fmt;
use std::fmt::Display;
use std::fmt::Formatter;

use crate::RedactedText;
use crate::RedactionCompletion;
use crate::RedactionOutput;

/// One escaped environment-variable name and its redacted, escaped value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedEnvPair {
    /// Escaped assignment paired with its exact completion state.
    output: RedactionOutput,
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
    #[must_use]
    pub(super) fn new(name: RedactedText, value: RedactedText) -> Self {
        Self::complete(RedactedText::from_escaped(format!(
            "{}={}",
            name.as_str(),
            value.as_str()
        )))
    }

    /// Creates a complete pair from an already escaped representation.
    ///
    /// # Parameters
    ///
    /// * `rendered` - Complete escaped assignment text.
    ///
    /// # Returns
    ///
    /// A pair carrying [`RedactionCompletion::Complete`].
    #[inline(always)]
    #[must_use]
    pub(super) fn complete(rendered: RedactedText) -> Self {
        Self {
            output: RedactionOutput::complete(rendered),
        }
    }

    /// Creates a truncated pair from non-empty safe substitute output.
    ///
    /// # Parameters
    ///
    /// * `rendered` - Non-empty escaped fallback or truncation marker.
    ///
    /// # Returns
    ///
    /// A truncated pair for non-empty text, or the sole valid exhausted pair
    /// when no substitute text was emitted.
    #[inline(always)]
    #[must_use]
    pub(super) fn truncated(rendered: RedactedText) -> Self {
        Self {
            output: RedactionOutput::truncated(rendered).unwrap_or_else(RedactionOutput::empty),
        }
    }

    /// Borrows the log-safe assignment or fallback text.
    ///
    /// # Returns
    ///
    /// Complete or substitute safe text, or an empty value for exhaustion.
    #[must_use]
    #[inline(always)]
    pub const fn text(&self) -> &RedactedText {
        self.output.text()
    }

    /// Reports how pair redaction completed.
    ///
    /// # Returns
    ///
    /// Complete rendering, non-empty safe truncation, or empty exhaustion as
    /// established by the shared output invariant.
    #[inline(always)]
    pub const fn completion(&self) -> RedactionCompletion {
        self.output.summary().completion()
    }

    /// Consumes the result and returns its log-safe text.
    ///
    /// # Returns
    ///
    /// Complete or substitute assignment text, or an empty exhausted value.
    #[must_use]
    #[inline(always)]
    pub fn into_text(self) -> RedactedText {
        self.output.into_text()
    }
}

impl Display for RedactedEnvPair {
    /// Writes the escaped pair in `NAME=VALUE` form or its safe fallback.
    ///
    /// # Parameters
    ///
    /// * `formatter` - Destination formatting context.
    ///
    /// # Returns
    ///
    /// The formatter result from writing the safe result text.
    ///
    /// # Errors
    ///
    /// Returns [`fmt::Error`] when the destination formatter rejects output.
    #[inline]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(self.output.text(), formatter)
    }
}
