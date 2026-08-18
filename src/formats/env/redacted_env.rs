// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Log-safe rendering of a redacted environment batch.

use std::fmt;
use std::fmt::Display;
use std::fmt::Formatter;

use crate::RedactedText;
use crate::RedactionCompletion;
use crate::RedactionOutput;

/// A bounded environment batch paired with its exact completion state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedEnv {
    /// Escaped batch rendering paired with its exact completion state.
    output: RedactionOutput,
}

impl RedactedEnv {
    /// Creates a complete environment batch.
    ///
    /// # Parameters
    ///
    /// * `rendered` - Complete escaped debug-style batch rendering.
    ///
    /// # Returns
    ///
    /// Safe text paired with [`RedactionCompletion::Complete`].
    #[inline(always)]
    #[must_use]
    pub(super) fn complete(rendered: RedactedText) -> Self {
        Self {
            output: RedactionOutput::complete(rendered),
        }
    }

    /// Creates a truncated environment batch.
    ///
    /// # Parameters
    ///
    /// * `rendered` - Non-empty safe replacement text or truncation marker.
    ///
    /// # Returns
    ///
    /// A truncated result for non-empty text, or an exhausted result when no
    /// safe replacement was emitted.
    #[inline(always)]
    #[must_use]
    pub(super) fn truncated(rendered: RedactedText) -> Self {
        Self {
            output: RedactionOutput::truncated(rendered).unwrap_or_else(RedactionOutput::empty),
        }
    }

    /// Borrows the log-safe batch rendering.
    ///
    /// # Returns
    ///
    /// Complete or substitute safe text, or an empty value for exhaustion.
    #[must_use]
    #[inline(always)]
    pub const fn log_safe_text(&self) -> &RedactedText {
        self.output.log_safe_text()
    }

    /// Reports how batch redaction completed.
    ///
    /// `Complete` means every admitted pair and delimiter was rendered.
    /// `Truncated` means input or output was omitted but non-empty safe
    /// replacement text was emitted. `Exhausted` means the result is empty and
    /// the input iterator was not advanced after exhaustion.
    ///
    /// # Returns
    ///
    /// The completion state paired with the batch text.
    #[inline(always)]
    pub const fn completion(&self) -> RedactionCompletion {
        self.output.completion()
    }

    /// Consumes the result and returns its log-safe batch text.
    ///
    /// # Returns
    ///
    /// Complete or substitute safe text, or an empty exhausted value.
    #[must_use]
    #[inline(always)]
    pub fn into_log_safe_text(self) -> RedactedText {
        self.output.into_log_safe_text()
    }
}

impl Display for RedactedEnv {
    /// Writes the complete, substitute, or empty log-safe batch text.
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
    #[inline(always)]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(self.output.log_safe_text(), formatter)
    }
}
