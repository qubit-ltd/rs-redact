// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Structured URI redaction results.

use std::fmt;
use std::fmt::Debug;
use std::fmt::Display;
use std::fmt::Formatter;

use super::UriComponent;
use super::UriRedactionReason;
use super::UriRedactionStatus;
use crate::LogSafeText;
use crate::RedactionCompletion;
use crate::text::redaction_output::RedactionOutput;

/// A log-safe URI together with explainable processing metadata.
///
/// Completion is exposed as the explicit three-state
/// [`RedactionCompletion`] contract rather than a derived truncation boolean:
///
/// ```compile_fail
/// use qubit_redact::uri::UriRedactor;
///
/// let result = UriRedactor::default().redact_uri_str("https://example.test");
/// let _ = result.is_truncated();
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct UriRedaction {
    output: RedactionOutput,
    pub(crate) status: UriRedactionStatus,
    pub(crate) reasons: Vec<UriRedactionReason>,
    pub(crate) components: Vec<UriComponent>,
}

impl UriRedaction {
    /// Creates a URI result while enforcing the shared output invariants.
    ///
    /// # Parameters
    ///
    /// * `text` - Log-safe URI text or substitute content.
    /// * `status` - Existing URI processing classification.
    /// * `reasons` - Existing URI processing reasons.
    /// * `components` - Sensitive URI components that were changed.
    /// * `completion` - Whether safe URI rendering completed, substituted
    ///   non-empty text, or exhausted the output budget.
    ///
    /// # Returns
    ///
    /// A URI result whose text and completion obey the shared three-state
    /// invariant. Empty truncated text is normalized to `Exhausted`.
    #[must_use]
    pub(crate) fn new(
        text: LogSafeText<'static>,
        status: UriRedactionStatus,
        reasons: Vec<UriRedactionReason>,
        components: Vec<UriComponent>,
        completion: RedactionCompletion,
    ) -> Self {
        let output = match completion {
            RedactionCompletion::Complete => RedactionOutput::complete(text),
            RedactionCompletion::Truncated => RedactionOutput::truncated(text)
                .unwrap_or_else(RedactionOutput::exhausted),
            RedactionCompletion::Exhausted => RedactionOutput::exhausted(),
        };
        Self {
            output,
            status,
            reasons,
            components,
        }
    }

    /// Returns the log-safe URI text without exposing an unescaped source.
    #[must_use]
    #[inline]
    pub fn log_safe_text(&self) -> &LogSafeText<'static> {
        self.output.log_safe_text()
    }

    /// Consumes the result and returns typed log-safe text.
    #[must_use]
    #[inline]
    pub fn into_log_safe_text(self) -> LogSafeText<'static> {
        self.output.into_log_safe_text()
    }

    /// Returns the overall processing status.
    #[must_use]
    #[inline]
    pub const fn status(&self) -> UriRedactionStatus {
        self.status
    }

    /// Returns all reasons recorded while processing the URI.
    #[must_use]
    #[inline]
    pub fn reasons(&self) -> &[UriRedactionReason] {
        &self.reasons
    }

    /// Returns whether any sensitive URI component was changed.
    #[must_use]
    #[inline]
    pub const fn has_sensitive_components(&self) -> bool {
        !self.components.is_empty()
    }

    /// Returns whether `component` was changed or classified as sensitive.
    #[must_use]
    #[inline]
    pub fn has_sensitive_component(&self, component: UriComponent) -> bool {
        self.components.contains(&component)
    }

    /// Returns whether `reason` was recorded.
    #[must_use]
    #[inline(never)]
    pub fn has_reason(&self, reason: UriRedactionReason) -> bool {
        self.reasons.contains(&reason)
    }

    /// Returns how URI redaction completed without changing status or reasons.
    ///
    /// # Returns
    ///
    /// [`RedactionCompletion::Complete`] for a fully rendered safe URI,
    /// including ordinary masking and invalid-input replacement after complete
    /// inspection; [`RedactionCompletion::Truncated`] when a non-empty safe
    /// substitute represents rejected input or omitted output; or
    /// [`RedactionCompletion::Exhausted`] when no safe text fit. URI status and
    /// reason metadata retain their existing meanings independently.
    #[must_use]
    pub const fn completion(&self) -> RedactionCompletion {
        self.output.completion()
    }
}

impl Debug for UriRedaction {
    /// Formats only safe text and redaction metadata.
    #[inline]
    #[must_use]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UriRedaction")
            .field("text", &self.log_safe_text().as_str())
            .field("status", &self.status)
            .field("reasons", &self.reasons)
            .field("components", &self.components)
            .field("completion", &self.completion())
            .finish()
    }
}

impl Display for UriRedaction {
    /// Formats only the log-safe URI text.
    #[inline]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.log_safe_text().as_str())
    }
}
