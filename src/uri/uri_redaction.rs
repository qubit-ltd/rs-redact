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
#[must_use]
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
    #[must_use = "use the safe text when logging the URI"]
    #[inline]
    pub fn log_safe_text(&self) -> &LogSafeText<'static> {
        self.output.log_safe_text()
    }

    /// Consumes the result and returns typed log-safe text.
    #[must_use = "consume the result to obtain safe text"]
    #[inline]
    pub fn into_log_safe_text(self) -> LogSafeText<'static> {
        self.output.into_log_safe_text()
    }

    /// Returns the overall processing status.
    #[must_use = "inspect the URI processing status"]
    #[inline]
    pub const fn status(&self) -> UriRedactionStatus {
        self.status
    }

    /// Returns all reasons recorded while processing the URI.
    #[must_use = "inspect the URI processing reasons"]
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

    /// Returns whether output was shortened to fit the policy budget.
    ///
    /// Input-limit fallback preserves the historical `false` result because
    /// it substitutes rejected input rather than shortening rendered output;
    /// inspect [`Self::completion`] to observe that case as `Truncated`.
    #[must_use]
    #[inline]
    pub fn is_truncated(&self) -> bool {
        self.completion() == RedactionCompletion::Exhausted
            || self.has_reason(UriRedactionReason::OutputTruncated)
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
    #[must_use = "inspect whether the safe URI output is complete"]
    pub const fn completion(&self) -> RedactionCompletion {
        self.output.completion()
    }
}

impl Debug for UriRedaction {
    /// Formats only safe text and redaction metadata.
    #[inline]
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UriRedaction")
            .field("text", &self.log_safe_text().as_str())
            .field("status", &self.status)
            .field("reasons", &self.reasons)
            .field("components", &self.components)
            .field("truncated", &self.is_truncated())
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
