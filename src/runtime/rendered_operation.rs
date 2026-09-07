// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Unpublished format-rendering outcomes consumed by the transaction runtime.

use crate::RedactionCompletion;
use crate::RedactionReasons;

/// Carries rendered text and degradation provenance without constructing a
/// publishable output or transaction summary inside a format adapter.
pub(crate) struct RenderedOperation {
    /// Log-safe unpublished text produced by one adapter.
    text: String,
    /// Completion state produced by bounded rendering.
    completion: RedactionCompletion,
    /// Machine-readable degradation provenance.
    reasons: RedactionReasons,
    /// Whether actual output rejection prevents later work.
    output_closed: bool,
}

impl RenderedOperation {
    /// Creates an unpublished operation from the runtime sink's final state.
    ///
    /// # Parameters
    ///
    /// - `text`: Already escaped and bounded output.
    /// - `completion`: Rendering completion, independent of later admission.
    /// - `reasons`: Accumulated observed failure facts.
    /// - `output_closed`: Whether an actual output rejection forbids later
    ///   work.
    ///
    /// # Returns
    ///
    /// The unpublished operation without publishing its text.
    ///
    /// # Panics
    ///
    /// In debug builds, panics if `Exhausted` lacks `OutputLimitReached`.
    #[must_use]
    pub(super) const fn from_parts(
        text: String,
        completion: RedactionCompletion,
        reasons: RedactionReasons,
        output_closed: bool,
    ) -> Self {
        debug_assert!(
            !matches!(completion, RedactionCompletion::Exhausted)
                || reasons.contains(crate::RedactionReason::OutputLimitReached)
        );
        Self {
            text,
            completion,
            reasons,
            output_closed,
        }
    }

    /// Reports whether the output sink rejected further payload.
    ///
    /// # Returns
    ///
    /// Whether an actual output rejection closed further admission.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn output_closed(&self) -> bool {
        self.output_closed
    }

    /// Borrows the unpublished rendered text.
    ///
    /// # Returns
    ///
    /// The retained escaped text, still unpublished.
    #[must_use]
    #[inline(always)]
    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    /// Returns the renderer's completion state.
    ///
    /// # Returns
    ///
    /// The rendering completion of this operation.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn completion(&self) -> RedactionCompletion {
        self.completion
    }

    /// Returns the renderer's accumulated provenance.
    ///
    /// # Returns
    ///
    /// All observed provenance for this operation.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn reasons(&self) -> RedactionReasons {
        self.reasons
    }

    /// Adds observed provenance while preserving the sink's completion facts.
    ///
    /// # Parameters
    ///
    /// - `reason`: Additional observed provenance.
    ///
    /// # Returns
    ///
    /// This operation with the reason unioned into its existing set.
    #[cfg(feature = "http")]
    #[must_use]
    #[inline(always)]
    pub(crate) fn with_reason(mut self, reason: crate::RedactionReason) -> Self {
        self.reasons = self.reasons.with(reason);
        self
    }

    /// Combines two independently rendered parts into one unpublished result.
    ///
    /// # Parameters
    ///
    /// - `other`: Following independently bounded part, admitted under the
    ///   shared allowance.
    ///
    /// # Returns
    ///
    /// The concatenated parts with strongest completion, unioned reasons, and
    /// output closure if either part rejected output.
    #[must_use]
    pub(crate) fn merge(mut self, other: Self) -> Self {
        self.text.push_str(other.text());
        self.completion = match (self.completion, other.completion()) {
            (RedactionCompletion::Exhausted, _) | (_, RedactionCompletion::Exhausted) => RedactionCompletion::Exhausted,
            (RedactionCompletion::Truncated, _) | (_, RedactionCompletion::Truncated) => RedactionCompletion::Truncated,
            _ => RedactionCompletion::Complete,
        };
        self.reasons = self.reasons.union(other.reasons());
        self.output_closed |= other.output_closed;
        self
    }

    /// Consumes this unpublished outcome into its runtime-owned parts.
    ///
    /// # Returns
    ///
    /// Owned text, completion, and provenance, in that order. The caller must
    /// read `output_closed` before consuming this value when combining
    /// operations.
    #[must_use]
    #[inline(always)]
    pub(crate) fn into_parts(self) -> (String, RedactionCompletion, RedactionReasons) {
        (self.text, self.completion, self.reasons)
    }
}
