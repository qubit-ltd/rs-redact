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
}

impl RenderedOperation {
    /// Creates an unpublished operation from the runtime sink's final state.
    #[must_use]
    pub(super) const fn from_parts(
        text: String,
        completion: RedactionCompletion,
        reasons: RedactionReasons,
    ) -> Self {
        Self {
            text,
            completion,
            reasons,
        }
    }

    /// Borrows the unpublished rendered text.
    #[must_use]
    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    /// Returns the renderer's completion state.
    #[must_use]
    pub(crate) const fn completion(&self) -> RedactionCompletion {
        self.completion
    }

    /// Returns the renderer's accumulated provenance.
    #[must_use]
    pub(crate) const fn reasons(&self) -> RedactionReasons {
        self.reasons
    }

    /// Combines two independently rendered parts into one unpublished result.
    #[must_use]
    pub(crate) fn merge(mut self, other: Self) -> Self {
        self.text.push_str(other.text());
        self.completion = match (self.completion, other.completion()) {
            (RedactionCompletion::Exhausted, _) | (_, RedactionCompletion::Exhausted) => {
                RedactionCompletion::Exhausted
            }
            (RedactionCompletion::Truncated, _) | (_, RedactionCompletion::Truncated) => {
                RedactionCompletion::Truncated
            }
            _ => RedactionCompletion::Complete,
        };
        self.reasons = self.reasons.union(other.reasons());
        self
    }

    /// Consumes this unpublished outcome into its runtime-owned parts.
    #[must_use]
    pub(crate) fn into_parts(self) -> (String, RedactionCompletion, RedactionReasons) {
        (self.text, self.completion, self.reasons)
    }
}
