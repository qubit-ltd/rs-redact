// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Completion and provenance state separated from transaction resource usage.

use crate::RedactionCompletion;
use crate::RedactionReasons;
use crate::RedactionSummary;
use crate::RedactionUsage;

/// Transaction-local completion state converted to a public summary only at
/// publication time. Resource accounting remains exclusively in
/// [`super::redaction_budget::RedactionBudget`].
#[derive(Clone, Copy)]
pub(super) struct SummaryBuilder {
    /// Whether any contributing operation used disabled policy mode.
    redaction_disabled: bool,
    /// Strongest completion state accumulated so far.
    completion: RedactionCompletion,
    /// Union of machine-readable degradation causes.
    reasons: RedactionReasons,
}

impl SummaryBuilder {
    /// Creates an empty complete transaction state.
    ///
    /// # Parameters
    ///
    /// - `redaction_disabled`: Whether the owning policy disables masking.
    ///
    /// # Returns
    ///
    /// Neutral complete summary state with empty provenance.
    #[must_use]
    #[inline(always)]
    pub(super) const fn new(redaction_disabled: bool) -> Self {
        Self {
            redaction_disabled,
            completion: RedactionCompletion::Complete,
            reasons: RedactionReasons::empty(),
        }
    }

    /// Wraps the completion and provenance of an immutable summary.
    ///
    /// # Parameters
    ///
    /// - `summary`: Existing completion and provenance; usage is not retained.
    ///
    /// # Returns
    ///
    /// A builder carrying only the supplied completion facts.
    #[must_use]
    #[inline(always)]
    pub(super) const fn from_summary(summary: RedactionSummary) -> Self {
        Self {
            redaction_disabled: summary.is_redaction_disabled(),
            completion: summary.completion(),
            reasons: summary.reasons(),
        }
    }

    /// Returns a summary paired with runtime-owned resource usage.
    ///
    /// # Parameters
    ///
    /// - `usage`: Resource measurements supplied by the transaction ledger.
    ///
    /// # Returns
    ///
    /// An immutable summary pairing these completion facts with that usage.
    #[must_use]
    #[inline(always)]
    pub(super) const fn build(self, usage: RedactionUsage) -> RedactionSummary {
        RedactionSummary::from_parts(self.redaction_disabled, self.completion, self.reasons, usage)
    }

    /// Merges an operation's completion and provenance into this state.
    ///
    /// # Parameters
    ///
    /// - `delta`: Additional completion and provenance facts.
    ///
    /// # Returns
    ///
    /// Combined state with strongest completion and unioned reasons; resource
    /// usage remains owned by the separate ledger.
    #[must_use]
    pub(super) const fn merge(self, delta: RedactionSummary) -> Self {
        Self {
            redaction_disabled: self.redaction_disabled || delta.is_redaction_disabled(),
            completion: match (self.completion, delta.completion()) {
                (RedactionCompletion::Exhausted, _) | (_, RedactionCompletion::Exhausted) => {
                    RedactionCompletion::Exhausted
                }
                (RedactionCompletion::Truncated, _) | (_, RedactionCompletion::Truncated) => {
                    RedactionCompletion::Truncated
                }
                _ => RedactionCompletion::Complete,
            },
            reasons: self.reasons.union(delta.reasons()),
        }
    }
}
