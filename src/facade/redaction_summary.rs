// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Machine-readable redaction summaries.
// qubit-style: allow multiple-public-types

use crate::output::RedactionCompletion;

/// Reason why a safe representation is degraded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RedactionReason {
    /// Structural traversal reached a configured limit.
    TraversalLimitReached,
    /// Maximum traversal depth was reached.
    DepthLimitReached,
    /// Source data was already truncated at its ingress boundary.
    SourceTruncated,
    /// Source data was not valid JSON.
    InvalidJson,
    /// Source data was not a valid URI.
    InvalidUri,
    /// Source content type was invalid.
    InvalidContentType,
    /// Source content type is unsupported.
    UnsupportedContentType,
}

/// Compact set of summary reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RedactionReasons(u16);

impl RedactionReasons {
    /// Creates an empty reason set.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Adds one reason.
    #[must_use]
    pub const fn with(self, reason: RedactionReason) -> Self {
        Self(self.0 | (1 << reason as u8))
    }

    /// Returns whether a reason is present.
    #[must_use]
    pub const fn contains(self, reason: RedactionReason) -> bool {
        self.0 & (1 << reason as u8) != 0
    }

    /// Combines two reason sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Machine-readable summary of one redaction operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedactionSummary {
    completion: RedactionCompletion,
    reasons: RedactionReasons,
}

impl RedactionSummary {
    /// Merges completion and reasons from two operations.
    #[must_use]
    pub const fn merge(self, other: Self) -> Self {
        let completion = match (self.completion, other.completion) {
            (RedactionCompletion::Truncated, _) | (_, RedactionCompletion::Truncated) => RedactionCompletion::Truncated,
            _ => RedactionCompletion::Complete,
        };
        Self {
            completion,
            reasons: self.reasons.union(other.reasons),
        }
    }

    /// Creates a complete summary.
    #[must_use]
    pub const fn complete() -> Self {
        Self {
            completion: RedactionCompletion::Complete,
            reasons: RedactionReasons::empty(),
        }
    }

    /// Creates a degraded summary.
    #[must_use]
    pub const fn truncated(reason: RedactionReason) -> Self {
        Self {
            completion: RedactionCompletion::Truncated,
            reasons: RedactionReasons::empty().with(reason),
        }
    }

    /// Creates an empty degraded result.
    #[must_use]
    #[doc(hidden)]
    pub const fn empty() -> Self {
        Self {
            completion: RedactionCompletion::Truncated,
            reasons: RedactionReasons::empty().with(RedactionReason::TraversalLimitReached),
        }
    }

    /// Returns completion state.
    #[must_use]
    pub const fn completion(self) -> RedactionCompletion {
        self.completion
    }

    /// Returns accumulated reasons.
    #[must_use]
    pub const fn reasons(self) -> RedactionReasons {
        self.reasons
    }
}
