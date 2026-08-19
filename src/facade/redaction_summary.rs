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
    /// The admitted input prefix reached the configured input-byte limit.
    InputLimitReached,
    /// The shared transaction output reached its configured byte limit.
    OutputLimitReached,
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

/// Measured resource use for one redaction transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RedactionUsage {
    presented_input_bytes: usize,
    inspected_input_bytes: usize,
    output_bytes: usize,
    visited_nodes: usize,
    visited_collection_items: usize,
    max_depth: usize,
    omitted_input_bytes: Option<usize>,
}

impl RedactionUsage {
    /// Creates an empty measurement for a newly started transaction.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            presented_input_bytes: 0,
            inspected_input_bytes: 0,
            output_bytes: 0,
            visited_nodes: 0,
            visited_collection_items: 0,
            max_depth: 0,
            omitted_input_bytes: Some(0),
        }
    }

    /// Returns the bytes supplied by callers before input admission.
    #[must_use]
    pub const fn presented_input_bytes(self) -> usize {
        self.presented_input_bytes
    }

    /// Returns the bytes the transaction actually inspected.
    #[must_use]
    pub const fn inspected_input_bytes(self) -> usize {
        self.inspected_input_bytes
    }

    /// Returns the final escaped bytes retained by the transaction.
    #[must_use]
    pub const fn output_bytes(self) -> usize {
        self.output_bytes
    }

    /// Returns the admitted domain or format nodes visited by the transaction.
    #[must_use]
    pub const fn visited_nodes(self) -> usize {
        self.visited_nodes
    }

    /// Returns the admitted collection items visited by the transaction.
    #[must_use]
    pub const fn visited_collection_items(self) -> usize {
        self.visited_collection_items
    }

    /// Returns the greatest active structural depth observed by the
    /// transaction.
    #[must_use]
    pub const fn max_depth(self) -> usize {
        self.max_depth
    }

    /// Returns omitted source bytes when the source length is known.
    #[must_use]
    pub const fn omitted_input_bytes(self) -> Option<usize> {
        self.omitted_input_bytes
    }

    /// Adds bytes written to the final output buffer.
    #[must_use]
    pub(crate) const fn with_added_output_bytes(mut self, bytes: usize) -> Self {
        self.output_bytes = self.output_bytes.saturating_add(bytes);
        self
    }

    /// Records input supplied to and, when admitted, inspected by an adapter.
    #[must_use]
    pub(crate) const fn with_input(mut self, presented: usize, inspected: usize) -> Self {
        self.presented_input_bytes = self.presented_input_bytes.saturating_add(presented);
        self.inspected_input_bytes = self.inspected_input_bytes.saturating_add(inspected);
        self.omitted_input_bytes = match self.omitted_input_bytes {
            Some(omitted) => Some(omitted.saturating_add(presented.saturating_sub(inspected))),
            None => None,
        };
        self
    }

    /// Records input whose omitted-byte count is supplied by the source.
    #[cfg(feature = "http")]
    #[must_use]
    pub(crate) const fn with_source_input(
        mut self,
        presented: usize,
        inspected: usize,
        omitted: Option<usize>,
    ) -> Self {
        self.presented_input_bytes = self.presented_input_bytes.saturating_add(presented);
        self.inspected_input_bytes = self.inspected_input_bytes.saturating_add(inspected);
        self.omitted_input_bytes = match (self.omitted_input_bytes, omitted) {
            (Some(previous), Some(current)) => Some(previous.saturating_add(current)),
            _ => None,
        };
        self
    }

    /// Merges two independently measured operation usages.
    #[must_use]
    const fn merge(self, other: Self) -> Self {
        Self {
            presented_input_bytes: self.presented_input_bytes.saturating_add(other.presented_input_bytes),
            inspected_input_bytes: self.inspected_input_bytes.saturating_add(other.inspected_input_bytes),
            output_bytes: self.output_bytes.saturating_add(other.output_bytes),
            visited_nodes: self.visited_nodes.saturating_add(other.visited_nodes),
            visited_collection_items: self
                .visited_collection_items
                .saturating_add(other.visited_collection_items),
            max_depth: if self.max_depth > other.max_depth {
                self.max_depth
            } else {
                other.max_depth
            },
            omitted_input_bytes: match (self.omitted_input_bytes, other.omitted_input_bytes) {
                (Some(left), Some(right)) => Some(left.saturating_add(right)),
                _ => None,
            },
        }
    }
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
    usage: RedactionUsage,
}

impl RedactionSummary {
    /// Merges completion and reasons from two operations.
    #[must_use]
    pub const fn merge(self, other: Self) -> Self {
        let completion = match (self.completion, other.completion) {
            (RedactionCompletion::Exhausted, _) | (_, RedactionCompletion::Exhausted) => RedactionCompletion::Exhausted,
            (RedactionCompletion::Truncated, _) | (_, RedactionCompletion::Truncated) => RedactionCompletion::Truncated,
            _ => RedactionCompletion::Complete,
        };
        Self {
            completion,
            reasons: self.reasons.union(other.reasons),
            usage: self.usage.merge(other.usage),
        }
    }

    /// Creates a complete summary.
    #[must_use]
    pub const fn complete() -> Self {
        Self {
            completion: RedactionCompletion::Complete,
            reasons: RedactionReasons::empty(),
            usage: RedactionUsage::empty(),
        }
    }

    /// Creates a complete summary that records non-truncating provenance.
    #[must_use]
    #[cfg(any(feature = "json", feature = "http", feature = "uri"))]
    pub(crate) const fn complete_with_reason(reason: RedactionReason) -> Self {
        Self {
            completion: RedactionCompletion::Complete,
            reasons: RedactionReasons::empty().with(reason),
            usage: RedactionUsage::empty(),
        }
    }

    /// Creates a degraded summary.
    #[must_use]
    pub const fn truncated(reason: RedactionReason) -> Self {
        Self {
            completion: RedactionCompletion::Truncated,
            reasons: RedactionReasons::empty().with(reason),
            usage: RedactionUsage::empty(),
        }
    }

    /// Creates an empty degraded result.
    #[must_use]
    #[doc(hidden)]
    pub const fn empty() -> Self {
        Self {
            completion: RedactionCompletion::Truncated,
            reasons: RedactionReasons::empty().with(RedactionReason::TraversalLimitReached),
            usage: RedactionUsage::empty(),
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

    /// Returns resource use measured by the operation that produced this
    /// summary.
    #[must_use]
    pub const fn usage(self) -> RedactionUsage {
        self.usage
    }

    /// Creates a summary for a transaction that exhausted safe output capacity.
    #[must_use]
    pub const fn exhausted(reason: RedactionReason) -> Self {
        Self {
            completion: RedactionCompletion::Exhausted,
            reasons: RedactionReasons::empty().with(reason),
            usage: RedactionUsage::empty(),
        }
    }

    /// Adds bytes written to the transaction's final output buffer.
    #[must_use]
    pub(crate) const fn with_added_output_bytes(mut self, bytes: usize) -> Self {
        self.usage = self.usage.with_added_output_bytes(bytes);
        self
    }

    /// Records format input presented to this summary.
    #[must_use]
    pub(crate) const fn with_input(mut self, presented: usize, inspected: usize) -> Self {
        self.usage = self.usage.with_input(presented, inspected);
        self
    }

    /// Records source-aware input use, preserving unknown omitted lengths.
    #[cfg(feature = "http")]
    #[must_use]
    pub(crate) const fn with_source_input(
        mut self,
        presented: usize,
        inspected: usize,
        omitted: Option<usize>,
    ) -> Self {
        self.usage = self.usage.with_source_input(presented, inspected, omitted);
        self
    }

    /// Records one structural node admitted by the shared transaction.
    #[must_use]
    pub(crate) const fn with_domain_node(mut self, depth: usize) -> Self {
        self.usage.visited_nodes = self.usage.visited_nodes.saturating_add(1);
        self.usage.max_depth = if self.usage.max_depth > depth {
            self.usage.max_depth
        } else {
            depth
        };
        self
    }

    /// Records one admitted collection item.
    #[must_use]
    pub(crate) const fn with_collection_item(mut self) -> Self {
        self.usage.visited_collection_items = self.usage.visited_collection_items.saturating_add(1);
        self
    }
}
