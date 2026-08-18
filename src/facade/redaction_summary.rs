// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Machine-readable execution summary for one redaction operation.
// qubit-style: allow multiple-public-types

use crate::output::RedactionCompletion;

/// Reasons recorded while producing a redaction output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RedactionReason {
    /// Input budget was reached.
    InputLimitReached,
    /// Output budget was reached.
    OutputLimitReached,
    /// Structure traversal budget was reached.
    TraversalLimitReached,
    /// Maximum depth was reached.
    DepthLimitReached,
    /// The source capture was already truncated.
    SourceTruncated,
    /// The source was not valid JSON.
    InvalidJson,
    /// The source was not a valid URI.
    InvalidUri,
    /// The source had an invalid content type.
    InvalidContentType,
    /// The source content type is not supported.
    UnsupportedContentType,
}

/// A compact set of execution reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RedactionReasons(u16);

impl RedactionReasons {
    /// Creates an empty reason set.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Adds one reason.
    pub const fn with(mut self, reason: RedactionReason) -> Self {
        self.0 |= 1 << reason as u8;
        self
    }

    /// Returns whether `reason` is present.
    #[must_use]
    pub const fn contains(self, reason: RedactionReason) -> bool {
        self.0 & (1 << reason as u8) != 0
    }

    /// Combines two reason sets without losing either operation's evidence.
    #[must_use]
    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Resource usage observed during one redaction operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RedactionUsage {
    inspected_input_bytes: usize,
    emitted_output_bytes: usize,
    visited_nodes: usize,
    visited_collection_items: usize,
    maximum_depth: usize,
}

impl RedactionUsage {
    /// Adds usage counters while saturating on arithmetic overflow.
    #[must_use]
    pub const fn add(left: Self, right: Self) -> Self {
        Self {
            inspected_input_bytes: left.inspected_input_bytes.saturating_add(right.inspected_input_bytes),
            emitted_output_bytes: left.emitted_output_bytes.saturating_add(right.emitted_output_bytes),
            visited_nodes: left.visited_nodes.saturating_add(right.visited_nodes),
            visited_collection_items: left
                .visited_collection_items
                .saturating_add(right.visited_collection_items),
            maximum_depth: if left.maximum_depth > right.maximum_depth {
                left.maximum_depth
            } else {
                right.maximum_depth
            },
        }
    }

    /// Creates usage from runtime accounting.
    #[must_use]
    pub(crate) const fn from_runtime(
        inspected_input_bytes: usize,
        emitted_output_bytes: usize,
        visited_nodes: usize,
        visited_collection_items: usize,
        maximum_depth: usize,
    ) -> Self {
        Self {
            inspected_input_bytes,
            emitted_output_bytes,
            visited_nodes,
            visited_collection_items,
            maximum_depth,
        }
    }
    /// Returns the number of inspected source bytes.
    #[must_use]
    pub const fn inspected_input_bytes(self) -> usize {
        self.inspected_input_bytes
    }

    /// Returns the number of emitted output bytes.
    #[must_use]
    pub const fn emitted_output_bytes(self) -> usize {
        self.emitted_output_bytes
    }

    /// Returns the number of visited nodes.
    #[must_use]
    pub const fn visited_nodes(self) -> usize {
        self.visited_nodes
    }

    /// Returns the number of visited collection items.
    #[must_use]
    pub const fn visited_collection_items(self) -> usize {
        self.visited_collection_items
    }

    /// Returns the maximum observed depth.
    #[must_use]
    pub const fn maximum_depth(self) -> usize {
        self.maximum_depth
    }
}

/// Machine-readable summary of one completed redaction operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedactionSummary {
    completion: RedactionCompletion,
    reasons: RedactionReasons,
    usage: RedactionUsage,
}

impl RedactionSummary {
    /// Merges the completion, reasons, and usage of two operations.
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
            usage: RedactionUsage::add(self.usage, other.usage),
        }
    }

    /// Replaces the placeholder usage with counters collected at runtime.
    #[must_use]
    pub(crate) const fn with_usage(self, usage: RedactionUsage) -> Self {
        Self { usage, ..self }
    }
    /// Creates a summary for a complete operation.
    #[must_use]
    pub const fn complete() -> Self {
        Self {
            completion: RedactionCompletion::Complete,
            reasons: RedactionReasons::empty(),
            usage: RedactionUsage {
                inspected_input_bytes: 0,
                emitted_output_bytes: 0,
                visited_nodes: 0,
                visited_collection_items: 0,
                maximum_depth: 0,
            },
        }
    }

    /// Creates a summary for a bounded or substituted operation.
    #[must_use]
    pub const fn truncated(reason: RedactionReason) -> Self {
        Self {
            completion: RedactionCompletion::Truncated,
            reasons: RedactionReasons::empty().with(reason),
            usage: RedactionUsage {
                inspected_input_bytes: 0,
                emitted_output_bytes: 0,
                visited_nodes: 0,
                visited_collection_items: 0,
                maximum_depth: 0,
            },
        }
    }

    /// Creates a summary for an operation with no remaining output budget.
    #[must_use]
    pub const fn exhausted() -> Self {
        Self {
            completion: RedactionCompletion::Exhausted,
            reasons: RedactionReasons::empty().with(RedactionReason::OutputLimitReached),
            usage: RedactionUsage {
                inspected_input_bytes: 0,
                emitted_output_bytes: 0,
                visited_nodes: 0,
                visited_collection_items: 0,
                maximum_depth: 0,
            },
        }
    }

    /// Returns the completion state.
    #[must_use]
    pub const fn completion(self) -> RedactionCompletion {
        self.completion
    }

    /// Returns the accumulated reasons.
    #[must_use]
    pub const fn reasons(self) -> RedactionReasons {
        self.reasons
    }

    /// Returns resource usage.
    #[must_use]
    pub const fn usage(self) -> RedactionUsage {
        self.usage
    }
}
