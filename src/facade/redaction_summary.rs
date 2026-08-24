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
    /// Source data was not a valid URL-encoded form.
    InvalidForm,
    /// Source data was not a valid multipart body.
    InvalidMultipart,
}

impl RedactionReason {
    /// Returns the stable bit assigned to this reason in a reason set.
    const fn bit(self) -> u64 {
        match self {
            Self::InputLimitReached => 1 << 0,
            Self::OutputLimitReached => 1 << 1,
            Self::TraversalLimitReached => 1 << 2,
            Self::DepthLimitReached => 1 << 3,
            Self::SourceTruncated => 1 << 4,
            Self::InvalidJson => 1 << 5,
            Self::InvalidUri => 1 << 6,
            Self::InvalidContentType => 1 << 7,
            Self::UnsupportedContentType => 1 << 8,
            Self::InvalidForm => 1 << 9,
            Self::InvalidMultipart => 1 << 10,
        }
    }
}

/// Measured resource use for one redaction transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedactionUsage {
    /// Bytes presented at public input boundaries.
    presented_input_bytes: usize,
    /// Presented bytes admitted for inspection.
    inspected_input_bytes: usize,
    /// Escaped bytes retained in final output.
    output_bytes: usize,
    /// Structural nodes admitted during traversal.
    visited_nodes: usize,
    /// Sequence and map items admitted during traversal.
    visited_collection_items: usize,
    /// Greatest active structural depth observed.
    max_depth: usize,
    /// Known bytes omitted at admission boundaries.
    omitted_input_bytes: Option<usize>,
}

impl Default for RedactionUsage {
    fn default() -> Self {
        Self::empty()
    }
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
    #[inline(always)]
    pub const fn presented_input_bytes(self) -> usize {
        self.presented_input_bytes
    }

    /// Returns the bytes the transaction actually inspected.
    #[must_use]
    #[inline(always)]
    pub const fn inspected_input_bytes(self) -> usize {
        self.inspected_input_bytes
    }

    /// Returns the final escaped bytes retained by the transaction.
    #[must_use]
    #[inline(always)]
    pub const fn output_bytes(self) -> usize {
        self.output_bytes
    }

    /// Returns the admitted domain or format nodes visited by the transaction.
    #[must_use]
    #[inline(always)]
    pub const fn visited_nodes(self) -> usize {
        self.visited_nodes
    }

    /// Returns the admitted collection items visited by the transaction.
    #[must_use]
    #[inline(always)]
    pub const fn visited_collection_items(self) -> usize {
        self.visited_collection_items
    }

    /// Returns the greatest active structural depth observed by the
    /// transaction.
    #[must_use]
    #[inline(always)]
    pub const fn max_depth(self) -> usize {
        self.max_depth
    }

    /// Returns omitted source bytes when the source length is known.
    #[must_use]
    #[inline(always)]
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

    /// Records one admitted structural node.
    #[must_use]
    pub(crate) const fn with_domain_node(mut self, depth: usize) -> Self {
        self.visited_nodes = self.visited_nodes.saturating_add(1);
        self.max_depth = if self.max_depth > depth { self.max_depth } else { depth };
        self
    }

    /// Records one admitted collection item.
    #[must_use]
    pub(crate) const fn with_collection_item(mut self) -> Self {
        self.visited_collection_items = self.visited_collection_items.saturating_add(1);
        self
    }
}

/// Compact set of summary reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RedactionReasons(
    /// Stable bit flags for the reasons accumulated by one operation.
    u64,
);

impl RedactionReasons {
    /// Creates an empty reason set.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Adds one reason.
    #[must_use]
    pub const fn with(self, reason: RedactionReason) -> Self {
        Self(self.0 | reason.bit())
    }

    /// Returns whether a reason is present.
    #[must_use]
    pub const fn contains(self, reason: RedactionReason) -> bool {
        self.0 & reason.bit() != 0
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
    /// Whether the operation intentionally bypassed redaction.
    redaction_disabled: bool,
    /// Final completion state of the operation.
    completion: RedactionCompletion,
    /// Reasons explaining degraded completion.
    reasons: RedactionReasons,
    /// Resource accounting captured by the operation.
    usage: RedactionUsage,
}

impl RedactionSummary {
    /// Creates a summary from runtime-owned completion, reasons, and usage.
    #[must_use]
    pub(crate) const fn from_parts(
        redaction_disabled: bool,
        completion: RedactionCompletion,
        reasons: RedactionReasons,
        usage: RedactionUsage,
    ) -> Self {
        Self {
            redaction_disabled,
            completion,
            reasons,
            usage,
        }
    }

    /// Creates a complete summary.
    #[must_use]
    pub(crate) const fn complete() -> Self {
        Self {
            redaction_disabled: false,
            completion: RedactionCompletion::Complete,
            reasons: RedactionReasons::empty(),
            usage: RedactionUsage::empty(),
        }
    }

    /// Creates a degraded summary.
    #[must_use]
    pub(crate) const fn truncated(reason: RedactionReason) -> Self {
        Self {
            redaction_disabled: false,
            completion: RedactionCompletion::Truncated,
            reasons: RedactionReasons::empty().with(reason),
            usage: RedactionUsage::empty(),
        }
    }

    /// Returns completion state.
    #[must_use]
    #[inline(always)]
    pub const fn completion(self) -> RedactionCompletion {
        self.completion
    }

    /// Returns whether redaction was globally disabled for this operation.
    #[must_use]
    #[inline(always)]
    pub const fn is_redaction_disabled(self) -> bool {
        self.redaction_disabled
    }

    /// Returns accumulated reasons.
    #[must_use]
    #[inline(always)]
    pub const fn reasons(self) -> RedactionReasons {
        self.reasons
    }

    /// Returns resource use measured by the operation that produced this
    /// summary.
    #[must_use]
    #[inline(always)]
    pub const fn usage(self) -> RedactionUsage {
        self.usage
    }

    /// Creates a summary for a transaction that exhausted safe output capacity.
    #[must_use]
    pub(crate) const fn exhausted(reason: RedactionReason) -> Self {
        Self {
            redaction_disabled: false,
            completion: RedactionCompletion::Exhausted,
            reasons: RedactionReasons::empty().with(reason),
            usage: RedactionUsage::empty(),
        }
    }
}
