// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable domain-structure accounting for one redaction session.

use super::DomainRedactionLimits;
use super::DomainTraversalAdmission;

// qubit-style: allow type-file-name
/// Internal result of charging one domain value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DomainValueBudgetAdmission {
    Entered,
    DepthLimitReached,
    TraversalLimitReached,
}

/// Snapshot used to classify truncation that occurs during one fragment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DomainTruncationCheckpoint {
    depth_generation: usize,
    traversal_generation: usize,
}

/// Structural completion observed since a domain checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DomainTruncation {
    None,
    Depth,
    Traversal,
}

/// Tracks cumulative domain traversal and currently active nesting depth.
#[must_use]
#[derive(Debug)]
pub(crate) struct DomainRedactionBudget {
    remaining_nodes: usize,
    remaining_collection_items: usize,
    current_depth: usize,
    max_depth: usize,
    traversal_closed: bool,
    depth_generation: usize,
    traversal_generation: usize,
}

impl DomainRedactionBudget {
    /// Creates fresh session accounting from immutable domain limits.
    #[inline]
    pub(crate) const fn new(limits: DomainRedactionLimits) -> Self {
        Self {
            remaining_nodes: limits.max_nodes(),
            remaining_collection_items: limits.max_collection_items(),
            current_depth: 0,
            max_depth: limits.max_depth(),
            traversal_closed: false,
            depth_generation: 0,
            traversal_generation: 0,
        }
    }

    /// Charges one domain value and enters its active depth.
    ///
    /// Admission checks permanent traversal closure first, active depth second,
    /// and cumulative nodes last. A depth rejection records truncation without
    /// closing traversal, so sibling values remain eligible. Node exhaustion
    /// records truncation and permanently closes domain traversal. Successful
    /// entry consumes one node and increments active depth; the depth must
    /// later be released by the owning RAII scope, while the node is never
    /// restored.
    pub(crate) fn enter_value(&mut self) -> DomainValueBudgetAdmission {
        if self.traversal_closed {
            return DomainValueBudgetAdmission::TraversalLimitReached;
        }
        if self.current_depth >= self.max_depth {
            self.record_depth_truncation();
            return DomainValueBudgetAdmission::DepthLimitReached;
        }
        if self.remaining_nodes == 0 {
            self.close_traversal();
            return DomainValueBudgetAdmission::TraversalLimitReached;
        }
        self.remaining_nodes -= 1;
        self.current_depth += 1;
        DomainValueBudgetAdmission::Entered
    }

    /// Charges one field before the caller reads or formats its value.
    ///
    /// Successful charges consume one cumulative node. Exhaustion records a
    /// truncation and permanently closes domain traversal for this session.
    pub(crate) fn admit_field(&mut self) -> DomainTraversalAdmission {
        if self.traversal_closed {
            return DomainTraversalAdmission::LimitReached;
        }
        if self.remaining_nodes == 0 {
            self.close_traversal();
            return DomainTraversalAdmission::LimitReached;
        }
        self.remaining_nodes -= 1;
        DomainTraversalAdmission::Render
    }

    /// Charges one collection item before the caller advances its iterator.
    ///
    /// Successful charges consume one cumulative collection item. Exhaustion
    /// records a truncation and permanently closes domain traversal, ensuring
    /// callers can stop before pulling or formatting an unadmitted value.
    pub(crate) fn admit_collection_item(&mut self) -> DomainTraversalAdmission {
        if self.traversal_closed {
            return DomainTraversalAdmission::LimitReached;
        }
        if self.remaining_collection_items == 0 {
            self.close_traversal();
            return DomainTraversalAdmission::LimitReached;
        }
        self.remaining_collection_items -= 1;
        DomainTraversalAdmission::Render
    }

    /// Releases one successfully entered domain-value depth.
    ///
    /// This restores only active depth. Cumulative node and collection-item
    /// charges intentionally remain consumed.
    pub(crate) fn leave_value(&mut self) {
        debug_assert!(self.current_depth > 0, "domain scope depth underflow");
        self.current_depth -= 1;
    }

    /// Returns the current truncation checkpoint for later comparison.
    #[inline(always)]
    pub(crate) const fn truncation_checkpoint(
        &self,
    ) -> DomainTruncationCheckpoint {
        DomainTruncationCheckpoint {
            depth_generation: self.depth_generation,
            traversal_generation: self.traversal_generation,
        }
    }

    /// Classifies structural truncation recorded after `checkpoint`.
    #[inline(always)]
    pub(crate) const fn truncation_since(
        &self,
        checkpoint: DomainTruncationCheckpoint,
    ) -> DomainTruncation {
        if self.traversal_generation != checkpoint.traversal_generation {
            DomainTruncation::Traversal
        } else if self.depth_generation != checkpoint.depth_generation {
            DomainTruncation::Depth
        } else {
            DomainTruncation::None
        }
    }

    /// Records branch-local depth truncation.
    #[inline]
    fn record_depth_truncation(&mut self) {
        self.depth_generation = self.depth_generation.wrapping_add(1);
    }

    /// Records truncation and permanently closes domain traversal.
    #[inline]
    fn close_traversal(&mut self) {
        self.traversal_closed = true;
        self.traversal_generation = self.traversal_generation.wrapping_add(1);
    }
}
