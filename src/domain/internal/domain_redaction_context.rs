// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Private domain traversal state backed by [`qubit_budget::StructureBudget`].
// qubit-style: allow multiple-public-types

use qubit_budget::StructureBudget;
use qubit_budget::StructureLimits;

use crate::policy::DomainTraversalAdmission;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DomainValueBudgetAdmission {
    Entered,
    DepthLimitReached,
    TraversalLimitReached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DomainTruncationCheckpoint {
    depth_generation: usize,
    traversal_generation: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DomainTruncation {
    None,
    Depth,
    Traversal,
}

/// Tracks one value's independent structural traversal budget.
#[derive(Debug)]
pub(crate) struct DomainRedactionContext {
    budget: StructureBudget,
    current_depth: usize,
    max_depth: usize,
    traversal_closed: bool,
    depth_generation: usize,
    traversal_generation: usize,
    collection_items_seen: usize,
    maximum_depth_observed: usize,
}

impl DomainRedactionContext {
    #[must_use]
    pub(crate) fn new(limits: StructureLimits) -> Self {
        let max_depth = limits.max_depth().unwrap_or(usize::MAX);
        Self {
            budget: limits.budget(),
            current_depth: 0,
            max_depth,
            traversal_closed: false,
            depth_generation: 0,
            traversal_generation: 0,
            collection_items_seen: 0,
            maximum_depth_observed: 0,
        }
    }

    pub(crate) fn enter_value(&mut self) -> DomainValueBudgetAdmission {
        if self.traversal_closed {
            return DomainValueBudgetAdmission::TraversalLimitReached;
        }
        if self.current_depth >= self.max_depth {
            self.depth_generation = self.depth_generation.wrapping_add(1);
            return DomainValueBudgetAdmission::DepthLimitReached;
        }
        if self.budget.enter_node(self.current_depth.saturating_add(1)).is_err() {
            self.close_traversal();
            return DomainValueBudgetAdmission::TraversalLimitReached;
        }
        self.current_depth += 1;
        self.maximum_depth_observed = self.maximum_depth_observed.max(self.current_depth);
        DomainValueBudgetAdmission::Entered
    }

    pub(crate) fn admit_field(&mut self) -> DomainTraversalAdmission {
        if self.traversal_closed {
            return DomainTraversalAdmission::LimitReached;
        }
        if self.budget.charge_node().is_err() {
            self.close_traversal();
            return DomainTraversalAdmission::LimitReached;
        }
        DomainTraversalAdmission::Render
    }

    pub(crate) fn admit_collection_item(&mut self) -> DomainTraversalAdmission {
        if self.traversal_closed {
            return DomainTraversalAdmission::LimitReached;
        }
        let next = self.collection_items_seen.saturating_add(1);
        if self.budget.check_sequence_items(next).is_err() {
            self.close_traversal();
            return DomainTraversalAdmission::LimitReached;
        }
        self.collection_items_seen = next;
        DomainTraversalAdmission::Render
    }

    pub(crate) fn leave_value(&mut self) {
        debug_assert!(self.current_depth > 0, "domain scope depth underflow");
        self.current_depth -= 1;
    }

    pub(crate) const fn truncation_checkpoint(&self) -> DomainTruncationCheckpoint {
        DomainTruncationCheckpoint {
            depth_generation: self.depth_generation,
            traversal_generation: self.traversal_generation,
        }
    }

    pub(crate) const fn truncation_since(&self, checkpoint: DomainTruncationCheckpoint) -> DomainTruncation {
        if self.traversal_generation != checkpoint.traversal_generation {
            DomainTruncation::Traversal
        } else if self.depth_generation != checkpoint.depth_generation {
            DomainTruncation::Depth
        } else {
            DomainTruncation::None
        }
    }

    fn close_traversal(&mut self) {
        self.traversal_closed = true;
        self.traversal_generation = self.traversal_generation.wrapping_add(1);
    }
}
