// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Private domain traversal state backed by [`qubit_budget::StructureBudget`].
// qubit-style: allow multiple-public-types

use qubit_budget::StructureBudget;
use qubit_budget::StructureLimits;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DomainEntry {
    Entered,
    DepthLimitReached,
    TraversalLimitReached,
}

/// Tracks one value's independent structural traversal budget.
#[derive(Debug)]
pub(crate) struct DomainRedactionContext {
    budget: StructureBudget,
    current_depth: usize,
    max_depth: Option<usize>,
    traversal_closed: bool,
    collection_items_seen: usize,
    maximum_depth_observed: usize,
}

impl DomainRedactionContext {
    #[must_use]
    pub(crate) fn new(limits: StructureLimits) -> Self {
        Self {
            budget: limits.budget(),
            current_depth: 0,
            max_depth: limits.max_depth(),
            traversal_closed: false,
            collection_items_seen: 0,
            maximum_depth_observed: 0,
        }
    }

    pub(crate) fn enter_value(&mut self) -> DomainEntry {
        if self.traversal_closed {
            return DomainEntry::TraversalLimitReached;
        }
        if self.max_depth.is_some_and(|max_depth| self.current_depth >= max_depth) {
            return DomainEntry::DepthLimitReached;
        }
        if self.budget.enter_node(self.current_depth.saturating_add(1)).is_err() {
            self.close_traversal();
            return DomainEntry::TraversalLimitReached;
        }
        self.current_depth += 1;
        self.maximum_depth_observed = self.maximum_depth_observed.max(self.current_depth);
        DomainEntry::Entered
    }

    pub(crate) fn admit_field(&mut self) -> bool {
        if self.traversal_closed {
            return false;
        }
        if self.budget.charge_node().is_err() {
            self.close_traversal();
            return false;
        }
        true
    }

    /// Charges one non-domain structural node to this transaction's shared
    /// budget without changing the domain writer's active nesting scope.
    pub(crate) fn admit_format_node(&mut self, depth: usize) -> DomainEntry {
        if self.traversal_closed {
            return DomainEntry::TraversalLimitReached;
        }
        if self.max_depth.is_some_and(|max_depth| depth > max_depth) {
            return DomainEntry::DepthLimitReached;
        }
        if self.budget.charge_node().is_err() {
            self.close_traversal();
            return DomainEntry::TraversalLimitReached;
        }
        self.maximum_depth_observed = self.maximum_depth_observed.max(depth);
        DomainEntry::Entered
    }

    pub(crate) fn admit_collection_item(&mut self) -> bool {
        if self.traversal_closed {
            return false;
        }
        let next = self.collection_items_seen.saturating_add(1);
        if self.budget.check_sequence_items(next).is_err() {
            self.close_traversal();
            return false;
        }
        self.collection_items_seen = next;
        true
    }

    /// Reports whether another format collection item can be admitted without
    /// changing the cumulative traversal state.
    #[must_use]
    pub(crate) fn can_admit_collection_item(&self) -> bool {
        !self.traversal_closed
            && self
                .budget
                .limits()
                .sequence_items_limit()
                .is_none_or(|limit| self.collection_items_seen < limit.maximum())
    }

    /// Reports whether another format node at `depth` can be admitted without
    /// changing the cumulative traversal state.
    #[must_use]
    pub(crate) fn can_admit_format_node(&self, depth: usize) -> bool {
        if self.traversal_closed || self.max_depth.is_some_and(|maximum| depth > maximum) {
            return false;
        }
        self.budget
            .limits()
            .nodes_limit()
            .is_none_or(|limit| self.budget.used_nodes() < limit.maximum())
    }

    pub(crate) fn leave_value(&mut self) {
        debug_assert!(self.current_depth > 0, "domain scope depth underflow");
        self.current_depth -= 1;
    }

    #[must_use]
    pub(crate) const fn current_depth(&self) -> usize {
        self.current_depth
    }

    fn close_traversal(&mut self) {
        self.traversal_closed = true;
    }
}
