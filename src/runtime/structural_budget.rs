// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Transaction-owned structural accounting backed by
//! [`qubit_budget::StructureBudget`].

use qubit_budget::StructureBudget;
use qubit_budget::StructureLimits;

use super::structural_entry::StructuralEntry;

/// Tracks the shared structural resources of one redaction transaction.
#[derive(Debug)]
pub(crate) struct StructuralBudget {
    /// Underlying node, collection, and key budget.
    budget: StructureBudget,
    /// Active domain-value nesting depth.
    current_depth: usize,
    /// Optional maximum domain or format nesting depth.
    max_depth: Option<usize>,
    /// Whether a prior rejection prevents any later traversal.
    traversal_closed: bool,
    /// Cumulative collection items admitted across namespaces.
    collection_items_seen: usize,
}

impl StructuralBudget {
    /// Creates the structural ledger from immutable transaction limits.
    #[must_use]
    pub(crate) fn new(limits: StructureLimits) -> Self {
        Self {
            budget: limits.budget(),
            current_depth: 0,
            max_depth: limits.max_depth(),
            traversal_closed: false,
            collection_items_seen: 0,
        }
    }

    /// Enters an explicitly nested domain value.
    pub(crate) fn enter_value(&mut self) -> StructuralEntry {
        if self.traversal_closed {
            return StructuralEntry::TraversalLimitReached;
        }
        if self.max_depth.is_some_and(|max_depth| self.current_depth >= max_depth) {
            return StructuralEntry::DepthLimitReached;
        }
        if self.budget.enter_node(self.current_depth.saturating_add(1)).is_err() {
            self.close_traversal();
            return StructuralEntry::TraversalLimitReached;
        }
        self.current_depth += 1;
        StructuralEntry::Entered
    }

    /// Charges one field node without changing the nesting depth.
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

    /// Charges a format node without changing domain nesting depth.
    pub(crate) fn admit_format_node(&mut self, depth: usize) -> StructuralEntry {
        if self.traversal_closed {
            return StructuralEntry::TraversalLimitReached;
        }
        if self.max_depth.is_some_and(|max_depth| depth > max_depth) {
            return StructuralEntry::DepthLimitReached;
        }
        if self.budget.charge_node().is_err() {
            self.close_traversal();
            return StructuralEntry::TraversalLimitReached;
        }
        StructuralEntry::Entered
    }

    /// Charges one collection item.
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

    /// Leaves one explicitly nested domain value.
    pub(crate) fn leave_value(&mut self) {
        debug_assert!(self.current_depth > 0, "domain scope depth underflow");
        self.current_depth -= 1;
    }

    /// Returns the active domain nesting depth.
    #[must_use]
    pub(crate) const fn current_depth(&self) -> usize {
        self.current_depth
    }

    /// Closes traversal after a resource limit rejects it.
    fn close_traversal(&mut self) {
        self.traversal_closed = true;
    }
}
