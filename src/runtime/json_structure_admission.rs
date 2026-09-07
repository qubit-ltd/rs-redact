// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Narrow structural accounting used while materializing admitted JSON text.

use super::StructuralBudget;
use super::structural_entry::StructuralEntry;
use super::summary_builder::SummaryBuilder;
use crate::RedactionReason;
use crate::RedactionSummary;
use crate::RedactionUsage;

/// Borrows only the runtime state needed to account for JSON structure.
///
/// # Type Parameters
///
/// - `'runtime`: Exclusive borrow of the disjoint shared accounting fields.
pub(crate) struct JsonStructureAdmission<'runtime> {
    /// Shared structural limits and cumulative traversal state.
    structural: &'runtime mut StructuralBudget,
    /// Transaction-wide resource usage.
    usage: &'runtime mut RedactionUsage,
    /// Resource usage for the active independently published operation.
    active_operation_usage: &'runtime mut Option<RedactionUsage>,
    /// Transaction-wide completion and reason state.
    summary: &'runtime mut SummaryBuilder,
    /// Completion and reason state for the active operation.
    active_operation_summary: &'runtime mut Option<SummaryBuilder>,
}

impl<'runtime> JsonStructureAdmission<'runtime> {
    /// Creates a narrow admission capability from disjoint runtime borrows.
    ///
    /// # Parameters
    ///
    /// - `structural`: Shared node, key, collection, and depth budget.
    /// - `usage`: Transaction-wide resource counters.
    /// - `active_operation_usage`: Current item counters, or `None` outside an
    ///   item.
    /// - `summary`: Transaction-wide completion and provenance.
    /// - `active_operation_summary`: Current item summary, or `None` outside an
    ///   item.
    ///
    /// # Returns
    ///
    /// An admission capability borrowing only the disjoint accounting state.
    #[must_use]
    #[inline(always)]
    pub(super) const fn new(
        structural: &'runtime mut StructuralBudget,
        usage: &'runtime mut RedactionUsage,
        active_operation_usage: &'runtime mut Option<RedactionUsage>,
        summary: &'runtime mut SummaryBuilder,
        active_operation_summary: &'runtime mut Option<SummaryBuilder>,
    ) -> Self {
        Self {
            structural,
            usage,
            active_operation_usage,
            summary,
            active_operation_summary,
        }
    }

    /// Admits one JSON node at its root-inclusive structural depth.
    ///
    /// # Parameters
    ///
    /// - `depth`: Root-inclusive node depth, starting at one.
    ///
    /// # Returns
    ///
    /// Whether the node was charged; rejection records its structural reason.
    #[must_use]
    pub(crate) fn admit_node(&mut self, depth: usize) -> bool {
        match self.structural.admit_format_node(depth) {
            StructuralEntry::Entered => {
                self.record_structural_node(depth);
                true
            }
            StructuralEntry::DepthLimitReached => {
                self.record_summary(RedactionSummary::truncated(RedactionReason::DepthLimitReached));
                false
            }
            StructuralEntry::TraversalLimitReached => {
                self.record_summary(RedactionSummary::truncated(RedactionReason::TraversalLimitReached));
                false
            }
        }
    }

    /// Admits one array element or object entry through the shared ledger.
    ///
    /// # Returns
    ///
    /// Whether the item was charged; rejection records traversal truncation.
    #[must_use]
    #[inline]
    pub(crate) fn admit_collection_item(&mut self) -> bool {
        if self.structural.admit_collection_item() {
            self.record_collection_item();
            true
        } else {
            self.record_summary(RedactionSummary::truncated(RedactionReason::TraversalLimitReached));
            false
        }
    }

    /// Records one admitted node in transaction and operation usage.
    ///
    /// # Parameters
    ///
    /// - `depth`: Depth of the successfully admitted node.
    #[inline]
    fn record_structural_node(&mut self, depth: usize) {
        *self.usage = (*self.usage).with_domain_node(depth);
        if let Some(usage) = self.active_operation_usage.as_mut() {
            *usage = usage.with_domain_node(depth);
        }
    }

    /// Records one admitted collection item in both accounting scopes.
    #[inline]
    fn record_collection_item(&mut self) {
        *self.usage = (*self.usage).with_collection_item();
        if let Some(usage) = self.active_operation_usage.as_mut() {
            *usage = usage.with_collection_item();
        }
    }

    /// Merges one structural rejection into transaction and operation state.
    ///
    /// # Parameters
    ///
    /// - `delta`: Newly observed completion and reason facts to merge.
    #[inline]
    fn record_summary(&mut self, delta: RedactionSummary) {
        *self.summary = self.summary.merge(delta);
        if let Some(summary) = self.active_operation_summary.as_mut() {
            *summary = summary.merge(delta);
        }
    }
}
