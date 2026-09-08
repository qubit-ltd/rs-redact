// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared policy and accounting independent of a publication model.

use std::sync::Arc;

#[cfg(feature = "json")]
use qubit_budget::json::JsonValueBudget;
#[cfg(feature = "json")]
use serde_json::Value;

use super::redaction_budget::RedactionBudget;
use super::structural_entry::StructuralEntry;
use super::summary_builder::SummaryBuilder;
use super::transaction_phase::TransactionPhase;
use crate::RedactionPolicy;
use crate::RedactionReason;
use crate::RedactionSummary;

/// Holds policy, resource accounting, and publication-independent state.
pub(crate) struct RuntimeCore {
    /// Immutable policy snapshot shared by the active transaction.
    pub(super) policy: Arc<RedactionPolicy>,
    /// Mutable resource ledger for the active transaction.
    pub(super) budget: RedactionBudget,
    /// Aggregate summary accumulated across all operations.
    pub(super) summary: SummaryBuilder,
    /// Whether future output is still admissible.
    pub(super) phase: TransactionPhase,
    /// Summary scope for an individually published operation, when active.
    pub(super) active_operation_summary: Option<SummaryBuilder>,
    /// Buffered output for the current structured domain frame.
    pub(super) domain_frame: String,
    /// Number of bytes retained in the current domain frame.
    pub(super) domain_frame_output_bytes: usize,
    /// Whether the current domain frame omitted output.
    pub(super) domain_frame_truncated: bool,
    /// Whether the domain frame reached its output allowance.
    pub(super) domain_frame_output_limit_reached: bool,
}

impl RuntimeCore {
    /// Creates runtime state for one active transaction.
    ///
    /// # Parameters
    ///
    /// - `policy`: Immutable snapshot governing the new transaction.
    ///
    /// # Returns
    ///
    /// An active, empty runtime with no item or domain frame in progress.
    #[must_use]
    pub(super) fn new(policy: Arc<RedactionPolicy>) -> Self {
        let redaction_disabled = policy.is_disabled();
        Self {
            budget: RedactionBudget::new(policy.limits()),
            policy,
            summary: SummaryBuilder::new(redaction_disabled),
            phase: TransactionPhase::Active,
            active_operation_summary: None,
            domain_frame: String::new(),
            domain_frame_output_bytes: 0,
            domain_frame_truncated: false,
            domain_frame_output_limit_reached: false,
        }
    }

    /// Returns the immutable policy snapshot.
    ///
    /// # Returns
    ///
    /// The immutable policy snapshot retained by this transaction.
    #[inline(always)]
    #[must_use]
    pub(super) fn policy(&self) -> &RedactionPolicy {
        self.policy.as_ref()
    }

    /// Returns output capacity not yet charged to this transaction.
    ///
    /// # Returns
    ///
    /// Remaining final escaped-output bytes according to this shared ledger.
    #[must_use]
    #[inline(always)]
    pub(super) fn remaining_output_bytes(&self) -> usize {
        self.budget
            .output_limit()
            .saturating_sub(self.budget.usage().output_bytes())
    }

    /// Returns input capacity not yet inspected by this transaction.
    ///
    /// # Returns
    ///
    /// Remaining admitted input bytes according to this shared ledger.
    #[must_use]
    #[inline(always)]
    pub(super) fn remaining_input_bytes(&self) -> usize {
        self.policy()
            .limits()
            .max_input_bytes()
            .saturating_sub(self.budget.usage().inspected_input_bytes())
    }

    /// Reports whether no further output can be admitted.
    ///
    /// # Returns
    ///
    /// Whether no later rendering operation may inspect input or emit output.
    #[must_use]
    #[inline(always)]
    pub(super) fn is_output_exhausted(&self) -> bool {
        self.phase == TransactionPhase::OutputExhausted || self.remaining_output_bytes() == 0
    }

    /// Borrows the transaction-wide JSON budget for lexical decoder admission.
    ///
    /// # Returns
    ///
    /// An exclusive borrow of the shared lexical JSON value budget.
    #[cfg(feature = "http")]
    #[inline(always)]
    #[must_use]
    pub(crate) fn json_value_budget_mut(&mut self) -> &mut JsonValueBudget {
        self.budget.json_value_budget_mut()
    }

    /// Splits JSON structure accounting from lexical value accounting.
    ///
    /// # Returns
    ///
    /// Disjoint structural-accounting capability and lexical JSON value budget.
    #[cfg(feature = "json")]
    #[must_use]
    pub(crate) fn split_json_admission(&mut self) -> (super::JsonStructureAdmission<'_>, &mut JsonValueBudget) {
        let Self {
            budget,
            summary,
            active_operation_summary,
            ..
        } = self;
        let (structural, usage, active_operation_usage, json_budget) = budget.split_json_admission();
        (
            super::JsonStructureAdmission::new(
                structural,
                usage,
                active_operation_usage,
                summary,
                active_operation_summary,
            ),
            json_budget,
        )
    }

    /// Consumes runtime state into its aggregate summary.
    ///
    /// # Returns
    ///
    /// The final accumulated completion, provenance, and resource usage.
    #[must_use]
    #[inline(always)]
    pub(super) fn into_summary(self) -> RedactionSummary {
        self.summary.build(self.budget.usage())
    }

    /// Starts isolated accounting for one individually published item.
    ///
    /// # Returns
    ///
    /// `true` if this call owns a newly created item scope; `false` when an
    /// outer operation already owns it. Only the owner may close the scope.
    ///
    /// # Panics
    ///
    /// In debug builds, panics if a new summary scope encounters an already
    /// active usage scope, which indicates an internal ownership mismatch.
    pub(super) fn begin_item_summary(&mut self) -> bool {
        if self.active_operation_summary.is_some() {
            return false;
        }
        self.active_operation_summary = Some(SummaryBuilder::new(self.policy().is_disabled()));
        let owns_operation_usage = self.budget.begin_operation_usage();
        debug_assert!(owns_operation_usage);
        true
    }

    /// Ends isolated accounting when this call created the item scope.
    ///
    /// # Parameters
    ///
    /// - `owns_item_summary`: Ownership returned by `begin_item_summary`.
    #[inline]
    pub(super) fn end_item_summary(&mut self, owns_item_summary: bool) {
        if owns_item_summary {
            self.active_operation_summary = None;
            self.budget.end_operation_usage(true);
        }
    }

    /// Merges one result summary into transaction and item summaries.
    ///
    /// # Parameters
    ///
    /// - `delta`: Observed completion and reason facts to merge.
    #[inline]
    pub(super) fn record_summary(&mut self, delta: RedactionSummary) {
        self.summary = self.summary.merge(delta);
        if let Some(item_summary) = self.active_operation_summary {
            self.active_operation_summary = Some(item_summary.merge(delta));
        }
    }

    /// Charges retained output bytes to the active accounting scopes.
    ///
    /// # Parameters
    ///
    /// - `bytes`: Newly retained final escaped bytes.
    #[inline(always)]
    pub(super) fn record_output_bytes(&mut self, bytes: usize) {
        self.budget.record_output_bytes(bytes);
    }

    /// Records rejection by the transaction-wide JSON value budget.
    #[cfg(feature = "json")]
    #[inline(always)]
    pub(crate) fn record_json_value_limit_reached(&mut self) {
        self.record_summary(RedactionSummary::truncated(RedactionReason::TraversalLimitReached));
    }

    /// Admits one structured format node or records its rejection.
    ///
    /// # Parameters
    ///
    /// - `depth`: Root-inclusive format depth, starting at one.
    ///
    /// # Returns
    ///
    /// Whether the node was charged; rejection records its depth or traversal
    /// cause.
    #[must_use]
    pub(super) fn admit_format_node(&mut self, depth: usize) -> bool {
        match self.budget.structural().admit_format_node(depth) {
            StructuralEntry::Entered => {
                self.budget.record_structural_node(depth);
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

    /// Checks whether one collection item and one format node can be charged
    /// before advancing an untrusted iterator.
    ///
    /// # Parameters
    ///
    /// - `depth`: Root-inclusive depth of the next format item.
    ///
    /// # Returns
    ///
    /// Whether both collection and node capacity permit advancing the iterator;
    /// this preflight does not charge the item itself.
    #[must_use]
    pub(super) fn preflight_format_item(&mut self, depth: usize) -> bool {
        let limits = self.policy().limits();
        let usage = self.budget.usage();
        if limits.max_depth().is_some_and(|maximum| depth > maximum) {
            self.record_summary(RedactionSummary::truncated(RedactionReason::DepthLimitReached));
            return false;
        }
        if limits
            .max_collection_items()
            .is_some_and(|maximum| usage.visited_collection_items() >= maximum)
            || limits
                .max_nodes()
                .is_some_and(|maximum| usage.visited_nodes() >= maximum)
        {
            self.record_summary(RedactionSummary::truncated(RedactionReason::TraversalLimitReached));
            return false;
        }
        true
    }

    /// Checks collection capacity before advancing an untrusted iterator.
    ///
    /// # Returns
    ///
    /// Whether collection capacity permits advancing the iterator; the caller
    /// must subsequently charge any yielded item.
    #[must_use]
    pub(super) fn preflight_collection_item(&mut self) -> bool {
        let limits = self.policy().limits();
        let usage = self.budget.usage();
        if limits
            .max_collection_items()
            .is_some_and(|maximum| usage.visited_collection_items() >= maximum)
        {
            self.record_summary(RedactionSummary::truncated(RedactionReason::TraversalLimitReached));
            return false;
        }
        true
    }

    /// Enters one structured domain value or records its rejection.
    ///
    /// # Returns
    ///
    /// Whether a node was admitted and its nesting scope entered. Call
    /// `leave_domain_value` only after successful entry.
    #[must_use]
    pub(super) fn begin_domain_value(&mut self) -> bool {
        match self.budget.structural().enter_value() {
            StructuralEntry::Entered => {
                let depth = self.budget.structural().current_depth();
                self.budget.record_structural_node(depth);
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

    /// Admits one field in the active structured domain value.
    ///
    /// # Returns
    ///
    /// Whether one field node was charged before value access.
    #[must_use]
    pub(super) fn admit_domain_field(&mut self) -> bool {
        let admission = self.budget.structural().admit_field();
        if admission {
            let depth = self.budget.structural().current_depth();
            self.budget.record_structural_node(depth);
        } else {
            self.record_summary(RedactionSummary::truncated(RedactionReason::TraversalLimitReached));
        }
        admission
    }

    /// Admits one collection item in the active structured domain value.
    ///
    /// # Returns
    ///
    /// Whether one cumulative collection item was charged before value access.
    #[must_use]
    pub(super) fn admit_domain_collection_item(&mut self) -> bool {
        let admission = self.budget.structural().admit_collection_item();
        if admission {
            self.budget.record_collection_item();
        } else {
            self.record_summary(RedactionSummary::truncated(RedactionReason::TraversalLimitReached));
        }
        admission
    }

    /// Admits a raw domain key without charging a second field or item node.
    ///
    /// Returns `false` and records structural truncation before any key
    /// normalization or value access when its byte length exceeds the limit.
    ///
    /// # Parameters
    ///
    /// - `key`: Raw UTF-8 key checked before normalization or value access.
    ///
    /// # Returns
    ///
    /// Whether the key fits and structural traversal remains open.
    #[inline]
    pub(super) fn admit_domain_key(&mut self, key: &str) -> bool {
        let admitted = self.budget.structural().admit_key(key.len());
        if !admitted {
            self.record_summary(RedactionSummary::truncated(RedactionReason::TraversalLimitReached));
        }
        admitted
    }

    /// Releases the current structured domain-value depth.
    ///
    /// # Panics
    ///
    /// In debug builds, panics if there is no successfully entered domain scope
    /// to leave. Every successful entry must have exactly one matching leave.
    #[inline(always)]
    pub(super) fn leave_domain_value(&mut self) {
        self.budget.structural().leave_value();
    }

    /// Admits a parsed JSON value through JSON-specific limits.
    ///
    /// # Parameters
    ///
    /// - `value`: Parsed tree to account before it is rendered.
    ///
    /// # Returns
    ///
    /// Whether the entire tree fits the shared JSON-specific limits.
    #[cfg(feature = "json")]
    #[must_use]
    #[inline]
    pub(super) fn admit_json_value(&mut self, value: &Value) -> bool {
        if self.budget.admit_json_value(value) {
            true
        } else {
            self.record_summary(RedactionSummary::truncated(RedactionReason::TraversalLimitReached));
            false
        }
    }

    /// Records output exhaustion and tells the caller to skip aggregate work.
    ///
    /// # Returns
    ///
    /// Whether the caller must skip this operation. A skipped rendering records
    /// output exhaustion without inspecting additional input.
    #[must_use]
    pub(super) fn skip_aggregate_for_exhausted_output(&mut self) -> bool {
        if !self.is_output_exhausted() {
            return false;
        }
        self.phase = TransactionPhase::OutputExhausted;
        self.record_summary(RedactionSummary::exhausted());
        true
    }

    /// Charges input bytes only when the whole input remains admissible.
    ///
    /// # Parameters
    ///
    /// - `bytes`: Size of the complete raw input unit submitted for admission.
    ///
    /// # Returns
    ///
    /// Whether the whole unit was admitted. Rejected units count as presented
    /// but contribute no inspected bytes.
    pub(super) fn admit_input(&mut self, bytes: usize) -> bool {
        let inspected = self.budget.usage().inspected_input_bytes();
        let limit = self.policy().limits().max_input_bytes();
        if bytes > limit.saturating_sub(inspected) {
            self.budget.record_input(bytes, 0);
            self.record_summary(RedactionSummary::truncated(RedactionReason::InputLimitReached));
            return false;
        }
        self.budget.record_input(bytes, bytes);
        true
    }

    /// Records scalar input that was formatted through a bounded capture.
    ///
    /// # Parameters
    ///
    /// - `presented`: Bytes submitted by the bounded formatter.
    /// - `inspected`: Accepted bytes, including bytes discarded after formatter
    ///   failure.
    #[inline]
    pub(super) fn record_input_usage(&mut self, presented: usize, inspected: usize) {
        self.budget.record_input(presented, inspected);
        if presented > inspected {
            self.record_summary(RedactionSummary::truncated(RedactionReason::InputLimitReached));
        }
    }

    /// Charges HTTP source input while preserving capture truncation metadata.
    ///
    /// # Parameters
    ///
    /// - `total`: `Some(length)` is the complete source length; `None` means
    ///   unknown.
    /// - `inspectable`: Captured bytes available for whole-unit admission.
    ///
    /// # Returns
    ///
    /// Whether the complete captured unit was admitted; omitted source
    /// accounting retains the distinction between a known count and unknown
    /// length.
    #[cfg(feature = "http")]
    pub(super) fn admit_source_input(&mut self, total: Option<usize>, inspectable: usize) -> bool {
        let already_inspected = self.budget.usage().inspected_input_bytes();
        let limit = self.policy().limits().max_input_bytes();
        let admitted = inspectable <= limit.saturating_sub(already_inspected);
        let inspected = if admitted { inspectable } else { 0 };
        let presented = total.unwrap_or(inspectable);
        let omitted = total.map(|length| length.saturating_sub(inspected));
        self.budget.record_source_input(presented, inspected, omitted);
        if !admitted {
            self.record_summary(RedactionSummary::truncated(RedactionReason::InputLimitReached));
        }
        admitted
    }
}

#[cfg(test)]
mod tests {
    use super::RuntimeCore;
    use crate::RedactionPolicy;

    /// Private operation accounting must start even without debug assertions.
    #[test]
    fn test_item_scope_records_its_own_usage_in_every_build_profile() {
        let mut core = RuntimeCore::new(RedactionPolicy::standard().into());
        assert!(core.begin_item_summary());
        core.record_input_usage(7, 5);
        core.record_output_bytes(3);
        let usage = core
            .budget
            .active_operation_usage()
            .expect("active item owns a usage ledger");
        assert_eq!(usage.presented_input_bytes(), 7);
        assert_eq!(usage.inspected_input_bytes(), 5);
        assert_eq!(usage.output_bytes(), 3);
        core.end_item_summary(true);
        assert!(core.budget.active_operation_usage().is_none());
        assert_eq!(core.budget.usage().inspected_input_bytes(), 5);
    }
}
