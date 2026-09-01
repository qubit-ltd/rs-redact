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
    #[inline(always)]
    #[must_use]
    pub(super) fn policy(&self) -> &RedactionPolicy {
        self.policy.as_ref()
    }

    /// Consumes runtime state into its aggregate summary.
    pub(super) fn into_summary(self) -> RedactionSummary {
        self.summary.build(self.budget.usage())
    }

    /// Starts isolated accounting for one individually published item.
    pub(super) fn begin_item_summary(&mut self) -> bool {
        if self.active_operation_summary.is_some() {
            return false;
        }
        self.active_operation_summary = Some(SummaryBuilder::new(self.policy().is_disabled()));
        debug_assert!(self.budget.begin_operation_usage());
        true
    }

    /// Ends isolated accounting when this call created the item scope.
    pub(super) fn end_item_summary(&mut self, owns_item_summary: bool) {
        if owns_item_summary {
            self.active_operation_summary = None;
            self.budget.end_operation_usage(true);
        }
    }

    /// Merges one result summary into transaction and item summaries.
    pub(super) fn record_summary(&mut self, delta: RedactionSummary) {
        self.summary = self.summary.merge(delta);
        if let Some(item_summary) = self.active_operation_summary {
            self.active_operation_summary = Some(item_summary.merge(delta));
        }
    }

    /// Charges retained output bytes to the active accounting scopes.
    pub(super) fn record_output_bytes(&mut self, bytes: usize) {
        self.budget.record_output_bytes(bytes);
    }

    /// Borrows the transaction-wide JSON budget for lexical decoder admission.
    #[cfg(feature = "http")]
    pub(crate) fn json_value_budget_mut(&mut self) -> &mut JsonValueBudget {
        self.budget.json_value_budget_mut()
    }

    /// Splits JSON structure accounting from lexical value accounting.
    #[cfg(feature = "json")]
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

    /// Records rejection by the transaction-wide JSON value budget.
    #[cfg(feature = "json")]
    pub(crate) fn record_json_value_limit_reached(&mut self) {
        self.record_summary(RedactionSummary::truncated(RedactionReason::TraversalLimitReached));
    }

    /// Admits one structured format node or records its rejection.
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
    #[must_use]
    #[inline(always)]
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
    #[must_use]
    #[inline(always)]
    pub(super) fn admit_domain_collection_item(&mut self) -> bool {
        let admission = self.budget.structural().admit_collection_item();
        if admission {
            self.budget.record_collection_item();
        } else {
            self.record_summary(RedactionSummary::truncated(RedactionReason::TraversalLimitReached));
        }
        admission
    }

    /// Releases the current structured domain-value depth.
    #[inline(always)]
    pub(super) fn leave_domain_value(&mut self) {
        self.budget.structural().leave_value();
    }

    /// Admits a parsed JSON value through JSON-specific limits.
    #[cfg(feature = "json")]
    #[must_use]
    pub(super) fn admit_json_value(&mut self, value: &serde_json::Value) -> bool {
        if self.budget.admit_json_value(value) {
            true
        } else {
            self.record_summary(RedactionSummary::truncated(RedactionReason::TraversalLimitReached));
            false
        }
    }

    /// Returns output capacity not yet charged to this transaction.
    #[must_use]
    #[inline(always)]
    pub(super) fn remaining_output_bytes(&self) -> usize {
        self.budget
            .output_limit()
            .saturating_sub(self.budget.usage().output_bytes())
    }

    /// Reports whether no further output can be admitted.
    #[must_use]
    #[inline(always)]
    pub(super) fn is_output_exhausted(&self) -> bool {
        self.phase == TransactionPhase::OutputExhausted || self.remaining_output_bytes() == 0
    }

    /// Records output exhaustion and tells the caller to skip aggregate work.
    #[must_use]
    #[inline(always)]
    pub(super) fn skip_aggregate_for_exhausted_output(&mut self) -> bool {
        if !self.is_output_exhausted() {
            return false;
        }
        self.phase = TransactionPhase::OutputExhausted;
        self.record_summary(RedactionSummary::exhausted(RedactionReason::OutputLimitReached));
        true
    }

    /// Charges input bytes only when the whole input remains admissible.
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

    /// Admits the UTF-8 prefix that fits in the remaining input allowance.
    #[cfg(any(feature = "json", feature = "http", feature = "uri"))]
    #[must_use]
    pub(super) fn admit_input_prefix<'text>(&mut self, text: &'text str) -> &'text str {
        let inspected = self.budget.usage().inspected_input_bytes();
        let remaining = self.policy().limits().max_input_bytes().saturating_sub(inspected);
        let mut admitted = text.len().min(remaining);
        while admitted > 0 && !text.is_char_boundary(admitted) {
            admitted -= 1;
        }
        self.budget.record_input(text.len(), admitted);
        if admitted < text.len() {
            self.record_summary(RedactionSummary::truncated(RedactionReason::InputLimitReached));
        }
        &text[..admitted]
    }

    /// Charges HTTP source input while preserving capture truncation metadata.
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
