// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared policy and accounting independent of a publication model.

use std::sync::Arc;

use super::redaction_budget::RedactionBudget;
use super::structural_entry::StructuralEntry;
use super::summary_builder::SummaryBuilder;
use super::transaction_phase::TransactionPhase;
use crate::RedactionPolicy;
use crate::RedactionReason;
use crate::RedactionSummary;

pub(super) struct RedactionRuntime {
    pub(super) policy: Arc<RedactionPolicy>,
    pub(super) budget: RedactionBudget,
    pub(super) summary: SummaryBuilder,
    pub(super) phase: TransactionPhase,
    pub(super) active_operation_summary: Option<SummaryBuilder>,
    pub(super) domain_frame: String,
    pub(super) domain_frame_output_bytes: usize,
    pub(super) domain_frame_truncated: bool,
    pub(super) domain_frame_output_limit_reached: bool,
}

impl RedactionRuntime {
    #[must_use]
    pub(super) fn new(policy: Arc<RedactionPolicy>) -> Self {
        Self {
            budget: RedactionBudget::new(policy.limits()),
            policy,
            summary: SummaryBuilder::new(),
            phase: TransactionPhase::Active,
            active_operation_summary: None,
            domain_frame: String::new(),
            domain_frame_output_bytes: 0,
            domain_frame_truncated: false,
            domain_frame_output_limit_reached: false,
        }
    }

    #[inline(always)]
    #[must_use]
    pub(super) fn policy(&self) -> &RedactionPolicy {
        self.policy.as_ref()
    }

    pub(super) fn into_summary(self) -> RedactionSummary {
        self.summary.build(self.budget.usage())
    }

    pub(super) fn begin_item_summary(&mut self) -> bool {
        if self.active_operation_summary.is_some() {
            return false;
        }
        self.active_operation_summary = Some(SummaryBuilder::new());
        debug_assert!(self.budget.begin_operation_usage());
        true
    }

    pub(super) fn end_item_summary(&mut self, owns_item_summary: bool) {
        if owns_item_summary {
            self.active_operation_summary = None;
            self.budget.end_operation_usage(true);
        }
    }

    pub(super) fn record_summary(&mut self, delta: RedactionSummary) {
        self.summary = self.summary.merge(delta);
        if let Some(item_summary) = self.active_operation_summary {
            self.active_operation_summary = Some(item_summary.merge(delta));
        }
    }

    pub(super) fn record_output_bytes(&mut self, bytes: usize) {
        self.budget.record_output_bytes(bytes);
    }

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

    #[inline(always)]
    pub(super) fn leave_domain_value(&mut self) {
        self.budget.structural().leave_value();
    }

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

    #[must_use]
    #[inline(always)]
    pub(super) fn remaining_output_bytes(&self) -> usize {
        self.budget
            .output_limit()
            .saturating_sub(self.budget.usage().output_bytes())
    }

    #[must_use]
    #[inline(always)]
    pub(super) fn is_output_exhausted(&self) -> bool {
        self.phase == TransactionPhase::OutputExhausted || self.remaining_output_bytes() == 0
    }

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
