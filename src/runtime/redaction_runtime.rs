// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Shared policy and accounting independent of a publication model.

use std::sync::Arc;

use super::redaction_budget::RedactionBudget;
use super::summary_builder::SummaryBuilder;
use super::transaction_phase::TransactionPhase;
use crate::RedactionPolicy;

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
}
