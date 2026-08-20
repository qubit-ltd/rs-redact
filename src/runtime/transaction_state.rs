// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Unpublished mutable state owned by one redaction transaction.

use super::item_range::ItemRange;
use super::output_buffer::OutputBuffer;
use super::redaction_budget::RedactionBudget;
use super::summary_builder::SummaryBuilder;
use super::transaction_phase::TransactionPhase;
use crate::RedactionPolicy;

/// All mutable accounting and unpublished output for one transaction.
pub struct TransactionState {
    pub(super) id: u64,
    pub(super) budget: RedactionBudget,
    pub(super) output: OutputBuffer,
    pub(super) items: Vec<ItemRange>,
    /// Canonical empty item returned by all handles requested after exhaustion.
    pub(super) exhausted_handle_item: Option<usize>,
    pub(super) phase: TransactionPhase,
    pub(super) summary: SummaryBuilder,
    /// Summary accumulated only for the currently staged handle operation.
    pub(super) item_summary: Option<SummaryBuilder>,
}

impl TransactionState {
    /// Creates an empty transaction governed by `policy`.
    #[must_use]
    pub(super) fn new(policy: &RedactionPolicy, id: u64) -> Self {
        Self {
            id,
            budget: RedactionBudget::new(policy.limits()),
            output: OutputBuffer::new(),
            items: Vec::new(),
            exhausted_handle_item: None,
            phase: TransactionPhase::Active,
            summary: SummaryBuilder::new(),
            item_summary: None,
        }
    }
}
