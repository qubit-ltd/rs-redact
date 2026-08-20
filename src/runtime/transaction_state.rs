// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Unpublished mutable state owned by one redaction transaction.

use super::redaction_budget::RedactionBudget;
use super::summary_builder::SummaryBuilder;
use crate::RedactionOutput;
use crate::RedactionPolicy;

/// All mutable accounting and unpublished output for one transaction.
pub struct TransactionState {
    pub(super) id: u64,
    pub(super) budget: RedactionBudget,
    pub(super) fragments: String,
    /// Bounded unpublished output for the domain writer currently using this
    /// transaction. Keeping this frame here prevents writers from owning a
    /// second mutable output model.
    pub(super) domain_frame: String,
    /// Final log-safe byte count retained in `domain_frame`.
    pub(super) domain_frame_output_bytes: usize,
    /// Whether the active domain frame has stopped accepting later fields.
    pub(super) domain_frame_truncated: bool,
    /// Whether the active domain frame reached the shared output limit.
    pub(super) domain_frame_output_limit_reached: bool,
    pub(super) items: Vec<RedactionOutput>,
    /// Canonical empty item returned by all handles requested after exhaustion.
    pub(super) exhausted_handle_item: Option<usize>,
    pub(super) output_exhausted: bool,
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
            fragments: String::new(),
            domain_frame: String::new(),
            domain_frame_output_bytes: 0,
            domain_frame_truncated: false,
            domain_frame_output_limit_reached: false,
            items: Vec::new(),
            exhausted_handle_item: None,
            output_exhausted: false,
            summary: SummaryBuilder::new(),
            item_summary: None,
        }
    }
}
