// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Unpublished mutable state owned by one redaction transaction.

use super::redaction_budget::RedactionBudget;
use crate::RedactionOutput;
use crate::RedactionPolicy;
use crate::RedactionSummary;

/// All mutable accounting and unpublished output for one transaction.
pub struct TransactionState {
    pub(super) id: u64,
    pub(super) budget: RedactionBudget,
    pub(super) fragments: String,
    pub(super) items: Vec<RedactionOutput>,
    pub(super) output_exhausted: bool,
    pub(super) summary: RedactionSummary,
    /// Summary accumulated only for the currently staged handle operation.
    pub(super) item_summary: Option<RedactionSummary>,
}

impl TransactionState {
    /// Creates an empty transaction governed by `policy`.
    #[must_use]
    pub(super) fn new(policy: &RedactionPolicy, id: u64) -> Self {
        Self {
            id,
            budget: RedactionBudget::new(policy.limits()),
            fragments: String::new(),
            items: Vec::new(),
            output_exhausted: false,
            summary: RedactionSummary::complete(),
            item_summary: None,
        }
    }
}
