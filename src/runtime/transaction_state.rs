// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Unpublished mutable state owned by one redaction transaction.

use super::redaction_budget::RedactionBudget;
use crate::RedactionOutput;
use crate::RedactionPolicy;
use crate::RedactionSummary;
use crate::domain::internal::DomainRedactionContext;

/// All mutable accounting and unpublished output for one transaction.
#[derive(Debug)]
pub struct TransactionState {
    pub(super) id: u64,
    pub(super) budget: RedactionBudget,
    pub(super) domain_context: DomainRedactionContext,
    pub(super) fragments: String,
    pub(super) items: Vec<RedactionOutput>,
    pub(super) output_exhausted: bool,
    pub(super) summary: RedactionSummary,
}

impl TransactionState {
    /// Creates an empty transaction governed by `policy`.
    #[must_use]
    pub(super) fn new(policy: &RedactionPolicy, id: u64) -> Self {
        Self {
            id,
            budget: RedactionBudget::new(policy.limits()),
            domain_context: DomainRedactionContext::new(policy.limits().domain()),
            fragments: String::new(),
            items: Vec::new(),
            output_exhausted: false,
            summary: RedactionSummary::complete(),
        }
    }
}
