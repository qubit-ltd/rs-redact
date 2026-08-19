// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Immutable limits owned by one active redaction transaction.

use crate::RedactionLimits;

/// The single output allowance for an active transaction.
#[derive(Debug)]
pub(super) struct RedactionBudget {
    output_limit: usize,
}

impl RedactionBudget {
    /// Creates the budget from the immutable policy limits.
    #[must_use]
    pub(super) const fn new(limits: &RedactionLimits) -> Self {
        Self {
            output_limit: limits.max_output_bytes(),
        }
    }

    /// Returns the transaction-wide output ceiling.
    #[must_use]
    pub(super) const fn output_limit(&self) -> usize {
        self.output_limit
    }
}
