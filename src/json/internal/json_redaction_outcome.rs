// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Observable result of mutable JSON traversal.

/// Reports whether a JSON traversal completed or exhausted its mask budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JsonRedactionOutcome {
    /// Traversal completed, optionally passing through an unkeyed scalar.
    Complete {
        /// Whether at least one unkeyed scalar remained visible.
        passed_unkeyed: bool,
    },
    /// Traversal stopped because no complete unkeyed marker fit the budget.
    MaskBudgetExhausted,
}

impl JsonRedactionOutcome {
    /// Reports whether no complete unkeyed marker remained affordable.
    ///
    /// # Returns
    ///
    /// `true` when traversal stopped before completing all mutations.
    #[inline(always)]
    pub(crate) const fn is_mask_budget_exhausted(self) -> bool {
        matches!(self, Self::MaskBudgetExhausted)
    }
}
