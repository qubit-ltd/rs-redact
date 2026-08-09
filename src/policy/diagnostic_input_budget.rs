// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared input accounting for bounded diagnostic redaction.

use qubit_budget::BudgetState;
use qubit_budget::ResourceBudget;
use qubit_budget::ResourceLimit;

use super::RedactionResource;

/// Tracks source bytes consumed across one diagnostic rendering.
///
/// Once a reservation does not fit, the budget closes without changing its
/// exact accepted-byte count, so later diagnostic segments cannot inspect
/// additional source bytes.
#[must_use]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DiagnosticInputBudget {
    /// Source-byte budget delegated to the shared accounting primitive.
    budget: ResourceBudget<RedactionResource>,
}

impl DiagnosticInputBudget {
    /// Creates input accounting from a validated maximum source-byte limit.
    ///
    /// # Parameters
    ///
    /// * `max_input_bytes` - Maximum source bytes available to the diagnostic.
    ///
    /// # Returns
    ///
    /// A budget with all bytes available for reservation.
    #[inline(always)]
    pub(crate) const fn new(max_input_bytes: usize) -> Self {
        Self {
            budget: ResourceBudget::new(ResourceLimit::bounded(
                RedactionResource::Input,
                max_input_bytes,
            )),
        }
    }

    /// Reserves source bytes before inspecting a diagnostic segment.
    ///
    /// # Parameters
    ///
    /// * `input_bytes` - Source-byte length that will be inspected.
    ///
    /// # Returns
    ///
    /// `true` when the full segment fits and may be inspected. `false` when
    /// the segment must be skipped; this closes the budget without charging
    /// the rejected bytes.
    #[inline]
    pub(crate) fn reserve(&mut self, input_bytes: usize) -> bool {
        if self.budget.try_charge(input_bytes).is_err() {
            self.budget.close();
            return false;
        }
        true
    }

    /// Returns the exact source bytes accepted before any rejected reservation.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn charged_input_bytes(&self) -> usize {
        self.budget.charged()
    }

    /// Returns whether a rejected reservation has terminally closed this
    /// diagnostic source budget.
    #[must_use]
    #[inline(always)]
    pub(crate) fn is_closed(&self) -> bool {
        self.budget.state() == BudgetState::Closed
    }
}
