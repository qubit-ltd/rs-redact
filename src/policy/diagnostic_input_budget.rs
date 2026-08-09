// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared input accounting for bounded diagnostic redaction.

use qubit_budget::ResourceBudget;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiagnosticInputResource {
    InputBytes,
}

/// Tracks source bytes consumed across one diagnostic rendering.
///
/// Once a reservation does not fit, the budget becomes permanently exhausted
/// so later diagnostic segments cannot inspect additional source bytes.
#[must_use]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DiagnosticInputBudget {
    /// Source-byte budget delegated to the shared accounting primitive.
    budget: ResourceBudget<DiagnosticInputResource>,
    /// Whether a reservation has exhausted or exceeded the budget.
    exhausted: bool,
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
            budget: ResourceBudget::new(
                DiagnosticInputResource::InputBytes,
                max_input_bytes,
            ),
            exhausted: false,
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
    /// the segment must be skipped; this permanently exhausts the budget.
    #[inline]
    pub(crate) fn reserve(&mut self, input_bytes: usize) -> bool {
        if self.exhausted {
            self.budget.exhaust();
            return false;
        }
        if self.budget.consume_or_exhaust(input_bytes).is_err() {
            self.exhausted = true;
            return false;
        }
        self.exhausted = self.budget.is_empty();
        true
    }

    /// Returns source bytes still available before the next reservation.
    ///
    /// # Returns
    ///
    /// The remaining source-byte allowance, or zero after exhaustion.
    #[must_use]
    #[inline(always)]
    pub(crate) const fn remaining_input_bytes(&self) -> usize {
        self.budget.remaining()
    }
}
