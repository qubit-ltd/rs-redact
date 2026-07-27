// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared input accounting for bounded diagnostic redaction.

/// Tracks source bytes consumed across one diagnostic rendering.
///
/// Once a reservation does not fit, the budget becomes permanently exhausted
/// so later diagnostic segments cannot inspect additional source bytes.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticInputBudget {
    /// Source bytes still available for inspection.
    remaining_input_bytes: usize,
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
            remaining_input_bytes: max_input_bytes,
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
    pub fn reserve(&mut self, input_bytes: usize) -> bool {
        if self.exhausted || input_bytes > self.remaining_input_bytes {
            self.remaining_input_bytes = 0;
            self.exhausted = true;
            return false;
        }
        self.remaining_input_bytes -= input_bytes;
        self.exhausted = self.remaining_input_bytes == 0;
        true
    }

    /// Returns source bytes still available before the next reservation.
    ///
    /// # Returns
    ///
    /// The remaining source-byte allowance, or zero after exhaustion.
    #[must_use]
    #[inline(always)]
    pub const fn remaining_input_bytes(&self) -> usize {
        self.remaining_input_bytes
    }
}
