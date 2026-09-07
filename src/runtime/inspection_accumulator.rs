// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Runtime-private aggregation of sensitivity without retaining source data.

use crate::Sensitivity;

/// Strongest sensitivity observed by one inspection transaction.
#[derive(Clone, Copy, Default)]
pub(super) struct InspectionAccumulator {
    /// Maximum level observed so far, or `None` before any sensitive value.
    max_sensitivity: Option<Sensitivity>,
}

impl InspectionAccumulator {
    /// Returns the strongest level observed by the complete traversal.
    ///
    /// # Returns
    ///
    /// `Some(level)` is the strongest observed level; `None` means no
    /// sensitive value has been observed.
    #[must_use]
    #[inline(always)]
    pub(super) const fn max_sensitivity(self) -> Option<Sensitivity> {
        self.max_sensitivity
    }

    /// Records one policy-resolved sensitivity level.
    ///
    /// # Parameters
    ///
    /// - `sensitivity`: Newly observed level to combine with the current
    ///   maximum.
    #[inline]
    pub(super) fn observe(&mut self, sensitivity: Sensitivity) {
        self.max_sensitivity = Some(
            self.max_sensitivity
                .map_or(sensitivity, |current| current.max(sensitivity)),
        );
    }
}
