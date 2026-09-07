// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Non-rendering runtime with an obligatory sensitivity accumulator.

use std::sync::Arc;

use super::inspection_accumulator::InspectionAccumulator;
use super::runtime_core::RuntimeCore;
use super::runtime_session::RuntimeSession;
use crate::RedactionPolicy;
use crate::RedactionSummary;
use crate::Sensitivity;

/// Owns shared accounting and sensitivity observations for inspection.
pub(super) struct InspectionRuntime {
    /// Policy, budget, summary, and structural state shared with renderers.
    pub(super) core: RuntimeCore,
    /// Highest sensitivity observed during this inspection.
    accumulator: InspectionAccumulator,
}

impl RuntimeSession for InspectionRuntime {
    /// Borrows the publication-independent inspection core.
    ///
    /// # Returns
    ///
    /// The accounting core borrowed without changing transaction state.
    #[inline(always)]
    fn runtime(&self) -> &RuntimeCore {
        &self.core
    }

    /// Mutably borrows the publication-independent inspection core.
    ///
    /// # Returns
    ///
    /// An exclusive borrow of the transaction accounting core.
    #[inline(always)]
    fn runtime_mut(&mut self) -> &mut RuntimeCore {
        &mut self.core
    }

    /// Identifies this runtime as non-rendering inspection state.
    ///
    /// # Returns
    ///
    /// Whether this implementation observes sensitivity without rendering
    /// output.
    #[inline(always)]
    fn is_inspection(&self) -> bool {
        true
    }

    /// Accumulates the strongest sensitivity observed so far.
    ///
    /// # Parameters
    ///
    /// - `sensitivity`: New classification combined with the inspection
    ///   maximum.
    #[inline(always)]
    fn observe_sensitivity(&mut self, sensitivity: Sensitivity) {
        self.accumulator.observe(sensitivity);
    }
}

impl InspectionRuntime {
    /// Creates inspection state governed by one immutable policy snapshot.
    ///
    /// # Parameters
    ///
    /// - `policy`: Immutable snapshot shared by the new transaction.
    ///
    /// # Returns
    ///
    /// Fresh mode-specific state with empty resource accounting.
    #[must_use]
    #[inline(always)]
    pub(super) fn new(policy: Arc<RedactionPolicy>) -> Self {
        Self {
            core: RuntimeCore::new(policy),
            accumulator: InspectionAccumulator::default(),
        }
    }

    /// Records one sensitivity in the active inspection.
    ///
    /// # Parameters
    ///
    /// - `sensitivity`: New classification combined with the inspection
    ///   maximum.
    #[inline(always)]
    pub(super) fn observe_sensitivity(&mut self, sensitivity: Sensitivity) {
        self.accumulator.observe(sensitivity);
    }

    /// Consumes the runtime into its highest sensitivity and final summary.
    ///
    /// # Returns
    ///
    /// The strongest sensitivity and final summary. `Some(level)` means a
    /// sensitive value was observed; `None` means none was observed. The
    /// summary must still be checked before treating that absence as
    /// conclusive.
    #[must_use]
    #[inline]
    pub(super) fn into_parts(self) -> (Option<Sensitivity>, RedactionSummary) {
        let sensitivity = self.accumulator.max_sensitivity();
        let summary = self.core.into_summary();
        (sensitivity, summary)
    }
}
