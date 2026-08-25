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
    #[inline(always)]
    fn runtime(&self) -> &RuntimeCore {
        &self.core
    }

    /// Mutably borrows the publication-independent inspection core.
    #[inline(always)]
    fn runtime_mut(&mut self) -> &mut RuntimeCore {
        &mut self.core
    }

    /// Identifies this runtime as non-rendering inspection state.
    #[inline(always)]
    fn is_inspection(&self) -> bool {
        true
    }

    /// Accumulates the strongest sensitivity observed so far.
    #[inline(always)]
    fn observe_sensitivity(&mut self, sensitivity: Sensitivity) {
        self.accumulator.observe(sensitivity);
    }
}

impl InspectionRuntime {
    /// Creates inspection state governed by one immutable policy snapshot.
    #[must_use]
    pub(super) fn new(policy: Arc<RedactionPolicy>) -> Self {
        Self {
            core: RuntimeCore::new(policy),
            accumulator: InspectionAccumulator::default(),
        }
    }

    /// Records one sensitivity in the active inspection.
    pub(super) fn observe_sensitivity(&mut self, sensitivity: Sensitivity) {
        self.accumulator.observe(sensitivity);
    }

    /// Consumes the runtime into its highest sensitivity and final summary.
    #[must_use]
    pub(super) fn into_parts(self) -> (Option<Sensitivity>, RedactionSummary) {
        let sensitivity = self.accumulator.max_sensitivity();
        let summary = self.core.into_summary();
        (sensitivity, summary)
    }
}
