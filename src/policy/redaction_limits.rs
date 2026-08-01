// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Immutable execution limits used while rendering diagnostics.

#[cfg(feature = "json")]
use super::JsonDepthBudget;

use super::DiagnosticBudget;

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RedactionLimits {
    /// Maximum source bytes and final output bytes for one diagnostic.
    diagnostic_budget: DiagnosticBudget,
    /// Maximum JSON recursion depth for structured redaction.
    #[cfg(feature = "json")]
    json_depth_budget: JsonDepthBudget,
}

impl RedactionLimits {
    /// Constructs limits from a validated diagnostic and optional JSON depth
    /// limit.
    #[inline]
    pub(crate) const fn new(
        diagnostic_budget: DiagnosticBudget,
        #[cfg(feature = "json")] json_depth_budget: JsonDepthBudget,
    ) -> Self {
        Self {
            diagnostic_budget,
            #[cfg(feature = "json")]
            json_depth_budget,
        }
    }

    /// Returns the hard diagnostic input and output limits.
    #[inline(always)]
    pub(crate) const fn diagnostic_budget(&self) -> DiagnosticBudget {
        self.diagnostic_budget
    }

    /// Returns the hard recursion-depth limit for structured JSON redaction.
    #[cfg(feature = "json")]
    #[inline(always)]
    pub(crate) const fn json_depth_budget(&self) -> JsonDepthBudget {
        self.json_depth_budget
    }
}
