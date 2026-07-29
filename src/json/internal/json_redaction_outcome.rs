// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Observable result of mutable JSON traversal.

/// Records whether a JSON traversal retained any unkeyed scalar value.
#[must_use]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct JsonRedactionOutcome {
    /// Whether at least one unkeyed scalar remained visible.
    passed_unkeyed: bool,
}

impl JsonRedactionOutcome {
    /// Returns an outcome for one retained unkeyed scalar.
    ///
    /// # Returns
    ///
    /// An outcome reporting that a scalar passed through.
    #[inline(always)]
    pub(crate) const fn passed_unkeyed() -> Self {
        Self {
            passed_unkeyed: true,
        }
    }

    /// Reports whether any traversed unkeyed scalar remained visible.
    ///
    /// # Returns
    ///
    /// True when at least one unkeyed scalar passed through.
    #[cfg_attr(not(feature = "http"), allow(dead_code))]
    #[inline(always)]
    pub(crate) const fn has_passed_unkeyed(self) -> bool {
        self.passed_unkeyed
    }

    /// Combines this outcome with a nested traversal result.
    ///
    /// # Parameters
    ///
    /// * other - Nested traversal result.
    #[inline(always)]
    pub(crate) fn merge(&mut self, other: Self) {
        self.passed_unkeyed |= other.passed_unkeyed;
    }
}
