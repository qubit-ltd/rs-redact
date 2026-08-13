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
    mask_exhausted: bool,
}

impl JsonRedactionOutcome {
    /// Records that an unkeyed scalar remained visible during traversal.
    #[inline(always)]
    pub(crate) fn record_passed_unkeyed(&mut self) {
        self.passed_unkeyed = true;
    }

    /// Records that traversal could not afford another unkeyed marker.
    #[inline(always)]
    pub(crate) fn record_mask_exhausted(&mut self) {
        self.mask_exhausted = true;
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

    /// Reports whether no unkeyed marker remained affordable.
    #[inline(always)]
    pub(crate) const fn is_mask_exhausted(self) -> bool {
        self.mask_exhausted
    }
}
