// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compact sets of redaction degradation reasons.

use super::RedactionReason;

/// Compact set of summary reasons.
///
/// # Examples
///
/// ```
/// use qubit_redact::RedactionReason;
/// use qubit_redact::RedactionReasons;
///
/// let reasons = RedactionReasons::empty().with(RedactionReason::InputLimitReached);
/// assert!(reasons.contains(RedactionReason::InputLimitReached));
/// assert!(!reasons.contains(RedactionReason::OutputLimitReached));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RedactionReasons(
    /// Stable bit flags for the reasons accumulated by one operation.
    u64,
);

impl RedactionReasons {
    /// Creates an empty reason set.
    ///
    /// # Returns
    ///
    /// A set containing no degradation reasons.
    #[must_use]
    #[inline(always)]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Returns whether a reason is present.
    ///
    /// # Parameters
    ///
    /// - `reason`: Degradation reason whose membership is queried.
    ///
    /// # Returns
    ///
    /// True exactly when this set contains the requested reason.
    #[must_use]
    #[inline(always)]
    pub const fn contains(self, reason: RedactionReason) -> bool {
        self.0 & reason.bit() != 0
    }

    /// Adds one reason.
    ///
    /// # Parameters
    ///
    /// - `reason`: Degradation reason to insert.
    ///
    /// # Returns
    ///
    /// A copy of this set containing the supplied reason.
    #[must_use]
    #[inline(always)]
    pub const fn with(self, reason: RedactionReason) -> Self {
        Self(self.0 | reason.bit())
    }

    /// Combines two reason sets.
    ///
    /// # Parameters
    ///
    /// - `other`: Additional degradation reasons to combine.
    ///
    /// # Returns
    ///
    /// A set containing every reason present in either operand.
    #[must_use]
    #[inline(always)]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}
