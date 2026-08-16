// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Read-only views of configured allow rules.

use super::FieldNameMatching;

/// A borrowed canonical field name and the breadth of its allow rule.
///
/// # Type Parameters
///
/// * `'a` - Lifetime of the borrowed canonical field name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllowRule<'a> {
    /// Canonical field name.
    field: &'a str,
    /// Whether the rule applies exactly or at token suffix boundaries.
    matching: FieldNameMatching,
}

impl<'a> AllowRule<'a> {
    /// Creates a borrowed allow-rule view.
    ///
    /// # Parameters
    ///
    /// * `field` - Canonical field name.
    /// * `matching` - Breadth of the allow rule.
    ///
    /// # Returns
    ///
    /// A read-only view over the supplied rule.
    #[must_use]
    pub(super) const fn new(
        field: &'a str,
        matching: FieldNameMatching,
    ) -> Self {
        Self { field, matching }
    }

    /// Returns the canonical field name.
    ///
    /// # Returns
    ///
    /// The canonical field name borrowed from the policy.
    #[must_use]
    #[inline(always)]
    pub const fn field(&self) -> &'a str {
        self.field
    }

    #[must_use]
    #[inline(always)]
    /// Returns the breadth of the allow rule.
    ///
    /// # Returns
    ///
    /// [`FieldNameMatching::Exact`] for an exact-only allow rule or
    /// [`FieldNameMatching::ExactOrTokenSuffix`] for a suffix allow rule.
    pub const fn matching(&self) -> FieldNameMatching {
        self.matching
    }
}
