// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Read-only views of configured sensitive-field rules.

use super::Sensitivity;

/// A borrowed canonical field name and its configured sensitivity.
///
/// # Type Parameters
///
/// * `'a` - Lifetime of the borrowed canonical field name.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SensitiveFieldRule<'a> {
    /// Canonical field name.
    field: &'a str,
    /// Configured sensitivity level.
    sensitivity: Sensitivity,
}

impl<'a> SensitiveFieldRule<'a> {
    /// Creates a borrowed sensitive-field rule view.
    ///
    /// # Parameters
    ///
    /// * `field` - Canonical field name.
    /// * `sensitivity` - Configured sensitivity level.
    ///
    /// # Returns
    ///
    /// A read-only view over the supplied rule.
    #[inline]
    pub(super) const fn new(field: &'a str, sensitivity: Sensitivity) -> Self {
        Self { field, sensitivity }
    }

    /// Returns the canonical field name.
    ///
    /// # Returns
    ///
    /// The canonical field name borrowed from the policy.
    #[must_use]
    #[inline]
    pub const fn field(&self) -> &'a str {
        self.field
    }

    /// Returns the configured sensitivity level.
    ///
    /// # Returns
    ///
    /// The sensitivity assigned to the field.
    #[inline]
    pub const fn sensitivity(&self) -> Sensitivity {
        self.sensitivity
    }
}
