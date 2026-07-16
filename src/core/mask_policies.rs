// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use super::{MaskPolicy, SensitivityLevel};

/// Mask policies assigned to all supported sensitivity levels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskPolicies {
    /// Policy for [`SensitivityLevel::Low`].
    low: MaskPolicy,
    /// Policy for [`SensitivityLevel::Medium`].
    medium: MaskPolicy,
    /// Policy for [`SensitivityLevel::High`].
    high: MaskPolicy,
    /// Policy for [`SensitivityLevel::Secret`].
    secret: MaskPolicy,
}

impl MaskPolicies {
    /// Creates policies for all supported sensitivity levels.
    ///
    /// # Parameters
    ///
    /// * `low` - Policy for [`SensitivityLevel::Low`].
    /// * `medium` - Policy for [`SensitivityLevel::Medium`].
    /// * `high` - Policy for [`SensitivityLevel::High`].
    /// * `secret` - Policy for [`SensitivityLevel::Secret`].
    ///
    /// # Returns
    ///
    /// A policy collection containing the supplied level policies.
    #[inline(always)]
    pub const fn new(
        low: MaskPolicy,
        medium: MaskPolicy,
        high: MaskPolicy,
        secret: MaskPolicy,
    ) -> Self {
        Self {
            low,
            medium,
            high,
            secret,
        }
    }

    /// Returns a copy with the policy for one sensitivity level replaced.
    ///
    /// # Parameters
    ///
    /// * `level` - Sensitivity level to update.
    /// * `policy` - Replacement mask policy.
    ///
    /// # Returns
    ///
    /// The updated policy collection.
    #[inline(always)]
    pub fn with_policy(mut self, level: SensitivityLevel, policy: MaskPolicy) -> Self {
        self.set(level, policy);
        self
    }

    /// Returns the policy for one sensitivity level.
    ///
    /// # Parameters
    ///
    /// * `level` - Sensitivity level to resolve.
    ///
    /// # Returns
    ///
    /// Borrowed mask policy configured for `level`.
    #[inline(always)]
    pub const fn for_level(&self, level: SensitivityLevel) -> &MaskPolicy {
        match level {
            SensitivityLevel::Low => &self.low,
            SensitivityLevel::Medium => &self.medium,
            SensitivityLevel::High => &self.high,
            SensitivityLevel::Secret => &self.secret,
        }
    }

    /// Returns the policy for one sensitivity level mutably.
    ///
    /// # Parameters
    ///
    /// * `level` - Sensitivity level to resolve.
    ///
    /// # Returns
    ///
    /// Mutable mask policy configured for `level`.
    #[inline(always)]
    pub fn for_level_mut(&mut self, level: SensitivityLevel) -> &mut MaskPolicy {
        match level {
            SensitivityLevel::Low => &mut self.low,
            SensitivityLevel::Medium => &mut self.medium,
            SensitivityLevel::High => &mut self.high,
            SensitivityLevel::Secret => &mut self.secret,
        }
    }

    /// Replaces the policy for one sensitivity level.
    ///
    /// # Parameters
    ///
    /// * `level` - Sensitivity level to update.
    /// * `policy` - Replacement mask policy.
    #[inline(always)]
    pub fn set(&mut self, level: SensitivityLevel, policy: MaskPolicy) {
        *self.for_level_mut(level) = policy;
    }
}

impl Default for MaskPolicies {
    /// Creates conservative default mask policies.
    fn default() -> Self {
        Self::new(
            MaskPolicy::preserve_edges(2, 2, "****", 4),
            MaskPolicy::preserve_suffix(1, "****", 1),
            MaskPolicy::fixed("****"),
            MaskPolicy::fixed("<redacted>"),
        )
    }
}
