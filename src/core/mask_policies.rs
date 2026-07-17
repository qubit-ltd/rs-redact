// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use std::sync::{
    Arc,
    LazyLock,
};

use super::{
    MaskPolicy,
    SensitivityLevel,
};

/// Mask policies assigned to all supported sensitivity levels.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskPolicies {
    /// Shared policies ordered by [`SensitivityLevel`].
    policies: Arc<[MaskPolicy; 4]>,
}

/// Shared default policy collection cloned by [`MaskPolicies::default`].
static DEFAULT_MASK_POLICIES: LazyLock<MaskPolicies> =
    LazyLock::new(MaskPolicies::new_default);

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
    pub fn new(
        low: MaskPolicy,
        medium: MaskPolicy,
        high: MaskPolicy,
        secret: MaskPolicy,
    ) -> Self {
        Self {
            policies: Arc::new([low, medium, high, secret]),
        }
    }

    /// Creates the conservative default policy collection.
    ///
    /// # Returns
    ///
    /// Default mask policies for all sensitivity levels.
    #[inline]
    fn new_default() -> Self {
        Self::new(
            MaskPolicy::preserve_edges(2, 2, "****", 4),
            MaskPolicy::preserve_suffix(1, "****", 1),
            MaskPolicy::fixed("****"),
            MaskPolicy::fixed("<redacted>"),
        )
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
    pub fn with_policy(
        mut self,
        level: SensitivityLevel,
        policy: MaskPolicy,
    ) -> Self {
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
    pub fn for_level(&self, level: SensitivityLevel) -> &MaskPolicy {
        &self.policies[level_index(level)]
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
    pub fn for_level_mut(
        &mut self,
        level: SensitivityLevel,
    ) -> &mut MaskPolicy {
        &mut Arc::make_mut(&mut self.policies)[level_index(level)]
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
    #[inline(always)]
    fn default() -> Self {
        DEFAULT_MASK_POLICIES.clone()
    }
}

/// Returns the stable array index for a sensitivity level.
///
/// # Parameters
///
/// * `level` - Sensitivity level to index.
///
/// # Returns
///
/// Index into the low, medium, high, and secret policy array.
#[must_use]
#[inline]
const fn level_index(level: SensitivityLevel) -> usize {
    match level {
        SensitivityLevel::Low => 0,
        SensitivityLevel::Medium => 1,
        SensitivityLevel::High => 2,
        SensitivityLevel::Secret => 3,
    }
}
