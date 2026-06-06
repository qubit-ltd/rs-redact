// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use super::{
    MaskPolicy,
    SensitivityLevel,
};

/// Mask policies assigned to all supported sensitivity levels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskPolicies {
    /// Policy for [`SensitivityLevel::Low`].
    pub low: MaskPolicy,
    /// Policy for [`SensitivityLevel::Medium`].
    pub medium: MaskPolicy,
    /// Policy for [`SensitivityLevel::High`].
    pub high: MaskPolicy,
    /// Policy for [`SensitivityLevel::Secret`].
    pub secret: MaskPolicy,
}

impl MaskPolicies {
    /// Returns the policy for one sensitivity level.
    ///
    /// # Parameters
    ///
    /// * `level` - Sensitivity level to resolve.
    ///
    /// # Returns
    ///
    /// Borrowed mask policy configured for `level`.
    pub const fn for_level(&self, level: SensitivityLevel) -> &MaskPolicy {
        match level {
            SensitivityLevel::Low => &self.low,
            SensitivityLevel::Medium => &self.medium,
            SensitivityLevel::High => &self.high,
            SensitivityLevel::Secret => &self.secret,
        }
    }
}

impl Default for MaskPolicies {
    /// Creates conservative default mask policies.
    fn default() -> Self {
        Self {
            low: MaskPolicy::preserve_edges(2, 2, "****", 4),
            medium: MaskPolicy::preserve_suffix(1, "****", 1),
            high: MaskPolicy::fixed("****"),
            secret: MaskPolicy::fixed("<redacted>"),
        }
    }
}
