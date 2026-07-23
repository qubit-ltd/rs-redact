// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Four-level immutable masking configuration.

use std::borrow::Cow;

use super::{
    MaskPolicy,
    Sensitivity,
};

/// Mask policies assigned to all supported sensitivity levels.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskingPolicy {
    /// Policy for low-sensitivity values.
    low: MaskPolicy,
    /// Policy for medium-sensitivity values.
    medium: MaskPolicy,
    /// Policy for high-sensitivity values.
    high: MaskPolicy,
    /// Policy for secret values.
    secret: MaskPolicy,
}

impl MaskingPolicy {
    /// Creates a four-level masking configuration from the supplied policies.
    ///
    /// # Parameters
    ///
    /// * `low` - Policy for low-sensitivity values.
    /// * `medium` - Policy for medium-sensitivity values.
    /// * `high` - Policy for high-sensitivity values.
    /// * `secret` - Policy for secret values.
    ///
    /// # Returns
    ///
    /// A masking configuration containing the supplied policies.
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

    /// Returns a copy with the policy for `level` replaced by `policy`.
    ///
    /// # Parameters
    ///
    /// * `level` - Sensitivity level to update.
    /// * `policy` - Replacement mask policy.
    ///
    /// # Returns
    ///
    /// The updated immutable masking configuration.
    #[inline]
    pub fn with_policy(
        mut self,
        level: Sensitivity,
        policy: MaskPolicy,
    ) -> Self {
        match level {
            Sensitivity::Low => self.low = policy,
            Sensitivity::Medium => self.medium = policy,
            Sensitivity::High => self.high = policy,
            Sensitivity::Secret => self.secret = policy,
        }
        self
    }

    /// Masks `value` with the policy configured for `level`.
    ///
    /// Empty values remain empty; otherwise the selected policy determines
    /// whether the result borrows or owns its contents.
    ///
    /// # Parameters
    ///
    /// * `level` - Sensitivity level selecting the mask policy.
    /// * `value` - Value to mask.
    ///
    /// # Returns
    ///
    /// The borrowed empty input or an owned masked value.
    #[must_use = "use the returned masked value instead of the original value"]
    #[inline(always)]
    pub fn mask<'a>(&self, level: Sensitivity, value: &'a str) -> Cow<'a, str> {
        self.for_level(level).mask(value)
    }

    /// Masks a value without allocating beyond a byte limit.
    ///
    /// # Parameters
    ///
    /// * `level` - Sensitivity level selecting the mask policy.
    /// * `value` - Value to mask.
    /// * `max_bytes` - Maximum bytes allocated for the masked result.
    ///
    /// # Returns
    ///
    /// The borrowed empty input or an owned mask bounded by `max_bytes`.
    #[cfg(feature = "http")]
    #[must_use = "use the returned bounded mask instead of the original value"]
    #[inline(always)]
    pub(crate) fn mask_bounded<'a>(
        &self,
        level: Sensitivity,
        value: &'a str,
        max_bytes: usize,
    ) -> Cow<'a, str> {
        self.for_level(level).mask_bounded(value, max_bytes)
    }

    /// Returns the mask policy configured for `level`.
    ///
    /// # Parameters
    ///
    /// * `level` - Sensitivity level to resolve.
    ///
    /// # Returns
    ///
    /// The mask policy assigned to `level`.
    #[must_use = "use the mask policy selected for this sensitivity level"]
    #[inline(always)]
    pub const fn for_level(&self, level: Sensitivity) -> &MaskPolicy {
        match level {
            Sensitivity::Low => &self.low,
            Sensitivity::Medium => &self.medium,
            Sensitivity::High => &self.high,
            Sensitivity::Secret => &self.secret,
        }
    }
}

impl Default for MaskingPolicy {
    /// Creates the built-in conservative four-level masking configuration.
    ///
    /// # Returns
    ///
    /// The built-in masking configuration.
    fn default() -> Self {
        Self::new(
            MaskPolicy::preserve_edges(2, 2, "****", 4),
            MaskPolicy::preserve_suffix(1, "*******", 1),
            MaskPolicy::fixed("****"),
            MaskPolicy::fixed("<redacted>"),
        )
    }
}
