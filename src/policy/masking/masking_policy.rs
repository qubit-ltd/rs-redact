// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Four-level immutable masking configuration.
// qubit-style: allow multiple-public-types

use std::borrow::Cow;

use super::MaskPolicy;
use crate::policy::PolicyError;
use crate::policy::PolicyLocation;
use crate::policy::Sensitivity;

/// Mutable construction state for a [`MaskingPolicy`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskingPolicyBuilder {
    low: MaskPolicy,
    medium: MaskPolicy,
    high: MaskPolicy,
    secret: MaskPolicy,
}

/// Mask policies assigned to all supported sensitivity levels.
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
    /// Creates a builder initialized with the standard masking policies.
    #[must_use]
    #[inline]
    pub fn builder() -> MaskingPolicyBuilder {
        MaskingPolicyBuilder::default()
    }

    /// Creates a builder by copying an existing masking configuration.
    #[must_use]
    #[inline]
    pub(crate) fn builder_from(base: &Self) -> MaskingPolicyBuilder {
        MaskingPolicyBuilder {
            low: base.low.clone(),
            medium: base.medium.clone(),
            high: base.high.clone(),
            secret: base.secret.clone(),
        }
    }

    /// Masks `value` with the policy configured for `level`.
    ///
    /// Empty values remain empty; otherwise the selected policy determines
    /// whether the result borrows or owns its contents.
    ///
    /// # Type Parameters
    ///
    /// * `'a` - Lifetime of the input and any borrowed result.
    ///
    /// # Parameters
    ///
    /// * `level` - Sensitivity level selecting the mask policy.
    /// * `value` - Value to mask.
    ///
    /// # Returns
    ///
    /// The borrowed empty input or an owned masked value.
    #[must_use]
    #[inline(always)]
    pub fn mask<'a>(&self, level: Sensitivity, value: &'a str) -> Cow<'a, str> {
        self.for_level(level).mask(value)
    }

    /// Returns the configured complete replacement for an opaque value.
    ///
    /// This never reads the original value. Edge-preserving policies return
    /// only their replacement text because no prefix or suffix is safe to
    /// retain when the value is opaque.
    ///
    /// # Parameters
    ///
    /// * `level` - Sensitivity level selecting the mask policy.
    ///
    /// # Returns
    ///
    /// The complete replacement configured for `level`.
    #[must_use]
    #[inline(always)]
    pub fn mask_opaque(&self, level: Sensitivity) -> &str {
        self.for_level(level).opaque_mask()
    }

    /// Masks a value without allocating beyond a byte limit.
    ///
    /// # Type Parameters
    ///
    /// * `'a` - Lifetime of the input and any borrowed result.
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
    #[must_use]
    #[inline(always)]
    #[cfg(any(feature = "json", feature = "http"))]
    #[cfg(feature = "http")]
    pub(crate) fn mask_bounded<'a>(&self, level: Sensitivity, value: &'a str, max_bytes: usize) -> Cow<'a, str> {
        self.for_level(level).mask_bounded(value, max_bytes)
    }

    /// Masks a value and reports byte-limit truncation.
    #[inline(always)]
    pub(crate) fn mask_bounded_with_truncation<'a>(
        &self,
        level: Sensitivity,
        value: &'a str,
        max_bytes: usize,
    ) -> (Cow<'a, str>, bool) {
        self.for_level(level).mask_bounded_with_truncation(value, max_bytes)
    }

    /// Returns an opaque replacement constrained to `max_bytes`.
    ///
    /// # Parameters
    ///
    /// * `level` - Sensitivity level selecting the mask policy.
    /// * `max_bytes` - Maximum bytes retained from the replacement.
    ///
    /// # Returns
    ///
    /// An owned bounded prefix of the configured opaque replacement.
    #[must_use]
    #[inline(always)]
    pub(crate) fn mask_opaque_bounded(&self, level: Sensitivity, max_bytes: usize) -> String {
        self.for_level(level).opaque_mask_bounded(max_bytes)
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
    #[must_use]
    #[inline(always)]
    pub const fn for_level(&self, level: Sensitivity) -> &MaskPolicy {
        match level {
            Sensitivity::Low => &self.low,
            Sensitivity::Medium => &self.medium,
            Sensitivity::High => &self.high,
            Sensitivity::Secret => &self.secret,
        }
    }

    /// Validates fixed replacements for one policy construction location.
    pub(crate) fn validate(&self, location: PolicyLocation) -> Result<(), PolicyError> {
        for level in [
            Sensitivity::Low,
            Sensitivity::Medium,
            Sensitivity::High,
            Sensitivity::Secret,
        ] {
            if matches!(
                self.for_level(level),
                MaskPolicy::Fixed { replacement } if replacement.is_empty()
            ) {
                return Err(PolicyError::EmptyFixedReplacement { location, level });
            }
        }
        Ok(())
    }
}

impl MaskingPolicyBuilder {
    /// Sets the policy for low-sensitivity values.
    #[inline]
    pub fn low(&mut self, policy: MaskPolicy) -> &mut Self {
        self.low = policy;
        self
    }

    /// Sets the policy for medium-sensitivity values.
    #[inline]
    pub fn medium(&mut self, policy: MaskPolicy) -> &mut Self {
        self.medium = policy;
        self
    }

    /// Sets the policy for high-sensitivity values.
    #[inline]
    pub fn high(&mut self, policy: MaskPolicy) -> &mut Self {
        self.high = policy;
        self
    }

    /// Sets the policy for secret values.
    #[inline]
    pub fn secret(&mut self, policy: MaskPolicy) -> &mut Self {
        self.secret = policy;
        self
    }

    /// Replaces one sensitivity policy while rebuilding an existing policy.
    #[inline]
    pub(crate) fn policy(&mut self, level: Sensitivity, policy: MaskPolicy) {
        match level {
            Sensitivity::Low => self.low(policy),
            Sensitivity::Medium => self.medium(policy),
            Sensitivity::High => self.high(policy),
            Sensitivity::Secret => self.secret(policy),
        };
    }

    /// Builds the immutable masking configuration.
    #[must_use]
    #[inline]
    pub fn build(self) -> MaskingPolicy {
        MaskingPolicy {
            low: self.low,
            medium: self.medium,
            high: self.high,
            secret: self.secret,
        }
    }
}

impl Default for MaskingPolicyBuilder {
    /// Creates a builder with the standard masking policies.
    fn default() -> Self {
        Self {
            low: MaskPolicy::preserve_edges(2, 2, "****", 4),
            medium: MaskPolicy::preserve_suffix(1, "*******", 1),
            high: MaskPolicy::fixed("****"),
            secret: MaskPolicy::fixed("<redacted>"),
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
        Self::builder().build()
    }
}

#[cfg(test)]
mod tests {
    use super::MaskingPolicy;
    use crate::MaskPolicy;
    use crate::Sensitivity;

    #[test]
    fn builder_low_and_medium_replace_their_respective_policies() {
        let mut builder = MaskingPolicy::builder();
        builder.low(MaskPolicy::fixed("low"));
        builder.medium(MaskPolicy::fixed("medium"));
        let policy = builder.build();

        assert_eq!(policy.for_level(Sensitivity::Low).mask("value"), "low");
        assert_eq!(policy.for_level(Sensitivity::Medium).mask("value"), "medium");
    }
}
