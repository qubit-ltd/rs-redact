// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Four-level immutable masking configuration.

use std::borrow::Cow;

use super::MaskPolicy;
use super::MaskingPolicyBuilder;
use crate::policy::PolicyError;
use crate::policy::PolicyLocation;
use crate::policy::Sensitivity;

/// Mask policies assigned to all supported sensitivity levels.
///
/// # Examples
///
/// ```
/// use qubit_redact::MaskingPolicy;
/// use qubit_redact::Sensitivity;
///
/// let masking = MaskingPolicy::builder().build();
/// assert_eq!(masking.mask(Sensitivity::Secret, "raw"), "<redacted>");
/// ```
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
    ///
    /// # Returns
    ///
    /// A builder with the standard mask for each sensitivity level.
    #[must_use]
    #[inline(always)]
    pub fn builder() -> MaskingPolicyBuilder {
        MaskingPolicyBuilder::default()
    }

    /// Creates a builder by copying an existing masking configuration.
    ///
    /// # Parameters
    ///
    /// - `base`: Immutable mask table whose four choices are copied.
    ///
    /// # Returns
    ///
    /// An independent builder initialized from the supplied table.
    #[must_use]
    #[inline(always)]
    pub(crate) fn builder_from(base: &Self) -> MaskingPolicyBuilder {
        MaskingPolicyBuilder::from_policy(base)
    }

    /// Creates an immutable mask table from the completed builder fields.
    ///
    /// # Parameters
    ///
    /// - `low`: Mask for low sensitivity.
    /// - `medium`: Mask for medium sensitivity.
    /// - `high`: Mask for high sensitivity.
    /// - `secret`: Mask for secret sensitivity.
    ///
    /// # Returns
    ///
    /// The immutable table. Enclosing policy construction validates its masks.
    #[must_use]
    #[inline(always)]
    pub(super) fn from_parts(low: MaskPolicy, medium: MaskPolicy, high: MaskPolicy, secret: MaskPolicy) -> Self {
        Self {
            low,
            medium,
            high,
            secret,
        }
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
    #[cfg(feature = "http")]
    pub(crate) fn mask_bounded<'a>(&self, level: Sensitivity, value: &'a str, max_bytes: usize) -> Cow<'a, str> {
        self.for_level(level).mask_bounded(value, max_bytes)
    }

    /// Masks a value and reports byte-limit truncation.
    ///
    /// # Type Parameters
    ///
    /// - `'a`: Borrow of the input retained when no allocation is required.
    ///
    /// # Parameters
    ///
    /// - `level`: Sensitivity selecting a mask policy.
    /// - `value`: Source text needed by edge-preserving masks.
    /// - `max_bytes`: Maximum allocated bytes for the resulting mask.
    ///
    /// # Returns
    ///
    /// The borrowed empty input or bounded owned mask, followed by whether
    /// the byte allowance omitted any part of the selected mask.
    #[must_use]
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

    /// Validates fixed replacements for one policy construction location.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::EmptyFixedReplacement`] when a fixed mask is
    /// empty, reporting its sensitivity and construction location.
    ///
    /// # Parameters
    ///
    /// - `location`: Construction context attached to a rejected fixed mask.
    ///
    /// # Returns
    ///
    /// Success when every fixed replacement is nonempty.
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

impl Default for MaskingPolicy {
    /// Creates the built-in conservative four-level masking configuration.
    ///
    /// # Returns
    ///
    /// The built-in masking configuration.
    #[inline(always)]
    fn default() -> Self {
        Self::builder().build()
    }
}
