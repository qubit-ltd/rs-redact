// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable construction of the four-level immutable mask table.

use super::MaskPolicy;
use super::MaskingPolicy;
use crate::Sensitivity;

/// Mutable construction state for a [`MaskingPolicy`].
///
/// # Examples
///
/// ```
/// use qubit_redact::MaskPolicy;
/// use qubit_redact::MaskingPolicy;
/// use qubit_redact::Sensitivity;
///
/// let mut builder = MaskingPolicy::builder();
/// builder.secret(MaskPolicy::fixed("[hidden]"));
/// assert_eq!(builder.build().mask(Sensitivity::Secret, "raw"), "[hidden]");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskingPolicyBuilder {
    /// Draft mask for low-sensitivity values.
    low: MaskPolicy,
    /// Draft mask for medium-sensitivity values.
    medium: MaskPolicy,
    /// Draft mask for high-sensitivity values.
    high: MaskPolicy,
    /// Draft mask for secret values.
    secret: MaskPolicy,
}

impl MaskingPolicyBuilder {
    /// Copies every mask from an immutable table into independent draft state.
    ///
    /// # Parameters
    ///
    /// - `policy`: Immutable mask table to copy.
    ///
    /// # Returns
    ///
    /// A builder retaining all four mask choices.
    #[must_use]
    #[inline(always)]
    pub(super) fn from_policy(policy: &MaskingPolicy) -> Self {
        Self {
            low: policy.for_level(Sensitivity::Low).clone(),
            medium: policy.for_level(Sensitivity::Medium).clone(),
            high: policy.for_level(Sensitivity::High).clone(),
            secret: policy.for_level(Sensitivity::Secret).clone(),
        }
    }

    /// Sets the policy for low-sensitivity values.
    ///
    /// # Parameters
    ///
    /// - `policy`: Replacement masking rule for low sensitivity.
    ///
    /// # Returns
    ///
    /// This builder with the selected level replaced.
    #[inline(always)]
    pub fn low(&mut self, policy: MaskPolicy) -> &mut Self {
        self.low = policy;
        self
    }

    /// Sets the policy for medium-sensitivity values.
    ///
    /// # Parameters
    ///
    /// - `policy`: Replacement masking rule for medium sensitivity.
    ///
    /// # Returns
    ///
    /// This builder with the selected level replaced.
    #[inline(always)]
    pub fn medium(&mut self, policy: MaskPolicy) -> &mut Self {
        self.medium = policy;
        self
    }

    /// Sets the policy for high-sensitivity values.
    ///
    /// # Parameters
    ///
    /// - `policy`: Replacement masking rule for high sensitivity.
    ///
    /// # Returns
    ///
    /// This builder with the selected level replaced.
    #[inline(always)]
    pub fn high(&mut self, policy: MaskPolicy) -> &mut Self {
        self.high = policy;
        self
    }

    /// Sets the policy for secret values.
    ///
    /// # Parameters
    ///
    /// - `policy`: Replacement masking rule for secret sensitivity.
    ///
    /// # Returns
    ///
    /// This builder with the selected level replaced.
    #[inline(always)]
    pub fn secret(&mut self, policy: MaskPolicy) -> &mut Self {
        self.secret = policy;
        self
    }

    /// Builds the immutable masking configuration.
    ///
    /// # Returns
    ///
    /// The immutable mask table. The enclosing redaction policy builder checks
    /// that fixed replacements are nonempty before accepting the table.
    #[must_use]
    #[inline(always)]
    pub fn build(self) -> MaskingPolicy {
        MaskingPolicy::from_parts(self.low, self.medium, self.high, self.secret)
    }

    /// Replaces one sensitivity policy while rebuilding an existing policy.
    ///
    /// # Parameters
    ///
    /// - `level`: Sensitivity whose draft mask is replaced.
    /// - `policy`: Replacement mask for that level.
    #[inline]
    pub(crate) fn policy(&mut self, level: Sensitivity, policy: MaskPolicy) {
        match level {
            Sensitivity::Low => self.low(policy),
            Sensitivity::Medium => self.medium(policy),
            Sensitivity::High => self.high(policy),
            Sensitivity::Secret => self.secret(policy),
        };
    }
}

impl Default for MaskingPolicyBuilder {
    /// Creates a builder with the standard masking policies.
    ///
    /// # Returns
    ///
    /// A builder using the standard low, medium, high, and secret masks.
    #[inline(always)]
    fn default() -> Self {
        Self {
            low: MaskPolicy::preserve_edges(2, 2, "****", 4),
            medium: MaskPolicy::preserve_suffix(1, "*******", 1),
            high: MaskPolicy::fixed("****"),
            secret: MaskPolicy::fixed("<redacted>"),
        }
    }
}
