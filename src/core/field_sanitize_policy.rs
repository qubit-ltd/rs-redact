// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use super::{
    MaskPolicies,
    SensitiveFields,
};

/// Policy used by [`crate::FieldSanitizer`] for field-value sanitization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldSanitizePolicy {
    /// Sensitive fields and their sensitivity levels.
    sensitive_fields: SensitiveFields,
    /// Mask policies for each sensitivity level.
    mask_policies: MaskPolicies,
}

impl FieldSanitizePolicy {
    /// Creates a policy from sensitive fields and mask policies.
    ///
    /// # Parameters
    ///
    /// * `sensitive_fields` - Sensitive field names and levels.
    /// * `mask_policies` - Mask policies for all sensitivity levels.
    ///
    /// # Returns
    ///
    /// A policy containing the supplied components.
    #[inline(always)]
    pub const fn new(
        sensitive_fields: SensitiveFields,
        mask_policies: MaskPolicies,
    ) -> Self {
        Self {
            sensitive_fields,
            mask_policies,
        }
    }

    /// Creates a policy without built-in sensitive fields.
    ///
    /// # Returns
    ///
    /// Empty sensitive field policy with default mask policies.
    #[inline(always)]
    pub fn empty() -> Self {
        Self::new(SensitiveFields::new(), MaskPolicies::default())
    }

    /// Returns a copy with the sensitive fields replaced.
    ///
    /// # Parameters
    ///
    /// * `fields` - Replacement sensitive fields.
    ///
    /// # Returns
    ///
    /// The updated sanitization policy.
    #[inline(always)]
    pub fn with_sensitive_fields(mut self, fields: SensitiveFields) -> Self {
        self.sensitive_fields = fields;
        self
    }

    /// Returns a copy with the mask policies replaced.
    ///
    /// # Parameters
    ///
    /// * `policies` - Replacement mask policies.
    ///
    /// # Returns
    ///
    /// The updated sanitization policy.
    #[inline(always)]
    pub fn with_mask_policies(mut self, policies: MaskPolicies) -> Self {
        self.mask_policies = policies;
        self
    }

    /// Returns the configured sensitive fields.
    ///
    /// # Returns
    ///
    /// Borrowed sensitive fields and their levels.
    #[inline(always)]
    pub const fn sensitive_fields(&self) -> &SensitiveFields {
        &self.sensitive_fields
    }

    /// Returns the configured sensitive fields mutably.
    ///
    /// # Returns
    ///
    /// Mutable sensitive fields and their levels.
    #[inline(always)]
    pub fn sensitive_fields_mut(&mut self) -> &mut SensitiveFields {
        &mut self.sensitive_fields
    }

    /// Returns the configured mask policies.
    ///
    /// # Returns
    ///
    /// Borrowed mask policies for all sensitivity levels.
    #[inline(always)]
    pub const fn mask_policies(&self) -> &MaskPolicies {
        &self.mask_policies
    }

    /// Returns the configured mask policies mutably.
    ///
    /// # Returns
    ///
    /// Mutable mask policies for all sensitivity levels.
    #[inline(always)]
    pub fn mask_policies_mut(&mut self) -> &mut MaskPolicies {
        &mut self.mask_policies
    }
}

impl Default for FieldSanitizePolicy {
    /// Creates a policy with built-in sensitive fields and default masks.
    fn default() -> Self {
        Self::new(SensitiveFields::default(), MaskPolicies::default())
    }
}
