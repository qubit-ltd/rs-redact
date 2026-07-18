// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use std::collections::BTreeSet;

use super::{
    MaskPolicies,
    SensitiveFields,
    SensitivityLevel,
    canonicalize_field_name,
};

/// Policy used by [`crate::FieldSanitizer`] for field-value sanitization.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldSanitizePolicy {
    /// Sensitive fields and their sensitivity levels.
    sensitive_fields: SensitiveFields,
    /// Canonical names that override positive field matches.
    excluded_fields: BTreeSet<String>,
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
            excluded_fields: BTreeSet::new(),
            mask_policies,
        }
    }

    /// Creates a policy without built-in sensitive fields.
    ///
    /// # Returns
    ///
    /// Empty sensitive field policy with default mask policies.
    #[inline]
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

    /// Records one explicit exclusion and removes its exact positive entry.
    ///
    /// # Parameters
    ///
    /// * `field` - Field name to exclude after canonicalization.
    ///
    /// # Returns
    ///
    /// The removed exact sensitivity level, or `None` when no exact entry was
    /// configured.
    #[inline]
    pub(super) fn exclude_sensitive_field(
        &mut self,
        field: &str,
    ) -> Option<SensitivityLevel> {
        let canonical = canonicalize_field_name(field);
        if !canonical.is_empty() {
            self.excluded_fields.insert(canonical);
        }
        self.sensitive_fields.remove(field)
    }

    /// Cancels the exact exclusion for one field name.
    ///
    /// # Parameters
    ///
    /// * `field` - Field name to include after canonicalization.
    #[inline]
    pub(super) fn include_sensitive_field(&mut self, field: &str) {
        self.excluded_fields.remove(&canonicalize_field_name(field));
    }

    /// Returns canonical field names that override positive matches.
    ///
    /// # Returns
    ///
    /// Borrowed explicit exclusion set.
    #[inline(always)]
    pub(super) const fn excluded_fields(&self) -> &BTreeSet<String> {
        &self.excluded_fields
    }
}

impl Default for FieldSanitizePolicy {
    /// Creates a policy with built-in sensitive fields and default masks.
    #[inline]
    fn default() -> Self {
        Self::new(SensitiveFields::default(), MaskPolicies::default())
    }
}
