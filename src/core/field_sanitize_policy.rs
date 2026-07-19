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
    SensitiveFieldPreset,
    SensitiveFields,
    SensitivityLevel,
    canonicalize_field_name,
};

/// Policy used by [`crate::FieldSanitizer`] for field-value sanitization.
///
/// The policy owns both positive field entries and explicit exclusions. Its
/// mutation methods keep those sets consistent: adding or setting a field
/// cancels its matching exclusion, while replacing the complete field set
/// clears every exclusion.
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
    /// Replacing the complete field set clears every explicit exclusion so
    /// that `fields` is authoritative.
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
        self.set_sensitive_fields(fields);
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

    /// Replaces the configured sensitive fields.
    ///
    /// Replacing the complete field set clears every explicit exclusion so
    /// that the supplied set is authoritative.
    ///
    /// # Parameters
    ///
    /// * `fields` - Replacement sensitive fields.
    #[inline]
    pub fn set_sensitive_fields(&mut self, fields: SensitiveFields) {
        self.sensitive_fields = fields;
        self.excluded_fields.clear();
    }

    /// Adds one sensitive field without lowering an existing level.
    ///
    /// A matching explicit exclusion is cancelled before the field is added.
    ///
    /// # Parameters
    ///
    /// * `field` - Field name to mark sensitive.
    /// * `level` - Minimum sensitivity level assigned to the field.
    #[inline]
    pub fn insert_sensitive_field(
        &mut self,
        field: &str,
        level: SensitivityLevel,
    ) {
        self.excluded_fields.remove(&canonicalize_field_name(field));
        self.sensitive_fields.insert_strongest(field, level);
    }

    /// Explicitly replaces the sensitivity level for one field.
    ///
    /// A matching explicit exclusion is cancelled before the field is added.
    ///
    /// # Parameters
    ///
    /// * `field` - Field name whose level should be replaced.
    /// * `level` - Replacement sensitivity level, even when weaker.
    #[inline]
    pub fn set_sensitive_field_level(
        &mut self,
        field: &str,
        level: SensitivityLevel,
    ) {
        self.excluded_fields.remove(&canonicalize_field_name(field));
        self.sensitive_fields.insert(field, level);
    }

    /// Adds each field without lowering existing sensitivity levels.
    ///
    /// Matching explicit exclusions are cancelled as fields are added.
    ///
    /// # Parameters
    ///
    /// * `fields` - Field names to add.
    /// * `level` - Minimum sensitivity level assigned to every field.
    pub fn extend_sensitive_fields<I, S>(
        &mut self,
        fields: I,
        level: SensitivityLevel,
    ) where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for field in fields {
            self.insert_sensitive_field(field.as_ref(), level);
        }
    }

    /// Adds one predefined field group without lowering existing levels.
    ///
    /// Matching explicit exclusions are cancelled as fields are added.
    ///
    /// # Parameters
    ///
    /// * `preset` - Predefined group to insert.
    pub fn extend_preset(&mut self, preset: SensitiveFieldPreset) {
        for &(field, level) in preset.fields() {
            self.insert_sensitive_field(field, level);
        }
    }

    /// Explicitly excludes one sensitive field.
    ///
    /// The exclusion wins over positive matches at the same canonical token
    /// boundary. With [`crate::NameMatchMode::ExactOrSuffix`], excluding
    /// `access_token` also prevents a contextual name such as
    /// `OPENAI_ACCESS_TOKEN` from falling back to the shorter built-in
    /// `token` suffix. Callers should use this only after deciding that
    /// exposing matching values is acceptable in their diagnostic context.
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
    pub fn exclude_sensitive_field(
        &mut self,
        field: &str,
    ) -> Option<SensitivityLevel> {
        let canonical = canonicalize_field_name(field);
        if !canonical.is_empty() {
            self.excluded_fields.insert(canonical);
        }
        self.sensitive_fields.remove(field)
    }

    /// Returns whether one field has an explicit exclusion.
    ///
    /// # Parameters
    ///
    /// * `field` - Field name to test after canonicalization.
    ///
    /// # Returns
    ///
    /// `true` when the canonical field name is explicitly excluded.
    #[must_use]
    #[inline]
    pub fn is_sensitive_field_excluded(&self, field: &str) -> bool {
        self.excluded_fields
            .contains(&canonicalize_field_name(field))
    }

    /// Iterates canonical field names with explicit exclusions.
    ///
    /// # Returns
    ///
    /// Iterator over excluded canonical field names in sorted order.
    #[inline(always)]
    pub fn excluded_sensitive_fields(&self) -> impl Iterator<Item = &str> {
        self.excluded_fields.iter().map(String::as_str)
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

    /// Returns canonical field names that override positive matches.
    ///
    /// # Returns
    ///
    /// Borrowed explicit exclusion set.
    #[must_use]
    #[inline(always)]
    pub(super) const fn excluded_fields(&self) -> &BTreeSet<String> {
        &self.excluded_fields
    }
}

impl Default for FieldSanitizePolicy {
    /// Creates a policy with built-in sensitive fields and default masks.
    ///
    /// # Returns
    ///
    /// Default field sanitization policy.
    #[inline]
    fn default() -> Self {
        Self::new(SensitiveFields::default(), MaskPolicies::default())
    }
}
