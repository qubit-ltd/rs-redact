// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use std::borrow::Cow;

use super::{
    FieldSanitizePolicy,
    NameMatchMode,
    SensitiveFieldPreset,
    SensitivityLevel,
    field_name::find_canonical_field_match,
};

/// Sanitizes values by looking up their field names in a configurable policy.
#[must_use = "the sanitizer must be used to produce sanitized output"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldSanitizer {
    /// Field matching and masking policy.
    policy: FieldSanitizePolicy,
}

impl FieldSanitizer {
    /// Creates a sanitizer from an explicit policy.
    ///
    /// # Parameters
    ///
    /// * `policy` - Field matching and masking policy.
    ///
    /// # Returns
    ///
    /// New field sanitizer.
    #[inline(always)]
    pub const fn new(policy: FieldSanitizePolicy) -> Self {
        Self { policy }
    }

    /// Returns the underlying policy.
    ///
    /// # Returns
    ///
    /// Borrowed sanitization policy.
    #[inline(always)]
    pub const fn policy(&self) -> &FieldSanitizePolicy {
        &self.policy
    }

    /// Returns the underlying policy mutably.
    ///
    /// # Returns
    ///
    /// Mutable sanitization policy for advanced customization.
    #[inline(always)]
    pub fn policy_mut(&mut self) -> &mut FieldSanitizePolicy {
        &mut self.policy
    }

    /// Adds one sensitive field to this sanitizer.
    ///
    /// # Parameters
    ///
    /// * `field` - Field name to mark sensitive.
    /// * `level` - Sensitivity level assigned to the field.
    #[inline(always)]
    pub fn insert_sensitive_field(
        &mut self,
        field: &str,
        level: SensitivityLevel,
    ) {
        self.policy
            .sensitive_fields_mut()
            .insert_strongest(field, level);
    }

    /// Removes one sensitive field from this sanitizer.
    ///
    /// This can remove built-in defaults. Callers should do so only after
    /// deciding that exposing the matching value is acceptable for their
    /// logging or diagnostic context.
    ///
    /// # Parameters
    ///
    /// * `field` - Field name to remove after canonicalization.
    ///
    /// # Returns
    ///
    /// The removed sensitivity level, or `None` when the field was not
    /// configured.
    #[inline(always)]
    pub fn remove_sensitive_field(
        &mut self,
        field: &str,
    ) -> Option<SensitivityLevel> {
        self.policy.sensitive_fields_mut().remove(field)
    }

    /// Explicitly replaces the sensitivity level for one field.
    ///
    /// # Parameters
    ///
    /// * `field` - Field name whose level should be replaced.
    /// * `level` - Replacement sensitivity level, even when weaker.
    #[inline(always)]
    pub fn set_sensitive_field_level(
        &mut self,
        field: &str,
        level: SensitivityLevel,
    ) {
        self.policy.sensitive_fields_mut().insert(field, level);
    }

    /// Adds each field with the same sensitivity level.
    ///
    /// # Parameters
    ///
    /// * `fields` - Field names to add.
    /// * `level` - Sensitivity level assigned to every field.
    #[inline(always)]
    pub fn extend_sensitive_fields<I, S>(
        &mut self,
        fields: I,
        level: SensitivityLevel,
    ) where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.policy
            .sensitive_fields_mut()
            .extend_strongest(fields, level);
    }

    /// Adds one predefined field group.
    ///
    /// # Parameters
    ///
    /// * `preset` - Predefined group to insert.
    #[inline(always)]
    pub fn extend_preset(&mut self, preset: SensitiveFieldPreset) {
        self.policy.sensitive_fields_mut().extend_preset(preset);
    }

    /// Returns the sensitivity level for a field name.
    ///
    /// [`NameMatchMode::ExactOrSuffix`] first tries exact canonical matching.
    /// If that fails, it treats configured field names as canonical suffixes
    /// that start at separator or camel-case token boundaries in contextual
    /// names such as `OPENAI_API_KEY`. When multiple suffixes match, the
    /// longest field name wins.
    ///
    /// # Parameters
    ///
    /// * `name` - Field name to resolve.
    /// * `match_mode` - Field-name matching mode.
    ///
    /// # Returns
    ///
    /// `Some(level)` when the name is sensitive, otherwise `None`.
    pub fn sensitivity_for_name(
        &self,
        name: &str,
        match_mode: NameMatchMode,
    ) -> Option<SensitivityLevel> {
        let fields = self.policy.sensitive_fields();
        match match_mode {
            NameMatchMode::Exact => fields.level_for(name),
            NameMatchMode::ExactOrSuffix => {
                find_canonical_field_match(name, |canonical| {
                    fields.level_for_canonical(canonical)
                })
            }
        }
    }

    /// Sanitizes one field-value pair.
    ///
    /// # Parameters
    ///
    /// * `field` - Field name used for sensitivity lookup.
    /// * `value` - Field value to sanitize.
    /// * `match_mode` - Field-name matching mode.
    ///
    /// # Returns
    ///
    /// Borrowed `value` when `field` is not sensitive, otherwise an owned
    /// masked value according to the resolved sensitivity level.
    ///
    /// # Examples
    ///
    /// Sanitized output must replace the original value instead of being
    /// discarded.
    ///
    /// ```compile_fail
    /// #![deny(unused_must_use)]
    /// use qubit_sanitize::{FieldSanitizer, NameMatchMode};
    ///
    /// let sanitizer = FieldSanitizer::default();
    /// sanitizer.sanitize_value("password", "secret", NameMatchMode::Exact);
    /// ```
    #[must_use = "use the returned sanitized value instead of the original value"]
    #[inline]
    pub fn sanitize_value<'a>(
        &self,
        field: &str,
        value: &'a str,
        match_mode: NameMatchMode,
    ) -> Cow<'a, str> {
        let Some(level) = self.sensitivity_for_name(field, match_mode) else {
            return Cow::Borrowed(value);
        };
        self.mask_value_at_level(value, level)
    }

    /// Returns a sanitized copy of a string map.
    ///
    /// # Parameters
    ///
    /// * `map` - Source map whose keys are treated as field names.
    /// * `match_mode` - Field-name matching mode.
    ///
    /// # Returns
    ///
    /// New map preserving keys and sanitizing sensitive values.
    ///
    /// This supports any standard map type that iterates as `(&String,
    /// &String)` and can be rebuilt from `(String, String)` items, such as
    /// `std::collections::BTreeMap` and `std::collections::HashMap`.
    #[must_use = "use the returned sanitized map instead of the original map"]
    pub fn sanitize_map<M>(&self, map: &M, match_mode: NameMatchMode) -> M
    where
        for<'a> &'a M: IntoIterator<Item = (&'a String, &'a String)>,
        M: FromIterator<(String, String)>,
    {
        map.into_iter()
            .map(|(field, value)| {
                (
                    field.clone(),
                    self.sanitize_value(field, value.as_str(), match_mode)
                        .into_owned(),
                )
            })
            .collect()
    }

    /// Sanitizes sensitive values in a string map in place.
    ///
    /// # Parameters
    ///
    /// * `map` - Mutable map whose keys are treated as field names.
    /// * `match_mode` - Field-name matching mode.
    pub fn sanitize_map_in_place<M>(
        &self,
        map: &mut M,
        match_mode: NameMatchMode,
    ) where
        for<'a> &'a mut M: IntoIterator<Item = (&'a String, &'a mut String)>,
    {
        for (field, value) in map {
            let sanitized =
                self.sanitize_value(field, value.as_str(), match_mode);
            if let Cow::Owned(sanitized) = sanitized {
                *value = sanitized;
            }
        }
    }

    /// Masks a value whose sensitivity level has already been resolved.
    ///
    /// # Parameters
    ///
    /// * `value` - Value to mask.
    /// * `level` - Previously resolved sensitivity level.
    ///
    /// # Returns
    ///
    /// Masked value according to the policy for `level`.
    #[must_use = "use the returned masked value instead of the original value"]
    #[inline(always)]
    pub(crate) fn mask_value_at_level<'a>(
        &self,
        value: &'a str,
        level: SensitivityLevel,
    ) -> Cow<'a, str> {
        self.policy.mask_policies().for_level(level).mask(value)
    }
}

impl Default for FieldSanitizer {
    /// Creates a sanitizer with [`FieldSanitizePolicy::default`].
    #[inline(always)]
    fn default() -> Self {
        Self::new(FieldSanitizePolicy::default())
    }
}
