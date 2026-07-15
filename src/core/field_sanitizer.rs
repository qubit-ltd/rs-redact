// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
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
    field_name::canonicalize_field_name_suffixes,
};

/// Sanitizes values by looking up their field names in a configurable policy.
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
    pub const fn new(policy: FieldSanitizePolicy) -> Self {
        Self { policy }
    }

    /// Returns the underlying policy.
    ///
    /// # Returns
    ///
    /// Borrowed sanitization policy.
    pub const fn policy(&self) -> &FieldSanitizePolicy {
        &self.policy
    }

    /// Returns the underlying policy mutably.
    ///
    /// # Returns
    ///
    /// Mutable sanitization policy for advanced customization.
    pub fn policy_mut(&mut self) -> &mut FieldSanitizePolicy {
        &mut self.policy
    }

    /// Adds one sensitive field to this sanitizer.
    ///
    /// # Parameters
    ///
    /// * `field` - Field name to mark sensitive.
    /// * `level` - Sensitivity level assigned to the field.
    pub fn insert_sensitive_field(
        &mut self,
        field: &str,
        level: SensitivityLevel,
    ) {
        self.policy.sensitive_fields.insert(field, level);
    }

    /// Adds each field with the same sensitivity level.
    ///
    /// # Parameters
    ///
    /// * `fields` - Field names to add.
    /// * `level` - Sensitivity level assigned to every field.
    pub fn extend_sensitive_fields<I, S>(
        &mut self,
        fields: I,
        level: SensitivityLevel,
    ) where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.policy.sensitive_fields.extend(fields, level);
    }

    /// Adds one predefined field group.
    ///
    /// # Parameters
    ///
    /// * `preset` - Predefined group to insert.
    pub fn extend_preset(&mut self, preset: SensitiveFieldPreset) {
        self.policy.sensitive_fields.extend_preset(preset);
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
        let fields = &self.policy.sensitive_fields;
        if let Some(level) = fields.level_for(name) {
            return Some(level);
        }
        if match_mode == NameMatchMode::Exact {
            return None;
        }

        let suffixes = canonicalize_field_name_suffixes(name);
        if suffixes.is_empty() {
            return None;
        }

        fields
            .iter()
            .filter_map(|(field, level)| {
                if suffixes.iter().any(|suffix| suffix == field) {
                    Some((field.len(), level))
                } else {
                    None
                }
            })
            .max_by_key(|(field_len, level)| (*field_len, *level))
            .map(|(_, level)| level)
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
    pub fn sanitize_value<'a>(
        &self,
        field: &str,
        value: &'a str,
        match_mode: NameMatchMode,
    ) -> Cow<'a, str> {
        let Some(level) = self.sensitivity_for_name(field, match_mode) else {
            return Cow::Borrowed(value);
        };
        self.policy.mask_policies.for_level(level).mask(value)
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
}

impl Default for FieldSanitizer {
    /// Creates a sanitizer with [`FieldSanitizePolicy::default`].
    fn default() -> Self {
        Self::new(FieldSanitizePolicy::default())
    }
}
