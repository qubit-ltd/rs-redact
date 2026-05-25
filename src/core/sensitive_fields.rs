/*******************************************************************************
 *
 *    Copyright (c) 2026 Haixing Hu.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    Licensed under the Apache License, Version 2.0.
 *
 ******************************************************************************/
use std::collections::BTreeMap;

use super::{
    SensitiveFieldPreset,
    SensitivityLevel,
    canonicalize_field_name,
    default_sensitive_fields::DEFAULT_EXTRA_FIELDS,
};

/// Set of sensitive field names and their sensitivity levels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitiveFields {
    /// Canonical field names mapped to sensitivity levels.
    fields: BTreeMap<String, SensitivityLevel>,
}

impl SensitiveFields {
    /// Creates an empty sensitive field set.
    ///
    /// # Returns
    ///
    /// Empty field set without built-in names.
    pub fn new() -> Self {
        Self {
            fields: BTreeMap::new(),
        }
    }

    /// Inserts one sensitive field name.
    ///
    /// # Parameters
    ///
    /// * `field` - Field name to mark sensitive.
    /// * `level` - Sensitivity level assigned to the field.
    pub fn insert(&mut self, field: &str, level: SensitivityLevel) {
        let field = canonicalize_field_name(field);
        if !field.is_empty() {
            self.fields.insert(field, level);
        }
    }

    /// Inserts each field with the same sensitivity level.
    ///
    /// # Parameters
    ///
    /// * `fields` - Field names to add.
    /// * `level` - Sensitivity level assigned to every field.
    pub fn extend<I, S>(&mut self, fields: I, level: SensitivityLevel)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for field in fields {
            self.insert(field.as_ref(), level);
        }
    }

    /// Extends this set with one predefined field group.
    ///
    /// # Parameters
    ///
    /// * `preset` - Predefined group to insert.
    pub fn extend_preset(&mut self, preset: SensitiveFieldPreset) {
        for (field, level) in preset.fields() {
            self.insert(field, *level);
        }
    }

    /// Returns whether a field is configured as sensitive.
    ///
    /// # Parameters
    ///
    /// * `field` - Field name to test.
    ///
    /// # Returns
    ///
    /// `true` when `field` has a configured sensitivity level.
    pub fn contains(&self, field: &str) -> bool {
        self.level_for(field).is_some()
    }

    /// Returns the sensitivity level for a field.
    ///
    /// # Parameters
    ///
    /// * `field` - Field name to resolve.
    ///
    /// # Returns
    ///
    /// `Some(level)` when the field is sensitive, otherwise `None`.
    pub fn level_for(&self, field: &str) -> Option<SensitivityLevel> {
        self.fields.get(&canonicalize_field_name(field)).copied()
    }

    /// Returns the number of configured sensitive fields.
    ///
    /// # Returns
    ///
    /// Field count.
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Returns whether no fields are configured.
    ///
    /// # Returns
    ///
    /// `true` when the set is empty.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Iterates canonical field names and sensitivity levels.
    ///
    /// # Returns
    ///
    /// Iterator over canonical field names and their levels.
    pub fn iter(&self) -> impl Iterator<Item = (&str, SensitivityLevel)> {
        self.fields.iter().map(|(field, level)| (field.as_str(), *level))
    }
}

impl Default for SensitiveFields {
    /// Creates a set containing built-in sensitive fields.
    fn default() -> Self {
        let mut fields = Self::new();
        for preset in [
            SensitiveFieldPreset::Credentials,
            SensitiveFieldPreset::AuthTokens,
            SensitiveFieldPreset::Http,
            SensitiveFieldPreset::Session,
        ] {
            fields.extend_preset(preset);
        }
        for (field, level) in DEFAULT_EXTRA_FIELDS {
            fields.insert(field, level);
        }
        fields
    }
}
