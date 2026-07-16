// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        LazyLock,
    },
};

use super::{
    SensitiveFieldPreset,
    SensitivityLevel,
    canonicalize_field_name,
    default_sensitive_fields::DEFAULT_EXTRA_FIELDS,
};

/// Set of sensitive field names and their sensitivity levels.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitiveFields {
    /// Shared canonical field names mapped to sensitivity levels.
    fields: Arc<BTreeMap<String, SensitivityLevel>>,
}

/// Shared immutable map cloned by every default sensitive-field set.
static DEFAULT_SENSITIVE_FIELDS: LazyLock<
    Arc<BTreeMap<String, SensitivityLevel>>,
> = LazyLock::new(|| {
    let mut fields = SensitiveFields::new();
    for preset in [
        SensitiveFieldPreset::Credentials,
        SensitiveFieldPreset::AuthTokens,
        SensitiveFieldPreset::Http,
        SensitiveFieldPreset::Session,
    ] {
        fields.extend_preset(preset);
    }
    for &(field, level) in DEFAULT_EXTRA_FIELDS {
        fields.insert_strongest(field, level);
    }
    fields.fields
});

impl SensitiveFields {
    /// Creates an empty sensitive field set.
    ///
    /// # Returns
    ///
    /// Empty field set without built-in names.
    #[inline]
    pub fn new() -> Self {
        Self {
            fields: Arc::new(BTreeMap::new()),
        }
    }

    /// Inserts one sensitive field name.
    ///
    /// # Parameters
    ///
    /// * `field` - Field name to mark sensitive.
    /// * `level` - Sensitivity level assigned to the field.
    ///
    /// An existing canonical field is replaced even when `level` is weaker.
    #[inline]
    pub fn insert(&mut self, field: &str, level: SensitivityLevel) {
        let field = canonicalize_field_name(field);
        if field.is_empty() || self.fields.get(&field).copied() == Some(level) {
            return;
        }
        Arc::make_mut(&mut self.fields).insert(field, level);
    }

    /// Inserts one field without lowering an existing sensitivity level.
    ///
    /// # Parameters
    ///
    /// * `field` - Field name to mark sensitive.
    /// * `level` - Minimum sensitivity level assigned to the field.
    #[inline]
    pub fn insert_strongest(&mut self, field: &str, level: SensitivityLevel) {
        let field = canonicalize_field_name(field);
        if field.is_empty() {
            return;
        }
        if self
            .fields
            .get(&field)
            .is_some_and(|current| *current >= level)
        {
            return;
        }
        Arc::make_mut(&mut self.fields).insert(field, level);
    }

    /// Removes one sensitive field name.
    ///
    /// # Parameters
    ///
    /// * `field` - Field name to remove after canonicalization.
    ///
    /// # Returns
    ///
    /// The removed sensitivity level, or `None` when the canonical field name
    /// is empty or not configured.
    #[inline]
    pub fn remove(&mut self, field: &str) -> Option<SensitivityLevel> {
        let field = canonicalize_field_name(field);
        let level = self.fields.get(&field).copied()?;
        Arc::make_mut(&mut self.fields).remove(&field);
        Some(level)
    }

    /// Removes all configured sensitive fields.
    #[inline]
    pub fn clear(&mut self) {
        if self.fields.is_empty() {
            return;
        }
        if let Some(fields) = Arc::get_mut(&mut self.fields) {
            fields.clear();
        } else {
            self.fields = Arc::new(BTreeMap::new());
        }
    }

    /// Merges another field set without lowering existing sensitivity levels.
    ///
    /// # Parameters
    ///
    /// * `other` - Field set whose entries should be merged.
    ///
    /// Existing canonical fields keep the stronger of the two levels. Fields
    /// present only in `other` are inserted unchanged.
    pub fn merge_strongest(&mut self, other: &Self) {
        if Arc::ptr_eq(&self.fields, &other.fields)
            || !other.fields.iter().any(|(field, level)| {
                self.fields.get(field).is_none_or(|current| current < level)
            })
        {
            return;
        }
        let fields = Arc::make_mut(&mut self.fields);
        for (field, level) in other.fields.iter() {
            if fields.get(field).is_none_or(|current| current < level) {
                fields.insert(field.clone(), *level);
            }
        }
    }

    /// Inserts each field with the same sensitivity level.
    ///
    /// # Parameters
    ///
    /// * `fields` - Field names to add.
    /// * `level` - Sensitivity level assigned to every field.
    ///
    /// Existing canonical fields are replaced even when `level` is weaker.
    pub fn extend<I, S>(&mut self, fields: I, level: SensitivityLevel)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for field in fields {
            self.insert(field.as_ref(), level);
        }
    }

    /// Inserts fields without lowering their existing sensitivity levels.
    ///
    /// # Parameters
    ///
    /// * `fields` - Field names to add.
    /// * `level` - Minimum sensitivity level assigned to every field.
    pub fn extend_strongest<I, S>(&mut self, fields: I, level: SensitivityLevel)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for field in fields {
            self.insert_strongest(field.as_ref(), level);
        }
    }

    /// Extends this set with one predefined field group.
    ///
    /// # Parameters
    ///
    /// * `preset` - Predefined group to insert.
    ///
    /// Existing canonical fields keep the stronger sensitivity level.
    pub fn extend_preset(&mut self, preset: SensitiveFieldPreset) {
        for &(field, level) in preset.fields() {
            self.insert_strongest(field, level);
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
    #[must_use]
    #[inline(always)]
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
    #[inline]
    pub fn level_for(&self, field: &str) -> Option<SensitivityLevel> {
        let field = canonicalize_field_name(field);
        self.level_for_canonical(&field)
    }

    /// Returns the number of configured sensitive fields.
    ///
    /// # Returns
    ///
    /// Field count.
    #[must_use]
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Returns whether no fields are configured.
    ///
    /// # Returns
    ///
    /// `true` when the set is empty.
    #[must_use]
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Iterates canonical field names and sensitivity levels.
    ///
    /// # Returns
    ///
    /// Iterator over canonical field names and their levels.
    #[inline(always)]
    pub fn iter(&self) -> impl Iterator<Item = (&str, SensitivityLevel)> {
        self.fields
            .iter()
            .map(|(field, level)| (field.as_str(), *level))
    }

    /// Returns the sensitivity level for an already canonicalized field name.
    ///
    /// # Parameters
    ///
    /// * `field` - Canonical field name to look up directly.
    ///
    /// # Returns
    ///
    /// `Some(level)` when the canonical field is configured, otherwise
    /// `None`.
    #[inline(always)]
    pub(super) fn level_for_canonical(
        &self,
        field: &str,
    ) -> Option<SensitivityLevel> {
        self.fields.get(field).copied()
    }
}

impl Default for SensitiveFields {
    /// Creates a set containing built-in sensitive fields.
    ///
    /// # Returns
    ///
    /// A field set containing every built-in preset and extra field.
    #[inline(always)]
    fn default() -> Self {
        Self {
            fields: Arc::clone(&DEFAULT_SENSITIVE_FIELDS),
        }
    }
}

impl<S> FromIterator<(S, SensitivityLevel)> for SensitiveFields
where
    S: AsRef<str>,
{
    /// Collects field-level pairs using [`SensitiveFields::insert`] semantics.
    ///
    /// Later entries overwrite earlier entries with the same canonical name.
    ///
    /// # Parameters
    ///
    /// * `iter` - Field-name and sensitivity-level pairs to collect.
    ///
    /// # Returns
    ///
    /// A sensitive-field set containing the collected canonical names.
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = (S, SensitivityLevel)>,
    {
        let mut fields = Self::new();
        for (field, level) in iter {
            fields.insert(field.as_ref(), level);
        }
        fields
    }
}
