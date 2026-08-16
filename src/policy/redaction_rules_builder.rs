// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared construction kernel for application rules and floors.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use super::FieldNameMatching;
use super::PolicyError;
use super::PolicyLocation;
use super::SensitiveFieldPreset;
use super::Sensitivity;
use super::UnknownFieldPolicy;
use super::internal::RedactionPolicyInner;
use super::internal::canonicalize_field_name;

/// Mutable construction state for one set of redaction rules.
#[derive(Debug, Clone)]
pub(crate) struct RedactionRulesBuilder {
    sensitive: BTreeMap<String, Sensitivity>,
    allow_exact: BTreeSet<String>,
    allow_suffix: BTreeSet<String>,
    matching: FieldNameMatching,
    unknown_field_policy: UnknownFieldPolicy,
    location: PolicyLocation,
}

impl RedactionRulesBuilder {
    /// Creates an empty rules builder for one policy location.
    ///
    /// # Parameters
    ///
    /// * `location` - Policy location used when reporting validation errors.
    pub(crate) fn empty(location: PolicyLocation) -> Self {
        Self {
            sensitive: BTreeMap::new(),
            allow_exact: BTreeSet::new(),
            allow_suffix: BTreeSet::new(),
            matching: FieldNameMatching::ExactOrTokenSuffix,
            unknown_field_policy: UnknownFieldPolicy::PassThrough,
            location,
        }
    }

    /// Copies rule configuration from an immutable policy snapshot.
    ///
    /// # Parameters
    ///
    /// * `inner` - Immutable rule state to copy.
    /// * `location` - Policy location used for later validation errors.
    pub(crate) fn from_inner(
        inner: &RedactionPolicyInner,
        location: PolicyLocation,
    ) -> Self {
        Self {
            sensitive: inner.sensitive.clone(),
            allow_exact: inner.allow_exact.clone(),
            allow_suffix: inner.allow_suffix.clone(),
            matching: inner.matching,
            unknown_field_policy: inner.unknown_field_policy,
            location,
        }
    }

    /// Sets the field-name matching mode.
    ///
    /// # Parameters
    ///
    /// * `matching` - Matching mode used for subsequent field lookups.
    #[inline(always)]
    pub(crate) fn matching(&mut self, matching: FieldNameMatching) {
        self.matching = matching;
    }

    /// Sets the fallback behavior for fields without an explicit rule.
    ///
    /// # Parameters
    ///
    /// * `policy` - Fallback behavior for unknown fields.
    #[inline(always)]
    pub(crate) fn unknown_field_policy(&mut self, policy: UnknownFieldPolicy) {
        self.unknown_field_policy = policy;
    }

    /// Adds every field rule supplied by a built-in sensitive-field preset.
    ///
    /// # Parameters
    ///
    /// * `preset` - Preset whose rules are added.
    ///
    /// # Panics
    ///
    /// Panics if a built-in preset contains an invalid field name.
    pub(crate) fn include_preset(&mut self, preset: SensitiveFieldPreset) {
        for &(field, level) in preset.fields() {
            self.raise(field, level)
                .expect("built-in sensitive field presets must be valid");
        }
    }

    /// Raises a field's configured sensitivity without lowering an existing
    /// one.
    ///
    /// # Parameters
    ///
    /// * `field` - Field name to canonicalize and update.
    /// * `level` - Minimum sensitivity to apply.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::EmptyFieldName`] when `field` has no canonical
    /// field name.
    pub(crate) fn raise(
        &mut self,
        field: &str,
        level: Sensitivity,
    ) -> Result<(), PolicyError> {
        let field = self.canonical_field(field)?;
        self.sensitive
            .entry(field)
            .and_modify(|old| *old = (*old).max(level))
            .or_insert(level);
        Ok(())
    }

    /// Replaces a field's configured sensitivity.
    ///
    /// # Parameters
    ///
    /// * `field` - Field name to canonicalize and update.
    /// * `level` - Sensitivity to apply.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::EmptyFieldName`] when `field` has no canonical
    /// field name.
    pub(crate) fn override_level(
        &mut self,
        field: &str,
        level: Sensitivity,
    ) -> Result<(), PolicyError> {
        let field = self.canonical_field(field)?;
        self.sensitive.insert(field, level);
        Ok(())
    }

    /// Adds an exact allow rule for a field.
    ///
    /// # Parameters
    ///
    /// * `field` - Field name to allow after canonicalization.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::EmptyFieldName`] when `field` has no canonical
    /// field name.
    pub(crate) fn allow_canonical_exact(
        &mut self,
        field: &str,
    ) -> Result<(), PolicyError> {
        let field = self.canonical_field(field)?;
        self.allow_exact.insert(field);
        Ok(())
    }

    /// Adds a token-suffix allow rule for a field.
    ///
    /// # Parameters
    ///
    /// * `field` - Field-name suffix to allow after canonicalization.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::EmptyFieldName`] when `field` has no canonical
    /// field name.
    pub(crate) fn allow_suffix(
        &mut self,
        field: &str,
    ) -> Result<(), PolicyError> {
        let field = self.canonical_field(field)?;
        self.allow_suffix.insert(field);
        Ok(())
    }

    /// Removes an exact allow rule for a field.
    ///
    /// # Parameters
    ///
    /// * `field` - Field name to remove after canonicalization.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::EmptyFieldName`] when `field` has no canonical
    /// field name.
    pub(crate) fn remove_allow_canonical_exact(
        &mut self,
        field: &str,
    ) -> Result<(), PolicyError> {
        let field = self.canonical_field(field)?;
        self.allow_exact.remove(&field);
        Ok(())
    }

    /// Removes a token-suffix allow rule for a field.
    ///
    /// # Parameters
    ///
    /// * `field` - Field-name suffix to remove after canonicalization.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::EmptyFieldName`] when `field` has no canonical
    /// field name.
    pub(crate) fn remove_allow_suffix(
        &mut self,
        field: &str,
    ) -> Result<(), PolicyError> {
        let field = self.canonical_field(field)?;
        self.allow_suffix.remove(&field);
        Ok(())
    }

    /// Removes all exact and suffix allow rules.
    pub(crate) fn clear_allow_rules(&mut self) {
        self.allow_exact.clear();
        self.allow_suffix.clear();
    }

    /// Validates a field name at a specific policy location.
    ///
    /// # Parameters
    ///
    /// * `field` - Field name to canonicalize and validate.
    /// * `location` - Location attached to any validation error.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::EmptyFieldName`] when `field` has no canonical
    /// field name.
    pub(crate) fn validate_field_name(
        field: &str,
        location: PolicyLocation,
    ) -> Result<(), PolicyError> {
        Self::checked_canonical_field(field, location).map(|_| ())
    }

    /// Builds immutable rule state from the accumulated configuration.
    ///
    /// # Returns
    ///
    /// The immutable rule state used by policy snapshots.
    pub(crate) fn build_inner(
        self,
    ) -> Result<RedactionPolicyInner, PolicyError> {
        Ok(RedactionPolicyInner {
            sensitive: self.sensitive,
            allow_exact: self.allow_exact,
            allow_suffix: self.allow_suffix,
            matching: self.matching,
            unknown_field_policy: self.unknown_field_policy,
        })
    }

    /// Canonicalizes and validates a field using this builder's location.
    ///
    /// # Parameters
    ///
    /// * `field` - Field name to canonicalize and validate.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::EmptyFieldName`] when `field` has no canonical
    /// field name.
    fn canonical_field(&self, field: &str) -> Result<String, PolicyError> {
        Self::checked_canonical_field(field, self.location)
    }

    /// Canonicalizes a field and attaches `location` to validation errors.
    ///
    /// # Parameters
    ///
    /// * `field` - Field name to canonicalize.
    /// * `location` - Location attached to any validation error.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::EmptyFieldName`] when canonicalization produces
    /// an empty field name.
    fn checked_canonical_field(
        field: &str,
        location: PolicyLocation,
    ) -> Result<String, PolicyError> {
        let canonical = canonicalize_field_name(field);
        if canonical.is_empty() {
            Err(PolicyError::EmptyFieldName { location })
        } else {
            Ok(canonical.into_owned())
        }
    }
}
