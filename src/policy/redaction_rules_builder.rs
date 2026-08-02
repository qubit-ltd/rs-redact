// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared construction kernel for application rules and floors.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    FieldNameMatching, PolicyError, PolicyLocation, SensitiveFieldPreset, Sensitivity,
    UnknownFieldPolicy,
    internal::{RedactionPolicyInner, canonicalize_field_name},
};

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

    pub(crate) fn from_inner(inner: &RedactionPolicyInner, location: PolicyLocation) -> Self {
        Self {
            sensitive: inner.sensitive.clone(),
            allow_exact: inner.allow_exact.clone(),
            allow_suffix: inner.allow_suffix.clone(),
            matching: inner.matching,
            unknown_field_policy: inner.unknown_field_policy,
            location,
        }
    }

    pub(crate) fn matching(&mut self, matching: FieldNameMatching) {
        self.matching = matching;
    }
    pub(crate) fn unknown_field_policy(&mut self, policy: UnknownFieldPolicy) {
        self.unknown_field_policy = policy;
    }
    pub(crate) fn include_preset(&mut self, preset: SensitiveFieldPreset) {
        for &(field, level) in preset.fields() {
            self.raise(field, level)
                .expect("built-in sensitive field presets must be valid");
        }
    }
    pub(crate) fn raise(&mut self, field: &str, level: Sensitivity) -> Result<(), PolicyError> {
        let field = self.canonical_field(field)?;
        self.sensitive
            .entry(field)
            .and_modify(|old| *old = (*old).max(level))
            .or_insert(level);
        Ok(())
    }
    pub(crate) fn override_level(
        &mut self,
        field: &str,
        level: Sensitivity,
    ) -> Result<(), PolicyError> {
        let field = self.canonical_field(field)?;
        self.sensitive.insert(field, level);
        Ok(())
    }
    pub(crate) fn allow_canonical_exact(&mut self, field: &str) -> Result<(), PolicyError> {
        let field = self.canonical_field(field)?;
        self.allow_exact.insert(field);
        Ok(())
    }
    pub(crate) fn allow_suffix(&mut self, field: &str) -> Result<(), PolicyError> {
        let field = self.canonical_field(field)?;
        self.allow_suffix.insert(field);
        Ok(())
    }
    pub(crate) fn remove_allow_canonical_exact(&mut self, field: &str) -> Result<(), PolicyError> {
        let field = self.canonical_field(field)?;
        self.allow_exact.remove(&field);
        Ok(())
    }
    pub(crate) fn remove_allow_suffix(&mut self, field: &str) -> Result<(), PolicyError> {
        let field = self.canonical_field(field)?;
        self.allow_suffix.remove(&field);
        Ok(())
    }
    pub(crate) fn clear_allow_rules(&mut self) {
        self.allow_exact.clear();
        self.allow_suffix.clear();
    }
    pub(crate) fn validate_field_name(
        field: &str,
        location: PolicyLocation,
    ) -> Result<(), PolicyError> {
        Self::checked_canonical_field(field, location).map(|_| ())
    }
    pub(crate) fn build_inner(self) -> Result<RedactionPolicyInner, PolicyError> {
        Ok(RedactionPolicyInner {
            sensitive: self.sensitive,
            allow_exact: self.allow_exact,
            allow_suffix: self.allow_suffix,
            matching: self.matching,
            unknown_field_policy: self.unknown_field_policy,
        })
    }
    fn canonical_field(&self, field: &str) -> Result<String, PolicyError> {
        Self::checked_canonical_field(field, self.location)
    }
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
