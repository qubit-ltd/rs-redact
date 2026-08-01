// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Shared construction kernel for application rules and floors.

use std::collections::{
    BTreeMap,
    BTreeSet,
};

use super::{
    FieldNameMatching,
    MaskPolicy,
    MaskingPolicy,
    PolicyError,
    PolicyLocation,
    SensitiveFieldPreset,
    Sensitivity,
    UnknownFieldPolicy,
    internal::{
        RedactionPolicyInner,
        canonicalize_field_name,
    },
};

#[derive(Debug, Clone)]
pub(crate) struct RedactionRulesBuilder {
    sensitive: BTreeMap<String, Sensitivity>,
    allow_exact: BTreeSet<String>,
    allow_suffix: BTreeSet<String>,
    matching: FieldNameMatching,
    unknown_field_policy: UnknownFieldPolicy,
    masking: MaskingPolicy,
    location: PolicyLocation,
    error: Option<PolicyError>,
}

impl RedactionRulesBuilder {
    pub(crate) fn empty(location: PolicyLocation) -> Self {
        Self {
            sensitive: BTreeMap::new(),
            allow_exact: BTreeSet::new(),
            allow_suffix: BTreeSet::new(),
            matching: FieldNameMatching::ExactOrTokenSuffix,
            unknown_field_policy: UnknownFieldPolicy::PassThrough,
            masking: MaskingPolicy::default(),
            location,
            error: None,
        }
    }

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
            masking: inner.masking.clone(),
            location,
            error: None,
        }
    }

    pub(crate) fn matching(mut self, matching: FieldNameMatching) -> Self {
        self.matching = matching;
        self
    }
    pub(crate) fn unknown_field_policy(
        mut self,
        policy: UnknownFieldPolicy,
    ) -> Self {
        self.unknown_field_policy = policy;
        self
    }
    pub(crate) fn include_preset(
        mut self,
        preset: SensitiveFieldPreset,
    ) -> Self {
        for &(field, level) in preset.fields() {
            self = self.raise(field, level);
        }
        self
    }
    pub(crate) fn raise(mut self, field: &str, level: Sensitivity) -> Self {
        let Some(field) = self.canonical_field(field) else {
            return self;
        };
        self.sensitive
            .entry(field)
            .and_modify(|old| *old = (*old).max(level))
            .or_insert(level);
        self
    }
    pub(crate) fn override_level(
        mut self,
        field: &str,
        level: Sensitivity,
    ) -> Self {
        let Some(field) = self.canonical_field(field) else {
            return self;
        };
        self.sensitive.insert(field, level);
        self
    }
    pub(crate) fn allow_canonical_exact(mut self, field: &str) -> Self {
        let Some(field) = self.canonical_field(field) else {
            return self;
        };
        self.allow_exact.insert(field);
        self
    }
    pub(crate) fn allow_suffix(mut self, field: &str) -> Self {
        let Some(field) = self.canonical_field(field) else {
            return self;
        };
        self.allow_suffix.insert(field);
        self
    }
    pub(crate) fn remove_allow_canonical_exact(mut self, field: &str) -> Self {
        let Some(field) = self.canonical_field(field) else {
            return self;
        };
        self.allow_exact.remove(&field);
        self
    }
    pub(crate) fn remove_allow_suffix(mut self, field: &str) -> Self {
        let Some(field) = self.canonical_field(field) else {
            return self;
        };
        self.allow_suffix.remove(&field);
        self
    }
    pub(crate) fn clear_allow_rules(mut self) -> Self {
        self.allow_exact.clear();
        self.allow_suffix.clear();
        self
    }
    pub(crate) fn mask(
        mut self,
        level: Sensitivity,
        policy: MaskPolicy,
    ) -> Self {
        self.masking = self.masking.with_policy(level, policy);
        self
    }
    pub(crate) fn validate_field_name(
        field: &str,
        location: PolicyLocation,
    ) -> Result<(), PolicyError> {
        Self::checked_canonical_field(field, location).map(|_| ())
    }
    pub(crate) fn build_inner(
        self,
    ) -> Result<RedactionPolicyInner, PolicyError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        for level in [
            Sensitivity::Low,
            Sensitivity::Medium,
            Sensitivity::High,
            Sensitivity::Secret,
        ] {
            if matches!(self.masking.for_level(level), MaskPolicy::Fixed { replacement } if replacement.is_empty())
            {
                return Err(PolicyError::EmptyFixedReplacement {
                    location: self.location,
                    level,
                });
            }
        }
        Ok(RedactionPolicyInner {
            sensitive: self.sensitive,
            allow_exact: self.allow_exact,
            allow_suffix: self.allow_suffix,
            matching: self.matching,
            unknown_field_policy: self.unknown_field_policy,
            masking: self.masking,
        })
    }
    fn canonical_field(&mut self, field: &str) -> Option<String> {
        match Self::checked_canonical_field(field, self.location) {
            Ok(field) => Some(field),
            Err(error) => {
                self.error.get_or_insert(error);
                None
            }
        }
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
