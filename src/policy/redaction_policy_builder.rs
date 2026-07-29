// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable builder for immutable redaction policies.

use std::collections::{
    BTreeMap,
    BTreeSet,
};

use super::{
    DiagnosticBudget,
    FieldNameMatching,
    MaskPolicy,
    MaskingPolicy,
    PolicyError,
    RedactionPolicy,
    SensitiveFieldPreset,
    Sensitivity,
    internal::canonicalize_field_name,
};

/// Mutable construction state for an immutable [`RedactionPolicy`].
#[must_use]
#[derive(Debug, Clone)]
pub struct RedactionPolicyBuilder {
    /// Canonical sensitive fields and their levels.
    sensitive: BTreeMap<String, Sensitivity>,
    /// Canonical exact-only allow rules.
    allow_exact: BTreeSet<String>,
    /// Canonical suffix allow rules.
    allow_suffix: BTreeSet<String>,
    /// Candidate-generation breadth for sensitive rules.
    matching: FieldNameMatching,
    /// Value masks selected by sensitivity level.
    masking: MaskingPolicy,
    /// Limits applied to diagnostics rendered with the built policy.
    diagnostic_budget: DiagnosticBudget,
    /// First validation error observed while canonicalizing rules.
    error: Option<PolicyError>,
}

impl RedactionPolicyBuilder {
    /// Creates a builder without sensitive or allow rules.
    ///
    /// # Returns
    ///
    /// Empty construction state with default matching, masks, and diagnostic
    /// limits.
    #[inline]
    pub fn new() -> Self {
        Self::empty()
    }

    /// Creates a builder with no field rules and default masks.
    ///
    /// # Returns
    ///
    /// Empty construction state using token-suffix matching.
    #[inline]
    pub(crate) fn empty() -> Self {
        Self {
            sensitive: BTreeMap::new(),
            allow_exact: BTreeSet::new(),
            allow_suffix: BTreeSet::new(),
            matching: FieldNameMatching::ExactOrTokenSuffix,
            masking: MaskingPolicy::default(),
            diagnostic_budget: DiagnosticBudget::default(),
            error: None,
        }
    }

    /// Replaces this builder with the current default policy snapshot.
    ///
    /// # Returns
    ///
    /// A mutable copy of `RedactionPolicy::default`.
    ///
    /// # Warning
    ///
    /// This replaces every builder component, including prior rules, matching,
    /// masks, diagnostic budget, and recorded validation error. Call this
    /// method before adding application-specific configuration.
    #[inline]
    pub fn load_default(self) -> Self {
        Self::from_policy(&RedactionPolicy::default())
    }

    /// Copies complete construction state from an immutable policy.
    ///
    /// # Parameters
    ///
    /// * `policy` - Immutable base policy to copy.
    ///
    /// # Returns
    ///
    /// Mutable construction state initialized from `policy`.
    pub(super) fn from_policy(policy: &RedactionPolicy) -> Self {
        Self {
            sensitive: policy.clone_sensitive(),
            allow_exact: policy.clone_allow_exact(),
            allow_suffix: policy.clone_allow_suffix(),
            matching: policy.matching(),
            masking: policy.masking().clone(),
            diagnostic_budget: policy.diagnostic_budget(),
            error: None,
        }
    }

    /// Validates one field name using the builder's canonicalization rules.
    ///
    /// # Parameters
    ///
    /// * `field` - Raw field name to canonicalize and validate.
    ///
    /// # Returns
    ///
    /// `Ok(())` when the name remains non-empty after canonicalization.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::EmptyFieldName`] when canonicalization removes
    /// every character.
    pub fn validate_field_name(field: &str) -> Result<(), PolicyError> {
        Self::checked_canonical_field(field).map(|_| ())
    }

    /// Sets the candidate-generation breadth for sensitive rules.
    ///
    /// # Parameters
    ///
    /// * `matching` - Matching mode used by the built policy.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[inline(always)]
    pub const fn matching(mut self, matching: FieldNameMatching) -> Self {
        self.matching = matching;
        self
    }

    /// Adds every rule from one predefined field group.
    ///
    /// Existing rules retain the stronger sensitivity level.
    ///
    /// # Parameters
    ///
    /// * `preset` - Predefined field group to merge.
    ///
    /// # Returns
    ///
    /// The updated builder.
    pub fn include_preset(mut self, preset: SensitiveFieldPreset) -> Self {
        for &(field, level) in preset.fields() {
            self = self.raise(field, level);
        }
        self
    }

    /// Raises one field to at least the requested sensitivity.
    ///
    /// # Parameters
    ///
    /// * `field` - Field name to canonicalize and classify.
    /// * `requested` - Minimum sensitivity for the field.
    ///
    /// # Returns
    ///
    /// The updated builder, retaining any stronger existing level.
    pub fn raise(mut self, field: &str, requested: Sensitivity) -> Self {
        let Some(field) = self.canonical_field(field) else {
            return self;
        };
        self.sensitive
            .entry(field)
            .and_modify(|existing| *existing = (*existing).max(requested))
            .or_insert(requested);
        self
    }

    /// Replaces the exact rule for one field with the requested sensitivity.
    ///
    /// # Parameters
    ///
    /// * `field` - Field name to canonicalize and classify.
    /// * `level` - Replacement sensitivity level.
    ///
    /// # Returns
    ///
    /// The updated builder.
    pub fn override_level(mut self, field: &str, level: Sensitivity) -> Self {
        let Some(field) = self.canonical_field(field) else {
            return self;
        };
        self.sensitive.insert(field, level);
        self
    }

    /// Adds an allow rule that applies only to a complete field name.
    ///
    /// The allow rule may coexist with a sensitive rule and wins when both
    /// match the complete canonical candidate.
    ///
    /// # Parameters
    ///
    /// * `field` - Field name to canonicalize and allow exactly.
    ///
    /// # Returns
    ///
    /// The updated builder.
    pub fn allow_exact(mut self, field: &str) -> Self {
        let Some(field) = self.canonical_field(field) else {
            return self;
        };
        self.allow_exact.insert(field);
        self
    }

    /// Adds a broad allow rule that applies at token-suffix boundaries.
    ///
    /// # Parameters
    ///
    /// * `field` - Field name to canonicalize and allow as a suffix.
    ///
    /// # Returns
    ///
    /// The updated builder.
    pub fn allow_suffix(mut self, field: &str) -> Self {
        let Some(field) = self.canonical_field(field) else {
            return self;
        };
        self.allow_suffix.insert(field);
        self
    }

    /// Removes one exact allow rule.
    ///
    /// # Parameters
    ///
    /// * `field` - Field name to canonicalize and remove from exact rules.
    ///
    /// # Returns
    ///
    /// The updated builder. Removing an absent rule has no effect.
    pub fn remove_allow_exact(mut self, field: &str) -> Self {
        let Some(field) = self.canonical_field(field) else {
            return self;
        };
        self.allow_exact.remove(&field);
        self
    }

    /// Removes one token-suffix allow rule.
    ///
    /// # Parameters
    ///
    /// * `field` - Field name to canonicalize and remove from suffix rules.
    ///
    /// # Returns
    ///
    /// The updated builder. Removing an absent rule has no effect.
    pub fn remove_allow_suffix(mut self, field: &str) -> Self {
        let Some(field) = self.canonical_field(field) else {
            return self;
        };
        self.allow_suffix.remove(&field);
        self
    }

    /// Removes every exact and token-suffix allow rule.
    ///
    /// # Returns
    ///
    /// The updated builder without allow-rule exceptions.
    pub fn clear_allow_rules(mut self) -> Self {
        self.allow_exact.clear();
        self.allow_suffix.clear();
        self
    }

    /// Replaces the mask assigned to one sensitivity level.
    ///
    /// # Parameters
    ///
    /// * `level` - Sensitivity level whose mask is replaced.
    /// * `policy` - Replacement mask policy.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[inline]
    pub fn mask(mut self, level: Sensitivity, policy: MaskPolicy) -> Self {
        self.masking = self.masking.with_policy(level, policy);
        self
    }

    /// Replaces the hard limits for diagnostics rendered with this policy.
    ///
    /// # Parameters
    ///
    /// * `budget` - Replacement diagnostic input and output limits.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[inline(always)]
    pub const fn diagnostic_budget(mut self, budget: DiagnosticBudget) -> Self {
        self.diagnostic_budget = budget;
        self
    }

    /// Validates and builds an immutable redaction policy.
    ///
    /// # Returns
    ///
    /// `Ok(policy)` when all rules and masks are valid.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::EmptyFieldName`] for a field name that
    /// canonicalizes to empty, or [`PolicyError::EmptyFixedReplacement`] when
    /// a fixed mask has an empty replacement.
    pub fn build(self) -> Result<RedactionPolicy, PolicyError> {
        if let Some(error) = self.error.clone() {
            return Err(error);
        }
        for level in [
            Sensitivity::Low,
            Sensitivity::Medium,
            Sensitivity::High,
            Sensitivity::Secret,
        ] {
            if matches!(
                self.masking.for_level(level),
                MaskPolicy::Fixed { replacement } if replacement.is_empty()
            ) {
                return Err(PolicyError::EmptyFixedReplacement { level });
            }
        }
        Ok(self.into_policy())
    }

    /// Converts builder state into an immutable policy without validation.
    ///
    /// This is used only after validation or for compile-time built-in rules.
    ///
    /// # Returns
    ///
    /// An immutable policy sharing the complete constructed state.
    pub(super) fn into_policy(self) -> RedactionPolicy {
        RedactionPolicy::from_parts(
            self.sensitive,
            self.allow_exact,
            self.allow_suffix,
            self.matching,
            self.masking,
            self.diagnostic_budget,
        )
    }

    /// Canonicalizes a rule field and records an empty-name error.
    ///
    /// # Parameters
    ///
    /// * `field` - Raw field name to canonicalize.
    ///
    /// # Returns
    ///
    /// `Some(canonical)` for a non-empty name, otherwise `None` after storing
    /// the first [`PolicyError::EmptyFieldName`].
    fn canonical_field(&mut self, field: &str) -> Option<String> {
        match Self::checked_canonical_field(field) {
            Ok(canonical) => Some(canonical),
            Err(error) => {
                self.error.get_or_insert(error);
                None
            }
        }
    }

    /// Canonicalizes one field name and rejects an empty result.
    ///
    /// # Parameters
    ///
    /// * `field` - Raw field name to canonicalize.
    ///
    /// # Returns
    ///
    /// The canonical field name when it is non-empty.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::EmptyFieldName`] when canonicalization removes
    /// every character.
    fn checked_canonical_field(field: &str) -> Result<String, PolicyError> {
        let canonical = canonicalize_field_name(field);
        if canonical.is_empty() {
            Err(PolicyError::EmptyFieldName)
        } else {
            Ok(canonical.into_owned())
        }
    }
}

impl Default for RedactionPolicyBuilder {
    /// Creates the same empty construction state as [`Self::new`].
    ///
    /// # Returns
    ///
    /// A builder with no sensitive or allow rules.
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
