// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable builder for immutable redaction policies.

#[cfg(feature = "json")]
use super::JsonDepthBudget;
use super::{
    DiagnosticBudget,
    FieldNameMatching,
    MaskPolicy,
    PolicyError,
    PolicyLocation,
    RedactionFloor,
    RedactionFloorState,
    RedactionPolicy,
    RedactionRules,
    RedactionRulesBuilder,
    SensitiveFieldPreset,
    Sensitivity,
    UnknownFieldPolicy,
};

/// Mutable construction state for an immutable [`RedactionPolicy`].
#[must_use]
#[derive(Debug, Clone)]
pub struct RedactionPolicyBuilder {
    rules: RedactionRulesBuilder,
    floor: Option<RedactionFloor>,
    floor_state: RedactionFloorState,
    diagnostic_budget: DiagnosticBudget,
    #[cfg(feature = "json")]
    json_depth_budget: JsonDepthBudget,
}

impl RedactionPolicyBuilder {
    /// Creates an empty application-rule builder that snapshots the global
    /// floor now.
    pub fn new() -> Self {
        Self {
            rules: RedactionRulesBuilder::empty(PolicyLocation::Rules),
            floor: Some(RedactionFloor::global_default()),
            floor_state: RedactionFloorState::GlobalDefault,
            diagnostic_budget: DiagnosticBudget::default(),
            #[cfg(feature = "json")]
            json_depth_budget: JsonDepthBudget::default(),
        }
    }
    pub(super) fn from_policy(policy: &RedactionPolicy) -> Self {
        Self {
            rules: RedactionRulesBuilder::from_inner(
                &policy.rules().clone_application(),
                PolicyLocation::Rules,
            ),
            floor: policy.rules().floor().cloned(),
            floor_state: policy.rules().floor_state(),
            diagnostic_budget: policy.diagnostic_budget(),
            #[cfg(feature = "json")]
            json_depth_budget: policy.json_depth_budget(),
        }
    }

    /// Replaces every builder setting with the current default-policy snapshot.
    ///
    /// This discards application rules, limits, floor state, and any deferred
    /// validation error previously recorded by this builder.
    pub fn load_default(self) -> Self {
        Self::from_policy(&RedactionPolicy::default())
    }

    /// Validates that `field` has a non-empty canonical application-rule name.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::EmptyFieldName`] at
    /// [`PolicyLocation::Rules`] when canonicalization leaves no name.
    pub fn validate_field_name(field: &str) -> Result<(), PolicyError> {
        RedactionRulesBuilder::validate_field_name(field, PolicyLocation::Rules)
    }

    /// Replaces the floor snapshot and marks it as explicitly configured.
    ///
    /// This is last-call-wins with [`Self::disable_floor`].
    pub fn floor(mut self, floor: RedactionFloor) -> Self {
        self.floor = Some(floor);
        self.floor_state = RedactionFloorState::Explicit;
        self
    }
    /// Disables every floor, including an inherited global floor.
    ///
    /// # Security
    ///
    /// This removes minimum field protection. Call it only when this is an
    /// intentional, reviewed decision by the policy owner.
    pub fn disable_floor(mut self) -> Self {
        self.floor = None;
        self.floor_state = RedactionFloorState::Disabled;
        self
    }

    /// Sets application field-name matching behavior.
    pub fn matching(mut self, matching: FieldNameMatching) -> Self {
        self.rules = self.rules.matching(matching);
        self
    }

    /// Sets the application fallback for unclassified fields.
    pub fn unknown_field_policy(mut self, policy: UnknownFieldPolicy) -> Self {
        self.rules = self.rules.unknown_field_policy(policy);
        self
    }

    /// Adds every sensitive field defined by `preset` to application rules.
    pub fn include_preset(mut self, preset: SensitiveFieldPreset) -> Self {
        self.rules = self.rules.include_preset(preset);
        self
    }

    /// Raises application sensitivity for `field` to at least `level`.
    ///
    /// Invalid field names are recorded and returned by [`Self::build`].
    pub fn raise(mut self, field: &str, level: Sensitivity) -> Self {
        self.rules = self.rules.raise(field, level);
        self
    }

    /// Replaces the application sensitivity for `field` with `level`.
    ///
    /// This does not weaken an enabled floor.
    pub fn override_level(mut self, field: &str, level: Sensitivity) -> Self {
        self.rules = self.rules.override_level(field, level);
        self
    }

    /// Allows one canonical exact application field name.
    ///
    /// An enabled floor remains independently effective for the same field.
    pub fn allow_canonical_exact(mut self, field: &str) -> Self {
        self.rules = self.rules.allow_canonical_exact(field);
        self
    }

    /// Allows one application field-name token suffix.
    ///
    /// An enabled floor remains independently effective for matching fields.
    pub fn allow_suffix(mut self, field: &str) -> Self {
        self.rules = self.rules.allow_suffix(field);
        self
    }

    /// Removes the exact application allow rule for `field` when present.
    pub fn remove_allow_canonical_exact(mut self, field: &str) -> Self {
        self.rules = self.rules.remove_allow_canonical_exact(field);
        self
    }

    /// Removes the suffix application allow rule for `field` when present.
    pub fn remove_allow_suffix(mut self, field: &str) -> Self {
        self.rules = self.rules.remove_allow_suffix(field);
        self
    }

    /// Removes every application allow rule.
    pub fn clear_allow_rules(mut self) -> Self {
        self.rules = self.rules.clear_allow_rules();
        self
    }

    /// Sets the application masking policy for values at `level`.
    pub fn mask(mut self, level: Sensitivity, policy: MaskPolicy) -> Self {
        self.rules = self.rules.mask(level, policy);
        self
    }

    /// Sets the ordinary diagnostic input and output limits.
    pub const fn diagnostic_budget(mut self, budget: DiagnosticBudget) -> Self {
        self.diagnostic_budget = budget;
        self
    }

    /// Sets the maximum JSON nesting depth used by JSON redaction.
    #[cfg(feature = "json")]
    pub const fn json_depth_budget(mut self, budget: JsonDepthBudget) -> Self {
        self.json_depth_budget = budget;
        self
    }

    /// Validates and returns the immutable policy snapshot.
    ///
    /// # Errors
    ///
    /// Returns the first deferred [`PolicyError`] from application-rule
    /// validation.
    pub fn build(self) -> Result<RedactionPolicy, PolicyError> {
        let rules = RedactionRules::new(
            self.rules.build_inner()?,
            self.floor,
            self.floor_state,
        );
        Ok(RedactionPolicy::from_rules(
            rules,
            self.diagnostic_budget,
            #[cfg(feature = "json")]
            self.json_depth_budget,
        ))
    }
}

impl Default for RedactionPolicyBuilder {
    fn default() -> Self {
        Self::new()
    }
}
