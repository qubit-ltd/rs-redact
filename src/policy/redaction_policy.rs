// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Immutable field-classification, masking, and diagnostic policy.

use std::sync::{
    LazyLock,
    OnceLock,
};

#[cfg(feature = "json")]
use super::JsonDepthBudget;
use super::redaction_limits::RedactionLimits;
use super::{
    AllowRule,
    DiagnosticBudget,
    FieldClassification,
    FieldNameMatching,
    GlobalDefaultAlreadySet,
    MaskingPolicy,
    RedactionFloor,
    RedactionFloorState,
    RedactionPolicyBuilder,
    RedactionRules,
    SensitiveFieldRule,
    Sensitivity,
    UnknownFieldPolicy,
    internal::RedactionPolicyInner,
};

/// Built-in sensitive fields not owned by a named preset.
pub(super) const STANDARD_EXTRA_FIELDS: &[(&str, Sensitivity)] = &[
    ("auth_app_token", Sensitivity::High),
    ("auth_user_token", Sensitivity::High),
    ("connection_string", Sensitivity::Secret),
    ("database_uri", Sensitivity::Secret),
    ("database_url", Sensitivity::Secret),
    ("license_key", Sensitivity::Medium),
    ("mysql_pwd", Sensitivity::Secret),
    ("rediscli_auth", Sensitivity::Secret),
    ("sig", Sensitivity::Secret),
    ("signature", Sensitivity::Secret),
];

static STANDARD_POLICY: LazyLock<RedactionPolicy> = LazyLock::new(|| {
    RedactionPolicy::from_rules(
        RedactionRules::new(
            RedactionPolicyInner {
                sensitive: Default::default(),
                allow_exact: Default::default(),
                allow_suffix: Default::default(),
                matching: FieldNameMatching::ExactOrTokenSuffix,
                unknown_field_policy: UnknownFieldPolicy::PassThrough,
                masking: MaskingPolicy::default(),
            },
            Some(RedactionFloor::standard()),
            RedactionFloorState::Explicit,
        ),
        DiagnosticBudget::default(),
        #[cfg(feature = "json")]
        JsonDepthBudget::default(),
    )
});
static GLOBAL_DEFAULT: OnceLock<RedactionPolicy> = OnceLock::new();

/// Immutable redaction policy.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionPolicy {
    rules: RedactionRules,
    limits: RedactionLimits,
}

impl RedactionPolicy {
    /// Returns the fixed built-in conservative policy.
    ///
    /// Its application rules are empty and its explicit floor is
    /// [`RedactionFloor::standard`], so it never observes later process-wide
    /// default installations.
    #[inline]
    pub fn standard() -> Self {
        STANDARD_POLICY.clone()
    }

    /// Returns a snapshot of the process-wide application-policy default.
    ///
    /// Before installation, this returns [`Self::standard`]. A returned policy
    /// is immutable and does not change after a later installation.
    #[inline]
    pub fn global_default() -> Self {
        GLOBAL_DEFAULT.get().cloned().unwrap_or_else(Self::standard)
    }

    /// Creates a builder with no application rules and a global-floor snapshot.
    #[inline]
    pub fn empty_builder() -> RedactionPolicyBuilder {
        RedactionPolicyBuilder::new()
    }

    /// Creates a builder that exactly copies the current default-policy
    /// snapshot.
    ///
    /// Use this to extend the default application's rules, limits, and floor
    /// state rather than starting with empty application rules.
    #[inline]
    pub fn builder_from_default() -> RedactionPolicyBuilder {
        RedactionPolicyBuilder::from_policy(&Self::default())
    }

    /// Creates a builder that exactly copies `base`.
    ///
    /// The copy includes application rules, limits, the attached floor, and
    /// its [`RedactionFloorState`].
    #[inline]
    pub fn builder_from(base: &Self) -> RedactionPolicyBuilder {
        RedactionPolicyBuilder::from_policy(base)
    }

    /// Installs `policy` as the process-wide default exactly once.
    ///
    /// Installation only affects future calls that acquire the global policy;
    /// existing builders, policies, and redactors retain their snapshots.
    ///
    /// # Errors
    ///
    /// Returns [`GlobalDefaultAlreadySet`] when a policy default was already
    /// installed in this process.
    #[inline]
    pub fn set_global_default(
        policy: Self,
    ) -> Result<(), GlobalDefaultAlreadySet> {
        GLOBAL_DEFAULT
            .set(policy)
            .map_err(|_| GlobalDefaultAlreadySet)
    }

    /// Creates a policy from fully resolved field rules and resource limits.
    pub(crate) fn from_rules(
        rules: RedactionRules,
        diagnostic_budget: DiagnosticBudget,
        #[cfg(feature = "json")] json_depth_budget: JsonDepthBudget,
    ) -> Self {
        Self {
            rules,
            limits: RedactionLimits::new(
                diagnostic_budget,
                #[cfg(feature = "json")]
                json_depth_budget,
            ),
        }
    }

    /// Returns the input and output limits for ordinary diagnostics.
    #[inline]
    pub const fn diagnostic_budget(&self) -> DiagnosticBudget {
        self.limits.diagnostic_budget()
    }

    /// Returns the maximum JSON nesting depth for JSON redaction.
    #[cfg(feature = "json")]
    #[inline]
    pub const fn json_depth_budget(&self) -> JsonDepthBudget {
        self.limits.json_depth_budget()
    }
    /// Returns the immutable field rules without diagnostic resource limits.
    #[inline]
    pub const fn rules(&self) -> &RedactionRules {
        &self.rules
    }

    /// Returns the attached minimum floor, or `None` when it was explicitly
    /// disabled.
    #[inline]
    pub fn floor(&self) -> Option<&RedactionFloor> {
        self.rules.floor()
    }

    /// Returns how this policy's current floor snapshot was obtained.
    #[inline]
    pub const fn floor_state(&self) -> RedactionFloorState {
        self.rules.floor_state()
    }

    /// Replaces the floor for this immutable policy.
    pub fn with_floor(mut self, floor: RedactionFloor) -> Self {
        self.rules = self.rules.with_floor(floor);
        self
    }
    /// Disables every floor for this immutable policy.
    ///
    /// # Security
    ///
    /// This explicitly removes minimum protection inherited from any source.
    pub fn disable_floor(mut self) -> Self {
        self.rules = self.rules.disable_floor();
        self
    }

    /// Explains application-rule matching for `field` without applying the
    /// floor.
    ///
    /// This is useful for diagnostics about configured application rules. Use
    /// [`Self::sensitivity_for`] for the final security decision.
    #[inline]
    pub fn classify_field<'a>(
        &'a self,
        field: &str,
    ) -> FieldClassification<'a> {
        self.rules.classify_field(field)
    }

    /// Returns the final sensitivity for `field` after applying application
    /// rules and the enabled floor.
    ///
    /// Returns `None` only when neither layer classifies the field as
    /// sensitive.
    #[inline]
    pub fn sensitivity_for(&self, field: &str) -> Option<Sensitivity> {
        self.rules.sensitivity_for(field)
    }

    /// Resolves final sensitivity with exact-only field matching.
    #[inline]
    pub(crate) fn sensitivity_for_exact(
        &self,
        field: &str,
    ) -> Option<Sensitivity> {
        self.rules.sensitivity_for_exact(field)
    }

    /// Resolves final sensitivity and masking with exact-only field matching.
    #[inline]
    pub(crate) fn resolve_field_exact(
        &self,
        field: &str,
    ) -> super::ResolvedField<'_> {
        self.rules.resolve_field_exact(field)
    }

    /// Returns the application layer's field-name matching mode.
    ///
    /// An attached floor may use a different matching mode for its independent
    /// classification.
    #[inline]
    pub fn matching(&self) -> FieldNameMatching {
        self.rules.matching()
    }

    /// Returns the application layer's fallback for unclassified fields.
    ///
    /// An attached floor applies its own fallback independently.
    #[inline]
    pub fn unknown_field_policy(&self) -> UnknownFieldPolicy {
        self.rules.unknown_field_policy()
    }
    /// Returns application masks; field redaction must use atomic resolution.
    #[inline]
    pub fn masking(&self) -> &MaskingPolicy {
        self.rules.masking()
    }

    /// Iterates sensitive rules configured in the application layer only.
    ///
    /// Use [`Self::floor`] to inspect the independent minimum-protection
    /// rules.
    #[inline]
    pub fn application_sensitive_rules(
        &self,
    ) -> impl Iterator<Item = SensitiveFieldRule<'_>> {
        self.rules.application_sensitive_rules()
    }

    /// Iterates allow rules configured in the application layer only.
    ///
    /// These rules never bypass an enabled floor.
    #[inline]
    pub fn application_allow_rules(
        &self,
    ) -> impl Iterator<Item = AllowRule<'_>> {
        self.rules.application_allow_rules()
    }

    /// Resolves final sensitivity and the correct masking policy for `field`.
    #[inline]
    pub(crate) fn resolve_field(
        &self,
        field: &str,
    ) -> super::ResolvedField<'_> {
        self.rules.resolve_field(field)
    }
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        Self::global_default()
    }
}
