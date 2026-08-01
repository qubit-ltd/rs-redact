// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Immutable field-classification, masking, and diagnostic policy.

use std::sync::{LazyLock, OnceLock};

#[cfg(feature = "json")]
use super::JsonDepthBudget;
use super::redaction_limits::RedactionLimits;
use super::{
    AllowRule, DiagnosticBudget, FieldClassification, FieldNameMatching, GlobalDefaultAlreadySet,
    MaskingPolicy, RedactionFloor, RedactionFloorState, RedactionPolicyBuilder, RedactionRules,
    SensitiveFieldRule, Sensitivity, UnknownFieldPolicy, internal::RedactionPolicyInner,
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
    #[inline]
    pub fn standard() -> Self {
        STANDARD_POLICY.clone()
    }
    #[inline]
    pub fn global_default() -> Self {
        GLOBAL_DEFAULT.get().cloned().unwrap_or_else(Self::standard)
    }
    /// Creates a builder with no application rules and a global-floor snapshot.
    #[inline]
    pub fn empty_builder() -> RedactionPolicyBuilder {
        RedactionPolicyBuilder::new()
    }
    #[inline]
    pub fn builder_from_default() -> RedactionPolicyBuilder {
        RedactionPolicyBuilder::from_policy(&Self::default())
    }
    #[inline]
    pub fn builder_from(base: &Self) -> RedactionPolicyBuilder {
        RedactionPolicyBuilder::from_policy(base)
    }
    #[inline]
    pub fn set_global_default(policy: Self) -> Result<(), GlobalDefaultAlreadySet> {
        GLOBAL_DEFAULT
            .set(policy)
            .map_err(|_| GlobalDefaultAlreadySet)
    }
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
    #[inline]
    pub const fn diagnostic_budget(&self) -> DiagnosticBudget {
        self.limits.diagnostic_budget()
    }
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
    #[inline]
    pub fn floor(&self) -> Option<&RedactionFloor> {
        self.rules.floor()
    }
    #[inline]
    pub const fn floor_state(&self) -> RedactionFloorState {
        self.rules.floor_state()
    }
    /// Replaces the floor for this immutable policy.
    #[must_use]
    pub fn with_floor(mut self, floor: RedactionFloor) -> Self {
        self.rules = self.rules.with_floor(floor);
        self
    }
    /// Disables every floor for this immutable policy.
    ///
    /// # Security
    ///
    /// This explicitly removes minimum protection inherited from any source.
    #[must_use]
    pub fn disable_floor(mut self) -> Self {
        self.rules = self.rules.disable_floor();
        self
    }
    #[inline]
    pub fn classify_field<'a>(&'a self, field: &str) -> FieldClassification<'a> {
        self.rules.classify_field(field)
    }
    #[inline]
    pub fn sensitivity_for(&self, field: &str) -> Option<Sensitivity> {
        self.rules.sensitivity_for(field)
    }
    #[inline]
    pub(crate) fn sensitivity_for_exact(&self, field: &str) -> Option<Sensitivity> {
        self.rules.sensitivity_for_exact(field)
    }
    #[inline]
    pub(crate) fn resolve_field_exact(
        &self,
        field: &str,
    ) -> super::redaction_rules::ResolvedField<'_> {
        self.rules.resolve_field_exact(field)
    }
    #[inline]
    pub fn matching(&self) -> FieldNameMatching {
        self.rules.matching()
    }
    #[inline]
    pub fn unknown_field_policy(&self) -> UnknownFieldPolicy {
        self.rules.unknown_field_policy()
    }
    /// Returns application masks; field redaction must use atomic resolution.
    #[inline]
    pub fn masking(&self) -> &MaskingPolicy {
        self.rules.masking()
    }
    #[inline]
    pub fn application_sensitive_rules(&self) -> impl Iterator<Item = SensitiveFieldRule<'_>> {
        self.rules.application_sensitive_rules()
    }
    #[inline]
    pub fn application_allow_rules(&self) -> impl Iterator<Item = AllowRule<'_>> {
        self.rules.application_allow_rules()
    }
    #[inline]
    pub(crate) fn resolve_field(&self, field: &str) -> super::redaction_rules::ResolvedField<'_> {
        self.rules.resolve_field(field)
    }
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        Self::global_default()
    }
}
