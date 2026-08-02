// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Immutable field-classification, masking, and diagnostic policy.

use std::sync::{
    Arc,
    LazyLock,
};

#[cfg(feature = "json")]
use super::JsonDepthBudget;
use super::redaction_limits::RedactionLimits;
use super::{
    AllowRule,
    DiagnosticBudget,
    FieldClassification,
    FieldNameMatching,
    MaskingPolicy,
    RedactionFloor,
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
            },
            Some(RedactionFloor::standard()),
        ),
        MaskingPolicy::default(),
        DiagnosticBudget::default(),
        #[cfg(feature = "json")]
        JsonDepthBudget::default(),
    )
});
static STRICT_POLICY: LazyLock<RedactionPolicy> = LazyLock::new(|| {
    RedactionPolicy::from_rules(
        RedactionRules::new(
            RedactionPolicyInner {
                sensitive: Default::default(),
                allow_exact: Default::default(),
                allow_suffix: Default::default(),
                matching: FieldNameMatching::ExactOrTokenSuffix,
                unknown_field_policy: UnknownFieldPolicy::Redact(
                    Sensitivity::Secret,
                ),
            },
            Some(RedactionFloor::standard()),
        ),
        MaskingPolicy::default(),
        DiagnosticBudget::default(),
        #[cfg(feature = "json")]
        JsonDepthBudget::default(),
    )
});
/// Immutable redaction policy.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionPolicy {
    rules: RedactionRules,
    masking: Arc<MaskingPolicy>,
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

    /// Returns a strict boundary policy whose unknown fields are masked at
    /// [`Sensitivity::Secret`] in addition to the standard floor.
    ///
    /// This preset is intended for untrusted external boundaries. It is more
    /// protective than [`Self::standard`] but may reduce diagnostic detail.
    #[inline]
    pub fn strict() -> Self {
        STRICT_POLICY.clone()
    }

    /// Creates a deterministic builder with no application rules and the
    /// standard minimum-protection floor.
    #[inline]
    pub fn builder() -> RedactionPolicyBuilder {
        RedactionPolicyBuilder::new()
    }

    /// Creates a builder that exactly copies `self`.
    ///
    /// The copy includes application rules, limits, and the attached floor.
    #[inline]
    pub fn to_builder(&self) -> RedactionPolicyBuilder {
        RedactionPolicyBuilder::from_policy(self)
    }

    /// Creates a builder that exactly copies `base`.
    #[inline]
    pub fn builder_from(base: &Self) -> RedactionPolicyBuilder {
        base.to_builder()
    }

    /// Creates a policy from fully resolved field rules and resource limits.
    pub(crate) fn from_rules(
        rules: RedactionRules,
        masking: MaskingPolicy,
        diagnostic_budget: DiagnosticBudget,
        #[cfg(feature = "json")] json_depth_budget: JsonDepthBudget,
    ) -> Self {
        Self {
            rules,
            masking: Arc::new(masking),
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

    /// Resolves final sensitivity with exact-only field matching.
    #[inline]
    pub(crate) fn resolve_field_exact(
        &self,
        field: &str,
    ) -> super::ResolvedField {
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
    /// Returns the single mask table used by every sensitivity decision.
    ///
    /// Field classification determines the effective sensitivity; this table
    /// determines how that sensitivity is rendered. Floors never own a second
    /// mask table.
    #[inline]
    pub fn masking(&self) -> &MaskingPolicy {
        self.masking.as_ref()
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

    /// Resolves final sensitivity for `field`.
    #[inline]
    pub(crate) fn resolve_field(&self, field: &str) -> super::ResolvedField {
        self.rules.resolve_field(field)
    }
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        crate::GlobalRedactionConfig::current().policy().clone()
    }
}
