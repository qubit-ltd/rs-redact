// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Immutable field-classification and masking policy.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{LazyLock, OnceLock},
};

use super::{
    AllowRule, DiagnosticBudget, FieldClassification, FieldNameMatching, GlobalDefaultAlreadySet,
    MaskingPolicy, RedactionPolicyBuilder, SensitiveFieldPreset, SensitiveFieldRule, Sensitivity,
    UnknownFieldPolicy, internal::RedactionPolicyInner, redaction_limits::RedactionLimits,
};

#[cfg(feature = "json")]
use super::json_depth_budget::JsonDepthBudget;
use super::redaction_rules::RedactionRules;

/// Built-in sensitive fields not owned by a named preset.
const STANDARD_EXTRA_FIELDS: &[(&str, Sensitivity)] = &[
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

/// Lazily initialized built-in conservative policy.
static STANDARD_POLICY: LazyLock<RedactionPolicy> = LazyLock::new(RedactionPolicy::build_standard);

/// Process-wide default policy installed at most once.
static GLOBAL_DEFAULT: OnceLock<RedactionPolicy> = OnceLock::new();

/// Immutable field-classification and value-masking policy.
///
/// Cloning a policy shares its complete configuration and has constant cost.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionPolicy {
    /// Shared immutable policy state.
    rules: RedactionRules,
    /// Limits applied whenever this policy renders a diagnostic.
    limits: RedactionLimits,
}

impl RedactionPolicy {
    /// Returns the built-in conservative policy.
    ///
    /// # Returns
    ///
    /// A policy containing every built-in preset and extra sensitive field.
    #[inline(always)]
    pub fn standard() -> Self {
        STANDARD_POLICY.clone()
    }

    /// Returns a snapshot of the process-wide default policy.
    ///
    /// Before a custom default is installed, this returns a new shared handle
    /// to the built-in [`Self::standard`] policy. The returned snapshot never
    /// changes after a later installation.
    ///
    /// # Returns
    ///
    /// A shared immutable snapshot of the current process-wide default.
    #[inline]
    pub fn global_default() -> Self {
        GLOBAL_DEFAULT.get().cloned().unwrap_or_else(Self::standard)
    }

    /// Creates a builder without sensitive or allow rules.
    ///
    /// # Returns
    ///
    /// A mutable builder with default matching, masking, and diagnostic limits.
    #[inline]
    pub fn builder() -> RedactionPolicyBuilder {
        RedactionPolicyBuilder::new()
    }

    /// Creates a builder initialized from the current default policy.
    ///
    /// # Returns
    ///
    /// A mutable builder containing a snapshot of the current default policy.
    #[inline]
    pub fn builder_from_default() -> RedactionPolicyBuilder {
        RedactionPolicyBuilder::from_policy(&Self::default())
    }

    /// Creates a builder by copying one immutable policy snapshot.
    ///
    /// # Parameters
    ///
    /// * `base` - Policy whose complete configuration is copied.
    ///
    /// # Returns
    ///
    /// A mutable builder initialized from `base`.
    #[inline]
    pub fn builder_from(base: &Self) -> RedactionPolicyBuilder {
        RedactionPolicyBuilder::from_policy(base)
    }

    /// Constructs the built-in policy without consulting `Default`.
    ///
    /// # Returns
    ///
    /// The complete built-in conservative policy.
    pub(super) fn build_standard() -> Self {
        let mut builder = RedactionPolicyBuilder::empty();
        for preset in [
            SensitiveFieldPreset::Credentials,
            SensitiveFieldPreset::CredentialContainers,
            SensitiveFieldPreset::AuthTokens,
            SensitiveFieldPreset::Http,
            SensitiveFieldPreset::Session,
        ] {
            builder = builder.include_preset(preset);
        }
        for &(field, level) in STANDARD_EXTRA_FIELDS {
            builder = builder.raise(field, level);
        }
        builder.into_policy()
    }

    /// Creates an immutable policy from validated builder components.
    ///
    /// # Parameters
    ///
    /// * `inner` - Complete field-classification and masking configuration.
    /// * `diagnostic_budget` - Input and output limits for diagnostics.
    /// * `json_depth_budget` - Maximum JSON recursion depth when enabled.
    ///
    /// # Returns
    ///
    /// A cheap-clone immutable policy.
    #[inline(always)]
    pub(super) fn from_parts(
        inner: RedactionPolicyInner,
        diagnostic_budget: DiagnosticBudget,
        #[cfg(feature = "json")] json_depth_budget: JsonDepthBudget,
    ) -> Self {
        Self {
            rules: RedactionRules::new(inner),
            limits: RedactionLimits::new(
                diagnostic_budget,
                #[cfg(feature = "json")]
                json_depth_budget,
            ),
        }
    }

    /// Returns the hard limits for diagnostics rendered with this policy.
    ///
    /// # Returns
    ///
    /// The immutable diagnostic input and output budget.
    #[must_use = "use the diagnostic budget to bound rendered diagnostics"]
    #[inline(always)]
    pub const fn diagnostic_budget(&self) -> DiagnosticBudget {
        self.limits.diagnostic_budget()
    }

    /// Returns the hard recursion-depth limit for JSON redaction.
    ///
    /// # Returns
    ///
    /// The immutable positive JSON depth budget.
    #[cfg(feature = "json")]
    #[must_use = "use the JSON depth budget to bound recursive traversal"]
    #[inline(always)]
    pub const fn json_depth_budget(&self) -> JsonDepthBudget {
        self.limits.json_depth_budget()
    }

    /// Installs the process-wide default policy exactly once.
    ///
    /// The installed immutable policy affects later calls to [`Self::default`]
    /// and [`RedactionPolicyBuilder::load_default`]. Previously created
    /// snapshots remain unchanged.
    ///
    /// # Parameters
    ///
    /// * `policy` - Immutable policy to install as the process-wide default.
    ///
    /// # Returns
    ///
    /// `Ok(())` when this call installs the process-wide default.
    ///
    /// # Errors
    ///
    /// Returns [`GlobalDefaultAlreadySet`] when a policy was installed by an
    /// earlier successful call. The existing policy is never replaced.
    #[inline]
    pub fn set_global_default(policy: Self) -> Result<(), GlobalDefaultAlreadySet> {
        GLOBAL_DEFAULT
            .set(policy)
            .map_err(|_| GlobalDefaultAlreadySet)
    }

    /// Classifies `field` and returns the configured rule that decided it.
    ///
    /// Candidates are examined from the complete canonical name to shorter
    /// semantic token suffixes. An allow rule wins over a sensitive rule at
    /// the same candidate, but exact allow rules apply only to the complete
    /// input candidate.
    ///
    /// # Type Parameters
    ///
    /// * `'a` - Lifetime of rules borrowed from this policy in the result.
    ///
    /// # Parameters
    ///
    /// * `field` - Raw field name to classify.
    ///
    /// # Returns
    ///
    /// A borrowed sensitive or allow rule for the first matching candidate, or
    /// [`FieldClassification::Unknown`] when no rule matches.
    pub fn classify_field<'a>(&'a self, field: &str) -> FieldClassification<'a> {
        self.rules.classify_field(field)
    }

    /// Resolves the sensitivity configured for `field`.
    ///
    /// # Parameters
    ///
    /// * `field` - Raw field name to classify.
    ///
    /// # Returns
    ///
    /// `Some(level)` for a sensitive classification or configured unknown-field
    /// fallback, or `None` when an allow rule wins or the fallback passes
    /// unknown fields through.
    #[must_use]
    #[inline]
    pub fn sensitivity_for(&self, field: &str) -> Option<Sensitivity> {
        self.rules.sensitivity_for(field)
    }

    /// Resolves sensitivity only for the complete canonical field name.
    ///
    /// This restricted lookup supports syntax adapters that must not interpret
    /// compact values as semantic field-name suffixes.
    ///
    /// # Parameters
    ///
    /// * `field` - Raw field name to classify exactly.
    ///
    /// # Returns
    ///
    /// `Some(level)` for an exact sensitive rule or configured unknown-field
    /// fallback, or `None` when an allow rule wins or the fallback passes
    /// unknown fields through.
    pub(crate) fn sensitivity_for_exact(&self, field: &str) -> Option<Sensitivity> {
        self.rules.sensitivity_for_exact(field)
    }

    /// Returns the configured sensitive-field matching breadth.
    ///
    /// # Returns
    ///
    /// The matching mode used to generate lookup candidates.
    #[inline(always)]
    pub fn matching(&self) -> FieldNameMatching {
        self.rules.matching()
    }

    /// Returns fallback behavior for fields with no matching rule.
    ///
    /// # Returns
    ///
    /// The immutable unknown-field policy configured for this snapshot.
    #[inline(always)]
    pub fn unknown_field_policy(&self) -> UnknownFieldPolicy {
        self.rules.unknown_field_policy()
    }

    /// Returns the configured value-masking policy.
    ///
    /// # Returns
    ///
    /// The four-level immutable masking configuration.
    #[inline(always)]
    pub fn masking(&self) -> &MaskingPolicy {
        self.rules.masking()
    }

    /// Iterates configured sensitive-field rules in canonical name order.
    ///
    /// # Returns
    ///
    /// Borrowed read-only views of all sensitive-field rules.
    pub fn sensitive_rules(&self) -> impl Iterator<Item = SensitiveFieldRule<'_>> {
        self.rules.sensitive_rules()
    }

    /// Iterates exact allow rules followed by suffix allow rules.
    ///
    /// Each group is ordered by canonical field name.
    ///
    /// # Returns
    ///
    /// Borrowed read-only views of all allow rules.
    pub fn allow_rules(&self) -> impl Iterator<Item = AllowRule<'_>> {
        self.rules.allow_rules()
    }

    /// Clones the canonical sensitive-field map for a new builder.
    ///
    /// # Returns
    ///
    /// An owned copy of all sensitive-field rules.
    pub(super) fn clone_sensitive(&self) -> BTreeMap<String, Sensitivity> {
        self.rules.clone_sensitive()
    }

    /// Clones the exact allow-rule set for a new builder.
    ///
    /// # Returns
    ///
    /// An owned copy of all exact allow rules.
    pub(super) fn clone_allow_exact(&self) -> BTreeSet<String> {
        self.rules.clone_allow_exact()
    }

    /// Clones the suffix allow-rule set for a new builder.
    ///
    /// # Returns
    ///
    /// An owned copy of all suffix allow rules.
    pub(super) fn clone_allow_suffix(&self) -> BTreeSet<String> {
        self.rules.clone_allow_suffix()
    }
}

impl Default for RedactionPolicy {
    /// Returns a snapshot of the current process-wide default policy.
    ///
    /// # Returns
    ///
    /// The installed global configuration, or [`RedactionPolicy::standard`]
    /// before a custom default is installed.
    #[inline(always)]
    fn default() -> Self {
        Self::global_default()
    }
}
