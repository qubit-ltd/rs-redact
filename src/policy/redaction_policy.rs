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
    ops::ControlFlow,
    sync::{Arc, LazyLock, OnceLock},
};

use super::{
    AllowRule, DiagnosticBudget, FieldClassification, FieldMatchKind, FieldNameMatching,
    GlobalDefaultAlreadySet, MaskingPolicy, RedactionPolicyBuilder, SensitiveFieldPreset,
    SensitiveFieldRule, Sensitivity,
    internal::{RedactionPolicyInner, visit_canonical_field_candidates},
};

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
    inner: Arc<RedactionPolicyInner>,
    /// Limits applied whenever this policy renders a diagnostic.
    diagnostic_budget: DiagnosticBudget,
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

    /// Creates a builder initialized from the current default policy.
    ///
    /// # Returns
    ///
    /// A mutable builder containing a snapshot of the default policy.
    #[inline]
    pub fn builder() -> RedactionPolicyBuilder {
        RedactionPolicyBuilder::new()
    }

    /// Creates a builder without any built-in sensitive fields.
    ///
    /// This weakens the built-in protection baseline and should only be used
    /// when the caller intends to define the complete field set explicitly.
    ///
    /// # Returns
    ///
    /// An empty field-rule builder with default matching and masks.
    #[inline]
    pub fn empty_builder() -> RedactionPolicyBuilder {
        RedactionPolicyBuilder::empty()
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
    /// * `sensitive` - Canonical sensitive fields and levels.
    /// * `allow_exact` - Canonical exact-only allow rules.
    /// * `allow_suffix` - Canonical suffix allow rules.
    /// * `matching` - Sensitive-field matching breadth.
    /// * `masking` - Four-level value-masking policy.
    ///
    /// # Returns
    ///
    /// A cheap-clone immutable policy.
    #[inline(always)]
    pub(super) fn from_parts(
        sensitive: BTreeMap<String, Sensitivity>,
        allow_exact: BTreeSet<String>,
        allow_suffix: BTreeSet<String>,
        matching: FieldNameMatching,
        masking: MaskingPolicy,
        diagnostic_budget: DiagnosticBudget,
    ) -> Self {
        Self {
            inner: Arc::new(RedactionPolicyInner {
                sensitive,
                allow_exact,
                allow_suffix,
                matching,
                masking,
            }),
            diagnostic_budget,
        }
    }

    /// Returns the hard limits for diagnostics rendered with this policy.
    #[must_use = "use the diagnostic budget to bound rendered diagnostics"]
    #[inline(always)]
    pub const fn diagnostic_budget(&self) -> DiagnosticBudget {
        self.diagnostic_budget
    }

    /// Installs the process-wide default policy exactly once.
    ///
    /// The installed immutable policy affects later calls to [`Self::default`]
    /// and [`Self::builder`]. Previously created snapshots remain unchanged.
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
    /// # Parameters
    ///
    /// * `field` - Raw field name to classify.
    ///
    /// # Returns
    ///
    /// A borrowed sensitive or allow rule for the first matching candidate, or
    /// [`FieldClassification::Unknown`] when no rule matches.
    pub fn classify_field<'a>(&'a self, field: &str) -> FieldClassification<'a> {
        self.classify_field_with_matching(field, self.inner.matching)
    }

    /// Resolves the sensitivity configured for `field`.
    ///
    /// # Parameters
    ///
    /// * `field` - Raw field name to classify.
    ///
    /// # Returns
    ///
    /// `Some(level)` for a sensitive classification, or `None` when an allow
    /// rule wins or no rule matches.
    #[must_use]
    #[inline]
    pub fn sensitivity_for(&self, field: &str) -> Option<Sensitivity> {
        self.classify_field(field).sensitivity()
    }

    /// Classifies a field using an explicit candidate-generation breadth.
    ///
    /// # Parameters
    ///
    /// * `field` - Raw field name to classify.
    /// * `matching` - Exact or semantic-suffix candidate generation.
    ///
    /// # Returns
    ///
    /// The first sensitive or allow rule in candidate order, otherwise
    /// [`FieldClassification::Unknown`].
    fn classify_field_with_matching<'a>(
        &'a self,
        field: &str,
        matching: FieldNameMatching,
    ) -> FieldClassification<'a> {
        match visit_canonical_field_candidates(field, matching, |is_exact, candidate| {
            let match_kind = if is_exact {
                FieldMatchKind::Exact
            } else {
                FieldMatchKind::TokenSuffix
            };
            if is_exact && let Some(field) = self.inner.allow_exact.get(candidate) {
                return ControlFlow::Break(FieldClassification::Allowed {
                    rule: AllowRule::new(field, FieldNameMatching::Exact),
                    match_kind,
                });
            }
            if let Some(field) = self.inner.allow_suffix.get(candidate) {
                return ControlFlow::Break(FieldClassification::Allowed {
                    rule: AllowRule::new(field, FieldNameMatching::ExactOrTokenSuffix),
                    match_kind,
                });
            }
            if let Some((field, sensitivity)) = self.inner.sensitive.get_key_value(candidate) {
                return ControlFlow::Break(FieldClassification::Sensitive {
                    rule: SensitiveFieldRule::new(field, *sensitivity),
                    match_kind,
                });
            }
            ControlFlow::Continue(())
        }) {
            ControlFlow::Break(classification) => classification,
            ControlFlow::Continue(()) => FieldClassification::Unknown,
        }
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
    /// `Some(level)` for an exact sensitive rule, or `None` when an allow rule
    /// wins or no exact sensitive rule matches.
    pub(crate) fn sensitivity_for_exact(&self, field: &str) -> Option<Sensitivity> {
        self.classify_field_with_matching(field, FieldNameMatching::Exact)
            .sensitivity()
    }

    /// Returns the configured sensitive-field matching breadth.
    ///
    /// # Returns
    ///
    /// The matching mode used to generate lookup candidates.
    #[inline(always)]
    pub fn matching(&self) -> FieldNameMatching {
        self.inner.matching
    }

    /// Returns the configured value-masking policy.
    ///
    /// # Returns
    ///
    /// The four-level immutable masking configuration.
    #[inline(always)]
    pub fn masking(&self) -> &MaskingPolicy {
        &self.inner.masking
    }

    /// Iterates configured sensitive-field rules in canonical name order.
    ///
    /// # Returns
    ///
    /// Borrowed read-only views of all sensitive-field rules.
    pub fn sensitive_rules(&self) -> impl Iterator<Item = SensitiveFieldRule<'_>> {
        self.inner
            .sensitive
            .iter()
            .map(|(field, sensitivity)| SensitiveFieldRule::new(field, *sensitivity))
    }

    /// Iterates exact allow rules followed by suffix allow rules.
    ///
    /// Each group is ordered by canonical field name.
    ///
    /// # Returns
    ///
    /// Borrowed read-only views of all allow rules.
    pub fn allow_rules(&self) -> impl Iterator<Item = AllowRule<'_>> {
        let exact = self
            .inner
            .allow_exact
            .iter()
            .map(|field| AllowRule::new(field, FieldNameMatching::Exact));
        let suffix = self
            .inner
            .allow_suffix
            .iter()
            .map(|field| AllowRule::new(field, FieldNameMatching::ExactOrTokenSuffix));
        exact.chain(suffix)
    }

    /// Clones the canonical sensitive-field map for a new builder.
    ///
    /// # Returns
    ///
    /// An owned copy of all sensitive-field rules.
    pub(super) fn clone_sensitive(&self) -> BTreeMap<String, Sensitivity> {
        self.inner.sensitive.clone()
    }

    /// Clones the exact allow-rule set for a new builder.
    ///
    /// # Returns
    ///
    /// An owned copy of all exact allow rules.
    pub(super) fn clone_allow_exact(&self) -> BTreeSet<String> {
        self.inner.allow_exact.clone()
    }

    /// Clones the suffix allow-rule set for a new builder.
    ///
    /// # Returns
    ///
    /// An owned copy of all suffix allow rules.
    pub(super) fn clone_allow_suffix(&self) -> BTreeSet<String> {
        self.inner.allow_suffix.clone()
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
