// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
// =============================================================================
//! Immutable rule components of redaction policies.

use std::{
    collections::{BTreeMap, BTreeSet},
    ops::ControlFlow,
    sync::Arc,
};

use crate::policy::{
    AllowRule, FieldClassification, FieldMatchKind, FieldNameMatching, MaskingPolicy,
    SensitiveFieldRule, Sensitivity, UnknownFieldPolicy,
    internal::{RedactionPolicyInner, visit_canonical_field_candidates},
};

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RedactionRules {
    /// Shared canonical rule state.
    inner: Arc<RedactionPolicyInner>,
}

impl RedactionRules {
    /// Creates immutable rules from complete rule-state fields.
    #[inline]
    pub(crate) fn new(inner: RedactionPolicyInner) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }

    /// Classifies `field` and returns the configured rule that decided it.
    ///
    /// # Parameters
    ///
    /// * `field` - Raw field name to classify.
    ///
    /// # Returns
    ///
    /// The rule for the first matching candidate, or unknown when no rule
    /// matches.
    pub(crate) fn classify_field<'a>(&'a self, field: &str) -> FieldClassification<'a> {
        self.classify_field_with_matching(field, self.inner.matching)
    }

    /// Resolves sensitivity using the configured matching strategy.
    ///
    /// # Parameters
    ///
    /// * `field` - Raw field name to classify.
    ///
    /// # Returns
    ///
    /// Sensitivity for one field, or none when it is allowed or unknown.
    pub(crate) fn sensitivity_for(&self, field: &str) -> Option<Sensitivity> {
        self.effective_sensitivity(self.classify_field(field))
    }

    /// Classifies a field using an explicit canonical candidate strategy.
    ///
    /// # Parameters
    ///
    /// * `field` - Raw field name to classify.
    /// * `matching` - Exact-only or exact-or-suffix candidate generation.
    ///
    /// # Returns
    ///
    /// The first matching rule in candidate order, or unknown.
    pub(crate) fn classify_field_with_matching<'a>(
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

    /// Resolves sensitivity for one complete canonical candidate.
    ///
    /// This path is used by adapters that must avoid token-suffix fallback.
    ///
    /// # Parameters
    ///
    /// * `field` - Raw field name to classify.
    ///
    /// # Returns
    ///
    /// Sensitive level, none when unknown or explicitly allowed.
    pub(crate) fn sensitivity_for_exact(&self, field: &str) -> Option<Sensitivity> {
        self.effective_sensitivity(
            self.classify_field_with_matching(field, FieldNameMatching::Exact),
        )
    }

    /// Returns the configured matching strategy.
    #[inline(always)]
    pub(crate) fn matching(&self) -> FieldNameMatching {
        self.inner.matching
    }

    /// Returns the configured behavior for unknown fields.
    #[inline(always)]
    pub(crate) fn unknown_field_policy(&self) -> UnknownFieldPolicy {
        self.inner.unknown_field_policy
    }

    /// Returns the masking policy for all sensitivity levels.
    #[inline(always)]
    pub(crate) fn masking(&self) -> &MaskingPolicy {
        &self.inner.masking
    }

    /// Iterates configured sensitive rules in canonical order.
    pub(crate) fn sensitive_rules(&self) -> impl Iterator<Item = SensitiveFieldRule<'_>> {
        self.inner
            .sensitive
            .iter()
            .map(|(field, sensitivity)| SensitiveFieldRule::new(field, *sensitivity))
    }

    /// Iterates allow rules: exact first then suffix candidates.
    pub(crate) fn allow_rules(&self) -> impl Iterator<Item = AllowRule<'_>> {
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

    /// Clones sensitive rules for a new builder.
    #[inline]
    pub(crate) fn clone_sensitive(&self) -> BTreeMap<String, Sensitivity> {
        self.inner.sensitive.clone()
    }

    /// Clones exact-allow rules for a new builder.
    #[inline]
    pub(crate) fn clone_allow_exact(&self) -> BTreeSet<String> {
        self.inner.allow_exact.clone()
    }

    /// Clones suffix-allow rules for a new builder.
    #[inline]
    pub(crate) fn clone_allow_suffix(&self) -> BTreeSet<String> {
        self.inner.allow_suffix.clone()
    }

    /// Resolves fallback behavior after explicit candidate traversal.
    #[inline(always)]
    fn effective_sensitivity(
        &self,
        classification: FieldClassification<'_>,
    ) -> Option<Sensitivity> {
        match classification {
            FieldClassification::Sensitive { rule, .. } => Some(rule.sensitivity()),
            FieldClassification::Allowed { .. } => None,
            FieldClassification::Unknown => self.unknown_field_policy().sensitivity(),
        }
    }
}
