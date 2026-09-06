// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Immutable field rules and their resolved floor protection.

use std::ops::ControlFlow;
use std::sync::Arc;

use super::AllowRule;
use super::FieldClassification;
use super::FieldMatchKind;
use super::FieldNameMatching;
use super::RedactionFloor;
use super::SensitiveFieldRule;
use super::Sensitivity;
use super::UnknownFieldPolicy;
use crate::policy::ResolvedField;
use crate::policy::internal::RedactionPolicyInner;
use crate::policy::internal::visit_canonical_field_candidates;

/// Immutable, cheap-to-clone field classification snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionRules {
    /// Immutable application-owned classification rules.
    application: Arc<RedactionPolicyInner>,
    /// Optional minimum protection evaluated after application rules.
    floor: Option<RedactionFloor>,
}

impl RedactionRules {
    /// Creates immutable rules from application rules and an optional floor.
    #[must_use]
    pub(crate) fn new(application: RedactionPolicyInner, floor: Option<RedactionFloor>) -> Self {
        Self {
            application: Arc::new(application),
            floor,
        }
    }

    /// Returns the attached minimum floor, if enabled.
    #[must_use]
    #[inline]
    pub fn floor(&self) -> Option<&RedactionFloor> {
        self.floor.as_ref()
    }

    /// Replaces the floor for this rules snapshot.
    #[must_use]
    #[inline]
    pub fn with_floor(mut self, floor: RedactionFloor) -> Self {
        self.floor = Some(floor);
        self
    }

    /// Disables all floor protection for this rules snapshot.
    ///
    /// # Security
    ///
    /// This explicitly removes global and configured minimum protection. Use it
    /// only when the caller intentionally accepts responsibility for doing so.
    #[must_use]
    pub fn disable_floor(mut self) -> Self {
        self.floor = None;
        self
    }

    /// Explains application-rule matching only; it is not the final safety
    /// decision.
    #[must_use]
    pub fn classify_field<'a>(&'a self, field: &str) -> FieldClassification<'a> {
        classify_inner(&self.application, field, self.application.matching, true)
    }

    /// Resolves final sensitivity from application and floor layers.
    #[must_use]
    #[inline]
    pub fn sensitivity_for(&self, field: &str) -> Option<Sensitivity> {
        match self.resolve_field(field) {
            ResolvedField::Sensitive { sensitivity } => Some(sensitivity),
            ResolvedField::PassThrough => None,
        }
    }

    /// Resolves final sensitivity using exact-only matching in both layers.
    #[must_use]
    #[inline]
    pub(crate) fn sensitivity_for_exact(&self, field: &str) -> Option<Sensitivity> {
        match self.resolve_field_exact(field) {
            ResolvedField::Sensitive { sensitivity } => Some(sensitivity),
            ResolvedField::PassThrough => None,
        }
    }

    /// Resolves exact-only sensitivity from application and floor rules.
    pub(crate) fn resolve_field_exact(&self, field: &str) -> ResolvedField {
        let application =
            sensitivity_inner(&self.application, field, FieldNameMatching::Exact, true);
        let floor = self.floor.as_ref().and_then(|floor| {
            sensitivity_inner(&floor.inner, field, FieldNameMatching::Exact, false)
        });
        match self.floor.as_ref().zip(floor) {
            Some((_floor, floor_level)) => ResolvedField::Sensitive {
                sensitivity: application.map_or(floor_level, |level| level.max(floor_level)),
            },
            None => match application {
                Some(sensitivity) => ResolvedField::Sensitive { sensitivity },
                None => ResolvedField::PassThrough,
            },
        }
    }

    /// Resolves final sensitivity for `field` exactly once.
    #[inline]
    pub(crate) fn resolve_field(&self, field: &str) -> ResolvedField {
        self.resolve_field_with_matching(field, self.application.matching)
    }

    /// Resolves final sensitivity using `matching` for application rules.
    fn resolve_field_with_matching(
        &self,
        field: &str,
        matching: FieldNameMatching,
    ) -> ResolvedField {
        let application = sensitivity_inner(&self.application, field, matching, true);
        let floor = self
            .floor
            .as_ref()
            .and_then(|floor| sensitivity_inner(&floor.inner, field, floor.inner.matching, false));
        match floor {
            Some(floor_level) => ResolvedField::Sensitive {
                sensitivity: application.map_or(floor_level, |level| level.max(floor_level)),
            },
            None => match application {
                Some(sensitivity) => ResolvedField::Sensitive { sensitivity },
                None => ResolvedField::PassThrough,
            },
        }
    }

    /// Returns the application layer's field-name matching mode.
    #[must_use]
    #[inline]
    pub fn matching(&self) -> FieldNameMatching {
        self.application.matching
    }

    /// Returns the application fallback for unclassified fields.
    #[must_use]
    #[inline]
    pub fn unknown_field_policy(&self) -> UnknownFieldPolicy {
        self.application.unknown_field_policy
    }

    /// Iterates only application sensitive rules, never floor rules.
    pub fn application_sensitive_rules(&self) -> impl Iterator<Item = SensitiveFieldRule<'_>> {
        self.application
            .sensitive
            .iter()
            .map(|(field, level)| SensitiveFieldRule::new(field, *level))
    }

    /// Iterates only application allow rules, never floor rules.
    pub fn application_allow_rules(&self) -> impl Iterator<Item = AllowRule<'_>> {
        self.application
            .allow_exact
            .iter()
            .map(|field| AllowRule::new(field, FieldNameMatching::Exact))
            .chain(
                self.application
                    .allow_suffix
                    .iter()
                    .map(|field| AllowRule::new(field, FieldNameMatching::ExactOrTokenSuffix)),
            )
    }

    /// Clones only the application-rule layer for builder reconstruction.
    pub(crate) fn clone_application(&self) -> RedactionPolicyInner {
        (*self.application).clone()
    }
}

/// Classifies one field against a single rule layer.
#[must_use]
fn classify_inner<'a>(
    inner: &'a RedactionPolicyInner,
    field: &str,
    matching: FieldNameMatching,
    allow: bool,
) -> FieldClassification<'a> {
    match visit_canonical_field_candidates(field, matching, |is_exact, candidate| {
        let match_kind = if is_exact {
            FieldMatchKind::Exact
        } else {
            FieldMatchKind::TokenSuffix
        };
        if allow
            && is_exact
            && let Some(field) = inner.allow_exact.get(candidate)
        {
            return ControlFlow::Break(FieldClassification::Allowed {
                rule: AllowRule::new(field, FieldNameMatching::Exact),
                match_kind,
            });
        }
        if allow && let Some(field) = inner.allow_suffix.get(candidate) {
            return ControlFlow::Break(FieldClassification::Allowed {
                rule: AllowRule::new(field, FieldNameMatching::ExactOrTokenSuffix),
                match_kind,
            });
        }
        if let Some((field, sensitivity)) = inner.sensitive.get_key_value(candidate) {
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

/// Resolves the strongest sensitivity applicable to one field name.
#[must_use]
fn sensitivity_inner(
    inner: &RedactionPolicyInner,
    field: &str,
    matching: FieldNameMatching,
    allow: bool,
) -> Option<Sensitivity> {
    match classify_inner(inner, field, matching, allow) {
        FieldClassification::Allowed { .. } => None,
        FieldClassification::Sensitive { .. } | FieldClassification::Unknown => {
            strongest_sensitive_match(inner, field, matching)
                .or_else(|| inner.unknown_field_policy.sensitivity())
        }
    }
}

/// Returns the strongest sensitivity among every matching field candidate.
#[must_use]
fn strongest_sensitive_match(
    inner: &RedactionPolicyInner,
    field: &str,
    matching: FieldNameMatching,
) -> Option<Sensitivity> {
    let mut strongest: Option<Sensitivity> = None;
    let _ = visit_canonical_field_candidates(field, matching, |_is_exact, candidate| {
        if let Some(level) = inner.sensitive.get(candidate) {
            strongest = Some(strongest.map_or(*level, |current| current.max(*level)));
        }
        ControlFlow::<()>::Continue(())
    });
    strongest
}
