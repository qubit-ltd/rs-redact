// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Immutable field rules and their resolved floor protection.

use std::{ops::ControlFlow, sync::Arc};

use super::{
    AllowRule, FieldClassification, FieldMatchKind, FieldNameMatching, MaskingPolicy,
    RedactionFloor, RedactionFloorState, SensitiveFieldRule, Sensitivity, UnknownFieldPolicy,
    internal::{RedactionPolicyInner, visit_canonical_field_candidates},
};

/// One atomic field-resolution result.
#[derive(Clone, Copy)]
pub(crate) struct ResolvedField<'a> {
    pub(crate) sensitivity: Option<Sensitivity>,
    pub(crate) masking: Option<&'a MaskingPolicy>,
}

/// Immutable, cheap-to-clone field classification and masking snapshot.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionRules {
    application: Arc<RedactionPolicyInner>,
    floor: Option<RedactionFloor>,
    floor_state: RedactionFloorState,
}

impl RedactionRules {
    pub(crate) fn new(
        application: RedactionPolicyInner,
        floor: Option<RedactionFloor>,
        floor_state: RedactionFloorState,
    ) -> Self {
        Self {
            application: Arc::new(application),
            floor,
            floor_state,
        }
    }

    /// Returns the attached minimum floor, if enabled.
    #[inline]
    pub fn floor(&self) -> Option<&RedactionFloor> {
        self.floor.as_ref()
    }

    /// Returns the origin state of this snapshot's floor.
    #[inline]
    pub const fn floor_state(&self) -> RedactionFloorState {
        self.floor_state
    }

    /// Replaces the floor and marks it as explicitly configured.
    #[must_use]
    pub fn with_floor(mut self, floor: RedactionFloor) -> Self {
        self.floor = Some(floor);
        self.floor_state = RedactionFloorState::Explicit;
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
        self.floor_state = RedactionFloorState::Disabled;
        self
    }

    /// Explains application-rule matching only; it is not the final safety decision.
    pub fn classify_field<'a>(&'a self, field: &str) -> FieldClassification<'a> {
        classify_inner(&self.application, field, self.application.matching, true)
    }

    /// Resolves final sensitivity from application and floor layers.
    #[inline]
    pub fn sensitivity_for(&self, field: &str) -> Option<Sensitivity> {
        self.resolve_field(field).sensitivity
    }

    pub(crate) fn sensitivity_for_exact(&self, field: &str) -> Option<Sensitivity> {
        self.resolve_field_exact(field).sensitivity
    }

    pub(crate) fn resolve_field_exact(&self, field: &str) -> ResolvedField<'_> {
        let application =
            sensitivity_inner(&self.application, field, FieldNameMatching::Exact, true);
        let floor = self.floor.as_ref().and_then(|floor| {
            sensitivity_inner(&floor.inner, field, FieldNameMatching::Exact, false)
        });
        match self.floor.as_ref().zip(floor) {
            Some((floor, floor_level)) => ResolvedField {
                sensitivity: Some(application.map_or(floor_level, |level| level.max(floor_level))),
                masking: Some(floor.masking()),
            },
            None => ResolvedField {
                sensitivity: application,
                masking: application.map(|_| &self.application.masking),
            },
        }
    }

    #[inline]
    pub(crate) fn resolve_field(&self, field: &str) -> ResolvedField<'_> {
        self.resolve_field_with_matching(field, self.application.matching)
    }

    fn resolve_field_with_matching(
        &self,
        field: &str,
        matching: FieldNameMatching,
    ) -> ResolvedField<'_> {
        let application = sensitivity_inner(&self.application, field, matching, true);
        let floor = self.floor.as_ref().and_then(|floor| {
            sensitivity_inner(&floor.inner, field, floor.inner.matching, false)
                .map(|level| (level, floor.masking()))
        });
        match floor {
            Some((floor_level, masking)) => ResolvedField {
                sensitivity: Some(application.map_or(floor_level, |level| level.max(floor_level))),
                masking: Some(masking),
            },
            None => ResolvedField {
                sensitivity: application,
                masking: application.map(|_| &self.application.masking),
            },
        }
    }

    #[inline]
    pub fn matching(&self) -> FieldNameMatching {
        self.application.matching
    }
    #[inline]
    pub fn unknown_field_policy(&self) -> UnknownFieldPolicy {
        self.application.unknown_field_policy
    }
    #[inline]
    pub fn masking(&self) -> &MaskingPolicy {
        &self.application.masking
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

    pub(crate) fn clone_application(&self) -> RedactionPolicyInner {
        (*self.application).clone()
    }
}

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

fn sensitivity_inner(
    inner: &RedactionPolicyInner,
    field: &str,
    matching: FieldNameMatching,
    allow: bool,
) -> Option<Sensitivity> {
    match classify_inner(inner, field, matching, allow) {
        FieldClassification::Sensitive { rule, .. } => Some(rule.sensitivity()),
        FieldClassification::Allowed { .. } => None,
        FieldClassification::Unknown => inner.unknown_field_policy.sensitivity(),
    }
}
