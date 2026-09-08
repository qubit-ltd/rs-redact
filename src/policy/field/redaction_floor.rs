// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Minimum field-protection floors.

use std::fmt;
use std::sync::Arc;
use std::sync::LazyLock;

use super::FieldNameMatching;
use super::RedactionFloorBuilder;
use super::SensitiveFieldPreset;
use super::SensitiveFieldRule;
use super::UnknownFieldPolicy;
use crate::policy::internal::RedactionPolicyInner;

/// Immutable minimum field-protection rules.
///
/// A floor contains sensitive-field rules, matching behavior, and an
/// unknown-field fallback. It intentionally has no allow rules or mask table.
///
/// # Examples
///
/// ```
/// use qubit_redact::RedactionFloor;
/// use qubit_redact::RedactionPolicy;
/// use qubit_redact::Sensitivity;
///
/// let floor = RedactionFloor::builder().raise("pin", Sensitivity::Secret)?.build()?;
/// let policy = RedactionPolicy::standard().with_floor(floor);
/// assert_eq!(policy.sensitivity_for("pin"), Some(Sensitivity::Secret));
/// # Ok::<(), qubit_redact::PolicyError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionFloor {
    /// Shared immutable rule state containing only minimum protections.
    pub(crate) inner: Arc<RedactionPolicyInner>,
}

/// Lazily initialized conservative floor shared by standard policies.
static STANDARD_FLOOR: LazyLock<RedactionFloor> = LazyLock::new(|| {
    let mut builder = RedactionFloor::builder();
    for preset in [
        SensitiveFieldPreset::Credentials,
        SensitiveFieldPreset::CredentialContainers,
        SensitiveFieldPreset::AuthTokens,
        SensitiveFieldPreset::Http,
        SensitiveFieldPreset::Session,
    ] {
        builder = builder.include_preset(preset);
    }
    for &(field, level) in super::super::redaction_policy::STANDARD_EXTRA_FIELDS {
        builder = builder
            .raise(field, level)
            .expect("built-in standard floor fields must be valid");
    }
    builder.build().expect("the built-in redaction floor is valid")
});

impl RedactionFloor {
    /// Returns the built-in conservative floor.
    #[must_use]
    #[inline(always)]
    pub fn standard() -> Self {
        STANDARD_FLOOR.clone()
    }

    /// Creates a deterministic empty floor builder.
    #[must_use]
    #[inline(always)]
    pub fn builder() -> RedactionFloorBuilder {
        RedactionFloorBuilder::empty()
    }

    /// Iterates the floor's canonical sensitive rules.
    pub fn sensitive_rules(&self) -> impl Iterator<Item = SensitiveFieldRule<'_>> {
        self.inner
            .sensitive
            .iter()
            .map(|(field, level)| SensitiveFieldRule::new(field, *level))
    }

    /// Creates a floor builder by copying `self` exactly.
    #[must_use]
    #[inline(always)]
    pub fn to_builder(&self) -> RedactionFloorBuilder {
        RedactionFloorBuilder::from_floor(self)
    }

    /// Combines two floors by retaining the strongest classification for every
    /// canonical field. This is used when a format boundary adds mandatory
    /// protection to an application policy.
    #[must_use]
    pub(crate) fn combine(&self, other: &Self) -> Self {
        let mut sensitive = self.inner.sensitive.clone();
        for (field, level) in &other.inner.sensitive {
            sensitive
                .entry(field.clone())
                .and_modify(|current| *current = (*current).max(*level))
                .or_insert(*level);
        }
        let unknown = match (
            self.inner.unknown_field_policy.sensitivity(),
            other.inner.unknown_field_policy.sensitivity(),
        ) {
            (Some(left), Some(right)) => Some(left.max(right)),
            (Some(level), None) | (None, Some(level)) => Some(level),
            (None, None) => None,
        };
        let unknown_field_policy = unknown.map_or(UnknownFieldPolicy::PassThrough, UnknownFieldPolicy::Redact);
        Self {
            inner: std::sync::Arc::new(RedactionPolicyInner {
                sensitive,
                allow_exact: Default::default(),
                allow_suffix: Default::default(),
                matching: if self.inner.matching == FieldNameMatching::ExactOrTokenSuffix
                    || other.inner.matching == FieldNameMatching::ExactOrTokenSuffix
                {
                    FieldNameMatching::ExactOrTokenSuffix
                } else {
                    FieldNameMatching::Exact
                },
                unknown_field_policy,
            }),
        }
    }
}

impl Default for RedactionFloor {
    /// Returns the built-in conservative floor.
    #[inline(always)]
    fn default() -> Self {
        Self::standard()
    }
}

impl fmt::Display for RedactionFloor {
    /// Writes the diagnostic type name, propagating any destination formatter
    /// error.
    #[inline(always)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RedactionFloor")
    }
}
