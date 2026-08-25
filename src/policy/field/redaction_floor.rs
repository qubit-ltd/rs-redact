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

use super::RedactionFloorBuilder;
use super::SensitiveFieldPreset;
use super::SensitiveFieldRule;
use crate::policy::internal::RedactionPolicyInner;

/// Immutable minimum field-protection rules.
///
/// A floor contains sensitive-field rules, matching behavior, and an
/// unknown-field fallback. It intentionally has no allow rules or mask table.
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
    #[inline]
    pub fn standard() -> Self {
        STANDARD_FLOOR.clone()
    }

    /// Creates a deterministic empty floor builder.
    #[must_use]
    #[inline]
    pub fn builder() -> RedactionFloorBuilder {
        RedactionFloorBuilder::empty()
    }

    /// Creates a floor builder by copying `self` exactly.
    #[must_use]
    #[inline]
    pub fn to_builder(&self) -> RedactionFloorBuilder {
        RedactionFloorBuilder::from_floor(self)
    }

    /// Creates a floor builder that exactly copies `base`.
    #[must_use]
    #[inline]
    pub fn builder_from(base: &Self) -> RedactionFloorBuilder {
        base.to_builder()
    }

    /// Iterates the floor's canonical sensitive rules.
    pub fn sensitive_rules(&self) -> impl Iterator<Item = SensitiveFieldRule<'_>> {
        self.inner
            .sensitive
            .iter()
            .map(|(field, level)| SensitiveFieldRule::new(field, *level))
    }
}

impl Default for RedactionFloor {
    /// Returns the built-in conservative floor.
    #[inline]
    fn default() -> Self {
        Self::standard()
    }
}

impl fmt::Display for RedactionFloor {
    /// Writes the type name used by diagnostic formatting.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RedactionFloor")
    }
}
