// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Minimum field-protection floors.

use std::{
    fmt,
    sync::{Arc, LazyLock, OnceLock},
};

use super::internal::RedactionPolicyInner;
use super::{
    FieldNameMatching, GlobalDefaultAlreadySet, MaskPolicy, MaskingPolicy, PolicyError,
    PolicyLocation, RedactionRulesBuilder, SensitiveFieldPreset, SensitiveFieldRule, Sensitivity,
    UnknownFieldPolicy,
};

/// Describes how a rules snapshot obtained its redaction floor.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionFloorState {
    /// The builder captured the process-wide floor when it was created.
    GlobalDefault,
    /// A caller explicitly supplied the floor.
    Explicit,
    /// The caller explicitly disabled every floor.
    Disabled,
}

/// Immutable minimum field-protection rules.
///
/// A floor contains sensitive-field rules, matching behavior, an unknown-field
/// fallback, and its own masking policy. It intentionally has no allow rules.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionFloor {
    pub(crate) inner: Arc<RedactionPolicyInner>,
}

static STANDARD_FLOOR: LazyLock<RedactionFloor> = LazyLock::new(|| {
    let mut builder = RedactionFloor::empty_builder();
    for preset in [
        SensitiveFieldPreset::Credentials,
        SensitiveFieldPreset::CredentialContainers,
        SensitiveFieldPreset::AuthTokens,
        SensitiveFieldPreset::Http,
        SensitiveFieldPreset::Session,
    ] {
        builder = builder.include_preset(preset);
    }
    for &(field, level) in super::redaction_policy::STANDARD_EXTRA_FIELDS {
        builder = builder.raise(field, level);
    }
    builder
        .build()
        .expect("the built-in redaction floor is valid")
});

static GLOBAL_DEFAULT: OnceLock<RedactionFloor> = OnceLock::new();

impl RedactionFloor {
    /// Returns the built-in conservative floor.
    #[inline]
    pub fn standard() -> Self {
        STANDARD_FLOOR.clone()
    }

    /// Returns a snapshot of the process-wide floor default.
    #[inline]
    pub fn global_default() -> Self {
        GLOBAL_DEFAULT.get().cloned().unwrap_or_else(Self::standard)
    }

    /// Installs the process-wide floor default exactly once.
    pub fn set_global_default(floor: Self) -> Result<(), GlobalDefaultAlreadySet> {
        GLOBAL_DEFAULT
            .set(floor)
            .map_err(|_| GlobalDefaultAlreadySet)
    }

    /// Creates an empty floor builder without reading the global default.
    #[inline]
    pub fn empty_builder() -> RedactionFloorBuilder {
        RedactionFloorBuilder::empty()
    }

    /// Creates a floor builder from the current global floor snapshot.
    #[inline]
    pub fn builder_from_default() -> RedactionFloorBuilder {
        RedactionFloorBuilder::from_floor(&Self::global_default())
    }

    /// Creates a floor builder by copying `base` exactly.
    #[inline]
    pub fn builder_from(base: &Self) -> RedactionFloorBuilder {
        RedactionFloorBuilder::from_floor(base)
    }

    /// Iterates the floor's canonical sensitive rules.
    pub fn sensitive_rules(&self) -> impl Iterator<Item = SensitiveFieldRule<'_>> {
        self.inner
            .sensitive
            .iter()
            .map(|(field, level)| SensitiveFieldRule::new(field, *level))
    }

    #[inline]
    pub(crate) fn masking(&self) -> &MaskingPolicy {
        &self.inner.masking
    }
}

impl Default for RedactionFloor {
    #[inline]
    fn default() -> Self {
        Self::global_default()
    }
}

impl fmt::Display for RedactionFloor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RedactionFloor")
    }
}

/// Builder for a [`RedactionFloor`].
#[must_use]
#[derive(Debug, Clone)]
pub struct RedactionFloorBuilder {
    rules: RedactionRulesBuilder,
}

impl RedactionFloorBuilder {
    fn empty() -> Self {
        Self {
            rules: RedactionRulesBuilder::empty(PolicyLocation::Floor),
        }
    }

    fn from_floor(floor: &RedactionFloor) -> Self {
        Self {
            rules: RedactionRulesBuilder::from_inner(&floor.inner, PolicyLocation::Floor),
        }
    }

    /// Adds every sensitive field in one preset.
    pub fn include_preset(mut self, preset: SensitiveFieldPreset) -> Self {
        self.rules = self.rules.include_preset(preset);
        self
    }

    /// Raises `field` to at least `level`.
    pub fn raise(mut self, field: &str, level: Sensitivity) -> Self {
        self.rules = self.rules.raise(field, level);
        self
    }

    /// Sets field-name matching behavior.
    pub fn matching(mut self, matching: FieldNameMatching) -> Self {
        self.rules = self.rules.matching(matching);
        self
    }

    /// Sets the fallback for fields without an explicit floor rule.
    pub fn unknown_field_policy(mut self, policy: UnknownFieldPolicy) -> Self {
        self.rules = self.rules.unknown_field_policy(policy);
        self
    }

    /// Replaces the mask selected for `level`.
    pub fn mask(mut self, level: Sensitivity, policy: MaskPolicy) -> Self {
        self.rules = self.rules.mask(level, policy);
        self
    }

    /// Validates and constructs the immutable floor.
    pub fn build(self) -> Result<RedactionFloor, PolicyError> {
        let inner = self.rules.build_inner()?;
        Ok(RedactionFloor {
            inner: Arc::new(inner),
        })
    }
}
