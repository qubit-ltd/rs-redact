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
    sync::{
        Arc,
        LazyLock,
        OnceLock,
    },
};

use super::internal::RedactionPolicyInner;
use super::{
    GlobalDefaultAlreadySet,
    MaskingPolicy,
    RedactionFloorBuilder,
    SensitiveFieldPreset,
    SensitiveFieldRule,
};

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
    pub fn set_global_default(
        floor: Self,
    ) -> Result<(), GlobalDefaultAlreadySet> {
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
    pub fn sensitive_rules(
        &self,
    ) -> impl Iterator<Item = SensitiveFieldRule<'_>> {
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
