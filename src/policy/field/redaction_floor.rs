// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Minimum field-protection floors.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::sync::LazyLock;

use super::RedactionFloorBuilder;
use super::SensitiveFieldPreset;
use super::SensitiveFieldRule;
use super::Sensitivity;
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
    /// Independent immutable layers whose resolved sensitivities are combined
    /// by taking their maximum.
    pub(crate) layers: Arc<[Arc<RedactionPolicyInner>]>,
    /// Canonical strongest explicit rules, used only for public enumeration.
    pub(crate) sensitive_index: Arc<BTreeMap<String, Sensitivity>>,
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
        self.sensitive_index
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
        if other
            .layers
            .iter()
            .all(|layer| self.layers.iter().any(|existing| Arc::ptr_eq(existing, layer)))
        {
            return self.clone();
        }
        let mut layers = self.layers.to_vec();
        for layer in other.layers.iter() {
            if !layers.iter().any(|existing| Arc::ptr_eq(existing, layer)) {
                layers.push(Arc::clone(layer));
            }
        }
        Self::from_layers(layers)
    }

    pub(crate) fn from_layers(layers: Vec<Arc<RedactionPolicyInner>>) -> Self {
        let mut sensitive_index = BTreeMap::new();
        for layer in &layers {
            for (field, level) in &layer.sensitive {
                sensitive_index
                    .entry(field.clone())
                    .and_modify(|current: &mut Sensitivity| *current = (*current).max(*level))
                    .or_insert(*level);
            }
        }
        Self {
            layers: layers.into(),
            sensitive_index: Arc::new(sensitive_index),
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::RedactionFloor;

    /// Combining an already present standard floor retains both shared indexes.
    #[test]
    fn test_floor_combine_reuses_standard_allocations() {
        let standard = RedactionFloor::standard();
        let combined = standard.combine(&RedactionFloor::standard());

        assert!(Arc::ptr_eq(&standard.layers, &combined.layers));
        assert!(Arc::ptr_eq(&standard.sensitive_index, &combined.sensitive_index));
    }
}
