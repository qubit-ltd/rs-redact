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
    ///
    /// # Returns
    ///
    /// A cheap clone sharing the immutable standard layers and rule index.
    #[must_use]
    #[inline(always)]
    pub fn standard() -> Self {
        STANDARD_FLOOR.clone()
    }

    /// Creates a deterministic empty floor builder.
    ///
    /// # Returns
    ///
    /// An owned builder with no configured field rules.
    #[must_use]
    #[inline(always)]
    pub fn builder() -> RedactionFloorBuilder {
        RedactionFloorBuilder::empty()
    }

    /// Builds a floor from already constructed policy layers, preserving their
    /// order and keeping each layer available for independent resolution.
    ///
    /// The sensitive index merges only explicitly configured canonical field
    /// rules, retaining the strongest level for each field. It supports
    /// enumerating the floor's canonical sensitive rules; actual resolution
    /// still evaluates the retained layers so each layer's matching mode and
    /// unknown-field fallback remain effective. This constructor does not
    /// deduplicate layers; callers are responsible for supplying valid layers.
    ///
    /// # Parameters
    ///
    /// * `layers` - Owned layer handles to retain in their supplied order.
    ///
    /// # Returns
    ///
    /// A floor owning the supplied handles and a newly merged canonical index.
    #[must_use]
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

    /// Iterates the floor's canonical sensitive rules without allocating.
    ///
    /// # Returns
    ///
    /// A lazy iterator borrowing canonical field names from this floor, in
    /// canonical-name order.
    #[must_use = "iterators are lazy and do nothing unless consumed"]
    #[inline]
    pub fn sensitive_rules(&self) -> impl Iterator<Item = SensitiveFieldRule<'_>> {
        self.sensitive_index
            .iter()
            .map(|(field, level)| SensitiveFieldRule::new(field, *level))
    }

    /// Creates a floor builder by copying `self` exactly.
    ///
    /// # Returns
    ///
    /// An owned editable copy of the first layer, retaining shared additional
    /// layers and their independent matching behavior.
    #[must_use]
    #[inline(always)]
    pub fn to_builder(&self) -> RedactionFloorBuilder {
        RedactionFloorBuilder::from_floor(self)
    }

    /// Combines two floors by retaining the strongest classification for every
    /// canonical field. This is used when a format boundary adds mandatory
    /// protection to an application policy.
    ///
    /// # Parameters
    ///
    /// * `other` - Additional floor whose layers are shared rather than copied.
    ///
    /// # Returns
    ///
    /// A floor preserving this floor's layers and their order, then appending
    /// previously absent layer allocations from `other`. If every
    /// additional layer is already present, both existing indexes are shared.
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
}

impl Default for RedactionFloor {
    /// Returns the built-in conservative floor.
    ///
    /// # Returns
    ///
    /// A cheap clone sharing the immutable standard layers and rule index.
    #[inline(always)]
    fn default() -> Self {
        Self::standard()
    }
}

impl fmt::Display for RedactionFloor {
    /// Writes the diagnostic type name, propagating any destination formatter
    /// error.
    ///
    /// # Parameters
    ///
    /// * `formatter` - Destination for the diagnostic label.
    ///
    /// # Returns
    ///
    /// Success after the label is written.
    ///
    /// # Errors
    ///
    /// Returns the destination formatter's error if writing fails.
    #[inline(always)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RedactionFloor")
    }
}
