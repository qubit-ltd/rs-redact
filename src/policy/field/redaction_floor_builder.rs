// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Builder for immutable minimum redaction floors.

use std::sync::Arc;

use super::FieldNameMatching;
use super::RedactionFloor;
use super::SensitiveFieldPreset;
use super::Sensitivity;
use super::UnknownFieldPolicy;
use crate::policy::PolicyError;
use crate::policy::PolicyLocation;
use crate::policy::RedactionRulesBuilder;

/// Builder for a [`RedactionFloor`].
///
/// # Examples
///
/// ```
/// use qubit_redact::RedactionFloor;
/// use qubit_redact::Sensitivity;
///
/// let floor = RedactionFloor::builder().raise("pin", Sensitivity::Secret)?.build()?;
/// assert!(floor.sensitive_rules().any(|rule| rule.field() == "pin"));
/// # Ok::<(), qubit_redact::PolicyError>(())
/// ```
#[derive(Debug, Clone)]
pub struct RedactionFloorBuilder {
    /// Mutable rules validated in the floor policy location.
    rules: RedactionRulesBuilder,
    /// Immutable layers retained when editing a composed floor.
    retained_layers: Vec<Arc<crate::policy::internal::RedactionPolicyInner>>,
}

impl RedactionFloorBuilder {
    /// Creates an empty builder for the floor construction context.
    ///
    /// # Returns
    ///
    /// An editable first layer with no retained floor layers.
    #[must_use]
    #[inline(always)]
    pub(super) fn empty() -> Self {
        Self {
            rules: RedactionRulesBuilder::empty(PolicyLocation::Floor),
            retained_layers: Vec::new(),
        }
    }

    /// Copies the first layer of `floor` and shares its retained immutable
    /// layers.
    ///
    /// # Parameters
    ///
    /// * `floor` - Floor whose rules and layer order are preserved.
    ///
    /// # Returns
    ///
    /// A builder with an editable copy of the first layer.
    ///
    /// # Panics
    ///
    /// Panics if `floor` has no layers, violating the built-floor invariant.
    #[must_use]
    #[inline(always)]
    pub(super) fn from_floor(floor: &RedactionFloor) -> Self {
        let mut layers = floor.layers.iter();
        let first = layers.next().expect("a built floor always has one layer");
        Self {
            rules: RedactionRulesBuilder::from_inner(first, PolicyLocation::Floor),
            retained_layers: layers.cloned().collect(),
        }
    }

    /// Sets field-name matching behavior for the editable first layer.
    ///
    /// When this builder came from a composed floor, retained layers keep
    /// their original matching behavior.
    ///
    /// # Parameters
    ///
    /// * `matching` - Field-name matching mode for the editable first layer.
    ///
    /// # Returns
    ///
    /// This builder with the updated matching mode.
    #[must_use]
    #[inline(always)]
    pub fn matching(mut self, matching: FieldNameMatching) -> Self {
        self.rules.matching(matching);
        self
    }

    /// Sets the fallback for fields without an explicit rule in the editable
    /// first layer. Retained layers keep their own fallback behavior.
    ///
    /// # Parameters
    ///
    /// * `policy` - Fallback used by the editable first layer for unknown
    ///   fields.
    ///
    /// # Returns
    ///
    /// This builder with the updated fallback policy.
    #[must_use]
    #[inline(always)]
    pub fn unknown_field_policy(mut self, policy: UnknownFieldPolicy) -> Self {
        self.rules.unknown_field_policy(policy);
        self
    }

    /// Adds every sensitive field in one preset to the editable first layer,
    /// preserving any stronger classification already configured there.
    ///
    /// # Parameters
    ///
    /// * `preset` - Built-in sensitive-field rules to add.
    ///
    /// # Returns
    ///
    /// This builder with the preset rules applied.
    ///
    /// # Panics
    ///
    /// Panics if a built-in preset contains an invalid field name.
    #[must_use]
    #[inline(always)]
    pub fn include_preset(mut self, preset: SensitiveFieldPreset) -> Self {
        self.rules.include_preset(preset);
        self
    }

    /// Raises `field` to at least `level` in the editable first layer.
    ///
    /// # Parameters
    ///
    /// * `field` - Field name to canonicalize and update.
    /// * `level` - Minimum sensitivity to apply without lowering an existing
    ///   rule.
    ///
    /// # Returns
    ///
    /// This builder with the field rule updated on success.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::EmptyFieldName`] when `field` has no canonical
    /// floor-rule name.
    #[inline]
    pub fn raise(mut self, field: &str, level: Sensitivity) -> Result<Self, PolicyError> {
        self.rules.raise(field, level)?;
        Ok(self)
    }

    /// Consumes this builder and constructs the immutable floor.
    ///
    /// # Returns
    ///
    /// A floor containing the edited first layer followed by the retained
    /// layers.
    ///
    /// # Errors
    ///
    /// Currently infallible because field names are validated when added.
    /// The result retains the policy construction error type.
    pub fn build(self) -> Result<RedactionFloor, PolicyError> {
        let mut layers = Vec::with_capacity(1 + self.retained_layers.len());
        layers.push(Arc::new(self.rules.build_inner()?));
        layers.extend(self.retained_layers);
        Ok(RedactionFloor::from_layers(layers))
    }
}
