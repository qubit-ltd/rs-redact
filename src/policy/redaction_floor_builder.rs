// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Builder for immutable minimum redaction floors.

use std::sync::Arc;

use super::{
    FieldNameMatching,
    MaskPolicy,
    PolicyError,
    PolicyLocation,
    RedactionFloor,
    RedactionRulesBuilder,
    SensitiveFieldPreset,
    Sensitivity,
    UnknownFieldPolicy,
};

/// Builder for a [`RedactionFloor`].
#[must_use]
#[derive(Debug, Clone)]
pub struct RedactionFloorBuilder {
    rules: RedactionRulesBuilder,
}

impl RedactionFloorBuilder {
    /// Creates an empty builder for the floor construction context.
    pub(super) fn empty() -> Self {
        Self {
            rules: RedactionRulesBuilder::empty(PolicyLocation::Floor),
        }
    }

    /// Copies every field rule and masking choice from `floor`.
    pub(super) fn from_floor(floor: &RedactionFloor) -> Self {
        Self {
            rules: RedactionRulesBuilder::from_inner(
                &floor.inner,
                PolicyLocation::Floor,
            ),
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
    ///
    /// # Errors
    ///
    /// Returns a [`PolicyError`] located at [`PolicyLocation::Floor`] when a
    /// field name or fixed mask is invalid.
    pub fn build(self) -> Result<RedactionFloor, PolicyError> {
        let inner = self.rules.build_inner()?;
        Ok(RedactionFloor {
            inner: Arc::new(inner),
        })
    }
}
