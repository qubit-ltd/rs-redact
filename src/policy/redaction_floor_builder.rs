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
use super::PolicyError;
use super::PolicyLocation;
use super::RedactionFloor;
use super::RedactionRulesBuilder;
use super::SensitiveFieldPreset;
use super::Sensitivity;
use super::UnknownFieldPolicy;

/// Builder for a [`RedactionFloor`].
#[derive(Debug, Clone)]
pub struct RedactionFloorBuilder {
    rules: RedactionRulesBuilder,
}

impl RedactionFloorBuilder {
    /// Creates an empty builder for the floor construction context.
    #[must_use]
    pub(super) fn empty() -> Self {
        Self {
            rules: RedactionRulesBuilder::empty(PolicyLocation::Floor),
        }
    }

    #[must_use]
    /// Copies every field rule from `floor`.
    pub(super) fn from_floor(floor: &RedactionFloor) -> Self {
        Self {
            rules: RedactionRulesBuilder::from_inner(
                &floor.inner,
                PolicyLocation::Floor,
            ),
        }
    }

    /// Adds every sensitive field in one preset.
    #[must_use]
    pub fn include_preset(mut self, preset: SensitiveFieldPreset) -> Self {
        self.rules.include_preset(preset);
        self
    }

    /// Raises `field` to at least `level`.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::EmptyFieldName`] when `field` has no canonical
    /// floor-rule name.
    pub fn raise(
        mut self,
        field: &str,
        level: Sensitivity,
    ) -> Result<Self, PolicyError> {
        self.rules.raise(field, level)?;
        Ok(self)
    }

    #[must_use]
    #[inline(always)]
    /// Sets field-name matching behavior.
    pub fn matching(mut self, matching: FieldNameMatching) -> Self {
        self.rules.matching(matching);
        self
    }

    #[must_use]
    #[inline(always)]
    /// Sets the fallback for fields without an explicit floor rule.
    pub fn unknown_field_policy(mut self, policy: UnknownFieldPolicy) -> Self {
        self.rules.unknown_field_policy(policy);
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
