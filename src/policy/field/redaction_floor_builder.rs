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
}

impl RedactionFloorBuilder {
    /// Creates an empty builder for the floor construction context.
    #[must_use]
    #[inline(always)]
    pub(super) fn empty() -> Self {
        Self {
            rules: RedactionRulesBuilder::empty(PolicyLocation::Floor),
        }
    }

    /// Copies every field rule from `floor`.
    #[must_use]
    #[inline(always)]
    pub(super) fn from_floor(floor: &RedactionFloor) -> Self {
        Self {
            rules: RedactionRulesBuilder::from_inner(&floor.inner, PolicyLocation::Floor),
        }
    }

    /// Sets field-name matching behavior.
    #[must_use]
    #[inline(always)]
    pub fn matching(mut self, matching: FieldNameMatching) -> Self {
        self.rules.matching(matching);
        self
    }

    /// Sets the fallback for fields without an explicit floor rule.
    #[must_use]
    #[inline(always)]
    pub fn unknown_field_policy(mut self, policy: UnknownFieldPolicy) -> Self {
        self.rules.unknown_field_policy(policy);
        self
    }

    /// Adds every sensitive field in one preset.
    #[must_use]
    #[inline(always)]
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
    pub fn raise(mut self, field: &str, level: Sensitivity) -> Result<Self, PolicyError> {
        self.rules.raise(field, level)?;
        Ok(self)
    }

    /// Validates and constructs the immutable floor.
    ///
    /// # Errors
    ///
    /// Currently infallible because field names are validated when added.
    /// The result retains the policy construction error type.
    pub fn build(self) -> Result<RedactionFloor, PolicyError> {
        let inner = self.rules.build_inner()?;
        Ok(RedactionFloor { inner: Arc::new(inner) })
    }
}
