// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Transactional view over one HTTP field context.

use super::PolicyError;
use super::RedactionFloor;
use super::RedactionRules;
use super::Sensitivity;

/// Mutable view over one HTTP field context.
///
/// # Examples
///
/// ```
/// use qubit_redact::RedactionPolicy;
/// use qubit_redact::Sensitivity;
///
/// let policy = RedactionPolicy::builder().http(|http| {
///     http.header().raise("x-pin", Sensitivity::Secret).expect("valid header rule");
/// })?.build()?;
/// assert!(!policy.is_disabled());
/// # Ok::<(), qubit_redact::PolicyError>(())
/// ```
#[cfg(feature = "http")]
pub struct HttpContextBuilderView<'a> {
    /// HTTP builder receiving context-specific changes.
    pub(super) builder: &'a mut crate::formats::http::HttpPolicyBuilder,
    /// Shared transaction error slot.
    pub(super) error: &'a mut Option<PolicyError>,
    /// Field context targeted by this view.
    pub(super) context: crate::formats::http::HttpFieldContext,
}

#[cfg(feature = "http")]
impl HttpContextBuilderView<'_> {
    /// Replaces all rules for this HTTP field context.
    #[inline(always)]
    pub fn replace_rules(&mut self, rules: RedactionRules) -> &mut Self {
        self.builder.rules_mut(self.context, rules);
        self
    }

    /// Raises a context field's minimum sensitivity.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] when `field` has no canonical name.
    pub fn raise(&mut self, field: &str, level: Sensitivity) -> Result<&mut Self, PolicyError> {
        if self.error.is_none()
            && let Err(error) = self.builder.raise_mut(self.context, field, level)
        {
            *self.error = Some(error.clone());
            return Err(error);
        }
        Ok(self)
    }

    /// Replaces a context field rule without weakening the base policy.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] when `field` has no canonical name.
    pub fn override_level(&mut self, field: &str, level: Sensitivity) -> Result<&mut Self, PolicyError> {
        if self.error.is_none()
            && let Err(error) = self.builder.override_level_mut(self.context, field, level)
        {
            *self.error = Some(error.clone());
            return Err(error);
        }
        Ok(self)
    }

    /// Adds a context exact allow rule; the base policy still applies.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] when `field` has no canonical name.
    pub fn allow_exact(&mut self, field: &str) -> Result<&mut Self, PolicyError> {
        if self.error.is_none()
            && let Err(error) = self.builder.allow_exact_mut(self.context, field)
        {
            *self.error = Some(error.clone());
            return Err(error);
        }
        Ok(self)
    }

    /// Adds a context suffix allow rule; the base policy still applies.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] when `field` has no canonical suffix.
    pub fn allow_suffix(&mut self, field: &str) -> Result<&mut Self, PolicyError> {
        if self.error.is_none()
            && let Err(error) = self.builder.allow_suffix_mut(self.context, field)
        {
            *self.error = Some(error.clone());
            return Err(error);
        }
        Ok(self)
    }

    /// Removes a context exact allow rule.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] when `field` has no canonical name.
    pub fn remove_allow_exact(&mut self, field: &str) -> Result<&mut Self, PolicyError> {
        if self.error.is_none()
            && let Err(error) = self.builder.remove_allow_exact_mut(self.context, field)
        {
            *self.error = Some(error.clone());
            return Err(error);
        }
        Ok(self)
    }

    /// Removes a context suffix allow rule.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] when `field` has no canonical suffix.
    pub fn remove_allow_suffix(&mut self, field: &str) -> Result<&mut Self, PolicyError> {
        if self.error.is_none()
            && let Err(error) = self.builder.remove_allow_suffix_mut(self.context, field)
        {
            *self.error = Some(error.clone());
            return Err(error);
        }
        Ok(self)
    }

    /// Removes all context allow rules.
    #[inline(always)]
    pub fn clear_allow_rules(&mut self) -> &mut Self {
        self.builder.clear_allow_rules_mut(self.context);
        self
    }

    /// Adds a context floor. Base protection remains independently
    /// effective.
    #[must_use]
    #[inline(always)]
    pub fn floor(&mut self, floor: RedactionFloor) -> &mut Self {
        self.builder.floor_mut(self.context, floor);
        self
    }

    /// Disables this context's explicit floor.
    #[inline(always)]
    pub fn disable_floor(&mut self) -> &mut Self {
        self.builder.disable_floor_mut(self.context);
        self
    }
}
