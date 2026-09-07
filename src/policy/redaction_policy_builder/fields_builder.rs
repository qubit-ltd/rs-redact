// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Transactional view over application field rules.

use super::MaskingPolicy;
use super::PolicyError;
use super::PolicyLocation;
use super::RedactionFloor;
use super::RedactionPolicyBuilder;
use super::Sensitivity;
use crate::policy::FieldNameMatching;
use crate::policy::MaskPolicy;
use crate::policy::SensitiveFieldPreset;
use crate::policy::UnknownFieldPolicy;

/// Mutable view over the base field policy.
///
/// # Examples
///
/// ```
/// use qubit_redact::RedactionPolicy;
/// use qubit_redact::Sensitivity;
///
/// let policy = RedactionPolicy::builder().fields(|fields| {
///     fields.secret_sensitive("pin").allow_exact("request_id");
/// })?.build()?;
/// assert_eq!(policy.sensitivity_for("pin"), Some(Sensitivity::Secret));
/// # Ok::<(), qubit_redact::PolicyError>(())
/// ```
pub struct FieldsBuilder<'a> {
    /// Root builder receiving validated field changes.
    pub(super) builder: &'a mut RedactionPolicyBuilder,
    /// First validation error recorded by the transactional view.
    pub(super) error: Option<PolicyError>,
}

impl FieldsBuilder<'_> {
    /// Marks a field as low sensitivity.
    #[inline(always)]
    pub fn low_sensitive(&mut self, field: &str) -> &mut Self {
        self.set_sensitive(field, Sensitivity::Low)
    }

    /// Marks a field as medium sensitivity.
    #[inline(always)]
    pub fn medium_sensitive(&mut self, field: &str) -> &mut Self {
        self.set_sensitive(field, Sensitivity::Medium)
    }

    /// Marks a field as high sensitivity.
    #[inline(always)]
    pub fn high_sensitive(&mut self, field: &str) -> &mut Self {
        self.set_sensitive(field, Sensitivity::High)
    }

    /// Marks a field as secret sensitivity.
    #[inline(always)]
    pub fn secret_sensitive(&mut self, field: &str) -> &mut Self {
        self.set_sensitive(field, Sensitivity::Secret)
    }

    /// Raises a field's minimum sensitivity to `level`.
    #[inline(always)]
    pub fn sensitive(&mut self, level: Sensitivity, field: &str) -> &mut Self {
        self.set_sensitive(field, level)
    }

    /// Sets field-name matching for the base policy.
    #[inline(always)]
    pub fn matching(&mut self, matching: FieldNameMatching) -> &mut Self {
        self.builder.rules.matching(matching);
        self
    }

    /// Sets the base fallback for unknown fields.
    #[inline(always)]
    pub fn unknown_field_policy(&mut self, policy: UnknownFieldPolicy) -> &mut Self {
        self.builder.rules.unknown_field_policy(policy);
        self
    }

    /// Includes all fields from a built-in sensitive preset.
    #[inline(always)]
    pub fn include_preset(&mut self, preset: SensitiveFieldPreset) -> &mut Self {
        self.builder.rules.include_preset(preset);
        self
    }

    /// Raises a base field's minimum sensitivity.
    pub fn raise(&mut self, field: &str, level: Sensitivity) -> &mut Self {
        if self.error.is_none()
            && let Err(error) = self.builder.rules.raise(field, level)
        {
            self.error = Some(error);
        }
        self
    }

    /// Replaces one base field rule without weakening floors.
    pub fn override_level(&mut self, field: &str, level: Sensitivity) -> &mut Self {
        if self.error.is_none()
            && let Err(error) = self.builder.rules.override_level(field, level)
        {
            self.error = Some(error);
        }
        self
    }

    /// Adds a base exact allow rule.
    pub fn allow_exact(&mut self, field: &str) -> &mut Self {
        if self.error.is_none()
            && let Err(error) = self.builder.rules.allow_canonical_exact(field)
        {
            self.error = Some(error);
        }
        self
    }

    /// Adds a base suffix allow rule.
    pub fn allow_suffix(&mut self, field: &str) -> &mut Self {
        if self.error.is_none()
            && let Err(error) = self.builder.rules.allow_suffix(field)
        {
            self.error = Some(error);
        }
        self
    }

    /// Removes a base exact allow rule.
    pub fn remove_allow_exact(&mut self, field: &str) -> &mut Self {
        if self.error.is_none()
            && let Err(error) = self.builder.rules.remove_allow_canonical_exact(field)
        {
            self.error = Some(error);
        }
        self
    }

    /// Removes a base suffix allow rule.
    pub fn remove_allow_suffix(&mut self, field: &str) -> &mut Self {
        if self.error.is_none()
            && let Err(error) = self.builder.rules.remove_allow_suffix(field)
        {
            self.error = Some(error);
        }
        self
    }

    /// Removes all base allow rules.
    #[inline(always)]
    pub fn clear_allow_rules(&mut self) -> &mut Self {
        self.builder.rules.clear_allow_rules();
        self
    }

    /// Replaces the base minimum-protection floor.
    #[inline(always)]
    pub fn floor(&mut self, floor: RedactionFloor) -> &mut Self {
        self.builder.floor = Some(floor);
        self
    }

    /// Disables the base floor explicitly.
    #[inline(always)]
    pub fn disable_floor(&mut self) -> &mut Self {
        self.builder.floor = None;
        self
    }

    /// Replaces one shared masking level.
    pub fn mask(&mut self, level: Sensitivity, policy: MaskPolicy) -> &mut Self {
        let mut masking = MaskingPolicy::builder_from(&self.builder.masking);
        masking.policy(level, policy);
        let masking = masking.build();
        if self.error.is_none() {
            match masking.validate(PolicyLocation::Rules) {
                Ok(()) => self.builder.masking = masking,
                Err(error) => self.error = Some(error),
            }
        }
        self
    }

    /// Raises one field's minimum sensitivity in a transactional draft.
    #[inline(always)]
    fn set_sensitive(&mut self, field: &str, level: Sensitivity) -> &mut Self {
        if self.error.is_none()
            && let Err(error) = self.builder.rules.raise(field, level)
        {
            self.error = Some(error);
        }
        self
    }
}
