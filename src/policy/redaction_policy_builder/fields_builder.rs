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
/// This view edits a temporary policy draft supplied to
/// [`RedactionPolicyBuilder::fields`]. Invalid field rules are recorded and
/// returned by that outer call after its closure finishes, so configuration
/// methods can be chained without returning individual `Result` values.
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
    /// Marks `field` as low sensitivity in the draft.
    #[inline(always)]
    pub fn low_sensitive(&mut self, field: &str) -> &mut Self {
        self.set_sensitive(field, Sensitivity::Low)
    }

    /// Marks `field` as medium sensitivity in the draft.
    #[inline(always)]
    pub fn medium_sensitive(&mut self, field: &str) -> &mut Self {
        self.set_sensitive(field, Sensitivity::Medium)
    }

    /// Marks `field` as high sensitivity in the draft.
    #[inline(always)]
    pub fn high_sensitive(&mut self, field: &str) -> &mut Self {
        self.set_sensitive(field, Sensitivity::High)
    }

    /// Marks `field` as secret sensitivity in the draft.
    #[inline(always)]
    pub fn secret_sensitive(&mut self, field: &str) -> &mut Self {
        self.set_sensitive(field, Sensitivity::Secret)
    }

    /// Raises `field`'s minimum sensitivity to `level` in the draft.
    #[inline(always)]
    pub fn sensitive(&mut self, level: Sensitivity, field: &str) -> &mut Self {
        self.set_sensitive(field, level)
    }

    /// Sets how field names are matched by the base policy.
    #[inline(always)]
    pub fn matching(&mut self, matching: FieldNameMatching) -> &mut Self {
        self.builder.rules.matching(matching);
        self
    }

    /// Sets the base policy applied to fields without an explicit rule.
    #[inline(always)]
    pub fn unknown_field_policy(&mut self, policy: UnknownFieldPolicy) -> &mut Self {
        self.builder.rules.unknown_field_policy(policy);
        self
    }

    /// Adds every field in `preset` to the base sensitivity rules.
    #[inline(always)]
    pub fn include_preset(&mut self, preset: SensitiveFieldPreset) -> &mut Self {
        self.builder.rules.include_preset(preset);
        self
    }

    /// Raises the base minimum sensitivity for `field`.
    ///
    /// An invalid field name is recorded and returned by the enclosing
    /// [`RedactionPolicyBuilder::fields`] call after configuration completes.
    pub fn raise(&mut self, field: &str, level: Sensitivity) -> &mut Self {
        if self.error.is_none()
            && let Err(error) = self.builder.rules.raise(field, level)
        {
            self.error = Some(error);
        }
        self
    }

    /// Replaces the base sensitivity rule for `field` without weakening floors.
    ///
    /// An invalid field name is recorded and returned by the enclosing
    /// [`RedactionPolicyBuilder::fields`] call after configuration completes.
    pub fn override_level(&mut self, field: &str, level: Sensitivity) -> &mut Self {
        if self.error.is_none()
            && let Err(error) = self.builder.rules.override_level(field, level)
        {
            self.error = Some(error);
        }
        self
    }

    /// Adds an exact-name exception to the base redaction rules.
    ///
    /// An invalid field name is recorded and returned by the enclosing
    /// [`RedactionPolicyBuilder::fields`] call after configuration completes.
    pub fn allow_exact(&mut self, field: &str) -> &mut Self {
        if self.error.is_none()
            && let Err(error) = self.builder.rules.allow_canonical_exact(field)
        {
            self.error = Some(error);
        }
        self
    }

    /// Adds an allow rule declared for exact and token-suffix candidates.
    ///
    /// Whether token-suffix candidates are considered is still controlled by
    /// the application's [`FieldNameMatching`] mode. With
    /// [`FieldNameMatching::Exact`], this rule can allow only the complete
    /// normalized name; use [`Self::matching`] with
    /// [`FieldNameMatching::ExactOrTokenSuffix`] to allow names such as
    /// `request_diagnostic` through an `allow_suffix("diagnostic")` rule.
    ///
    /// An invalid field name is recorded and returned by the enclosing
    /// [`RedactionPolicyBuilder::fields`] call after configuration completes.
    pub fn allow_suffix(&mut self, field: &str) -> &mut Self {
        if self.error.is_none()
            && let Err(error) = self.builder.rules.allow_suffix(field)
        {
            self.error = Some(error);
        }
        self
    }

    /// Removes the exact-name exception for `field` from the base rules.
    ///
    /// An invalid field name is recorded and returned by the enclosing
    /// [`RedactionPolicyBuilder::fields`] call after configuration completes.
    pub fn remove_allow_exact(&mut self, field: &str) -> &mut Self {
        if self.error.is_none()
            && let Err(error) = self.builder.rules.remove_allow_canonical_exact(field)
        {
            self.error = Some(error);
        }
        self
    }

    /// Removes the suffix exception for `field` from the base rules.
    ///
    /// An invalid field name is recorded and returned by the enclosing
    /// [`RedactionPolicyBuilder::fields`] call after configuration completes.
    pub fn remove_allow_suffix(&mut self, field: &str) -> &mut Self {
        if self.error.is_none()
            && let Err(error) = self.builder.rules.remove_allow_suffix(field)
        {
            self.error = Some(error);
        }
        self
    }

    /// Removes every exact-name and suffix exception from the base rules.
    #[inline(always)]
    pub fn clear_allow_rules(&mut self) -> &mut Self {
        self.builder.rules.clear_allow_rules();
        self
    }

    /// Sets the minimum-protection floor applied to the base field rules.
    #[inline(always)]
    pub fn floor(&mut self, floor: RedactionFloor) -> &mut Self {
        self.builder.floor = Some(floor);
        self
    }

    /// Removes the minimum-protection floor from the base field rules.
    #[inline(always)]
    pub fn disable_floor(&mut self) -> &mut Self {
        self.builder.floor = None;
        self
    }

    /// Replaces the masking policy for `level` across all policy fields.
    ///
    /// If the resulting masking configuration is invalid, the error is
    /// recorded and returned by the enclosing
    /// [`RedactionPolicyBuilder::fields`] call after configuration completes.
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

    /// Raises `field`'s minimum sensitivity in the draft, recording any
    /// validation error for the enclosing `fields` call.
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
