// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Immutable field-classification, masking, and diagnostic policy.

use std::sync::Arc;
use std::sync::LazyLock;

use super::AllowRule;
use super::FieldClassification;
use super::FieldNameMatching;
use super::MaskingPolicy;
use super::RedactionFloor;
use super::RedactionPolicyBuilder;
use super::RedactionRules;
use super::SensitiveFieldRule;
use super::Sensitivity;
#[cfg(feature = "json")]
use super::UnkeyedJsonValuePolicy;
use super::UnknownFieldPolicy;
use super::internal::RedactionPolicyInner;
use super::redaction_limits::RedactionLimits;

/// Built-in sensitive fields not owned by a named preset.
pub(super) const STANDARD_EXTRA_FIELDS: &[(&str, Sensitivity)] = &[
    ("auth_app_token", Sensitivity::High),
    ("auth_user_token", Sensitivity::High),
    ("connection_string", Sensitivity::Secret),
    ("database_uri", Sensitivity::Secret),
    ("database_url", Sensitivity::Secret),
    ("license_key", Sensitivity::Medium),
    ("mysql_pwd", Sensitivity::Secret),
    ("rediscli_auth", Sensitivity::Secret),
    ("sig", Sensitivity::Secret),
    ("signature", Sensitivity::Secret),
];

/// Lazily initialized fixed standard policy.
static STANDARD_POLICY: LazyLock<RedactionPolicy> = LazyLock::new(|| {
    RedactionPolicy::from_rules(
        RedactionRules::new(
            RedactionPolicyInner {
                sensitive: Default::default(),
                allow_exact: Default::default(),
                allow_suffix: Default::default(),
                matching: FieldNameMatching::ExactOrTokenSuffix,
                unknown_field_policy: UnknownFieldPolicy::PassThrough,
            },
            Some(RedactionFloor::standard()),
        ),
        MaskingPolicy::default(),
        RedactionLimits::default(),
        #[cfg(feature = "http")]
        crate::formats::http::HttpPolicyBuilder::new()
            .build()
            .expect("the built-in HTTP policy must be valid"),
        #[cfg(feature = "uri")]
        crate::formats::uri::UriPolicyBuilder::new()
            .build()
            .expect("the built-in URI policy must be valid"),
        #[cfg(feature = "json")]
        UnkeyedJsonValuePolicy::PassThrough,
        false,
    )
});
/// Lazily initialized fixed strict policy.
static STRICT_POLICY: LazyLock<RedactionPolicy> = LazyLock::new(|| {
    RedactionPolicy::from_rules(
        RedactionRules::new(
            RedactionPolicyInner {
                sensitive: Default::default(),
                allow_exact: Default::default(),
                allow_suffix: Default::default(),
                matching: FieldNameMatching::ExactOrTokenSuffix,
                unknown_field_policy: UnknownFieldPolicy::Redact(Sensitivity::Secret),
            },
            Some(RedactionFloor::standard()),
        ),
        MaskingPolicy::default(),
        RedactionLimits::default(),
        #[cfg(feature = "http")]
        {
            let mut http = crate::formats::http::HttpPolicyBuilder::new();
            http.url_path_mut(crate::formats::http::UrlPathPolicy::Redact);
            http.text_body_mut(crate::formats::http::TextBodyPolicy::Redact);
            http.build().expect("the built-in HTTP policy must be valid")
        },
        #[cfg(feature = "uri")]
        crate::formats::uri::UriPolicyBuilder::new()
            .build()
            .expect("the built-in URI policy must be valid"),
        #[cfg(feature = "json")]
        UnkeyedJsonValuePolicy::Redact,
        false,
    )
});
/// Immutable field classification, masking, format, and resource policy.
///
/// A disabled policy intentionally restores original values while retaining
/// resource limits. Toggle it only as a reviewed startup configuration.
///
/// # Examples
///
/// ```
/// use qubit_redact::RedactionPolicy;
///
/// let mut policy = RedactionPolicy::disabled();
/// assert!(policy.is_disabled());
/// policy.set_disabled(false);
/// assert!(!policy.is_disabled());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionPolicy {
    disabled: bool,
    rules: RedactionRules,
    masking: Arc<MaskingPolicy>,
    limits: RedactionLimits,
    #[cfg(feature = "http")]
    http: Arc<crate::formats::http::HttpPolicy>,
    #[cfg(feature = "uri")]
    uri: Arc<crate::formats::uri::UriPolicy>,
    #[cfg(feature = "json")]
    unkeyed_json_value_policy: UnkeyedJsonValuePolicy,
}

impl RedactionPolicy {
    /// Returns the fixed built-in standard policy.
    ///
    /// Its application rules are empty and its explicit floor is
    /// [`RedactionFloor::standard`], so it never observes later process-wide
    /// default installations.
    #[must_use]
    #[inline]
    pub fn standard() -> Self {
        STANDARD_POLICY.clone()
    }

    /// Returns a strict boundary policy whose unknown fields are masked at
    /// [`Sensitivity::Secret`] in addition to the standard floor.
    ///
    /// This preset is intended for untrusted external boundaries. It is more
    /// protective than [`Self::standard`] but may reduce diagnostic detail.
    #[must_use]
    #[inline]
    pub fn strict() -> Self {
        STRICT_POLICY.clone()
    }

    /// Returns the standard policy with redaction globally disabled.
    #[must_use]
    pub fn disabled() -> Self {
        let mut policy = Self::standard();
        policy.disabled = true;
        policy
    }

    /// Returns whether this policy bypasses redaction while retaining limits.
    #[must_use]
    pub const fn is_disabled(&self) -> bool {
        self.disabled
    }

    /// Changes the global redaction switch and returns this policy for
    /// chaining.
    #[must_use]
    pub fn set_disabled(&mut self, disabled: bool) -> &mut Self {
        self.disabled = disabled;
        self
    }

    /// Creates a deterministic builder with no application rules and the
    /// standard minimum-protection floor.
    #[must_use]
    #[inline]
    pub fn builder() -> RedactionPolicyBuilder {
        RedactionPolicyBuilder::new()
    }

    /// Creates a builder that exactly copies `self`.
    ///
    /// The copy includes application rules, limits, and the attached floor.
    #[must_use]
    #[inline]
    pub fn to_builder(&self) -> RedactionPolicyBuilder {
        RedactionPolicyBuilder::from_policy(self)
    }

    /// Creates a policy from fully resolved field rules and resource limits.
    #[must_use]
    pub(crate) fn from_rules(
        rules: RedactionRules,
        masking: MaskingPolicy,
        limits: RedactionLimits,
        #[cfg(feature = "http")] http: crate::formats::http::HttpPolicy,
        #[cfg(feature = "uri")] uri: crate::formats::uri::UriPolicy,
        #[cfg(feature = "json")] unkeyed_json_value_policy: UnkeyedJsonValuePolicy,
        disabled: bool,
    ) -> Self {
        Self {
            disabled,
            rules,
            masking: Arc::new(masking),
            limits,
            #[cfg(feature = "http")]
            http: Arc::new(http),
            #[cfg(feature = "uri")]
            uri: Arc::new(uri),
            #[cfg(feature = "json")]
            unkeyed_json_value_policy,
        }
    }

    /// Returns all static limits used by this policy.
    #[must_use]
    #[inline]
    pub const fn limits(&self) -> &RedactionLimits {
        &self.limits
    }

    /// Returns the unified HTTP context policy.
    #[must_use]
    #[cfg(feature = "http")]
    #[inline]
    pub fn http(&self) -> &crate::formats::http::HttpPolicy {
        self.http.as_ref()
    }

    /// Returns the unified URI context policy.
    #[must_use]
    #[cfg(feature = "uri")]
    #[inline]
    pub fn uri(&self) -> &crate::formats::uri::UriPolicy {
        self.uri.as_ref()
    }

    /// Returns the HTTP header field rules.
    #[must_use]
    #[cfg(feature = "http")]
    #[inline]
    pub fn header_rules(&self) -> &RedactionRules {
        self.http.header_rules()
    }

    /// Returns the HTTP query field rules.
    #[must_use]
    #[cfg(feature = "http")]
    #[inline]
    pub fn query_rules(&self) -> &RedactionRules {
        self.http.query_rules()
    }

    /// Returns the HTTP body field rules.
    #[must_use]
    #[cfg(feature = "http")]
    #[inline]
    pub fn body_rules(&self) -> &RedactionRules {
        self.http.body_rules()
    }

    /// Returns the HTTP URL path policy.
    #[must_use]
    #[cfg(feature = "http")]
    #[inline]
    pub fn url_path_policy(&self) -> crate::formats::http::UrlPathPolicy {
        self.http.url_path_policy()
    }

    /// Returns the HTTP text-body policy.
    #[must_use]
    #[cfg(feature = "http")]
    #[inline]
    pub fn text_body_policy(&self) -> crate::formats::http::TextBodyPolicy {
        self.http.text_body_policy()
    }

    /// Returns the URI path policy.
    #[must_use]
    #[cfg(feature = "uri")]
    #[inline]
    pub fn path_policy(&self) -> crate::formats::uri::UriPathPolicy {
        self.uri.path_policy()
    }

    /// Returns the URI fragment policy.
    #[must_use]
    #[cfg(feature = "uri")]
    #[inline]
    pub fn fragment_policy(&self) -> crate::formats::uri::UriFragmentPolicy {
        self.uri.fragment_policy()
    }

    /// Returns the behavior for root and array JSON scalar values.
    #[must_use]
    #[cfg(feature = "json")]
    #[inline]
    pub const fn unkeyed_json_value_policy(&self) -> UnkeyedJsonValuePolicy {
        self.unkeyed_json_value_policy
    }
    /// Returns the immutable field rules without diagnostic resource limits.
    #[must_use]
    #[inline]
    pub const fn rules(&self) -> &RedactionRules {
        &self.rules
    }

    /// Returns the base field policy view.
    #[must_use]
    #[inline]
    pub const fn fields(&self) -> &RedactionRules {
        &self.rules
    }

    /// Returns the attached minimum floor, or `None` when it was explicitly
    /// disabled.
    #[must_use]
    #[inline]
    pub fn floor(&self) -> Option<&RedactionFloor> {
        self.rules.floor()
    }

    /// Replaces the floor for this immutable policy.
    #[must_use]
    #[inline]
    pub fn with_floor(mut self, floor: RedactionFloor) -> Self {
        self.rules = self.rules.with_floor(floor);
        self
    }
    /// Disables every floor for this immutable policy.
    ///
    /// # Security
    ///
    /// This explicitly removes minimum protection inherited from any source.
    #[must_use]
    pub fn disable_floor(mut self) -> Self {
        self.rules = self.rules.disable_floor();
        self
    }

    /// Explains application-rule matching for `field` without applying the
    /// floor.
    ///
    /// This is useful for diagnostics about configured application rules. Use
    /// [`Self::sensitivity_for`] for the final security decision.
    #[inline]
    #[must_use]
    pub fn classify_field<'a>(&'a self, field: &str) -> FieldClassification<'a> {
        self.rules.classify_field(field)
    }

    /// Returns the final sensitivity for `field` after applying application
    /// rules and the enabled floor.
    ///
    /// Returns `None` only when neither layer classifies the field as
    /// sensitive.
    #[must_use]
    #[inline]
    pub fn sensitivity_for(&self, field: &str) -> Option<Sensitivity> {
        self.rules.sensitivity_for(field)
    }

    /// Resolves final sensitivity with exact-only field matching.
    #[must_use]
    #[inline]
    pub(crate) fn sensitivity_for_exact(&self, field: &str) -> Option<Sensitivity> {
        self.rules.sensitivity_for_exact(field)
    }

    /// Resolves final sensitivity with exact-only field matching.
    #[inline]
    pub(crate) fn resolve_field_exact(&self, field: &str) -> super::ResolvedField {
        self.rules.resolve_field_exact(field)
    }

    /// Returns the application layer's field-name matching mode.
    ///
    /// An attached floor may use a different matching mode for its independent
    /// classification.
    #[must_use]
    #[inline]
    pub fn matching(&self) -> FieldNameMatching {
        self.rules.matching()
    }

    /// Returns the application layer's fallback for unclassified fields.
    ///
    /// An attached floor applies its own fallback independently.
    #[must_use]
    #[inline]
    pub fn unknown_field_policy(&self) -> UnknownFieldPolicy {
        self.rules.unknown_field_policy()
    }
    /// Returns the single mask table used by every sensitivity decision.
    ///
    /// Field classification determines the effective sensitivity; this table
    /// determines how that sensitivity is rendered. Floors never own a second
    /// mask table.
    #[must_use]
    #[inline]
    pub fn masking(&self) -> &MaskingPolicy {
        self.masking.as_ref()
    }

    /// Iterates sensitive rules configured in the application layer only.
    ///
    /// Use [`Self::floor`] to inspect the independent minimum-protection
    /// rules.
    #[inline]
    pub fn application_sensitive_rules(&self) -> impl Iterator<Item = SensitiveFieldRule<'_>> {
        self.rules.application_sensitive_rules()
    }

    /// Iterates allow rules configured in the application layer only.
    ///
    /// These rules never bypass an enabled floor.
    #[inline]
    pub fn application_allow_rules(&self) -> impl Iterator<Item = AllowRule<'_>> {
        self.rules.application_allow_rules()
    }

    /// Resolves final sensitivity for `field`.
    #[inline]
    #[must_use]
    pub(crate) fn resolve_field(&self, field: &str) -> super::ResolvedField {
        self.rules.resolve_field(field)
    }
}

impl Default for RedactionPolicy {
    /// Clones the fixed standard policy.
    fn default() -> Self {
        STANDARD_POLICY.clone()
    }
}
