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
use std::sync::OnceLock;

use super::AllowRule;
use super::FieldClassification;
use super::FieldNameMatching;
#[cfg(feature = "json")]
use super::JsonDepthLimit;
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
        crate::http::HttpPolicyBuilder::new()
            .build()
            .expect("the built-in HTTP policy must be valid"),
        #[cfg(feature = "uri")]
        crate::uri::UriPolicyBuilder::new()
            .build()
            .expect("the built-in URI policy must be valid"),
        #[cfg(feature = "json")]
        UnkeyedJsonValuePolicy::PassThrough,
    )
});
static STRICT_POLICY: LazyLock<RedactionPolicy> = LazyLock::new(|| {
    RedactionPolicy::from_rules(
        RedactionRules::new(
            RedactionPolicyInner {
                sensitive: Default::default(),
                allow_exact: Default::default(),
                allow_suffix: Default::default(),
                matching: FieldNameMatching::ExactOrTokenSuffix,
                unknown_field_policy: UnknownFieldPolicy::Redact(
                    Sensitivity::Secret,
                ),
            },
            Some(RedactionFloor::standard()),
        ),
        MaskingPolicy::default(),
        RedactionLimits::default(),
        #[cfg(feature = "http")]
        {
            let mut http = crate::http::HttpPolicyBuilder::new();
            http.url_path_mut(crate::http::UrlPathPolicy::Redact);
            http.text_body_mut(crate::http::TextBodyPolicy::Redact);
            http.build()
                .expect("the built-in HTTP policy must be valid")
        },
        #[cfg(feature = "uri")]
        crate::uri::UriPolicyBuilder::new()
            .build()
            .expect("the built-in URI policy must be valid"),
        #[cfg(feature = "json")]
        UnkeyedJsonValuePolicy::Redact,
    )
});
static GLOBAL_POLICY: OnceLock<RedactionPolicy> = OnceLock::new();
/// Immutable redaction policy.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionPolicy {
    rules: RedactionRules,
    masking: Arc<MaskingPolicy>,
    limits: RedactionLimits,
    #[cfg(feature = "http")]
    http: Arc<crate::http::HttpPolicy>,
    #[cfg(feature = "uri")]
    uri: Arc<crate::uri::UriPolicy>,
    #[cfg(feature = "json")]
    unkeyed_json_value_policy: UnkeyedJsonValuePolicy,
}

impl RedactionPolicy {
    /// Installs the application-owned default policy exactly once.
    ///
    /// The policy is copied into a process-wide immutable slot. Reading
    /// [`Self::global`] before installation only observes [`Self::standard`]
    /// and does not occupy this slot. If a policy was already installed, the
    /// rejected policy is returned through
    /// [`crate::InstallGlobalPolicyError::into_policy`]. Libraries should leave
    /// this operation to their host application.
    ///
    /// # Warning
    ///
    /// This is application-assembly configuration, not runtime reconfiguration.
    /// The executable should call it at most once, after constructing the final
    /// policy and before starting workers or request processing. Library crates
    /// must never call it. Calling it from feature code, tests sharing one
    /// process, or after concurrent application work has begun is a lifecycle
    /// error even though the type system cannot distinguish those call sites.
    ///
    /// Objects created before installation may already own a snapshot of
    /// [`Self::standard`]. They intentionally keep that snapshot after
    /// installation. Any object that must use the application policy must be
    /// created after this call or receive the policy explicitly.
    pub fn install_global(
        policy: Self,
    ) -> Result<(), crate::InstallGlobalPolicyError> {
        GLOBAL_POLICY
            .set(policy)
            .map_err(crate::InstallGlobalPolicyError)
    }

    /// Returns the process-wide default policy snapshot.
    ///
    /// Returns the installed policy when available; otherwise returns the
    /// fixed standard policy without changing global installation state.
    /// Existing policy and redactor snapshots are unaffected by a later global
    /// installation.
    ///
    /// # Warning
    ///
    /// The pre-installation fallback exists so application assembly may safely
    /// construct dependencies that consult redaction defaults before the host
    /// has finalized its policy. It is not a runtime configuration mechanism.
    /// A caller that requires the application policy must either run after
    /// [`Self::install_global`] or use an explicitly injected policy. Never
    /// assume that a value returned before installation will change afterward.
    #[inline]
    pub fn global() -> &'static Self {
        GLOBAL_POLICY.get().unwrap_or(&STANDARD_POLICY)
    }

    /// Returns the fixed built-in standard policy.
    ///
    /// Its application rules are empty and its explicit floor is
    /// [`RedactionFloor::standard`], so it never observes later process-wide
    /// default installations.
    #[inline]
    pub fn standard() -> Self {
        STANDARD_POLICY.clone()
    }

    /// Returns a strict boundary policy whose unknown fields are masked at
    /// [`Sensitivity::Secret`] in addition to the standard floor.
    ///
    /// This preset is intended for untrusted external boundaries. It is more
    /// protective than [`Self::standard`] but may reduce diagnostic detail.
    #[inline]
    pub fn strict() -> Self {
        STRICT_POLICY.clone()
    }

    /// Creates a builder initialized from the process-wide default snapshot.
    #[inline]
    pub fn builder_from_default() -> RedactionPolicyBuilder {
        Self::builder_from(&Self::default())
    }

    /// Creates a deterministic builder with no application rules and the
    /// standard minimum-protection floor.
    #[inline]
    pub fn builder() -> RedactionPolicyBuilder {
        RedactionPolicyBuilder::new()
    }

    /// Creates a builder that exactly copies `self`.
    ///
    /// The copy includes application rules, limits, and the attached floor.
    #[inline]
    pub fn to_builder(&self) -> RedactionPolicyBuilder {
        RedactionPolicyBuilder::from_policy(self)
    }

    /// Creates a builder that exactly copies `base`.
    #[inline]
    pub fn builder_from(base: &Self) -> RedactionPolicyBuilder {
        base.to_builder()
    }

    /// Creates a policy from fully resolved field rules and resource limits.
    pub(crate) fn from_rules(
        rules: RedactionRules,
        masking: MaskingPolicy,
        limits: RedactionLimits,
        #[cfg(feature = "http")] http: crate::http::HttpPolicy,
        #[cfg(feature = "uri")] uri: crate::uri::UriPolicy,
        #[cfg(feature = "json")]
        unkeyed_json_value_policy: UnkeyedJsonValuePolicy,
    ) -> Self {
        Self {
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
    #[inline]
    pub const fn limits(&self) -> &RedactionLimits {
        &self.limits
    }

    /// Returns the unified HTTP context policy.
    #[cfg(feature = "http")]
    #[inline]
    pub fn http(&self) -> &crate::http::HttpPolicy {
        self.http.as_ref()
    }

    /// Returns the unified URI context policy.
    #[cfg(feature = "uri")]
    #[inline]
    pub fn uri(&self) -> &crate::uri::UriPolicy {
        self.uri.as_ref()
    }

    /// Returns the HTTP header field rules.
    #[cfg(feature = "http")]
    #[inline]
    pub fn header_rules(&self) -> &RedactionRules {
        self.http.header_rules()
    }

    /// Returns the HTTP query field rules.
    #[cfg(feature = "http")]
    #[inline]
    pub fn query_rules(&self) -> &RedactionRules {
        self.http.query_rules()
    }

    /// Returns the HTTP body field rules.
    #[cfg(feature = "http")]
    #[inline]
    pub fn body_rules(&self) -> &RedactionRules {
        self.http.body_rules()
    }

    /// Returns the HTTP URL path policy.
    #[cfg(feature = "http")]
    #[inline]
    pub fn url_path_policy(&self) -> crate::http::UrlPathPolicy {
        self.http.url_path_policy()
    }

    /// Returns the HTTP text-body policy.
    #[cfg(feature = "http")]
    #[inline]
    pub fn text_body_policy(&self) -> crate::http::TextBodyPolicy {
        self.http.text_body_policy()
    }

    /// Returns the HTTP body byte budget.
    #[cfg(feature = "http")]
    #[inline]
    pub fn body_budget(&self) -> crate::http::BodyBudget {
        self.limits.http_body()
    }

    /// Returns the URI path policy.
    #[cfg(feature = "uri")]
    #[inline]
    pub fn path_policy(&self) -> crate::uri::UriPathPolicy {
        self.uri.path_policy()
    }

    /// Returns the URI fragment policy.
    #[cfg(feature = "uri")]
    #[inline]
    pub fn fragment_policy(&self) -> crate::uri::UriFragmentPolicy {
        self.uri.fragment_policy()
    }

    /// Returns the maximum JSON nesting depth for JSON redaction.
    #[cfg(feature = "json")]
    #[inline]
    pub const fn json_depth_limit(&self) -> JsonDepthLimit {
        self.limits.json_depth_limit()
    }

    /// Returns the behavior for root and array JSON scalar values.
    #[cfg(feature = "json")]
    #[inline]
    pub const fn unkeyed_json_value_policy(&self) -> UnkeyedJsonValuePolicy {
        self.unkeyed_json_value_policy
    }
    /// Returns the immutable field rules without diagnostic resource limits.
    #[inline]
    pub const fn rules(&self) -> &RedactionRules {
        &self.rules
    }

    /// Returns the base field policy view.
    #[inline]
    pub const fn fields(&self) -> &RedactionRules {
        &self.rules
    }

    /// Returns the attached minimum floor, or `None` when it was explicitly
    /// disabled.
    #[inline]
    pub fn floor(&self) -> Option<&RedactionFloor> {
        self.rules.floor()
    }

    /// Replaces the floor for this immutable policy.
    pub fn with_floor(mut self, floor: RedactionFloor) -> Self {
        self.rules = self.rules.with_floor(floor);
        self
    }
    /// Disables every floor for this immutable policy.
    ///
    /// # Security
    ///
    /// This explicitly removes minimum protection inherited from any source.
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
    pub fn classify_field<'a>(
        &'a self,
        field: &str,
    ) -> FieldClassification<'a> {
        self.rules.classify_field(field)
    }

    /// Returns the final sensitivity for `field` after applying application
    /// rules and the enabled floor.
    ///
    /// Returns `None` only when neither layer classifies the field as
    /// sensitive.
    #[inline]
    pub fn sensitivity_for(&self, field: &str) -> Option<Sensitivity> {
        self.rules.sensitivity_for(field)
    }

    /// Resolves final sensitivity with exact-only field matching.
    #[inline]
    pub(crate) fn sensitivity_for_exact(
        &self,
        field: &str,
    ) -> Option<Sensitivity> {
        self.rules.sensitivity_for_exact(field)
    }

    /// Resolves final sensitivity with exact-only field matching.
    #[inline]
    pub(crate) fn resolve_field_exact(
        &self,
        field: &str,
    ) -> super::ResolvedField {
        self.rules.resolve_field_exact(field)
    }

    /// Returns the application layer's field-name matching mode.
    ///
    /// An attached floor may use a different matching mode for its independent
    /// classification.
    #[inline]
    pub fn matching(&self) -> FieldNameMatching {
        self.rules.matching()
    }

    /// Returns the application layer's fallback for unclassified fields.
    ///
    /// An attached floor applies its own fallback independently.
    #[inline]
    pub fn unknown_field_policy(&self) -> UnknownFieldPolicy {
        self.rules.unknown_field_policy()
    }
    /// Returns the single mask table used by every sensitivity decision.
    ///
    /// Field classification determines the effective sensitivity; this table
    /// determines how that sensitivity is rendered. Floors never own a second
    /// mask table.
    #[inline]
    pub fn masking(&self) -> &MaskingPolicy {
        self.masking.as_ref()
    }

    /// Iterates sensitive rules configured in the application layer only.
    ///
    /// Use [`Self::floor`] to inspect the independent minimum-protection
    /// rules.
    #[inline]
    pub fn application_sensitive_rules(
        &self,
    ) -> impl Iterator<Item = SensitiveFieldRule<'_>> {
        self.rules.application_sensitive_rules()
    }

    /// Iterates allow rules configured in the application layer only.
    ///
    /// These rules never bypass an enabled floor.
    #[inline]
    pub fn application_allow_rules(
        &self,
    ) -> impl Iterator<Item = AllowRule<'_>> {
        self.rules.application_allow_rules()
    }

    /// Resolves final sensitivity for `field`.
    #[inline]
    pub(crate) fn resolve_field(&self, field: &str) -> super::ResolvedField {
        self.rules.resolve_field(field)
    }
}

impl Default for RedactionPolicy {
    /// Clones the currently visible process default.
    ///
    /// # Warning
    ///
    /// Before application assembly calls [`Self::install_global`], this clones
    /// [`Self::standard`]. The clone is a permanent snapshot and will not be
    /// updated by a later installation. Policy-sensitive objects that require
    /// application configuration must be constructed after installation or be
    /// given an explicit policy. The standard policy is only a deterministic
    /// library baseline; the host application must configure every field that
    /// requires stricter handling and must not infer application coverage from
    /// this fallback snapshot.
    fn default() -> Self {
        Self::global().clone()
    }
}
