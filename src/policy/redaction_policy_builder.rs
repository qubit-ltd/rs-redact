// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable builder for immutable redaction policies.

use super::DomainRedactionLimits;
use super::FieldNameMatching;
use super::InputOutputLimit;
#[cfg(feature = "json")]
use super::JsonDepthLimit;
use super::MaskPolicy;
use super::MaskingPolicy;
use super::PolicyError;
use super::PolicyLocation;
use super::RedactionFloor;
use super::RedactionLimits;
use super::RedactionPolicy;
use super::RedactionRules;
use super::RedactionRulesBuilder;
use super::SensitiveFieldPreset;
use super::Sensitivity;
#[cfg(feature = "json")]
use super::UnkeyedJsonValuePolicy;
use super::UnknownFieldPolicy;

/// Mutable construction state for an immutable [`RedactionPolicy`].
///
/// Configuration setters are available through the grouped views returned by
/// [`Self::fields`], [`Self::limits`], [`Self::http`], and [`Self::uri`].
/// Duplicate consuming setters are intentionally not available at this level:
///
/// ```compile_fail
/// use qubit_redact::{RedactionPolicy, Sensitivity};
///
/// let _ = RedactionPolicy::builder().raise("token", Sensitivity::Secret);
/// ```
#[derive(Debug, Clone)]
pub struct RedactionPolicyBuilder {
    rules: RedactionRulesBuilder,
    masking: MaskingPolicy,
    floor: Option<RedactionFloor>,
    limits: RedactionLimits,
    #[cfg(feature = "http")]
    http: crate::formats::http::HttpPolicyBuilder,
    #[cfg(feature = "uri")]
    uri: crate::formats::uri::UriPolicyBuilder,
    #[cfg(feature = "json")]
    unkeyed_json_value_policy: UnkeyedJsonValuePolicy,
}

impl RedactionPolicyBuilder {
    #[must_use]
    /// Creates an empty application-rule builder with the standard floor.
    pub fn new() -> Self {
        Self {
            rules: RedactionRulesBuilder::empty(PolicyLocation::Rules),
            masking: MaskingPolicy::default(),
            floor: Some(RedactionFloor::standard()),
            limits: RedactionLimits::default(),
            #[cfg(feature = "http")]
            http: crate::formats::http::HttpPolicyBuilder::new(),
            #[cfg(feature = "uri")]
            uri: crate::formats::uri::UriPolicyBuilder::new(),
            #[cfg(feature = "json")]
            unkeyed_json_value_policy: UnkeyedJsonValuePolicy::PassThrough,
        }
    }
    #[must_use]
    /// Copies the immutable policy into mutable builder state.
    pub(super) fn from_policy(policy: &RedactionPolicy) -> Self {
        Self {
            rules: RedactionRulesBuilder::from_inner(
                &policy.rules().clone_application(),
                PolicyLocation::Rules,
            ),
            masking: policy.masking().clone(),
            floor: policy.rules().floor().cloned(),
            limits: *policy.limits(),
            #[cfg(feature = "http")]
            http: crate::formats::http::HttpPolicyBuilder::from_policy(
                policy.http(),
            ),
            #[cfg(feature = "uri")]
            uri: crate::formats::uri::UriPolicyBuilder::from_policy(
                policy.uri(),
            ),
            #[cfg(feature = "json")]
            unkeyed_json_value_policy: policy.unkeyed_json_value_policy(),
        }
    }

    #[must_use]
    #[inline(always)]
    /// Returns the mutable base-field configuration view.
    pub fn fields(&mut self) -> FieldsBuilder<'_> {
        FieldsBuilder { builder: self }
    }

    /// Returns the mutable HTTP configuration view.
    #[must_use]
    #[inline(always)]
    #[cfg(feature = "http")]
    pub fn http(&mut self) -> HttpPolicyBuilderView<'_> {
        HttpPolicyBuilderView { builder: self }
    }

    /// Returns the mutable URI configuration view.
    #[must_use]
    #[inline(always)]
    #[cfg(feature = "uri")]
    pub fn uri(&mut self) -> UriPolicyBuilderView<'_> {
        UriPolicyBuilderView {
            builder: &mut self.uri,
        }
    }

    #[must_use]
    #[inline(always)]
    /// Returns the mutable static-limits configuration view.
    pub fn limits(&mut self) -> LimitsBuilder<'_> {
        LimitsBuilder { builder: self }
    }

    /// Validates that `field` has a non-empty canonical application-rule name.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::EmptyFieldName`] at
    /// [`PolicyLocation::Rules`] when canonicalization leaves no name.
    pub fn validate_field_name(field: &str) -> Result<(), PolicyError> {
        RedactionRulesBuilder::validate_field_name(field, PolicyLocation::Rules)
    }

    /// Sets behavior for root and array JSON scalar values.
    ///
    /// This setter remains on the root builder because the JSON feature does
    /// not expose a separate grouped builder.
    #[cfg(feature = "json")]
    #[must_use]
    pub const fn unkeyed_json_value_policy(
        mut self,
        policy: UnkeyedJsonValuePolicy,
    ) -> Self {
        self.unkeyed_json_value_policy = policy;
        self
    }

    #[must_use]
    /// Validates and returns the immutable policy snapshot.
    ///
    /// # Errors
    ///
    /// Returns a [`PolicyError`] when final policy validation fails.
    pub fn build(self) -> Result<RedactionPolicy, PolicyError> {
        let rules = RedactionRules::new(self.rules.build_inner()?, self.floor);
        self.masking.validate(PolicyLocation::Rules)?;
        #[cfg(feature = "http")]
        let http = self.http.build()?;
        #[cfg(feature = "uri")]
        let uri = self.uri.build()?;
        Ok(RedactionPolicy::from_rules(
            rules,
            self.masking,
            self.limits,
            #[cfg(feature = "http")]
            http,
            #[cfg(feature = "uri")]
            uri,
            #[cfg(feature = "json")]
            self.unkeyed_json_value_policy,
        ))
    }
}

mod views {
    use super::DomainRedactionLimits;
    use super::FieldNameMatching;
    use super::InputOutputLimit;
    #[cfg(feature = "json")]
    use super::JsonDepthLimit;
    use super::MaskPolicy;
    use super::MaskingPolicy;
    use super::PolicyError;
    use super::PolicyLocation;
    use super::RedactionFloor;
    use super::RedactionLimits;
    use super::RedactionPolicyBuilder;
    #[cfg(feature = "http")]
    use super::RedactionRules;
    use super::SensitiveFieldPreset;
    use super::Sensitivity;
    use super::UnknownFieldPolicy;

    /// Mutable view over the base field policy.
    pub struct FieldsBuilder<'a> {
        pub(super) builder: &'a mut RedactionPolicyBuilder,
    }

    impl FieldsBuilder<'_> {
        #[must_use]
        #[inline(always)]
        /// Sets field-name matching for the base policy.
        pub fn matching(&mut self, matching: FieldNameMatching) -> &mut Self {
            self.builder.rules.matching(matching);
            self
        }

        /// Sets the base fallback for unknown fields.
        pub fn unknown_field_policy(
            &mut self,
            policy: UnknownFieldPolicy,
        ) -> &mut Self {
            self.builder.rules.unknown_field_policy(policy);
            self
        }

        /// Includes all fields from a built-in sensitive preset.
        pub fn include_preset(
            &mut self,
            preset: SensitiveFieldPreset,
        ) -> &mut Self {
            self.builder.rules.include_preset(preset);
            self
        }

        /// Raises a base field's minimum sensitivity.
        pub fn raise(
            &mut self,
            field: &str,
            level: Sensitivity,
        ) -> Result<&mut Self, PolicyError> {
            self.builder.rules.raise(field, level)?;
            Ok(self)
        }

        /// Replaces one base field rule without weakening floors.
        pub fn override_level(
            &mut self,
            field: &str,
            level: Sensitivity,
        ) -> Result<&mut Self, PolicyError> {
            self.builder.rules.override_level(field, level)?;
            Ok(self)
        }

        /// Adds a base exact allow rule.
        pub fn allow_exact(
            &mut self,
            field: &str,
        ) -> Result<&mut Self, PolicyError> {
            self.builder.rules.allow_canonical_exact(field)?;
            Ok(self)
        }

        /// Adds a base suffix allow rule.
        pub fn allow_suffix(
            &mut self,
            field: &str,
        ) -> Result<&mut Self, PolicyError> {
            self.builder.rules.allow_suffix(field)?;
            Ok(self)
        }

        /// Removes a base exact allow rule.
        pub fn remove_allow_exact(
            &mut self,
            field: &str,
        ) -> Result<&mut Self, PolicyError> {
            self.builder.rules.remove_allow_canonical_exact(field)?;
            Ok(self)
        }

        /// Removes a base suffix allow rule.
        pub fn remove_allow_suffix(
            &mut self,
            field: &str,
        ) -> Result<&mut Self, PolicyError> {
            self.builder.rules.remove_allow_suffix(field)?;
            Ok(self)
        }

        /// Removes all base allow rules.
        pub fn clear_allow_rules(&mut self) -> &mut Self {
            self.builder.rules.clear_allow_rules();
            self
        }

        #[must_use]
        #[inline(always)]
        /// Replaces the base minimum-protection floor.
        pub fn floor(&mut self, floor: RedactionFloor) -> &mut Self {
            self.builder.floor = Some(floor);
            self
        }

        /// Disables the base floor explicitly.
        pub fn disable_floor(&mut self) -> &mut Self {
            self.builder.floor = None;
            self
        }

        /// Replaces one shared masking level.
        pub fn mask(
            &mut self,
            level: Sensitivity,
            policy: MaskPolicy,
        ) -> Result<&mut Self, PolicyError> {
            let mut masking =
                MaskingPolicy::builder_from(&self.builder.masking);
            masking.policy(level, policy);
            let masking = masking.build();
            masking.validate(PolicyLocation::Rules)?;
            self.builder.masking = masking;
            Ok(self)
        }
    }

    /// Mutable view over all HTTP context differences.
    #[cfg(feature = "http")]
    pub struct HttpPolicyBuilderView<'a> {
        pub(super) builder: &'a mut RedactionPolicyBuilder,
    }

    /// Mutable view over URI-specific behavior.
    #[cfg(feature = "uri")]
    pub struct UriPolicyBuilderView<'a> {
        pub(super) builder: &'a mut crate::formats::uri::UriPolicyBuilder,
    }

    #[cfg(feature = "uri")]
    impl UriPolicyBuilderView<'_> {
        /// Sets URI path visibility.
        pub fn path(
            &mut self,
            policy: crate::formats::uri::UriPathPolicy,
        ) -> &mut Self {
            self.builder.path_policy_mut(policy);
            self
        }

        /// Sets URI fragment visibility.
        pub fn fragment(
            &mut self,
            policy: crate::formats::uri::UriFragmentPolicy,
        ) -> &mut Self {
            self.builder.fragment_policy_mut(policy);
            self
        }
    }

    #[cfg(feature = "http")]
    impl HttpPolicyBuilderView<'_> {
        /// Returns the header context view.
        #[must_use]
        pub fn header(&mut self) -> HttpContextBuilderView<'_> {
            HttpContextBuilderView {
                builder: &mut self.builder.http,
                context: crate::formats::http::HttpFieldContext::Header,
            }
        }

        /// Returns the query/form context view.
        #[must_use]
        pub fn query(&mut self) -> HttpContextBuilderView<'_> {
            HttpContextBuilderView {
                builder: &mut self.builder.http,
                context: crate::formats::http::HttpFieldContext::Query,
            }
        }

        /// Returns the structured-body context view.
        #[must_use]
        pub fn body(&mut self) -> HttpContextBuilderView<'_> {
            HttpContextBuilderView {
                builder: &mut self.builder.http,
                context: crate::formats::http::HttpFieldContext::Body,
            }
        }

        /// Sets URL path visibility for HTTP diagnostics.
        pub fn url_path(
            &mut self,
            policy: crate::formats::http::UrlPathPolicy,
        ) -> &mut Self {
            self.builder.http.url_path_mut(policy);
            self
        }

        /// Sets opaque text-body visibility for HTTP diagnostics.
        pub fn text_body(
            &mut self,
            policy: crate::formats::http::TextBodyPolicy,
        ) -> &mut Self {
            self.builder.http.text_body_mut(policy);
            self
        }

        /// Sets the same floor for every HTTP field context.
        pub fn floor_all(&mut self, floor: RedactionFloor) -> &mut Self {
            self.builder.http.floor_all_mut(floor);
            self
        }

        /// Disables every HTTP field-context floor explicitly.
        pub fn disable_all_floors(&mut self) -> &mut Self {
            self.builder.http.disable_all_floors_mut();
            self
        }

        /// Sets the handling of root and array JSON scalar values in HTTP
        /// bodies.
        pub fn unkeyed_json(
            &mut self,
            policy: crate::formats::http::UnkeyedJsonValuePolicy,
        ) -> &mut Self {
            self.builder.unkeyed_json_value_policy = policy;
            self
        }
    }

    /// Mutable view over one HTTP field context.
    #[cfg(feature = "http")]
    pub struct HttpContextBuilderView<'a> {
        builder: &'a mut crate::formats::http::HttpPolicyBuilder,
        context: crate::formats::http::HttpFieldContext,
    }

    #[cfg(feature = "http")]
    impl HttpContextBuilderView<'_> {
        /// Replaces all rules for this HTTP field context.
        pub fn replace_rules(&mut self, rules: RedactionRules) -> &mut Self {
            self.builder.rules_mut(self.context, rules);
            self
        }

        /// Raises a context field's minimum sensitivity.
        pub fn raise(
            &mut self,
            field: &str,
            level: Sensitivity,
        ) -> Result<&mut Self, PolicyError> {
            self.builder.raise_mut(self.context, field, level)?;
            Ok(self)
        }

        /// Replaces a context field rule without weakening the base policy.
        pub fn override_level(
            &mut self,
            field: &str,
            level: Sensitivity,
        ) -> Result<&mut Self, PolicyError> {
            self.builder
                .override_level_mut(self.context, field, level)?;
            Ok(self)
        }

        /// Adds a context exact allow rule; the base policy still applies.
        pub fn allow_exact(
            &mut self,
            field: &str,
        ) -> Result<&mut Self, PolicyError> {
            self.builder.allow_exact_mut(self.context, field)?;
            Ok(self)
        }

        /// Adds a context suffix allow rule; the base policy still applies.
        pub fn allow_suffix(
            &mut self,
            field: &str,
        ) -> Result<&mut Self, PolicyError> {
            self.builder.allow_suffix_mut(self.context, field)?;
            Ok(self)
        }

        /// Removes a context exact allow rule.
        pub fn remove_allow_exact(
            &mut self,
            field: &str,
        ) -> Result<&mut Self, PolicyError> {
            self.builder.remove_allow_exact_mut(self.context, field)?;
            Ok(self)
        }

        /// Removes a context suffix allow rule.
        pub fn remove_allow_suffix(
            &mut self,
            field: &str,
        ) -> Result<&mut Self, PolicyError> {
            self.builder.remove_allow_suffix_mut(self.context, field)?;
            Ok(self)
        }

        /// Removes all context allow rules.
        pub fn clear_allow_rules(&mut self) -> &mut Self {
            self.builder.clear_allow_rules_mut(self.context);
            self
        }

        #[must_use]
        #[inline(always)]
        /// Adds a context floor. Base protection remains independently
        /// effective.
        pub fn floor(&mut self, floor: RedactionFloor) -> &mut Self {
            self.builder.floor_mut(self.context, floor);
            self
        }

        /// Disables this context's explicit floor.
        pub fn disable_floor(&mut self) -> &mut Self {
            self.builder.disable_floor_mut(self.context);
            self
        }
    }

    /// Mutable view over policy limits.
    pub struct LimitsBuilder<'a> {
        pub(super) builder: &'a mut RedactionPolicyBuilder,
    }

    impl LimitsBuilder<'_> {
        /// Sets the cumulative domain-structure traversal limits.
        pub fn domain(&mut self, limits: DomainRedactionLimits) -> &mut Self {
            let mut builder =
                RedactionLimits::builder_from(&self.builder.limits);
            builder.domain(limits);
            self.builder.limits = builder.build();
            self
        }

        /// Sets the cumulative diagnostic-event limit.
        pub fn diagnostic_event(
            &mut self,
            limit: InputOutputLimit,
        ) -> &mut Self {
            let mut builder =
                RedactionLimits::builder_from(&self.builder.limits);
            builder.diagnostic_event(limit);
            self.builder.limits = builder.build();
            self
        }

        /// Sets the independent ordinary-operation limit.
        pub fn ordinary_operation(
            &mut self,
            limit: InputOutputLimit,
        ) -> &mut Self {
            let mut builder =
                RedactionLimits::builder_from(&self.builder.limits);
            builder.ordinary_operation(limit);
            self.builder.limits = builder.build();
            self
        }

        /// Sets the local HTTP body limit.
        #[cfg(feature = "http")]
        pub fn http_body(
            &mut self,
            limit: crate::formats::http::BodyBudget,
        ) -> &mut Self {
            let mut builder =
                RedactionLimits::builder_from(&self.builder.limits);
            builder.http_body(limit);
            self.builder.limits = builder.build();
            self
        }

        /// Sets the JSON recursion-depth limit.
        #[cfg(feature = "json")]
        pub fn json_depth(&mut self, limit: JsonDepthLimit) -> &mut Self {
            let mut builder =
                RedactionLimits::builder_from(&self.builder.limits);
            builder.json_depth_limit(limit);
            self.builder.limits = builder.build();
            self
        }
    }
}

pub use views::FieldsBuilder;
#[cfg(feature = "http")]
pub use views::HttpContextBuilderView;
#[cfg(feature = "http")]
pub use views::HttpPolicyBuilderView;
pub use views::LimitsBuilder;
#[cfg(feature = "uri")]
pub use views::UriPolicyBuilderView;

impl Default for RedactionPolicyBuilder {
    /// Creates a builder with the standard floor and default limits.

    fn default() -> Self {
        Self::new()
    }
}
