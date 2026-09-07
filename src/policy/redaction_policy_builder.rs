// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable builder for immutable redaction policies.

use super::MaskingPolicy;
use super::PolicyError;
use super::PolicyLocation;
use super::RedactionFloor;
use super::RedactionLimits;
use super::RedactionLimitsBuilder;
use super::RedactionPolicy;
use super::RedactionRules;
use super::RedactionRulesBuilder;
use super::Sensitivity;
#[cfg(feature = "json")]
use super::UnkeyedJsonValuePolicy;

// Provides the transactional application-field view.
mod fields_builder;
// Provides the independently configured HTTP field-context view.
#[cfg(feature = "http")]
mod http_context_builder_view;
// Provides the grouped HTTP policy view.
#[cfg(feature = "http")]
mod http_policy_builder_view;
// Provides the grouped URI policy view.
#[cfg(feature = "uri")]
mod uri_policy_builder_view;

/// Mutable construction state for an immutable [`RedactionPolicy`].
///
/// Configuration setters are available through the grouped views returned by
/// [`Self::fields`] and [`Self::limits`], with feature-specific HTTP and URI
/// views when those formats are enabled.
/// Duplicate consuming setters are intentionally not available at this level:
///
/// ```compile_fail
/// use qubit_redact::{RedactionPolicy, Sensitivity};
///
/// let _ = RedactionPolicy::builder().raise("token", Sensitivity::Secret);
/// ```
///
/// # Examples
///
/// ```
/// use qubit_redact::RedactionPolicy;
///
/// let policy = RedactionPolicy::builder()
///     .fields(|fields| {
///         let _ = fields.secret_sensitive("api_token");
///     })
///     .expect("valid field rules")
///     .build()
///     .expect("valid policy");
/// assert!(policy.sensitivity_for("api_token").is_some());
/// ```
#[derive(Debug, Clone)]
pub struct RedactionPolicyBuilder {
    /// Whether the resulting policy bypasses redaction.
    disabled: bool,
    /// Mutable application field rules.
    rules: RedactionRulesBuilder,
    /// Shared masking strategies by sensitivity.
    masking: MaskingPolicy,
    /// Optional minimum-protection floor.
    floor: Option<RedactionFloor>,
    /// Resource limits for each transaction.
    limits: RedactionLimits,
    /// Mutable HTTP-specific policy state.
    #[cfg(feature = "http")]
    http: crate::formats::http::HttpPolicyBuilder,
    /// Mutable URI-specific policy state.
    #[cfg(feature = "uri")]
    uri: crate::formats::uri::UriPolicyBuilder,
    /// Handling for JSON scalars without a field key.
    #[cfg(feature = "json")]
    unkeyed_json_value_policy: UnkeyedJsonValuePolicy,
}

impl RedactionPolicyBuilder {
    /// Creates an empty application-rule builder with the standard floor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            disabled: false,
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

    /// Copies the immutable policy into mutable builder state.
    #[must_use]
    pub(super) fn from_policy(policy: &RedactionPolicy) -> Self {
        Self {
            disabled: policy.is_disabled(),
            rules: RedactionRulesBuilder::from_inner(&policy.rules().clone_application(), PolicyLocation::Rules),
            masking: policy.masking().clone(),
            floor: policy.rules().floor().cloned(),
            limits: *policy.limits(),
            #[cfg(feature = "http")]
            http: crate::formats::http::HttpPolicyBuilder::from_policy(policy.http()),
            #[cfg(feature = "uri")]
            uri: crate::formats::uri::UriPolicyBuilder::from_policy(policy.uri()),
            #[cfg(feature = "json")]
            unkeyed_json_value_policy: policy.unkeyed_json_value_policy(),
        }
    }

    /// Configures base field sensitivity rules transactionally.
    ///
    /// The closure writes into a temporary field draft. Field names are
    /// validated after the closure returns and the draft is applied only when
    /// every field is valid. The configuration methods inside the closure are
    /// therefore infallible and can be chained without a trailing `Ok(())`.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] when a field name is empty after
    /// canonicalization. The builder remains unchanged on error.
    pub fn fields<F>(self, configure: F) -> Result<Self, PolicyError>
    where
        F: FnOnce(&mut FieldsBuilder<'_>),
    {
        let mut draft = self.clone();
        let error = {
            let mut fields = FieldsBuilder {
                builder: &mut draft,
                error: None,
            };
            configure(&mut fields);
            fields.error.take()
        };
        if let Some(error) = error {
            return Err(error);
        }
        Ok(draft)
    }

    /// Configures HTTP policy through an isolated draft.
    ///
    /// The draft replaces this namespace only after the closure returns, so a
    /// failed build never partially updates the caller's builder.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] when the HTTP view records an invalid field
    /// rule. The original builder remains unchanged.
    #[cfg(feature = "http")]
    pub fn http<F>(self, configure: F) -> Result<Self, PolicyError>
    where
        F: FnOnce(&mut HttpPolicyBuilderView<'_>),
    {
        let mut draft = self.clone();
        let error = {
            let mut view = HttpPolicyBuilderView {
                builder: &mut draft,
                error: None,
            };
            configure(&mut view);
            view.error.take()
        };
        if let Some(error) = error {
            return Err(error);
        }
        Ok(draft)
    }

    /// Configures URI policy through an isolated draft.
    ///
    /// # Errors
    ///
    /// This operation is currently infallible. The result preserves the
    /// transactional shape shared by feature-specific builder views.
    #[cfg(feature = "uri")]
    pub fn uri<F>(self, configure: F) -> Result<Self, PolicyError>
    where
        F: FnOnce(&mut UriPolicyBuilderView<'_>),
    {
        let mut draft = self.clone();
        let mut view = UriPolicyBuilderView {
            builder: &mut draft.uri,
        };
        configure(&mut view);
        Ok(draft)
    }

    /// Configures transaction limits through a draft that is applied
    /// atomically.
    ///
    /// The closure mutates only a temporary limits builder. Once it returns,
    /// the completed limits replace this builder's limits as one update.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] when the completed limit set violates a
    /// platform collection capacity limit. No invalid limit snapshot is
    /// installed.
    pub fn limits<F>(mut self, configure: F) -> Result<Self, PolicyError>
    where
        F: FnOnce(&mut RedactionLimitsBuilder),
    {
        let mut limits = RedactionLimits::builder_from(&self.limits);
        configure(&mut limits);
        let limits = limits.build();
        limits.validate()?;
        self.limits = limits;
        Ok(self)
    }

    /// Sets behavior for root and array JSON scalar values.
    ///
    /// This setter remains on the root builder because the JSON feature does
    /// not expose a separate grouped builder.
    #[cfg(feature = "json")]
    #[must_use]
    #[inline(always)]
    pub const fn unkeyed_json_value_policy(mut self, policy: UnkeyedJsonValuePolicy) -> Self {
        self.unkeyed_json_value_policy = policy;
        self
    }

    /// Validates that `field` has a non-empty canonical application-rule name.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::EmptyFieldName`] at
    /// [`PolicyLocation::Rules`] when canonicalization leaves no name.
    #[inline(always)]
    pub fn validate_field_name(field: &str) -> Result<(), PolicyError> {
        RedactionRulesBuilder::validate_field_name(field, PolicyLocation::Rules)
    }

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
            self.disabled,
        ))
    }
}

pub use fields_builder::FieldsBuilder;
#[cfg(feature = "http")]
pub use http_context_builder_view::HttpContextBuilderView;
#[cfg(feature = "http")]
pub use http_policy_builder_view::HttpPolicyBuilderView;
#[cfg(feature = "uri")]
pub use uri_policy_builder_view::UriPolicyBuilderView;

impl Default for RedactionPolicyBuilder {
    /// Creates a builder with the standard floor and default limits.
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}
