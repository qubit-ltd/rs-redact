// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Builder for immutable HTTP redaction policy snapshots.

use crate::RedactionPolicy;

use super::{
    BodyBudget,
    HttpRedactionPolicy,
    TextBodyPolicy,
    UnkeyedJsonValuePolicy,
    UrlPathPolicy,
};

/// Mutable construction state for an [`HttpRedactionPolicy`].
#[must_use]
#[derive(Debug, Clone)]
pub struct HttpRedactionPolicyBuilder {
    /// Field policy used for HTTP headers.
    header_policy: RedactionPolicy,
    /// Field policy used for URL query and form values.
    query_policy: RedactionPolicy,
    /// Field policy used inside structured bodies.
    body_policy: RedactionPolicy,
    /// Visibility choice for non-root URL paths.
    url_path_policy: UrlPathPolicy,
    /// Visibility choice for opaque UTF-8 text bodies.
    text_body_policy: TextBodyPolicy,
    /// Visibility choice for unkeyed JSON scalars.
    unkeyed_json_value_policy: UnkeyedJsonValuePolicy,
    /// Finite body parser-input and log-output limits.
    body_budget: BodyBudget,
}

impl HttpRedactionPolicyBuilder {
    /// Creates a builder with three independent snapshots of `base`.
    ///
    /// # Parameters
    ///
    /// * `base` - Field policy cloned for header, query, and body contexts.
    ///
    /// # Returns
    ///
    /// A builder with fail-closed behavior choices and finite default limits.
    #[inline]
    pub fn new(base: RedactionPolicy) -> Self {
        Self {
            header_policy: base.clone(),
            query_policy: base.clone(),
            body_policy: base,
            url_path_policy: UrlPathPolicy::default(),
            text_body_policy: TextBodyPolicy::default(),
            unkeyed_json_value_policy: UnkeyedJsonValuePolicy::default(),
            body_budget: BodyBudget::default(),
        }
    }

    /// Replaces the header-field policy snapshot.
    ///
    /// # Parameters
    ///
    /// * `policy` - Immutable policy used for HTTP headers.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[inline(always)]
    pub fn header_policy(mut self, policy: RedactionPolicy) -> Self {
        self.header_policy = policy;
        self
    }

    /// Replaces the query and form field-policy snapshot.
    ///
    /// # Parameters
    ///
    /// * `policy` - Immutable policy used for query and form fields.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[inline(always)]
    pub fn query_policy(mut self, policy: RedactionPolicy) -> Self {
        self.query_policy = policy;
        self
    }

    /// Replaces the structured-body field-policy snapshot.
    ///
    /// # Parameters
    ///
    /// * `policy` - Immutable policy used for fields inside HTTP bodies.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[inline(always)]
    pub fn body_policy(mut self, policy: RedactionPolicy) -> Self {
        self.body_policy = policy;
        self
    }

    /// Replaces the URL path visibility choice.
    ///
    /// # Parameters
    ///
    /// * `policy` - Visibility behavior for non-root URL paths.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[inline(always)]
    pub const fn url_path_policy(mut self, policy: UrlPathPolicy) -> Self {
        self.url_path_policy = policy;
        self
    }

    /// Replaces the opaque text-body visibility choice.
    ///
    /// # Parameters
    ///
    /// * `policy` - Visibility behavior for opaque UTF-8 body text.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[inline(always)]
    pub const fn text_body_policy(mut self, policy: TextBodyPolicy) -> Self {
        self.text_body_policy = policy;
        self
    }

    /// Replaces the unkeyed JSON scalar visibility choice.
    ///
    /// # Parameters
    ///
    /// * `policy` - Visibility behavior for JSON values without field names.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[inline(always)]
    pub const fn unkeyed_json_value_policy(
        mut self,
        policy: UnkeyedJsonValuePolicy,
    ) -> Self {
        self.unkeyed_json_value_policy = policy;
        self
    }

    /// Replaces the finite hard body limits.
    ///
    /// # Parameters
    ///
    /// * `budget` - Previously checked parser-input and output byte limits.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[inline(always)]
    pub const fn body_budget(mut self, budget: BodyBudget) -> Self {
        self.body_budget = budget;
        self
    }

    /// Builds the complete immutable HTTP policy.
    ///
    /// All fallible validation occurs while constructing the component field
    /// policies and [`BodyBudget`], so this final operation is infallible.
    ///
    /// # Returns
    ///
    /// A complete immutable HTTP policy snapshot.
    #[inline(always)]
    pub fn build(self) -> HttpRedactionPolicy {
        HttpRedactionPolicy::from_parts(
            self.header_policy,
            self.query_policy,
            self.body_policy,
            self.url_path_policy,
            self.text_body_policy,
            self.unkeyed_json_value_policy,
            self.body_budget,
        )
    }
}

impl Default for HttpRedactionPolicyBuilder {
    /// Creates a builder from the current process-wide field-policy default.
    ///
    /// # Returns
    ///
    /// The same construction state as
    /// `HttpRedactionPolicy::builder(RedactionPolicy::default())`.
    #[inline(always)]
    fn default() -> Self {
        Self::new(RedactionPolicy::default())
    }
}
