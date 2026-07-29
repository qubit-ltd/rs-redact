// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Builder for immutable HTTP redaction policy snapshots.

use crate::{DiagnosticBudget, PolicyError, RedactionPolicy, RedactionPolicyBuilder, Sensitivity};

use super::{
    BodyBudget, HttpRedactionPolicy, TextBodyPolicy, UnkeyedJsonValuePolicy, UrlPathPolicy,
};

/// Mutable construction state for an [`HttpRedactionPolicy`].
#[must_use]
#[derive(Debug, Clone)]
pub struct HttpRedactionPolicyBuilder {
    /// Header-field policy construction state.
    header: RedactionPolicyBuilder,
    /// Query and form field-policy construction state.
    query: RedactionPolicyBuilder,
    /// Structured-body field-policy construction state.
    body: RedactionPolicyBuilder,
    /// Visibility choice for non-root URL paths.
    url_path_policy: UrlPathPolicy,
    /// Visibility choice for opaque UTF-8 text bodies.
    text_body_policy: TextBodyPolicy,
    /// Visibility choice for unkeyed JSON scalars.
    unkeyed_json_value_policy: UnkeyedJsonValuePolicy,
    /// Finite body parser-input and log-output limits.
    body_budget: BodyBudget,
    /// Finite limits for HTTP diagnostics outside captured bodies.
    diagnostic_budget: DiagnosticBudget,
}

impl HttpRedactionPolicyBuilder {
    /// Creates a builder with empty field policies and default HTTP behavior.
    ///
    /// # Returns
    ///
    /// A builder with fail-closed behavior choices and finite default limits.
    #[inline]
    pub fn new() -> Self {
        Self::empty()
    }

    /// Creates a builder with empty field policies and default HTTP behavior.
    ///
    /// # Returns
    ///
    /// A builder with fail-closed behavior choices and finite default limits.
    #[inline]
    pub(super) fn empty() -> Self {
        Self {
            header: RedactionPolicyBuilder::empty(),
            query: RedactionPolicyBuilder::empty(),
            body: RedactionPolicyBuilder::empty(),
            url_path_policy: UrlPathPolicy::default(),
            text_body_policy: TextBodyPolicy::default(),
            unkeyed_json_value_policy: UnkeyedJsonValuePolicy::default(),
            body_budget: BodyBudget::default(),
            diagnostic_budget: DiagnosticBudget::default(),
        }
    }

    /// Replaces this builder with the current default HTTP policy snapshot.
    ///
    /// # Returns
    ///
    /// A mutable copy of `HttpRedactionPolicy::default`.
    ///
    /// # Warning
    ///
    /// This replaces every builder component, including the header, query, and
    /// body policies, behavior choices, and budgets. Call this method before
    /// adding application-specific configuration.
    #[inline]
    pub fn load_default(self) -> Self {
        Self::from_policy(&HttpRedactionPolicy::default())
    }

    /// Creates a builder by copying a complete immutable HTTP policy.
    ///
    /// # Parameters
    ///
    /// * `policy` - HTTP policy whose fields, behaviors, and budgets are
    ///   copied.
    ///
    /// # Returns
    ///
    /// Mutable construction state equivalent to `policy`.
    #[inline]
    pub fn from_policy(policy: &HttpRedactionPolicy) -> Self {
        Self {
            header: RedactionPolicy::builder_from(policy.header_policy()),
            query: RedactionPolicy::builder_from(policy.query_policy()),
            body: RedactionPolicy::builder_from(policy.body_policy()),
            url_path_policy: policy.url_path_policy(),
            text_body_policy: policy.text_body_policy(),
            unkeyed_json_value_policy: policy.unkeyed_json_value_policy(),
            body_budget: policy.body_budget(),
            diagnostic_budget: policy.diagnostic_budget(),
        }
    }

    /// Creates a builder with three mutable copies of `base`.
    ///
    /// # Parameters
    ///
    /// * `base` - Field policy copied for all three HTTP contexts.
    ///
    /// # Returns
    ///
    /// A builder with fail-closed behavior choices and finite default limits.
    #[inline]
    pub(super) fn from_base_policy(base: RedactionPolicy) -> Self {
        Self {
            header: RedactionPolicy::builder_from(&base),
            query: RedactionPolicy::builder_from(&base),
            body: RedactionPolicy::builder_from(&base),
            url_path_policy: UrlPathPolicy::default(),
            text_body_policy: TextBodyPolicy::default(),
            unkeyed_json_value_policy: UnkeyedJsonValuePolicy::default(),
            body_budget: BodyBudget::default(),
            diagnostic_budget: base.diagnostic_budget(),
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
        self.header = RedactionPolicy::builder_from(&policy);
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
        self.query = RedactionPolicy::builder_from(&policy);
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
    #[inline]
    pub fn body_policy(mut self, policy: RedactionPolicy) -> Self {
        self.body = RedactionPolicy::builder_from(&policy);
        self
    }

    /// Raises one header field to at least `level`.
    ///
    /// # Parameters
    ///
    /// * `name` - Header name to canonicalize.
    /// * `level` - Minimum sensitivity level.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[inline]
    pub fn raise_header(mut self, name: &str, level: Sensitivity) -> Self {
        self.header = self.header.raise(name, level);
        self
    }

    /// Replaces one header field's sensitivity with `level`.
    ///
    /// # Parameters
    ///
    /// * `name` - Header name to canonicalize.
    /// * `level` - Explicit replacement sensitivity.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[inline]
    pub fn override_header(mut self, name: &str, level: Sensitivity) -> Self {
        self.header = self.header.override_level(name, level);
        self
    }

    /// Allows one exact header name to remain visible.
    ///
    /// # Parameters
    ///
    /// * `name` - Exact header name to allow after canonicalization.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[inline]
    pub fn allow_header_exact(mut self, name: &str) -> Self {
        self.header = self.header.allow_exact(name);
        self
    }

    /// Allows one header name at token-suffix boundaries.
    ///
    /// # Parameters
    ///
    /// * `name` - Header suffix to allow after canonicalization.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[inline]
    pub fn allow_header_suffix(mut self, name: &str) -> Self {
        self.header = self.header.allow_suffix(name);
        self
    }

    /// Removes one exact header allow rule.
    ///
    /// # Parameters
    ///
    /// * `name` - Header name whose exact allow rule is removed.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[inline]
    pub fn remove_header_allow_exact(mut self, name: &str) -> Self {
        self.header = self.header.remove_allow_exact(name);
        self
    }

    /// Removes one token-suffix header allow rule.
    ///
    /// # Parameters
    ///
    /// * `name` - Header suffix whose allow rule is removed.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[inline]
    pub fn remove_header_allow_suffix(mut self, name: &str) -> Self {
        self.header = self.header.remove_allow_suffix(name);
        self
    }

    /// Removes every header allow rule.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[inline]
    pub fn clear_header_allow_rules(mut self) -> Self {
        self.header = self.header.clear_allow_rules();
        self
    }

    /// Raises one query or form field to at least `level`.
    ///
    /// # Parameters
    ///
    /// * `name` - Query field name to canonicalize.
    /// * `level` - Minimum sensitivity level.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[inline]
    pub fn raise_query(mut self, name: &str, level: Sensitivity) -> Self {
        self.query = self.query.raise(name, level);
        self
    }

    /// Replaces one query or form field's sensitivity with `level`.
    ///
    /// # Parameters
    ///
    /// * `name` - Query field name to canonicalize.
    /// * `level` - Explicit replacement sensitivity.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[inline]
    pub fn override_query(mut self, name: &str, level: Sensitivity) -> Self {
        self.query = self.query.override_level(name, level);
        self
    }

    /// Allows one exact query or form field name to remain visible.
    ///
    /// # Parameters
    ///
    /// * `name` - Exact query field name to allow after canonicalization.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[inline]
    pub fn allow_query_exact(mut self, name: &str) -> Self {
        self.query = self.query.allow_exact(name);
        self
    }

    /// Allows one query or form field at token-suffix boundaries.
    ///
    /// # Parameters
    ///
    /// * `name` - Query field suffix to allow after canonicalization.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[inline]
    pub fn allow_query_suffix(mut self, name: &str) -> Self {
        self.query = self.query.allow_suffix(name);
        self
    }

    /// Removes one exact query or form-field allow rule.
    ///
    /// # Parameters
    ///
    /// * `name` - Query or form-field name whose exact allow rule is removed.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[inline]
    pub fn remove_query_allow_exact(mut self, name: &str) -> Self {
        self.query = self.query.remove_allow_exact(name);
        self
    }

    /// Removes one token-suffix query or form-field allow rule.
    ///
    /// # Parameters
    ///
    /// * `name` - Query or form-field suffix whose allow rule is removed.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[inline]
    pub fn remove_query_allow_suffix(mut self, name: &str) -> Self {
        self.query = self.query.remove_allow_suffix(name);
        self
    }

    /// Removes every query and form-field allow rule.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[inline]
    pub fn clear_query_allow_rules(mut self) -> Self {
        self.query = self.query.clear_allow_rules();
        self
    }

    /// Raises one structured-body field to at least `level`.
    ///
    /// # Parameters
    ///
    /// * `name` - Body field name to canonicalize.
    /// * `level` - Minimum sensitivity level.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[inline]
    pub fn raise_body(mut self, name: &str, level: Sensitivity) -> Self {
        self.body = self.body.raise(name, level);
        self
    }

    /// Replaces one structured-body field's sensitivity with `level`.
    ///
    /// # Parameters
    ///
    /// * `name` - Body field name to canonicalize.
    /// * `level` - Explicit replacement sensitivity.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[inline]
    pub fn override_body(mut self, name: &str, level: Sensitivity) -> Self {
        self.body = self.body.override_level(name, level);
        self
    }

    /// Allows one exact structured-body field name to remain visible.
    ///
    /// # Parameters
    ///
    /// * `name` - Exact body field name to allow after canonicalization.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[inline]
    pub fn allow_body_exact(mut self, name: &str) -> Self {
        self.body = self.body.allow_exact(name);
        self
    }

    /// Allows one structured-body field at token-suffix boundaries.
    ///
    /// # Parameters
    ///
    /// * `name` - Body field suffix to allow after canonicalization.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[inline]
    pub fn allow_body_suffix(mut self, name: &str) -> Self {
        self.body = self.body.allow_suffix(name);
        self
    }

    /// Removes one exact structured-body allow rule.
    ///
    /// # Parameters
    ///
    /// * `name` - Body-field name whose exact allow rule is removed.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[inline]
    pub fn remove_body_allow_exact(mut self, name: &str) -> Self {
        self.body = self.body.remove_allow_exact(name);
        self
    }

    /// Removes one token-suffix structured-body allow rule.
    ///
    /// # Parameters
    ///
    /// * `name` - Body-field suffix whose allow rule is removed.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[inline]
    pub fn remove_body_allow_suffix(mut self, name: &str) -> Self {
        self.body = self.body.remove_allow_suffix(name);
        self
    }

    /// Removes every structured-body allow rule.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[inline]
    pub fn clear_body_allow_rules(mut self) -> Self {
        self.body = self.body.clear_allow_rules();
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
    #[inline]
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
    #[inline]
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
    #[inline]
    pub const fn unkeyed_json_value_policy(mut self, policy: UnkeyedJsonValuePolicy) -> Self {
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

    /// Replaces the finite hard HTTP diagnostic limits.
    ///
    /// # Parameters
    ///
    /// * `budget` - Previously checked diagnostic input and output byte limits.
    ///
    /// # Returns
    ///
    /// The updated builder.
    #[inline(always)]
    pub fn diagnostic_budget(mut self, budget: DiagnosticBudget) -> Self {
        self.diagnostic_budget = budget;
        self
    }

    /// Validates all field rules and builds the complete HTTP policy.
    ///
    /// # Returns
    ///
    /// A complete immutable HTTP policy snapshot.
    ///
    /// # Errors
    ///
    /// Returns the first [`PolicyError`] found while validating the header,
    /// query, and body policy builders in that order.
    pub fn build(self) -> Result<HttpRedactionPolicy, PolicyError> {
        let header = self.header.build()?;
        let query = self.query.build()?;
        let body = self.body.build()?;
        Ok(HttpRedactionPolicy::from_parts(
            header,
            query,
            body,
            self.url_path_policy,
            self.text_body_policy,
            self.unkeyed_json_value_policy,
            self.body_budget,
        )
        .with_diagnostic_budget(self.diagnostic_budget))
    }
}

impl Default for HttpRedactionPolicyBuilder {
    /// Creates the same empty construction state as [`Self::new`].
    ///
    /// # Returns
    ///
    /// A builder with empty field policies and default HTTP behavior.
    fn default() -> Self {
        Self::new()
    }
}
