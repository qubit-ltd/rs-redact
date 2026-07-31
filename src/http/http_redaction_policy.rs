// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Immutable policy snapshot for every HTTP redaction context.

use crate::{
    DiagnosticBudget,
    JsonDepthBudget,
    RedactionPolicy,
};

use super::{
    BodyBudget,
    HttpRedactionPolicyBuilder,
    TextBodyPolicy,
    UnkeyedJsonValuePolicy,
    UrlPathPolicy,
};

/// Combines independent HTTP field policies, behavior choices, and hard limits.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRedactionPolicy {
    /// Field policy used for HTTP header names and values.
    header_policy: RedactionPolicy,
    /// Field policy used for URL query and form names and values.
    query_policy: RedactionPolicy,
    /// Field policy used inside structured HTTP body formats.
    body_policy: RedactionPolicy,
    /// Visibility choice for non-root URL paths.
    url_path_policy: UrlPathPolicy,
    /// Visibility choice for opaque UTF-8 text bodies.
    text_body_policy: TextBodyPolicy,
    /// Visibility choice for JSON scalar values without a field name.
    unkeyed_json_value_policy: UnkeyedJsonValuePolicy,
    /// Finite parser-input and log-output byte limits.
    body_budget: BodyBudget,
    /// Finite input and output limits for non-body diagnostics.
    diagnostic_budget: DiagnosticBudget,
}

impl HttpRedactionPolicy {
    /// Creates a builder without header, query, or body field rules.
    ///
    /// # Returns
    ///
    /// A mutable HTTP policy builder with fail-closed behavior defaults and
    /// finite budgets.
    #[inline(always)]
    pub fn builder() -> HttpRedactionPolicyBuilder {
        HttpRedactionPolicyBuilder::new()
    }

    /// Creates a builder initialized from the current default HTTP policy.
    ///
    /// # Returns
    ///
    /// A mutable HTTP policy builder containing a snapshot of the current
    /// default policy.
    #[inline(always)]
    pub fn builder_from_default() -> HttpRedactionPolicyBuilder {
        HttpRedactionPolicyBuilder::from_policy(&Self::default())
    }

    /// Creates a builder with three mutable copies of `base`.
    ///
    /// # Parameters
    ///
    /// * `base` - Field policy copied for header, query, and body contexts.
    ///
    /// # Returns
    ///
    /// A mutable HTTP policy builder using fail-closed behavior defaults and
    /// `base`'s diagnostic budget snapshot.
    pub fn builder_from(base: RedactionPolicy) -> HttpRedactionPolicyBuilder {
        HttpRedactionPolicyBuilder::from_base_policy(base)
    }

    /// Creates an immutable HTTP policy from complete builder state.
    ///
    /// # Parameters
    ///
    /// * `header_policy` - Header field-policy snapshot.
    /// * `query_policy` - Query and form field-policy snapshot.
    /// * `body_policy` - Structured-body field-policy snapshot.
    /// * `url_path_policy` - URL path visibility choice.
    /// * `text_body_policy` - Opaque text-body visibility choice.
    /// * `unkeyed_json_value_policy` - Unkeyed scalar visibility choice.
    /// * `body_budget` - Checked body input and output byte limits.
    ///
    /// # Returns
    ///
    /// A complete immutable HTTP policy.
    #[inline(always)]
    pub(super) fn from_parts(
        header_policy: RedactionPolicy,
        query_policy: RedactionPolicy,
        body_policy: RedactionPolicy,
        url_path_policy: UrlPathPolicy,
        text_body_policy: TextBodyPolicy,
        unkeyed_json_value_policy: UnkeyedJsonValuePolicy,
        body_budget: BodyBudget,
    ) -> Self {
        let diagnostic_budget = body_policy.diagnostic_budget();
        Self {
            header_policy,
            query_policy,
            body_policy,
            url_path_policy,
            text_body_policy,
            unkeyed_json_value_policy,
            body_budget,
            diagnostic_budget,
        }
    }

    /// Replaces the non-body diagnostic input and output byte limits.
    ///
    /// # Parameters
    ///
    /// * `diagnostic_budget` - Replacement limits for non-body diagnostics.
    ///
    /// # Returns
    ///
    /// The policy with its diagnostic budget replaced.
    #[inline(always)]
    pub(super) const fn with_diagnostic_budget(
        mut self,
        diagnostic_budget: DiagnosticBudget,
    ) -> Self {
        self.diagnostic_budget = diagnostic_budget;
        self
    }

    /// Returns the immutable header-field policy snapshot.
    ///
    /// # Returns
    ///
    /// The policy used for HTTP headers.
    #[inline(always)]
    pub const fn header_policy(&self) -> &RedactionPolicy {
        &self.header_policy
    }

    /// Returns the immutable query and form field-policy snapshot.
    ///
    /// # Returns
    ///
    /// The policy used for URL query and form fields.
    #[inline(always)]
    pub const fn query_policy(&self) -> &RedactionPolicy {
        &self.query_policy
    }

    /// Returns the immutable structured-body field-policy snapshot.
    ///
    /// # Returns
    ///
    /// The policy used for fields inside HTTP bodies.
    #[inline(always)]
    pub const fn body_policy(&self) -> &RedactionPolicy {
        &self.body_policy
    }

    /// Returns the URL path visibility choice.
    ///
    /// # Returns
    ///
    /// The immutable URL path behavior.
    #[inline(always)]
    pub const fn url_path_policy(&self) -> UrlPathPolicy {
        self.url_path_policy
    }

    /// Returns the opaque text-body visibility choice.
    ///
    /// # Returns
    ///
    /// The immutable text-body behavior.
    #[inline(always)]
    pub const fn text_body_policy(&self) -> TextBodyPolicy {
        self.text_body_policy
    }

    /// Returns the unkeyed JSON scalar visibility choice.
    ///
    /// # Returns
    ///
    /// The immutable unkeyed JSON behavior.
    #[inline(always)]
    pub const fn unkeyed_json_value_policy(&self) -> UnkeyedJsonValuePolicy {
        self.unkeyed_json_value_policy
    }

    /// Returns the recursion-depth limit for structured JSON bodies.
    ///
    /// # Returns
    ///
    /// The immutable positive JSON depth budget from the body policy.
    #[inline(always)]
    pub const fn json_depth_budget(&self) -> JsonDepthBudget {
        self.body_policy.json_depth_budget()
    }

    /// Returns the finite body input and output limits.
    ///
    /// # Returns
    ///
    /// The checked hard body budget.
    #[inline(always)]
    pub const fn body_budget(&self) -> BodyBudget {
        self.body_budget
    }

    /// Returns the finite diagnostic input and output limits.
    ///
    /// # Returns
    ///
    /// The checked hard diagnostic budget.
    #[inline(always)]
    pub const fn diagnostic_budget(&self) -> DiagnosticBudget {
        self.diagnostic_budget
    }
}

impl Default for HttpRedactionPolicy {
    /// Creates a fail-closed HTTP policy from the current global field default.
    ///
    /// # Returns
    ///
    /// Three independent default policy snapshots and finite body limits.
    #[inline(always)]
    fn default() -> Self {
        let base = RedactionPolicy::default();
        Self::from_parts(
            base.clone(),
            base.clone(),
            base,
            UrlPathPolicy::default(),
            TextBodyPolicy::default(),
            UnkeyedJsonValuePolicy::default(),
            BodyBudget::default(),
        )
    }
}
