// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Builder for immutable HTTP redaction policy snapshots.
// qubit-style: allow type-file-name

use super::HttpFieldContext;
use super::TextBodyPolicy;
use super::UrlPathPolicy;
use super::context_rules_builder::ContextRulesBuilder;
use super::http_redaction_policy_parts::HttpPolicyParts;
use crate::PolicyError;
use crate::PolicyLocation;
use crate::RedactionFloor;
use crate::RedactionRules;
use crate::Sensitivity;

/// Mutable construction state for an [`super::HttpPolicy`].
#[derive(Debug, Clone)]
pub struct HttpPolicyBuilder {
    /// Mutable header classification state.
    header: ContextRulesBuilder,
    /// Mutable query and form classification state.
    query: ContextRulesBuilder,
    /// Mutable structured-body classification state.
    body: ContextRulesBuilder,
    /// Selected URL path visibility rule.
    url_path_policy: UrlPathPolicy,
    /// Selected opaque text-body visibility rule.
    text_body_policy: TextBodyPolicy,
}

impl HttpPolicyBuilder {
    /// Creates empty application rules using the standard floor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            header: ContextRulesBuilder::empty(PolicyLocation::HttpHeader),
            query: ContextRulesBuilder::empty(PolicyLocation::HttpQuery),
            body: ContextRulesBuilder::empty(PolicyLocation::HttpBody),
            url_path_policy: UrlPathPolicy::default(),
            text_body_policy: TextBodyPolicy::default(),
        }
    }

    /// Copies the immutable HTTP context snapshot.
    #[must_use]
    pub(crate) fn from_policy(policy: &super::HttpPolicy) -> Self {
        Self {
            header: ContextRulesBuilder::from_rules(policy.header_rules(), PolicyLocation::HttpHeader),
            query: ContextRulesBuilder::from_rules(policy.query_rules(), PolicyLocation::HttpQuery),
            body: ContextRulesBuilder::from_rules(policy.body_rules(), PolicyLocation::HttpBody),
            url_path_policy: policy.url_path_policy(),
            text_body_policy: policy.text_body_policy(),
        }
    }

    /// Returns mutable rules for one HTTP field context.
    ///
    /// # Parameters
    ///
    /// * `context` - HTTP field context whose rules are selected.
    ///
    /// # Returns
    ///
    /// The mutable rules builder for `context`.
    fn context_mut(&mut self, context: HttpFieldContext) -> &mut ContextRulesBuilder {
        match context {
            HttpFieldContext::Header => &mut self.header,
            HttpFieldContext::Query => &mut self.query,
            HttpFieldContext::Body => &mut self.body,
        }
    }

    /// Replaces the rules for one HTTP field context.
    ///
    /// # Parameters
    ///
    /// * `context` - HTTP field context whose rules are replaced.
    /// * `rules` - Application rules to copy into the builder.
    pub(crate) fn rules_mut(&mut self, context: HttpFieldContext, rules: RedactionRules) {
        *self.context_mut(context) = ContextRulesBuilder::from_rules(&rules, context.location());
    }

    /// Replaces the minimum sensitivity floor for one HTTP context.
    ///
    /// # Parameters
    ///
    /// * `context` - HTTP field context whose floor is changed.
    /// * `floor` - Minimum sensitivity required for that context.
    pub(crate) fn floor_mut(&mut self, context: HttpFieldContext, floor: RedactionFloor) {
        self.context_mut(context).with_floor(floor);
    }

    /// Disables the minimum floor for one HTTP field context.
    ///
    /// # Parameters
    ///
    /// * `context` - HTTP field context whose floor is disabled.
    pub(crate) fn disable_floor_mut(&mut self, context: HttpFieldContext) {
        self.context_mut(context).disable_floor();
    }

    /// Applies one minimum sensitivity floor to every HTTP context.
    ///
    /// # Parameters
    ///
    /// * `floor` - Minimum sensitivity copied into each context.
    #[inline]
    pub(crate) fn floor_all_mut(&mut self, floor: RedactionFloor) {
        self.header.with_floor(floor.clone());
        self.query.with_floor(floor.clone());
        self.body.with_floor(floor);
    }

    /// Disables the minimum floor for every HTTP context.
    pub(crate) fn disable_all_floors_mut(&mut self) {
        self.header.disable_floor();
        self.query.disable_floor();
        self.body.disable_floor();
    }

    /// Raises one HTTP context field to at least `level`.
    ///
    /// # Parameters
    ///
    /// * `context` - HTTP field context to update.
    /// * `name` - Field name to canonicalize and update.
    /// * `level` - Minimum sensitivity to apply.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::EmptyFieldName`] when `name` has no canonical
    /// field name.
    pub(crate) fn raise_mut(
        &mut self,
        context: HttpFieldContext,
        name: &str,
        level: Sensitivity,
    ) -> Result<(), PolicyError> {
        self.context_mut(context).rules.raise(name, level)
    }

    /// Sets one HTTP context field to exactly `level`.
    ///
    /// # Parameters
    ///
    /// * `context` - HTTP field context to update.
    /// * `name` - Field name to canonicalize and update.
    /// * `level` - Sensitivity to apply.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::EmptyFieldName`] when `name` has no canonical
    /// field name.
    pub(crate) fn override_level_mut(
        &mut self,
        context: HttpFieldContext,
        name: &str,
        level: Sensitivity,
    ) -> Result<(), PolicyError> {
        self.context_mut(context).rules.override_level(name, level)
    }

    /// Adds an exact allow rule to one HTTP field context.
    ///
    /// # Parameters
    ///
    /// * `context` - HTTP field context to update.
    /// * `name` - Field name to allow after canonicalization.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::EmptyFieldName`] when `name` has no canonical
    /// field name.
    pub(crate) fn allow_exact_mut(&mut self, context: HttpFieldContext, name: &str) -> Result<(), PolicyError> {
        self.context_mut(context).rules.allow_canonical_exact(name)
    }

    /// Adds a token-suffix allow rule to one HTTP field context.
    ///
    /// # Parameters
    ///
    /// * `context` - HTTP field context to update.
    /// * `name` - Field-name suffix to allow after canonicalization.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::EmptyFieldName`] when `name` has no canonical
    /// field name.
    pub(crate) fn allow_suffix_mut(&mut self, context: HttpFieldContext, name: &str) -> Result<(), PolicyError> {
        self.context_mut(context).rules.allow_suffix(name)
    }

    /// Removes an exact allow rule from one HTTP field context.
    ///
    /// # Parameters
    ///
    /// * `context` - HTTP field context to update.
    /// * `name` - Field name to remove after canonicalization.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::EmptyFieldName`] when `name` has no canonical
    /// field name.
    pub(crate) fn remove_allow_exact_mut(&mut self, context: HttpFieldContext, name: &str) -> Result<(), PolicyError> {
        self.context_mut(context).rules.remove_allow_canonical_exact(name)
    }

    /// Removes a token-suffix allow rule from one HTTP field context.
    ///
    /// # Parameters
    ///
    /// * `context` - HTTP field context to update.
    /// * `name` - Field-name suffix to remove after canonicalization.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::EmptyFieldName`] when `name` has no canonical
    /// field name.
    pub(crate) fn remove_allow_suffix_mut(&mut self, context: HttpFieldContext, name: &str) -> Result<(), PolicyError> {
        self.context_mut(context).rules.remove_allow_suffix(name)
    }

    /// Removes all allow rules from one HTTP field context.
    ///
    /// # Parameters
    ///
    /// * `context` - HTTP field context to clear.
    pub(crate) fn clear_allow_rules_mut(&mut self, context: HttpFieldContext) {
        self.context_mut(context).rules.clear_allow_rules();
    }

    /// Sets the URL path handling policy.
    ///
    /// # Parameters
    ///
    /// * `policy` - Policy controlling URL path redaction.
    pub(crate) fn url_path_mut(&mut self, policy: UrlPathPolicy) {
        self.url_path_policy = policy;
    }

    /// Sets the text-body handling policy.
    ///
    /// # Parameters
    ///
    /// * `policy` - Policy controlling text-body redaction.
    pub(crate) fn text_body_mut(&mut self, policy: TextBodyPolicy) {
        self.text_body_policy = policy;
    }

    /// Builds the complete HTTP policy, validating header, query, then body.
    pub(crate) fn build(self) -> Result<super::HttpPolicy, PolicyError> {
        Ok(super::HttpPolicy::from_parts(HttpPolicyParts {
            header_rules: self.header.build()?,
            query_rules: self.query.build()?,
            body_rules: self.body.build()?,
            url_path_policy: self.url_path_policy,
            text_body_policy: self.text_body_policy,
        }))
    }
}

impl Default for HttpPolicyBuilder {
    /// Creates a builder with the standard HTTP handling defaults.
    fn default() -> Self {
        Self::new()
    }
}
