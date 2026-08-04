// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Builder for immutable HTTP redaction policy snapshots.

use crate::{
    PolicyError,
    PolicyLocation,
    RedactionFloor,
    RedactionRules,
    Sensitivity,
};

use super::context_rules_builder::ContextRulesBuilder;
use super::http_redaction_policy_parts::HttpPolicyParts;
use super::{
    HttpFieldContext,
    TextBodyPolicy,
    UrlPathPolicy,
};

/// Mutable construction state for an [`HttpPolicy`].
#[must_use]
#[derive(Debug, Clone)]
pub struct HttpPolicyBuilder {
    header: ContextRulesBuilder,
    query: ContextRulesBuilder,
    body: ContextRulesBuilder,
    url_path_policy: UrlPathPolicy,
    text_body_policy: TextBodyPolicy,
}

impl HttpPolicyBuilder {
    /// Creates empty application rules using the standard floor.
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
    pub(crate) fn from_policy(policy: &super::HttpPolicy) -> Self {
        Self {
            header: ContextRulesBuilder::from_rules(
                policy.header_rules(),
                PolicyLocation::HttpHeader,
            ),
            query: ContextRulesBuilder::from_rules(
                policy.query_rules(),
                PolicyLocation::HttpQuery,
            ),
            body: ContextRulesBuilder::from_rules(
                policy.body_rules(),
                PolicyLocation::HttpBody,
            ),
            url_path_policy: policy.url_path_policy(),
            text_body_policy: policy.text_body_policy(),
        }
    }

    /// Returns mutable construction state for one HTTP field context.
    fn context_mut(
        &mut self,
        context: HttpFieldContext,
    ) -> &mut ContextRulesBuilder {
        match context {
            HttpFieldContext::Header => &mut self.header,
            HttpFieldContext::Query => &mut self.query,
            HttpFieldContext::Body => &mut self.body,
        }
    }

    pub(crate) fn rules_mut(
        &mut self,
        context: HttpFieldContext,
        rules: RedactionRules,
    ) {
        *self.context_mut(context) =
            ContextRulesBuilder::from_rules(&rules, context.location());
    }

    pub(crate) fn floor_mut(
        &mut self,
        context: HttpFieldContext,
        floor: RedactionFloor,
    ) {
        self.context_mut(context).with_floor(floor);
    }

    pub(crate) fn disable_floor_mut(&mut self, context: HttpFieldContext) {
        self.context_mut(context).disable_floor();
    }

    pub(crate) fn floor_all_mut(&mut self, floor: RedactionFloor) {
        self.header.with_floor(floor.clone());
        self.query.with_floor(floor.clone());
        self.body.with_floor(floor);
    }

    pub(crate) fn disable_all_floors_mut(&mut self) {
        self.header.disable_floor();
        self.query.disable_floor();
        self.body.disable_floor();
    }

    pub(crate) fn raise_mut(
        &mut self,
        context: HttpFieldContext,
        name: &str,
        level: Sensitivity,
    ) -> Result<(), PolicyError> {
        self.context_mut(context).rules.raise(name, level)
    }

    pub(crate) fn override_level_mut(
        &mut self,
        context: HttpFieldContext,
        name: &str,
        level: Sensitivity,
    ) -> Result<(), PolicyError> {
        self.context_mut(context).rules.override_level(name, level)
    }

    pub(crate) fn allow_exact_mut(
        &mut self,
        context: HttpFieldContext,
        name: &str,
    ) -> Result<(), PolicyError> {
        self.context_mut(context).rules.allow_canonical_exact(name)
    }

    pub(crate) fn allow_suffix_mut(
        &mut self,
        context: HttpFieldContext,
        name: &str,
    ) -> Result<(), PolicyError> {
        self.context_mut(context).rules.allow_suffix(name)
    }

    pub(crate) fn remove_allow_exact_mut(
        &mut self,
        context: HttpFieldContext,
        name: &str,
    ) -> Result<(), PolicyError> {
        self.context_mut(context)
            .rules
            .remove_allow_canonical_exact(name)
    }

    pub(crate) fn remove_allow_suffix_mut(
        &mut self,
        context: HttpFieldContext,
        name: &str,
    ) -> Result<(), PolicyError> {
        self.context_mut(context).rules.remove_allow_suffix(name)
    }

    pub(crate) fn clear_allow_rules_mut(&mut self, context: HttpFieldContext) {
        self.context_mut(context).rules.clear_allow_rules();
    }

    pub(crate) fn url_path_mut(&mut self, policy: UrlPathPolicy) {
        self.url_path_policy = policy;
    }

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
    fn default() -> Self {
        Self::new()
    }
}
