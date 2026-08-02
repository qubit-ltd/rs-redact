// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Builder for immutable HTTP redaction policy snapshots.

use std::sync::Arc;

use crate::{
    DiagnosticBudget, JsonDepthBudget, MaskPolicy, MaskingPolicy, PolicyError, PolicyLocation,
    RedactionFloor, RedactionPolicy, RedactionRules, Sensitivity, policy::RedactionRulesBuilder,
};

use super::context_rules_builder::ContextRulesBuilder;
use super::http_redaction_policy_parts::HttpRedactionPolicyParts;
use super::{
    BodyBudget, HttpFieldContext, HttpRedactionPolicy, TextBodyPolicy, UnkeyedJsonValuePolicy,
    UrlPathPolicy,
};

/// Mutable construction state for an [`HttpRedactionPolicy`].
#[must_use]
#[derive(Debug, Clone)]
pub struct HttpRedactionPolicyBuilder {
    header: ContextRulesBuilder,
    query: ContextRulesBuilder,
    body: ContextRulesBuilder,
    masking: MaskingPolicy,
    url_path_policy: UrlPathPolicy,
    text_body_policy: TextBodyPolicy,
    unkeyed_json_value_policy: UnkeyedJsonValuePolicy,
    body_budget: BodyBudget,
    diagnostic_budget: DiagnosticBudget,
    json_depth_budget: JsonDepthBudget,
}

impl HttpRedactionPolicyBuilder {
    /// Creates empty application rules using the standard floor.
    pub fn new() -> Self {
        let floor = RedactionFloor::standard();
        Self {
            header: ContextRulesBuilder::empty(PolicyLocation::HttpHeader, floor.clone()),
            query: ContextRulesBuilder::empty(PolicyLocation::HttpQuery, floor.clone()),
            body: ContextRulesBuilder::empty(PolicyLocation::HttpBody, floor),
            masking: MaskingPolicy::default(),
            url_path_policy: UrlPathPolicy::default(),
            text_body_policy: TextBodyPolicy::default(),
            unkeyed_json_value_policy: UnkeyedJsonValuePolicy::default(),
            body_budget: BodyBudget::default(),
            diagnostic_budget: DiagnosticBudget::default(),
            json_depth_budget: JsonDepthBudget::default(),
        }
    }

    /// Copies a complete immutable HTTP policy.
    pub fn from_policy(policy: &HttpRedactionPolicy) -> Self {
        Self {
            header: ContextRulesBuilder::from_rules(
                policy.header_rules(),
                PolicyLocation::HttpHeader,
            ),
            query: ContextRulesBuilder::from_rules(policy.query_rules(), PolicyLocation::HttpQuery),
            body: ContextRulesBuilder::from_rules(policy.body_rules(), PolicyLocation::HttpBody),
            masking: policy.masking().clone(),
            url_path_policy: policy.url_path_policy(),
            text_body_policy: policy.text_body_policy(),
            unkeyed_json_value_policy: policy.unkeyed_json_value_policy(),
            body_budget: policy.body_budget(),
            diagnostic_budget: policy.diagnostic_budget(),
            json_depth_budget: policy.json_depth_budget(),
        }
    }

    /// Creates three context copies from one complete field policy.
    pub(crate) fn from_base_policy(policy: &RedactionPolicy) -> Self {
        Self {
            header: ContextRulesBuilder::from_rules(policy.rules(), PolicyLocation::HttpHeader),
            query: ContextRulesBuilder::from_rules(policy.rules(), PolicyLocation::HttpQuery),
            body: ContextRulesBuilder::from_rules(policy.rules(), PolicyLocation::HttpBody),
            masking: policy.masking().clone(),
            url_path_policy: UrlPathPolicy::default(),
            text_body_policy: TextBodyPolicy::default(),
            unkeyed_json_value_policy: UnkeyedJsonValuePolicy::default(),
            body_budget: BodyBudget::default(),
            diagnostic_budget: policy.diagnostic_budget(),
            json_depth_budget: policy.json_depth_budget(),
        }
    }

    /// Returns mutable construction state for one HTTP field context.
    fn context_mut(&mut self, context: HttpFieldContext) -> &mut ContextRulesBuilder {
        match context {
            HttpFieldContext::Header => &mut self.header,
            HttpFieldContext::Query => &mut self.query,
            HttpFieldContext::Body => &mut self.body,
        }
    }

    /// Replaces rules for one HTTP field context.
    pub fn rules(mut self, context: HttpFieldContext, rules: RedactionRules) -> Self {
        *self.context_mut(context) = ContextRulesBuilder::from_rules(&rules, context.location());
        self
    }

    /// Sets a floor for one HTTP field context.
    pub fn floor_for(mut self, context: HttpFieldContext, floor: RedactionFloor) -> Self {
        self.context_mut(context).with_floor(floor);
        self
    }

    /// Disables the floor for one HTTP field context.
    pub fn disable_floor_for(mut self, context: HttpFieldContext) -> Self {
        self.context_mut(context).disable_floor();
        self
    }

    /// Raises one field's application sensitivity in a selected context.
    pub fn raise(
        mut self,
        context: HttpFieldContext,
        name: &str,
        level: Sensitivity,
    ) -> Result<Self, PolicyError> {
        self.context_mut(context).rules.raise(name, level)?;
        Ok(self)
    }

    /// Overrides one field's application sensitivity in a selected context.
    pub fn override_level(
        mut self,
        context: HttpFieldContext,
        name: &str,
        level: Sensitivity,
    ) -> Result<Self, PolicyError> {
        self.context_mut(context)
            .rules
            .override_level(name, level)?;
        Ok(self)
    }

    /// Adds an exact allow rule in a selected context.
    pub fn allow_exact(
        mut self,
        context: HttpFieldContext,
        name: &str,
    ) -> Result<Self, PolicyError> {
        self.context_mut(context)
            .rules
            .allow_canonical_exact(name)?;
        Ok(self)
    }

    /// Adds a suffix allow rule in a selected context.
    pub fn allow_suffix(
        mut self,
        context: HttpFieldContext,
        name: &str,
    ) -> Result<Self, PolicyError> {
        self.context_mut(context).rules.allow_suffix(name)?;
        Ok(self)
    }

    /// Removes an exact allow rule in a selected context.
    pub fn remove_allow_exact(
        mut self,
        context: HttpFieldContext,
        name: &str,
    ) -> Result<Self, PolicyError> {
        self.context_mut(context)
            .rules
            .remove_allow_canonical_exact(name)?;
        Ok(self)
    }

    /// Removes a suffix allow rule in a selected context.
    pub fn remove_allow_suffix(
        mut self,
        context: HttpFieldContext,
        name: &str,
    ) -> Result<Self, PolicyError> {
        self.context_mut(context).rules.remove_allow_suffix(name)?;
        Ok(self)
    }

    /// Removes every application allow rule in a selected context.
    pub fn clear_allow_rules(mut self, context: HttpFieldContext) -> Self {
        self.context_mut(context).rules.clear_allow_rules();
        self
    }

    /// Sets the same floor for every HTTP context.
    pub fn floor_all(mut self, floor: RedactionFloor) -> Self {
        self.header.with_floor(floor.clone());
        self.query.with_floor(floor.clone());
        self.body.with_floor(floor);
        self
    }

    /// Disables every HTTP context floor.
    pub fn disable_all_floors(mut self) -> Self {
        self.header.disable_floor();
        self.query.disable_floor();
        self.body.disable_floor();
        self
    }

    /// Validates a field name in the selected HTTP context.
    pub fn validate_field_name(context: HttpFieldContext, name: &str) -> Result<(), PolicyError> {
        RedactionRulesBuilder::validate_field_name(name, context.location())
    }

    /// Sets the shared mask policy for values at `level`.
    pub fn mask(mut self, level: Sensitivity, policy: MaskPolicy) -> Result<Self, PolicyError> {
        let masking = self.masking.with_policy(level, policy);
        masking.validate(PolicyLocation::HttpMasking)?;
        self.masking = masking;
        Ok(self)
    }

    /// Replaces URL path handling.
    pub const fn url_path_policy(mut self, policy: UrlPathPolicy) -> Self {
        self.url_path_policy = policy;
        self
    }
    /// Replaces opaque text-body handling.
    pub const fn text_body_policy(mut self, policy: TextBodyPolicy) -> Self {
        self.text_body_policy = policy;
        self
    }
    /// Replaces unkeyed JSON value handling.
    pub const fn unkeyed_json_value_policy(mut self, policy: UnkeyedJsonValuePolicy) -> Self {
        self.unkeyed_json_value_policy = policy;
        self
    }
    /// Replaces the structured JSON depth limit.
    pub const fn json_depth_budget(mut self, budget: JsonDepthBudget) -> Self {
        self.json_depth_budget = budget;
        self
    }
    /// Replaces the body byte limits.
    pub const fn body_budget(mut self, budget: BodyBudget) -> Self {
        self.body_budget = budget;
        self
    }
    /// Replaces diagnostic limits.
    pub const fn diagnostic_budget(mut self, budget: DiagnosticBudget) -> Self {
        self.diagnostic_budget = budget;
        self
    }

    /// Builds the complete HTTP policy, validating header, query, then body.
    pub fn build(self) -> Result<HttpRedactionPolicy, PolicyError> {
        self.masking.validate(PolicyLocation::HttpMasking)?;
        Ok(HttpRedactionPolicy::from_parts(HttpRedactionPolicyParts {
            header_rules: self.header.build()?,
            query_rules: self.query.build()?,
            body_rules: self.body.build()?,
            masking: Arc::new(self.masking),
            diagnostic_budget: self.diagnostic_budget,
            body_budget: self.body_budget,
            json_depth_budget: self.json_depth_budget,
            url_path_policy: self.url_path_policy,
            text_body_policy: self.text_body_policy,
            unkeyed_json_value_policy: self.unkeyed_json_value_policy,
        }))
    }
}

impl Default for HttpRedactionPolicyBuilder {
    fn default() -> Self {
        Self::new()
    }
}
