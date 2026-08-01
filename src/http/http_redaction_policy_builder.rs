// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Builder for immutable HTTP redaction policy snapshots.

use crate::{
    DiagnosticBudget,
    JsonDepthBudget,
    PolicyError,
    PolicyLocation,
    RedactionFloor,
    RedactionFloorState,
    RedactionPolicy,
    RedactionRules,
    Sensitivity,
    policy::RedactionRulesBuilder,
};

use super::http_redaction_policy_parts::HttpRedactionPolicyParts;
use super::{
    BodyBudget,
    HttpRedactionPolicy,
    TextBodyPolicy,
    UnkeyedJsonValuePolicy,
    UrlPathPolicy,
};

/// Construction state for a single HTTP field context.
#[derive(Debug, Clone)]
struct ContextRulesBuilder {
    rules: RedactionRulesBuilder,
    floor: Option<RedactionFloor>,
    floor_state: RedactionFloorState,
}

impl ContextRulesBuilder {
    /// Creates empty application rules inheriting `floor`.
    fn empty(location: PolicyLocation, floor: RedactionFloor) -> Self {
        Self {
            rules: RedactionRulesBuilder::empty(location),
            floor: Some(floor),
            floor_state: RedactionFloorState::GlobalDefault,
        }
    }

    /// Copies an immutable rules snapshot while assigning validation location.
    fn from_rules(rules: &RedactionRules, location: PolicyLocation) -> Self {
        Self {
            rules: RedactionRulesBuilder::from_inner(
                &rules.clone_application(),
                location,
            ),
            floor: rules.floor().cloned(),
            floor_state: rules.floor_state(),
        }
    }

    /// Replaces the floor snapshot.
    fn with_floor(mut self, floor: RedactionFloor) -> Self {
        self.floor = Some(floor);
        self.floor_state = RedactionFloorState::Explicit;
        self
    }

    /// Disables the floor snapshot.
    fn disable_floor(mut self) -> Self {
        self.floor = None;
        self.floor_state = RedactionFloorState::Disabled;
        self
    }

    /// Builds the immutable rules snapshot.
    fn build(self) -> Result<RedactionRules, PolicyError> {
        Ok(RedactionRules::new(
            self.rules.build_inner()?,
            self.floor,
            self.floor_state,
        ))
    }
}

/// Mutable construction state for an [`HttpRedactionPolicy`].
#[must_use]
#[derive(Debug, Clone)]
pub struct HttpRedactionPolicyBuilder {
    header: ContextRulesBuilder,
    query: ContextRulesBuilder,
    body: ContextRulesBuilder,
    url_path_policy: UrlPathPolicy,
    text_body_policy: TextBodyPolicy,
    unkeyed_json_value_policy: UnkeyedJsonValuePolicy,
    body_budget: BodyBudget,
    diagnostic_budget: DiagnosticBudget,
    json_depth_budget: JsonDepthBudget,
}

impl HttpRedactionPolicyBuilder {
    /// Creates empty application rules using a single global-floor snapshot.
    pub fn new() -> Self {
        let floor = RedactionFloor::global_default();
        Self {
            header: ContextRulesBuilder::empty(
                PolicyLocation::HttpHeader,
                floor.clone(),
            ),
            query: ContextRulesBuilder::empty(
                PolicyLocation::HttpQuery,
                floor.clone(),
            ),
            body: ContextRulesBuilder::empty(PolicyLocation::HttpBody, floor),
            url_path_policy: UrlPathPolicy::default(),
            text_body_policy: TextBodyPolicy::default(),
            unkeyed_json_value_policy: UnkeyedJsonValuePolicy::default(),
            body_budget: BodyBudget::default(),
            diagnostic_budget: DiagnosticBudget::default(),
            json_depth_budget: JsonDepthBudget::default(),
        }
    }

    /// Replaces every component with the current default HTTP snapshot.
    pub fn load_default(self) -> Self {
        Self::from_policy(&HttpRedactionPolicy::default())
    }

    /// Copies a complete immutable HTTP policy.
    pub fn from_policy(policy: &HttpRedactionPolicy) -> Self {
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
            unkeyed_json_value_policy: policy.unkeyed_json_value_policy(),
            body_budget: policy.body_budget(),
            diagnostic_budget: policy.diagnostic_budget(),
            json_depth_budget: policy.json_depth_budget(),
        }
    }

    /// Creates three context copies from one complete field policy.
    pub(crate) fn from_base_policy(policy: &RedactionPolicy) -> Self {
        Self {
            header: ContextRulesBuilder::from_rules(
                policy.rules(),
                PolicyLocation::HttpHeader,
            ),
            query: ContextRulesBuilder::from_rules(
                policy.rules(),
                PolicyLocation::HttpQuery,
            ),
            body: ContextRulesBuilder::from_rules(
                policy.rules(),
                PolicyLocation::HttpBody,
            ),
            url_path_policy: UrlPathPolicy::default(),
            text_body_policy: TextBodyPolicy::default(),
            unkeyed_json_value_policy: UnkeyedJsonValuePolicy::default(),
            body_budget: BodyBudget::default(),
            diagnostic_budget: policy.diagnostic_budget(),
            json_depth_budget: policy.json_depth_budget(),
        }
    }

    /// Replaces header rules.
    pub fn header_rules(mut self, rules: RedactionRules) -> Self {
        self.header =
            ContextRulesBuilder::from_rules(&rules, PolicyLocation::HttpHeader);
        self
    }
    /// Replaces query and form rules.
    pub fn query_rules(mut self, rules: RedactionRules) -> Self {
        self.query =
            ContextRulesBuilder::from_rules(&rules, PolicyLocation::HttpQuery);
        self
    }
    /// Replaces structured-body rules.
    pub fn body_rules(mut self, rules: RedactionRules) -> Self {
        self.body =
            ContextRulesBuilder::from_rules(&rules, PolicyLocation::HttpBody);
        self
    }

    /// Sets one floor for every HTTP context.
    pub fn floor(mut self, floor: RedactionFloor) -> Self {
        self.header = self.header.with_floor(floor.clone());
        self.query = self.query.with_floor(floor.clone());
        self.body = self.body.with_floor(floor);
        self
    }
    /// Sets the header floor.
    pub fn header_floor(mut self, floor: RedactionFloor) -> Self {
        self.header = self.header.with_floor(floor);
        self
    }
    /// Sets the query and form floor.
    pub fn query_floor(mut self, floor: RedactionFloor) -> Self {
        self.query = self.query.with_floor(floor);
        self
    }
    /// Sets the structured-body floor.
    pub fn body_floor(mut self, floor: RedactionFloor) -> Self {
        self.body = self.body.with_floor(floor);
        self
    }
    /// Disables every context floor.
    ///
    /// # Security
    /// This explicitly removes all minimum HTTP field protection.
    pub fn disable_floor(mut self) -> Self {
        self.header = self.header.disable_floor();
        self.query = self.query.disable_floor();
        self.body = self.body.disable_floor();
        self
    }
    /// Disables the header floor.
    ///
    /// # Security
    /// This explicitly removes minimum header protection.
    pub fn disable_header_floor(mut self) -> Self {
        self.header = self.header.disable_floor();
        self
    }
    /// Disables the query and form floor.
    ///
    /// # Security
    /// This explicitly removes minimum query protection.
    pub fn disable_query_floor(mut self) -> Self {
        self.query = self.query.disable_floor();
        self
    }
    /// Disables the structured-body floor.
    ///
    /// # Security
    /// This explicitly removes minimum body protection.
    pub fn disable_body_floor(mut self) -> Self {
        self.body = self.body.disable_floor();
        self
    }

    /// Applies header application rules.
    pub fn raise_header(mut self, name: &str, level: Sensitivity) -> Self {
        self.header.rules = self.header.rules.raise(name, level);
        self
    }
    /// Overrides one header application sensitivity.
    pub fn override_header(mut self, name: &str, level: Sensitivity) -> Self {
        self.header.rules = self.header.rules.override_level(name, level);
        self
    }
    /// Allows one exact header application name.
    pub fn allow_header_exact(mut self, name: &str) -> Self {
        self.header.rules = self.header.rules.allow_canonical_exact(name);
        self
    }
    /// Allows one header application suffix.
    pub fn allow_header_suffix(mut self, name: &str) -> Self {
        self.header.rules = self.header.rules.allow_suffix(name);
        self
    }
    /// Removes an exact header allow rule.
    pub fn remove_header_allow_exact(mut self, name: &str) -> Self {
        self.header.rules =
            self.header.rules.remove_allow_canonical_exact(name);
        self
    }
    /// Removes a header suffix allow rule.
    pub fn remove_header_allow_suffix(mut self, name: &str) -> Self {
        self.header.rules = self.header.rules.remove_allow_suffix(name);
        self
    }
    /// Removes all header allow rules.
    pub fn clear_header_allow_rules(mut self) -> Self {
        self.header.rules = self.header.rules.clear_allow_rules();
        self
    }

    /// Applies query application rules.
    pub fn raise_query(mut self, name: &str, level: Sensitivity) -> Self {
        self.query.rules = self.query.rules.raise(name, level);
        self
    }
    /// Overrides one query application sensitivity.
    pub fn override_query(mut self, name: &str, level: Sensitivity) -> Self {
        self.query.rules = self.query.rules.override_level(name, level);
        self
    }
    /// Allows one exact query application name.
    pub fn allow_query_exact(mut self, name: &str) -> Self {
        self.query.rules = self.query.rules.allow_canonical_exact(name);
        self
    }
    /// Allows one query application suffix.
    pub fn allow_query_suffix(mut self, name: &str) -> Self {
        self.query.rules = self.query.rules.allow_suffix(name);
        self
    }
    /// Removes an exact query allow rule.
    pub fn remove_query_allow_exact(mut self, name: &str) -> Self {
        self.query.rules = self.query.rules.remove_allow_canonical_exact(name);
        self
    }
    /// Removes a query suffix allow rule.
    pub fn remove_query_allow_suffix(mut self, name: &str) -> Self {
        self.query.rules = self.query.rules.remove_allow_suffix(name);
        self
    }
    /// Removes all query allow rules.
    pub fn clear_query_allow_rules(mut self) -> Self {
        self.query.rules = self.query.rules.clear_allow_rules();
        self
    }

    /// Applies structured-body application rules.
    pub fn raise_body(mut self, name: &str, level: Sensitivity) -> Self {
        self.body.rules = self.body.rules.raise(name, level);
        self
    }
    /// Overrides one structured-body application sensitivity.
    pub fn override_body(mut self, name: &str, level: Sensitivity) -> Self {
        self.body.rules = self.body.rules.override_level(name, level);
        self
    }
    /// Allows one exact structured-body application name.
    pub fn allow_body_exact(mut self, name: &str) -> Self {
        self.body.rules = self.body.rules.allow_canonical_exact(name);
        self
    }
    /// Allows one structured-body application suffix.
    pub fn allow_body_suffix(mut self, name: &str) -> Self {
        self.body.rules = self.body.rules.allow_suffix(name);
        self
    }
    /// Removes an exact structured-body allow rule.
    pub fn remove_body_allow_exact(mut self, name: &str) -> Self {
        self.body.rules = self.body.rules.remove_allow_canonical_exact(name);
        self
    }
    /// Removes a structured-body suffix allow rule.
    pub fn remove_body_allow_suffix(mut self, name: &str) -> Self {
        self.body.rules = self.body.rules.remove_allow_suffix(name);
        self
    }
    /// Removes all structured-body allow rules.
    pub fn clear_body_allow_rules(mut self) -> Self {
        self.body.rules = self.body.rules.clear_allow_rules();
        self
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
    pub const fn unkeyed_json_value_policy(
        mut self,
        policy: UnkeyedJsonValuePolicy,
    ) -> Self {
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
        Ok(HttpRedactionPolicy::from_parts(HttpRedactionPolicyParts {
            header_rules: self.header.build()?,
            query_rules: self.query.build()?,
            body_rules: self.body.build()?,
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
