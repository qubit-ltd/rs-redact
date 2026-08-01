// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Immutable policy snapshot for every HTTP redaction context.

use std::sync::Arc;

use crate::{DiagnosticBudget, JsonDepthBudget, MaskingPolicy, RedactionPolicy, RedactionRules};

use super::http_redaction_policy_parts::HttpRedactionPolicyParts;
use super::{
    BodyBudget, HttpRedactionPolicyBuilder, TextBodyPolicy, UnkeyedJsonValuePolicy, UrlPathPolicy,
};

/// Combines HTTP field rules, behavior choices, and resource limits.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRedactionPolicy {
    header_rules: RedactionRules,
    query_rules: RedactionRules,
    body_rules: RedactionRules,
    masking: Arc<MaskingPolicy>,
    diagnostic_budget: DiagnosticBudget,
    body_budget: BodyBudget,
    json_depth_budget: JsonDepthBudget,
    url_path_policy: UrlPathPolicy,
    text_body_policy: TextBodyPolicy,
    unkeyed_json_value_policy: UnkeyedJsonValuePolicy,
}

impl HttpRedactionPolicy {
    /// Creates a deterministic builder with empty application rules and the
    /// standard floor shared by the three initial contexts.
    #[inline(always)]
    pub fn builder() -> HttpRedactionPolicyBuilder {
        HttpRedactionPolicyBuilder::new()
    }

    /// Creates a builder with three copies of `base`'s rules and limits.
    #[inline(always)]
    pub fn builder_from(base: &RedactionPolicy) -> HttpRedactionPolicyBuilder {
        HttpRedactionPolicyBuilder::from_base_policy(base)
    }

    /// Creates a builder that exactly copies `self`.
    #[inline(always)]
    pub fn to_builder(&self) -> HttpRedactionPolicyBuilder {
        HttpRedactionPolicyBuilder::from_policy(self)
    }

    #[inline(always)]
    pub(super) fn from_parts(parts: HttpRedactionPolicyParts) -> Self {
        Self {
            header_rules: parts.header_rules,
            query_rules: parts.query_rules,
            body_rules: parts.body_rules,
            masking: parts.masking,
            diagnostic_budget: parts.diagnostic_budget,
            body_budget: parts.body_budget,
            json_depth_budget: parts.json_depth_budget,
            url_path_policy: parts.url_path_policy,
            text_body_policy: parts.text_body_policy,
            unkeyed_json_value_policy: parts.unkeyed_json_value_policy,
        }
    }

    /// Returns the header field-rule snapshot.
    #[inline(always)]
    pub const fn header_rules(&self) -> &RedactionRules {
        &self.header_rules
    }

    /// Returns the query and form field-rule snapshot.
    #[inline(always)]
    pub const fn query_rules(&self) -> &RedactionRules {
        &self.query_rules
    }

    /// Returns the structured-body field-rule snapshot.
    #[inline(always)]
    pub const fn body_rules(&self) -> &RedactionRules {
        &self.body_rules
    }

    /// Returns the single mask table shared by all HTTP contexts.
    #[inline(always)]
    pub fn masking(&self) -> &MaskingPolicy {
        self.masking.as_ref()
    }

    /// Returns the URL path visibility choice.
    #[inline(always)]
    pub const fn url_path_policy(&self) -> UrlPathPolicy {
        self.url_path_policy
    }

    /// Returns the opaque text-body visibility choice.
    #[inline(always)]
    pub const fn text_body_policy(&self) -> TextBodyPolicy {
        self.text_body_policy
    }

    /// Returns the unkeyed JSON scalar visibility choice.
    #[inline(always)]
    pub const fn unkeyed_json_value_policy(&self) -> UnkeyedJsonValuePolicy {
        self.unkeyed_json_value_policy
    }

    /// Returns the structured JSON recursion-depth limit.
    #[inline(always)]
    pub const fn json_depth_budget(&self) -> JsonDepthBudget {
        self.json_depth_budget
    }

    /// Returns the hard body input and output limits.
    #[inline(always)]
    pub const fn body_budget(&self) -> BodyBudget {
        self.body_budget
    }

    /// Returns the non-body diagnostic limits.
    #[inline(always)]
    pub const fn diagnostic_budget(&self) -> DiagnosticBudget {
        self.diagnostic_budget
    }
}

impl Default for HttpRedactionPolicy {
    /// Creates a policy snapshot from the current global configuration.
    #[inline(always)]
    fn default() -> Self {
        crate::GlobalRedactionConfig::current().http_policy().clone()
    }
}
