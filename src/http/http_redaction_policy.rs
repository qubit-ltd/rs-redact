// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Immutable policy snapshot for every HTTP redaction context.
// qubit-style: allow type-file-name

use std::sync::Arc;

use super::TextBodyPolicy;
use super::UrlPathPolicy;
use super::http_redaction_policy_parts::HttpPolicyParts;
use crate::RedactionRules;

/// Combines HTTP field rules, behavior choices, and resource limits.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpPolicy {
    inner: Arc<HttpPolicyInner>,
}

/// Shared immutable HTTP behavior state.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpPolicyInner {
    header_rules: RedactionRules,
    query_rules: RedactionRules,
    body_rules: RedactionRules,
    url_path_policy: UrlPathPolicy,
    text_body_policy: TextBodyPolicy,
}

impl HttpPolicy {
    /// Creates an HTTP policy from its validated component policies.
    pub(super) fn from_parts(parts: HttpPolicyParts) -> Self {
        Self {
            inner: std::sync::Arc::new(HttpPolicyInner {
                header_rules: parts.header_rules,
                query_rules: parts.query_rules,
                body_rules: parts.body_rules,
                url_path_policy: parts.url_path_policy,
                text_body_policy: parts.text_body_policy,
            }),
        }
    }

    /// Returns the header field-rule snapshot.
    #[inline(always)]
    pub fn header_rules(&self) -> &RedactionRules {
        &self.inner.header_rules
    }

    /// Returns the query and form field-rule snapshot.
    #[inline(always)]
    pub fn query_rules(&self) -> &RedactionRules {
        &self.inner.query_rules
    }

    /// Returns the structured-body field-rule snapshot.
    #[inline(always)]
    pub fn body_rules(&self) -> &RedactionRules {
        &self.inner.body_rules
    }

    /// Returns the URL path visibility choice.
    #[inline(always)]
    pub fn url_path_policy(&self) -> UrlPathPolicy {
        self.inner.url_path_policy
    }

    /// Returns the opaque text-body visibility choice.
    #[inline(always)]
    pub fn text_body_policy(&self) -> TextBodyPolicy {
        self.inner.text_body_policy
    }
}
