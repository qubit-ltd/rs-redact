// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Immutable URI redaction policy.

use std::sync::Arc;

use crate::RedactionPolicy;

use super::uri_redaction_policy_inner::UriRedactionPolicyInner;
use super::{
    UriFragmentPolicy,
    UriPathPolicy,
    UriRedactionPolicyBuilder,
};

/// Immutable URI policy that delegates field decisions to the core policy.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UriRedactionPolicy {
    pub(crate) inner: Arc<UriRedactionPolicyInner>,
}

impl UriRedactionPolicy {
    /// Creates a builder using the current core policy snapshot.
    #[must_use = "configure or build the URI policy"]
    #[inline]
    pub fn builder() -> UriRedactionPolicyBuilder {
        UriRedactionPolicyBuilder::new()
    }

    /// Creates a builder that copies the core policy snapshot.
    #[must_use = "configure or build the URI policy"]
    #[inline]
    pub fn builder_from(policy: &RedactionPolicy) -> UriRedactionPolicyBuilder {
        UriRedactionPolicyBuilder::from_policy(policy)
    }

    /// Returns a builder that copies this URI policy exactly.
    #[must_use = "configure or build the URI policy"]
    #[inline]
    pub fn to_builder(&self) -> UriRedactionPolicyBuilder {
        UriRedactionPolicyBuilder::from_uri_policy(self)
    }

    /// Returns the core field policy used for usernames, passwords, and query
    /// keys.
    #[must_use = "inspect the core redaction policy"]
    #[inline]
    pub fn redaction_policy(&self) -> &RedactionPolicy {
        &self.inner.redaction_policy
    }

    /// Returns the path handling policy.
    #[must_use = "inspect the path policy"]
    #[inline]
    pub fn path_policy(&self) -> UriPathPolicy {
        self.inner.path_policy
    }

    /// Returns the fragment handling policy.
    #[must_use = "inspect the fragment policy"]
    #[inline]
    pub fn fragment_policy(&self) -> UriFragmentPolicy {
        self.inner.fragment_policy
    }

    pub(crate) fn new(
        redaction_policy: RedactionPolicy,
        path_policy: UriPathPolicy,
        fragment_policy: UriFragmentPolicy,
    ) -> Self {
        Self {
            inner: Arc::new(UriRedactionPolicyInner {
                redaction_policy,
                path_policy,
                fragment_policy,
            }),
        }
    }
}

impl Default for UriRedactionPolicy {
    /// Creates a URI policy snapshot from the current global configuration.
    #[inline]
    fn default() -> Self {
        crate::GlobalRedactionConfig::current()
            .uri_policy()
            .clone()
    }
}
