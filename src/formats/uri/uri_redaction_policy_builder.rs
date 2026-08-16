// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable builder for URI redaction policies.
// qubit-style: allow type-file-name

use super::UriFragmentPolicy;
use super::UriPathPolicy;
use super::UriPolicy;
use crate::PolicyError;

/// Mutable construction state for an immutable URI policy.
#[derive(Debug, Clone)]
pub struct UriPolicyBuilder {
    path_policy: UriPathPolicy,
    fragment_policy: UriFragmentPolicy,
}

impl UriPolicyBuilder {
    /// Creates a builder for URI-specific behavior.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self {
            path_policy: UriPathPolicy::default(),
            fragment_policy: UriFragmentPolicy::default(),
        }
    }

    /// Creates a builder that copies an existing URI context snapshot.

    #[must_use]
    pub(crate) fn from_policy(policy: &UriPolicy) -> Self {
        Self {
            path_policy: policy.path_policy(),
            fragment_policy: policy.fragment_policy(),
        }
    }

    /// Replaces the path handling policy in place.
    pub(crate) fn path_policy_mut(&mut self, policy: UriPathPolicy) {
        self.path_policy = policy;
    }

    /// Replaces the fragment handling policy in place.
    pub(crate) fn fragment_policy_mut(&mut self, policy: UriFragmentPolicy) {
        self.fragment_policy = policy;
    }

    /// Validates and creates the immutable URI policy.
    ///
    /// The core policy is already validated when supplied, so this builder
    /// currently has no additional error cases.
    #[inline]
    pub(crate) fn build(self) -> Result<UriPolicy, PolicyError> {
        Ok(UriPolicy::new(self.path_policy, self.fragment_policy))
    }
}

impl Default for UriPolicyBuilder {
    /// Creates a builder with standard URI handling defaults.
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
