// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable builder for URI redaction policies.

use crate::{
    PolicyError,
    RedactionPolicy,
};

use super::{
    UriFragmentPolicy,
    UriPathPolicy,
    UriRedactionPolicy,
};

/// Mutable construction state for an immutable URI policy.
#[must_use]
#[derive(Debug, Clone)]
pub struct UriRedactionPolicyBuilder {
    redaction_policy: RedactionPolicy,
    path_policy: UriPathPolicy,
    fragment_policy: UriFragmentPolicy,
}

impl UriRedactionPolicyBuilder {
    /// Creates a builder from the current core policy snapshot.
    #[inline]
    pub fn new() -> Self {
        Self {
            redaction_policy: RedactionPolicy::default(),
            path_policy: UriPathPolicy::default(),
            fragment_policy: UriFragmentPolicy::default(),
        }
    }

    /// Creates a builder from an explicit core policy.
    #[inline]
    pub fn from_policy(policy: &RedactionPolicy) -> Self {
        Self {
            redaction_policy: policy.clone(),
            path_policy: UriPathPolicy::default(),
            fragment_policy: UriFragmentPolicy::default(),
        }
    }

    /// Creates a builder that copies an existing URI policy.
    #[inline]
    pub fn from_uri_policy(policy: &UriRedactionPolicy) -> Self {
        Self {
            redaction_policy: policy.redaction_policy().clone(),
            path_policy: policy.path_policy(),
            fragment_policy: policy.fragment_policy(),
        }
    }

    /// Replaces the core policy used for field classification and masking.
    #[inline]
    pub fn redaction_policy(mut self, policy: RedactionPolicy) -> Self {
        self.redaction_policy = policy;
        self
    }

    /// Replaces the path handling policy.
    #[inline]
    pub const fn path_policy(mut self, policy: UriPathPolicy) -> Self {
        self.path_policy = policy;
        self
    }

    /// Replaces the fragment handling policy.
    #[inline]
    pub const fn fragment_policy(mut self, policy: UriFragmentPolicy) -> Self {
        self.fragment_policy = policy;
        self
    }

    /// Validates and creates the immutable URI policy.
    ///
    /// The core policy is already validated when supplied, so this builder
    /// currently has no additional error cases.
    #[inline]
    pub fn build(self) -> Result<UriRedactionPolicy, PolicyError> {
        Ok(UriRedactionPolicy::new(
            self.redaction_policy,
            self.path_policy,
            self.fragment_policy,
        ))
    }
}

impl Default for UriRedactionPolicyBuilder {
    /// Creates a builder with standard URI handling defaults.
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
