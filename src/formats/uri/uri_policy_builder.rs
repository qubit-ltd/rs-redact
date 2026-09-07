// =============================================================================
//    Copyright (c) 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Mutable builder for URI redaction policies.

use super::UriFragmentPolicy;
use super::UriPathPolicy;
use super::UriPolicy;
use crate::PolicyError;

/// Mutable construction state for an immutable URI policy.
#[derive(Debug, Clone)]
pub struct UriPolicyBuilder {
    /// Selected visibility rule for path components.
    path_policy: UriPathPolicy,
    /// Selected visibility rule for URI fragments.
    fragment_policy: UriFragmentPolicy,
}

impl UriPolicyBuilder {
    /// Creates a builder for URI-specific behavior.
    ///
    /// # Returns
    ///
    /// A builder initialized with the standard URI path and fragment policies.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self {
            path_policy: UriPathPolicy::default(),
            fragment_policy: UriFragmentPolicy::default(),
        }
    }

    /// Creates a builder that copies an existing URI context snapshot.
    ///
    /// # Parameters
    ///
    /// - `policy`: Immutable URI snapshot whose component choices are copied.
    ///
    /// # Returns
    ///
    /// An independent builder retaining the supplied policy choices.
    #[must_use]
    #[inline(always)]
    pub(crate) fn from_policy(policy: &UriPolicy) -> Self {
        Self {
            path_policy: policy.path_policy(),
            fragment_policy: policy.fragment_policy(),
        }
    }

    /// Replaces the path handling policy in place.
    ///
    /// # Parameters
    ///
    /// - `policy`: Replacement visibility policy for URI path components.
    #[inline(always)]
    pub(crate) fn path_policy_mut(&mut self, policy: UriPathPolicy) {
        self.path_policy = policy;
    }

    /// Replaces the fragment handling policy in place.
    ///
    /// # Parameters
    ///
    /// - `policy`: Replacement classification and visibility policy for URI
    ///   fragments.
    #[inline(always)]
    pub(crate) fn fragment_policy_mut(&mut self, policy: UriFragmentPolicy) {
        self.fragment_policy = policy;
    }

    /// Creates the immutable URI policy from typed component choices.
    ///
    /// # Errors
    ///
    /// Currently infallible: both choices are typed enum values, and this
    /// builder does not validate the enclosing field rules.
    ///
    /// # Returns
    ///
    /// An immutable snapshot of the selected path and fragment policies.
    #[inline]
    pub(crate) fn build(self) -> Result<UriPolicy, PolicyError> {
        Ok(UriPolicy::new(self.path_policy, self.fragment_policy))
    }
}

impl Default for UriPolicyBuilder {
    /// Creates a builder with standard URI handling defaults.
    ///
    /// # Returns
    ///
    /// A builder with standard path and fragment behavior.
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}
